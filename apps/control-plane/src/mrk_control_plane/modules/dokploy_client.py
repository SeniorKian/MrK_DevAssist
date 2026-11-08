"""Outbound client for the official Dokploy API (Gate 17, S1).

Dokploy exposes its tRPC routers through ``@dokploy/trpc-openapi`` at
``<panel>/api/<router>.<procedure>``: queries are ``GET`` with the input as
query parameters, mutations are ``POST`` with a JSON body. Authentication is
the ``x-api-key`` header (a key generated under Settings → Profile → API/CLI).
See docs/28 §9 for the pinned endpoint table.

Protecting Dokploy is the point of this file: every request goes through one
token bucket (default 2 req/s) and a concurrency limit (default 2), redirects
are never followed, proxies from the environment are ignored, and response
bodies are capped. The API key is only ever placed in the request header and
never appears in logs, errors or return values.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import math
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

import httpx

from ..logging_config import redact_text

# Tests replace this with a factory returning e.g. httpx.MockTransport(handler).
TRANSPORT_FACTORY: Callable[[], httpx.AsyncBaseTransport] | None = None

MAX_RESPONSE_BYTES = 8 * 1024 * 1024
API_KEY_MIN = 16
API_KEY_MAX = 512

# Body the trpc-openapi adapter returns when a procedure does not exist (older
# Dokploy release) or the HTTP method is wrong. Service-level NOT_FOUND errors
# carry their own message ("Application not found", ...).
PROCEDURE_NOT_FOUND_MESSAGE = "Not found"


class DokployError(Exception):
    """An error already mapped to the MRK API contract (code + HTTP status)."""

    def __init__(
        self,
        code: str,
        status_code: int,
        message: str,
        *,
        upstream_status: int | None = None,
        procedure_missing: bool = False,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.status_code = status_code
        self.message = message
        self.upstream_status = upstream_status
        self.procedure_missing = procedure_missing


def _is_forbidden_literal(host: str, allow_loopback: bool) -> bool:
    lowered = host.lower().rstrip(".")
    if not allow_loopback and (lowered == "localhost" or lowered.endswith(".localhost")):
        return True
    try:
        address = ipaddress.ip_address(lowered)
    except ValueError:
        return False
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    if address.is_link_local or address.is_multicast or address.is_unspecified:
        # 169.254.0.0/16 holds cloud metadata services; never a Dokploy panel.
        return True
    return address.is_loopback and not allow_loopback


def validate_dokploy_url(value: str, *, allow_loopback: bool = False) -> str:
    """Normalize an operator-entered Dokploy panel URL.

    Dokploy normally runs on the same host or LAN, so private addresses and
    LAN names are allowed for this one operator-chosen admin endpoint.
    Rejected: non-http(s), credentials, query/fragment, link-local/metadata,
    multicast/unspecified and (unless MRK_DOKPLOY_ALLOW_LOOPBACK) loopback,
    which inside the MRK container would point at MRK itself.
    A path prefix is kept (reverse proxy); a trailing ``/api`` is stripped.
    """
    text = value.strip()
    if not text or any(char.isspace() or ord(char) < 32 for char in text):
        raise ValueError("Dokploy URL is invalid")
    try:
        parts = urlsplit(text)
        port = parts.port
    except ValueError as exc:
        raise ValueError("Dokploy URL is invalid") from exc
    if parts.scheme not in {"http", "https"}:
        raise ValueError("Dokploy URL must use http or https")
    if not parts.hostname:
        raise ValueError("Dokploy URL must include a host")
    if parts.username is not None or parts.password is not None or "@" in parts.netloc:
        raise ValueError("Dokploy URL must not contain credentials")
    if parts.query or parts.fragment or "?" in text or "#" in text:
        raise ValueError("Dokploy URL must not contain a query or fragment")
    if _is_forbidden_literal(parts.hostname, allow_loopback):
        raise ValueError("Dokploy URL points at a forbidden address")
    path = parts.path.rstrip("/")
    if path.lower().endswith("/api"):
        path = path[:-4]
    if ".." in path.split("/") or "%" in path or "\\" in path:
        raise ValueError("Dokploy URL path is invalid")
    host = parts.hostname if ":" not in parts.hostname else f"[{parts.hostname}]"
    netloc = host if port is None else f"{host}:{port}"
    return f"{parts.scheme}://{netloc}{path}"


def validate_api_key(value: str) -> str:
    key = value.strip()
    if not API_KEY_MIN <= len(key) <= API_KEY_MAX:
        raise ValueError("Dokploy API key has an invalid length")
    if any(ord(char) <= 32 or ord(char) > 126 for char in key):
        raise ValueError("Dokploy API key contains invalid characters")
    return key


class TokenBucket:
    """Async token bucket. No lock needed: the critical section never awaits."""

    def __init__(
        self,
        rate: float,
        burst: int | None = None,
        *,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        self.rate = max(rate, 0.01)
        self.burst = float(burst if burst is not None else max(1, math.ceil(self.rate)))
        self._tokens = self.burst
        self._clock = clock
        self._sleep = sleep
        self._updated = clock()

    def _refill(self) -> None:
        now = self._clock()
        elapsed = max(0.0, now - self._updated)
        self._updated = now
        self._tokens = min(self.burst, self._tokens + elapsed * self.rate)

    async def acquire(self, max_wait: float) -> float:
        """Reserve one token; wait for it, or raise if the wait exceeds max_wait."""
        self._refill()
        self._tokens -= 1.0
        if self._tokens >= 0:
            return 0.0
        wait = -self._tokens / self.rate
        if wait > max_wait:
            self._tokens += 1.0
            raise DokployError(
                "dokploy_rate_limited",
                429,
                "Too many Dokploy requests; MRK is protecting the Dokploy panel. Retry shortly.",
            )
        await self._sleep(wait)
        return wait


class TTLCache:
    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        self._items: dict[str, tuple[float, Any]] = {}
        self._clock = clock

    def get(self, key: str) -> Any | None:
        item = self._items.get(key)
        if item is None:
            return None
        if item[0] <= self._clock():
            self._items.pop(key, None)
            return None
        return item[1]

    def set(self, key: str, value: Any, ttl: float) -> None:
        if ttl <= 0:
            return
        if len(self._items) > 2048:
            now = self._clock()
            self._items = {k: v for k, v in self._items.items() if v[0] > now}
            if len(self._items) > 2048:
                self._items.clear()
        self._items[key] = (self._clock() + ttl, value)

    def clear(self) -> None:
        self._items.clear()


@dataclass(frozen=True, slots=True)
class Connection:
    url: str
    api_key: str


def _upstream_message(body: bytes) -> str:
    try:
        payload = json.loads(body)
    except ValueError:
        return ""
    if isinstance(payload, dict) and isinstance(payload.get("message"), str):
        return redact_text(payload["message"][:300])
    return ""


class DokployClient:
    """Rate-limited, size-capped caller for ``/api/<procedure>``."""

    def __init__(
        self,
        *,
        rate_per_second: float = 2.0,
        concurrency: int = 2,
        timeout_seconds: float = 15.0,
        max_wait_seconds: float = 10.0,
    ) -> None:
        self.bucket = TokenBucket(rate_per_second)
        self.concurrency = max(1, concurrency)
        self._semaphore: asyncio.Semaphore | None = None
        self._semaphore_loop: asyncio.AbstractEventLoop | None = None
        self.timeout_seconds = timeout_seconds
        self.max_wait_seconds = max_wait_seconds
        self.request_count = 0

    def set_rate(self, rate_per_second: float) -> None:
        if abs(rate_per_second - self.bucket.rate) > 1e-9:
            self.bucket = TokenBucket(rate_per_second)

    def _sem(self) -> asyncio.Semaphore:
        loop = asyncio.get_running_loop()
        if self._semaphore is None or self._semaphore_loop is not loop:
            self._semaphore = asyncio.Semaphore(self.concurrency)
            self._semaphore_loop = loop
        return self._semaphore

    def _client(self, base_url: str) -> httpx.AsyncClient:
        transport = TRANSPORT_FACTORY() if TRANSPORT_FACTORY is not None else None
        return httpx.AsyncClient(
            base_url=base_url,
            transport=transport,
            timeout=httpx.Timeout(self.timeout_seconds, connect=min(5.0, self.timeout_seconds)),
            follow_redirects=False,
            trust_env=False,
            headers={"accept": "application/json", "user-agent": "mrk-control-plane"},
        )

    async def call(
        self,
        connection: Connection,
        procedure: str,
        *,
        params: dict[str, Any] | None = None,
        body: dict[str, Any] | None = None,
        mutation: bool = False,
        parse: bool = True,
    ) -> Any:
        """Call one Dokploy procedure and return its JSON output (None for empty)."""
        await self.bucket.acquire(self.max_wait_seconds)
        async with self._sem():
            self.request_count += 1
            path = f"/api/{procedure}"
            headers = {"x-api-key": connection.api_key}
            async with self._client(connection.url) as client:
                if mutation:
                    request = client.build_request(
                        "POST", path, json=body or {}, headers=headers
                    )
                else:
                    request = client.build_request("GET", path, params=params, headers=headers)
                try:
                    response = await client.send(request, stream=True)
                    try:
                        raw = bytearray()
                        too_large = False
                        async for chunk in response.aiter_bytes():
                            raw.extend(chunk)
                            if len(raw) > MAX_RESPONSE_BYTES:
                                too_large = True
                                break
                    finally:
                        await response.aclose()
                except httpx.HTTPError as exc:
                    raise DokployError(
                        "dokploy_unreachable",
                        502,
                        f"Dokploy is unreachable ({type(exc).__name__})",
                    ) from None
        status = response.status_code
        if 200 <= status < 300:
            if not parse:
                return None
            if too_large:
                raise DokployError(
                    "dokploy_unreachable", 502, "The Dokploy response is too large"
                )
            if not raw.strip():
                return None
            try:
                return json.loads(bytes(raw))
            except ValueError:
                raise DokployError(
                    "dokploy_unreachable", 502, "Dokploy returned invalid JSON"
                ) from None
        raise self._map_status(status, bytes(raw[:4096]))

    @staticmethod
    def _map_status(status: int, body: bytes) -> DokployError:
        message = _upstream_message(body)
        if 300 <= status < 400:
            return DokployError(
                "dokploy_unreachable",
                502,
                f"Dokploy answered with a redirect (HTTP {status}); check the panel URL",
                upstream_status=status,
            )
        if status == 401:
            return DokployError(
                "dokploy_auth_failed",
                502,
                "Dokploy rejected the API key (invalid, expired or over its own rate limit)",
                upstream_status=status,
            )
        if status == 403:
            return DokployError(
                "dokploy_auth_failed",
                502,
                "The Dokploy API key lacks permission for this operation",
                upstream_status=status,
            )
        if status == 404:
            missing = message == PROCEDURE_NOT_FOUND_MESSAGE
            return DokployError(
                "dokploy_not_found",
                404,
                "Not supported by this Dokploy version" if missing else (message or "Not found"),
                upstream_status=status,
                procedure_missing=missing,
            )
        if status == 429:
            return DokployError(
                "dokploy_rate_limited", 429, "Dokploy is rate limiting requests",
                upstream_status=status,
            )
        if status in {400, 409, 412, 422}:
            return DokployError(
                "dokploy_rejected",
                409,
                f"Dokploy rejected the request: {message}"
                if message
                else "Dokploy rejected the request",
                upstream_status=status,
            )
        return DokployError(
            "dokploy_unreachable",
            502,
            f"Dokploy returned HTTP {status}",
            upstream_status=status,
        )
