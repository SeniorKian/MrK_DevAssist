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
import logging
import math
import re
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

import httpx

from ..logging_config import redact_text

LOGGER = logging.getLogger(__name__)

# Tests replace this with a factory returning e.g. httpx.MockTransport(handler).
TRANSPORT_FACTORY: Callable[[], httpx.AsyncBaseTransport] | None = None

MAX_RESPONSE_BYTES = 8 * 1024 * 1024
API_KEY_MIN = 16
API_KEY_MAX = 512

# Body the trpc-openapi adapter returns when a procedure does not exist (older
# Dokploy release) or the HTTP method is wrong. Service-level NOT_FOUND errors
# carry their own message ("Application not found", ...).
PROCEDURE_NOT_FOUND_MESSAGE = "Not found"
# Messages Dokploy (better-auth / tRPC) gives a key it does not know at all, as opposed
# to a known key refused one resource ("You are not authorized to access this project").
GENERIC_UNAUTHORIZED = frozenset({"", "unauthorized", "not authorized", "unauthenticated"})
NOT_FOUND_RE = re.compile(r"not found", re.IGNORECASE)
MAX_MESSAGE = 300


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
        connection_failure: bool = False,
        upstream_message: str | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.status_code = status_code
        self.message = message
        self.upstream_status = upstream_status
        self.procedure_missing = procedure_missing
        # True when Dokploy itself could not be talked to (network, timeout, redirect,
        # unreadable reply): the only failures that say something about the connection.
        self.connection_failure = connection_failure
        # Dokploy's own words (already redacted), "" when it gave none.
        self.upstream_message = upstream_message or ""


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
                "Too many Dokploy requests; DevAssist is protecting the Dokploy panel. "
                "Retry shortly.",
            )
        await self._sleep(wait)
        return wait

    async def acquire_background(self, max_wait: float, reserve: float = 1.0) -> float:
        """Take a token only while ``reserve`` more stay free for interactive callers.

        Background work (the poller) never queues ahead of a page load: it waits, without
        holding a reservation, until the bucket has spare capacity.
        """
        waited = 0.0
        need = 1.0 + min(max(reserve, 0.0), max(self.burst - 1.0, 0.0))
        while True:
            self._refill()
            if self._tokens >= need:
                self._tokens -= 1.0
                return waited
            step = max((need - self._tokens) / self.rate, 0.05)
            if waited + step > max_wait:
                raise DokployError(
                    "dokploy_rate_limited",
                    429,
                    "Background Dokploy work is waiting for spare request capacity",
                )
            await self._sleep(step)
            waited += step


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

    def pop(self, key: str) -> None:
        self._items.pop(key, None)

    def clear(self) -> None:
        self._items.clear()


@dataclass(frozen=True, slots=True)
class Connection:
    url: str
    api_key: str


def _clip(value: str) -> str:
    return redact_text(" ".join(value.split())[:MAX_MESSAGE])


def _issues_text(issues: Any) -> str:
    parts: list[str] = []
    for issue in issues if isinstance(issues, list) else []:
        if not isinstance(issue, dict) or not isinstance(issue.get("message"), str):
            continue
        path = issue.get("path")
        where = ".".join(str(item) for item in path) if isinstance(path, list) and path else ""
        parts.append(f"{where}: {issue['message']}" if where else issue["message"])
        if len(parts) >= 5:
            break
    return "; ".join(parts)


def parse_upstream_error(body: bytes) -> tuple[str, str | None]:
    """(message, tRPC code) from any error body Dokploy produces.

    Shapes: ``{"message"}`` (trpc-openapi), zod ``{"message": "Input validation failed",
    "issues": [...]}``, and tRPC envelopes ``{"error": {"message"}}`` /
    ``{"error": {"json": {"message", "data": {"code"}}}}``. The message is redacted.
    """
    try:
        payload = json.loads(body)
    except ValueError:
        return "", None
    if isinstance(payload, list) and payload and isinstance(payload[0], dict):
        payload = payload[0]  # batched tRPC reply
    if not isinstance(payload, dict):
        return "", None
    code = payload.get("code") if isinstance(payload.get("code"), str) else None
    node: dict[str, Any] = payload
    error = payload.get("error")
    if isinstance(error, dict):
        node = error.get("json") if isinstance(error.get("json"), dict) else error
    message = node.get("message") if isinstance(node.get("message"), str) else ""
    data = node.get("data")
    if isinstance(data, dict) and isinstance(data.get("code"), str):
        code = data["code"]
    elif isinstance(node.get("code"), str):
        code = node["code"]
    issues = _issues_text(node.get("issues") or payload.get("issues"))
    if issues:
        message = f"{message}: {issues}" if message else issues
    return (_clip(message) if message else ""), (code[:64] if code else None)


def _upstream_message(body: bytes) -> str:
    return parse_upstream_error(body)[0]


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
        probe: bool = False,
        background: bool = False,
    ) -> Any:
        """Call one Dokploy procedure and return its JSON output (None for empty).

        ``probe`` marks the connection check (settings.getDokployVersion / project.all):
        only there does any 401 certainly mean "this key is rejected". ``background``
        calls yield the request budget to interactive ones.
        """
        if background:
            await self.bucket.acquire_background(max(self.max_wait_seconds, 1.0) * 6)
        else:
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
                    LOGGER.info(
                        "dokploy request failed",
                        extra={"procedure": procedure, "error": type(exc).__name__},
                    )
                    raise DokployError(
                        "dokploy_unreachable",
                        502,
                        f"Dokploy is unreachable ({type(exc).__name__})",
                        connection_failure=True,
                    ) from None
        status = response.status_code
        if 200 <= status < 300:
            if not parse:
                return None
            if too_large:
                raise DokployError(
                    "dokploy_unreachable", 502, "The Dokploy response is too large",
                    connection_failure=True,
                )
            if not raw.strip():
                return None
            try:
                return json.loads(bytes(raw))
            except ValueError:
                raise DokployError(
                    "dokploy_unreachable", 502, "Dokploy returned invalid JSON",
                    connection_failure=True,
                ) from None
        error = self._map_status(status, bytes(raw[:4096]), probe=probe)
        if connection.api_key and connection.api_key in error.message:
            error.message = error.message.replace(connection.api_key, "[REDACTED]")
            error.upstream_message = error.upstream_message.replace(
                connection.api_key, "[REDACTED]"
            )
            error.args = (error.message,)
        LOGGER.info(
            "dokploy answered with an error",
            extra={
                "procedure": procedure,
                "upstream_status": status,
                "error_code": error.code,
                "upstream_message": error.upstream_message,
            },
        )
        raise error

    @staticmethod
    def _map_status(status: int, body: bytes, *, probe: bool = False) -> DokployError:
        message, trpc_code = parse_upstream_error(body)

        def said(prefix: str) -> str:
            return f"{prefix}: {message}" if message else prefix

        common: dict[str, Any] = {"upstream_status": status, "upstream_message": message}
        if 300 <= status < 400:
            return DokployError(
                "dokploy_unreachable",
                502,
                f"Dokploy answered with a redirect (HTTP {status}); check the panel URL",
                connection_failure=True,
                **common,
            )
        if status == 401 and (probe or message.strip().lower() in GENERIC_UNAUTHORIZED):
            return DokployError(
                "dokploy_auth_failed",
                502,
                said("Dokploy rejected the API key (invalid, expired or over its own limit)"),
                **common,
            )
        if status in {401, 403}:
            # The key is known, but its Dokploy user may not use this resource or action.
            return DokployError(
                "dokploy_forbidden",
                502,
                said("Dokploy does not allow this API key to do this"),
                **common,
            )
        if status == 404 and message == PROCEDURE_NOT_FOUND_MESSAGE:
            return DokployError(
                "dokploy_not_found",
                404,
                "Not supported by this Dokploy version",
                procedure_missing=True,
                **common,
            )
        if status == 404 or (
            status == 400 and (trpc_code == "NOT_FOUND" or NOT_FOUND_RE.search(message))
        ):
            # Dokploy v0.31 answers for a removed Compose/app with HTTP 400 "... not found".
            return DokployError("dokploy_not_found", 404, message or "Not found", **common)
        if status == 429:
            return DokployError(
                "dokploy_rate_limited", 429, said("Dokploy is rate limiting requests"), **common
            )
        if status in {400, 409, 412, 422}:
            return DokployError(
                "dokploy_rejected", 409, said("Dokploy rejected the request"), **common
            )
        return DokployError(
            "dokploy_failed", 502, said(f"Dokploy returned HTTP {status}"), **common
        )
