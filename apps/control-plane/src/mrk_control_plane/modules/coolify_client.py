"""Outbound client for the Coolify v4 REST API (docs/44, phase 6).

Coolify serves its API at ``<panel>/api/v1/...`` with a Bearer token created
under Keys & Tokens → API tokens (the API must be enabled in Settings).
Endpoints used (https://coolify.io/docs/api-reference/api/):

- ``GET  /version``                         check URL + token
- ``GET  /projects``, ``POST /projects``     list / create a project
- ``GET  /projects/{uuid}/environments``     environments of a project
- ``GET  /servers``                          servers (the stack must run on the panel's own)
- ``GET  /services``, ``GET /services/{uuid}``
- ``POST /services``                         create from ``docker_compose_raw`` (base64)
- ``PATCH /services/{uuid}``                 replace the compose of an existing service
- ``PATCH /services/{uuid}/envs/bulk``       set environment variables
- ``POST /services/{uuid}/start`` / ``/restart``

Same protections as the Dokploy client: one token bucket, a concurrency limit,
no redirects, no proxies from the environment, capped bodies, and the token
only ever in the Authorization header (never in logs, errors or results).
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import httpx

from ..logging_config import redact_text
from .dokploy_client import DokployError, TokenBucket, validate_dokploy_url

# Tests replace this with a factory returning e.g. httpx.MockTransport(handler).
TRANSPORT_FACTORY: Callable[[], httpx.AsyncBaseTransport] | None = None

MAX_RESPONSE_BYTES = 4 * 1024 * 1024
TOKEN_MIN = 16
TOKEN_MAX = 512


class CoolifyError(Exception):
    """An error already mapped to the MRK API contract (code + HTTP status)."""

    def __init__(
        self, code: str, status_code: int, message: str, *, upstream_status: int | None = None
    ) -> None:
        super().__init__(message)
        self.code = code
        self.status_code = status_code
        self.message = message
        self.upstream_status = upstream_status


def validate_coolify_url(value: str, *, allow_loopback: bool = False) -> str:
    """Same rules as the Dokploy URL (no metadata/link-local, no credentials, no query).

    A trailing ``/api`` or ``/api/v1`` is stripped; the client adds ``/api/v1``.
    """
    text = value.strip().rstrip("/")
    if text.lower().endswith("/api/v1"):
        text = text[:-3]
    try:
        return validate_dokploy_url(text, allow_loopback=allow_loopback)
    except ValueError as exc:
        raise ValueError(str(exc).replace("Dokploy", "Coolify")) from None


def validate_token(value: str) -> str:
    token = value.strip()
    if not TOKEN_MIN <= len(token) <= TOKEN_MAX:
        raise ValueError("Coolify token has an invalid length")
    if any(ord(char) <= 32 or ord(char) > 126 for char in token):
        raise ValueError("Coolify token contains invalid characters")
    return token


@dataclass(frozen=True, slots=True)
class Connection:
    url: str
    token: str


def _upstream_message(body: bytes) -> str:
    try:
        payload = json.loads(body)
    except ValueError:
        return ""
    if isinstance(payload, dict) and isinstance(payload.get("message"), str):
        return redact_text(payload["message"][:300])
    return ""


class CoolifyClient:
    def __init__(
        self,
        *,
        rate_per_second: float = 2.0,
        concurrency: int = 2,
        timeout_seconds: float = 20.0,
        max_wait_seconds: float = 15.0,
    ) -> None:
        self.bucket = TokenBucket(rate_per_second)
        self.concurrency = max(1, concurrency)
        self._semaphore: asyncio.Semaphore | None = None
        self._semaphore_loop: asyncio.AbstractEventLoop | None = None
        self.timeout_seconds = timeout_seconds
        self.max_wait_seconds = max_wait_seconds

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
        method: str,
        path: str,
        *,
        body: dict[str, Any] | None = None,
        text: bool = False,
    ) -> Any:
        """Call ``/api/v1<path>``; returns parsed JSON (or the text when ``text``)."""
        try:
            await self.bucket.acquire(self.max_wait_seconds)
        except DokployError:
            raise CoolifyError(
                "coolify_rate_limited", 429,
                "Too many Coolify requests; DevAssist is protecting the Coolify panel. "
                "Retry shortly.",
            ) from None
        async with self._sem():
            headers = {"authorization": f"Bearer {connection.token}"}
            async with self._client(connection.url) as client:
                request = client.build_request(
                    method, f"/api/v1{path}", json=body if body is not None else None,
                    headers=headers,
                )
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
                    raise CoolifyError(
                        "coolify_unreachable", 502,
                        f"Coolify is unreachable ({type(exc).__name__})",
                    ) from None
        status = response.status_code
        if 200 <= status < 300:
            if too_large:
                raise CoolifyError("coolify_unreachable", 502, "The Coolify response is too large")
            if text:
                return bytes(raw).decode("utf-8", "replace").strip()[:200]
            if not raw.strip():
                return None
            try:
                return json.loads(bytes(raw))
            except ValueError:
                raise CoolifyError(
                    "coolify_unreachable", 502, "Coolify returned invalid JSON"
                ) from None
        raise self.map_status(status, bytes(raw[:4096]))

    @staticmethod
    def map_status(status: int, body: bytes) -> CoolifyError:
        message = _upstream_message(body)
        if 300 <= status < 400:
            return CoolifyError(
                "coolify_unreachable", 502,
                f"Coolify answered with a redirect (HTTP {status}); check the panel URL",
                upstream_status=status,
            )
        if status in {400, 401} and (status == 401 or "token" in message.lower()):
            return CoolifyError(
                "coolify_auth_failed", 502, "Coolify rejected the API token",
                upstream_status=status,
            )
        if status == 403:
            return CoolifyError(
                "coolify_auth_failed", 502,
                "The Coolify token lacks permission, or the API is turned off in Coolify settings",
                upstream_status=status,
            )
        if status == 404:
            return CoolifyError(
                "coolify_not_found", 404, message or "Not found in Coolify",
                upstream_status=status,
            )
        if status == 405:
            return CoolifyError(
                "coolify_not_supported", 409, "Not supported by this Coolify version",
                upstream_status=status,
            )
        if status == 429:
            return CoolifyError(
                "coolify_rate_limited", 429, "Coolify is rate limiting requests",
                upstream_status=status,
            )
        if status in {400, 409, 422}:
            return CoolifyError(
                "coolify_rejected", 409,
                f"Coolify rejected the request: {message}" if message
                else "Coolify rejected the request",
                upstream_status=status,
            )
        return CoolifyError(
            "coolify_unreachable", 502, f"Coolify returned HTTP {status}",
            upstream_status=status,
        )
