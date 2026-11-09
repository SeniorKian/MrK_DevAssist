"""Client for the MRK DNS engine admin API (docs/37 §2): HTTP over a unix socket.

The engine writes ``admin.token`` next to its socket on first start; the panel
and the engine share a uid/gid, so the panel can read it. Every failure becomes
a ``DnsError`` with a stable code:

* ``dns_not_installed`` - the socket file does not exist (the ``dns`` compose
  profile is not running here);
* ``dns_unreachable`` - the socket exists but the engine does not answer, the
  token is missing or rejected, or the answer is not JSON (``reason`` says which);
* engine errors ``{error:{code, message, fields?}}`` are passed through with the
  panel's code (see ``ENGINE_CODES``) and the engine's ``fields``.
"""

from __future__ import annotations

import contextvars
import json
import os
import threading
import time
from collections.abc import AsyncIterator, Callable
from typing import Any

import httpx

from .config import setting_env

# Panel user behind the current change; sent as X-MRK-Actor (zone history).
CURRENT_ACTOR: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "mrk_dns_actor", default=None
)

DEFAULT_SOCKET = "/run/mrk-dns/admin.sock"
DEFAULT_TOKEN_FILE = "/run/mrk-dns/admin.token"  # noqa: S105 - a path, not a secret
SOCKET_ENV = "MRK_DNS_ADMIN_SOCKET"
TOKEN_ENV = "MRK_DNS_ADMIN_TOKEN_FILE"  # noqa: S105 - an env name
MAX_RESPONSE_BYTES = 8 * 1024 * 1024
MAX_TOKEN_BYTES = 512
DEFAULT_TIMEOUT = 5.0

# Tests replace this with ``lambda socket_path: httpx.ASGITransport(fake_engine)``.
TRANSPORT_FACTORY: Callable[[str], httpx.AsyncBaseTransport] | None = None

# engine code -> (panel code, default HTTP status of the panel response)
ENGINE_CODES: dict[str, tuple[str, int]] = {
    "config_conflict": ("dns_config_conflict", 409),
    "zone_exists": ("dns_zone_exists", 409),
    "zone_not_found": ("dns_zone_not_found", 404),
    "record_not_found": ("dns_record_not_found", 404),
    "record_invalid": ("dns_record_invalid", 422),
    "invalid_record": ("dns_record_invalid", 422),
    "cname_conflict": ("dns_cname_conflict", 409),
    "invalid_zone_name": ("invalid_zone_name", 422),
    "zone_invalid": ("invalid_zone_name", 422),
    "override_not_found": ("dns_override_not_found", 404),
    "override_exists": ("dns_override_exists", 409),
    "version_not_found": ("dns_version_not_found", 404),
    "settings_invalid": ("dns_settings_invalid", 422),
    "invalid_settings": ("dns_settings_invalid", 422),
    "import_invalid": ("dns_import_invalid", 422),
    "invalid_zone_file": ("dns_import_invalid", 422),
    "body_too_large": ("dns_request_too_large", 413),
    # D2 (docs/38 §0.2): engine names → the codes the panel has words for.
    "too_many_streams": ("dns_stream_limit", 429),
    "query_invalid": ("dns_query_invalid", 422),
    "mitigation_invalid": ("dns_mitigation_invalid", 422),
    "mitigation_not_found": ("dns_mitigation_not_found", 404),
    "querylog_disabled": ("dns_querylog_disabled", 409),
    "limit_reached": ("dns_limit_reached", 409),
    # D4 (docs/40 §3): certificates, DoH tokens, encrypted listeners.
    "certificate_required": ("dns_certificate_required", 409),
    "certificate_in_use": ("dns_certificate_in_use", 409),
    "tls_invalid": ("dns_tls_invalid", 422),
    "token_not_found": ("dns_token_not_found", 404),
    "token_invalid": ("dns_token_invalid", 422),
    "listen_conflict": ("dns_listen_conflict", 422),
    "plain_doh_public": ("dns_plain_doh_public", 422),
}


class DnsError(Exception):
    def __init__(
        self,
        code: str,
        status_code: int,
        message: str,
        *,
        fields: list[dict[str, Any]] | None = None,
        **extra: Any,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.status_code = status_code
        self.message = message
        self.fields = fields
        self.extra = extra


def socket_path() -> str:
    return (setting_env(SOCKET_ENV, DEFAULT_SOCKET) or DEFAULT_SOCKET).strip() or DEFAULT_SOCKET


def token_path() -> str:
    return (setting_env(TOKEN_ENV, DEFAULT_TOKEN_FILE) or DEFAULT_TOKEN_FILE).strip() or (
        DEFAULT_TOKEN_FILE
    )


def installed() -> bool:
    """The engine counts as installed when its admin socket exists."""
    try:
        return os.path.exists(socket_path())
    except OSError:
        return False


class _TokenCache:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._value: tuple[str, float, int, str] | None = None

    def read(self, path: str) -> str:
        try:
            info = os.stat(path)
        except OSError:
            raise DnsError(
                "dns_unreachable", 502, "The DNS engine token is not readable",
                reason="token_unavailable",
            ) from None
        with self._lock:
            cached = self._value
            if cached and cached[0] == path and cached[1] == info.st_mtime and cached[2] == (
                info.st_size
            ):
                return cached[3]
        try:
            with open(path, "rb") as handle:
                raw = handle.read(MAX_TOKEN_BYTES + 1)
        except OSError:
            raise DnsError(
                "dns_unreachable", 502, "The DNS engine token is not readable",
                reason="token_unavailable",
            ) from None
        token = raw.decode("ascii", errors="ignore").strip()
        if not token or len(raw) > MAX_TOKEN_BYTES or any(ch.isspace() for ch in token):
            raise DnsError(
                "dns_unreachable", 502, "The DNS engine token is invalid",
                reason="token_invalid",
            )
        with self._lock:
            self._value = (path, info.st_mtime, info.st_size, token)
        return token


TOKENS = _TokenCache()


def map_engine_error(status_code: int, body: bytes) -> DnsError:
    payload: Any = None
    try:
        payload = json.loads(body) if body else None
    except ValueError:
        payload = None
    error = payload.get("error") if isinstance(payload, dict) else None
    code = message = reason_code = None
    fields = None
    if isinstance(error, dict):
        raw_reason = error.get("reason_code")
        if isinstance(raw_reason, str) and raw_reason[:64].replace("_", "").isalnum():
            reason_code = raw_reason[:64]
        code = error.get("code") if isinstance(error.get("code"), str) else None
        message = error.get("message") if isinstance(error.get("message"), str) else None
        raw_fields = error.get("fields")
        if isinstance(raw_fields, list):
            fields = [
                {
                    key: value
                    for key, value in item.items()
                    if key in {"field", "reason_code", "message", "params"}
                }
                for item in raw_fields[:50]
                if isinstance(item, dict)
            ] or None
    elif isinstance(error, str):
        code = error
    if status_code == 401 or code in {"unauthorized", "auth_failed"}:
        return DnsError(
            "dns_unreachable", 502, "The DNS engine rejected the panel's token",
            reason="auth_failed",
        )
    if status_code >= 500 and code is None:
        return DnsError(
            "dns_unreachable", 502, f"The DNS engine returned HTTP {status_code}",
            reason="engine_error",
        )
    code = (code or "").strip()[:64]
    message = (message or f"The DNS engine refused the request ({code or status_code})")[:300]
    if code in ENGINE_CODES:
        panel_code, panel_status = ENGINE_CODES[code]
    elif code.startswith("dns_") or code == "invalid_zone_name":
        panel_code, panel_status = code, status_code
    elif code:
        panel_code, panel_status = f"dns_{code}", status_code
    else:
        panel_code, panel_status = "dns_engine_error", status_code
    if panel_status == 400:
        panel_status = 422
    if not 400 <= panel_status <= 599:
        panel_status = 502
    if reason_code and not fields:
        # D4 (tls_invalid …): the reason sits on the error itself.
        fields = [{"field": "body", "reason_code": reason_code}]
    return DnsError(panel_code, panel_status, message, fields=fields, engine_code=code or None,
                    reason_code=reason_code)


class DnsClient:
    """One short-lived httpx client per call; cheap over a unix socket."""

    def __init__(self, timeout: float = DEFAULT_TIMEOUT) -> None:
        self.timeout = timeout

    def _transport(self, path: str) -> httpx.AsyncBaseTransport:
        if TRANSPORT_FACTORY is not None:
            return TRANSPORT_FACTORY(path)
        return httpx.AsyncHTTPTransport(uds=path, retries=0)

    async def request(
        self,
        method: str,
        path: str,
        body: Any = None,
        *,
        timeout: float | None = None,
        expect_json: bool = True,
    ) -> Any:
        socket_file = socket_path()
        if not os.path.exists(socket_file):
            raise DnsError("dns_not_installed", 503, "The MRK DNS engine is not installed here")
        token = TOKENS.read(token_path())
        headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
        actor = CURRENT_ACTOR.get()
        if actor and method.upper() != "GET":
            # Only safe characters go into the header (user names are already restricted).
            headers["X-MRK-Actor"] = "".join(
                ch for ch in actor[:64] if ch.isalnum() or ch in "._@-"
            ) or "panel"
        content = b""
        if body is not None:
            content = json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode()
            headers["Content-Type"] = "application/json"
        limit = timeout if timeout is not None else self.timeout
        try:
            async with httpx.AsyncClient(
                transport=self._transport(socket_file),
                base_url="http://mrk-dns",
                timeout=httpx.Timeout(limit, connect=2.0),
                follow_redirects=False,
                trust_env=False,
            ) as client:
                request = client.build_request(method, path, content=content, headers=headers)
                response = await client.send(request, stream=True)
                try:
                    data = bytearray()
                    async for chunk in response.aiter_bytes():
                        data.extend(chunk)
                        if len(data) > MAX_RESPONSE_BYTES:
                            raise DnsError(
                                "dns_unreachable", 502, "The DNS engine answer is too large",
                                reason="response_too_large",
                            )
                finally:
                    await response.aclose()
        except httpx.TimeoutException:
            raise DnsError(
                "dns_unreachable", 502, "The DNS engine did not answer in time", reason="timeout"
            ) from None
        except (httpx.HTTPError, OSError) as exc:
            raise DnsError(
                "dns_unreachable", 502,
                f"The DNS engine is not answering ({type(exc).__name__})",
                reason="connect_failed",
            ) from None
        if response.status_code >= 400:
            raise map_engine_error(response.status_code, bytes(data))
        if not expect_json:
            return bytes(data).decode("utf-8", errors="replace")
        if not data:
            return {}
        try:
            return json.loads(bytes(data))
        except ValueError:
            if response.headers.get("content-type", "").startswith("text/"):
                return bytes(data).decode("utf-8", errors="replace")
            raise DnsError(
                "dns_unreachable", 502, "The DNS engine returned invalid JSON",
                reason="invalid_response",
            ) from None

    async def open_stream(
        self,
        path: str,
        *,
        max_bytes: int,
        max_seconds: float,
        read_timeout: float = 45.0,
        method: str = "GET",
        body: Any = None,
    ) -> EngineStream:
        """Start a streamed engine answer (NDJSON tail or export).

        Errors before the first byte (not installed, token, HTTP 4xx/5xx) raise
        ``DnsError`` like ``request``; afterwards the caller iterates the
        returned ``EngineStream`` and must ``aclose()`` it (also on cancel).
        """
        socket_file = socket_path()
        if not os.path.exists(socket_file):
            raise DnsError("dns_not_installed", 503, "The MRK DNS engine is not installed here")
        token = TOKENS.read(token_path())
        headers = {"Authorization": f"Bearer {token}", "Accept": "*/*"}
        content = b""
        if body is not None:
            content = json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode()
            headers["Content-Type"] = "application/json"
        client = httpx.AsyncClient(
            transport=self._transport(socket_file),
            base_url="http://mrk-dns",
            timeout=httpx.Timeout(read_timeout, connect=2.0),
            follow_redirects=False,
            trust_env=False,
        )
        try:
            request = client.build_request(method, path, content=content, headers=headers)
            response = await client.send(request, stream=True)
        except httpx.TimeoutException:
            await client.aclose()
            raise DnsError(
                "dns_unreachable", 502, "The DNS engine did not answer in time", reason="timeout"
            ) from None
        except (httpx.HTTPError, OSError) as exc:
            await client.aclose()
            raise DnsError(
                "dns_unreachable", 502,
                f"The DNS engine is not answering ({type(exc).__name__})",
                reason="connect_failed",
            ) from None
        except BaseException:
            await client.aclose()
            raise
        if response.status_code >= 400:
            try:
                data = bytearray()
                async for chunk in response.aiter_bytes():
                    data.extend(chunk)
                    if len(data) > 64 * 1024:
                        break
            except (httpx.HTTPError, OSError):
                data = bytearray()
            finally:
                await response.aclose()
                await client.aclose()
            raise map_engine_error(response.status_code, bytes(data))
        return EngineStream(client, response, max_bytes=max_bytes, max_seconds=max_seconds)

    async def get(self, path: str, **kwargs: Any) -> Any:
        return await self.request("GET", path, **kwargs)

    async def status(self) -> dict[str, Any]:
        payload = await self.request("GET", "/v1/status", timeout=3.0)
        if not isinstance(payload, dict):
            raise DnsError(
                "dns_unreachable", 502, "The DNS engine status is invalid",
                reason="invalid_response",
            )
        return payload


class StreamLimit(Exception):  # noqa: N818 - a normal end, not an error
    """A streamed answer reached the panel's byte or time limit."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason  # "max_bytes" | "max_seconds"


MAX_STREAM_LINE = 64 * 1024


class EngineStream:
    """An open streamed engine answer with byte and time limits.

    ``chunks()`` yields raw bytes, ``lines()`` NDJSON objects (bad lines are
    skipped). Both end with ``StreamLimit`` when a limit is reached; transport
    failures become ``DnsError(dns_unreachable)``. ``aclose()`` is idempotent
    and closes the engine connection, which ends the engine-side stream too.
    """

    def __init__(
        self, client: httpx.AsyncClient, response: httpx.Response, *, max_bytes: int,
        max_seconds: float,
    ) -> None:
        self._client = client
        self.response = response
        self.max_bytes = max_bytes
        self.deadline = time.monotonic() + max_seconds
        self.bytes_read = 0
        self.closed = False

    @property
    def content_type(self) -> str:
        return self.response.headers.get("content-type", "")

    async def chunks(self) -> AsyncIterator[bytes]:
        try:
            async for chunk in self.response.aiter_bytes():
                if not chunk:
                    continue
                self.bytes_read += len(chunk)
                if self.bytes_read > self.max_bytes:
                    raise StreamLimit("max_bytes")
                yield chunk
                if time.monotonic() > self.deadline:
                    raise StreamLimit("max_seconds")
        except httpx.TimeoutException:
            raise DnsError(
                "dns_unreachable", 502, "The DNS engine stopped sending", reason="timeout"
            ) from None
        except (httpx.HTTPError, OSError) as exc:
            raise DnsError(
                "dns_unreachable", 502,
                f"The DNS engine stream broke ({type(exc).__name__})", reason="connect_failed",
            ) from None

    async def lines(self) -> AsyncIterator[dict[str, Any]]:
        buffer = bytearray()
        skipping = False
        async for chunk in self.chunks():
            buffer.extend(chunk)
            while True:
                index = buffer.find(b"\n")
                if index < 0:
                    break
                line = bytes(buffer[:index])
                del buffer[: index + 1]
                if skipping:
                    skipping = False
                    continue
                item = _json_line(line)
                if item is not None:
                    yield item
            if len(buffer) > MAX_STREAM_LINE:
                buffer.clear()
                skipping = True
        if buffer and not skipping:
            item = _json_line(bytes(buffer))
            if item is not None:
                yield item

    async def aclose(self) -> None:
        if self.closed:
            return
        self.closed = True
        try:
            await self.response.aclose()
        except Exception:  # noqa: BLE001, S110 - closing a broken stream
            pass
        try:
            await self._client.aclose()
        except Exception:  # noqa: BLE001, S110
            pass


def _json_line(line: bytes) -> dict[str, Any] | None:
    line = line.strip()
    if not line:
        return None
    try:
        value = json.loads(line)
    except ValueError:
        return None
    return value if isinstance(value, dict) else None
