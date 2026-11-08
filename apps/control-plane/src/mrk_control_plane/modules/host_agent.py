"""Host Agent module: pairing, status, and read-only Docker/host views via mrk-agent.

The agent is optional. Without it the appliance works as before and this module
only reports ``configured: false``. Configuration comes from the panel
(``data_dir/control-plane/agent.json`` + SecretStore) or, if both MRK_AGENT_URL
and MRK_AGENT_KEY_FILE are set, from the environment (env wins, read-only in UI).
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import secrets
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx
from fastapi import APIRouter, Request
from pydantic import BaseModel, ConfigDict, Field

from ..agent.signing import KEY_BYTES, decode_key, encode_key, sign_headers
from ..module_context import Event, ModuleContext

LOGGER = logging.getLogger(__name__)
MODULE_NAME = "host_agent"
CONFIG_FILE = "agent.json"
DEDUPE_KEY = "agent.reachability"
REQUEST_TIMEOUT_SECONDS = 5.0
STATUS_REFRESH_SECONDS = 10.0
_MAX_RESPONSE_BYTES = 4 * 1024 * 1024

# Tests replace this with a factory returning e.g. httpx.ASGITransport(agent_app).
TRANSPORT_FACTORY: Callable[[], httpx.AsyncBaseTransport] | None = None


class AgentConfigRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    url: str = Field(min_length=8, max_length=2048)
    key: str | None = Field(default=None, min_length=40, max_length=64)


class AgentUnpairRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    confirmation: str = Field(min_length=1, max_length=32)


class AgentError(Exception):
    def __init__(self, code: str, status_code: int, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.status_code = status_code
        self.message = message


def validate_agent_url(value: str) -> str:
    """Our own component, so private/compose addresses are fine; shape is still strict."""
    text = value.strip()
    try:
        parts = urlsplit(text)
        port = parts.port
    except ValueError as exc:
        raise ValueError("agent URL is invalid") from exc
    if parts.scheme not in {"http", "https"}:
        raise ValueError("agent URL must use http or https")
    if not parts.hostname:
        raise ValueError("agent URL must include a host")
    if parts.username is not None or parts.password is not None or "@" in parts.netloc:
        raise ValueError("agent URL must not contain credentials")
    if parts.query or parts.fragment or parts.path not in {"", "/"}:
        raise ValueError("agent URL must not contain a path, query or fragment")
    if any(char.isspace() for char in text):
        raise ValueError("agent URL is invalid")
    netloc = parts.hostname if ":" not in parts.hostname else f"[{parts.hostname}]"
    if port is not None:
        netloc = f"{netloc}:{port}"
    return f"{parts.scheme}://{netloc}"


class HostAgentService:
    def __init__(self, ctx: ModuleContext) -> None:
        self.ctx = ctx
        self.config_path = ctx.data_dir / "control-plane" / CONFIG_FILE
        self.interval = self._interval()
        self._lock = asyncio.Lock()
        self._task: asyncio.Task[None] | None = None
        self.reachable: bool | None = None
        self.last_checked_at: float | None = None
        self.last_error: str | None = None
        self.info: dict[str, Any] | None = None

    @staticmethod
    def _interval() -> int:
        try:
            value = int(os.getenv("MRK_AGENT_CHECK_INTERVAL_SECONDS", "60"))
        except ValueError:
            value = 60
        return min(max(value, 5), 3600)

    # ----- configuration -------------------------------------------------
    def _env_config(self) -> tuple[str, bytes] | None:
        url = os.getenv("MRK_AGENT_URL", "").strip()
        key_file = os.getenv("MRK_AGENT_KEY_FILE", "").strip()
        if not url or not key_file:
            return None
        raw = Path(key_file).read_bytes()
        key = raw if len(raw) == KEY_BYTES else decode_key(raw.decode("ascii"))
        return validate_agent_url(url), key

    def env_managed(self) -> bool:
        return bool(os.getenv("MRK_AGENT_URL", "").strip() and os.getenv(
            "MRK_AGENT_KEY_FILE", ""
        ).strip())

    def _panel_file(self) -> dict[str, Any] | None:
        if not self.config_path.exists():
            return None
        payload = json.loads(self.config_path.read_text(encoding="utf-8"))
        return payload if isinstance(payload, dict) else None

    def resolve(self) -> tuple[str | None, str | None, bytes | None]:
        """Return (source, url, key). Invalid stored config resolves to unconfigured."""
        if self.env_managed():
            try:
                env = self._env_config()
            except (OSError, ValueError) as exc:
                self.last_error = f"environment configuration invalid: {type(exc).__name__}"
                return "env", os.getenv("MRK_AGENT_URL", "").strip() or None, None
            assert env is not None
            return "env", env[0], env[1]
        try:
            stored = self._panel_file()
        except (OSError, ValueError):
            return None, None, None
        if not stored or not isinstance(stored.get("url"), str):
            return None, None, None
        key: bytes | None = None
        reference = stored.get("secret_ref")
        if isinstance(reference, str):
            try:
                key = decode_key(self.ctx.secret_store.get(reference)["key"])
            except (KeyError, ValueError):
                key = None
        return "panel", stored["url"], key

    def _write_panel(self, url: str, reference: str) -> None:
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.config_path.with_name(f".{CONFIG_FILE}.{secrets.token_hex(4)}.tmp")
        temporary.write_text(
            json.dumps({"url": url, "secret_ref": reference, "updated_at": int(time.time())})
            + "\n",
            encoding="utf-8",
        )
        temporary.chmod(0o600)
        os.replace(temporary, self.config_path)

    def save(self, url: str, key_text: str | None) -> None:
        normalized = validate_agent_url(url)
        stored = self._panel_file() or {}
        reference = stored.get("secret_ref") if isinstance(stored.get("secret_ref"), str) else None
        if key_text is not None:
            key = decode_key(key_text)
            reference, _ = self.ctx.secret_store.replace(reference, {"key": encode_key(key)})
        elif reference is None:
            raise AgentError("agent_key_required", 422, "A pairing key is required")
        else:
            try:
                self.ctx.secret_store.get(reference)
            except (KeyError, ValueError) as exc:
                raise AgentError("agent_key_required", 422, "A pairing key is required") from exc
        self._write_panel(normalized, reference)
        self._reset()

    def unpair(self) -> None:
        stored = self._panel_file() or {}
        reference = stored.get("secret_ref")
        if isinstance(reference, str):
            self.ctx.secret_store.delete(reference)
        self.config_path.unlink(missing_ok=True)
        self._reset()

    def _reset(self) -> None:
        self.reachable = None
        self.last_checked_at = None
        self.last_error = None
        self.info = None

    # ----- outbound calls ------------------------------------------------
    def _client(
        self, url: str, timeout: httpx.Timeout | float | None = None
    ) -> httpx.AsyncClient:
        transport = TRANSPORT_FACTORY() if TRANSPORT_FACTORY is not None else None
        if timeout is None:
            timeout = httpx.Timeout(REQUEST_TIMEOUT_SECONDS, connect=3.0)
        elif not isinstance(timeout, httpx.Timeout):
            timeout = httpx.Timeout(timeout, connect=3.0)
        return httpx.AsyncClient(
            base_url=url,
            transport=transport,
            timeout=timeout,
            follow_redirects=False,
            trust_env=False,
        )

    def _target(self) -> tuple[str, bytes]:
        source, url, key = self.resolve()
        if source is None or url is None:
            raise AgentError("agent_not_configured", 409, "The host agent is not configured")
        if key is None:
            raise AgentError("agent_auth_failed", 502, "The agent pairing key is unavailable")
        return url, key

    @staticmethod
    def _signed_request(
        client: httpx.AsyncClient, key: bytes, method: str, path: str, body: Any
    ) -> httpx.Request:
        raw_body = b"" if body is None else json.dumps(body, separators=(",", ":")).encode()
        headers = {"Content-Type": "application/json"} if body is not None else {}
        request = client.build_request(method, path, content=raw_body, headers=headers)
        raw_path = request.url.raw_path.decode("ascii")
        request.headers.update(sign_headers(key, method, raw_path, raw_body))
        return request

    @staticmethod
    def _raise_for_status(status_code: int, body: bytes) -> None:
        if status_code in (200, 201, 202):
            return
        error: str | None = None
        try:
            payload = json.loads(body) if body else None
            if isinstance(payload, dict) and isinstance(payload.get("error"), str):
                error = payload["error"][:80]
        except ValueError:
            error = None
        if status_code == 401:
            raise AgentError("agent_auth_failed", 502, "The agent rejected the signature")
        if status_code == 503:
            raise AgentError(
                "agent_docker_unavailable", 503, "Docker is unavailable on the agent host"
            )
        if status_code == 403 and error == "protected":
            raise AgentError(
                "container_protected", 403, "The container is protected by the agent"
            )
        if status_code == 403 and error:
            # e.g. volume_unreadable: report the real reason, not "unreachable".
            raise AgentError(error, 403, f"The agent refused the request ({error})")
        if status_code == 404 and error == "traefik_disabled":
            raise AgentError(
                "traefik_disabled", 409, "The agent has no Traefik dynamic directory configured"
            )
        if status_code == 404:
            raise AgentError("agent_not_found", 404, "The agent could not find that object")
        if status_code == 409 and error == "plan_changed":
            raise AgentError(
                "plan_changed", 409, "The prune plan changed; preview again before pruning"
            )
        if status_code in (400, 422):
            raise AgentError(
                "agent_rejected", 422, f"The agent rejected the request ({error or 'invalid'})"
            )
        if status_code == 504:
            raise AgentError("agent_timeout", 504, "The agent timed out")
        raise AgentError("agent_unreachable", 502, f"The agent returned HTTP {status_code}")

    async def request(
        self,
        method: str,
        path: str,
        body: Any = None,
        *,
        timeout: float | None = None,
        max_bytes: int = _MAX_RESPONSE_BYTES,
    ) -> Any:
        """Signed JSON request to the agent. Raises AgentError with a stable code."""
        url, key = self._target()
        async with self._client(url, timeout) as client:
            request = self._signed_request(client, key, method, path, body)
            try:
                response = await client.send(request, stream=True)
                try:
                    data = bytearray()
                    async for chunk in response.aiter_bytes():
                        data.extend(chunk)
                        if len(data) > max_bytes:
                            raise AgentError(
                                "agent_unreachable", 502, "The agent response is too large"
                            )
                finally:
                    await response.aclose()
            except httpx.TimeoutException as exc:
                raise AgentError("agent_timeout", 504, "The agent timed out") from exc
            except httpx.HTTPError as exc:
                raise AgentError(
                    "agent_unreachable", 502, f"The agent is unreachable ({type(exc).__name__})"
                ) from exc
        self._raise_for_status(response.status_code, bytes(data))
        try:
            return json.loads(bytes(data))
        except ValueError as exc:
            raise AgentError("agent_unreachable", 502, "The agent returned invalid JSON") from exc

    async def call(self, path: str) -> Any:
        return await self.request("GET", path)

    async def open_stream(self, path: str) -> tuple[httpx.AsyncClient, httpx.Response]:
        """Open a signed streaming GET. The caller must close both response and client."""
        url, key = self._target()
        client = self._client(url, httpx.Timeout(connect=3.0, read=None, write=5.0, pool=5.0))
        try:
            request = self._signed_request(client, key, "GET", path, None)
            try:
                response = await client.send(request, stream=True)
            except httpx.TimeoutException as exc:
                raise AgentError("agent_timeout", 504, "The agent timed out") from exc
            except httpx.HTTPError as exc:
                raise AgentError(
                    "agent_unreachable", 502, f"The agent is unreachable ({type(exc).__name__})"
                ) from exc
            if response.status_code != 200:
                try:
                    body = await response.aread()
                except httpx.HTTPError:
                    body = b""
                finally:
                    await response.aclose()
                self._raise_for_status(response.status_code, body[:65536])
                raise AgentError(
                    "agent_unreachable", 502, f"The agent returned HTTP {response.status_code}"
                )
        except BaseException:
            await client.aclose()
            raise
        return client, response

    async def probe(self) -> tuple[bool, float, str | None]:
        """Call /v1/info, update cached state, emit events on transitions."""
        async with self._lock:
            started = time.perf_counter()
            error_code: str | None = None
            try:
                info = await self.call("/v1/info")
                if not isinstance(info, dict):
                    raise AgentError("agent_unreachable", 502, "unexpected agent payload")
                self.info = info
                self.last_error = None
                ok = True
            except AgentError as exc:
                if exc.code == "agent_not_configured":
                    self._reset()
                    return False, 0.0, exc.code
                error_code = exc.code
                self.last_error = exc.message
                ok = False
            latency_ms = round((time.perf_counter() - started) * 1000, 1)
            self.last_checked_at = time.time()
            previous = self.reachable
            self.reachable = ok
            self._publish_transition(previous, ok, error_code)
            return ok, latency_ms, error_code

    def _publish_transition(self, previous: bool | None, ok: bool, error_code: str | None) -> None:
        if ok and previous is False:
            self.ctx.events.publish(
                Event(
                    type="agent.online",
                    severity="info",
                    title="Host agent is reachable again",
                    module=MODULE_NAME,
                    dedupe_key=DEDUPE_KEY,
                )
            )
        elif not ok and previous is not False:
            self.ctx.events.publish(
                Event(
                    type="agent.offline",
                    severity="error",
                    title="Host agent is unreachable",
                    message=self.last_error or "",
                    module=MODULE_NAME,
                    dedupe_key=DEDUPE_KEY,
                    details={"error_code": error_code},
                )
            )

    # ----- status --------------------------------------------------------
    async def status(self, *, refresh: bool = True) -> dict[str, Any]:
        source, url, _key = self.resolve()
        configured = source is not None and url is not None
        if (
            configured
            and refresh
            and (
                self.last_checked_at is None
                or time.time() - self.last_checked_at > STATUS_REFRESH_SECONDS
            )
        ):
            await self.probe()
        info = self.info if configured and self.reachable else None
        return {
            "configured": configured,
            "source": source,
            "url": url,
            "reachable": self.reachable if configured else None,
            "last_checked_at": self.last_checked_at,
            "last_error": self.last_error if configured else None,
            "version": info.get("version") if info else None,
            "capabilities": info.get("capabilities") if info else None,
            "docker": info.get("docker") if info else None,
            "host": info.get("host") if info else None,
            "check_interval_seconds": self.interval,
        }

    # ----- background ----------------------------------------------------
    async def _loop(self) -> None:
        while True:
            try:
                source, url, _key = self.resolve()
                if source is not None and url is not None:
                    await self.probe()
            except asyncio.CancelledError:
                raise
            except Exception:
                LOGGER.exception("host agent probe failed")
            await asyncio.sleep(self.interval)

    async def start(self) -> None:
        self._task = asyncio.create_task(self._loop(), name="mrk-host-agent-probe")

    async def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None


def register(ctx: ModuleContext) -> None:
    service = HostAgentService(ctx)
    router = APIRouter(prefix="/api/v1/agent", tags=["host-agent"])

    def failure(exc: AgentError):
        return ctx.error_payload(exc.code, exc.message, exc.status_code)

    @router.get("/status")
    async def agent_status(request: Request):
        ctx.require_principal(request, "agent:read")
        return await service.status()

    @router.put("/config")
    async def agent_config(request: Request, body: AgentConfigRequest):
        principal = ctx.require_principal(request, "agent:write")
        ctx.require_csrf(request, principal)
        if service.env_managed():
            return ctx.error_payload(
                "agent_managed_by_environment",
                "The host agent is managed by environment variables",
                409,
            )
        try:
            await asyncio.to_thread(service.save, body.url, body.key)
        except AgentError as exc:
            return failure(exc)
        except ValueError as exc:
            message = str(exc)
            code = "invalid_agent_key" if "key" in message else "invalid_agent_url"
            return ctx.error_payload(code, message, 422)
        await asyncio.to_thread(
            ctx.audit, principal.user_id, "agent.config.update", "agent", "host-agent"
        )
        return await service.status()

    @router.delete("/config")
    async def agent_unpair(request: Request, body: AgentUnpairRequest):
        principal = ctx.require_principal(request, "agent:write")
        ctx.require_csrf(request, principal)
        if body.confirmation != "UNPAIR":
            return ctx.error_payload(
                "confirmation_required", 'Type "UNPAIR" to confirm', 422
            )
        if service.env_managed():
            return ctx.error_payload(
                "agent_managed_by_environment",
                "The host agent is managed by environment variables",
                409,
            )
        await asyncio.to_thread(service.unpair)
        await asyncio.to_thread(
            ctx.audit, principal.user_id, "agent.unpair", "agent", "host-agent"
        )
        return await service.status(refresh=False)

    @router.post("/test")
    async def agent_test(request: Request):
        principal = ctx.require_principal(request, "agent:write")
        ctx.require_csrf(request, principal)
        source, url, _key = service.resolve()
        if source is None or url is None:
            return ctx.error_payload(
                "agent_not_configured", "The host agent is not configured", 409
            )
        ok, latency_ms, error_code = await service.probe()
        await asyncio.to_thread(
            ctx.audit,
            principal.user_id,
            "agent.test",
            "agent",
            "host-agent",
            "success" if ok else "failure",
        )
        result: dict[str, Any] = {"ok": ok, "latency_ms": latency_ms}
        if error_code:
            result["error_code"] = error_code
        return result

    @router.get("/containers")
    async def agent_containers(request: Request):
        ctx.require_principal(request, "agent:read")
        try:
            return await service.call("/v1/docker/containers")
        except AgentError as exc:
            return failure(exc)

    @router.get("/summary")
    async def agent_summary(request: Request):
        ctx.require_principal(request, "agent:read")
        try:
            return await service.call("/v1/docker/summary")
        except AgentError as exc:
            return failure(exc)

    from .host_agent_docker import add_docker_routes

    jobs = add_docker_routes(ctx, router, service)

    ctx.routers.append(router)
    ctx.start_hooks.append(service.start)
    ctx.stop_hooks.append(service.stop)
    ctx.stop_hooks.append(jobs.stop)
