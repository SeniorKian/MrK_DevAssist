"""The mrk-agent HTTP API (FastAPI). Every route except /v1/health is HMAC-signed.

Gate 16 routes are GET only. Gate 17 adds the POST routes in ``_POST_ROUTES``
(container actions, image pull, prune preview/execute); any other non-GET request
is rejected with 405 before authentication, and every request's body hash is part
of the signature.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import re
import time
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, StreamingResponse

from . import AGENT_VERSION, cgroups, dns_facts, host_metrics
from . import backup as backup_sources
from . import traefik as traefik_files
from .docker_client import (
    DEFAULT_SOCKET,
    DockerClient,
    DockerNotAllowed,
    DockerRequestFailed,
    DockerUnavailable,
    container_labels,
    container_names,
    parse_image_reference,
    summarize_container,
    summarize_df,
    summarize_image,
    validate_container_ref,
)
from .logs import LogDecoder, line_size
from .protection import ProtectionRules
from .prune import PlanRequestError, build_plan, parse_plan_request
from .signing import RequestVerifier, SignatureError

LOGGER = logging.getLogger("mrk_control_plane.agent")
_MAX_BODY_BYTES = 64 * 1024
_MAX_LOG_TAIL = 5000
_MAX_LOG_BYTES = 5 * 1024 * 1024
_MAX_PULL_LINE = 64 * 1024
_CONTAINER_CACHE_SECONDS = 10.0
_DOCKER_FACTS_CACHE_SECONDS = 30.0
_DOCKER_FACTS_FAILURE_CACHE_SECONDS = 5.0
_DISCONNECT_POLL_SECONDS = 5.0
_POST_ROUTES = (
    re.compile(r"^/v1/docker/containers/[^/]+/(start|stop|restart)$"),
    re.compile(r"^/v1/docker/images/pull$"),
    re.compile(r"^/v1/docker/prune/preview$"),
    re.compile(r"^/v1/docker/prune$"),
    re.compile(r"^/v1/backup/db/[^/]+/dump$"),
    re.compile(r"^/v1/traefik/domains$"),
    re.compile(r"^/v1/traefik/domains/delete$"),
)


@dataclass(slots=True)
class AgentConfig:
    key: bytes
    docker_socket: str = DEFAULT_SOCKET
    proc_dir: Path = field(default_factory=lambda: Path("/proc"))
    root_paths: list[Path] = field(default_factory=lambda: [Path("/")])
    protection: ProtectionRules = field(default_factory=ProtectionRules.default)
    docker_timeout_seconds: float = 5.0
    cgroup_dir: Path = field(default_factory=lambda: Path(cgroups.DEFAULT_HOST_CGROUP))
    log_follow_max_seconds: float = 600.0
    pull_max_seconds: float = 600.0
    volumes_root: Path = field(
        default_factory=lambda: Path(backup_sources.DEFAULT_VOLUMES_ROOT)
    )
    backup_max_seconds: float = 6 * 3600.0
    # Read-only host root for the DNS setup facts (docs/37); None = not mounted.
    host_root: Path | None = field(default_factory=lambda: _default_host_root())

    @classmethod
    def from_env(cls, key: bytes) -> AgentConfig:
        try:
            timeout = float(os.getenv("MRK_AGENT_DOCKER_TIMEOUT_SECONDS", "5"))
        except ValueError as exc:
            raise ValueError("MRK_AGENT_DOCKER_TIMEOUT_SECONDS must be a number") from exc
        return cls(
            key=key,
            docker_socket=os.getenv("MRK_AGENT_DOCKER_SOCKET", "").strip() or DEFAULT_SOCKET,
            proc_dir=host_metrics.resolve_proc_dir(),
            root_paths=host_metrics.resolve_root_paths(),
            protection=ProtectionRules.from_env(),
            docker_timeout_seconds=min(max(timeout, 1.0), 60.0),
            cgroup_dir=cgroups.resolve_cgroup_dir(),
            volumes_root=Path(
                os.getenv("MRK_AGENT_HOST_VOLUMES", "").strip()
                or backup_sources.DEFAULT_VOLUMES_ROOT
            ),
            backup_max_seconds=_backup_max_seconds(),
        )


def _default_host_root() -> Path | None:
    root = Path(host_metrics.DEFAULT_HOST_ROOT)
    return root if root.is_dir() else None


def _backup_max_seconds() -> float:
    try:
        value = float(os.getenv("MRK_AGENT_BACKUP_MAX_SECONDS", str(6 * 3600)))
    except ValueError as exc:
        raise ValueError("MRK_AGENT_BACKUP_MAX_SECONDS must be a number") from exc
    return min(max(value, 60.0), 7 * 24 * 3600.0)


def _display_path(path: str) -> str:
    prefix = host_metrics.DEFAULT_HOST_ROOT
    if path == prefix or path.startswith(prefix + "/"):
        return "/" + path[len(prefix) :].lstrip("/")
    return path


def _error(code: str, status_code: int, **extra: Any) -> JSONResponse:
    return JSONResponse(status_code=status_code, content={"error": code, **extra})


def _docker_error(exc: DockerUnavailable) -> JSONResponse:
    if isinstance(exc, DockerRequestFailed):
        if exc.status_code == 404:
            return _error("not_found", 404)
        return _error("docker_error", 502, status=exc.status_code, message=exc.message)
    return _error("docker_unavailable", 503)


def _post_allowed(path: str) -> bool:
    return any(pattern.fullmatch(path) for pattern in _POST_ROUTES)


class SignatureMiddleware:
    """Pure ASGI (not BaseHTTPMiddleware) so streamed responses see client disconnects."""

    def __init__(self, app: Any, verifier: RequestVerifier) -> None:
        self.app = app
        self.verifier = verifier

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        method = scope["method"]
        path = scope["path"]
        if path == "/v1/health" and method == "GET":
            await self.app(scope, receive, send)
            return
        if method != "GET" and not (method == "POST" and _post_allowed(path)):
            await _error("method_not_allowed", 405)(scope, receive, send)
            return
        body = bytearray()
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            body.extend(message.get("body", b""))
            if len(body) > _MAX_BODY_BYTES:
                await _error("body_too_large", 413)(scope, receive, send)
                return
            if not message.get("more_body", False):
                break
        raw_path = scope.get("raw_path") or path.encode()
        query = scope.get("query_string") or b""
        path_with_query = raw_path.decode("latin-1") + (
            "?" + query.decode("latin-1") if query else ""
        )
        headers = {
            key.decode("latin-1"): value.decode("latin-1")
            for key, value in scope.get("headers") or []
        }
        try:
            self.verifier.verify(method, path_with_query, headers, bytes(body))
        except SignatureError as exc:
            LOGGER.warning("rejected unauthenticated request", extra={"reason": exc.reason})
            await _error("auth_failed", 401, reason=exc.reason)(scope, receive, send)
            return
        replayed = False

        async def replay() -> dict[str, Any]:
            nonlocal replayed
            if not replayed:
                replayed = True
                return {"type": "http.request", "body": bytes(body), "more_body": False}
            return await receive()

        await self.app(scope, replay, send)


async def _json_body(request: Request) -> object:
    raw = await request.body()
    if not raw.strip():
        return {}
    try:
        return json.loads(raw)
    except ValueError:
        return None


def _parse_int(value: str | None, *, low: int, high: int) -> int | None:
    if value is None or not re.fullmatch(r"[0-9]{1,12}", value):
        raise ValueError
    number = int(value)
    if not low <= number <= high:
        raise ValueError
    return number


def create_agent_app(
    config: AgentConfig, *, docker_transport: httpx.AsyncBaseTransport | None = None
) -> FastAPI:
    verifier = RequestVerifier(config.key)
    docker = DockerClient(
        config.docker_socket,
        transport=docker_transport,
        timeout_seconds=config.docker_timeout_seconds,
    )
    docker_possible = docker_transport is not None or Path(config.docker_socket).exists()
    cpu_sampler = host_metrics.CpuSampler()
    container_cache: dict[str, Any] = {"at": 0.0, "items": None}
    # /v1/info is the panel's reachability probe: serve Docker facts from a short
    # cache (one refresh at a time) so a slow daemon at 0.5 CPU never makes the
    # probe itself slow. A failed refresh is cached briefly too.
    docker_facts: dict[str, Any] = {"at": None, "value": None}
    docker_facts_lock = asyncio.Lock()
    prune_lock = asyncio.Lock()

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        LOGGER.info(
            "mrk-agent started",
            extra={
                "docker_socket_present": docker_possible,
                "host_proc": str(config.proc_dir),
                "host_cgroup": str(config.cgroup_dir),
            },
        )
        try:
            yield
        finally:
            await docker.aclose()
            LOGGER.info("mrk-agent stopped")

    app = FastAPI(
        title="mrk-agent",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )
    app.state.verifier = verifier
    app.state.docker = docker
    app.add_middleware(SignatureMiddleware, verifier=verifier)

    @app.get("/v1/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    async def docker_overview() -> dict[str, Any] | None:
        if not docker_possible:
            return None

        def fresh() -> bool:
            at = docker_facts["at"]
            if at is None:
                return False
            ttl = (_DOCKER_FACTS_CACHE_SECONDS if docker_facts["value"] is not None
                   else _DOCKER_FACTS_FAILURE_CACHE_SECONDS)
            return time.monotonic() - at < ttl

        if not fresh():
            async with docker_facts_lock:
                if not fresh():
                    docker_facts["value"] = await read_docker_facts()
                    docker_facts["at"] = time.monotonic()
        value = docker_facts["value"]
        return dict(value) if value is not None else None

    async def read_docker_facts() -> dict[str, Any] | None:
        try:
            if docker.api_version is None:
                # First call negotiates the API version that info() needs.
                version = await docker.version()
                info = await docker.info()
            else:
                # Both at once: the probe waits for one Docker timeout, not two.
                version, info = await asyncio.gather(docker.version(), docker.info())
        except DockerUnavailable as exc:
            LOGGER.warning("docker unavailable", extra={"reason": str(exc)})
            return None
        return {
            "version": docker.engine_version or str(version.get("Version", ""))[:64],
            "api_version": docker.api_version,
            "containers_running": info.get("ContainersRunning")
            if isinstance(info.get("ContainersRunning"), int)
            else None,
            "containers_total": info.get("Containers")
            if isinstance(info.get("Containers"), int)
            else None,
            # The daemon reports the real host name; files under a mounted
            # root can belong to a VM image (e.g. Docker Desktop).
            "host_name": str(info.get("Name", ""))[:253] or None,
        }

    def host_overview() -> dict[str, Any] | None:
        if not host_metrics.available(config.proc_dir):
            return None
        data = host_metrics.collect(config.proc_dir, config.root_paths)
        for disk in data["disks"]:
            disk["path"] = _display_path(disk["path"])
        return data

    @app.get("/v1/info")
    async def info() -> dict[str, Any]:
        docker_data = await docker_overview()
        host = await asyncio.to_thread(host_overview)
        daemon_host = docker_data.pop("host_name", None) if docker_data else None
        if host is not None and daemon_host:
            host["hostname"] = daemon_host
        return {
            "version": AGENT_VERSION,
            "capabilities": {
                "docker": docker_data is not None,
                "host_metrics": host is not None,
                "firewall": False,
                "traefik_file": traefik_files.resolve_dir() is not None,
                "dns_facts": True,
            },
            "docker": docker_data,
            "host": host,
        }

    @app.get("/v1/docker/containers")
    async def containers():
        if not docker_possible:
            return _error("docker_unavailable", 503)
        try:
            raw = await docker.containers()
        except DockerUnavailable:
            return _error("docker_unavailable", 503)
        except DockerNotAllowed:  # pragma: no cover - fixed call, defensive only
            return _error("not_allowed", 403)
        rules = config.protection
        items = [
            summarize_container(
                item,
                rules.is_protected(container_names(item), container_labels(item)),
                rules.label_prefixes,
            )
            for item in raw
        ]
        items.sort(key=lambda item: item["name"])
        return {"items": items}

    @app.get("/v1/docker/summary")
    async def summary():
        if not docker_possible:
            return _error("docker_unavailable", 503)
        try:
            images, volumes, networks, df = await asyncio.gather(
                docker.images(), docker.volumes(), docker.networks(), docker.system_df()
            )
        except DockerUnavailable:
            return _error("docker_unavailable", 503)
        return {
            "images": len(images),
            "volumes": len(volumes),
            "networks": len(networks),
            "disk_usage": summarize_df(df),
        }

    @app.get("/v1/docker/images")
    async def images_list():
        """Read-only image list for update tracking (Gate 18 S10)."""
        if not docker_possible:
            return _error("docker_unavailable", 503)
        try:
            raw = await docker.images()
        except DockerUnavailable:
            return _error("docker_unavailable", 503)
        return {"items": [summarize_image(item) for item in raw if isinstance(item, dict)]}

    # ----- Gate 17: metrics ---------------------------------------------------

    async def cached_containers() -> list[dict[str, Any]]:
        now = time.monotonic()
        items = container_cache["items"]
        if items is None or now - container_cache["at"] > _CONTAINER_CACHE_SECONDS:
            items = await docker.containers()
            container_cache.update(at=now, items=items)
        return items

    def read_container_metrics(raw: list[dict[str, Any]]) -> list[dict[str, Any]]:
        rules = config.protection
        result = []
        for item in raw:
            container_id = str(item.get("Id", ""))
            counters = cgroups.read_container(config.cgroup_dir, container_id)
            if counters is None:
                continue  # not running, or not in a known cgroup layout
            names = container_names(item)
            result.append(
                {
                    "id": container_id,
                    "name": names[0].lstrip("/") if names else "",
                    "protected": rules.is_protected(names, container_labels(item)),
                    **counters,
                }
            )
        result.sort(key=lambda entry: entry["name"])
        return result

    def host_metrics_now() -> dict[str, Any] | None:
        if not host_metrics.available(config.proc_dir):
            return None
        data = host_metrics.collect_metrics_host(config.proc_dir, config.root_paths, cpu_sampler)
        for disk in data["disks"]:
            disk["path"] = _display_path(disk["path"])
        return data

    @app.get("/v1/metrics")
    async def metrics() -> dict[str, Any]:
        host = await asyncio.to_thread(host_metrics_now)
        containers_data: list[dict[str, Any]] | None = None
        if docker_possible and cgroups.available(config.cgroup_dir):
            try:
                raw = await cached_containers()
            except DockerUnavailable:
                raw = None
            if raw is not None:
                containers_data = await asyncio.to_thread(read_container_metrics, raw)
        return {"ts": round(time.time(), 3), "host": host, "containers": containers_data}

    # ----- Gate 17: logs ------------------------------------------------------

    @app.get("/v1/docker/containers/{ref}/logs")
    async def container_logs(ref: str, request: Request):
        if not docker_possible:
            return _error("docker_unavailable", 503)
        query = request.query_params
        try:
            validate_container_ref(ref)
        except DockerNotAllowed:
            return _error("invalid_container", 422)
        values: dict[str, int | None] = {}
        for name, default, low, high in (
            ("tail", "200", 0, _MAX_LOG_TAIL),
            ("since", None, 0, 10**12 - 1),
            ("until", None, 0, 10**12 - 1),
            ("timestamps", "1", 0, 1),
            ("follow", "0", 0, 1),
        ):
            raw_value = query.get(name, default)
            try:
                values[name] = None if raw_value is None else _parse_int(
                    raw_value, low=low, high=high
                )
            except ValueError:
                return _error("invalid_query", 422, field=name)
        since, until = values["since"], values["until"]
        if since is not None and until is not None and until < since:
            return _error("invalid_query", 422, field="until")
        follow = values["follow"] == 1
        try:
            inspected = await docker.inspect_container(ref)
        except DockerUnavailable as exc:
            return _docker_error(exc)
        container_id = str(inspected.get("Id", ""))
        if not re.fullmatch(r"[0-9a-f]{64}", container_id):
            return _error("not_found", 404)
        container_config = inspected.get("Config")
        tty = bool(container_config.get("Tty")) if isinstance(container_config, dict) else False
        params = {"stdout": "1", "stderr": "1", "timestamps": "1", "tail": str(values["tail"])}
        if since is not None:
            params["since"] = str(since)
        if until is not None:
            params["until"] = str(until)
        if follow:
            params["follow"] = "1"
        try:
            response = await docker.open_stream("GET", f"/containers/{container_id}/logs", params)
        except DockerUnavailable as exc:
            return _docker_error(exc)
        decoder = LogDecoder(tty, timestamps=values["timestamps"] == 1)

        if not follow:
            lines: list[dict[str, Any]] = []
            size = 0
            truncated = False
            try:
                async with asyncio.timeout(max(config.docker_timeout_seconds * 6, 30.0)):
                    async for chunk in response.aiter_bytes():
                        for line in decoder.feed(chunk):
                            size += line_size(line)
                            if size > _MAX_LOG_BYTES:
                                truncated = True
                                break
                            lines.append(line)
                        if truncated:
                            break
            except (TimeoutError, httpx.HTTPError):
                truncated = True
            finally:
                await response.aclose()
            if not truncated:
                for line in decoder.flush():
                    size += line_size(line)
                    if size > _MAX_LOG_BYTES:
                        truncated = True
                        break
                    lines.append(line)
            return {"lines": lines, "truncated": truncated}

        async def stream() -> AsyncIterator[bytes]:
            loop = asyncio.get_running_loop()
            deadline = loop.time() + config.log_follow_max_seconds
            chunks: asyncio.Queue[bytes | None] = asyncio.Queue(maxsize=32)

            async def pump() -> None:
                try:
                    async for chunk in response.aiter_bytes():
                        await chunks.put(chunk)
                except httpx.HTTPError:
                    pass
                finally:
                    with contextlib.suppress(asyncio.QueueFull):
                        chunks.put_nowait(None)

            reader = asyncio.create_task(pump())
            try:
                while True:
                    remaining = deadline - loop.time()
                    if remaining <= 0:
                        break
                    try:
                        chunk = await asyncio.wait_for(
                            chunks.get(), min(remaining, _DISCONNECT_POLL_SECONDS)
                        )
                    except TimeoutError:
                        # A quiet container sends nothing; notice a gone client anyway.
                        if await request.is_disconnected():
                            break
                        continue
                    if chunk is None:
                        break
                    lines_out = decoder.feed(chunk)
                    if lines_out:
                        yield b"".join(_ndjson(line) for line in lines_out)
                tail_lines = decoder.flush()
                if tail_lines:
                    yield b"".join(_ndjson(line) for line in tail_lines)
            finally:
                # Runs on normal end, the 600 s cap and client disconnect.
                reader.cancel()
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await reader
                await response.aclose()

        return StreamingResponse(
            stream(),
            media_type="application/x-ndjson",
            headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"},
        )

    # ----- Gate 17: container actions ----------------------------------------

    @app.post("/v1/docker/containers/{ref}/{action}")
    async def container_action(ref: str, action: str, request: Request):
        if action not in {"start", "stop", "restart"}:
            return _error("not_found", 404)
        if not docker_possible:
            return _error("docker_unavailable", 503)
        try:
            validate_container_ref(ref)
        except DockerNotAllowed:
            return _error("invalid_container", 422)
        body = await _json_body(request)
        if not isinstance(body, dict):
            return _error("invalid_body", 422)
        timeout_seconds = body.get("timeout_seconds", 10)
        allow_protected = body.get("allow_protected", False)
        if (
            not isinstance(timeout_seconds, int)
            or isinstance(timeout_seconds, bool)
            or not 0 <= timeout_seconds <= 300
        ):
            return _error("invalid_body", 422, field="timeout_seconds")
        if not isinstance(allow_protected, bool):
            return _error("invalid_body", 422, field="allow_protected")
        try:
            inspected = await docker.inspect_container(ref)
        except DockerUnavailable as exc:
            return _docker_error(exc)
        container_id = str(inspected.get("Id", ""))
        if not re.fullmatch(r"[0-9a-f]{64}", container_id):
            return _error("not_found", 404)
        name = str(inspected.get("Name", ""))
        container_config = inspected.get("Config")
        labels = (
            container_config.get("Labels") if isinstance(container_config, dict) else None
        ) or {}
        protected = config.protection.is_protected(
            [name] if name else [], labels if isinstance(labels, dict) else {}
        )
        if protected and not allow_protected:
            return _error("protected", 403)
        try:
            await docker.container_action(container_id, action, timeout_seconds)
        except DockerUnavailable as exc:
            return _docker_error(exc)
        container_cache["items"] = None
        LOGGER.info(
            "container action",
            extra={"action": action, "container": name.lstrip("/"), "protected": protected},
        )
        return {"ok": True}

    # ----- Gate 17: image pull -------------------------------------------------

    @app.post("/v1/docker/images/pull")
    async def image_pull(request: Request):
        if not docker_possible:
            return _error("docker_unavailable", 503)
        body = await _json_body(request)
        if not isinstance(body, dict):
            return _error("invalid_body", 422)
        try:
            repository, tag = parse_image_reference(body.get("image"))
        except ValueError:
            return _error("invalid_image", 422)
        try:
            response = await docker.open_stream(
                "POST", "/images/create", {"fromImage": repository, "tag": tag}
            )
        except DockerUnavailable as exc:
            if isinstance(exc, DockerRequestFailed):
                return _error("pull_failed", 502, status=exc.status_code, message=exc.message)
            return _docker_error(exc)
        digest: str | None = tag if tag.startswith("sha256:") else None
        failure: str | None = None
        buffer = bytearray()

        def handle(line: bytes) -> None:
            nonlocal digest, failure
            try:
                event = json.loads(line)
            except ValueError:
                return
            if not isinstance(event, dict):
                return
            if event.get("error") or event.get("errorDetail"):
                detail = event.get("errorDetail")
                message = event.get("error") or (
                    detail.get("message") if isinstance(detail, dict) else ""
                )
                failure = str(message)[:300] or "pull failed"
                return
            status = event.get("status")
            if isinstance(status, str) and status.startswith("Digest: "):
                candidate = status.removeprefix("Digest: ").strip()
                if re.fullmatch(r"sha256:[0-9a-f]{64}", candidate):
                    digest = candidate

        try:
            async with asyncio.timeout(config.pull_max_seconds):
                async for chunk in response.aiter_bytes():
                    buffer.extend(chunk)
                    while (index := buffer.find(b"\n")) >= 0:
                        handle(bytes(buffer[:index]))
                        del buffer[: index + 1]
                    if len(buffer) > _MAX_PULL_LINE:
                        buffer.clear()
                if buffer.strip():
                    handle(bytes(buffer))
        except TimeoutError:
            return _error("pull_timeout", 504)
        except httpx.HTTPError:
            return _error("docker_unavailable", 503)
        finally:
            await response.aclose()
        if failure is not None:
            return _error("pull_failed", 502, message=failure)
        LOGGER.info("image pulled", extra={"image": f"{repository}:{tag}"})
        return {"ok": True, "digest": digest}

    # ----- Gate 17: prune -------------------------------------------------------

    async def compute_plan(targets: list[str], images_mode: str) -> dict[str, Any]:
        raw_containers, images, networks, df = await asyncio.gather(
            docker.containers(), docker.images(), docker.networks(), docker.system_df()
        )
        return build_plan(
            targets=targets,
            images_mode=images_mode,
            containers=raw_containers,
            images=images,
            networks=networks,
            df=df,
            rules=config.protection,
        )

    @app.post("/v1/docker/prune/preview")
    async def prune_preview(request: Request):
        if not docker_possible:
            return _error("docker_unavailable", 503)
        try:
            targets, images_mode = parse_plan_request(await _json_body(request))
        except PlanRequestError as exc:
            return _error("invalid_body", 422, field=exc.field)
        try:
            return await compute_plan(targets, images_mode)
        except DockerUnavailable as exc:
            return _docker_error(exc)

    @app.post("/v1/docker/prune")
    async def prune_execute(request: Request):
        if not docker_possible:
            return _error("docker_unavailable", 503)
        body = await _json_body(request)
        try:
            targets, images_mode = parse_plan_request(body)
        except PlanRequestError as exc:
            return _error("invalid_body", 422, field=exc.field)
        token = body.get("token") if isinstance(body, dict) else None
        if not isinstance(token, str) or not re.fullmatch(r"[0-9a-f]{64}", token):
            return _error("invalid_body", 422, field="token")
        if prune_lock.locked():
            return _error("busy", 409)
        async with prune_lock:
            try:
                plan = await compute_plan(targets, images_mode)
            except DockerUnavailable as exc:
                return _docker_error(exc)
            if plan["token"] != token:
                return _error("plan_changed", 409)
            removed = {"containers": 0, "images": 0, "networks": 0}
            reclaimed = 0
            errors: list[dict[str, Any]] = []

            async def attempt(kind: str, item: dict[str, Any], call) -> bool:
                try:
                    await call(item["id"])
                except (DockerUnavailable, DockerNotAllowed) as exc:
                    message = exc.message if isinstance(exc, DockerRequestFailed) else str(exc)
                    errors.append({"type": kind, "id": item["id"], "message": message})
                    return False
                return True

            for item in plan["containers"]:
                if await attempt("container", item, docker.remove_container):
                    removed["containers"] += 1
                    reclaimed += item["size_bytes"]
            for item in plan["images"]:
                if await attempt("image", item, docker.remove_image):
                    removed["images"] += 1
                    reclaimed += item["size_bytes"]
            for item in plan["networks"]:
                if await attempt("network", item, docker.remove_network):
                    removed["networks"] += 1
            if "build_cache" in targets:
                try:
                    result = await docker.build_prune()
                    space = result.get("SpaceReclaimed")
                    if isinstance(space, int) and not isinstance(space, bool) and space > 0:
                        reclaimed += space
                except DockerUnavailable as exc:
                    message = exc.message if isinstance(exc, DockerRequestFailed) else str(exc)
                    errors.append({"type": "build_cache", "id": None, "message": message})
            container_cache["items"] = None
        LOGGER.info(
            "prune executed",
            extra={"removed": removed, "reclaimed_bytes": reclaimed, "errors": len(errors)},
        )
        return {"removed": removed, "reclaimed_bytes": reclaimed, "errors": errors}

    # ----- Gate 18: backup sources ------------------------------------------------

    add_backup_routes(app, config, docker, lambda: docker_possible)

    # ----- Gate 19: package databases for the vulnerability scanner ---------------

    from .package_routes import add_package_routes

    add_package_routes(app, docker, lambda: docker_possible, _error)

    # ----- docs/35: opt-in Traefik dynamic file for MRK domains -------------------

    add_traefik_routes(app)

    # ----- docs/37: read-only facts for the DNS setup guide ------------------------

    @app.get("/v1/dns/facts")
    async def dns_host_facts() -> dict[str, Any]:
        facts = await asyncio.to_thread(dns_facts.collect, config.proc_dir, config.host_root)
        gateway = None
        if docker_possible:
            try:
                for network in await docker.networks():
                    if isinstance(network, dict) and network.get("Name") == "bridge":
                        configs = (network.get("IPAM") or {}).get("Config") or []
                        for item in configs if isinstance(configs, list) else []:
                            value = item.get("Gateway") if isinstance(item, dict) else None
                            if isinstance(value, str) and dns_facts.ip_text(value):
                                gateway = dns_facts.ip_text(value)
                                break
            except DockerUnavailable:
                gateway = None
        facts["docker_bridge_gateway"] = gateway
        return facts

    return app


def add_traefik_routes(app: FastAPI) -> None:
    """Write/delete only ``<MRK_AGENT_TRAEFIK_DYNAMIC_DIR>/mrk-domains.yml``.

    Disabled (404 ``traefik_disabled``) unless the operator set the variable and
    mounted Dokploy's dynamic directory read-write into the agent.
    """
    lock = asyncio.Lock()

    @app.get("/v1/traefik/status")
    async def traefik_status():
        return await asyncio.to_thread(traefik_files.status, traefik_files.resolve_dir())

    @app.post("/v1/traefik/domains")
    async def traefik_write(request: Request):
        directory = traefik_files.resolve_dir()
        if directory is None:
            return _error("traefik_disabled", 404)
        payload = await _json_body(request)
        try:
            text = traefik_files.render(payload)
        except traefik_files.TraefikPayloadError as exc:
            return _error("invalid_payload", 422, message=str(exc)[:120])
        async with lock:
            try:
                await asyncio.to_thread(traefik_files.write, directory, text)
            except OSError:
                LOGGER.warning("traefik dynamic file write failed")
                return _error("traefik_dir_unwritable", 403)
        LOGGER.info("traefik dynamic file written", extra={"bytes": len(text)})
        return {"ok": True, "file": traefik_files.FILE_NAME, "bytes": len(text.encode())}

    @app.post("/v1/traefik/domains/delete")
    async def traefik_delete():
        directory = traefik_files.resolve_dir()
        if directory is None:
            return _error("traefik_disabled", 404)
        async with lock:
            try:
                removed = await asyncio.to_thread(traefik_files.delete, directory)
            except OSError:
                return _error("traefik_dir_unwritable", 403)
        return {"ok": True, "removed": removed}


def _ndjson(line: dict[str, Any]) -> bytes:
    return json.dumps(line, ensure_ascii=False, separators=(",", ":")).encode("utf-8") + b"\n"


# ----- Gate 18: backup sources (docs/31 §4) ---------------------------------------

_STREAM_MEDIA_TYPE = "application/x-mrk-agent-stream"


def _stream_response(body: AsyncIterator[bytes]) -> StreamingResponse:
    return StreamingResponse(
        body,
        media_type=_STREAM_MEDIA_TYPE,
        headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"},
    )


def add_backup_routes(
    app: FastAPI, config: AgentConfig, docker: DockerClient, docker_ok: Callable[[], bool]
) -> None:
    """Read-only backup sources: volume tar and fixed-template database dumps."""
    rules = config.protection

    @app.get("/v1/backup/sources")
    async def backup_sources_list():
        if not docker_ok():
            return _error("docker_unavailable", 503)
        try:
            raw_volumes, raw_containers = await asyncio.gather(
                docker.volumes(), docker.containers()
            )
        except DockerUnavailable:
            return _error("docker_unavailable", 503)
        volumes = []
        for item in raw_volumes:
            if not isinstance(item, dict) or not isinstance(item.get("Name"), str):
                continue
            name = item["Name"]
            labels = item.get("Labels") if isinstance(item.get("Labels"), dict) else {}
            volumes.append(
                {
                    "name": name[:255],
                    "driver": str(item.get("Driver", ""))[:64],
                    "supported": item.get("Driver") == "local"
                    and bool(backup_sources.VOLUME_NAME.fullmatch(name)),
                    "compose_project": str(labels.get("com.docker.compose.project", ""))[:128]
                    or None,
                    "protected": rules.is_protected([], labels),
                }
            )
        volumes.sort(key=lambda entry: entry["name"])
        databases = []
        for item in raw_containers:
            engine = backup_sources.detect_engine(item.get("Image"))
            if engine is None:
                continue
            names = container_names(item)
            databases.append(
                {
                    "container_id": str(item.get("Id", ""))[:64],
                    "name": names[0].lstrip("/") if names else "",
                    "image": str(item.get("Image", ""))[:256],
                    "engine": engine,
                    "state": str(item.get("State", ""))[:32],
                    "protected": rules.is_protected(names, container_labels(item)),
                }
            )
        databases.sort(key=lambda entry: entry["name"])
        return {"volumes": volumes, "databases": databases}

    @app.get("/v1/backup/volumes/{name}/archive")
    async def volume_archive(name: str, request: Request):
        if not docker_ok():
            return _error("docker_unavailable", 503)
        if not backup_sources.VOLUME_NAME.fullmatch(name):
            return _error("invalid_volume", 422)
        try:
            raw_volumes = await docker.volumes()
        except DockerUnavailable:
            return _error("docker_unavailable", 503)
        volume = next(
            (v for v in raw_volumes if isinstance(v, dict) and v.get("Name") == name), None
        )
        if volume is None:
            return _error("not_found", 404)
        expected = f"{backup_sources.DOCKER_VOLUMES_DIR}/{name}/_data"
        if volume.get("Driver") != "local" or volume.get("Mountpoint") != expected:
            return _error("volume_unsupported", 422)
        try:
            data_path = backup_sources.volume_data_path(config.volumes_root, name)
        except backup_sources.BackupSourceError as exc:
            return _error(exc.code, exc.status_code)
        loop = asyncio.get_running_loop()
        chunks: asyncio.Queue[bytes | None] = asyncio.Queue(maxsize=16)
        stop = {"flag": False}
        outcome: dict[str, Any] = {}

        def emit(chunk: bytes) -> None:
            future = asyncio.run_coroutine_threadsafe(chunks.put(chunk), loop)
            while True:
                if stop["flag"]:
                    future.cancel()
                    raise backup_sources.StopRequested()
                try:
                    future.result(timeout=1.0)
                    return
                except TimeoutError:
                    continue

        def produce() -> None:
            writer = backup_sources.ChunkWriter(emit)
            try:
                stats = backup_sources.write_volume_tar(data_path, writer, lambda: stop["flag"])
                writer.close()
                outcome.update(ok=True, stats=stats.public(), bytes=writer.total)
            except backup_sources.StopRequested:
                outcome.update(ok=False, error="cancelled")
            except backup_sources.BackupSourceError as exc:
                outcome.update(ok=False, error=exc.code)
            except Exception:  # pragma: no cover - defensive
                LOGGER.exception("volume archive failed", extra={"volume": name})
                outcome.update(ok=False, error="archive_failed")
            finally:
                asyncio.run_coroutine_threadsafe(chunks.put(None), loop)

        async def stream() -> AsyncIterator[bytes]:
            worker = loop.run_in_executor(None, produce)
            deadline = loop.time() + config.backup_max_seconds
            try:
                while True:
                    remaining = deadline - loop.time()
                    if remaining <= 0:
                        stop["flag"] = True
                        yield backup_sources.end_frame({"ok": False, "error": "timeout"})
                        return
                    try:
                        chunk = await asyncio.wait_for(chunks.get(), min(remaining, 5.0))
                    except TimeoutError:
                        if await request.is_disconnected():
                            stop["flag"] = True
                            return
                        continue
                    if chunk is None:
                        break
                    for piece in backup_sources.data_frames(chunk):
                        yield piece
                await worker
                yield backup_sources.end_frame(outcome or {"ok": False, "error": "archive_failed"})
                LOGGER.info(
                    "volume archived",
                    extra={"volume": name, "ok": outcome.get("ok"), "bytes": outcome.get("bytes")},
                )
            finally:
                stop["flag"] = True
                # Unblock a producer waiting on a full queue.
                while not chunks.empty():
                    chunks.get_nowait()

        return _stream_response(stream())

    @app.post("/v1/backup/db/{ref}/dump")
    async def database_dump(ref: str, request: Request):
        if not docker_ok():
            return _error("docker_unavailable", 503)
        try:
            validate_container_ref(ref)
        except DockerNotAllowed:
            return _error("invalid_container", 422)
        body = await _json_body(request)
        if not isinstance(body, dict) or set(body) - {"engine", "database"}:
            return _error("invalid_body", 422)
        engine = body.get("engine")
        database = body.get("database")
        if engine not in backup_sources.ENGINES:
            return _error("invalid_engine", 422)
        if database is not None and (
            not isinstance(database, str) or not backup_sources.DATABASE_NAME.fullmatch(database)
        ):
            return _error("invalid_database", 422)
        try:
            inspected = await docker.inspect_container(ref)
        except DockerUnavailable as exc:
            return _docker_error(exc)
        container_id = str(inspected.get("Id", ""))
        if not re.fullmatch(r"[0-9a-f]{64}", container_id):
            return _error("not_found", 404)
        container_config = inspected.get("Config")
        image = container_config.get("Image") if isinstance(container_config, dict) else None
        detected = backup_sources.detect_engine(image)
        if detected is None or engine not in backup_sources.COMPATIBLE_ENGINES[detected]:
            return _error("engine_mismatch", 422)
        state = inspected.get("State")
        if not isinstance(state, dict) or state.get("Running") is not True:
            return _error("container_not_running", 409)
        try:
            spec = backup_sources.build_dump_spec(engine, database, inspected)
        except backup_sources.BackupSourceError as exc:
            return _error(exc.code, exc.status_code)
        name = str(inspected.get("Name", "")).lstrip("/")
        labels = container_config.get("Labels") if isinstance(container_config, dict) else None
        protected = rules.is_protected(
            [f"/{name}"] if name else [], labels if isinstance(labels, dict) else {}
        )
        try:
            exec_id = await docker.exec_create(container_id, spec.argv, spec.env)
            response = await docker.exec_start_stream(exec_id)
        except DockerNotAllowed:  # pragma: no cover - templates are pre-checked
            return _error("not_allowed", 403)
        except DockerUnavailable as exc:
            return _docker_error(exc)
        LOGGER.info(
            "database dump started",
            extra={"container": name, "engine": engine, "protected": protected},
        )

        async def stream() -> AsyncIterator[bytes]:
            demux = backup_sources.ExecDemuxer()
            total = 0
            try:
                try:
                    async with asyncio.timeout(config.backup_max_seconds):
                        async for chunk in response.aiter_bytes():
                            out = demux.feed(chunk)
                            if out:
                                total += len(out)
                                for piece in backup_sources.data_frames(out):
                                    yield piece
                except TimeoutError:
                    yield backup_sources.end_frame({"ok": False, "error": "timeout"})
                    return
                except httpx.HTTPError:
                    yield backup_sources.end_frame({"ok": False, "error": "docker_unavailable"})
                    return
                exit_code: int | None = None
                try:
                    inspected_exec = await docker.exec_inspect(exec_id)
                    value = inspected_exec.get("ExitCode")
                    exit_code = value if isinstance(value, int) else None
                except DockerUnavailable:
                    exit_code = None
                ok = exit_code == 0 and total > 0 and demux.pending == 0
                status: dict[str, Any] = {"ok": ok, "exit_code": exit_code, "bytes": total}
                if not ok:
                    status["error"] = "dump_failed" if total or exit_code else "dump_empty"
                    # Tool output may echo connection details; it stays in the agent log,
                    # redacted, and is never sent to the Control Plane.
                    tail = spec.redact(demux.stderr_tail.decode("utf-8", errors="replace"))
                    LOGGER.warning(
                        "database dump failed",
                        extra={
                            "container": name,
                            "engine": engine,
                            "exit_code": exit_code,
                            "stderr_tail": tail[-300:],
                        },
                    )
                yield backup_sources.end_frame(status)
            finally:
                await response.aclose()

        return _stream_response(stream())
