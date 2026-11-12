"""Automatic install through Dokploy or Coolify (docs/44, phase 6).

The add-service wizard can hand the generated ``compose.yaml`` + ``.env`` to a
deploy platform the operator already runs, instead of asking them to paste the
files by hand:

1. ``GET  /api/v1/install/targets``               which platforms are connected, with the
                                                   projects / environments / servers to pick;
2. ``POST /api/v1/install/{id}/auto``             make the files (same as /bundle), then in the
                                                   background: create (or reuse) ``mrk-<id>`` on
                                                   the platform, set compose + env, deploy, wait,
                                                   and pair with the panel (same as /connect);
3. ``GET  /api/v1/install/auto/jobs/{job}``        progress of that job;
4. ``POST /api/v1/install/auto/jobs/{job}/connect`` try the connection again.

Coolify's URL and token are kept like Dokploy's (``coolify.json`` + SecretStore,
never returned): ``GET|PUT|DELETE /api/v1/coolify/config``, ``POST /api/v1/coolify/test``.

The generated stacks join the external ``mrk-net`` network of the panel stack
(or publish loopback ports for a native panel), so the platform must deploy on
the panel's own server. Dokploy deploys on its own host (no ``serverId``);
Coolify lets the operator pick the server and the panel warns when it is not
the local one.

The ``.env`` text carries a pairing secret: it is only held in memory for the
running job and sent to the platform, never logged, stored in a job or returned.
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
import re
import secrets
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from ..logging_config import redact_text
from ..module_context import ModuleContext
from .coolify_client import (
    Connection as CoolifyConnection,
)
from .coolify_client import (
    CoolifyClient,
    CoolifyError,
    validate_coolify_url,
    validate_token,
)
from .dokploy_client import DokployError, TTLCache
from .dokploy_locate import (
    LocateError,
    compose_detail,
    deploy_mark,
    env_value,
    find_compose,
    set_env_value,
    wait_deployment,
)
from .dokploy_locate import sha256 as text_sha256
from .install import STATE_FILE, WRITE_PERMISSION, InstallError, InstallService
from .install_catalog import INSTALL_INDEX

LOGGER = logging.getLogger(__name__)
CONFIG_FILE = "coolify.json"
PROJECT_NAME = "MrK DevAssist"
# Existing Dokploy projects reused when no project is picked (never a second one).
PROJECT_NAMES = ("MrK DevAssist", "DevAssist")
DESCRIPTION = "Added by the MrK DevAssist panel"
TARGETS = ("dokploy", "coolify")
# Tunables (tests shorten them).
POLL_SECONDS = 3.0
DEPLOY_TIMEOUT_SECONDS = 900.0
CONNECT_ATTEMPTS = 20
CONNECT_DELAY_SECONDS = 3.0
TARGETS_CACHE_SECONDS = 20.0
MAX_JOBS = 50
MAX_COOLIFY_PROJECTS = 15
ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
JOB_ID_RE = re.compile(r"^[A-Za-z0-9_-]{8,32}$")
ENV_NAME_RE = re.compile(r"^[A-Za-z0-9 _.-]{1,64}$")
# Names Coolify gives the server it runs on ("localhost", host.docker.internal).
LOCAL_SERVER_HOSTS = frozenset({"host.docker.internal", "127.0.0.1", "localhost", "::1"})


def _env_flag(name: str) -> bool:
    return os.getenv(name, "").strip().lower() in {"1", "true", "yes", "on"}


class AutoError(Exception):
    def __init__(self, code: str, status_code: int, message: str, **extra: Any) -> None:
        super().__init__(message)
        self.code = code
        self.status_code = status_code
        self.message = message
        self.extra = extra


class CoolifyConfigRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    url: str = Field(min_length=8, max_length=2048)
    token: str | None = Field(default=None, min_length=16, max_length=512)


class CoolifyTestRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    url: str | None = Field(default=None, min_length=8, max_length=2048)
    token: str | None = Field(default=None, min_length=16, max_length=512)


class ConfirmationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    confirmation: str | None = Field(default=None, max_length=255)


class AutoRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    target: str = Field(pattern=r"^(dokploy|coolify)$")
    # Empty project = create a "MrK DevAssist" project on the platform.
    project_id: str | None = Field(default=None, max_length=64)
    environment_id: str | None = Field(default=None, max_length=64)  # Dokploy
    environment_name: str | None = Field(default=None, max_length=64)  # Coolify
    server_id: str | None = Field(default=None, max_length=64)  # Coolify
    env: dict[str, str] = Field(default_factory=dict, max_length=32)
    url: str | None = Field(default=None, max_length=300)
    engine_url: str | None = Field(default=None, max_length=300)
    # Where each storage slot lives (install_storage); shared slots follow the panel.
    storage: dict[str, dict[str, str]] = Field(default_factory=dict, max_length=8)


# ---------------------------------------------------------------------- Coolify settings


class CoolifySettings:
    def __init__(self, ctx: ModuleContext) -> None:
        self.ctx = ctx
        self.config_path: Path = ctx.data_dir / "control-plane" / CONFIG_FILE
        self.allow_loopback = _env_flag("MRK_COOLIFY_ALLOW_LOOPBACK")
        self.client = CoolifyClient(rate_per_second=5.0)
        self.reachable: bool | None = None
        self.last_error: str | None = None
        self.version: str | None = None

    def _file(self) -> dict[str, Any] | None:
        try:
            if not self.config_path.exists():
                return None
            payload = json.loads(self.config_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            LOGGER.warning("coolify config file is unreadable; treating as unconfigured")
            return None
        return payload if isinstance(payload, dict) else None

    def resolve(self) -> tuple[str | None, str | None]:
        stored = self._file()
        if not stored or not isinstance(stored.get("url"), str):
            return None, None
        token: str | None = None
        reference = stored.get("secret_ref")
        if isinstance(reference, str):
            try:
                token = self.ctx.secret_store.get(reference)["token"]
            except (KeyError, ValueError):
                token = None
        return stored["url"], token

    def configured(self) -> bool:
        return self.resolve()[0] is not None

    def connection(self) -> CoolifyConnection:
        url, token = self.resolve()
        if url is None:
            raise CoolifyError("coolify_not_configured", 409, "Coolify is not connected")
        if token is None:
            raise CoolifyError("coolify_auth_failed", 502, "The Coolify token is unavailable")
        return CoolifyConnection(url=url, token=token)

    def _write(self, payload: dict[str, Any]) -> None:
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.config_path.with_name(f".{CONFIG_FILE}.{secrets.token_hex(4)}.tmp")
        temporary.write_text(json.dumps(payload) + "\n", encoding="utf-8")
        temporary.chmod(0o600)
        os.replace(temporary, self.config_path)

    def save(self, url_text: str, token_text: str | None) -> None:
        url = validate_coolify_url(url_text, allow_loopback=self.allow_loopback)
        stored = self._file() or {}
        reference = stored.get("secret_ref") if isinstance(stored.get("secret_ref"), str) else None
        if token_text is not None:
            secret = {"token": validate_token(token_text)}
            reference, _ = self.ctx.secret_store.replace(reference, secret)
        elif reference is None or stored.get("url") != url:
            # Never forward a stored token to a different URL without re-entry.
            raise CoolifyError("coolify_token_required", 422, "A Coolify API token is required")
        self._write({"url": url, "secret_ref": reference, "updated_at": int(time.time())})
        self.reachable = None
        self.last_error = None
        self.version = None

    def disconnect(self) -> None:
        stored = self._file() or {}
        reference = stored.get("secret_ref")
        if isinstance(reference, str):
            self.ctx.secret_store.delete(reference)
        self.config_path.unlink(missing_ok=True)
        self.reachable = None
        self.last_error = None
        self.version = None

    def view(self) -> dict[str, Any]:
        url, token = self.resolve()
        return {
            "configured": url is not None,
            "url": url,
            "token_configured": token is not None,
            "reachable": self.reachable if url is not None else None,
            "last_error": self.last_error if url is not None else None,
            "version": self.version,
        }

    async def call(self, method: str, path: str, **kwargs: Any) -> Any:
        connection = self.connection()
        try:
            result = await self.client.call(connection, method, path, **kwargs)
        except CoolifyError as exc:
            if exc.code in {"coolify_unreachable", "coolify_auth_failed"}:
                self.reachable = False
                self.last_error = exc.message
            raise
        self.reachable = True
        self.last_error = None
        return result

    async def test(self, url: str | None, token: str | None) -> dict[str, Any]:
        started = time.perf_counter()
        candidate = url is not None or token is not None
        try:
            if candidate:
                current_url, current_token = self.resolve()
                target = (
                    validate_coolify_url(url, allow_loopback=self.allow_loopback)
                    if url is not None else current_url
                )
                if token is None and target != current_url:
                    raise CoolifyError(
                        "coolify_token_required", 422,
                        "A token is required to test a different Coolify URL",
                    )
                key = validate_token(token) if token is not None else current_token
                if target is None or key is None:
                    raise CoolifyError(
                        "coolify_not_configured", 409, "A Coolify URL and token are required"
                    )
                version = await self.client.call(
                    CoolifyConnection(url=target, token=key), "GET", "/version", text=True
                )
            else:
                version = await self.call("GET", "/version", text=True)
        except CoolifyError as exc:
            if exc.code in {"coolify_not_configured", "coolify_token_required"}:
                raise
            latency = round((time.perf_counter() - started) * 1000, 1)
            return {"ok": False, "latency_ms": latency, "error_code": exc.code}
        latency = round((time.perf_counter() - started) * 1000, 1)
        clean = version.strip('"')[:64] if isinstance(version, str) else None
        if not candidate:
            self.version = clean
        result: dict[str, Any] = {"ok": True, "latency_ms": latency}
        if clean:
            result["version"] = clean
        return result


# ---------------------------------------------------------------------- jobs


@dataclass
class Job:
    id: str
    service_id: str
    target: str
    actor_user_id: int | None
    status: str = "running"  # running | succeeded | failed
    phase: str = "preparing"  # preparing|creating|configuring|deploying|waiting|connecting|done
    error_code: str | None = None
    message: str | None = None
    connection: str | None = None
    deployed: bool = False
    reused: bool = False
    resource_id: str | None = None
    resource_url: str | None = None
    project_id: str | None = None
    warnings: list[str] = field(default_factory=list)
    url: str | None = None
    engine_url: str | None = None
    created_at: int = field(default_factory=lambda: int(time.time()))
    updated_at: int = field(default_factory=lambda: int(time.time()))

    def set(self, **changes: Any) -> None:
        for key, value in changes.items():
            setattr(self, key, value)
        self.updated_at = int(time.time())

    def view(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "service_id": self.service_id,
            "target": self.target,
            "status": self.status,
            "phase": self.phase,
            "error_code": self.error_code,
            "message": self.message,
            "connection": self.connection,
            "deployed": self.deployed,
            "reused": self.reused,
            "resource_id": self.resource_id,
            "resource_url": self.resource_url,
            "project_id": self.project_id,
            "warnings": list(self.warnings),
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


def env_pairs(env_text: str) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    for line in env_text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        name, value = stripped.split("=", 1)
        pairs.append((name.strip(), value))
    return pairs


def _list(value: Any) -> list[dict[str, Any]]:
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def _text(value: Any, limit: int = 120) -> str | None:
    return str(value)[:limit] if isinstance(value, str | int) and str(value) else None


def deployment_for(data_dir: Path, service_id: str) -> dict[str, Any] | None:
    """Where the panel deployed ``service_id`` (pure file read of ``install.json``).

    ``{"target": "dokploy", "compose_id", "service_name", "project_id", "environment_id"}``
    or ``{"target": "coolify", "uuid", "service_name", "project_id", "environment_name",
    "server_id"}``; None when the panel did not deploy it itself.
    """
    path = Path(data_dir) / "control-plane" / STATE_FILE
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    entry = payload.get(service_id) if isinstance(payload, dict) else None
    deployment = entry.get("deployment") if isinstance(entry, dict) else None
    return dict(deployment) if isinstance(deployment, dict) else None


def server_is_local(server: dict[str, Any]) -> bool:
    ip = str(server.get("ip") or "").strip().lower()
    return ip in LOCAL_SERVER_HOSTS or str(server.get("name") or "").strip().lower() == "localhost"


class AutoInstaller:
    def __init__(self, ctx: ModuleContext) -> None:
        self.ctx = ctx
        self.install = InstallService(ctx)
        self.coolify = CoolifySettings(ctx)
        self.jobs: OrderedDict[str, Job] = OrderedDict()
        self.tasks: set[asyncio.Task[None]] = set()
        self.cache = TTLCache()
        self._state_lock = asyncio.Lock()

    # ----- platforms -------------------------------------------------------
    def dokploy(self) -> Any | None:
        from . import dokploy as dokploy_module

        service = dokploy_module.ACTIVE_SERVICE
        return service if service is not None and service.ctx is self.ctx else None

    def dokploy_configured(self) -> bool:
        service = self.dokploy()
        if service is None:
            return False
        source, url, _key = service.resolve()
        return source is not None and url is not None

    async def _dokploy_projects(self) -> list[dict[str, Any]]:
        service = self.dokploy()
        if service is None:
            raise AutoError("module_unavailable", 503, "The Dokploy module is not loaded")
        raw = await service._projects_raw()  # cached in the Dokploy module
        projects = []
        for project in _list(raw):
            project_id = project.get("projectId")
            if not isinstance(project_id, str):
                continue
            legacy = "environments" not in project
            environments = [
                {"id": env["environmentId"], "name": _text(env.get("name")) or env["environmentId"]}
                for env in _list(project.get("environments"))
                if isinstance(env.get("environmentId"), str)
            ]
            projects.append({
                "id": project_id,
                "name": _text(project.get("name")) or project_id,
                "environments": environments,
                "legacy": legacy,
            })
        return projects

    async def _coolify_lists(self) -> dict[str, Any]:
        hit = self.cache.get("coolify")
        if hit is not None:
            return hit
        projects_raw = await self.coolify.call("GET", "/projects")
        servers_raw = await self.coolify.call("GET", "/servers")
        projects = []
        for project in _list(projects_raw)[:MAX_COOLIFY_PROJECTS]:
            uuid = project.get("uuid")
            if not isinstance(uuid, str):
                continue
            try:
                environments_raw = await self.coolify.call("GET", f"/projects/{uuid}/environments")
            except CoolifyError as exc:
                if exc.code in {"coolify_unreachable", "coolify_auth_failed"}:
                    raise
                environments_raw = []
            projects.append({
                "id": uuid,
                "name": _text(project.get("name")) or uuid,
                "environments": [
                    {"id": _text(env.get("uuid"), 64), "name": _text(env.get("name"), 64)}
                    for env in _list(environments_raw)
                    if isinstance(env.get("name"), str)
                ],
            })
        servers = []
        for server in _list(servers_raw):
            uuid = server.get("uuid")
            if not isinstance(uuid, str):
                continue
            settings = server.get("settings") if isinstance(server.get("settings"), dict) else {}
            servers.append({
                "id": uuid,
                "name": _text(server.get("name")) or uuid,
                "local": server_is_local(server),
                "reachable": settings.get("is_reachable")
                if isinstance(settings.get("is_reachable"), bool) else None,
            })
        result = {"projects": projects, "servers": servers}
        self.cache.set("coolify", result, TARGETS_CACHE_SECONDS)
        return result

    async def targets(self, principal: Any, refresh: bool = False) -> dict[str, Any]:
        if refresh:
            self.cache.clear()
        dokploy: dict[str, Any] = {
            "configured": self.dokploy_configured(),
            "allowed": bool(principal.allows("dokploy:deploy")),
            "reachable": None, "error_code": None, "panel_url": None, "projects": [],
        }
        if dokploy["configured"] and dokploy["allowed"]:
            service = self.dokploy()
            dokploy["panel_url"] = service.panel_url() if service else None
            try:
                if refresh and service is not None:
                    service.cache.clear()
                dokploy["projects"] = await self._dokploy_projects()
                dokploy["reachable"] = True
            except (DokployError, AutoError) as exc:
                dokploy["reachable"] = False
                dokploy["error_code"] = exc.code
        coolify_view = self.coolify.view()
        coolify: dict[str, Any] = {
            "configured": coolify_view["configured"],
            "allowed": True,
            "url": coolify_view["url"],
            "reachable": None, "error_code": None, "projects": [], "servers": [],
        }
        if coolify["configured"]:
            try:
                coolify.update(await self._coolify_lists())
                coolify["reachable"] = True
            except CoolifyError as exc:
                coolify["reachable"] = False
                coolify["error_code"] = exc.code
        return {"dokploy": dokploy, "coolify": coolify, "same_host_required": True}

    def _record(self, service_id: str, deployment: dict[str, Any]) -> None:
        """Keep where the service lives in install.json (domain routing reads it)."""
        state = self.install._read()
        entry = state.get(service_id)
        entry = dict(entry) if isinstance(entry, dict) else {}
        entry["deployment"] = {**deployment, "updated_at": int(time.time())}
        state[service_id] = entry
        self.install._write(state)

    async def record(self, service_id: str, deployment: dict[str, Any]) -> None:
        async with self._state_lock:
            await asyncio.to_thread(self._record, service_id, deployment)

    # ----- start -----------------------------------------------------------
    def _check(self, service_id: str, body: AutoRequest) -> None:
        item = INSTALL_INDEX.get(service_id)
        if item is None:
            raise AutoError("service_not_found", 404, "Unknown service")
        if item.availability == "ready" and body.target not in item.methods:
            raise AutoError("target_not_supported", 409,
                            "This service cannot be installed with that platform")
        ids = (("project_id", body.project_id), ("environment_id", body.environment_id),
               ("server_id", body.server_id))
        for name, value in ids:
            if value is not None and not ID_RE.fullmatch(value):
                raise AutoError("validation_error", 422, f"Invalid {name}")
        if body.environment_name is not None and not ENV_NAME_RE.fullmatch(body.environment_name):
            raise AutoError("validation_error", 422, "Invalid environment_name")
        if body.target == "dokploy" and not self.dokploy_configured():
            raise AutoError("dokploy_not_configured", 409, "Dokploy is not connected")
        if body.target == "coolify" and not self.coolify.configured():
            raise AutoError("coolify_not_configured", 409, "Coolify is not connected")
        for job in self.jobs.values():
            if job.service_id == service_id and job.status == "running":
                raise AutoError("install_in_progress", 409,
                                "An automatic install of this service is already running")

    async def start(self, principal: Any, service_id: str, body: AutoRequest) -> Job:
        self._check(service_id, body)
        storage = await self.install.resolve_storage(service_id, body.storage)
        checked = await self.install.check_storage(service_id, storage)
        if not checked["ok"]:
            # A folder Docker would create as root, or one owned by another user: the
            # service could not write there. Nothing is created in Dokploy/Coolify.
            raise AutoError("storage_not_ready", 409,
                            "Prepare the chosen folders first (see the commands)",
                            items=[item for item in checked["items"]
                                   if item["status"] == "error"])
        bundle = await asyncio.to_thread(self.install.bundle, service_id, body.env, storage)
        job = Job(
            id=secrets.token_urlsafe(12), service_id=service_id, target=body.target,
            actor_user_id=getattr(principal, "user_id", None),
            url=body.url, engine_url=body.engine_url,
        )
        job.warnings.append("same_host_required")
        if not checked["checked"]:
            job.warnings.append("storage_unchecked")
        self.jobs[job.id] = job
        while len(self.jobs) > MAX_JOBS:
            oldest = next(iter(self.jobs))
            if self.jobs[oldest].status == "running":
                break
            self.jobs.pop(oldest)
        task = asyncio.create_task(
            self._run(job, body, bundle["compose"], bundle["env"]),
            name=f"mrk-install-auto-{service_id}",
        )
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)
        return job

    async def _audit(self, job: Job, action: str, result: str = "success") -> None:
        await asyncio.to_thread(
            self.ctx.audit, job.actor_user_id, action, "service", job.service_id, result
        )

    async def _run(self, job: Job, body: AutoRequest, compose: str, env_text: str) -> None:
        try:
            if job.target == "dokploy":
                await self._run_dokploy(job, body, compose, env_text)
            else:
                await self._run_coolify(job, body, compose, env_text)
            del compose, env_text
            await self._connect(job)
        except asyncio.CancelledError:
            job.set(status="failed", error_code="cancelled", message="The panel stopped")
            raise
        except (DokployError, CoolifyError, AutoError, InstallError, LocateError) as exc:
            await self._audit(job, f"install.auto.{job.phase}", "failure")
            job.set(status="failed", error_code=exc.code, message=redact_text(exc.message)[:300])
        except Exception as exc:  # never log the exception text: it could carry env values
            LOGGER.error("automatic install failed", extra={"error_type": type(exc).__name__})
            await self._audit(job, f"install.auto.{job.phase}", "failure")
            job.set(status="failed", error_code="auto_install_failed",
                    message="The automatic install failed unexpectedly")

    # ----- Dokploy ---------------------------------------------------------
    def _agent(self) -> Any | None:
        from . import services as services_module

        service = services_module.ACTIVE_SERVICE
        if service is None or getattr(service, "ctx", None) is not self.ctx:
            return None
        try:
            return service.routing.agent()
        except Exception:  # noqa: BLE001 - the agent is optional
            return None

    @staticmethod
    def _merge_env(current: str, wanted: str) -> str:
        """The wizard's env on top of the one in Dokploy, keeping the admin's own lines.

        Every wizard value is set (the pairing key must match the panel), except a line
        whose current value points at a Dokploy variable such as ${{project.MRK_VERSION}}.
        """
        merged = current
        for line in wanted.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or "=" not in stripped:
                continue
            name, value = stripped.split("=", 1)
            name = name.strip()
            existing = env_value(merged, name)
            if existing is not None and "${{" in existing:
                continue
            merged = set_env_value(merged, name, value)
        return merged

    async def _run_dokploy(self, job: Job, body: AutoRequest, compose: str, env_text: str) -> None:
        service = self.dokploy()
        if service is None:
            raise AutoError("module_unavailable", 503, "The Dokploy module is not loaded")
        name = f"mrk-{job.service_id}"
        project_id, environment_id = body.project_id, body.environment_id
        job.set(phase="creating")
        # Already running somewhere in Dokploy (installed before, or pasted by hand)?
        recorded = deployment_for(self.ctx.data_dir, job.service_id) or {}
        found = await find_compose(service, name, known=(recorded.get("compose_id"),),
                                   agent=self._agent())
        if found is not None and found.get("project_id"):
            same_place = (project_id in {None, found["project_id"]}
                          and environment_id in {None, found.get("environment_id")})
            if not same_place:
                where = found.get("project_name") or found["project_id"]
                raise AutoError(
                    "already_installed", 409,
                    f"{name} already runs in the Dokploy project {where}; "
                    "pick that project or remove the other one first",
                )
            project_id = found["project_id"]
            environment_id = found.get("environment_id")
        if project_id is None:
            tree = await service._projects_raw()  # noqa: SLF001 - cached loader
            mine = next((item for wanted in PROJECT_NAMES for item in _list(tree)
                         if str(item.get("name") or "").strip().lower() == wanted.lower()
                         and isinstance(item.get("projectId"), str)), None)
            if mine is not None:
                project_id = mine["projectId"]
        if project_id is None:
            created = await service.call(
                "project.create", body={"name": PROJECT_NAME, "description": DESCRIPTION},
                mutation=True,
            )
            project = created.get("project") if isinstance(created, dict) else None
            project = project if isinstance(project, dict) else created
            environment = created.get("environment") if isinstance(created, dict) else None
            project_id = project.get("projectId") if isinstance(project, dict) else None
            if isinstance(environment, dict):
                environment_id = environment.get("environmentId")
            if not isinstance(project_id, str):
                raise AutoError("dokploy_rejected", 409, "Dokploy did not return the new project")
            service.cache.clear()
            await self._audit(job, "install.auto.project.create")
        raw = await service.call("project.one", params={"projectId": project_id})
        if not isinstance(raw, dict):
            raise AutoError("project_not_found", 404, "The Dokploy project was not found")
        environments = _list(raw.get("environments"))
        holder: dict[str, Any] = raw
        if "environments" in raw:
            if environment_id is None:
                if not environments:
                    raise AutoError("environment_required", 422,
                                    "Pick an environment of the Dokploy project")
                environment_id = environments[0].get("environmentId")
            match = next((env for env in environments
                          if env.get("environmentId") == environment_id), None)
            if match is None:
                raise AutoError("environment_not_found", 404,
                                "The Dokploy environment was not found")
            holder = match
        else:
            environment_id = None  # Dokploy before environments: services hang off the project
        existing_id = found["compose_id"] if found is not None else next(
            (item["composeId"] for item in _list(holder.get("compose"))
             if item.get("name") == name and isinstance(item.get("composeId"), str)), None)
        job.set(project_id=project_id)
        update: dict[str, Any]
        if existing_id is not None:
            compose_id = str(existing_id)
            job.set(reused=True)
            one = await compose_detail(service, compose_id)
            if one is None:
                raise AutoError("service_missing", 404, "The Dokploy service was not found")
            current_env = one.get("env") if isinstance(one.get("env"), str) else ""
            current_file = one.get("composeFile") if isinstance(one.get("composeFile"), str) \
                else ""
            del one
            update = {"composeId": compose_id, "env": self._merge_env(current_env, env_text)}
            del current_env
            written = recorded.get("compose_sha256")
            compose_hash = text_sha256(compose)
            if not current_file.strip() or (written and written == text_sha256(current_file)):
                update["composeFile"] = compose  # empty, or still the panel's own file
            elif text_sha256(current_file) != compose_hash:
                compose_hash = written or text_sha256(current_file)
                job.warnings.append("compose_customized")
        else:
            payload: dict[str, Any] = {
                "name": name, "description": DESCRIPTION, "composeType": "docker-compose",
            }
            if environment_id:
                payload["environmentId"] = environment_id
            else:
                payload["projectId"] = project_id
            created = await service.call("compose.create", body=payload, mutation=True)
            compose_id = created.get("composeId") if isinstance(created, dict) else None
            if not isinstance(compose_id, str):
                raise AutoError("dokploy_rejected", 409, "Dokploy did not return the new service")
            await self._audit(job, "install.auto.create")
            update = {"composeId": compose_id, "sourceType": "raw",
                      "composeType": "docker-compose", "composeFile": compose, "env": env_text}
            compose_hash = text_sha256(compose)
        await self.record(job.service_id, {
            "target": "dokploy", "compose_id": compose_id, "service_name": name,
            "project_id": project_id, "environment_id": environment_id,
            "compose_sha256": compose_hash,
        })
        panel = service.panel_url()
        job.set(
            resource_id=compose_id, phase="configuring",
            resource_url=service.service_url(panel, {
                "project_id": project_id, "environment_id": environment_id,
                "type": "compose", "id": compose_id,
            }) if panel else None,
        )
        await service.call("compose.update", body=update, mutation=True, parse=False)
        update.clear()
        job.set(phase="deploying")
        mark = await deploy_mark(service, compose_id)
        await service.call(
            "compose.deploy",
            body={"composeId": compose_id, "title": "Install from MrK DevAssist"},
            mutation=True, parse=False,
        )
        service.cache.clear()
        await self._audit(job, "install.auto.deploy")
        job.set(phase="waiting")
        await wait_deployment(service, compose_id, mark,
                              timeout=DEPLOY_TIMEOUT_SECONDS, poll=POLL_SECONDS)
        job.set(deployed=True)

    # ----- Coolify ---------------------------------------------------------
    async def _run_coolify(self, job: Job, body: AutoRequest, compose: str, env_text: str) -> None:
        call = self.coolify.call
        name = f"mrk-{job.service_id}"
        project_uuid = body.project_id
        environment_name = body.environment_name or "production"
        job.set(phase="creating")
        servers = _list(await call("GET", "/servers"))
        if body.server_id is not None:
            server = next((item for item in servers if item.get("uuid") == body.server_id), None)
            if server is None:
                raise AutoError("server_not_found", 404, "The Coolify server was not found")
        else:
            local = [item for item in servers if server_is_local(item)]
            candidates = local or servers
            if len(candidates) != 1:
                raise AutoError("server_required", 422,
                                "Pick the Coolify server that runs the panel")
            server = candidates[0]
        if not server_is_local(server):
            job.warnings.append("server_not_local")
        if project_uuid is None:
            created = await call("POST", "/projects", body={"name": PROJECT_NAME,
                                                            "description": DESCRIPTION})
            project_uuid = created.get("uuid") if isinstance(created, dict) else None
            if not isinstance(project_uuid, str):
                raise AutoError("coolify_rejected", 409, "Coolify did not return the new project")
            self.cache.clear()
            await self._audit(job, "install.auto.project.create")
        job.set(project_id=project_uuid)
        environments = _list(await call("GET", f"/projects/{project_uuid}/environments"))
        environment = next((env for env in environments
                            if env.get("name") == environment_name), None)
        existing = None
        if environment is not None and environment.get("id") is not None:
            existing = next(
                (item for item in _list(await call("GET", "/services"))
                 if item.get("name") == name
                 and item.get("environment_id") == environment.get("id")
                 and isinstance(item.get("uuid"), str)),
                None,
            )
        raw_b64 = base64.b64encode(compose.encode("utf-8")).decode("ascii")
        if existing is not None:
            uuid = existing["uuid"]
            job.set(reused=True, resource_id=uuid, phase="configuring")
            await call("PATCH", f"/services/{uuid}", body={"docker_compose_raw": raw_b64})
        else:
            payload: dict[str, Any] = {
                "project_uuid": project_uuid, "server_uuid": server["uuid"],
                "environment_name": environment_name, "name": name, "description": DESCRIPTION,
                "docker_compose_raw": raw_b64, "instant_deploy": False,
                "connect_to_docker_network": False,
            }
            created = await call("POST", "/services", body=payload)
            uuid = created.get("uuid") if isinstance(created, dict) else None
            if not isinstance(uuid, str):
                raise AutoError("coolify_rejected", 409, "Coolify did not return the new service")
            await self._audit(job, "install.auto.create")
            job.set(resource_id=uuid, phase="configuring")
        self.cache.clear()
        await self.record(job.service_id, {
            "target": "coolify", "uuid": uuid, "service_name": name,
            "project_id": project_uuid, "environment_name": environment_name,
            "server_id": server["uuid"],
        })
        job.set(resource_url=self.coolify.resolve()[0])
        await call("PATCH", f"/services/{uuid}/envs/bulk", body={"data": [
            {"key": key, "value": value, "is_literal": True}
            for key, value in env_pairs(env_text)
        ]})
        job.set(phase="deploying")
        action = "restart" if existing is not None else "start"
        try:
            await call("POST", f"/services/{uuid}/{action}")
        except CoolifyError as exc:
            if exc.code != "coolify_not_supported":
                raise
            await call("GET", f"/services/{uuid}/{action}")  # older v4 betas: GET only
        await self._audit(job, "install.auto.deploy")
        job.set(phase="waiting")
        deadline = time.monotonic() + DEPLOY_TIMEOUT_SECONDS
        while True:
            await asyncio.sleep(POLL_SECONDS)
            detail = await call("GET", f"/services/{uuid}")
            status = detail.get("status") if isinstance(detail, dict) else None
            del detail
            if not isinstance(status, str):
                break  # this Coolify does not report a status; the connect check decides
            lowered = status.lower()
            if lowered.startswith("running"):
                break
            if time.monotonic() > deadline:
                raise AutoError("deploy_timeout", 504,
                                "Coolify did not start the service in time; see its logs")
        job.set(deployed=True)

    # ----- connect ---------------------------------------------------------
    async def _connect(self, job: Job, attempts: int | None = None) -> None:
        job.set(phase="connecting", status="running", error_code=None, message=None)
        connection = None
        for attempt in range(attempts or CONNECT_ATTEMPTS):
            if attempt:
                await asyncio.sleep(CONNECT_DELAY_SECONDS)
            result = await self.install.connect(job.service_id, job.url, job.engine_url)
            connection = result.get("connection")
            if connection == "connected":
                break
        # Audit before the job shows as finished, so a finished job is always on record.
        if connection == "connected":
            await self._audit(job, "install.auto.connect")
            job.set(connection=connection, status="succeeded", phase="done")
            return
        await self._audit(job, "install.auto.connect", "failure")
        job.set(connection=connection, status="failed", error_code="connect_failed",
                message="The service was deployed but does not answer the panel yet")

    async def retry_connect(self, job: Job) -> None:
        if job.status == "running":
            raise AutoError("install_in_progress", 409, "This install is still running")
        if not job.deployed:
            raise AutoError("not_deployed", 409, "The service was not deployed")
        try:
            await self._connect(job, attempts=1)
        except InstallError as exc:
            await self._audit(job, "install.auto.connect", "failure")
            job.set(status="failed", error_code=exc.code, message=exc.message)

    async def stop(self) -> None:
        for task in list(self.tasks):
            task.cancel()
        for task in list(self.tasks):
            try:
                await task
            except (asyncio.CancelledError, Exception):  # noqa: S110 - shutting down
                pass


# ---------------------------------------------------------------------- routes


def register(ctx: ModuleContext) -> None:
    installer = AutoInstaller(ctx)
    router = APIRouter(tags=["install"])

    def failure(exc: AutoError | DokployError | CoolifyError | InstallError) -> JSONResponse:
        extra = getattr(exc, "extra", None) or {}
        return ctx.error_payload(exc.code, exc.message, exc.status_code, **extra)  # type: ignore[call-arg]

    def operator(request: Request, service_id: str, target: str | None = None):
        principal = ctx.require_principal(request, "services:operate")
        extra = WRITE_PERMISSION.get(service_id)
        if extra:
            ctx.require_principal(request, extra)
        if target == "dokploy":
            ctx.require_principal(request, "dokploy:deploy")
        ctx.require_csrf(request, principal)
        return principal

    async def audit(principal: Any, action: str, object_id: str, result: str = "success") -> None:
        await asyncio.to_thread(ctx.audit, principal.user_id, action, "coolify", object_id, result)

    def find_job(job_id: str) -> Job | None:
        return installer.jobs.get(job_id) if JOB_ID_RE.fullmatch(job_id) else None

    @router.get("/api/v1/install/targets")
    async def install_targets(request: Request, refresh: bool = False):
        principal = ctx.require_principal(request, "services:operate")
        return await installer.targets(principal, refresh)

    @router.post("/api/v1/install/{service_id}/auto", status_code=202)
    async def install_auto(service_id: str, request: Request, body: AutoRequest):
        principal = operator(request, service_id, body.target)
        try:
            job = await installer.start(principal, service_id, body)
        except (AutoError, InstallError) as exc:
            await asyncio.to_thread(
                ctx.audit, principal.user_id, "install.auto.start", "service", service_id[:64],
                "failure",
            )
            return failure(exc)
        await asyncio.to_thread(
            ctx.audit, principal.user_id, "install.auto.start", "service", service_id
        )
        return JSONResponse(job.view(), status_code=202)

    @router.get("/api/v1/install/auto/jobs/{job_id}")
    async def install_job(job_id: str, request: Request):
        ctx.require_principal(request, "services:operate")
        job = find_job(job_id)
        if job is None:
            return ctx.error_payload("job_not_found", "Install job not found", 404)
        return job.view()

    @router.post("/api/v1/install/auto/jobs/{job_id}/connect")
    async def install_job_connect(job_id: str, request: Request):
        job = find_job(job_id)
        if job is None:
            ctx.require_principal(request, "services:operate")
            return ctx.error_payload("job_not_found", "Install job not found", 404)
        operator(request, job.service_id)
        try:
            await installer.retry_connect(job)
        except AutoError as exc:
            return failure(exc)
        return job.view()

    # ----- Coolify connection -------------------------------------------------
    @router.get("/api/v1/coolify/config")
    async def coolify_config(request: Request):
        ctx.require_principal(request, "services:operate")
        return installer.coolify.view()

    @router.put("/api/v1/coolify/config")
    async def coolify_put(request: Request, body: CoolifyConfigRequest):
        principal = ctx.require_principal(request, "services:operate")
        ctx.require_csrf(request, principal)
        try:
            await asyncio.to_thread(installer.coolify.save, body.url, body.token)
        except CoolifyError as exc:
            await audit(principal, "coolify.config.update", "coolify", "failure")
            return failure(exc)
        except ValueError as exc:
            message = str(exc)
            code = "invalid_coolify_token" if "token" in message else "invalid_coolify_url"
            return ctx.error_payload(code, message, 422)
        installer.cache.clear()
        await audit(principal, "coolify.config.update", "coolify")
        return installer.coolify.view()

    @router.delete("/api/v1/coolify/config")
    async def coolify_delete(request: Request, body: ConfirmationRequest):
        principal = ctx.require_principal(request, "services:operate")
        ctx.require_csrf(request, principal)
        if body.confirmation != "DISCONNECT":
            return ctx.error_payload("confirmation_required", 'Type "DISCONNECT" to confirm', 422)
        await asyncio.to_thread(installer.coolify.disconnect)
        installer.cache.clear()
        await audit(principal, "coolify.disconnect", "coolify")
        return installer.coolify.view()

    @router.post("/api/v1/coolify/test")
    async def coolify_test(request: Request):
        principal = ctx.require_principal(request, "services:operate")
        ctx.require_csrf(request, principal)
        raw = await request.body()
        try:
            body = CoolifyTestRequest.model_validate_json(raw) if raw.strip() else None
        except ValueError:
            return ctx.error_payload("validation_error", "Invalid request body", 422)
        try:
            result = await installer.coolify.test(
                body.url if body else None, body.token if body else None
            )
        except CoolifyError as exc:
            return failure(exc)
        except ValueError as exc:
            message = str(exc)
            code = "invalid_coolify_token" if "token" in message else "invalid_coolify_url"
            return ctx.error_payload(code, message, 422)
        await audit(principal, "coolify.test", "coolify", "success" if result["ok"] else "failure")
        return result

    ctx.routers.append(router)
    ctx.stop_hooks.append(installer.stop)
