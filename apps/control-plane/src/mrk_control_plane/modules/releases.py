"""Panel versions and updates (release model: VERSION -> tag vX.Y.Z -> images X.Y.Z).

Every release publishes ``<registry>/mrk-<id>:X.Y.Z`` (plus ``X.Y`` and ``latest``)
and the panel image carries its own tag in ``MRK_IMAGE_TAG``, so the panel always
knows which image of each service belongs to it.

* Latest version: the tags of ``<registry>/mrk-panel`` through the OCI distribution
  API (``GET /v2/<repo>/tags/list``) with the anonymous bearer-token challenge,
  through the mirrors and outbound proxy configured for image updates. Checked at
  startup (after a delay) and every 12 hours; ``release.available`` is published
  once per newly seen version.
* Services: where each installed service runs (install.json), which image it was
  deployed with and whether the current panel would deploy another one. Services
  the panel deployed through Dokploy or Coolify are upgraded in the background:
  only the ``MRK_IMAGE=`` line of their env changes (pairing keys and every other
  value stay), the compose file becomes the current template, then it is
  redeployed. Others get the new compose file, the one env line and the steps.
* Panel self-update: a panel that runs as a Dokploy compose sets
  ``MRK_PANEL_IMAGE`` in its own env and redeploys; otherwise the commands.

Routes (``/api/v1/releases``): ``GET /status``, ``POST /check``,
``POST /services/{id}/upgrade``, ``GET /jobs/{job}``, ``GET /services/{id}/manual``,
``POST /services/{id}/mark-updated``, ``POST /panel/upgrade``.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import copy
import json
import logging
import os
import re
import secrets
import threading
import time
from collections import OrderedDict
from collections.abc import Callable
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlsplit

import httpx
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from .. import __version__, outbound
from ..logging_config import redact_text
from ..module_context import Event, ModuleContext
from ..netresolve import resolve_host
from .coolify_client import CoolifyError
from .dokploy_client import DokployError
from .dokploy_locate import (
    LocateError,
    apply_image,
    compose_detail,
    deploy_mark,
    find_compose,
    wait_deployment,
)
from .dokploy_locate import sha256 as text_sha256
from .install import WRITE_PERMISSION, InstallError, InstallService
from .install_auto import CoolifySettings, Job, deployment_for
from .install_catalog import (
    INSTALL_INDEX,
    INSTALLABLE,
    InstallDef,
    compose_for,
    image_registry,
    image_tag,
    panel_is_native,
    public_item,
)
from .updates_refs import InvalidReference, parse_challenge, parse_reference
from .updates_settings import DEFAULT_SETTINGS, endpoints_for, proxy_for

LOGGER = logging.getLogger(__name__)
MODULE_NAME = "releases"
STATE_FILE = "releases.json"
NOTES_URL = "https://github.com/SeniorKian/MrK_DevAssist/releases/tag/v{version}"
USER_AGENT = "MRK-ReleaseCheck/1"
# Tunables (tests shorten them).
STARTUP_DELAY_SECONDS = 90.0
CHECK_INTERVAL_SECONDS = 12 * 3600.0
RETRY_SECONDS = 1800.0
POLL_SECONDS = 3.0
DEPLOY_TIMEOUT_SECONDS = 900.0
CONNECT_ATTEMPTS = 20
CONNECT_DELAY_SECONDS = 3.0
MAX_TAG_PAGES = 10
MAX_BODY_BYTES = 1024 * 1024
MAX_TOKEN_BYTES = 64 * 1024
MAX_JOBS = 50
MAX_NOTIFIED = 50
SEMVER_RE = re.compile(r"^v?(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})$")
JOB_ID_RE = re.compile(r"^[A-Za-z0-9_-]{8,32}$")
_NEXT_LINK = re.compile(r'<([^>]+)>\s*;\s*rel="?next"?', re.IGNORECASE)

# Tests replace these (httpx.MockTransport / a fixed resolver).
TRANSPORT_FACTORY: Callable[[], httpx.AsyncBaseTransport] | None = None
RESOLVER: outbound.Resolver | None = None

ACTIVE_SERVICE: ReleasesService | None = None


def _resolve(host: str, port: int, config: Any) -> list[str]:
    if RESOLVER is not None:
        return RESOLVER(host, port, config)
    return resolve_host(host, port, config)


def parse_semver(text: Any) -> tuple[int, int, int] | None:
    match = SEMVER_RE.fullmatch(text) if isinstance(text, str) else None
    return (int(match.group(1)), int(match.group(2)), int(match.group(3))) if match else None


def version_text(parts: tuple[int, int, int]) -> str:
    return ".".join(str(part) for part in parts)


def pick_latest(tags: list[str]) -> tuple[str, str] | None:
    """Highest stable ``X.Y.Z`` (or ``vX.Y.Z``) tag: (version, tag as published)."""
    best: tuple[tuple[int, int, int], str] | None = None
    for tag in tags:
        parts = parse_semver(tag)
        if parts is None:
            continue
        # Prefer the bare "X.Y.Z" spelling when both exist.
        if best is None or parts > best[0] or (parts == best[0] and not tag.startswith("v")):
            best = (parts, tag)
    return (version_text(best[0]), best[1]) if best else None


def set_env_line(env_text: str, name: str, value: str) -> str:
    """Replace ``name=...`` (every occurrence) or append it; nothing else changes."""
    lines = env_text.splitlines()
    found = False
    pattern = re.compile(rf"^\s*(?:export\s+)?{re.escape(name)}\s*=")
    for index, line in enumerate(lines):
        if pattern.match(line):
            lines[index] = f"{name}={value}"
            found = True
    if not found:
        lines.append(f"{name}={value}")
    return "\n".join(lines) + "\n"


def panel_image(version: str) -> str:
    return f"{image_registry()}/mrk-panel:{version}"


class ReleaseError(Exception):
    def __init__(self, code: str, status_code: int, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.status_code = status_code
        self.message = message


class CheckFailed(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class PanelUpgradeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    version: str = Field(min_length=5, max_length=24)
    confirmation: str | None = Field(default=None, max_length=32)


# ---------------------------------------------------------------------- tag listing


class TagLister:
    """``GET /v2/<repo>/tags/list`` with the anonymous bearer challenge, no redirects."""

    def __init__(self, client: Any, scheme: str, netloc: str) -> None:
        self.client = client
        self.scheme = scheme
        self.netloc = netloc
        self.token: str | None = None

    async def _read(self, response: httpx.Response, limit: int) -> bytes:
        body = bytearray()
        try:
            async for chunk in response.aiter_bytes():
                body.extend(chunk)
                if len(body) > limit:
                    raise CheckFailed("response_too_large")
        finally:
            await response.aclose()
        return bytes(body)

    async def _fetch_token(self, challenge: dict[str, str], repo: str) -> str:
        realm = challenge.get("realm", "")
        parts = urlsplit(realm)
        allowed = {"https"} if self.scheme == "https" else {"https", "http"}
        if parts.scheme not in allowed or not parts.hostname or parts.username or parts.password:
            raise CheckFailed("auth_required")
        query: dict[str, str] = {"scope": challenge.get("scope") or f"repository:{repo}:pull"}
        if challenge.get("service"):
            query["service"] = challenge["service"]
        url = str(httpx.URL(realm).copy_merge_params(query))
        response = await self.client.send(
            "GET", url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
            stream=True,
        )
        status = response.status_code
        body = await self._read(response, MAX_TOKEN_BYTES)
        if status in (401, 403):
            raise CheckFailed("auth_required")
        if status == 429:
            raise CheckFailed("rate_limited")
        if status != 200:
            raise CheckFailed("unreachable")
        try:
            payload = json.loads(body)
        except ValueError:
            raise CheckFailed("auth_required") from None
        token = (payload.get("token") or payload.get("access_token")) if isinstance(
            payload, dict) else None
        if not isinstance(token, str) or not token or len(token) > 16384:
            raise CheckFailed("auth_required")
        return token

    async def _get(self, url: str, repo: str) -> httpx.Response:
        headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        response = await self.client.send("GET", url, headers=headers, stream=True)
        if response.status_code == 401 and self.token is None:
            challenge = parse_challenge(response.headers.get("www-authenticate"))
            await response.aclose()
            if challenge is None or challenge[0] != "bearer" or not challenge[1].get("realm"):
                raise CheckFailed("auth_required")
            self.token = await self._fetch_token(challenge[1], repo)
            headers["Authorization"] = f"Bearer {self.token}"
            response = await self.client.send("GET", url, headers=headers, stream=True)
        return response

    async def tags(self, repo: str) -> list[str]:
        url = f"{self.scheme}://{self.netloc}/v2/{repo}/tags/list?n=1000"
        tags: list[str] = []
        for _page in range(MAX_TAG_PAGES):
            response = await self._get(url, repo)
            status = response.status_code
            link = response.headers.get("link") or ""
            body = await self._read(response, MAX_BODY_BYTES)
            if status in (401, 403):
                raise CheckFailed("auth_required")
            if status == 404:
                raise CheckFailed("not_found")
            if status == 429:
                raise CheckFailed("rate_limited")
            if status != 200:  # redirects are not followed
                raise CheckFailed("unreachable")
            try:
                payload = json.loads(body)
            except ValueError:
                raise CheckFailed("invalid_response") from None
            items = payload.get("tags") if isinstance(payload, dict) else None
            if items is not None and not isinstance(items, list):
                raise CheckFailed("invalid_response")
            tags.extend(item for item in items or [] if isinstance(item, str) and len(item) <= 128)
            match = _NEXT_LINK.search(link)
            if match is None:
                return tags
            following = urljoin(url, match.group(1))
            if urlsplit(following).netloc != self.netloc:
                return tags  # never follow a page to another host
            url = following
        return tags


# ---------------------------------------------------------------------- service


class ReleasesService:
    def __init__(self, ctx: ModuleContext, clock: Callable[[], float] = time.time) -> None:
        self.ctx = ctx
        self.clock = clock
        self.path: Path = ctx.data_dir / "control-plane" / STATE_FILE
        self.install = InstallService(ctx)
        self.coolify = CoolifySettings(ctx)
        self.jobs: OrderedDict[str, Job] = OrderedDict()
        self.tasks: set[asyncio.Task[None]] = set()
        self._lock = threading.Lock()
        self._check_lock = asyncio.Lock()
        self._state_lock = asyncio.Lock()
        self._task: asyncio.Task[None] | None = None
        self._wake: asyncio.Event | None = None
        self.checking = False
        self.state = self._load()

    # ----- persistence ------------------------------------------------------
    @staticmethod
    def _empty() -> dict[str, Any]:
        return {"latest_version": None, "latest_tag": None, "checked_at": None,
                "attempted_at": None, "error_code": None, "notified": []}

    def _load(self) -> dict[str, Any]:
        state = self._empty()
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return state
        if isinstance(raw, dict):
            if parse_semver(raw.get("latest_version")) and isinstance(raw.get("latest_tag"), str):
                state["latest_version"] = raw["latest_version"]
                state["latest_tag"] = raw["latest_tag"]
            for key in ("checked_at", "attempted_at"):
                if isinstance(raw.get(key), int | float):
                    state[key] = float(raw[key])
            if isinstance(raw.get("error_code"), str):
                state["error_code"] = raw["error_code"][:64]
            notified = raw.get("notified")
            if isinstance(notified, list):
                kept = [item for item in notified if parse_semver(item)]
                state["notified"] = kept[-MAX_NOTIFIED:]
        return state

    def _save(self) -> None:
        with self._lock:
            payload = json.dumps(self.state, sort_keys=True) + "\n"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_name(f".{STATE_FILE}.{secrets.token_hex(4)}.tmp")
        temporary.write_bytes(payload.encode("utf-8"))
        with contextlib.suppress(OSError):
            temporary.chmod(0o600)
        os.replace(temporary, self.path)

    # ----- current / latest -------------------------------------------------
    @staticmethod
    def current() -> dict[str, Any]:
        tag = image_tag()
        version = version_text(parse_semver(tag)) if parse_semver(tag) else __version__
        return {"version": version, "image_tag": tag,
                "runtime": "native" if panel_is_native() else "docker"}

    def latest(self) -> dict[str, Any]:
        with self._lock:
            state = copy.deepcopy(self.state)
        version = state["latest_version"]
        return {
            "version": version,
            "tag": state["latest_tag"],
            "checked_at": state["checked_at"],
            "attempted_at": state["attempted_at"],
            "error_code": state["error_code"],
            "notes_url": NOTES_URL.format(version=version) if version else None,
            "checking": self.checking,
        }

    def update_available(self) -> bool:
        latest = parse_semver(self.state.get("latest_version"))
        current = parse_semver(self.current()["version"])
        return bool(latest and current and latest > current)

    def _settings(self) -> dict[str, Any]:
        from . import updates

        service = updates.ACTIVE_SERVICE
        if service is not None and service.ctx is self.ctx:
            try:
                return service.settings
            except Exception:  # noqa: BLE001 - fall back to the defaults
                LOGGER.warning("image update settings unavailable; using defaults")
        return copy.deepcopy(DEFAULT_SETTINGS)

    async def _list_tags(self) -> list[str]:
        try:
            ref = parse_reference(f"{image_registry()}/mrk-panel:latest")
        except InvalidReference as exc:
            raise CheckFailed("invalid_registry") from exc
        settings = self._settings()
        timeout = float(settings.get("timeout_seconds") or 15)
        first: str | None = None
        for endpoint in endpoints_for(ref.registry, settings):
            proxy_ref = proxy_for(ref.registry, endpoint, settings)
            try:
                async with outbound.outbound_client(
                    self.ctx.network_settings, self.ctx.secret_store, proxy_ref,
                    timeout=timeout,
                    transport=TRANSPORT_FACTORY() if TRANSPORT_FACTORY else None,
                    resolver=_resolve,
                ) as client:
                    lister = TagLister(client, endpoint.scheme, endpoint.netloc)
                    return await lister.tags(endpoint.repository(ref.repository))
            except CheckFailed as exc:
                code = exc.code
            except outbound.ProxyUnavailable:
                code = "proxy_unavailable"
            except httpx.ProxyError:
                code = "proxy_unavailable"
            except Exception as exc:  # noqa: BLE001 - never echo: messages may carry URLs
                network = isinstance(exc, outbound.OutboundError | httpx.HTTPError | OSError)
                code = "unreachable" if network else "check_failed"
            first = first or code
        raise CheckFailed(first or "unreachable")

    async def check(self) -> dict[str, Any]:
        async with self._check_lock:
            self.checking = True
            try:
                await self._check()
            finally:
                self.checking = False
        return self.latest()

    async def _check(self) -> None:
        now = self.clock()
        try:
            tags = await self._list_tags()
        except CheckFailed as exc:
            with self._lock:
                self.state["attempted_at"] = now
                self.state["error_code"] = exc.code
            await asyncio.to_thread(self._save)
            return
        picked = pick_latest(tags)
        event: Event | None = None
        with self._lock:
            self.state["attempted_at"] = now
            self.state["checked_at"] = now
            if picked is None:
                self.state["error_code"] = "no_release"
            else:
                self.state["error_code"] = None
                self.state["latest_version"], self.state["latest_tag"] = picked
        if picked is not None and self.update_available():
            version = picked[0]
            with self._lock:
                fresh = version not in self.state["notified"]
                if fresh:
                    self.state["notified"] = [*self.state["notified"], version][-MAX_NOTIFIED:]
            if fresh:
                event = self._event(version)
        await asyncio.to_thread(self._save)
        if event is not None:
            self.ctx.events.publish(event)

    def _event(self, version: str) -> Event:
        current = self.current()["version"]
        notes = NOTES_URL.format(version=version)
        return Event(
            type="release.available",
            severity="info",
            title=f"MrK DevAssist {version} is available",
            message=(f"This panel runs {current}. Version {version} is out ({notes}). "
                     "Update the panel first, then the services, from Versions & updates."),
            module=MODULE_NAME,
            dedupe_key=f"release.available:{version}",
            details={"version": version, "current": current, "notes_url": notes},
        )

    # ----- services ---------------------------------------------------------
    def _targets_ready(self) -> dict[str, bool]:
        from . import dokploy as dokploy_module

        service = dokploy_module.ACTIVE_SERVICE
        dokploy_ok = False
        if service is not None and service.ctx is self.ctx:
            source, url, _key = service.resolve()
            dokploy_ok = source is not None and url is not None
        return {"dokploy": dokploy_ok, "coolify": self.coolify.configured()}

    def _dokploy(self) -> Any:
        from . import dokploy as dokploy_module

        service = dokploy_module.ACTIVE_SERVICE
        if service is None or service.ctx is not self.ctx:
            raise ReleaseError("module_unavailable", 503, "The Dokploy module is not loaded")
        return service

    def _agent(self) -> Any | None:
        from . import services as services_module

        service = services_module.ACTIVE_SERVICE
        if service is None or getattr(service, "ctx", None) is not self.ctx:
            return None
        try:
            return service.routing.agent()
        except Exception:  # noqa: BLE001 - the agent is optional
            return None

    async def _running_images(self) -> dict[str, str]:
        """``mrk-<id>`` compose service -> image of its running container (Host Agent)."""
        agent = self._agent()
        if agent is None:
            return {}
        try:
            payload = await asyncio.wait_for(agent.call("/v1/docker/containers"), 10)
        except Exception:  # noqa: BLE001 - fall back to what install.json remembers
            return {}
        images: dict[str, str] = {}
        items = payload.get("items", []) if isinstance(payload, dict) else []
        for item in items if isinstance(items, list) else []:
            if not isinstance(item, dict):
                continue
            labels = item.get("labels_subset") or {}
            name = labels.get("com.docker.compose.service")
            swarm = str(labels.get("com.docker.swarm.service.name") or "")
            if not isinstance(name, str) and "_mrk-" in swarm:
                name = "mrk-" + swarm.split("_mrk-", 1)[1]
            image = item.get("image")
            running = str(item.get("state") or "running").lower() == "running"
            if isinstance(name, str) and isinstance(image, str) and running:
                images[name] = image
        return images

    def _service_info(self, item: InstallDef, state: dict[str, Any],
                      ready: dict[str, bool], running: dict[str, str]) -> dict[str, Any]:
        entry = state.get(item.id) if isinstance(state.get(item.id), dict) else None
        deployment = entry.get("deployment") if entry else None
        target = deployment.get("target") if isinstance(deployment, dict) else None
        target = target if target in {"dokploy", "coolify"} and target in item.methods else None
        live = running.get(f"mrk-{item.id}")
        if target is None and live and "dokploy" in item.methods and ready.get("dokploy"):
            # Running in Dokploy although the panel did not deploy it: found on update.
            target = "dokploy"
        recorded = entry.get("image") if entry and isinstance(entry.get("image"), str) else None
        return {
            "id": item.id,
            "image": public_item(item)["image"],
            # What really runs wins over what the panel last wrote.
            "deployed_image": live or recorded,
            "running": live is not None,
            "installed": entry is not None or live is not None,
            "target": target,
            "can_auto": bool(target and ready.get(target)),
        }

    async def services(self) -> list[dict[str, Any]]:
        state = await asyncio.to_thread(self.install._read)
        ready = self._targets_ready()
        items = [item for item in INSTALLABLE if item.availability == "ready"]

        async def connection(item: InstallDef) -> str:
            try:
                return await asyncio.wait_for(self.install.connection_state(item.id), 10)
            except Exception:  # noqa: BLE001 - a probe never breaks the page
                return "unreachable"

        states, running = await asyncio.gather(
            asyncio.gather(*(connection(item) for item in items)), self._running_images())
        result = []
        for item, state_name in zip(items, states, strict=True):
            info = self._service_info(item, state, ready, running)
            info["connection"] = state_name
            in_use = info["target"] is not None or state_name in {"connected", "unreachable"}
            info["needs_update"] = bool(
                info["installed"] and in_use and info["deployed_image"] != info["image"]
            )
            result.append(info)
        return result

    async def _record_image(self, service_id: str, image: str) -> None:
        async with self._state_lock:
            def write() -> None:
                state = self.install._read()
                entry = state.get(service_id)
                entry = dict(entry) if isinstance(entry, dict) else {}
                entry["image"] = image
                entry["updated_at"] = int(time.time())
                state[service_id] = entry
                self.install._write(state)

            await asyncio.to_thread(write)

    def _compose(self, item: InstallDef) -> str:
        """The current template with the folders chosen at install time (never lost)."""
        from .install_storage import apply as apply_storage

        entry = (self.install.pending(item.id) or {})
        storage = entry.get("storage") if isinstance(entry.get("storage"), dict) else {}
        return apply_storage(compose_for(item, self.ctx.data_dir), item.id, storage)

    def _ready_item(self, service_id: str) -> InstallDef:
        item = INSTALL_INDEX.get(service_id)
        if item is None or item.availability != "ready":
            raise ReleaseError("service_not_found", 404, "Unknown service")
        return item

    def manual(self, service_id: str) -> dict[str, Any]:
        item = self._ready_item(service_id)
        image = str(public_item(item)["image"])
        env_change = None if item.upstream_image else f"MRK_IMAGE={image}"
        return {
            "id": item.id,
            "image": image,
            "compose": self._compose(item),
            "env_change": env_change,
            "file_names": {"compose": "compose.yaml"},
            "steps": manual_steps(env_change is not None),
            "commands": ["docker compose pull", "docker compose up -d"],
        }

    async def mark_updated(self, service_id: str) -> dict[str, Any]:
        item = self._ready_item(service_id)
        image = str(public_item(item)["image"])
        await self._record_image(service_id, image)
        return {"id": service_id, "deployed_image": image}

    # ----- service upgrade --------------------------------------------------
    def find_job(self, job_id: str) -> Job | None:
        return self.jobs.get(job_id) if JOB_ID_RE.fullmatch(job_id) else None

    async def start_upgrade(self, principal: Any, service_id: str) -> Job:
        item = self._ready_item(service_id)
        deployment = deployment_for(self.ctx.data_dir, service_id) or {}
        target = deployment.get("target")
        ready = self._targets_ready()
        if target is None and "dokploy" in item.methods and ready.get("dokploy"):
            # Pasted into Dokploy by hand: the update finds its Compose in Dokploy.
            target = "dokploy"
            deployment = {"target": "dokploy", "service_name": f"mrk-{service_id}"}
        if target not in {"dokploy", "coolify"} or target not in item.methods:
            raise ReleaseError("manual_upgrade", 409,
                               "The panel did not deploy this service; update it by hand")
        if not ready.get(target):
            raise ReleaseError(f"{target}_not_configured", 409, f"{target} is not connected")
        if target == "coolify" and not isinstance(deployment.get("uuid"), str):
            raise ReleaseError("manual_upgrade", 409, "The Coolify service is not recorded")
        for job in self.jobs.values():
            if job.service_id == service_id and job.status == "running":
                raise ReleaseError("upgrade_in_progress", 409,
                                   "An update of this service is already running")
        job = Job(id=secrets.token_urlsafe(12), service_id=service_id, target=target,
                  actor_user_id=getattr(principal, "user_id", None))
        job.resource_id = deployment.get("compose_id") or deployment.get("uuid")
        self.jobs[job.id] = job
        while len(self.jobs) > MAX_JOBS:
            oldest = next(iter(self.jobs))
            if self.jobs[oldest].status == "running":
                break
            self.jobs.pop(oldest)
        task = asyncio.create_task(self._run(job, item, deployment),
                                   name=f"mrk-release-upgrade-{service_id}")
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)
        return job

    async def _audit(self, job: Job, action: str, result: str = "success") -> None:
        await asyncio.to_thread(
            self.ctx.audit, job.actor_user_id, action, "service", job.service_id, result
        )

    def _side_files(self, service_id: str) -> None:
        """Config files some templates read from the shared volume (same as /bundle)."""
        if service_id == "registry":
            helper = self.install._helper("registry")
            if helper is not None:
                helper.write_files()
        elif service_id == "npm":
            from .. import remote_services

            remote_services.write_npm_config(self.ctx.data_dir)

    async def _run(self, job: Job, item: InstallDef, deployment: dict[str, Any]) -> None:
        image = str(public_item(item)["image"])
        try:
            compose = self._compose(item)
            await asyncio.to_thread(self._side_files, item.id)
            if job.target == "dokploy":
                await self._upgrade_dokploy(job, item, deployment, compose, image)
            else:
                await self._upgrade_coolify(job, item, deployment["uuid"], compose, image)
            await self._record_image(item.id, image)
            await self._wait_connected(job)
        except asyncio.CancelledError:
            job.set(status="failed", error_code="cancelled", message="The panel stopped")
            raise
        except (DokployError, CoolifyError, ReleaseError, InstallError, LocateError) as exc:
            await self._audit(job, f"release.upgrade.{job.phase}", "failure")
            job.set(status="failed", error_code=exc.code, message=redact_text(exc.message)[:300])
        except Exception as exc:  # never log the text: it could carry env values
            LOGGER.error("service upgrade failed", extra={"error_type": type(exc).__name__})
            await self._audit(job, f"release.upgrade.{job.phase}", "failure")
            job.set(status="failed", error_code="upgrade_failed",
                    message="The update failed unexpectedly")

    async def _record_deployment(self, service_id: str, deployment: dict[str, Any]) -> None:
        async with self._state_lock:
            def write() -> None:
                state = self.install._read()
                entry = state.get(service_id)
                entry = dict(entry) if isinstance(entry, dict) else {}
                entry["deployment"] = {**deployment, "updated_at": int(time.time())}
                state[service_id] = entry
                self.install._write(state)

            await asyncio.to_thread(write)

    async def _upgrade_dokploy(self, job: Job, item: InstallDef, deployment: dict[str, Any],
                               compose: str, image: str) -> None:
        """Update a service in Dokploy the way an admin would, keeping their changes.

        The Compose is found in Dokploy (its id may have changed), the image moves through
        a shared variable when the line uses one, and the Compose file is replaced only
        when it is still the one the panel wrote.
        """
        service = self._dokploy()
        job.set(phase="configuring")
        name = f"mrk-{item.id}"
        recorded = deployment.get("compose_id")
        found = await find_compose(service, name, known=(recorded,), agent=self._agent())
        if found is None:
            raise ReleaseError("service_missing", 404,
                               f"No Dokploy Compose runs {name}; update it by hand")
        compose_id = str(found["compose_id"])
        job.set(resource_id=compose_id)
        one = await compose_detail(service, compose_id)
        if one is None:
            raise ReleaseError("service_missing", 404, "The Dokploy service was not found")
        body: dict[str, Any] = {"composeId": compose_id}
        if item.upstream_image is None:
            env_text, shared = await apply_image(service, one, "MRK_IMAGE", image)
            if env_text is not None:
                body["env"] = env_text
            if shared:
                job.warnings.append("shared_version_changed")
        current_file = one.get("composeFile") if isinstance(one.get("composeFile"), str) else ""
        del one
        written = deployment.get("compose_sha256")
        new_hash = text_sha256(compose)
        if text_sha256(current_file) == new_hash:
            pass  # already the current template
        elif written and written == text_sha256(current_file):
            body["composeFile"] = compose  # still the panel's own file: safe to replace
        else:
            new_hash = written  # the admin changed it: keep theirs, say so
            job.warnings.append("compose_customized")
        if len(body) > 1:
            await service.call("compose.update", body=body, mutation=True, parse=False)
        body.clear()
        if compose_id != recorded or new_hash != written:
            await self._record_deployment(item.id, {
                **deployment, "target": "dokploy", "compose_id": compose_id,
                "service_name": name,
                "project_id": found.get("project_id") or deployment.get("project_id"),
                "environment_id": found.get("environment_id")
                or deployment.get("environment_id"),
                "compose_sha256": new_hash,
            })
        job.set(phase="deploying")
        before = await deploy_mark(service, compose_id)
        await service.call(
            "compose.deploy",
            body={"composeId": compose_id, "title": "Update from MrK DevAssist"},
            mutation=True, parse=False,
        )
        service.cache.clear()
        await self._audit(job, "release.upgrade.deploy")
        job.set(phase="waiting")
        await wait_deployment(service, compose_id, before,
                              timeout=DEPLOY_TIMEOUT_SECONDS, poll=POLL_SECONDS)
        job.set(deployed=True)

    async def _upgrade_coolify(self, job: Job, item: InstallDef, uuid: str,
                               compose: str, image: str) -> None:
        call = self.coolify.call
        job.set(phase="configuring")
        raw_b64 = base64.b64encode(compose.encode("utf-8")).decode("ascii")
        await call("PATCH", f"/services/{uuid}", body={"docker_compose_raw": raw_b64})
        if item.upstream_image is None:
            # Only this one variable: the pairing key and the other values stay as they are.
            await call("PATCH", f"/services/{uuid}/envs/bulk", body={"data": [
                {"key": "MRK_IMAGE", "value": image, "is_literal": True}]})
        job.set(phase="deploying")
        try:
            await call("POST", f"/services/{uuid}/restart")
        except CoolifyError as exc:
            if exc.code != "coolify_not_supported":
                raise
            await call("GET", f"/services/{uuid}/restart")  # older v4 betas: GET only
        await self._audit(job, "release.upgrade.deploy")
        job.set(phase="waiting")
        deadline = time.monotonic() + DEPLOY_TIMEOUT_SECONDS
        while True:
            await asyncio.sleep(POLL_SECONDS)
            detail = await call("GET", f"/services/{uuid}")
            status = detail.get("status") if isinstance(detail, dict) else None
            del detail
            if not isinstance(status, str) or status.lower().startswith("running"):
                break
            if time.monotonic() > deadline:
                raise ReleaseError("deploy_timeout", 504,
                                   "Coolify did not start the service in time; see its logs")
        job.set(deployed=True)

    async def _wait_connected(self, job: Job) -> None:
        """Check the existing connection again; it is never re-paired or re-keyed."""
        job.set(phase="connecting")
        connection = None
        for attempt in range(CONNECT_ATTEMPTS):
            if attempt:
                await asyncio.sleep(CONNECT_DELAY_SECONDS)
            connection = await self.install.connection_state(job.service_id)
            if connection in {"connected", "not_connected", "unavailable"}:
                break
        if connection in {"connected", "not_connected", "unavailable"}:
            await self._audit(job, "release.upgrade.done")
            job.set(connection=connection, status="succeeded", phase="done")
            return
        await self._audit(job, "release.upgrade.connect", "failure")
        job.set(connection=connection, status="failed", error_code="connect_failed",
                message="The service was updated but does not answer the panel yet")

    # ----- panel ------------------------------------------------------------
    async def _detected(self) -> dict[str, Any] | None:
        from . import services as services_module

        service = services_module.ACTIVE_SERVICE
        if service is None or getattr(service, "ctx", None) is not self.ctx:
            return None
        try:
            return await service.routing.detect_quick()
        except Exception:  # noqa: BLE001 - detection is best effort
            return None

    async def panel(self) -> dict[str, Any]:
        current = self.current()
        version = self.state.get("latest_version") or current["version"]
        if current["runtime"] == "native":
            return {"method": "native", "can_auto": False, "commands": native_commands(version)}
        detected = await self._detected() or {}
        if (detected.get("inside_dokploy") and detected.get("dokploy_service_type") == "compose"
                and detected.get("dokploy_service_id")):
            return {"method": "dokploy", "can_auto": bool(detected.get("dokploy_connected")),
                    "commands": dokploy_commands(version)}
        return {"method": "compose", "can_auto": False, "commands": compose_commands(version)}

    async def upgrade_panel(self, version: str) -> dict[str, Any]:
        wanted = parse_semver(version)
        latest = parse_semver(self.state.get("latest_version"))
        if wanted is None or SEMVER_RE.fullmatch(version) is None or version.startswith("v"):
            raise ReleaseError("invalid_version", 422, "Give a release version such as 1.2.3")
        if latest is None:
            raise ReleaseError("latest_unknown", 409, "Check for a new version first")
        if wanted > latest:
            raise ReleaseError("invalid_version", 422, "That version has not been published")
        if self.current()["runtime"] == "native":
            raise ReleaseError("manual_upgrade", 409, "A native panel is updated from the shell")
        detected = await self._detected() or {}
        compose_id = detected.get("dokploy_service_id")
        if not (detected.get("inside_dokploy") and detected.get("dokploy_service_type") == "compose"
                and isinstance(compose_id, str) and detected.get("dokploy_connected")):
            raise ReleaseError("manual_upgrade", 409,
                               "The panel does not run as a Dokploy compose; update it by hand")
        service = self._dokploy()
        one = await compose_detail(service, compose_id)
        if one is None:
            raise ReleaseError("service_missing", 404, "The panel's Dokploy service was not found")
        compose_file = one.get("composeFile") if isinstance(one.get("composeFile"), str) else ""
        if "MRK_PANEL_IMAGE" not in compose_file:
            raise ReleaseError(
                "manual_upgrade", 409,
                "The panel's compose file does not read MRK_PANEL_IMAGE; change its image "
                "in Dokploy by hand",
            )
        image = panel_image(version_text(wanted))
        # Only the env (or the shared variable it reads) changes; the compose file stays.
        try:
            env_text, shared = await apply_image(service, one, "MRK_PANEL_IMAGE", image)
        except LocateError as exc:
            raise ReleaseError(exc.code, exc.status_code, exc.message) from None
        del one
        if env_text is not None:
            await service.call("compose.update", body={"composeId": compose_id, "env": env_text},
                               mutation=True, parse=False)
        del env_text
        await service.call(
            "compose.deploy",
            body={"composeId": compose_id, "title": f"Update MrK DevAssist to {version}"},
            mutation=True, parse=False,
        )
        service.cache.clear()
        return {"version": version_text(wanted), "image": image, "status": "deploying",
                "shared_variable": shared}

    async def status(self) -> dict[str, Any]:
        latest = self.latest()
        return {
            "current": self.current(),
            "latest": latest,
            "update_available": self.update_available(),
            "panel": await self.panel(),
            "services": await self.services(),
        }

    # ----- background -------------------------------------------------------
    def _next_due(self) -> float:
        with self._lock:
            checked, attempted = self.state["checked_at"], self.state["attempted_at"]
            failed = self.state["error_code"] is not None
        if failed and attempted is not None:
            return attempted + RETRY_SECONDS
        if checked is None:
            return 0.0
        return checked + CHECK_INTERVAL_SECONDS

    async def _loop(self) -> None:
        assert self._wake is not None
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(self._wake.wait(), STARTUP_DELAY_SECONDS)
        while True:
            self._wake.clear()
            delay = self._next_due() - self.clock()
            if delay <= 0:
                try:
                    await self.check()
                except asyncio.CancelledError:
                    raise
                except Exception:  # noqa: BLE001 - the loop must survive
                    LOGGER.exception("release check failed")
                await asyncio.sleep(1.0)
                continue
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(self._wake.wait(), min(max(delay, 1.0), 3600.0))

    async def start(self) -> None:
        self._wake = asyncio.Event()
        self._task = asyncio.create_task(self._loop(), name="mrk-release-check")

    async def stop(self) -> None:
        tasks = [self._task, *self.tasks]
        for task in tasks:
            if task is not None and not task.done():
                task.cancel()
        for task in tasks:
            if task is not None:
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await task
        self._task = None


# ---------------------------------------------------------------------- copy


def _cmd(title_fa: str, title_en: str, command: str) -> dict[str, str]:
    return {"title_fa": title_fa, "title_en": title_en, "command": command}


def native_commands(version: str) -> list[dict[str, str]]:
    return [
        _cmd("در پوشه کد پنل روی سرور، نسخه تازه را بگیرید و نصب کنید:",
             "In the panel's source folder on the server, fetch the new version and install it:",
             f"git fetch --tags && git checkout v{version} && "
             "sudo bash scripts/install-native.sh upgrade"),
    ]


def compose_commands(version: str) -> list[dict[str, str]]:
    return [
        _cmd("در فایل .env کنار compose.yaml پنل این خط را بگذارید (یا عوض کنید):",
             "In the .env next to the panel's compose.yaml, set (or change) this line:",
             f"MRK_PANEL_IMAGE={panel_image(version)}"),
        _cmd("اگر پنل را از کد گرفته‌اید، به‌جای آن می‌توانید کد را به نسخه تازه ببرید:",
             "If you run the panel from the source, you can move the code to the new version instead:",  # noqa: E501
             f"git fetch --tags && git checkout v{version}"),
        _cmd("بعد در همان پوشه این دستور را اجرا کنید:",
             "Then run this in the same folder:",
             "docker compose pull && docker compose up -d"),
    ]


def dokploy_commands(version: str) -> list[dict[str, str]]:
    return [
        _cmd("در Dokploy، در زبانه «Environment» سرویس پنل این خط را بگذارید و ذخیره کنید:",
             "In Dokploy, in the panel service's “Environment” tab, set this line and save:",
             f"MRK_PANEL_IMAGE={panel_image(version)}"),
        _cmd("اگر آن خط به متغیر پروژه اشاره می‌کند (مثل ${{project.MRK_VERSION}})، "
             "خط را دست نزنید و در «Environment» پروژه فقط این مقدار را بگذارید:",
             "If that line points at a project variable (like ${{project.MRK_VERSION}}), leave it "
             "and set only this value in the project's “Environment”:",
             f"MRK_VERSION={version}"),
        _cmd("بعد «Deploy» را بزنید؛ پنل چند ثانیه قطع می‌شود و با نسخه تازه برمی‌گردد.",
             "Then click “Deploy”; the panel goes away for a few seconds and comes back updated.",
             ""),
    ]


def manual_steps(env_line: bool) -> dict[str, list[dict[str, str]]]:
    env_fa = "در زبانه «Environment» فقط خط MRK_IMAGE را با خط بالا عوض کنید؛ بقیه خط‌ها، به‌خصوص کلید اتصال، همان بمانند. اگر MRK_IMAGE به متغیر پروژه اشاره می‌کند (مثل ${{project.MRK_VERSION}})، خط را دست نزنید و فقط آن متغیر را در «Environment» پروژه عوض کنید."  # noqa: E501
    env_en = "In the “Environment” tab change only the MRK_IMAGE line to the line above; keep every other line, especially the pairing key. If MRK_IMAGE points at a project variable (like ${{project.MRK_VERSION}}), leave the line and change only that variable in the project's “Environment”."  # noqa: E501
    steps: dict[str, list[dict[str, str]]] = {
        "dokploy": [
            {"fa": "در Dokploy سرویس Compose همین بخش را باز کنید.",
             "en": "In Dokploy open this part's Compose service."},
            {"fa": "در بخش «General» متن compose.yaml را با متن تازه عوض کنید و ذخیره کنید.",
             "en": "Under “General”, replace compose.yaml with the new text and save."},
        ],
        "coolify": [
            {"fa": "در Coolify منبع Compose همین بخش را باز کنید.",
             "en": "In Coolify open this part's Compose resource."},
            {"fa": "متن compose.yaml را با متن تازه عوض کنید و ذخیره کنید.",
             "en": "Replace compose.yaml with the new text and save."},
        ],
        "compose": [
            {"fa": "در پوشه این بخش روی سرور (مثلاً /opt/mrk-{id}) فایل compose.yaml را با فایل تازه عوض کنید.",  # noqa: E501
             "en": "In this part's folder on the server (for example /opt/mrk-{id}) replace compose.yaml with the new file."},  # noqa: E501
        ],
    }
    if env_line:
        steps["dokploy"].append({"fa": env_fa, "en": env_en})
        steps["coolify"].append({
            "fa": "در «Environment Variables» فقط مقدار MRK_IMAGE را عوض کنید؛ بقیه، به‌خصوص کلید اتصال، همان بمانند.",  # noqa: E501
            "en": "In “Environment Variables” change only MRK_IMAGE; keep the rest, especially the pairing key.",  # noqa: E501
        })
        steps["compose"].append({
            "fa": "در فایل .env همان پوشه فقط خط MRK_IMAGE را با خط بالا عوض کنید.",
            "en": "In the .env of that folder change only the MRK_IMAGE line to the line above.",
        })
    steps["dokploy"].append({"fa": "«Deploy» را بزنید و صبر کنید تا کار تمام شود.",
                             "en": "Click “Deploy” and wait until it finishes."})
    steps["coolify"].append({"fa": "«Redeploy» را بزنید و صبر کنید تا کار تمام شود.",
                             "en": "Click “Redeploy” and wait until it finishes."})
    steps["compose"].append({"fa": "در همان پوشه این دو دستور را اجرا کنید:",
                             "en": "In that folder run these two commands:"})
    return steps


# ---------------------------------------------------------------------- routes


def register(ctx: ModuleContext) -> None:
    global ACTIVE_SERVICE
    service = ReleasesService(ctx)
    ACTIVE_SERVICE = service
    router = APIRouter(prefix="/api/v1/releases", tags=["releases"])

    def failure(exc: ReleaseError | DokployError | CoolifyError | InstallError) -> JSONResponse:
        return ctx.error_payload(exc.code, exc.message, exc.status_code)

    def operator(request: Request, service_id: str, target: str | None = None):
        principal = ctx.require_principal(request, "services:operate")
        extra = WRITE_PERMISSION.get(service_id)
        if extra:
            ctx.require_principal(request, extra)
        if target == "dokploy":
            ctx.require_principal(request, "dokploy:deploy")
        ctx.require_csrf(request, principal)
        return principal

    async def audit(principal: Any, action: str, object_type: str, object_id: str,
                    result: str = "success") -> None:
        await asyncio.to_thread(ctx.audit, principal.user_id, action, object_type,
                                object_id[:64], result)

    @router.get("/status")
    async def releases_status(request: Request):
        ctx.require_principal(request, "services:read")
        return await service.status()

    @router.get("/summary")
    async def releases_summary(request: Request):
        # Cheap (no probes): the «new version» chip on the services page.
        ctx.require_principal(request, "services:read")
        return {"current": service.current()["version"],
                "latest": service.latest()["version"],
                "update_available": service.update_available()}

    @router.post("/check")
    async def releases_check(request: Request):
        principal = ctx.require_principal(request, "services:read")
        ctx.require_csrf(request, principal)
        latest = await service.check()
        await audit(principal, "release.check", "release", "panel",
                    "failure" if latest["error_code"] else "success")
        return {"latest": latest, "update_available": service.update_available()}

    @router.post("/services/{service_id}/upgrade", status_code=202)
    async def releases_upgrade(service_id: str, request: Request):
        known = service_id in INSTALL_INDEX
        deployment = deployment_for(ctx.data_dir, service_id) if known else None
        principal = operator(request, service_id, (deployment or {}).get("target"))
        try:
            job = await service.start_upgrade(principal, service_id)
        except ReleaseError as exc:
            await audit(principal, "release.upgrade.start", "service", service_id, "failure")
            return failure(exc)
        await audit(principal, "release.upgrade.start", "service", service_id)
        return JSONResponse(job.view(), status_code=202)

    @router.get("/jobs/{job_id}")
    async def releases_job(job_id: str, request: Request):
        ctx.require_principal(request, "services:read")
        job = service.find_job(job_id)
        if job is None:
            return ctx.error_payload("job_not_found", "Update job not found", 404)
        return job.view()

    @router.get("/services/{service_id}/manual")
    async def releases_manual(service_id: str, request: Request):
        ctx.require_principal(request, "services:read")
        try:
            return await asyncio.to_thread(service.manual, service_id)
        except ReleaseError as exc:
            return failure(exc)

    @router.post("/services/{service_id}/mark-updated")
    async def releases_mark(service_id: str, request: Request):
        principal = operator(request, service_id)
        try:
            result = await service.mark_updated(service_id)
        except ReleaseError as exc:
            return failure(exc)
        await audit(principal, "release.mark_updated", "service", service_id)
        return result

    @router.post("/panel/upgrade", status_code=202)
    async def releases_panel_upgrade(request: Request, body: PanelUpgradeRequest):
        # Replacing the panel is as strong as managing users: owner/admin only.
        principal = ctx.require_principal(request, "services:operate")
        ctx.require_principal(request, "dokploy:deploy")
        ctx.require_principal(request, "user:write")
        ctx.require_csrf(request, principal)
        if body.confirmation != "UPDATE":
            return ctx.error_payload("confirmation_required", 'Type "UPDATE" to confirm', 422)
        try:
            result = await service.upgrade_panel(body.version)
        except (ReleaseError, DokployError) as exc:
            await audit(principal, "release.panel.upgrade", "release", body.version, "failure")
            return failure(exc)
        await audit(principal, "release.panel.upgrade", "release", result["version"])
        return JSONResponse(result, status_code=202)

    ctx.routers.append(router)
    ctx.start_hooks.append(service.start)
    ctx.stop_hooks.append(service.stop)
