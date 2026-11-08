"""Image update tracking (Gate 18, S10; contract docs/31 §5).

Compares the digest of every image the host's containers run with the digest the
registry currently serves for the same tag. Remote digests come from
``HEAD /v2/<repo>/manifests/<tag>`` (free on Docker Hub) with the anonymous
bearer-token flow, through configurable mirrors and the outbound proxy layer
(provider kind ``registry``). Nothing is ever updated automatically: the module
only reports and publishes ``update.available`` (info) once per image+digest.

Local data comes from the host agent: ``GET /v1/docker/containers`` and, when
the agent offers it, ``GET /v1/docker/images`` (``{items:[{id, repo_tags,
repo_digests}]}``) plus ``image_id`` on each container. Without those the local
digest is unknown and ``update_available`` stays ``null``.

State (settings + last results) lives in ``data_dir/control-plane/updates.json``.
"""

from __future__ import annotations

import asyncio
import contextlib
import copy
import json
import logging
import os
import secrets
import threading
import time
from collections.abc import Callable
from typing import Any

import httpx
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from .. import outbound
from ..module_context import Event, ModuleContext
from ..netresolve import resolve_host
from .host_agent import AgentError, HostAgentService
from .updates_refs import (
    ImageRef,
    InvalidReference,
    is_ignored,
    local_digests,
    parse_reference,
    tag_matches,
)
from .updates_registry import RegistryChecker, Sender
from .updates_settings import (
    DEFAULT_SETTINGS,
    SettingsError,
    endpoints_for,
    validate_registry_key,
    validate_settings,
)

LOGGER = logging.getLogger(__name__)
MODULE_NAME = "updates"
STATE_FILE = "updates.json"
PROVIDER_KIND = "registry"
DEFAULT_ENTRY = "default"
LIVE_STATES = frozenset({"running", "restarting", "paused"})
STARTUP_DELAY_SECONDS = 60.0
RETRY_SECONDS = 900.0
MAX_IDLE_SECONDS = 300.0
MAX_IMAGES = 500

# Tests replace these (httpx.MockTransport / a fixed resolver).
TRANSPORT_FACTORY: Callable[[], httpx.AsyncBaseTransport] | None = None
RESOLVER: outbound.Resolver | None = None

ACTIVE_SERVICE: UpdatesService | None = None


def _resolve(host: str, port: int, config: Any) -> list[str]:
    # Late-bound so tests can patch netresolve/RESOLVER.
    if RESOLVER is not None:
        return RESOLVER(host, port, config)
    return resolve_host(host, port, config)


def _field(item: dict[str, Any], *names: str) -> Any:
    for name in names:
        if name in item:
            return item[name]
    return None


def _strings(value: Any) -> list[str]:
    return [item for item in value if isinstance(item, str)] if isinstance(value, list) else []


class UpdatesService:
    def __init__(
        self,
        ctx: ModuleContext,
        agent: Any = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.ctx = ctx
        self.agent = agent or HostAgentService(ctx)
        self.clock = clock
        self.path = ctx.data_dir / "control-plane" / STATE_FILE
        self._lock = threading.Lock()
        self._run_lock = asyncio.Lock()
        self._task: asyncio.Task[None] | None = None
        self._run_task: asyncio.Task[None] | None = None
        self._wake: asyncio.Event | None = None
        self.running = False
        self.state = self._load()

    # ----- persistence -----------------------------------------------------------
    def _empty(self) -> dict[str, Any]:
        return {
            "settings": copy.deepcopy(DEFAULT_SETTINGS),
            "items": [],
            "rate_limits": {},
            "notified": {},
            "last_run_at": None,
            "last_attempt_at": None,
            "last_error": None,
        }

    def _load(self) -> dict[str, Any]:
        state = self._empty()
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return state
        except (OSError, ValueError):
            LOGGER.warning("updates state file is invalid; using defaults")
            return state
        if not isinstance(raw, dict):
            return state
        try:
            state["settings"] = validate_settings(raw.get("settings") or {})
        except SettingsError:
            LOGGER.warning("updates settings are invalid; using defaults")
        for key in ("items",):
            if isinstance(raw.get(key), list):
                state[key] = [item for item in raw[key] if isinstance(item, dict)]
        for key in ("rate_limits", "notified"):
            if isinstance(raw.get(key), dict):
                state[key] = raw[key]
        for key in ("last_run_at", "last_attempt_at"):
            if isinstance(raw.get(key), int | float):
                state[key] = raw[key]
        if isinstance(raw.get("last_error"), str):
            state["last_error"] = raw["last_error"][:200]
        return state

    def _save_locked(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_name(f".{STATE_FILE}.{secrets.token_hex(4)}.tmp")
        temporary.write_text(json.dumps(self.state, indent=2) + "\n", encoding="utf-8")
        with contextlib.suppress(OSError):
            temporary.chmod(0o600)
        os.replace(temporary, self.path)

    @property
    def settings(self) -> dict[str, Any]:
        with self._lock:
            return copy.deepcopy(self.state["settings"])

    def save_settings(self, payload: Any) -> dict[str, Any]:
        with self._lock:
            value = validate_settings(
                payload, base=self.state["settings"], network=self.ctx.network_settings
            )
            self.state["settings"] = value
            self._save_locked()
        if self._wake is not None:
            self._wake.set()
        return copy.deepcopy(value)

    # ----- outbound provider -------------------------------------------------------
    def outbound_entries(self) -> list[dict[str, Any]]:
        with self._lock:
            settings = copy.deepcopy(self.state["settings"])
            seen = {
                item["registry"]
                for item in self.state["items"]
                if isinstance(item.get("registry"), str)
            }
        entries = [
            {
                "id": DEFAULT_ENTRY,
                "name": "All registries (default)",
                "group": "default",
                "proxy_id": settings["proxy_id"],
            }
        ]
        overrides = settings["registry_proxies"]
        registries = sorted(seen | set(settings["mirrors"]) | set(overrides))
        mirror_hosts = sorted(
            {
                endpoint.netloc
                for registry in settings["mirrors"]
                for endpoint in endpoints_for(registry, settings)
                if endpoint.mirror
            }
            - set(registries)
        )
        for host in registries:
            entries.append(
                {
                    "id": host,
                    "name": host,
                    "group": "registry",
                    "proxy_id": overrides.get(host, settings["proxy_id"]),
                }
            )
        for host in mirror_hosts:
            entries.append(
                {
                    "id": host,
                    "name": f"{host} (mirror)",
                    "group": "mirror",
                    "proxy_id": overrides.get(host, settings["proxy_id"]),
                }
            )
        return entries

    def set_proxy(self, entry_id: str, proxy_id: str | None) -> None:
        if entry_id not in {entry["id"] for entry in self.outbound_entries()}:
            raise KeyError(entry_id)
        with self._lock:
            settings = copy.deepcopy(self.state["settings"])
            if entry_id == DEFAULT_ENTRY:
                settings["proxy_id"] = proxy_id
            else:
                settings["registry_proxies"][validate_registry_key(entry_id)] = proxy_id
            self.state["settings"] = validate_settings(settings, base=DEFAULT_SETTINGS)
            self._save_locked()

    # ----- local inventory ---------------------------------------------------------
    def agent_configured(self) -> bool:
        source, url, _key = self.agent.resolve()
        return source is not None and url is not None

    async def _inventory(self) -> tuple[list[dict[str, Any]], list[dict[str, Any]] | None]:
        payload = await self.agent.call("/v1/docker/containers")
        containers = payload.get("items") if isinstance(payload, dict) else None
        if not isinstance(containers, list):
            raise AgentError("agent_unreachable", 502, "unexpected agent payload")
        images: list[dict[str, Any]] | None
        try:
            raw_images = await self.agent.call("/v1/docker/images")
        except AgentError as exc:
            if exc.code != "agent_not_found":
                raise
            images = None  # agent predates the images endpoint
        else:
            listed = raw_images.get("items") if isinstance(raw_images, dict) else raw_images
            images = [item for item in listed if isinstance(item, dict)] if isinstance(
                listed, list
            ) else None
        return [item for item in containers if isinstance(item, dict)], images

    @staticmethod
    def build_groups(
        containers: list[dict[str, Any]],
        images: list[dict[str, Any]] | None,
        settings: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """Group containers by image reference and attach the local digest sets."""
        by_id: dict[str, dict[str, Any]] = {}
        for image in images or []:
            image_id = _field(image, "id", "Id")
            if isinstance(image_id, str):
                by_id[image_id] = image
        groups: dict[str, dict[str, Any]] = {}
        for container in containers:
            state = str(container.get("state") or "")
            if not settings["include_stopped"] and state not in LIVE_STATES:
                continue
            raw = str(container.get("image") or "")
            try:
                ref: ImageRef | None = parse_reference(raw)
            except InvalidReference:
                ref = None
            key = ref.canonical if ref is not None else raw
            group = groups.setdefault(
                key, {"ref": ref, "raw": raw, "containers": [], "digest_sets": []}
            )
            entry: dict[str, Any] = {
                "name": str(container.get("name") or "")[:255],
                "protected": bool(container.get("protected")),
                "state": state[:32],
            }
            # Kept only when present: used to match the container to a Dokploy service.
            labels = container.get("labels_subset")
            if isinstance(labels, dict):
                for key, label in (
                    ("compose_project", "com.docker.compose.project"),
                    ("swarm_service", "com.docker.swarm.service.name"),
                ):
                    value = labels.get(label)
                    if isinstance(value, str) and value:
                        entry[key] = value[:128]
            group["containers"].append(entry)
            if ref is None or ref.pinned or images is None:
                continue
            image = by_id.get(str(container.get("image_id") or ""))
            if image is None:
                image = next(
                    (
                        item
                        for item in images
                        if tag_matches(ref, _strings(_field(item, "repo_tags", "RepoTags")))
                    ),
                    None,
                )
            digests = (
                local_digests(ref, _strings(_field(image, "repo_digests", "RepoDigests")))
                if image is not None
                else []
            )
            group["digest_sets"].append(digests)
        ordered = sorted(groups.values(), key=lambda group: group["raw"])
        return ordered[:MAX_IMAGES]

    # ----- check run -----------------------------------------------------------------
    @contextlib.asynccontextmanager
    async def _client_factory(self, timeout: float):
        stack = contextlib.AsyncExitStack()
        clients: dict[str | None, Sender | BaseException] = {}

        async def client_for(proxy_ref: str | None) -> Sender:
            cached = clients.get(proxy_ref)
            if cached is None:
                try:
                    cached = await stack.enter_async_context(
                        outbound.outbound_client(
                            self.ctx.network_settings,
                            self.ctx.secret_store,
                            proxy_ref,
                            timeout=timeout,
                            transport=TRANSPORT_FACTORY() if TRANSPORT_FACTORY else None,
                            resolver=_resolve,
                        )
                    )
                except outbound.OutboundError as exc:
                    cached = exc
                clients[proxy_ref] = cached
            if isinstance(cached, BaseException):
                raise cached
            return cached

        async with stack:
            yield client_for

    async def run_check(self, trigger: str = "manual") -> dict[str, Any]:
        async with self._run_lock:
            self.running = True
            try:
                return await self._run(trigger)
            finally:
                self.running = False

    async def _run(self, trigger: str) -> dict[str, Any]:
        settings = self.settings
        started = self.clock()
        with self._lock:
            self.state["last_attempt_at"] = started
        try:
            containers, images = await self._inventory()
        except AgentError as exc:
            with self._lock:
                self.state["last_error"] = exc.code
                self._save_locked()
            LOGGER.warning("update check skipped", extra={"error_code": exc.code})
            return {"ok": False, "error_code": exc.code}
        groups = self.build_groups(containers, images, settings)
        semaphore = asyncio.Semaphore(settings["concurrency"])
        async with self._client_factory(float(settings["timeout_seconds"])) as client_for:
            checker = RegistryChecker(settings, client_for, clock=self.clock)

            async def evaluate(group: dict[str, Any]) -> dict[str, Any]:
                async with semaphore:
                    return await self._evaluate(group, settings, checker, started, images)

            items = await asyncio.gather(*(evaluate(group) for group in groups))
        events = self._commit(list(items), checker.rate_limits, started)
        if settings["notify"]:
            for event in events:
                self.ctx.events.publish(event)
        LOGGER.info(
            "update check finished",
            extra={"trigger": trigger, "images": len(items), "updates": len(events)},
        )
        return {"ok": True, "images": len(items)}

    async def _evaluate(
        self,
        group: dict[str, Any],
        settings: dict[str, Any],
        checker: RegistryChecker,
        now: float,
        images: list[dict[str, Any]] | None,
    ) -> dict[str, Any]:
        ref: ImageRef | None = group["ref"]
        item: dict[str, Any] = {
            "image": group["raw"],
            "tag": None,
            "registry": None,
            "repository": None,
            "reference": group["raw"],
            "current_digest": None,
            "latest_digest": None,
            "update_available": None,
            "status": "unknown",
            "checked_at": now,
            "error_code": None,
            "error_detail": None,
            "endpoint": None,
            "media_type": None,
            "containers": group["containers"],
        }
        if ref is None:
            item["error_code"] = "invalid_reference"
            return item
        item.update(
            image=ref.familiar,
            tag=ref.tag,
            registry=ref.registry,
            repository=ref.repository,
            reference=ref.canonical,
        )
        if ref.pinned:
            item.update(current_digest=ref.digest, update_available=False, status="pinned")
            return item
        if is_ignored(ref, settings["ignore"]):
            item.update(status="ignored", checked_at=None)
            return item
        digest_sets: list[list[str]] = group["digest_sets"]
        known = [digests for digests in digest_sets if digests]
        result = await checker.check(ref)
        item["endpoint"] = result.endpoint
        if not result.ok:
            item.update(
                status="error",
                error_code=result.error_code,
                error_detail=result.error_detail,
                current_digest=known[0][0] if known else None,
            )
            return item
        latest = result.digest
        item.update(latest_digest=latest, media_type=result.media_type)
        if not known or len(known) != len(digest_sets):
            # At least one container's local digest is unknown (agent without image
            # data, image built locally, or pulled under another repository name).
            item.update(
                current_digest=known[0][0] if known else None,
                error_detail="local_digest_unknown" if images is not None else "agent_no_images",
            )
            if known and any(latest not in digests for digests in known):
                item.update(update_available=True, status="update_available")
            return item
        outdated = [digests for digests in known if latest not in digests]
        if outdated:
            item.update(current_digest=outdated[0][0], update_available=True,
                        status="update_available")
        else:
            item.update(current_digest=latest, update_available=False, status="up_to_date")
        return item

    def _commit(
        self, items: list[dict[str, Any]], rate_limits: dict[str, Any], now: float
    ) -> list[Event]:
        events: list[Event] = []
        with self._lock:
            notified: dict[str, str] = dict(self.state["notified"])
            current_refs = {item["reference"] for item in items}
            for item in items:
                reference, latest = item["reference"], item["latest_digest"]
                if item["status"] == "up_to_date":
                    notified.pop(reference, None)
                if item["update_available"] is True and latest:
                    if notified.get(reference) != latest:
                        events.append(self._event(item))
                    notified[reference] = latest
            # Forget images that no longer run so a later re-deploy notifies again.
            notified = {key: value for key, value in notified.items() if key in current_refs}
            merged_limits = dict(self.state["rate_limits"])
            merged_limits.update(rate_limits)
            self.state.update(
                items=items,
                rate_limits=merged_limits,
                notified=notified,
                last_run_at=now,
                last_error=None,
            )
            self._save_locked()
        return events

    @staticmethod
    def _event(item: dict[str, Any]) -> Event:
        name = f"{item['image']}:{item['tag']}"
        containers = [container["name"] for container in item["containers"]]
        return Event(
            type="update.available",
            severity="info",
            title=f"Image update available: {name}",
            message=(
                f"{name} has a newer digest in {item['registry']} "
                f"({item['latest_digest']}). Containers: {', '.join(containers) or '-'}. "
                "Nothing was updated automatically."
            ),
            module=MODULE_NAME,
            dedupe_key=f"update.available:{item['reference']}@{item['latest_digest']}",
            details={
                "image": item["image"],
                "tag": item["tag"],
                "registry": item["registry"],
                "reference": item["reference"],
                "current_digest": item["current_digest"],
                "latest_digest": item["latest_digest"],
                "containers": containers,
            },
        )

    # ----- views -----------------------------------------------------------------------
    def next_run_at(self) -> float | None:
        with self._lock:
            settings = self.state["settings"]
            last_run, last_attempt = self.state["last_run_at"], self.state["last_attempt_at"]
            failed = self.state["last_error"] is not None
        if not settings["enabled"]:
            return None
        if failed and last_attempt is not None:
            # A failed attempt (agent down/unpaired) retries sooner than the interval.
            return last_attempt + RETRY_SECONDS
        if last_run is None:
            return 0.0  # never ran: due now
        return last_run + settings["interval_hours"] * 3600

    def images_view(self) -> dict[str, Any]:
        with self._lock:
            state = copy.deepcopy(self.state)
        items = state["items"]
        return {
            "items": items,
            "last_run_at": state["last_run_at"],
            "last_attempt_at": state["last_attempt_at"],
            "last_error": state["last_error"],
            "running": self.running,
            "next_run_at": self.next_run_at(),
            "rate_limits": state["rate_limits"],
            "summary": {
                "total": len(items),
                "update_available": sum(1 for item in items if item["update_available"] is True),
                "errors": sum(1 for item in items if item["status"] == "error"),
            },
        }

    # ----- background ------------------------------------------------------------------
    def trigger(self) -> bool:
        """Start a manual check in the background; False if one is already running."""
        if self.running or (self._run_task is not None and not self._run_task.done()):
            return False
        self.running = True  # visible to the very next GET /images
        self._run_task = asyncio.create_task(self._guarded("manual"), name="mrk-updates-check")
        return True

    async def _guarded(self, trigger: str) -> None:
        try:
            await self.run_check(trigger)
        except asyncio.CancelledError:
            raise
        except Exception:
            self.running = False
            LOGGER.exception("update check failed")

    async def _loop(self) -> None:
        assert self._wake is not None
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(self._wake.wait(), STARTUP_DELAY_SECONDS)
        while True:
            self._wake.clear()
            due = self.next_run_at()
            delay = MAX_IDLE_SECONDS if due is None else due - self.clock()
            if due is not None and delay <= 0 and not self.running:
                if self.agent_configured():
                    await self._guarded("schedule")
                else:
                    with self._lock:
                        self.state["last_attempt_at"] = self.clock()
                        self.state["last_error"] = self.state["last_error"] or (
                            "agent_not_configured"
                        )
                await asyncio.sleep(1.0)  # never spin, whatever the clock says
                continue
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(
                    self._wake.wait(), min(max(delay, 1.0), MAX_IDLE_SECONDS)
                )

    async def start(self) -> None:
        self._wake = asyncio.Event()
        self._task = asyncio.create_task(self._loop(), name="mrk-updates-scheduler")

    async def stop(self) -> None:
        for task in (self._task, self._run_task):
            if task is not None and not task.done():
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await task
        self._task = self._run_task = None


def _dokploy_ref(
    container: dict[str, Any], index: dict[str, dict[str, Any]]
) -> dict[str, Any] | None:
    for key in ("compose_project", "swarm_service"):
        value = container.get(key)
        if isinstance(value, str) and value in index:
            return index[value]
    name = str(container.get("name") or "")
    # Swarm tasks are "<service>.<slot>.<task>", compose ones "<project>-<service>-<n>".
    for separator in (".", "-"):
        head = name
        while separator in head:
            head = head.rsplit(separator, 1)[0]
            if head in index:
                return index[head]
    return index.get(name)


async def annotate_dokploy(view: dict[str, Any], principal: Any) -> dict[str, Any]:
    """Add ``dokploy_url`` to every image item and container (best effort).

    A container belongs to a Dokploy service when its compose project / swarm
    service (or name prefix) is that service's ``appName``. Dokploy being
    unreachable never fails the updates list; ``dokploy.error_code`` says why.
    """
    from . import dokploy as dokploy_module

    info: dict[str, Any] = {
        "configured": False,
        "panel_url": None,
        "matched": 0,
        "error_code": None,
    }
    index: dict[str, dict[str, Any]] = {}
    panel_url: str | None = None
    dokploy_service = dokploy_module.ACTIVE_SERVICE
    if dokploy_service is not None and principal.allows("dokploy:read"):
        panel_url = dokploy_service.panel_url()
        info["configured"] = panel_url is not None
        info["panel_url"] = panel_url
        if panel_url is not None:
            try:
                index = await dokploy_service.app_index()
            except dokploy_module.DokployError as exc:
                info["error_code"] = exc.code
            except Exception:  # best effort: never break the updates page
                LOGGER.exception("dokploy app index failed")
                info["error_code"] = "dokploy_unavailable"
    matched = 0
    for item in view.get("items", []):
        item_url: str | None = None
        for container in item.get("containers", []):
            ref = _dokploy_ref(container, index) if index and panel_url else None
            url = dokploy_module.DokployService.service_url(panel_url, ref) if (
                ref is not None and panel_url is not None
            ) else None
            container["dokploy_url"] = url
            container["dokploy_service"] = (
                {key: ref[key] for key in ("type", "id", "name", "project_id")}
                if ref is not None and url is not None
                else None
            )
            if url is not None:
                matched += 1
                item_url = item_url or url
        item["dokploy_url"] = item_url
    info["matched"] = matched
    return info


def build_router(ctx: ModuleContext, service: UpdatesService) -> APIRouter:
    router = APIRouter(prefix="/api/v1/updates", tags=["updates"])

    @router.get("/images")
    async def list_images(request: Request) -> dict[str, Any]:
        principal = ctx.require_principal(request, "updates:read")
        view = service.images_view()
        view["dokploy"] = await annotate_dokploy(view, principal)
        return view

    @router.post("/check", status_code=202, response_model=None)
    async def check_now(request: Request) -> dict[str, Any] | JSONResponse:
        principal = ctx.require_principal(request, "updates:write")
        ctx.require_csrf(request, principal)
        if not await asyncio.to_thread(service.agent_configured):
            return ctx.error_payload(
                "agent_not_configured", "The host agent is not configured", 409
            )
        started = service.trigger()
        await asyncio.to_thread(
            ctx.audit, principal.user_id, "updates.check", "updates", "images"
        )
        return {"started": started, "running": True}

    @router.get("/settings")
    async def get_settings(request: Request) -> dict[str, Any]:
        ctx.require_principal(request, "updates:read")
        return service.settings

    @router.put("/settings", response_model=None)
    async def put_settings(request: Request) -> dict[str, Any] | JSONResponse:
        principal = ctx.require_principal(request, "updates:write")
        ctx.require_csrf(request, principal)
        try:
            payload = json.loads(await request.body() or b"{}")
        except (ValueError, UnicodeDecodeError):
            return ctx.error_payload("invalid_json", "request body must be JSON", 422)
        try:
            value = await asyncio.to_thread(service.save_settings, payload)
        except SettingsError as exc:
            await asyncio.to_thread(
                ctx.audit, principal.user_id, "updates.settings.update", "updates",
                "settings", "failure",
            )
            return ctx.error_payload(exc.code, exc.message, 422)
        await asyncio.to_thread(
            ctx.audit, principal.user_id, "updates.settings.update", "updates", "settings"
        )
        return value

    return router


def register_outbound(ctx: ModuleContext, service: UpdatesService) -> None:
    """Registry checks appear in the central "service -> proxy" table."""
    outbound.outbound_registry(ctx.data_dir).register(
        outbound.OutboundProvider(
            kind=PROVIDER_KIND,
            list_entries=service.outbound_entries,
            supported_types=lambda _entry: outbound.ALL_PROXY_TYPES,
            set_proxy=service.set_proxy,
            read_permission="updates:read",
            write_permission="updates:write",
        )
    )


def register(ctx: ModuleContext) -> None:
    global ACTIVE_SERVICE
    service = UpdatesService(ctx)
    ACTIVE_SERVICE = service
    ctx.routers.append(build_router(ctx, service))
    register_outbound(ctx, service)
    ctx.start_hooks.append(service.start)
    ctx.stop_hooks.append(service.stop)
