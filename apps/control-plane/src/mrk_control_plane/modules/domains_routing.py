"""How a domain reaches an MRK service: detect the setup and apply a routing mode (docs/35 §2).

Modes:

* ``dokploy_api`` – MRK runs as a Dokploy Compose (or Application) service; the
  domain is registered with Dokploy's official API (``domain.create`` /
  ``domain.update`` / ``domain.delete``, Dokploy v0.31.0). For Compose services
  Dokploy writes the Traefik labels only on the next deployment, so a redeploy is
  *suggested*, never started by MRK.
* ``traefik_file`` – opt-in. The Host Agent writes only ``mrk-domains.yml`` in
  Dokploy's Traefik dynamic directory from a structured payload.
* ``manual`` – step-by-step instructions; nothing is changed anywhere.

Detection reads MRK's own container through the Host Agent (labels
``com.docker.compose.project`` / ``com.docker.compose.service`` /
``com.docker.swarm.service.name`` and networks) and matches the Dokploy
``appName`` through the existing Dokploy client. When that does not work (no agent,
another hostname) the panel's Compose is looked up in Dokploy by the service it
defines (``mrk-panel``, see dokploy_locate.find_compose). A detection that failed or
is incomplete is kept only briefly, so a short Dokploy hiccup does not stick.
"""

from __future__ import annotations

import asyncio
import logging
import socket
import time
from datetime import datetime
from typing import Any

from .dokploy_client import DokployError
from .services_catalog import SERVICE_INDEX

LOGGER = logging.getLogger(__name__)
DETECT_TTL_SECONDS = 300.0
# A failed or incomplete detection is retried soon (never cached for minutes).
DETECT_FAIL_TTL_SECONDS = 15.0
# The Compose of a service in its own stack: found ids are reused for a minute,
# a failed lookup is not repeated for a few minutes (Dokploy rate limits).
OWN_HIT_TTL_SECONDS = 60.0
OWN_MISS_TTL_SECONDS = 180.0
# s3.py keeps the Compose the S3 admin picked for redeploys here.
S3_DOKPLOY_TARGET_KEY = "s3.dokploy_target"
# The panel's Compose service name (compose.yaml).
FALLBACK_TARGET = "mrk-panel"


class RoutingError(Exception):
    def __init__(self, code: str, status_code: int, message: str, **extra: Any) -> None:
        super().__init__(message)
        self.code = code
        self.status_code = status_code
        self.message = message
        self.extra = extra


def own_stack(data_dir: Any, service_id: str) -> dict[str, Any] | None:
    """Where a service that runs in its OWN stack is (docs/44), or None.

    ``{"host", "port", "service_name", "compose_id"}``; ``compose_id`` is known only
    when the panel installed the stack itself through the Dokploy API.
    """
    import json
    from pathlib import Path
    from urllib.parse import urlsplit

    from .. import remote_services

    host: str | None = None
    port: int | None = None
    if service_id in {"npm", "pypi"}:
        entry = remote_services.load(Path(data_dir)).get(service_id)
        if entry:
            host, port = entry["host"], int(entry["port"])
    elif service_id in {"git", "registry"}:
        if service_id == "git":
            from . import git_service as module
        else:
            from . import registry_service as module  # type: ignore[no-redef]
        service = module.ACTIVE_SERVICE
        remote = service.connected() if service is not None else None
        if remote:
            parts = urlsplit(remote["url"])
            host, port = parts.hostname, parts.port or (3000 if service_id == "git" else 5000)
    elif service_id == "s3":
        from .s3_client import remote_config

        remote = remote_config()
        if remote:
            parts = urlsplit(remote["engine_url"])
            host, port = parts.hostname, parts.port or 9000
    if host is None or port is None:
        return None
    compose_id = None
    try:
        state = json.loads((Path(data_dir) / "control-plane" / "install.json").read_text("utf-8"))
        deployment = (state.get(service_id) or {}).get("deployment") or {}
        if deployment.get("target") == "dokploy" and isinstance(deployment.get("compose_id"), str):
            compose_id = deployment["compose_id"]
    except (OSError, ValueError, AttributeError):
        pass
    return {"host": host, "port": port, "service_name": f"mrk-{service_id}",
            "compose_id": compose_id}


def _dokploy() -> Any | None:
    from . import dokploy

    return dokploy.ACTIVE_SERVICE


def _configured(dokploy: Any | None) -> bool:
    if dokploy is None:
        return False
    if not hasattr(dokploy, "resolve"):
        return True  # a stand-in without configuration (tests)
    source, url, key = dokploy.resolve()
    return source is not None and url is not None and key is not None


def dokploy_configured() -> bool:
    """Dokploy has an address and a key (whether it answers right now or not)."""
    return _configured(_dokploy())


def _timestamp(value: Any) -> float | None:
    """Seconds from Dokploy's ``createdAt`` (ISO text or a number)."""
    if isinstance(value, int | float) and not isinstance(value, bool):
        return float(value) / (1000.0 if value > 1e12 else 1.0)
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        return datetime.fromisoformat(value.strip().replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def _upstream_text(exc: BaseException) -> str:
    from ..logging_config import redact_text

    text = getattr(exc, "upstream_message", None) or getattr(exc, "message", None) or exc
    return redact_text(str(text))[:300]


def _log_dokploy_failure(procedure: str, exc: BaseException) -> None:
    LOGGER.warning(
        "dokploy %s failed", procedure,
        extra={"error_code": getattr(exc, "code", type(exc).__name__),
               "upstream_status": getattr(exc, "upstream_status", None),
               "upstream_message": _upstream_text(exc)},
    )


class Routing:
    def __init__(self, ctx: Any, settings: Any, store: Any = None) -> None:
        self.ctx = ctx
        self.settings = settings  # callable -> dict
        self.store = store  # domains_settings.SettingsStore (persists found Compose ids)
        # (monotonic time, detection, how long it stays fresh)
        self._detected: tuple[float, dict[str, Any], float] | None = None
        self._detect_lock = asyncio.Lock()
        self._background: asyncio.Task[dict[str, Any]] | None = None
        # service id -> (target host, port) for services outside this container
        # (dns-doh: the DNS engine on the host network, docs/40 §5).
        self.service_targets: Any = None
        # service id -> Dokploy Compose found to run its own stack (see own_compose_id).
        self._own_compose: dict[str, str] = {}
        self._own_rows: dict[str, dict[str, Any]] = {}
        self._own_hit: dict[str, float] = {}
        self._own_miss: dict[str, float] = {}

    def agent(self) -> Any | None:
        from .home import find_service

        return find_service(self.ctx, "HostAgentService")

    def _agent_or_none(self) -> Any | None:
        try:
            return self.agent()
        except Exception:  # noqa: BLE001 - no agent registered: the other ways remain
            return None

    def invalidate(self) -> None:
        """Forget the detection and the Compose lookups (Dokploy connected or changed)."""
        self._detected = None
        self._own_hit.clear()
        self._own_miss.clear()

    @staticmethod
    def _fresh(cached: tuple[float, dict[str, Any], float] | None) -> bool:
        return bool(cached and time.monotonic() - cached[0] < cached[2])

    # ------------------------------------------------------------------ detection
    async def _self_container(self, agent: Any, settings: dict[str, Any]) -> dict[str, Any] | None:
        payload = await agent.call("/v1/docker/containers")
        items = payload.get("items") if isinstance(payload, dict) else None
        if not isinstance(items, list):
            return None
        wanted = settings.get("self_container") or ""
        hostname = socket.gethostname().lower()
        for item in items:
            if not isinstance(item, dict):
                continue
            name = str(item.get("name") or "")
            container_id = str(item.get("id") or "")
            if wanted and name == wanted:
                return item
            if not wanted and (
                (len(hostname) >= 12 and container_id.startswith(hostname)) or name == hostname
            ):
                return item
        return None

    async def detect(self, *, refresh: bool = False) -> dict[str, Any]:
        cached = self._detected
        if not refresh and self._fresh(cached):
            assert cached is not None
            return cached[1]
        started = time.monotonic()
        async with self._detect_lock:
            # Another caller may have finished a detection while we waited.
            cached = self._detected
            if cached and cached[0] >= started:
                return cached[1]
            if not refresh and self._fresh(cached):
                assert cached is not None
                return cached[1]
            detected = await self._detect()
            self._detected = (time.monotonic(), detected, self._ttl(detected))
            return detected

    @staticmethod
    def _ttl(detected: dict[str, Any]) -> float:
        incomplete = bool(detected.get("errors")) or bool(
            detected.get("dokploy_configured") and not detected.get("inside_dokploy")
        )
        return DETECT_FAIL_TTL_SECONDS if incomplete else DETECT_TTL_SECONDS

    async def detect_quick(self, timeout: float = 2.0) -> dict[str, Any] | None:
        """Fresh cached detection, or wait briefly for one; never blocks a page for long.

        Returns the last known result (possibly stale) or None while the first
        detection is still running in the background.
        """
        cached = self._detected
        if cached is not None and self._fresh(cached):
            return cached[1]
        task = self._background
        if task is None or task.done():
            task = self._background = asyncio.create_task(self.detect())
        try:
            return await asyncio.wait_for(asyncio.shield(task), timeout)
        except TimeoutError:
            return cached[1] if cached else None

    async def _detect(self) -> dict[str, Any]:
        settings = self.settings()
        detected: dict[str, Any] = {
            "inside_dokploy": False,
            "dokploy_configured": False,
            "dokploy_connected": False,
            "detected_by": None,
            "dokploy_project": None,
            "dokploy_service": None,
            "dokploy_service_type": None,
            "dokploy_service_id": None,
            "compose_service": None,
            "container_name": None,
            "agent_connected": False,
            "traefik_dir_available": False,
            "traefik_file_enabled": bool(settings.get("traefik_file_enabled")),
            "on_dokploy_network": False,
            "server_ips": list(settings.get("server_public_ips") or []),
            "errors": [],
        }
        container: dict[str, Any] | None = None
        agent = self.agent()
        if agent is not None:
            source, url, _key = agent.resolve()
            if source is not None and url is not None:
                try:
                    container = await self._self_container(agent, settings)
                    detected["agent_connected"] = True
                except Exception as exc:  # noqa: BLE001 - detection is best effort
                    detected["errors"].append(getattr(exc, "code", "agent_unreachable"))
                if detected["agent_connected"]:
                    try:
                        status = await agent.call("/v1/traefik/status")
                        detected["traefik_dir_available"] = bool(
                            isinstance(status, dict) and status.get("writable")
                        )
                    except Exception:  # noqa: BLE001 - older agent / not enabled
                        detected["traefik_dir_available"] = False
        labels: dict[str, Any] = {}
        if container is not None:
            detected["container_name"] = str(container.get("name") or "")[:128] or None
            labels = container.get("labels_subset") or {}
            networks = container.get("networks") or []
            detected["on_dokploy_network"] = settings["dokploy_network"] in networks
            detected["compose_service"] = labels.get("com.docker.compose.service")
        dokploy = _dokploy()
        if _configured(dokploy):
            detected["dokploy_configured"] = True
            app_name = labels.get("com.docker.compose.project") or labels.get(
                "com.docker.swarm.service.name"
            )
            try:
                index = await dokploy.app_index()
                detected["dokploy_connected"] = True
            except Exception as exc:  # noqa: BLE001
                detected["errors"].append(getattr(exc, "code", "dokploy_unreachable"))
                index = {}
            ref = index.get(app_name) if app_name else None
            if ref and ref.get("type") in {"compose", "application"}:
                detected["inside_dokploy"] = True
                detected["detected_by"] = "container_labels"
                detected["dokploy_service_type"] = ref["type"]
                detected["dokploy_service_id"] = ref["id"]
                detected["dokploy_service"] = ref.get("name")
                detected["dokploy_project"] = await self._project_name(dokploy, ref)
            elif detected["dokploy_connected"]:
                await self._detect_by_compose(dokploy, agent, detected)
        return detected

    async def _detect_by_compose(
        self, dokploy: Any, agent: Any, detected: dict[str, Any]
    ) -> None:
        """Find the panel's Compose in Dokploy by the service it defines (no label match)."""
        from .dokploy_locate import find_compose

        name = detected.get("compose_service") or FALLBACK_TARGET
        try:
            found = await find_compose(
                dokploy, name, agent=agent if detected["agent_connected"] else None
            )
        except Exception as exc:  # noqa: BLE001 - detection is best effort
            detected["errors"].append(getattr(exc, "code", "compose_lookup_failed"))
            return
        if found is None:
            return
        detected.update({
            "inside_dokploy": True,
            "detected_by": "compose_lookup",
            "dokploy_service_type": "compose",
            "dokploy_service_id": str(found["compose_id"]),
            "dokploy_service": found.get("name"),
            "dokploy_project": found.get("project_name"),
            "compose_service": name,
        })

    @staticmethod
    async def _project_name(dokploy: Any, ref: dict[str, Any]) -> str | None:
        try:
            detail = await dokploy.service(ref["type"], ref["id"])
        except Exception:  # noqa: BLE001
            return None
        project = detail.get("project") if isinstance(detail, dict) else None
        return project.get("name") if isinstance(project, dict) else None

    def available_modes(
        self, detected: dict[str, Any], stack_compose: str | None = None
    ) -> dict[str, bool]:
        """Modes usable here; ``stack_compose``: the service runs in that own-stack Compose."""
        return {
            "dokploy_api": bool(
                detected["dokploy_connected"]
                and (stack_compose or (detected["inside_dokploy"]
                                       and detected["dokploy_service_id"]))
            ),
            "traefik_file": bool(
                detected["traefik_file_enabled"] and detected["traefik_dir_available"]
            ),
            "manual": True,
        }

    def effective_mode(
        self, detected: dict[str, Any], requested: str | None = None,
        stack_compose: str | None = None,
    ) -> str:
        settings = self.settings()
        mode = requested if requested and requested != "auto" else settings["routing_mode"]
        available = self.available_modes(detected, stack_compose)
        if mode == "auto":
            for candidate in ("dokploy_api", "traefik_file"):
                if available[candidate]:
                    return candidate
            return "manual"
        return mode

    def auto_detection_failed(self, detected: dict[str, Any], requested: str | None,
                              mode: str) -> bool:
        """Auto picked manual although Dokploy is set up: the detection did not work."""
        auto = (requested in (None, "auto")) and self.settings()["routing_mode"] == "auto"
        failed = not detected.get("dokploy_connected") or bool(detected.get("errors"))
        return bool(auto and mode == "manual" and detected.get("dokploy_configured") and failed)

    @staticmethod
    def panel_compose(detected: dict[str, Any]) -> str | None:
        """The Dokploy Compose the panel itself runs in (None: unknown / an Application)."""
        if detected.get("inside_dokploy") and detected.get("dokploy_service_type") == "compose":
            value = detected.get("dokploy_service_id")
            return str(value) if value else None
        return None

    def target_host(self, detected: dict[str, Any]) -> str:
        settings = self.settings()
        return settings.get("target_host") or detected.get("container_name") or FALLBACK_TARGET

    # ------------------------------------------------------------------ manual
    def instructions(
        self, service_id: str, host: str, https: bool, detected: dict[str, Any]
    ) -> dict[str, Any]:
        service = SERVICE_INDEX[service_id]
        port = service.internal_port
        project = detected.get("dokploy_project") or "MRK"
        target = (
            detected.get("dokploy_service")
            or detected.get("compose_service")
            or (self.target_host(detected))
        )
        compose_service = detected.get("compose_service") or FALLBACK_TARGET
        own = own_stack(self.ctx.data_dir, service_id)
        if own is not None:
            # Its own stack (docs/44): the domain belongs on that stack, not the panel's.
            row = self._own_rows.get(service_id) or {}
            compose_service = own["service_name"]
            target = row.get("name") or compose_service
            project = row.get("project_name") or project
            port = own["port"]
        cert = "Let's Encrypt" if https else "None"
        steps_fa = [
            f"در DNS دامنه، یک رکورد A برای «{host}» به IP عمومی همین سرور بسازید.",
            f"در Dokploy پروژه «{project}» و سرویس «{target}» را باز کنید.",
            "به تب Domains بروید و Add Domain را بزنید.",
            f"Host را «{host}»، Path را «/» و Container Port را «{port}» بگذارید"
            + (
                f" و Service Name را «{compose_service}» انتخاب کنید."
                if detected.get("dokploy_service_type") != "application"
                else "."
            ),
            f"HTTPS را {'روشن' if https else 'خاموش'} کنید؛ Certificate: {cert}.",
            "ذخیره کنید؛ برای سرویس Compose یک بار Deploy را بزنید تا دامنه فعال شود.",
            "در DevAssist روی «بررسی» بزنید تا DNS، گواهی و رسیدن درخواست بررسی شود.",
        ]
        steps_en = [
            f"In your DNS, create an A record for “{host}” pointing to this server's public IP.",
            f"In Dokploy, open project “{project}” and service “{target}”.",
            "Open the Domains tab and click Add Domain.",
            f"Set Host “{host}”, Path “/”, Container Port “{port}”"
            + (
                f" and Service Name “{compose_service}”."
                if detected.get("dokploy_service_type") != "application"
                else "."
            ),
            f"Turn HTTPS {'on' if https else 'off'}; Certificate: {cert}.",
            "Save; for a Compose service click Deploy once so the domain becomes active.",
            "Back in DevAssist, click Verify to check DNS, the certificate and that "
            "requests arrive.",
        ]
        return {
            "steps_fa": steps_fa,
            "steps_en": steps_en,
            "dokploy": {
                "project": project if own is not None else detected.get("dokploy_project"),
                "service": target if own is not None else detected.get("dokploy_service"),
                "service_name": compose_service,
                "port": port,
                "host": host,
                "https": https,
                "certificate_type": "letsencrypt" if https else "none",
            },
        }

    # ------------------------------------------------------------------ conflicts
    async def dokploy_conflict(self, host: str) -> tuple[dict[str, Any] | None, str]:
        """(owner, conflict_check) where conflict_check is ok | partial | skipped."""
        dokploy = _dokploy()
        if dokploy is None:
            return None, "skipped"
        source, url, key = dokploy.resolve()
        if source is None or url is None or key is None:
            return None, "skipped"
        try:
            tree = await dokploy._projects_raw()  # noqa: SLF001 - module's cached loader
            from . import dokploy_normalize as norm

            projects = norm.project_tree(tree)
            keys: list[tuple[str, str, dict[str, Any], str]] = []
            for project in projects:
                for service in project["services"]:
                    if service["type"] in norm.DEPLOYABLE_TYPES:
                        keys.append((service["type"], service["id"], service, project["name"]))
            budget = int(self.settings().get("conflict_check_budget", 20))
            complete = await dokploy._fill_domains(  # noqa: SLF001
                [(item[0], item[1]) for item in keys], budget
            )
        except Exception as exc:  # noqa: BLE001 - Dokploy down: warn, never block
            LOGGER.info(
                "dokploy conflict check skipped",
                extra={"error_code": getattr(exc, "code", type(exc).__name__)},
            )
            return None, "skipped"
        for service_type, service_id, service, project_name in keys:
            known = dokploy._fresh_domains((service_type, service_id)) or []  # noqa: SLF001
            for entry in known:
                if entry.split("/", 1)[0].lower().rstrip(".") == host:
                    return {
                        "kind": "dokploy",
                        "name": service["name"],
                        "project": project_name,
                        "service": service["name"],
                        "service_type": service_type,
                        "service_id": service_id,
                    }, "ok" if complete else "partial"
        return None, "ok" if complete else "partial"

    # ------------------------------------------------------------------ dokploy api
    async def own_compose_id(self, service_id: str, own: dict[str, Any]) -> str | None:
        """The Dokploy Compose that runs ``service_id`` in its own stack.

        One resolver for every caller: the Compose an admin saved for S3 redeploys
        first, then Dokploy itself (dokploy_locate.find_compose: container labels, the
        known ids, a Compose named after the service). install.json keeps the id from
        the panel's own install; it goes stale when the stack is created again and is
        missing for a stack pasted into Dokploy by hand. The id found is persisted.
        """
        from .dokploy_locate import compose_runs, find_compose

        recorded = own["compose_id"]
        persisted = self._persisted_own(service_id)
        fallback = self._own_compose.get(service_id) or persisted or recorded
        dokploy = _dokploy()
        if not _configured(dokploy):
            return fallback
        now = time.monotonic()
        if service_id in self._own_compose and now - self._own_hit.get(service_id, -1e9) < (
                OWN_HIT_TTL_SECONDS):
            return self._own_compose[service_id]
        if now - self._own_miss.get(service_id, -1e9) < OWN_MISS_TTL_SECONDS:
            return fallback
        found: dict[str, Any] | None = None
        saved = self._saved_target(service_id)
        if saved and await compose_runs(dokploy, saved, own["service_name"]) is not False:
            found = {"compose_id": saved}
        if found is None:
            found = await find_compose(
                dokploy, own["service_name"],
                known=(self._own_compose.get(service_id), persisted, recorded),
                agent=self._agent_or_none())
        if found is None:
            self._own_miss[service_id] = now
            return fallback
        compose_id = str(found["compose_id"])
        self._own_compose[service_id] = compose_id
        self._own_hit[service_id] = now
        self._own_miss.pop(service_id, None)
        if found.get("name") or found.get("project_name"):
            self._own_rows[service_id] = dict(found)
        if compose_id != persisted and self.store is not None:
            try:
                await asyncio.to_thread(self.store.save_own_compose, service_id, compose_id)
            except Exception:  # noqa: BLE001 - memory still has it
                LOGGER.warning("could not save the Dokploy Compose of %s", service_id)
        return compose_id

    def _persisted_own(self, service_id: str) -> str | None:
        if self.store is None:
            return None
        try:
            return self.store.own_compose().get(service_id)
        except Exception:  # noqa: BLE001 - database trouble: Dokploy is asked instead
            return None

    def _saved_target(self, service_id: str) -> str | None:
        """The Compose an S3 admin saved on the S3 page (``s3.dokploy_target``)."""
        if service_id != "s3" or self.ctx is None:
            return None
        from ..models import SystemSetting

        try:
            with self.ctx.database.session() as db:
                row = db.get(SystemSetting, S3_DOKPLOY_TARGET_KEY)
                value = row.value if row is not None and isinstance(row.value, dict) else {}
        except Exception:  # noqa: BLE001
            return None
        compose_id = value.get("compose_id")
        return compose_id if isinstance(compose_id, str) and compose_id else None

    async def _dokploy_body(
        self, service_id: str, host: str, https: bool, detected: dict[str, Any]
    ) -> dict[str, Any]:
        settings = self.settings()
        port = SERVICE_INDEX[service_id].internal_port
        own = own_stack(self.ctx.data_dir, service_id)
        if own is not None:
            own = {**own, "compose_id": await self.own_compose_id(service_id, own)}
            if own["compose_id"] is None:
                raise RoutingError(
                    "service_in_own_stack", 409,
                    "This service runs in its own stack: add the domain there "
                    f"(service {own['service_name']}, port {own['port']})",
                    service_name=own["service_name"], port=own["port"],
                )
            port = own["port"]
        resolver = settings["cert_resolver"]
        body: dict[str, Any] = {
            "host": host,
            "path": "/",
            "port": port,
            "https": https,
            "certificateType": (
                "none" if not https else "letsencrypt" if resolver == "letsencrypt" else "custom"
            ),
        }
        if https and resolver != "letsencrypt":
            body["customCertResolver"] = resolver
        if own is not None:
            body["domainType"] = "compose"
            body["composeId"] = own["compose_id"]
            body["serviceName"] = own["service_name"]
        elif detected["dokploy_service_type"] == "compose":
            body["domainType"] = "compose"
            body["composeId"] = detected["dokploy_service_id"]
            body["serviceName"] = detected.get("compose_service") or FALLBACK_TARGET
        else:
            body["domainType"] = "application"
            body["applicationId"] = detected["dokploy_service_id"]
        return body

    async def stack_compose(self, service_id: str) -> str | None:
        """The Dokploy Compose of a service in its own stack; None for the panel's stack."""
        own = own_stack(self.ctx.data_dir, service_id)
        return await self.own_compose_id(service_id, own) if own is not None else None

    def redeploy_hint(
        self, detected: dict[str, Any], compose_id: str | None = None
    ) -> dict[str, Any] | None:
        """What to redeploy: ``compose_id`` (a service's own stack) or the panel's service."""
        if compose_id is None and detected.get("dokploy_service_type") != "compose":
            return None
        service_id = compose_id or detected["dokploy_service_id"]
        return {
            "kind": "dokploy_redeploy",
            "service_type": "compose",
            "service_id": service_id,
            "method": "POST",
            "endpoint": f"/api/v1/dokploy/services/compose/{service_id}/redeploy",
        }

    async def _domain_call(self, procedure: str, body: dict[str, Any], **kwargs: Any) -> Any:
        """One domain.* mutation; failures are logged with Dokploy's own message."""
        dokploy = _dokploy()
        if dokploy is None:
            raise RoutingError("routing_unavailable", 409, "Dokploy is not connected")
        try:
            result = await dokploy.call(procedure, body=body, mutation=True, **kwargs)
        except DokployError as exc:
            _log_dokploy_failure(procedure, exc)
            from .dokploy_locate import is_missing

            if procedure != "domain.delete" and not exc.procedure_missing and is_missing(exc):
                raise RoutingError(
                    "dokploy_target_missing", 409,
                    "Dokploy no longer has the service this domain belongs to",
                    upstream_code=exc.code, upstream_status=exc.upstream_status,
                    upstream_message=_upstream_text(exc),
                ) from None
            raise
        finally:
            dokploy.cache.clear()
            dokploy.domains.clear()
        return result

    async def dokploy_create(
        self, service_id: str, host: str, https: bool, detected: dict[str, Any]
    ) -> str | None:
        body = await self._dokploy_body(service_id, host, https, detected)
        result = await self._domain_call("domain.create", body)
        domain_id = result.get("domainId") if isinstance(result, dict) else None
        if isinstance(domain_id, str):
            return domain_id[:64]
        return await self.dokploy_find_id(host, detected, body.get("composeId"))

    async def compose_domains(self, compose_id: str) -> list[dict[str, Any]] | None:
        """Dokploy's domains of one Compose; None when Dokploy cannot be asked."""
        return await self._service_domains("domain.byComposeId", "composeId", compose_id)

    async def application_domains(self, application_id: str) -> list[dict[str, Any]] | None:
        return await self._service_domains(
            "domain.byApplicationId", "applicationId", application_id)

    async def _service_domains(
        self, procedure: str, param: str, value: str
    ) -> list[dict[str, Any]] | None:
        dokploy = _dokploy()
        if not _configured(dokploy):
            return None
        try:
            payload = await dokploy.call(procedure, params={param: value})
        except Exception as exc:  # noqa: BLE001
            LOGGER.info("dokploy domain list skipped",
                        extra={"error_code": getattr(exc, "code", type(exc).__name__)})
            return None
        return [item for item in payload if isinstance(item, dict)] if isinstance(
            payload, list) else []

    async def dokploy_find_id(
        self, host: str, detected: dict[str, Any], compose_id: str | None = None
    ) -> str | None:
        """Dokploy's id of ``host`` on ``compose_id`` (own stack) or the panel's service."""
        dokploy = _dokploy()
        if dokploy is None:
            return None
        compose = compose_id is not None or detected.get("dokploy_service_type") == "compose"
        procedure, param = (
            ("domain.byComposeId", "composeId")
            if compose
            else ("domain.byApplicationId", "applicationId")
        )
        target = compose_id or detected.get("dokploy_service_id")
        if not target:
            return None
        try:
            payload = await dokploy.call(procedure, params={param: target})
        except Exception:  # noqa: BLE001
            return None
        for item in payload if isinstance(payload, list) else []:
            if isinstance(item, dict) and str(item.get("host", "")).lower().rstrip(".") == host:
                value = item.get("domainId")
                return str(value)[:64] if value else None
        return None

    async def dokploy_update(
        self, domain_id: str, service_id: str, host: str, https: bool, detected: dict[str, Any]
    ) -> None:
        body = await self._dokploy_body(service_id, host, https, detected)
        for field in ("composeId", "applicationId"):
            body.pop(field, None)
        body["domainId"] = domain_id
        await self._domain_call("domain.update", body, parse=False)

    async def dokploy_delete(self, domain_id: str) -> None:
        await self._domain_call("domain.delete", {"domainId": domain_id}, parse=False)

    # ------------------------------------------------------------------ deployments
    async def deploy_marker(self, compose_id: str) -> dict[str, Any]:
        """What "a new deployment" means later: the deployments Dokploy has now."""
        rows = await self._deployments(compose_id)
        before = None if rows is None else sorted(
            {str(row.get("deploymentId")) for row in rows if row.get("deploymentId")})[:1000]
        return {"compose_id": compose_id, "since": int(time.time()), "before": before}

    async def _deployments(self, compose_id: str) -> list[dict[str, Any]] | None:
        from .dokploy_locate import deployments as _deployments

        dokploy = _dokploy()
        if not _configured(dokploy):
            return None
        try:
            return await _deployments(dokploy, compose_id)
        except Exception:  # noqa: BLE001 - unknown, try again on the next tick
            return None

    async def deployed_since(self, marker: dict[str, Any]) -> bool | None:
        """True once a deployment newer than ``marker`` finished; None: Dokploy can't tell."""
        compose_id = marker.get("compose_id")
        if not isinstance(compose_id, str):
            return None
        rows = await self._deployments(compose_id)
        if rows is None:
            return None
        before = marker.get("before")
        known = set(before) if isinstance(before, list) else None
        since = float(marker.get("since") or 0)
        for row in rows:
            if row.get("status") != "done":
                continue
            if known is not None:
                if str(row.get("deploymentId")) not in known:
                    return True
            else:
                created = _timestamp(row.get("createdAt"))
                if created is not None and created >= since:
                    return True
        return False

    async def domain_deployed(self, compose_id: str, host: str) -> bool | None:
        """Whether a deployment finished after Dokploy got ``host`` (labels are written)."""
        items = await self.compose_domains(compose_id)
        item = next((entry for entry in items or []
                     if str(entry.get("host", "")).lower().rstrip(".") == host), None)
        created = _timestamp(item.get("createdAt")) if item else None
        if created is None:
            return None
        rows = await self._deployments(compose_id)
        if rows is None:
            return None
        return any(row.get("status") == "done"
                   and (_timestamp(row.get("createdAt")) or 0) >= created for row in rows)

    # ------------------------------------------------------------------ traefik file
    def traefik_payload(
        self, rows: list[dict[str, Any]], detected: dict[str, Any]
    ) -> dict[str, Any]:
        settings = self.settings()
        grouped: dict[str, dict[str, Any]] = {}
        for row in sorted(rows, key=lambda item: (not item["primary"], item["host"])):
            entry = grouped.setdefault(
                row["service_id"],
                {
                    "service": row["service_id"],
                    "hosts": [],
                    "https": True,
                },
            )
            entry["hosts"].append(row["host"])
            target = self.service_targets(row["service_id"]) if self.service_targets else None
            if target is not None:
                entry["target_host"], entry["port"] = target
            # One router per service: HTTPS unless every domain of it opted out.
            entry["https"] = bool(entry["https"] and row["https"])
        return {
            "target_host": self.target_host(detected),
            "entrypoints": {
                "web": settings["entrypoint_web"],
                "websecure": settings["entrypoint_websecure"],
            },
            "cert_resolver": settings["cert_resolver"],
            "redirect_middleware": settings["redirect_middleware"] or None,
            "services": [grouped[key] for key in sorted(grouped)],
        }

    async def traefik_apply(self, rows: list[dict[str, Any]], detected: dict[str, Any]) -> None:
        agent = self.agent()
        if agent is None:
            raise RoutingError("routing_unavailable", 409, "The host agent is not available")
        if not rows:
            await agent.request("POST", "/v1/traefik/domains/delete", {})
            return
        await agent.request("POST", "/v1/traefik/domains", self.traefik_payload(rows, detected))
