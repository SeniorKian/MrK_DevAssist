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
``appName`` through the existing Dokploy client.
"""

from __future__ import annotations

import asyncio
import logging
import socket
import time
from typing import Any

from .services_catalog import SERVICE_INDEX

LOGGER = logging.getLogger(__name__)
DETECT_TTL_SECONDS = 300.0
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


class Routing:
    def __init__(self, ctx: Any, settings: Any) -> None:
        self.ctx = ctx
        self.settings = settings  # callable -> dict
        self._detected: tuple[float, dict[str, Any]] | None = None
        self._detect_lock = asyncio.Lock()
        self._background: asyncio.Task[dict[str, Any]] | None = None
        # service id -> (target host, port) for services outside this container
        # (dns-doh: the DNS engine on the host network, docs/40 §5).
        self.service_targets: Any = None

    def agent(self) -> Any | None:
        from .home import find_service

        return find_service(self.ctx, "HostAgentService")

    def invalidate(self) -> None:
        self._detected = None

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
        if not refresh and cached and time.monotonic() - cached[0] < DETECT_TTL_SECONDS:
            return cached[1]
        started = time.monotonic()
        async with self._detect_lock:
            # Another caller may have finished a detection while we waited.
            cached = self._detected
            if cached and cached[0] >= started:
                return cached[1]
            if not refresh and cached and time.monotonic() - cached[0] < DETECT_TTL_SECONDS:
                return cached[1]
            detected = await self._detect()
            self._detected = (time.monotonic(), detected)
            return detected

    async def detect_quick(self, timeout: float = 2.0) -> dict[str, Any] | None:
        """Fresh cached detection, or wait briefly for one; never blocks a page for long.

        Returns the last known result (possibly stale) or None while the first
        detection is still running in the background.
        """
        cached = self._detected
        if cached and time.monotonic() - cached[0] < DETECT_TTL_SECONDS:
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
            "dokploy_connected": False,
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
        if dokploy is not None:
            source, url, key = dokploy.resolve()
            if source is not None and url is not None and key is not None:
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
                    detected["dokploy_service_type"] = ref["type"]
                    detected["dokploy_service_id"] = ref["id"]
                    detected["dokploy_service"] = ref.get("name")
                    detected["dokploy_project"] = await self._project_name(dokploy, ref)
        return detected

    @staticmethod
    async def _project_name(dokploy: Any, ref: dict[str, Any]) -> str | None:
        try:
            detail = await dokploy.service(ref["type"], ref["id"])
        except Exception:  # noqa: BLE001
            return None
        project = detail.get("project") if isinstance(detail, dict) else None
        return project.get("name") if isinstance(project, dict) else None

    def available_modes(self, detected: dict[str, Any]) -> dict[str, bool]:
        return {
            "dokploy_api": bool(
                detected["inside_dokploy"]
                and detected["dokploy_connected"]
                and detected["dokploy_service_id"]
            ),
            "traefik_file": bool(
                detected["traefik_file_enabled"] and detected["traefik_dir_available"]
            ),
            "manual": True,
        }

    def effective_mode(self, detected: dict[str, Any], requested: str | None = None) -> str:
        settings = self.settings()
        mode = requested if requested and requested != "auto" else settings["routing_mode"]
        available = self.available_modes(detected)
        if mode == "auto":
            for candidate in ("dokploy_api", "traefik_file"):
                if available[candidate]:
                    return candidate
            return "manual"
        return mode

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
            target = compose_service = own["service_name"]
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
                "project": detected.get("dokploy_project"),
                "service": detected.get("dokploy_service"),
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
    def _dokploy_body(
        self, service_id: str, host: str, https: bool, detected: dict[str, Any]
    ) -> dict[str, Any]:
        settings = self.settings()
        port = SERVICE_INDEX[service_id].internal_port
        own = own_stack(self.ctx.data_dir, service_id)
        if own is not None:
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

    def redeploy_hint(self, detected: dict[str, Any]) -> dict[str, Any] | None:
        if detected.get("dokploy_service_type") != "compose":
            return None
        service_id = detected["dokploy_service_id"]
        return {
            "kind": "dokploy_redeploy",
            "service_type": "compose",
            "service_id": service_id,
            "method": "POST",
            "endpoint": f"/api/v1/dokploy/services/compose/{service_id}/redeploy",
        }

    async def dokploy_create(
        self, service_id: str, host: str, https: bool, detected: dict[str, Any]
    ) -> str | None:
        dokploy = _dokploy()
        if dokploy is None:
            raise RoutingError("routing_unavailable", 409, "Dokploy is not connected")
        body = self._dokploy_body(service_id, host, https, detected)
        result = await dokploy.call("domain.create", body=body, mutation=True)
        dokploy.cache.clear()
        dokploy.domains.clear()
        domain_id = result.get("domainId") if isinstance(result, dict) else None
        if isinstance(domain_id, str):
            return domain_id[:64]
        return await self.dokploy_find_id(host, detected)

    async def dokploy_find_id(self, host: str, detected: dict[str, Any]) -> str | None:
        dokploy = _dokploy()
        if dokploy is None:
            return None
        compose = detected.get("dokploy_service_type") == "compose"
        procedure, param = (
            ("domain.byComposeId", "composeId")
            if compose
            else ("domain.byApplicationId", "applicationId")
        )
        try:
            payload = await dokploy.call(procedure, params={param: detected["dokploy_service_id"]})
        except Exception:  # noqa: BLE001
            return None
        for item in payload if isinstance(payload, list) else []:
            if isinstance(item, dict) and str(item.get("host", "")).lower() == host:
                value = item.get("domainId")
                return str(value)[:64] if value else None
        return None

    async def dokploy_update(
        self, domain_id: str, service_id: str, host: str, https: bool, detected: dict[str, Any]
    ) -> None:
        dokploy = _dokploy()
        if dokploy is None:
            raise RoutingError("routing_unavailable", 409, "Dokploy is not connected")
        body = self._dokploy_body(service_id, host, https, detected)
        for field in ("composeId", "applicationId"):
            body.pop(field, None)
        body["domainId"] = domain_id
        await dokploy.call("domain.update", body=body, mutation=True, parse=False)
        dokploy.cache.clear()
        dokploy.domains.clear()

    async def dokploy_delete(self, domain_id: str) -> None:
        dokploy = _dokploy()
        if dokploy is None:
            raise RoutingError("routing_unavailable", 409, "Dokploy is not connected")
        await dokploy.call(
            "domain.delete", body={"domainId": domain_id}, mutation=True, parse=False
        )
        dokploy.cache.clear()
        dokploy.domains.clear()

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
