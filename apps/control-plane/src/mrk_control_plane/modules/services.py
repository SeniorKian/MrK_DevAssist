"""«سرویس‌های من» and public domains coordinated with Dokploy (docs/35).

Routes:

* ``GET  /api/v1/services`` (services:read), ``POST /api/v1/services/{id}/actions``
  (services:operate, CSRF, audit).
* ``GET/POST /api/v1/domains``, ``PATCH/DELETE /api/v1/domains/{id}``,
  ``POST /api/v1/domains/{id}/verify`` (domains:read / domains:write).
* ``GET/PUT /api/v1/domains/routing``, ``POST /api/v1/domains/reconcile`` (read the
  domains back from Dokploy now).

Domain changes are applied to the routing layer (Dokploy API, the agent-written
Traefik file, or nothing for manual mode) and then synced into MRK itself:
TrustedHost names for the panel, devpi's outside URL, the S3 public endpoint
and virtual-host suffixes. Every sync has its own switch in the settings.

When Dokploy is connected it is the source of truth: ``reconcile_dokploy`` reads
the domains of the panel's Compose and of every own-stack Compose back, upgrades
manual rows Dokploy already has, imports domains added in Dokploy by hand and marks
rows whose Dokploy domain is gone. A Compose domain works only after the next
deployment, so such a row waits (``pending_redeploy``, no alarms) until Dokploy
reports a new finished deployment of that Compose.
"""

from __future__ import annotations

import asyncio
import logging
import os
import secrets
import time
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select

from .. import process_control
from ..components import check_http_component
from ..models import ServiceDomain, SystemSetting, User
from ..module_context import Event, ModuleContext
from .bucket_routes import BucketRoutes
from .domains_hosts import HostError, canonical_host, display_host
from .domains_routing import (
    FALLBACK_TARGET,
    Routing,
    RoutingError,
    dokploy_configured,
    own_stack,
)
from .domains_settings import ROUTING_MODES, SettingsError, SettingsStore
from .domains_verify import InternalRoute, Probes, default_probes, verify_domain
from .services_catalog import (
    CONDITIONAL_SERVICES,
    DOMAIN_SERVICES,
    SERVICE_INDEX,
    SERVICES,
    ServiceDef,
    UsageCache,
    read_stopped,
    state_from_programs,
    write_stopped,
)
from .services_watchdog import ServiceWatchdog

LOGGER = logging.getLogger(__name__)
MODULE_NAME = "services"
PYPI_OUTSIDE_FILE = Path("pypi") / "outside-url"
EMPTY_HEALTH: dict[str, Any] = {
    "dns": None,
    "tls": None,
    "reach": None,
    "checked_at": None,
    "problem_code": None,
    "problems": [],
}
VERIFY_TICK_SECONDS = 300.0
DOH_SERVICE = "dns-doh"
# A fresh certificate may take a while: no alarm for tls_pending in this window.
TLS_PENDING_GRACE_SECONDS = 3600
# Neutral health notes: shown, never an alarm.
NOTICE_PENDING = "pending_redeploy"
NOTICE_REMOVED = "removed_in_dokploy"

# Tests may replace these.
PROBES: Probes | None = None


class ServiceActionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action: str = Field(min_length=1, max_length=16)
    confirmation: str | None = Field(default=None, max_length=64)


class DomainCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    service_id: str = Field(min_length=1, max_length=32)
    host: str = Field(min_length=1, max_length=300)
    https: bool = True
    primary: bool | None = None
    mode: str = Field(default="auto", max_length=32)


class DomainUpdateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    primary: bool | None = None
    https: bool | None = None


class DomainDeleteRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    confirmation: str | None = Field(default=None, max_length=300)
    # The panel domain in use right now (or its last one): removing it needs this too.
    confirm_current: bool = False


class RoutingRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    mode: str = Field(max_length=32)
    traefik_file_enabled: bool | None = None


class ServiceError(Exception):
    def __init__(self, code: str, status_code: int, message: str, **extra: Any) -> None:
        super().__init__(message)
        self.code = code
        self.status_code = status_code
        self.message = message
        self.extra = extra


def _row(row: ServiceDomain, meta: dict[str, Any] | None = None) -> dict[str, Any]:
    meta = meta or {}
    pending = meta.get("pending_redeploy") if isinstance(meta.get("pending_redeploy"), dict) \
        else None
    return {
        "id": row.id,
        "service_id": row.service_id,
        "host": row.host,
        "display_host": display_host(row.host),
        "primary": bool(row.primary),
        "https": bool(row.https),
        "mode": row.mode,
        "dokploy_domain_id": row.dokploy_domain_id,
        "health": dict(row.health) if isinstance(row.health, dict) else dict(EMPTY_HEALTH),
        "created_at": row.created_at,
        "updated_at": row.updated_at,
        "created_by": row.created_by_user_id,
        # "panel" (added here) or "dokploy" (read back from Dokploy).
        "source": meta.get("source") or "panel",
        "pending_redeploy": pending is not None,
        "suggested_action": _redeploy_action(pending["compose_id"]) if pending else None,
        "removed_in_dokploy": bool(meta.get("removed_in_dokploy")),
    }


def _redeploy_action(compose_id: str) -> dict[str, Any]:
    return {
        "kind": "dokploy_redeploy",
        "service_type": "compose",
        "service_id": compose_id,
        "method": "POST",
        "endpoint": f"/api/v1/dokploy/services/compose/{compose_id}/redeploy",
    }


def _hold(health: dict[str, Any], notice: str) -> dict[str, Any]:
    """Keep what the check found, but as a neutral note (no problem, no alarm)."""
    return {**health, "notice": notice, "held_problem_code": health.get("problem_code"),
            "held_problems": list(health.get("problems") or []),
            "problem_code": None, "problems": []}


def _request_host(request: Request) -> str | None:
    raw = (request.headers.get("host") or "").strip().lower()
    if not raw:
        return None
    if raw.startswith("["):
        return raw.split("]", 1)[0] + "]"
    return raw.rsplit(":", 1)[0].rstrip(".") if raw.count(":") == 1 else raw.rstrip(".")


def _is_missing(exc: BaseException) -> bool:
    """Dokploy says the domain does not exist (any more)."""
    from .dokploy_client import DokployError
    from .dokploy_locate import is_missing

    return isinstance(exc, DokployError) and is_missing(exc)


def public_url(domain: dict[str, Any] | None) -> str | None:
    if not domain:
        return None
    return f"{'https' if domain['https'] else 'http'}://{domain['host']}"


class ServicesService:
    def __init__(self, ctx: ModuleContext) -> None:
        self.ctx = ctx
        self.store = SettingsStore(ctx.database)
        self.routing = Routing(ctx, self.get_settings, self.store)
        self.watchdog = ServiceWatchdog(ctx, self.get_settings)
        self.usage = UsageCache(
            ctx.data_dir,
            counters={
                "npm": lambda: self._package_count("npm"),
                "pypi": lambda: self._package_count("pypi"),
                "s3": self._bucket_count,
                "panel": self._user_count,
            },
        )
        self.routing.service_targets = self._service_target
        self.lock = asyncio.Lock()
        # docs/43 §0.1: verified bucket domains routed like S3 service domains.
        self.bucket_routes = BucketRoutes(self)
        self.last_sync: dict[str, Any] = {}
        self.busy: set[str] = set()
        self._task: asyncio.Task[None] | None = None
        self._probes: Probes | None = None
        self._reconcile_task: asyncio.Task[Any] | None = None
        self.last_reconcile: dict[str, Any] | None = None

    # ------------------------------------------------------------------ settings
    def get_settings(self) -> dict[str, Any]:
        return self.store.get_settings()

    def put_settings(self, payload: Any, actor_user_id: int | None) -> dict[str, Any]:
        value = self.store.put_settings(payload, actor_user_id)
        self.routing.invalidate()
        if isinstance(payload, dict) and "route_bucket_domains" in payload:
            self.bucket_routes.reconcile_soon()
        return value

    def on_dokploy_changed(self) -> None:
        """Hook for the Dokploy module: the connection was saved, changed or removed.

        Forgets the detection (and Compose lookups) and reads Dokploy's domains back soon.
        """
        self.routing.invalidate()
        self.reconcile_soon()

    def reconcile_soon(self) -> None:
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return
        if self._reconcile_task is not None and not self._reconcile_task.done():
            return

        async def run() -> None:
            try:
                await self.reconcile_dokploy()
                await self.bucket_routes.reconcile()
            except Exception:  # noqa: BLE001 - the next tick tries again
                LOGGER.exception("reading domains back from Dokploy failed")

        self._reconcile_task = loop.create_task(run())

    @property
    def probes(self) -> Probes:
        if PROBES is not None:
            return PROBES
        if self._probes is None:
            self._probes = default_probes(self.ctx.network_settings.dns)
        return self._probes

    # ------------------------------------------------------------------ usage counters
    def _package_count(self, ecosystem: str) -> dict[str, Any]:
        from ..catalog import PackageCatalog

        count = len(PackageCatalog(self.ctx.data_dir).all_packages(ecosystem))
        return {"items": count, "items_kind": "packages"}

    def _bucket_count(self) -> dict[str, Any]:
        from ..models import S3Bucket

        with self.ctx.database.session() as db:
            count = int(db.scalar(select(func.count()).select_from(S3Bucket)) or 0)
        return {"items": count, "items_kind": "buckets"}

    def _user_count(self) -> dict[str, Any]:
        with self.ctx.database.session() as db:
            count = int(db.scalar(select(func.count()).select_from(User)) or 0)
        return {"items": count, "items_kind": "users"}

    # ------------------------------------------------------------------ domains (db)
    def list_domains(self, service_id: str | None = None) -> list[dict[str, Any]]:
        meta = self.store.domain_meta()
        with self.ctx.database.session() as db:
            query = select(ServiceDomain).order_by(
                ServiceDomain.service_id, ServiceDomain.primary.desc(), ServiceDomain.host
            )
            if service_id:
                query = query.where(ServiceDomain.service_id == service_id)
            return [_row(row, meta.get(row.id)) for row in db.scalars(query)]

    def get_domain(self, domain_id: str) -> dict[str, Any]:
        meta = self.store.domain_meta()
        with self.ctx.database.session() as db:
            row = db.get(ServiceDomain, domain_id)
            if row is None:
                raise ServiceError("domain_not_found", 404, "Domain not found")
            return _row(row, meta.get(row.id))

    def _meta(self, domain_id: str) -> dict[str, Any]:
        return self.store.domain_meta().get(domain_id, {})

    async def _set_meta(self, domain_id: str, changes: dict[str, Any] | None) -> None:
        await asyncio.to_thread(self.store.update_domain_meta, domain_id, changes)

    def instructions_for(self, domain: dict[str, Any], detected: dict[str, Any] | None
                         ) -> dict[str, Any] | None:
        """Manual steps for a manual row (built for the right stack), else None."""
        if domain.get("mode") != "manual":
            return None
        if domain["service_id"] == DOH_SERVICE:
            return self._doh_instructions(domain["host"])
        return self.routing.instructions(
            domain["service_id"], domain["host"], bool(domain["https"]), detected or {})

    async def with_instructions(self, items: list[dict[str, Any]]) -> list[dict[str, Any]]:
        if not any(item.get("mode") == "manual" for item in items):
            return items
        detected = await self.routing.detect_quick()
        return [{**item, "instructions": self.instructions_for(item, detected)}
                if item.get("mode") == "manual" else item for item in items]

    def primary(self, service_id: str) -> dict[str, Any] | None:
        return next((item for item in self.list_domains(service_id) if item["primary"]), None)

    def _insert(
        self,
        service_id: str,
        host: str,
        https: bool,
        mode: str,
        primary: bool | None,
        dokploy_id: str | None,
        actor: int | None,
    ) -> dict[str, Any]:
        now = int(time.time())
        with self.ctx.database.session() as db, db.begin():
            existing = db.scalars(
                select(ServiceDomain).where(ServiceDomain.service_id == service_id)
            ).all()
            make_primary = not any(row.primary for row in existing) or bool(primary)
            if make_primary:
                for row in existing:
                    row.primary = False
            row = ServiceDomain(
                id=secrets.token_hex(8),
                service_id=service_id,
                host=host,
                primary=make_primary,
                https=https,
                mode=mode,
                dokploy_domain_id=dokploy_id,
                health=dict(EMPTY_HEALTH),
                created_at=now,
                updated_at=now,
                created_by_user_id=actor,
            )
            db.add(row)
            db.flush()
            return _row(row)

    def _delete_row(self, domain_id: str) -> None:
        with self.ctx.database.session() as db, db.begin():
            row = db.get(ServiceDomain, domain_id)
            if row is None:
                return
            service_id, was_primary = row.service_id, row.primary
            db.delete(row)
            db.flush()
            if was_primary:
                successor = db.scalars(
                    select(ServiceDomain)
                    .where(ServiceDomain.service_id == service_id)
                    .order_by(ServiceDomain.created_at, ServiceDomain.host)
                    .limit(1)
                ).first()
                if successor is not None:
                    successor.primary = True

    def _update_row(self, domain_id: str, **changes: Any) -> dict[str, Any]:
        with self.ctx.database.session() as db, db.begin():
            row = db.get(ServiceDomain, domain_id)
            if row is None:
                raise ServiceError("domain_not_found", 404, "Domain not found")
            if changes.get("primary") is True:
                for other in db.scalars(
                    select(ServiceDomain).where(ServiceDomain.service_id == row.service_id)
                ):
                    other.primary = other.id == row.id
            elif changes.get("primary") is False and row.primary:
                successor = db.scalars(
                    select(ServiceDomain)
                    .where(ServiceDomain.service_id == row.service_id, ServiceDomain.id != row.id)
                    .order_by(ServiceDomain.created_at, ServiceDomain.host)
                    .limit(1)
                ).first()
                if successor is not None:
                    row.primary = False
                    successor.primary = True
            for key in ("https", "health", "dokploy_domain_id", "mode"):
                if key in changes:
                    setattr(row, key, changes[key])
            row.updated_at = int(time.time())
            db.flush()
            return _row(row)

    # ------------------------------------------------------------------ create/update/delete
    async def create(self, body: DomainCreateRequest, actor: int | None) -> dict[str, Any]:
        if body.service_id not in DOMAIN_SERVICES:
            raise ServiceError(
                "invalid_service",
                422,
                "This service cannot have a domain",
                fields=[{"field": "service_id", "reason_code": "invalid_choice"}],
            )
        if body.service_id == DOH_SERVICE and await self._doh_port() is None:
            raise ServiceError(
                "dns_doh_plain_disabled",
                409,
                "Turn on DoH without TLS (behind Traefik) in the DNS settings first",
                fields=[{"field": "service_id", "reason_code": "service_disabled"}],
            )
        if body.mode not in ROUTING_MODES:
            raise ServiceError(
                "invalid_routing_mode",
                422,
                "Unknown routing mode",
                fields=[{"field": "mode", "reason_code": "invalid_choice"}],
            )
        try:
            host = canonical_host(body.host)
        except HostError as exc:
            raise ServiceError(
                "invalid_host",
                422,
                exc.message,
                fields=[{"field": "host", "reason_code": exc.reason_code}],
            ) from None
        async with self.lock:
            existing = next((item for item in self.list_domains() if item["host"] == host), None)
            if existing is not None:
                raise ServiceError(
                    "domain_exists",
                    409,
                    "This domain is already used by an DevAssist service",
                    owner={
                        "kind": "mrk",
                        "name": SERVICE_INDEX[existing["service_id"]].name_en,
                        "service_id": existing["service_id"],
                        "domain_id": existing["id"],
                    },
                    fields=[{"field": "host", "reason_code": "in_use"}],
                )
            if host in await asyncio.to_thread(self.bucket_routes.bucket_hosts):
                raise ServiceError(
                    "domain_exists",
                    409,
                    "This domain is already used by a bucket",
                    owner={"kind": "bucket"},
                    fields=[{"field": "host", "reason_code": "in_use"}],
                )
            detected = await self.routing.detect()
            stack = (
                await self.routing.stack_compose(body.service_id)
                if body.service_id != DOH_SERVICE else None
            )
            owner, conflict_check = await self.routing.dokploy_conflict(host)
            adopted: dict[str, Any] | None = None
            if owner is not None:
                # Already on the right service in Dokploy (added there by hand): adopt it.
                adopted = await self._adoptable(owner, body.service_id, host, detected, stack)
                if adopted is None:
                    raise ServiceError(
                        "domain_in_use",
                        409,
                        "This domain is already used in Dokploy",
                        owner=owner,
                        conflict_check=conflict_check,
                        fields=[{"field": "host", "reason_code": "in_use"}],
                    )
            https = bool(adopted.get("https", body.https)) if adopted else body.https
            if adopted is not None:
                mode = "dokploy_api"
            else:
                mode = self._choose_mode(body, detected, stack)
            applied: dict[str, Any] = {
                "mode": mode,
                "ok": True,
                "error_code": None,
                "conflict_check": conflict_check,
                "redeploy_required": False,
                "suggested_action": None,
                "adopted": adopted is not None,
            }
            dokploy_id: str | None = None
            created_in_dokploy = False
            marker: dict[str, Any] | None = None
            if adopted is not None:
                dokploy_id = str(adopted.get("domainId") or "")[:64] or None
            elif mode == "dokploy_api":
                try:
                    dokploy_id = await self.routing.dokploy_create(
                        body.service_id, host, https, detected
                    )
                except Exception as exc:  # noqa: BLE001 - mapped below
                    raise self._routing_failure(exc, "dokploy_domain_failed") from None
                created_in_dokploy = True
                hint = self.routing.redeploy_hint(detected, stack)
                applied["redeploy_required"] = hint is not None
                applied["suggested_action"] = hint
                if hint is not None:
                    marker = await self.routing.deploy_marker(hint["service_id"])
            domain: dict[str, Any] | None = None
            try:
                domain = await asyncio.to_thread(
                    self._insert,
                    body.service_id,
                    host,
                    https,
                    mode,
                    body.primary,
                    dokploy_id,
                    actor,
                )
                await self._set_meta(domain["id"], {
                    "source": "dokploy" if adopted is not None else "panel",
                    "pending_redeploy": marker,
                })
                if mode == "traefik_file":
                    try:
                        await self._apply_traefik(detected)
                    except Exception as exc:  # noqa: BLE001
                        raise self._routing_failure(exc, "traefik_write_failed") from None
                domain = await asyncio.to_thread(self.get_domain, domain["id"])
                result: dict[str, Any] = {"domain": domain, "applied": applied}
                if mode == "manual":
                    result["instructions"] = self.instructions_for(domain, detected)
                result["sync"] = await self.sync()
            except BaseException:
                # Roll back: never leave a row or a Dokploy domain nobody knows about.
                if domain is not None:
                    await asyncio.to_thread(self._delete_row, domain["id"])
                    await self._set_meta(domain["id"], None)
                if created_in_dokploy:
                    await self._quiet_dokploy_delete(dokploy_id, host, detected, stack)
                raise
        self._verify_soon(domain["id"])
        return result

    def _choose_mode(self, body: DomainCreateRequest, detected: dict[str, Any],
                     stack: str | None) -> str:
        mode = self.routing.effective_mode(detected, body.mode, stack)
        if body.service_id == DOH_SERVICE and mode == "dokploy_api":
            # Dokploy domains route to this container; the DNS engine runs on the
            # host network, so its DoH needs the Traefik file (or manual) route.
            file_ok = self.routing.available_modes(detected).get("traefik_file")
            return "traefik_file" if file_ok else "manual"
        available = self.routing.available_modes(detected, stack)
        if not available.get(mode):
            code = "traefik_dir_unavailable" if mode == "traefik_file" else "routing_unavailable"
            raise ServiceError(
                code,
                409,
                f"Routing mode {mode} is not available here",
                mode=mode,
                available_modes=[key for key, ok in available.items() if ok],
            )
        if body.service_id != DOH_SERVICE and self.routing.auto_detection_failed(
                detected, body.mode, mode):
            # Dokploy is set up but could not be read: never quietly fall back to manual.
            raise ServiceError(
                "routing_detection_failed",
                409,
                "Dokploy is set up, but DevAssist could not find its own service there. "
                "Check the Dokploy connection and try again, or choose the manual way.",
                detection_errors=list(dict.fromkeys(detected.get("errors") or []))[:5],
                available_modes=[key for key, ok in available.items() if ok],
            )
        return mode

    async def _adoptable(self, owner: dict[str, Any], service_id: str, host: str,
                         detected: dict[str, Any], stack: str | None) -> dict[str, Any] | None:
        """The Dokploy domain item when ``owner`` is this service's own place in Dokploy."""
        kind, owner_id = owner.get("service_type"), owner.get("service_id")
        if kind == "compose":
            expected_compose = stack or self.routing.panel_compose(detected)
            if not expected_compose or owner_id != expected_compose:
                return None
            items = await self.routing.compose_domains(expected_compose)
        elif kind == "application" and stack is None and (
                detected.get("dokploy_service_type") == "application"
                and owner_id == detected.get("dokploy_service_id")):
            items = await self.routing.application_domains(str(owner_id))
        else:
            return None
        item = next((entry for entry in items or []
                     if str(entry.get("host", "")).lower().rstrip(".") == host), None)
        if item is None:
            return None
        expected = self._expected_target(service_id, detected, stack)
        if expected is None or item.get("port") != expected[1]:
            return None
        if kind == "compose" and item.get("serviceName") not in (None, "", expected[0]):
            return None
        return item

    def _expected_target(self, service_id: str, detected: dict[str, Any],
                         stack: str | None) -> tuple[str, int] | None:
        """(Compose service name, port) a Dokploy domain of ``service_id`` must point at."""
        own = own_stack(self.ctx.data_dir, service_id) if stack else None
        if own is not None:
            return own["service_name"], int(own["port"])
        port = SERVICE_INDEX[service_id].internal_port
        if not port:
            return None
        return str(detected.get("compose_service") or FALLBACK_TARGET), int(port)

    async def _quiet_dokploy_delete(self, domain_id: str | None, host: str,
                                    detected: dict[str, Any], stack: str | None) -> None:
        try:
            domain_id = domain_id or await self.routing.dokploy_find_id(host, detected, stack)
            if domain_id:
                await self.routing.dokploy_delete(domain_id)
        except Exception:  # noqa: BLE001 - reconcile shows what is left
            LOGGER.warning("rolling back the Dokploy domain failed", exc_info=True)

    async def update(self, domain_id: str, body: DomainUpdateRequest) -> dict[str, Any]:
        async with self.lock:
            current = await asyncio.to_thread(self.get_domain, domain_id)
            applied: dict[str, Any] = {
                "mode": current["mode"],
                "ok": True,
                "error_code": None,
                "redeploy_required": False,
                "suggested_action": None,
            }
            https_changed = body.https is not None and body.https != current["https"]
            if https_changed and current["mode"] == "dokploy_api" and current["dokploy_domain_id"]:
                detected = await self.routing.detect()
                try:
                    await self.routing.dokploy_update(
                        current["dokploy_domain_id"],
                        current["service_id"],
                        current["host"],
                        bool(body.https),
                        detected,
                    )
                except Exception as exc:  # noqa: BLE001
                    raise self._routing_failure(exc, "dokploy_domain_failed") from None
                stack = await self.routing.stack_compose(current["service_id"])
                hint = self.routing.redeploy_hint(detected, stack)
                applied["redeploy_required"] = hint is not None
                applied["suggested_action"] = hint
                if hint is not None:
                    await self._set_meta(domain_id, {
                        "pending_redeploy": await self.routing.deploy_marker(
                            hint["service_id"])})
            changes: dict[str, Any] = {}
            if body.primary is not None:
                changes["primary"] = body.primary
            if https_changed:
                changes["https"] = body.https
                changes["health"] = dict(EMPTY_HEALTH)
            await asyncio.to_thread(lambda: self._update_row(domain_id, **changes))
            domain = await asyncio.to_thread(self.get_domain, domain_id)
            if https_changed and current["mode"] == "traefik_file":
                try:
                    await self._apply_traefik(await self.routing.detect())
                except Exception as exc:  # noqa: BLE001 - saved; report, do not roll back
                    applied.update(
                        {
                            "ok": False,
                            "error_code": "traefik_write_failed",
                            "upstream_code": getattr(exc, "code", None),
                        }
                    )
            if current["mode"] == "manual" and https_changed:
                result_instructions = self.routing.instructions(
                    current["service_id"],
                    current["host"],
                    bool(body.https),
                    await self.routing.detect(),
                )
            else:
                result_instructions = None
            sync = await self.sync()
        if https_changed:
            self._verify_soon(domain_id)
        result = {"domain": domain, "health": domain["health"], "applied": applied, "sync": sync}
        if result_instructions:
            result["instructions"] = result_instructions
        return result

    async def delete(self, domain_id: str, confirmation: str | None, *,
                     request_host: str | None = None,
                     confirm_current: bool = False) -> dict[str, Any]:
        async with self.lock:
            current = await asyncio.to_thread(self.get_domain, domain_id)
            if confirmation not in {current["host"], current["display_host"]}:
                raise ServiceError(
                    "confirmation_mismatch",
                    422,
                    "Type the domain name to confirm",
                    expected_confirmation=current["host"],
                    fields=[{"field": "confirmation", "reason_code": "incorrect"}],
                )
            if current["service_id"] == "panel" and not confirm_current:
                # Lockout guard: the address this page is open on, or the last way in.
                panel_rows = await asyncio.to_thread(self.list_domains, "panel")
                in_use = request_host is not None and request_host in {
                    current["host"], current["display_host"]}
                last = len(panel_rows) <= 1
                if in_use or last:
                    raise ServiceError(
                        "panel_domain_in_use",
                        409,
                        "You are using this panel domain right now"
                        if in_use else "This is the panel's last domain",
                        in_use_now=in_use,
                        last_panel_domain=last,
                    )
            applied: dict[str, Any] = {
                "mode": current["mode"],
                "ok": True,
                "error_code": None,
                "redeploy_required": False,
                "suggested_action": None,
            }
            if current["mode"] == "dokploy_api":
                detected = await self.routing.detect()
                stack = await self.routing.stack_compose(current["service_id"])
                dokploy_id = current["dokploy_domain_id"] or (
                    await self.routing.dokploy_find_id(current["host"], detected, stack))
                if dokploy_id:
                    try:
                        await self.routing.dokploy_delete(dokploy_id)
                    except Exception as exc:  # noqa: BLE001
                        if not _is_missing(exc):
                            raise self._routing_failure(exc, "dokploy_domain_failed") from None
                    hint = self.routing.redeploy_hint(detected, stack)
                    applied["redeploy_required"] = hint is not None
                    applied["suggested_action"] = hint
            await asyncio.to_thread(self._delete_row, domain_id)
            await self._set_meta(domain_id, None)
            if current["mode"] == "traefik_file":
                try:
                    await self._apply_traefik(await self.routing.detect())
                except Exception as exc:  # noqa: BLE001 - row is gone; report the file state
                    applied.update(
                        {
                            "ok": False,
                            "error_code": "traefik_write_failed",
                            "upstream_code": getattr(exc, "code", None),
                        }
                    )
            sync = await self.sync()
        return {"deleted": domain_id, "applied": applied, "sync": sync}

    async def _apply_traefik(self, detected: dict[str, Any]) -> None:
        rows = [item for item in self.list_domains() if item["mode"] == "traefik_file"]
        rows.extend(await asyncio.to_thread(self.bucket_routes.traefik_rows))
        await self.routing.traefik_apply(rows, detected)

    @staticmethod
    def _routing_failure(exc: BaseException, code: str) -> ServiceError:
        if isinstance(exc, RoutingError):
            return ServiceError(exc.code, exc.status_code, exc.message, **exc.extra)
        upstream = getattr(exc, "code", None) or type(exc).__name__
        if upstream == "traefik_disabled":
            code = "traefik_dir_unavailable"
        message = getattr(exc, "message", None) or "The routing change failed"
        status = 409 if code == "traefik_dir_unavailable" else 502
        from ..logging_config import redact_text

        return ServiceError(code, status, str(message)[:300], upstream_code=upstream,
                            upstream_status=getattr(exc, "upstream_status", None),
                            upstream_message=redact_text(str(message))[:300])

    # ------------------------------------------------------------------ verification
    def _verify_soon(self, domain_id: str) -> None:
        try:
            asyncio.get_running_loop().create_task(self._safe_verify(domain_id))
        except RuntimeError:
            return

    async def _safe_verify(self, domain_id: str) -> None:
        try:
            await self.verify(domain_id)
        except Exception:  # noqa: BLE001
            LOGGER.debug("background domain verification failed", exc_info=True)

    def _internal_route(self, settings: dict[str, Any]) -> InternalRoute | None:
        host = str(settings.get("traefik_internal_host") or "")
        if not settings.get("verify_via_traefik", True) or not host:
            return None
        return InternalRoute(host, int(settings.get("traefik_internal_https_port") or 443),
                             int(settings.get("traefik_internal_http_port") or 80))

    async def verify(self, domain_id: str) -> dict[str, Any]:
        current = await asyncio.to_thread(self.get_domain, domain_id)
        settings = self.get_settings()
        health = await verify_domain(
            host=current["host"],
            service_id=current["service_id"],
            https=current["https"],
            expected_ips=list(settings.get("server_public_ips") or []),
            probes=self.probes,
            expiry_warning_days=int(settings["tls_expiry_warning_days"]),
            internal=self._internal_route(settings),
        )
        meta = await asyncio.to_thread(self._meta, domain_id)
        if meta.get("pending_redeploy"):
            if health.get("problem_code") is None and health.get("notice") is None:
                # It answers properly: the deployment happened.
                await self._set_meta(domain_id, {"pending_redeploy": None})
            else:
                health = _hold(health, NOTICE_PENDING)
        elif meta.get("removed_in_dokploy"):
            health = _hold(health, NOTICE_REMOVED)
        await asyncio.to_thread(lambda: self._update_row(domain_id, health=health))
        domain = await asyncio.to_thread(self.get_domain, domain_id)
        self._publish_health(current, health)
        return domain

    def _publish_health(self, before: dict[str, Any], health: dict[str, Any]) -> None:
        previous = (before.get("health") or {}).get("problem_code")
        problem = health.get("problem_code")
        details = {
            "domain_id": before["id"],
            "host": before["host"],
            "service_id": before["service_id"],
            "problem_code": problem,
            "problems": health.get("problems", []),
        }
        if health.get("notice"):
            if previous:
                # An earlier alarm is no longer true (waiting for a deploy, or not
                # checkable from inside): close it without claiming the domain works.
                self.ctx.events.publish(
                    Event(
                        type="domain.healthy",
                        severity="info",
                        title=f"Domain {before['host']}: the earlier problem is no longer reported",
                        module=MODULE_NAME,
                        dedupe_key=f"domain.unhealthy:{before['id']}",
                        details={**details, "notice": health["notice"]},
                    )
                )
            return
        created = before.get("created_at") or 0
        if problem == "tls_pending" and time.time() - float(created) < TLS_PENDING_GRACE_SECONDS:
            return  # a new domain: the certificate is still being issued
        if problem == "tls_expiring":
            tls = health.get("tls") or {}
            self.ctx.events.publish(
                Event(
                    type="domain.cert_expiring",
                    severity="warning",
                    title=f"Certificate for {before['host']} expires soon",
                    message=f"{tls.get('days_left')} days left",
                    module=MODULE_NAME,
                    dedupe_key=f"domain.cert_expiring:{before['id']}",
                    details={**details, "expires_at": tls.get("expires_at")},
                )
            )
        elif problem and problem != previous:
            self.ctx.events.publish(
                Event(
                    type="domain.unhealthy",
                    severity="warning",
                    title=f"Domain {before['host']} has a problem: {problem}",
                    module=MODULE_NAME,
                    dedupe_key=f"domain.unhealthy:{before['id']}",
                    details=details,
                )
            )
        elif not problem and previous:
            self.ctx.events.publish(
                Event(
                    type="domain.healthy",
                    severity="info",
                    title=f"Domain {before['host']} works again",
                    module=MODULE_NAME,
                    dedupe_key=f"domain.unhealthy:{before['id']}",
                    details=details,
                )
            )


    async def verify_due(self) -> int:
        interval = int(self.get_settings()["verify_interval_seconds"])
        if interval <= 0:
            return 0
        now = time.time()
        done = 0
        for item in await asyncio.to_thread(self.list_domains):
            checked = (item.get("health") or {}).get("checked_at")
            if checked is None or now - float(checked) >= interval:
                await self._safe_verify(item["id"])
                done += 1
        return done

    # ------------------------------------------------------------------ dokploy read-back
    async def _dokploy_targets(self, detected: dict[str, Any]) -> list[dict[str, Any]]:
        """Composes/applications whose domains belong to DevAssist services.

        ``{"kind", "id", "routes": {(service name, port): service id}, "services": {...}}``;
        an Application matches by port only (it has no Compose service names).
        """
        targets: dict[tuple[str, str], dict[str, Any]] = {}
        own_ids: set[str] = set()
        for service_id in DOMAIN_SERVICES:
            if service_id == DOH_SERVICE:
                continue
            own = own_stack(self.ctx.data_dir, service_id)
            if own is None:
                continue
            own_ids.add(service_id)
            compose_id = await self.routing.stack_compose(service_id)
            if not compose_id:
                continue
            entry = targets.setdefault(("compose", compose_id),
                                       {"kind": "compose", "id": compose_id, "routes": {}})
            entry["routes"][(own["service_name"], int(own["port"]))] = service_id
        panel_kind = detected.get("dokploy_service_type")
        panel_id = detected.get("dokploy_service_id")
        if detected.get("inside_dokploy") and panel_kind in {"compose", "application"} and panel_id:
            entry = targets.setdefault((panel_kind, str(panel_id)),
                                       {"kind": panel_kind, "id": str(panel_id), "routes": {}})
            name = str(detected.get("compose_service") or FALLBACK_TARGET)
            for service_id in DOMAIN_SERVICES:
                port = SERVICE_INDEX[service_id].internal_port
                if service_id in own_ids or service_id == DOH_SERVICE or not port:
                    continue
                entry["routes"][(name if panel_kind == "compose" else "", int(port))] = service_id
        return list(targets.values())

    async def reconcile_dokploy(self) -> dict[str, Any]:
        """Read Dokploy's domains back; Dokploy is the source of truth when connected."""
        result: dict[str, Any] = {"status": "skipped", "upgraded": 0, "imported": 0,
                                  "removed": 0, "restored": 0, "deployed": 0,
                                  "at": int(time.time())}
        if not dokploy_configured():
            return result
        async with self.lock:
            detected = await self.routing.detect()
            if not detected.get("dokploy_connected"):
                result["status"] = "dokploy_unreachable"
                self.last_reconcile = result
                return result
            targets = await self._dokploy_targets(detected)
            rows = await asyncio.to_thread(self.list_domains)
            by_host = {row["host"]: row for row in rows}
            taken = await asyncio.to_thread(self._bucket_taken_hosts)
            listed: dict[tuple[str, str], set[str]] = {}
            changed = False
            for target in targets:
                if target["kind"] == "compose":
                    items = await self.routing.compose_domains(target["id"])
                else:
                    items = await self.routing.application_domains(target["id"])
                if items is None:
                    continue
                seen = listed.setdefault((target["kind"], target["id"]), set())
                for item in items:
                    try:
                        host = canonical_host(str(item.get("host") or ""))
                    except HostError:
                        continue
                    if str(item.get("path") or "/") not in {"", "/"}:
                        continue  # a path route is not a service domain
                    domain_id = str(item.get("domainId") or "")[:64] or None
                    if domain_id:
                        seen.add(domain_id)
                    port = item.get("port")
                    key = (str(item.get("serviceName") or "") if target["kind"] == "compose"
                           else "", int(port) if isinstance(port, int) else -1)
                    service_id = target["routes"].get(key)
                    https = bool(item.get("https"))
                    row = by_host.get(host)
                    if row is not None:
                        if service_id is not None and row["service_id"] != service_id:
                            continue  # Dokploy sends it elsewhere; the check will show it
                        updates: dict[str, Any] = {}
                        if row["mode"] != "dokploy_api":
                            updates["mode"] = "dokploy_api"
                            result["upgraded"] += 1
                        if domain_id and row["dokploy_domain_id"] != domain_id:
                            updates["dokploy_domain_id"] = domain_id
                        if row["https"] != https:
                            updates["https"] = https
                        if updates:
                            await asyncio.to_thread(
                                lambda rid=row["id"], u=updates: self._update_row(rid, **u))
                            changed = True
                        if row["removed_in_dokploy"]:
                            await self._set_meta(row["id"], {"removed_in_dokploy": None})
                            result["restored"] += 1
                        continue
                    if service_id is None or host in taken:
                        continue
                    created = await asyncio.to_thread(
                        self._insert, service_id, host, https, "dokploy_api", None, domain_id,
                        None)
                    await self._set_meta(created["id"], {"source": "dokploy"})
                    by_host[host] = created
                    result["imported"] += 1
                    changed = True
                    self._verify_soon(created["id"])
            # Rows whose Dokploy domain is gone (only where Dokploy was listed just now).
            compose_of = {service_id: key for key in listed
                          for target in targets if (target["kind"], target["id"]) == key
                          for service_id in target["routes"].values()}
            for row in await asyncio.to_thread(self.list_domains):
                key = compose_of.get(row["service_id"])
                if (key is None or row["mode"] != "dokploy_api" or not row["dokploy_domain_id"]
                        or row["dokploy_domain_id"] in listed[key] or row["removed_in_dokploy"]):
                    continue
                await self._set_meta(row["id"], {"removed_in_dokploy": True,
                                                 "pending_redeploy": None})
                result["removed"] += 1
            if changed:
                await self.sync()
        result["deployed"] = await self._finish_redeploys()
        result["status"] = "ok"
        self.last_reconcile = result
        return result

    def _bucket_taken_hosts(self) -> set[str]:
        """Hosts that are bucket domains (never imported as service domains)."""
        return self.bucket_routes.bucket_hosts() | set(self.bucket_routes.records())

    async def _finish_redeploys(self) -> int:
        """Clear ``pending_redeploy`` once Dokploy finished a newer deployment; re-check."""
        done = 0
        meta = await asyncio.to_thread(self.store.domain_meta)
        for domain_id, entry in meta.items():
            marker = entry.get("pending_redeploy")
            if not isinstance(marker, dict):
                continue
            if await self.routing.deployed_since(marker) is True:
                await self._set_meta(domain_id, {"pending_redeploy": None})
                done += 1
                self._verify_soon(domain_id)
        return done


    # ------------------------------------------------------------------ internal sync
    async def sync(self) -> dict[str, Any]:
        settings = self.get_settings()
        domains = await asyncio.to_thread(self.list_domains)
        result: dict[str, Any] = {
            "panel": self._sync_panel(settings, domains),
            "pypi": await self._sync_pypi(settings, domains),
            "s3": await asyncio.to_thread(self._sync_s3, settings, domains),
            "npm": {
                "status": "not_needed",
                "note": "Verdaccio builds tarball URLs from Host and X-Forwarded-Proto",
            },
            "dns": await self._sync_dns(),
            "at": int(time.time()),
        }
        self.last_sync = result
        return result

    def _sync_panel(
        self, settings: dict[str, Any], domains: list[dict[str, Any]]
    ) -> dict[str, Any]:
        holder = self.ctx.trusted_hosts
        hosts = [item["host"] for item in domains if item["service_id"] == "panel"]
        if holder is None:
            return {"status": "unavailable", "hosts": hosts}
        if not settings["sync_panel_trusted_hosts"]:
            holder.set_extra([])
            return {"status": "disabled", "hosts": []}
        holder.set_extra(hosts)
        return {"status": "applied", "hosts": hosts}

    async def _sync_pypi(
        self, settings: dict[str, Any], domains: list[dict[str, Any]]
    ) -> dict[str, Any]:
        path = self.ctx.data_dir / PYPI_OUTSIDE_FILE
        primary = next(
            (item for item in domains if item["service_id"] == "pypi" and item["primary"]), None
        )
        url = public_url(primary)
        if not settings["sync_pypi_outside_url"]:
            return {
                "status": "disabled",
                "outside_url": None,
                "restarted": False,
                "restart_required": False,
            }
        if os.getenv("MRK_PYPI_OUTSIDE_URL", "").strip():
            return {
                "status": "env_override",
                "outside_url": os.getenv("MRK_PYPI_OUTSIDE_URL"),
                "restarted": False,
                "restart_required": False,
            }

        def write() -> bool:
            try:
                current = path.read_text(encoding="utf-8").strip() if path.is_file() else None
            except OSError:
                current = None
            if current == url:
                return False
            if url is None:
                path.unlink(missing_ok=True)
                return True
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            temporary = path.with_name(f".{path.name}.{secrets.token_hex(4)}.tmp")
            temporary.write_text(url + "\n", encoding="utf-8")
            temporary.chmod(0o600)
            os.replace(temporary, path)
            return True

        changed = await asyncio.to_thread(write)
        result = {
            "status": "applied",
            "outside_url": url,
            "restarted": False,
            "restart_required": False,
        }
        if not changed:
            result["status"] = "unchanged"
            return result
        if "pypi" in read_stopped(self.ctx.data_dir):
            return result  # applies on the next start
        if settings["sync_pypi_restart"] and process_control.supervisor_available():
            try:
                await asyncio.to_thread(process_control.program_action, "devpi", "restart")
                result["restarted"] = True
            except process_control.SupervisorError as exc:
                LOGGER.warning(
                    "devpi restart after a domain change failed", extra={"error_code": exc.code}
                )
                result["restart_required"] = True
        else:
            result["restart_required"] = True
        return result

    def _sync_s3(self, settings: dict[str, Any], domains: list[dict[str, Any]]) -> dict[str, Any]:
        from . import s3 as s3_module
        from .s3_store import DOMAIN_SUFFIXES_KEY

        store = s3_module.ACTIVE_STORE
        if store is None:
            return {"status": "unavailable"}
        if not settings["sync_s3_endpoint"]:
            return {"status": "disabled"}
        s3_domains = [item for item in domains if item["service_id"] == "s3"]
        primary = next((item for item in s3_domains if item["primary"]), None)
        desired_endpoint = public_url(primary)
        desired_suffix = primary["host"] if primary else None
        state = self.store.state()
        managed = state.get("s3_managed") if isinstance(state.get("s3_managed"), dict) else {}
        current = store.get_settings()
        patch: dict[str, Any] = {}
        manual: list[str] = []
        for key, desired in (
            ("public_endpoint", desired_endpoint),
            ("virtual_host_suffix", desired_suffix),
        ):
            now_value = current.get(key)
            if now_value in (None, "") or now_value == managed.get(key):
                if now_value != desired:
                    patch[key] = desired
            elif desired is not None and now_value != desired:
                manual.append(key)  # set by hand on the S3 page; respected
        if patch:
            store.put_settings(patch, None)
        managed = {**managed, **patch}
        hosts = [item["host"] for item in s3_domains]
        now = int(time.time())
        with self.ctx.database.session() as db, db.begin():
            row = db.get(SystemSetting, DOMAIN_SUFFIXES_KEY)
            value = {"hosts": hosts, "managed_by": "domains"}
            if row is None:
                db.add(SystemSetting(key=DOMAIN_SUFFIXES_KEY, value=value, updated_at=now))
            elif row.value != value:
                row.value = value
                row.updated_at = now
        state["s3_managed"] = {
            key: managed.get(key) for key in ("public_endpoint", "virtual_host_suffix")
        }
        self.store.save_state(state)
        store.write_snapshot()
        return {
            "status": "manual_override" if manual else "applied",
            "managed_by": "domains",
            "public_endpoint": store.get_settings().get("public_endpoint"),
            "virtual_host_suffix": store.get_settings().get("virtual_host_suffix"),
            "virtual_host_suffixes": hosts,
            "manual_keys": manual,
        }

    # ------------------------------------------------------------------ services view
    async def _state(
        self, service: ServiceDef, status: dict[str, dict[str, str]] | None, stopped: set[str]
    ) -> tuple[str, str | None, bool]:
        settings = self.ctx.settings
        if service.id == "panel":
            return "running", None, False
        if service.id in {"agent", "firewall"}:
            return await self._helper_state(service.id)
        if service.id in {"git", "registry"}:
            return await self._own_stack_state(service.id)
        if service.id == "dns":
            return await self._dns_state()
        if service.id == DOH_SERVICE:
            state, reason, _supervised = await self._dns_state()
            if state == "running" and await self._doh_port() is None:
                return "disabled", "doh_plain_disabled", False
            return state, reason, False
        if service.id == "s3":
            from .s3_client import is_remote

            if await asyncio.to_thread(is_remote):
                # Its own container (docs/44): only its health is visible from here.
                ok, reason = await self._own_container_health("s3")
                return ("running", None, False) if ok else ("degraded", reason, False)
        if service.id in {"npm", "pypi"}:
            from ..remote_services import is_remote as registry_is_remote

            if await asyncio.to_thread(registry_is_remote, service.id):
                # Its own container (docs/44); the panel keeps only the PyPI router.
                ok, reason = await self._own_container_health(service.id)
                return ("running", None, False) if ok else ("degraded", reason, False)
        # The panel image runs the PyPI router itself, so a service counts as part
        # of this install only when ALL its programs are here.
        if status is not None and not all(name in status for name in service.programs):
            # The panel image runs alone (docs/44): a service whose programs this
            # supervisor does not have is not part of this install.
            return "not_installed", "not_installed_here", False
        enabled = {
            "npm": getattr(settings, "npm_enabled", False),
            "pypi": getattr(settings, "pypi_enabled", False),
            "s3": True,
        }[service.id]
        if service.id == "s3":
            from . import s3 as s3_module

            store = s3_module.ACTIVE_STORE
            if store is not None:
                enabled = bool((await asyncio.to_thread(store.get_settings)).get("enabled", True))
        if not enabled:
            return "disabled", "disabled_in_settings", False
        if status is None:
            ready = await self._health_fallback(service.id)
            if ready:
                return "running", "supervisor_unavailable", False
            return "unknown", "supervisor_unavailable", False
        state, reason = state_from_programs(service, status)
        if state == "stopped" and service.id in stopped:
            reason = "stopped_by_user"
        return state, reason, True

    async def _own_container_health(self, service_id: str) -> tuple[bool, str | None]:
        """(ok, reason) for a service in its own container, with the same probes (and
        timeouts, retries and name-lookup detection) as Home and the status page."""
        name_unresolved = False
        if service_id == "s3":
            from . import s3 as s3_module
            from .s3_client import EngineAdmin

            store = s3_module.ACTIVE_STORE
            if store is None:
                return False, "own_container_unreachable"
            try:
                ok, code = await EngineAdmin(store.admin_token_path).probe()
            except Exception:  # noqa: BLE001
                ok, code = False, None
            name_unresolved = code == "s3_name_unresolved"
        else:
            from ..components import registry_health

            health = await registry_health(self.ctx.settings, service_id)
            ok = health.state == "ready"
            if health.state in {"stopped", "restarting"}:
                return False, "stopped_by_user" if health.state == "stopped" else "crashed_retrying"
            name_unresolved = health.code == "registry_name_unresolved"
        if ok:
            return True, None
        return False, "own_container_name_unresolved" if name_unresolved \
            else "own_container_unreachable"

    async def _health_fallback(self, service_id: str) -> bool:
        settings = self.ctx.settings
        if service_id == "npm":
            return await asyncio.to_thread(
                check_http_component, settings.npm_health_host, settings.npm_health_port, "/-/ping"
            )
        if service_id == "pypi":
            return await asyncio.to_thread(
                check_http_component,
                settings.pypi_health_host,
                settings.pypi_health_port,
                "/+status",
            )
        if service_id == "s3":
            from . import s3 as s3_module
            from .s3_client import EngineAdmin

            store = s3_module.ACTIVE_STORE
            if store is None:
                return False
            try:
                return bool(await EngineAdmin(store.admin_token_path).health())
            except Exception:  # noqa: BLE001
                return False
        return False

    async def _own_stack_state(self, service_id: str) -> tuple[str, str | None, bool]:
        """Git and the registry (docs/46): added from the wizard, in their own stacks."""
        if service_id == "git":
            from . import git_service as module
        else:
            from . import registry_service as module  # type: ignore[no-redef]
        service = module.ACTIVE_SERVICE
        if service is None:
            return "not_installed", "module_unavailable", False
        if service.connected() is None:
            return "not_installed", f"{service_id}_not_configured", False
        if service_id == "git":
            reachable = (await service.status())["reachable"]
        else:
            reachable = await service.reachable()
        if reachable:
            return "running", None, False
        return "degraded", f"{service_id}_unreachable", False

    async def _helper_state(self, service_id: str) -> tuple[str, str | None, bool]:
        from .home import find_service

        name = "HostAgentService" if service_id == "agent" else "FirewallService"
        service = find_service(self.ctx, name)
        if service is None:
            return "not_installed", "module_unavailable", False
        if service_id == "agent":
            source, url, _key = service.resolve()
            configured = source is not None and url is not None
        else:
            configured = bool(await asyncio.to_thread(service.configured))
        if not configured:
            return "not_installed", f"{service_id}_not_configured", False
        reachable = getattr(service, "reachable", None)
        if reachable is True:
            return "running", None, False
        if reachable is False:
            return "degraded", f"{service_id}_unreachable", False
        return "unknown", "not_checked_yet", False

    def _dns_service(self) -> Any | None:
        from . import dns as dns_module

        service = dns_module.ACTIVE_SERVICE
        return service if service is not None and service.ctx is self.ctx else None

    async def _dns_state(self) -> tuple[str, str | None, bool]:
        service = self._dns_service()
        if service is None:
            return "not_installed", "module_unavailable", False
        status = await service.status(refresh=True)
        if not status.get("installed"):
            return "not_installed", "dns_not_installed", False
        if status.get("reachable"):
            return "running", None, False
        return "degraded", "dns_unreachable", False

    async def _doh_port(self) -> int | None:
        """The plain DoH port when the engine has ``doh.enabled && !doh.tls``."""
        service = self._dns_service()
        if service is None:
            return None
        try:
            await service.current_settings()
        except Exception:  # noqa: BLE001 - engine trouble = not offered
            return None
        return service.plain_doh_port()

    def _service_target(self, service_id: str) -> tuple[str, int] | None:
        """(host, port) for services outside the panel container (Traefik file mode)."""
        if service_id == DOH_SERVICE:
            return self.doh_target()
        from .domains_routing import own_stack

        own = own_stack(self.ctx.data_dir, service_id)
        return (own["host"], own["port"]) if own is not None else None

    def doh_target(self) -> tuple[str, int]:
        """(address, port) Traefik should send DoH requests to (docs/40 §5)."""
        service = self._dns_service()
        port = (service.plain_doh_port() if service else None) or SERVICE_INDEX[
            DOH_SERVICE].internal_port or 8053
        target = None
        settings = (service.cached_settings() if service else None) or {}
        doh = (settings.get("encrypted") or {}).get("doh") if isinstance(
            settings.get("encrypted"), dict) else None
        from .dns_validate_d4 import listen_on

        for item in (doh or {}).get("listen") or []:
            try:
                address, listen_port = listen_on(item, 443)
            except ValueError:
                continue
            if listen_port == port and address.version == 4 and not (
                address.is_loopback or address.is_unspecified
            ):
                target = str(address)
                break
        if target is None:
            target = service.effective_target() if service else "172.17.0.1"
        return target, port

    def _doh_instructions(self, host: str) -> dict[str, Any]:
        target, port = self.doh_target()
        upstream = f"http://{target}:{port}"
        return {
            "steps_fa": [
                f"در DNS دامنه، یک رکورد A برای «{host}» به IP عمومی همین سرور بسازید.",
                "در Traefik (Dokploy → Traefik → File System/Dynamic) یک router با "
                f"Host(`{host}`) و گواهی Let's Encrypt بسازید که به «{upstream}» برود.",
                "مسیر /dns-query را تغییر ندهید و هدر Host را نگه دارید.",
                "در DevAssist روی «بررسی» بزنید تا DNS، گواهی و رسیدن درخواست بررسی شود.",
            ],
            "steps_en": [
                f"In your DNS, create an A record for “{host}” pointing to this server's "
                "public IP.",
                "In Traefik (Dokploy → Traefik → File System/Dynamic) add a router for "
                f"Host(`{host}`) with a Let's Encrypt certificate that forwards to “{upstream}”.",
                "Keep the /dns-query path and the Host header unchanged.",
                "Back in DevAssist, click Verify to check DNS, the certificate and that "
                "requests arrive.",
            ],
            "traefik": {"host": host, "upstream": upstream, "path": "/dns-query"},
        }

    async def _sync_dns(self) -> dict[str, Any]:
        service = self._dns_service()
        if service is None:
            return {"status": "unavailable"}
        return await service.safe_sync()

    async def services_view(self, *, include_domains: bool) -> dict[str, Any]:
        programs = sorted({name for item in SERVICES for name in item.programs})
        status = await asyncio.to_thread(process_control.program_status, programs)
        stopped = await asyncio.to_thread(read_stopped, self.ctx.data_dir)
        domains = await asyncio.to_thread(self.list_domains)
        items = []
        doh_port = await self._doh_port()
        for service in SERVICES:
            own_rows = [item for item in domains if item["service_id"] == service.id]
            if service.id in CONDITIONAL_SERVICES and doh_port is None and not own_rows:
                continue  # dns-doh: only while plain DoH is on (or domains remain)
            state, reason, supervised = await self._state(service, status, stopped)
            crash = self.watchdog.record(service.id)
            if crash is not None:
                auto = bool(self.get_settings().get("auto_restart", True))
                state = "crashed"
                reason = "crashed_retrying" if auto else "crashed_no_auto_restart"
            own = [item for item in domains if item["service_id"] == service.id]
            primary = next((item for item in own if item["primary"]), None)
            controllable = bool(service.actions) and supervised and state != "disabled"
            usage = await self.usage.read(service)
            items.append(
                {
                    "id": service.id,
                    "name_fa": service.name_fa,
                    "name_en": service.name_en,
                    "description_fa": service.description_fa,
                    "description_en": service.description_en,
                    "state": state,
                    "reason_code": reason,
                    "recovery": crash.public() if crash is not None else None,
                    "controllable": controllable,
                    "actions": list(service.actions) if controllable else [],
                    "internal_port": (doh_port or service.internal_port)
                    if service.id == DOH_SERVICE
                    else service.internal_port,
                    "usage": usage
                    or {
                        "disk_bytes": None,
                        "disk_partial": False,
                        "items": None,
                        "items_kind": None,
                        "last_activity_at": None,
                        "requests_24h": None,
                    },
                    "domains": [
                        {
                            "id": item["id"],
                            "host": item["host"],
                            "display_host": item["display_host"],
                            "primary": item["primary"],
                            "https": item["https"],
                            "health": item["health"],
                            "mode": item["mode"],
                            "pending_redeploy": item["pending_redeploy"],
                            "removed_in_dokploy": item["removed_in_dokploy"],
                        }
                        for item in own
                    ]
                    if include_domains
                    else [],
                    "domains_supported": service.domains,
                    "public_url": public_url(primary),
                    "manage_route": service.manage_route,
                }
            )
        detected = await self.routing.detect_quick()
        return {
            "items": items,
            "routing": {
                "mode": self.get_settings()["routing_mode"],
                "effective_mode": (
                    self.routing.effective_mode(detected) if detected is not None else None
                ),
                "detected": self._public_detected(detected) if detected is not None else None,
                "detecting": detected is None,
            },
            "supervisor_available": status is not None,
        }

    @staticmethod
    def _public_detected(detected: dict[str, Any]) -> dict[str, Any]:
        return {key: value for key, value in detected.items() if key != "errors"} | {
            "errors": list(dict.fromkeys(detected.get("errors") or []))
        }

    async def action(
        self, service_id: str, action: str, confirmation: str | None
    ) -> dict[str, Any]:
        service = SERVICE_INDEX.get(service_id)
        if service is None:
            raise ServiceError("service_not_found", 404, "Unknown service")
        if action not in {"start", "stop", "restart"}:
            raise ServiceError(
                "service_action_not_allowed",
                422,
                "Unknown action",
                fields=[{"field": "action", "reason_code": "invalid_choice"}],
            )
        if action not in service.actions:
            raise ServiceError(
                "service_not_controllable",
                409,
                "This service cannot be started or stopped from the panel",
            )
        if action in {"stop", "restart"} and confirmation != service.id:
            raise ServiceError(
                "confirmation_mismatch",
                422,
                "Type the service id to confirm",
                expected_confirmation=service.id,
                fields=[{"field": "confirmation", "reason_code": "incorrect"}],
            )
        state, _reason, supervised = await self._state(
            service,
            await asyncio.to_thread(process_control.program_status, list(service.programs)),
            set(),
        )
        if state == "disabled":
            raise ServiceError(
                "service_action_not_allowed",
                409,
                "This service is turned off in settings",
                reason="service_disabled",
            )
        if not supervised:
            raise ServiceError(
                "service_not_controllable",
                409,
                "The process supervisor is not reachable here",
                reason="supervisor_unavailable",
            )
        if service.id in self.busy:
            raise ServiceError("service_busy", 409, "Another action on this service is running")
        self.busy.add(service.id)
        self.watchdog.busy.add(service.id)
        try:
            result = await self._run_action(service, action)
            # The operator took over: forget the automatic retry schedule.
            self.watchdog.reset(service.id)
            return result
        finally:
            self.busy.discard(service.id)
            self.watchdog.busy.discard(service.id)

    async def _run_action(self, service: ServiceDef, action: str) -> dict[str, Any]:
        order = list(service.programs)
        if action == "stop":
            order.reverse()  # devpi before its router
        elif service.id == "pypi":
            order = ["pypi-router", "devpi"]
        stopped = await asyncio.to_thread(read_stopped, self.ctx.data_dir)
        if action == "stop":
            await asyncio.to_thread(write_stopped, self.ctx.data_dir, stopped | {service.id})
        try:
            for program in order:
                await asyncio.to_thread(process_control.program_action, program, action)
        except process_control.SupervisorError as exc:
            raise ServiceError(
                "service_action_failed", 502, exc.message, upstream_code=exc.code
            ) from None
        if action in {"start", "restart"} and service.id in stopped:
            await asyncio.to_thread(write_stopped, self.ctx.data_dir, stopped - {service.id})
        status = await asyncio.to_thread(process_control.program_status, list(service.programs))
        new_state, reason = state_from_programs(service, status)
        return {"id": service.id, "action": action, "state": new_state, "reason_code": reason}

    # ------------------------------------------------------------------ routing view
    async def routing_view(self, *, refresh: bool = False) -> dict[str, Any]:
        detected = await self.routing.detect(refresh=refresh)
        if refresh:
            self.reconcile_soon()
        settings = self.get_settings()
        target = self.routing.target_host(detected)
        network = settings["dokploy_network"]
        return {
            "mode": settings["routing_mode"],
            "effective_mode": self.routing.effective_mode(detected),
            "available_modes": [
                key for key, ok in self.routing.available_modes(detected).items() if ok
            ],
            "detected": self._public_detected(detected),
            "settings": {
                key: settings[key]
                for key in (
                    "traefik_file_enabled",
                    "cert_resolver",
                    "entrypoint_web",
                    "entrypoint_websecure",
                    "redirect_middleware",
                    "target_host",
                    "dokploy_network",
                    "verify_interval_seconds",
                    "server_public_ips",
                )
            },
            "target_host": target,
            "guidance": guidance(network, target, detected),
            "sync": self.last_sync or None,
            "reconcile": self.last_reconcile,
        }

    # ------------------------------------------------------------------ lifecycle
    async def _restop(self) -> None:
        """Services stopped on purpose stay stopped after a container restart."""
        stopped = await asyncio.to_thread(read_stopped, self.ctx.data_dir)
        if not stopped or not process_control.supervisor_available():
            return
        for service_id in sorted(stopped):
            service = SERVICE_INDEX[service_id]
            for program in reversed(service.programs):
                try:
                    await asyncio.to_thread(process_control.program_action, program, "stop")
                except process_control.SupervisorError:
                    LOGGER.warning("could not keep %s stopped", service_id)

    async def _loop(self) -> None:
        await asyncio.sleep(30)
        while True:
            try:
                await self.reconcile_dokploy()
            except asyncio.CancelledError:
                raise
            except Exception:
                LOGGER.exception("reading domains back from Dokploy failed")
            try:
                await self.verify_due()
            except asyncio.CancelledError:
                raise
            except Exception:
                LOGGER.exception("domain verification loop failed")
            try:
                await self.bucket_routes.reconcile()
            except asyncio.CancelledError:
                raise
            except Exception:
                LOGGER.exception("bucket route reconcile failed")
            await asyncio.sleep(VERIFY_TICK_SECONDS)

    async def start(self) -> None:
        try:
            await self.sync()
        except Exception:
            LOGGER.exception("initial domain sync failed")
        try:
            await self._restop()
        except Exception:
            LOGGER.exception("re-stopping services failed")
        self._task = asyncio.create_task(self._loop(), name="mrk-domain-verify")
        self.watchdog.start()

    async def stop(self) -> None:
        await self.watchdog.stop()
        if self._reconcile_task is not None and not self._reconcile_task.done():
            self._reconcile_task.cancel()
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None


def guide_snippets(network: str, target: str) -> dict[str, str]:
    join_network = (
        "services:\n"
        f"  {target}:\n"
        "    networks:\n"
        "      - default\n"
        f"      - {network}\n"
        "networks:\n"
        f"  {network}:\n"
        "    external: true\n"
    )
    agent_mount = (
        "services:\n"
        "  mrk-agent:\n"
        "    environment:\n"
        "      MRK_AGENT_TRAEFIK_DYNAMIC_DIR: /host/traefik-dynamic\n"
        "    volumes:\n"
        "      # read-write, only this folder; the agent writes only mrk-domains.yml\n"
        "      - /etc/dokploy/traefik/dynamic:/host/traefik-dynamic\n"
    )
    dokploy_compose = (
        "# Dokploy → Create Service → Compose → Raw; paste the DevAssist compose file and\n"
        "# keep the service name (e.g. mrk-mirror). Then connect Dokploy in DevAssist\n"
        "# (Server → Dokploy) and add domains here: they are created through the\n"
        "# Dokploy API on this Compose service (ports 8080/4873/3141/9000).\n"
    )
    return {
        "join_dokploy_network": join_network,
        "agent_traefik_mount": agent_mount,
        "dokploy_compose_install": dokploy_compose,
    }


def guidance(network: str, target: str, detected: dict[str, Any]) -> list[dict[str, Any]]:
    """Ordered help cards for the routing page: {id, title_fa, title_en, body_fa, body_en, code}."""
    snippets = guide_snippets(network, target)
    cards = [
        {
            "id": "dokploy_compose_install",
            "title_fa": "نصب DevAssist به‌صورت Compose داخل Dokploy (روش پیشنهادی)",
            "title_en": "Install DevAssist as a Compose service in Dokploy (recommended)",
            "body_fa": "با این روش دامنه‌ها مستقیم با API رسمی Dokploy روی همان سرویس ثبت "
            "می‌شوند و گواهی Let's Encrypt خودکار گرفته می‌شود.",
            "body_en": "Domains are then registered through Dokploy's official API on the same "
            "service and Let's Encrypt certificates are issued automatically.",
            "code": snippets["dokploy_compose_install"],
            "done": bool(detected.get("inside_dokploy")),
        },
        {
            "id": "join_dokploy_network",
            "title_fa": f"اتصال کانتینر MRK به شبکه {network}",
            "title_en": f"Attach the MRK container to {network}",
            "body_fa": "Traefik دکپلوی فقط از این شبکه به DevAssist می‌رسد (برای روش فایل Traefik).",
            "body_en": ("Dokploy's Traefik reaches DevAssist only on this network "
                        "(Traefik file mode)."),
            "code": snippets["join_dokploy_network"],
            "done": bool(detected.get("on_dokploy_network")),
        },
        {
            "id": "agent_traefik_mount",
            "title_fa": "اجازه نوشتن فایل Traefik به Agent (اختیاری)",
            "title_en": "Let the agent write the Traefik file (optional)",
            "body_fa": "فقط پوشه dynamic دکپلوی، قابل نوشتن، به Agent داده می‌شود و Agent فقط "
            "فایل mrk-domains.yml را می‌سازد. سپس «اجازه نوشتن فایل Traefik» را روشن کنید.",
            "body_en": "Mount only Dokploy's dynamic folder read-write into the agent; it writes "
            "only mrk-domains.yml. Then turn on “Allow the Traefik file”.",
            "code": snippets["agent_traefik_mount"],
            "done": bool(detected.get("traefik_dir_available")),
        },
    ]
    return cards


ACTIVE_SERVICE: ServicesService | None = None


def register(ctx: ModuleContext) -> None:
    global ACTIVE_SERVICE
    service = ServicesService(ctx)
    ACTIVE_SERVICE = service
    services_router = APIRouter(prefix="/api/v1/services", tags=["services"])
    domains_router = APIRouter(prefix="/api/v1/domains", tags=["domains"])

    def fail(exc: ServiceError) -> JSONResponse:
        extra = dict(exc.extra)
        fields = extra.pop("fields", None)
        return ctx.error_payload(  # type: ignore[call-arg]
            exc.code, exc.message, exc.status_code, fields=fields, **extra
        )

    async def audit(
        principal: Any, action: str, object_type: str, object_id: str, result: str = "success"
    ) -> None:
        await asyncio.to_thread(
            ctx.audit, principal.user_id, action, object_type, object_id, result
        )

    @services_router.get("")
    async def list_services(request: Request) -> dict[str, Any]:
        ctx.require_principal(request, "services:read")
        return await service.services_view(include_domains=True)

    @services_router.post("/{service_id}/actions", response_model=None)
    async def service_action(service_id: str, request: Request) -> dict[str, Any] | JSONResponse:
        principal = ctx.require_principal(request, "services:operate")
        ctx.require_csrf(request, principal)
        try:
            body = ServiceActionRequest.model_validate_json(await request.body() or b"{}")
        except ValueError:
            return ctx.error_payload("validation_error", "Invalid request body", 422)
        try:
            result = await service.action(service_id, body.action, body.confirmation)
        except ServiceError as exc:
            if exc.status_code not in {404, 422}:
                await audit(
                    principal,
                    "services.action",
                    "service",
                    f"{service_id}:{body.action}",
                    "failure",
                )
            return fail(exc)
        await audit(principal, "services.action", "service", f"{service_id}:{body.action}")
        return result

    @domains_router.get("")
    async def list_domains(request: Request) -> dict[str, Any]:
        ctx.require_principal(request, "domains:read")
        items = await asyncio.to_thread(service.list_domains)
        return {"items": await service.with_instructions(items)}

    @domains_router.post("", status_code=201, response_model=None)
    async def create_domain(request: Request, body: DomainCreateRequest) -> Any:
        principal = ctx.require_principal(request, "domains:write")
        ctx.require_csrf(request, principal)
        try:
            result = await service.create(body, principal.user_id)
        except ServiceError as exc:
            await audit(principal, "domain.create", "domain", body.host[:255], "failure")
            return fail(exc)
        await audit(principal, "domain.create", "domain", result["domain"]["host"])
        return result

    @domains_router.get("/routing")
    async def get_routing(request: Request, refresh: bool = False) -> dict[str, Any]:
        ctx.require_principal(request, "domains:read")
        return await service.routing_view(refresh=refresh)

    @domains_router.put("/routing", response_model=None)
    async def put_routing(request: Request, body: RoutingRequest) -> Any:
        principal = ctx.require_principal(request, "domains:write")
        ctx.require_csrf(request, principal)
        patch: dict[str, Any] = {"routing_mode": body.mode}
        if body.traefik_file_enabled is not None:
            patch["traefik_file_enabled"] = body.traefik_file_enabled
        try:
            await asyncio.to_thread(service.put_settings, patch, principal.user_id)
        except SettingsError as exc:
            return ctx.error_payload(  # type: ignore[call-arg]
                "invalid_routing_mode",
                exc.message,
                422,
                fields=[{"field": "mode", "reason_code": "invalid_choice"}],
            )
        await audit(principal, "domains.routing.update", "domain_routing", body.mode)
        return await service.routing_view(refresh=True)

    @domains_router.post("/reconcile", response_model=None)
    async def reconcile_domains(request: Request) -> Any:
        """Read the domains back from Dokploy now (also runs on every verification tick)."""
        principal = ctx.require_principal(request, "domains:write")
        ctx.require_csrf(request, principal)
        result = await service.reconcile_dokploy()
        buckets = await service.bucket_routes.reconcile()
        await audit(principal, "domains.reconcile", "domain", "*")
        return {**result, "bucket_routes": buckets}

    # docs/43 §0.1: routes of verified bucket domains (shown on the admin S3 page).
    @domains_router.get("/bucket-routes")
    async def list_bucket_routes(request: Request) -> dict[str, Any]:
        ctx.require_principal(request, "domains:read")
        return await service.bucket_routes.admin_list()

    @domains_router.post("/bucket-routes/reconcile", response_model=None)
    async def reconcile_bucket_routes(request: Request) -> Any:
        principal = ctx.require_principal(request, "domains:write")
        ctx.require_csrf(request, principal)
        result = await service.bucket_routes.reconcile(retry=True)
        await audit(principal, "domains.bucket_routes.reconcile", "bucket_route", "*")
        return {**result, **await service.bucket_routes.admin_list()}

    @domains_router.post("/bucket-routes/{host}/retry", response_model=None)
    async def retry_bucket_route(host: str, request: Request) -> Any:
        principal = ctx.require_principal(request, "domains:write")
        ctx.require_csrf(request, principal)
        host = host.strip().lower().rstrip(".")
        listed = await service.bucket_routes.admin_list()
        if not any(item["host"] == host for item in listed["items"]):
            return ctx.error_payload("domain_not_found", "Domain not found", 404)
        await service.bucket_routes.ensure(host, retry=True)
        await audit(principal, "domains.bucket_routes.retry", "bucket_route", host)
        listed = await service.bucket_routes.admin_list()
        return next(item for item in listed["items"] if item["host"] == host)

    @domains_router.patch("/{domain_id}", response_model=None)
    async def update_domain(domain_id: str, request: Request, body: DomainUpdateRequest) -> Any:
        principal = ctx.require_principal(request, "domains:write")
        ctx.require_csrf(request, principal)
        try:
            result = await service.update(domain_id, body)
        except ServiceError as exc:
            if exc.status_code != 404:
                await audit(principal, "domain.update", "domain", domain_id, "failure")
            return fail(exc)
        await audit(principal, "domain.update", "domain", result["domain"]["host"])
        return result

    @domains_router.delete("/{domain_id}", response_model=None)
    async def delete_domain(domain_id: str, request: Request) -> Any:
        principal = ctx.require_principal(request, "domains:write")
        ctx.require_csrf(request, principal)
        raw = await request.body()
        try:
            body = (
                DomainDeleteRequest.model_validate_json(raw)
                if raw.strip()
                else (DomainDeleteRequest())
            )
        except ValueError:
            return ctx.error_payload("validation_error", "Invalid request body", 422)
        try:
            result = await service.delete(
                domain_id, body.confirmation, request_host=_request_host(request),
                confirm_current=body.confirm_current)
        except ServiceError as exc:
            if exc.status_code not in {404, 422}:
                await audit(principal, "domain.delete", "domain", domain_id, "failure")
            return fail(exc)
        await audit(principal, "domain.delete", "domain", domain_id)
        return result

    @domains_router.post("/{domain_id}/verify", response_model=None)
    async def verify(domain_id: str, request: Request) -> Any:
        principal = ctx.require_principal(request, "domains:write")
        ctx.require_csrf(request, principal)
        try:
            domain = await service.verify(domain_id)
            [domain] = await service.with_instructions([domain])
        except ServiceError as exc:
            return fail(exc)
        except Exception:  # noqa: BLE001 - a probe crashed; never a 500
            LOGGER.exception("domain verification failed")
            return ctx.error_payload("verify_failed", "The domain check could not run", 502)
        await audit(
            principal,
            "domain.verify",
            "domain",
            domain["host"],
            "success" if not domain["health"].get("problem_code") else "failure",
        )
        return {"domain": domain, "health": domain["health"]}

    ctx.routers.append(services_router)
    ctx.routers.append(domains_router)
    ctx.start_hooks.append(service.start)
    ctx.stop_hooks.append(service.stop)
