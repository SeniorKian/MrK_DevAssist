"""Public routes for verified bucket domains (docs/43 §0.1 «مسیر دامنه باکت»).

A verified bucket domain is routed exactly like a domain of the S3 service: same
routing mode (``dokploy_api`` / ``traefik_file`` / ``manual``, docs/35 §2), same
target (the S3 engine port of this container) and TLS through Dokploy's Traefik.
The S3 engine then maps the Host header to the bucket (``bucket_hosts``).

Route state lives in ``system_settings["services.bucket_routes"]`` keyed by host,
apart from the ownership row, so a route can still be removed after its domain,
bucket or workspace is gone (transfer, workspace delete). ``reconcile`` brings the
routes in line with the verified bucket domains; it runs after ownership changes
and on the domain-verification tick.

States: ``ok`` (routed), ``pending`` (Dokploy has the domain; a Compose redeploy by
the server admin is still needed), ``manual`` (the server admin follows steps),
``failed`` (the change was rolled back; ``error_code`` says why), ``conflict`` (the
host is used elsewhere; nothing was changed), ``stale`` (removal still to finish),
``off`` (``route_bucket_domains`` is turned off).
"""

from __future__ import annotations

import asyncio
import logging
import threading
import time
from typing import TYPE_CHECKING, Any

from sqlalchemy import select

from ..models import ResourceOwner, ServiceDomain, SystemSetting, Workspace

if TYPE_CHECKING:
    from .services import ServicesService

LOGGER = logging.getLogger(__name__)
ROUTES_KEY = "services.bucket_routes"
ADMIN_DOMAINS_KEY = "s3.admin_bucket_domains"
S3_SERVICE = "s3"
# States that keep a route in place (the host is served or being served).
LIVE_STATES = frozenset({"ok", "pending", "manual"})
# Serialises the read-modify-write of the admin host map inside this process.
_ADMIN_DOMAINS_LOCK = threading.Lock()


def read_admin_domains(db: Any) -> dict[str, str]:
    """Admin host -> bucket map from ``system_settings`` (read in ``db``)."""
    row = db.get(SystemSetting, ADMIN_DOMAINS_KEY)
    value = row.value if row is not None and isinstance(row.value, dict) else {}
    return {
        str(host): str(bucket)
        for host, bucket in value.items()
        if isinstance(host, str) and isinstance(bucket, str)
    }


def _now() -> int:
    return int(time.time())


class BucketRoutes:
    def __init__(self, service: ServicesService) -> None:
        self.service = service
        self.database = service.ctx.database
        self._soon: asyncio.Task[Any] | None = None

    # ------------------------------------------------------------------ storage
    def records(self) -> dict[str, dict[str, Any]]:
        with self.database.session() as db:
            row = db.get(SystemSetting, ROUTES_KEY)
            value = row.value if row is not None and isinstance(row.value, dict) else {}
            return {str(host): dict(item) for host, item in value.items()
                    if isinstance(item, dict)}

    def _save(self, records: dict[str, dict[str, Any]]) -> None:
        now = _now()
        with self.database.session() as db, db.begin():
            row = db.get(SystemSetting, ROUTES_KEY)
            if row is None:
                db.add(SystemSetting(key=ROUTES_KEY, value=records, updated_at=now,
                                     updated_by_user_id=None))
            else:
                row.value = records
                row.updated_at = now

    def _put(self, host: str, record: dict[str, Any] | None) -> None:
        records = self.records()
        if record is None:
            records.pop(host, None)
        else:
            records[host] = record
        self._save(records)

    def admin_domains(self) -> dict[str, str]:
        """Custom host -> bucket mappings created by an S3 administrator."""
        with self.database.session() as db:
            return read_admin_domains(db)

    def set_admin_domain(self, host: str, bucket: str | None, *,
                         only_if_free: bool = False) -> bool:
        """Map ``host`` to ``bucket`` (None removes it) in one read-modify-write.

        With ``only_if_free`` nothing changes and False is returned when the host is
        already mapped, so two concurrent adds cannot both win.
        """
        with _ADMIN_DOMAINS_LOCK, self.database.session() as db, db.begin():
            row = db.get(SystemSetting, ADMIN_DOMAINS_KEY)
            domains = read_admin_domains(db)
            if only_if_free and bucket is not None and host in domains:
                return False
            if bucket is None:
                domains.pop(host, None)
            else:
                domains[host] = bucket
            now = _now()
            if row is None:
                db.add(SystemSetting(key=ADMIN_DOMAINS_KEY, value=domains, updated_at=now,
                                     updated_by_user_id=None))
            else:
                row.value = domains
                row.updated_at = now
            return True

    def admin_domains_for(self, bucket: str) -> list[str]:
        return sorted(host for host, target in self.admin_domains().items() if target == bucket)

    def traefik_rows(self) -> list[dict[str, Any]]:
        """Rows for the shared Traefik file (only routes that are in place)."""
        return [
            {"service_id": S3_SERVICE, "host": host, "https": bool(item.get("https", True)),
             "primary": False, "mode": "traefik_file"}
            for host, item in sorted(self.records().items())
            if item.get("mode") == "traefik_file" and item.get("state") == "ok"
        ]

    def desired(self) -> dict[str, dict[str, Any]]:
        """Verified bucket domains: host -> {bucket, workspace_id}."""
        with self.database.session() as db:
            rows = db.scalars(select(ResourceOwner).where(ResourceOwner.kind == "bucket_domain"))
            workspace = {
                row.resource_id: {"bucket": str(row.meta["bucket"]),
                                  "workspace_id": row.workspace_id}
                for row in rows
                if (row.meta or {}).get("verified") and (row.meta or {}).get("bucket")
            }
        admin = {
            host: {"bucket": bucket, "workspace_id": None}
            for host, bucket in self.admin_domains().items()
        }
        # A workspace claim predates this feature and wins defensively if old data clashes.
        return {**admin, **workspace}

    def bucket_hosts(self) -> set[str]:
        with self.database.session() as db:
            workspace = set(db.scalars(select(ResourceOwner.resource_id).where(
                ResourceOwner.kind == "bucket_domain")))
        return workspace | set(self.admin_domains())

    def _service_host(self, host: str) -> bool:
        with self.database.session() as db:
            return db.scalar(select(ServiceDomain.id).where(ServiceDomain.host == host)) is not None

    # ------------------------------------------------------------------ views
    @staticmethod
    def public_view(record: dict[str, Any] | None, verified: bool) -> dict[str, Any]:
        """What a workspace sees: the state only, never server internals."""
        if not verified:
            return {"state": "unverified", "error_code": None}
        if record is None:
            return {"state": "pending", "error_code": None}
        state = record.get("state")
        if state == "stale":
            state = "pending"
        return {"state": state, "error_code": record.get("error_code")}

    def admin_view(self, host: str, record: dict[str, Any] | None,
                   detected: dict[str, Any] | None) -> dict[str, Any]:
        if record is None:
            return {"state": "none", "mode": None, "error_code": None, "https": True,
                    "redeploy_required": False, "suggested_action": None, "instructions": None,
                    "updated_at": None}
        view = {key: record.get(key) for key in (
            "state", "mode", "error_code", "upstream_code", "redeploy_required", "updated_at",
            "conflict")}
        view["https"] = bool(record.get("https", True))
        view["suggested_action"] = (
            self.service.routing.redeploy_hint(detected)
            if record.get("redeploy_required") and detected else None)
        view["instructions"] = (
            self.service.routing.instructions(S3_SERVICE, host, view["https"], detected)
            if record.get("state") == "manual" and detected is not None else None)
        return view

    def _owners(self) -> list[dict[str, Any]]:
        with self.database.session() as db:
            rows = db.execute(select(ResourceOwner, Workspace.slug).join(
                Workspace, Workspace.id == ResourceOwner.workspace_id, isouter=True).where(
                ResourceOwner.kind == "bucket_domain").order_by(ResourceOwner.resource_id))
            workspace = [{"host": row.resource_id, "bucket": (row.meta or {}).get("bucket"),
                          "verified": bool((row.meta or {}).get("verified")),
                          "workspace_id": row.workspace_id, "workspace_slug": slug,
                          "source": "workspace"}
                         for row, slug in rows]
        admin = [{"host": host, "bucket": bucket, "verified": True,
                  "workspace_id": None, "workspace_slug": None, "source": "admin"}
                 for host, bucket in sorted(self.admin_domains().items())]
        return [*admin, *workspace]

    async def admin_list(self) -> dict[str, Any]:
        """Every bucket domain with its route, plus routes still to remove."""
        owners = await asyncio.to_thread(self._owners)
        records = await asyncio.to_thread(self.records)
        detected = await self.service.routing.detect_quick()
        items: list[dict[str, Any]] = []
        for owner in owners:
            record = records.pop(owner["host"], None)
            route = (self.admin_view(owner["host"], record, detected) if owner["verified"]
                     else {**self.admin_view(owner["host"], None, detected),
                           "state": "unverified"})
            items.append({**owner, "route": route})
        for host, record in sorted(records.items()):
            items.append({"host": host, "bucket": record.get("bucket"), "verified": False,
                          "workspace_id": None, "workspace_slug": None, "source": None,
                          "route": {**self.admin_view(host, record, detected),
                                    "state": "stale"}})
        settings = self.service.get_settings()
        return {"items": items, "enabled": bool(settings.get("route_bucket_domains", True)),
                "mode": settings["routing_mode"],
                "effective_mode": (self.service.routing.effective_mode(detected)
                                   if detected is not None else None)}

    # ------------------------------------------------------------------ public api
    async def ensure(self, host: str, *, retry: bool = False) -> dict[str, Any]:
        """Route one verified bucket domain (or refresh its state); returns the record."""
        async with self.service.lock:
            return await self._ensure(host, retry=retry)

    async def remove(self, host: str) -> dict[str, Any]:
        async with self.service.lock:
            return await self._remove(host)

    async def reconcile(self, *, retry: bool = False) -> dict[str, Any]:
        """Add missing routes and remove routes nobody owns any more."""
        async with self.service.lock:
            desired = await asyncio.to_thread(self.desired)
            enabled = bool(self.service.get_settings().get("route_bucket_domains", True))
            records = await asyncio.to_thread(self.records)
            removed = added = 0
            for host, record in records.items():
                want = desired.get(host)
                if want is None or record.get("state") == "stale":
                    await self._remove(host)
                    removed += 1
                elif want != {"bucket": record.get("bucket"),
                              "workspace_id": record.get("workspace_id")}:
                    # Same host, another bucket/owner: the route target is the same engine.
                    record.update(want)
                    await asyncio.to_thread(self._put, host, record)
            records = await asyncio.to_thread(self.records)
            for host in sorted(desired):
                state = (records.get(host) or {}).get("state")
                if state is None or (state == "off") == enabled or (
                        retry and state not in {"ok", "off"}):
                    # _ensure removes live routes and records "off" while turned off.
                    await self._ensure(host, retry=retry)
                    added += 1
            return {"added": added, "removed": removed}

    def reconcile_soon(self) -> None:
        """Run ``reconcile`` in the background (after ownership changes)."""
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return
        if self._soon is not None and not self._soon.done():
            return

        async def run() -> None:
            try:
                await self.reconcile()
            except Exception:  # noqa: BLE001 - next tick tries again
                LOGGER.exception("bucket route reconcile failed")

        self._soon = loop.create_task(run())

    # ------------------------------------------------------------------ internals
    async def _ensure(self, host: str, *, retry: bool) -> dict[str, Any]:
        routing = self.service.routing
        settings = self.service.get_settings()
        want = (await asyncio.to_thread(self.desired)).get(host)
        current = (await asyncio.to_thread(self.records)).get(host)
        if want is None:
            if current is not None:
                await self._remove(host)
            return {"state": "none"}
        https = bool(settings.get("bucket_domains_https", True))
        base: dict[str, Any] = {
            **want, "https": https, "mode": None, "state": "failed", "error_code": None,
            "upstream_code": None, "dokploy_domain_id": None, "redeploy_required": False,
            "conflict": None, "updated_at": _now(),
        }
        if not settings.get("route_bucket_domains", True):
            if current is not None and current.get("state") != "off":
                await self._remove(host)
            record = {**base, "state": "off"}
            await asyncio.to_thread(self._put, host, record)
            return record
        if current is not None and current.get("state") in LIVE_STATES:
            if not retry or current.get("state") == "ok":
                return current
            if current.get("state") == "pending" and current.get("dokploy_domain_id"):
                # The admin redeployed: Dokploy still has the domain -> routed.
                detected = await routing.detect()
                if await routing.dokploy_find_id(host, detected):
                    current.update({"state": "ok", "redeploy_required": False,
                                    "updated_at": _now()})
                    await asyncio.to_thread(self._put, host, current)
                    return current
        if current is not None and current.get("state") in {*LIVE_STATES, "stale"}:
            # Take the old route away first; never stack a second one on top of it.
            if not (await self._remove(host))["ok"]:
                return (await asyncio.to_thread(self.records)).get(host) or {"state": "stale"}
        # Conflicts: a service domain or a Dokploy app already answers on this host.
        if await asyncio.to_thread(self._service_host, host):
            record = {**base, "state": "conflict", "error_code": "domain_in_use",
                      "conflict": {"kind": "mrk"}}
            await asyncio.to_thread(self._put, host, record)
            return record
        owner, _check = await routing.dokploy_conflict(host)
        if owner is not None:
            record = {**base, "state": "conflict", "error_code": "domain_in_use",
                      "conflict": {"kind": "dokploy", "name": owner.get("name"),
                                   "project": owner.get("project")}}
            await asyncio.to_thread(self._put, host, record)
            return record
        detected = await routing.detect()
        mode = routing.effective_mode(detected)
        record = {**base, "mode": mode}
        if not routing.available_modes(detected).get(mode):
            record["error_code"] = (
                "traefik_dir_unavailable" if mode == "traefik_file" else "routing_unavailable")
            await asyncio.to_thread(self._put, host, record)
            return record
        if mode == "manual":
            record["state"] = "manual"
            await asyncio.to_thread(self._put, host, record)
            return record
        if mode == "dokploy_api":
            try:
                domain_id = await routing.dokploy_create(S3_SERVICE, host, https, detected)
            except Exception as exc:  # noqa: BLE001 - recorded, nothing was created
                record.update({"error_code": "dokploy_domain_failed",
                               "upstream_code": _code(exc)})
                await asyncio.to_thread(self._put, host, record)
                return record
            hint = routing.redeploy_hint(detected)
            record.update({"state": "pending" if hint else "ok", "dokploy_domain_id": domain_id,
                           "redeploy_required": hint is not None})
            try:
                await asyncio.to_thread(self._put, host, record)
            except Exception:
                # Roll back: never leave a Dokploy domain nobody knows about.
                if domain_id:
                    await _quiet(routing.dokploy_delete(domain_id))
                raise
            return record
        # traefik_file: the file is rebuilt from every route in place.
        record["state"] = "ok"
        await asyncio.to_thread(self._put, host, record)
        try:
            await self.service._apply_traefik(detected)  # noqa: SLF001 - shared writer
        except Exception as exc:  # noqa: BLE001 - roll back to the file without it
            record.update({"state": "failed", "error_code": "traefik_write_failed",
                           "upstream_code": _code(exc)})
            await asyncio.to_thread(self._put, host, record)
            await _quiet(self.service._apply_traefik(detected))  # noqa: SLF001
        return record

    async def _remove(self, host: str) -> dict[str, Any]:
        records = await asyncio.to_thread(self.records)
        record = records.get(host)
        if record is None:
            return {"removed": False, "ok": True}
        routing = self.service.routing
        if record.get("mode") == "dokploy_api" and record.get("dokploy_domain_id"):
            try:
                await routing.dokploy_delete(str(record["dokploy_domain_id"]))
            except Exception as exc:  # noqa: BLE001
                if getattr(exc, "code", None) != "dokploy_not_found":
                    record.update({"state": "stale", "error_code": "dokploy_domain_failed",
                                   "upstream_code": _code(exc), "updated_at": _now()})
                    await asyncio.to_thread(self._put, host, record)
                    return {"removed": False, "ok": False, "error_code": "dokploy_domain_failed"}
        await asyncio.to_thread(self._put, host, None)
        if record.get("mode") == "traefik_file" and record.get("state") in {"ok", "stale"}:
            try:
                await self.service._apply_traefik(await routing.detect())  # noqa: SLF001
            except Exception as exc:  # noqa: BLE001 - keep it so a retry rewrites the file
                record.update({"state": "stale", "error_code": "traefik_write_failed",
                               "upstream_code": _code(exc), "updated_at": _now()})
                await asyncio.to_thread(self._put, host, record)
                return {"removed": False, "ok": False, "error_code": "traefik_write_failed"}
        return {"removed": True, "ok": True}


def _code(exc: BaseException) -> str:
    return str(getattr(exc, "code", None) or type(exc).__name__)[:64]


async def _quiet(awaitable: Any) -> None:
    try:
        await awaitable
    except Exception:  # noqa: BLE001 - best effort clean-up
        LOGGER.warning("bucket route clean-up failed", exc_info=True)


def active() -> BucketRoutes | None:
    from . import services

    service = services.ACTIVE_SERVICE
    return service.bucket_routes if service is not None else None
