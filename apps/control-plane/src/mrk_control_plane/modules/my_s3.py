"""«My space» file space (docs/43 §3): buckets, files, keys and bucket domains.

Buckets live in the shared registry (``S3Store``) with an ownership row
(``s3_bucket``); the engine enforces the workspace byte/object quota on every write
(``quota_groups`` in the snapshot). Keys are an S3 identity + one access key whose
policy Pishkar builds from ``read_only|read_write|admin`` limited to the workspace's own
buckets (``s3_policy.workspace_policy``); a policy document is never accepted.
"""

from __future__ import annotations

import asyncio
import logging
import re
import secrets
import time
from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING, Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from sqlalchemy import select

from ..models import ServiceDomain
from ..tenancy import TenancyError, WorkspaceContext, names_overlap, not_found
from . import bucket_routes
from .bucket_routes import BucketRoutes
from .dns_validate import DnsInputError, canonical_zone
from .s3_client import EngineAdmin, EngineError
from .s3_policy import WORKSPACE_TEMPLATES
from .s3_store import S3Error, S3Store

if TYPE_CHECKING:
    from .tenancy import MySpace

LOGGER = logging.getLogger(__name__)
_KEY_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,39}$")


def register_routes(space: MySpace, router: APIRouter) -> None:
    store = space.store
    ctx = space.ctx

    def s3() -> S3Store:
        from . import s3 as s3_module

        if s3_module.ACTIVE_STORE is None:
            raise TenancyError("s3_not_installed", 503, "The file space is not available")
        return s3_module.ACTIVE_STORE

    def admin_api() -> EngineAdmin:
        return EngineAdmin(s3().admin_token_path)

    def s3_fail(exc: S3Error | EngineError) -> JSONResponse:
        return ctx.error_payload(exc.code, exc.message, exc.status_code)

    async def run(
        request: Request,
        work: Callable[..., Awaitable[Any]],
        *,
        scope: str,
        write: bool = False,
        bucket: str | None = None,
        identity: str | None = None,
        feature: str = "s3",
    ) -> Any:
        try:
            wctx = await space.context(request, write=write)
            owner = None
            if bucket is not None:
                owner = await asyncio.to_thread(store.require_owned, wctx, "s3_bucket", bucket)
            if identity is not None:
                owner = await asyncio.to_thread(store.require_owned, wctx, "s3_identity",
                                                identity)
            wctx.need(scope, feature=feature)
            body = await space.body(request) if write else None
            return await work(wctx, body, owner)
        except TenancyError as exc:
            return space.fail(exc)
        except (S3Error, EngineError) as exc:
            return s3_fail(exc)

    def object_body(body: Any, allowed: set[str]) -> dict[str, Any]:
        if not isinstance(body, dict):
            raise TenancyError("invalid_request", 422, "The request must be an object")
        unknown = sorted(set(body) - allowed)
        if unknown:
            raise TenancyError("invalid_request", 422, "Unknown fields", fields=[
                {"field": key, "reason_code": "unknown_field"} for key in unknown[:10]])
        return body

    async def owned_buckets(workspace_id: str) -> list[str]:
        return [item["resource_id"] for item in await asyncio.to_thread(
            store.owned, "s3_bucket", workspace_id)]

    async def stats_for(names: list[str]) -> dict[str, dict[str, int] | None]:
        api = admin_api()
        if not names or not await api.health():
            return dict.fromkeys(names)
        results = await asyncio.gather(*(api.bucket_stats(name) for name in names))
        return dict(zip(names, results, strict=True))

    # ---------------------------------------------------------------- buckets
    @router.get("/s3/buckets", response_model=None)
    async def list_buckets(request: Request) -> Any:
        async def work(wctx: WorkspaceContext, _body: Any, _owner: Any) -> Any:
            names = await owned_buckets(wctx.workspace_id)
            stats = await stats_for(names)
            items = []
            for name in names:
                try:
                    item = await asyncio.to_thread(s3().get_bucket, name)
                except S3Error:
                    continue
                stat = stats.get(name)
                items.append({"name": name, "public_read": item["public_read"],
                              "created_at": item["created_at"],
                              "objects": stat["objects"] if stat else None,
                              "bytes": stat["bytes"] if stat else None})
            return {"items": items, "suggested_prefix": f"{wctx.slug}-"}

        return await run(request, work, scope="my.s3:read")

    @router.post("/s3/buckets", status_code=201, response_model=None)
    async def create_bucket(request: Request) -> Any:
        async def work(wctx: WorkspaceContext, body: Any, _owner: Any) -> Any:
            body = object_body(body, {"name", "public_read"})
            public = body.get("public_read", False)
            if public is True:
                wctx.feature("s3_public_links")
            name = body.get("name")
            if not isinstance(name, str):
                raise S3Error("invalid_bucket_name", 422, "name is required")
            async with store.alock(wctx.workspace_id):
                await asyncio.to_thread(store.claim, wctx, "s3_bucket", name,
                                        quota="s3_buckets")
                try:
                    item = await asyncio.to_thread(
                        s3().create_bucket, {"name": name, "public_read": public},
                        wctx.user_id, is_owner=False)
                except BaseException:
                    await asyncio.to_thread(store.release, "s3_bucket", name)
                    raise
            synced = await admin_api().ensure_bucket(name)
            await space.audit(wctx, "my.s3.bucket.create", "s3_bucket", name)
            return JSONResponse(status_code=201, content={
                "name": name, "public_read": item["public_read"],
                "created_at": item["created_at"], "objects": 0, "bytes": 0,
                "engine_synced": synced})

        return await run(request, work, scope="my.s3:write", write=True)

    @router.get("/s3/buckets/{name}", response_model=None)
    async def get_bucket(name: str, request: Request) -> Any:
        async def work(_wctx: WorkspaceContext, _body: Any, _owner: Any) -> Any:
            item = await asyncio.to_thread(s3().get_bucket, name)
            stat = (await stats_for([name]))[name]
            return {"name": name, "public_read": item["public_read"],
                    "created_at": item["created_at"],
                    "objects": stat["objects"] if stat else None,
                    "bytes": stat["bytes"] if stat else None}

        return await run(request, work, scope="my.s3:read", bucket=name)

    @router.patch("/s3/buckets/{name}", response_model=None)
    async def patch_bucket(name: str, request: Request) -> Any:
        async def work(wctx: WorkspaceContext, body: Any, _owner: Any) -> Any:
            body = object_body(body, {"public_read"})
            if body.get("public_read") is True:
                wctx.feature("s3_public_links")
            item = await asyncio.to_thread(s3().update_bucket, name, body, is_owner=False)
            await space.audit(wctx, "my.s3.bucket.update", "s3_bucket", name)
            return {"name": name, "public_read": item["public_read"],
                    "created_at": item["created_at"]}

        return await run(request, work, scope="my.s3:write", write=True, bucket=name)

    async def drop_bucket(name: str, *, force: bool) -> None:
        api = admin_api()
        if not force:
            stats = await api.bucket_stats(name)
            if stats is None and not await api.health():
                raise S3Error("engine_unreachable", 503,
                              "the S3 engine is not reachable; cannot check the bucket is empty")
            if stats is not None and stats["objects"] > 0:
                raise S3Error("bucket_not_empty", 409,
                              f"bucket holds {stats['objects']} object(s); delete with force")
        await api.delete_bucket(name, force=force)
        await asyncio.to_thread(s3().delete_bucket_record, name)
        await asyncio.to_thread(store.release, "s3_bucket", name)
        for item in await asyncio.to_thread(store.all_owned, ("bucket_domain",)):
            if item["meta"].get("bucket") == name:
                await asyncio.to_thread(store.release, "bucket_domain", item["resource_id"])
                await unroute(item["resource_id"])

    @router.delete("/s3/buckets/{name}", response_model=None)
    async def delete_bucket(name: str, request: Request) -> Any:
        async def work(wctx: WorkspaceContext, body: Any, _owner: Any) -> Any:
            body = object_body(body, {"confirmation", "force"})
            force = body.get("force", False)
            if not isinstance(force, bool):
                raise S3Error("invalid_request", 422, "force must be true or false")
            if body.get("confirmation") != name:
                raise S3Error("confirmation_mismatch", 422,
                              "confirmation must equal the bucket name")
            await drop_bucket(name, force=force)
            await asyncio.to_thread(s3().write_snapshot)
            await space.audit(wctx, "my.s3.bucket.delete", "s3_bucket", name)
            return {"deleted": True, "name": name}

        return await run(request, work, scope="my.s3:write", write=True, bucket=name)

    # ---------------------------------------------------------------- files
    files = APIRouter(prefix="/s3")

    async def authorize(request: Request, scope: str, write: bool) -> WorkspaceContext:
        wctx = await space.context(request, write=write)
        await asyncio.to_thread(store.require_owned, wctx, "s3_bucket",
                                str(request.path_params.get("name", "")))
        wctx.need(scope, feature="s3")
        return wctx

    async def file_reader(request: Request, _permission: str) -> WorkspaceContext:
        return await authorize(request, "my.s3:read", False)

    async def file_writer(request: Request, _permission: str) -> WorkspaceContext:
        return await authorize(request, "my.s3:write", True)

    async def file_audit(wctx: WorkspaceContext, action: str, object_type: str,
                         object_id: str | None, result: str = "success") -> None:
        await space.audit(wctx, f"my.{action}", object_type, object_id, result)

    from .s3 import add_file_routes

    class _Store:
        """``add_file_routes`` needs the store at request time (module may load later)."""

        def __getattr__(self, item: str) -> Any:
            return getattr(s3(), item)

    add_file_routes(files, ctx, _Store(), reader=file_reader,  # type: ignore[arg-type]
                    writer=file_writer, audit=file_audit)
    router.include_router(files)

    # ---------------------------------------------------------------- keys
    def key_view(identity: dict[str, Any], owner: dict[str, Any]) -> dict[str, Any]:
        keys = identity.get("keys") or []
        return {"id": identity["id"], "name": owner["meta"].get("label", identity["name"]),
                "access": identity["policy_template"], "buckets": identity["buckets"],
                "enabled": identity["enabled"],
                "access_key_id": keys[0]["access_key_id"] if keys else None,
                "created_at": identity["created_at"]}

    async def identity_of(identity_id: str) -> dict[str, Any]:
        for item in await asyncio.to_thread(s3().list_identities):
            if item["id"] == identity_id:
                return item
        raise not_found()

    async def checked_buckets(wctx: WorkspaceContext, raw: Any) -> list[str]:
        if not isinstance(raw, list) or not raw or not all(isinstance(i, str) for i in raw):
            raise TenancyError("invalid_request", 422, "Choose at least one bucket",
                               fields=[{"field": "buckets", "reason_code": "required"}])
        mine = set(await owned_buckets(wctx.workspace_id))
        if any(item not in mine for item in raw):
            raise not_found()
        return sorted(set(raw))

    def checked_access(value: Any) -> str:
        if value not in WORKSPACE_TEMPLATES:
            raise TenancyError("invalid_request", 422, "Choose an access level", fields=[
                {"field": "access", "reason_code": "invalid_choice",
                 "params": {"choices": list(WORKSPACE_TEMPLATES)}}])
        return str(value)

    @router.get("/s3/keys", response_model=None)
    async def list_keys(request: Request) -> Any:
        async def work(wctx: WorkspaceContext, _body: Any, _owner: Any) -> Any:
            owners = {item["resource_id"]: item for item in await asyncio.to_thread(
                store.owned, "s3_identity", wctx.workspace_id)}
            identities = await asyncio.to_thread(s3().list_identities)
            return {"items": [key_view(item, owners[item["id"]]) for item in identities
                              if item["id"] in owners]}

        return await run(request, work, scope="my.s3:read")

    @router.post("/s3/keys", status_code=201, response_model=None)
    async def create_key(request: Request) -> Any:
        async def work(wctx: WorkspaceContext, body: Any, _owner: Any) -> Any:
            body = object_body(body, {"name", "access", "buckets"})
            label = body.get("name")
            if not isinstance(label, str) or not _KEY_NAME.fullmatch(label):
                raise TenancyError("invalid_request", 422,
                                   "Use 1-40 letters, digits, dot, dash or underscore",
                                   fields=[{"field": "name", "reason_code": "invalid_format"}])
            access = checked_access(body.get("access"))
            buckets = await checked_buckets(wctx, body.get("buckets"))
            identity_name = f"{wctx.slug}.{label}-{secrets.token_hex(2)}"
            created: dict[str, Any] | None = None
            reservation = f"pending-{secrets.token_hex(8)}"
            async with store.alock(wctx.workspace_id):
                await asyncio.to_thread(store.claim, wctx, "s3_identity", reservation,
                                        quota="s3_keys", meta={"label": label})
                try:
                    created = await asyncio.to_thread(s3().create_identity, {
                        "name": identity_name, "policy_template": "read_only",
                        "buckets": buckets, "enabled": False}, wctx.user_id)
                    await asyncio.to_thread(store.transfer_reservation, "s3_identity",
                                            reservation, created["id"])
                    identity = await asyncio.to_thread(s3().set_workspace_policy,
                                                       created["id"], access, buckets)
                    await asyncio.to_thread(s3().update_identity, created["id"],
                                            {"enabled": True})
                    secret = await asyncio.to_thread(s3().create_key, created["id"])
                except BaseException:
                    await asyncio.to_thread(store.release, "s3_identity", reservation)
                    if created is not None:
                        await asyncio.to_thread(store.release, "s3_identity", created["id"])
                        await asyncio.to_thread(s3().delete_identity, created["id"],
                                                identity_name)
                    raise
            await space.audit(wctx, "my.s3.key.create", "s3_identity", created["id"])
            return JSONResponse(status_code=201, content={
                "id": created["id"], "name": label, "access": access,
                "buckets": identity["buckets"], "enabled": True,
                "access_key_id": secret["access_key_id"],
                "secret_access_key": secret["secret_access_key"],
                "created_at": identity["created_at"]})

        return await run(request, work, scope="my.s3:write", write=True)

    @router.patch("/s3/keys/{identity_id}", response_model=None)
    async def patch_key(identity_id: str, request: Request) -> Any:
        async def work(wctx: WorkspaceContext, body: Any, owner: Any) -> Any:
            body = object_body(body, {"enabled", "access", "buckets"})
            identity = await identity_of(identity_id)
            if "access" in body or "buckets" in body:
                access = checked_access(body.get("access", identity["policy_template"]))
                buckets = await checked_buckets(wctx, body.get("buckets", identity["buckets"]))
                identity = await asyncio.to_thread(s3().set_workspace_policy, identity_id,
                                                   access, buckets)
            if "enabled" in body:
                if not isinstance(body["enabled"], bool):
                    raise TenancyError("invalid_request", 422, "enabled must be true or false")
                identity = await asyncio.to_thread(s3().update_identity, identity_id,
                                                   {"enabled": body["enabled"]})
            await space.audit(wctx, "my.s3.key.update", "s3_identity", identity_id)
            return key_view(identity, owner)

        return await run(request, work, scope="my.s3:write", write=True, identity=identity_id)

    @router.delete("/s3/keys/{identity_id}", response_model=None)
    async def delete_key(identity_id: str, request: Request) -> Any:
        async def work(wctx: WorkspaceContext, _body: Any, _owner: Any) -> Any:
            identity = await identity_of(identity_id)
            await asyncio.to_thread(s3().delete_identity, identity_id, identity["name"])
            await asyncio.to_thread(store.release, "s3_identity", identity_id)
            await space.audit(wctx, "my.s3.key.delete", "s3_identity", identity_id)
            return {"deleted": identity_id}

        return await run(request, work, scope="my.s3:write", write=True, identity=identity_id)

    # ---------------------------------------------------------------- bucket domains
    def system_names() -> list[str]:
        from . import dns as dns_module

        names = [dns_module.INTERNAL_ZONE]
        with ctx.database.session() as db:
            names.extend(db.scalars(select(ServiceDomain.host)))
        suffix = s3().get_settings().get("virtual_host_suffix")
        if suffix:
            names.append(str(suffix))
        return names

    def domain_view(item: dict[str, Any],
                    routes: dict[str, dict[str, Any]] | None = None) -> dict[str, Any]:
        meta = item["meta"]
        from .my_dns import VERIFY_LABEL, VERIFY_PREFIX

        verified = bool(meta.get("verified"))
        record = (routes or {}).get(item["resource_id"])
        return {"host": item["resource_id"], "verified": verified,
                "verification": {"name": f"{VERIFY_LABEL}.{item['resource_id']}",
                                 "value": f"{VERIFY_PREFIX}{meta.get('verify_token', '')}"},
                "route": BucketRoutes.public_view(record, verified)}

    async def route_records() -> dict[str, dict[str, Any]]:
        routes = bucket_routes.active()
        return await asyncio.to_thread(routes.records) if routes is not None else {}

    async def route(host: str, *, retry: bool = False) -> None:
        """Route a verified domain; a routing problem never undoes the domain itself."""
        routes = bucket_routes.active()
        if routes is None:
            return
        try:
            await routes.ensure(host, retry=retry)
        except Exception:  # noqa: BLE001 - state stays for the admin page / next tick
            LOGGER.exception("routing bucket domain %s failed", host)

    async def unroute(host: str) -> None:
        routes = bucket_routes.active()
        if routes is None:
            return
        try:
            await routes.remove(host)
        except Exception:  # noqa: BLE001 - reconcile removes it on the next tick
            LOGGER.exception("removing the route of %s failed", host)
            routes.reconcile_soon()

    async def dokploy_owner(host: str) -> bool:
        from . import services as services_module

        service = services_module.ACTIVE_SERVICE
        if service is None:
            return False
        owner, _check = await service.routing.dokploy_conflict(host)
        return owner is not None

    async def domain_of(wctx: WorkspaceContext, bucket: str, host: str) -> dict[str, Any]:
        item = await asyncio.to_thread(store.require_owned, wctx, "bucket_domain",
                                       host.strip().lower().rstrip("."))
        if item["meta"].get("bucket") != bucket:
            raise not_found()
        return item

    @router.get("/s3/buckets/{name}/domains", response_model=None)
    async def list_domains(name: str, request: Request) -> Any:
        async def work(wctx: WorkspaceContext, _body: Any, _owner: Any) -> Any:
            items = await asyncio.to_thread(store.owned, "bucket_domain", wctx.workspace_id)
            routes = await route_records()
            return {"items": [domain_view(item, routes) for item in items
                              if item["meta"].get("bucket") == name]}

        return await run(request, work, scope="my.s3:read", bucket=name)

    @router.post("/s3/buckets/{name}/domains", status_code=201, response_model=None)
    async def add_domain(name: str, request: Request) -> Any:
        async def work(wctx: WorkspaceContext, body: Any, _owner: Any) -> Any:
            body = object_body(body, {"host"})
            try:
                host = canonical_zone(body.get("host"), "host")
            except DnsInputError as exc:
                raise TenancyError(exc.code, 422, exc.message, fields=exc.fields) from None
            unavailable = TenancyError("domain_unavailable", 409,
                                       "This domain cannot be used here",
                                       fields=[{"field": "host", "reason_code": "unavailable"}])
            if "." not in host:
                raise unavailable
            zones = await asyncio.to_thread(store.owned, "dns_zone", wctx.workspace_id)
            others = [item["resource_id"] for item in await asyncio.to_thread(
                store.all_owned, ("dns_zone", "bucket_domain"))
                if item["workspace_id"] != wctx.workspace_id]
            for other in [*others, *await asyncio.to_thread(system_names)]:
                if other and names_overlap(host, other):
                    raise unavailable
            # A Dokploy app already answers on this host (skipped when Dokploy is down).
            if await dokploy_owner(host):
                raise unavailable
            # Inside a verified zone of this workspace = already proven.
            verified = any(
                (host == zone["resource_id"] or host.endswith("." + zone["resource_id"]))
                and zone["meta"].get("status", "active") == "active" for zone in zones)
            meta = {"bucket": name, "verified": verified, "verify_token": secrets.token_hex(16)}
            await asyncio.to_thread(store.claim, wctx, "bucket_domain", host,
                                    quota="s3_bucket_domains", meta=meta)
            await asyncio.to_thread(s3().write_snapshot)
            await space.audit(wctx, "my.s3.domain.add", "bucket_domain", f"{host}->{name}")
            if verified:
                await route(host)
            item = await asyncio.to_thread(store.require_owned, wctx, "bucket_domain", host)
            return JSONResponse(status_code=201,
                                content=domain_view(item, await route_records()))

        return await run(request, work, scope="my.s3:write", write=True, bucket=name,
                         feature="s3_bucket_domains")

    @router.post("/s3/buckets/{name}/domains/{host}/verify", response_model=None)
    async def verify_domain(name: str, host: str, request: Request) -> Any:
        async def work(wctx: WorkspaceContext, _body: Any, _owner: Any) -> Any:
            from .my_dns import txt_verified

            item = await domain_of(wctx, name, host)
            host_id = item["resource_id"]
            if not item["meta"].get("verified"):
                if not await asyncio.to_thread(txt_verified, host_id,
                                               item["meta"].get("verify_token", "")):
                    return {"verified": False, "route": BucketRoutes.public_view(None, False)}
                await asyncio.to_thread(store.set_meta, "bucket_domain", host_id,
                                        {"verified": True, "verified_at": int(time.time())})
                await asyncio.to_thread(s3().write_snapshot)
                await space.audit(wctx, "my.s3.domain.verify", "bucket_domain", host_id)
            await route(host_id)
            return {"verified": True,
                    "route": BucketRoutes.public_view((await route_records()).get(host_id),
                                                      True)}

        return await run(request, work, scope="my.s3:write", write=True, bucket=name,
                         feature="s3_bucket_domains")

    @router.delete("/s3/buckets/{name}/domains/{host}", response_model=None)
    async def delete_domain(name: str, host: str, request: Request) -> Any:
        async def work(wctx: WorkspaceContext, _body: Any, _owner: Any) -> Any:
            item = await domain_of(wctx, name, host)
            await asyncio.to_thread(store.release, "bucket_domain", item["resource_id"])
            await asyncio.to_thread(s3().write_snapshot)
            await unroute(item["resource_id"])
            await space.audit(wctx, "my.s3.domain.delete", "bucket_domain", item["resource_id"])
            return {"deleted": item["resource_id"]}

        return await run(request, work, scope="my.s3:write", write=True, bucket=name)

    @router.post("/s3/buckets/{name}/domains/{host}/route", response_model=None)
    async def retry_route(name: str, host: str, request: Request) -> Any:
        async def work(wctx: WorkspaceContext, _body: Any, _owner: Any) -> Any:
            item = await domain_of(wctx, name, host)
            if not item["meta"].get("verified"):
                raise TenancyError("domain_not_verified", 409, "Verify the domain first")
            await route(item["resource_id"], retry=True)
            await space.audit(wctx, "my.s3.domain.route", "bucket_domain", item["resource_id"])
            return {"host": item["resource_id"], "route": BucketRoutes.public_view(
                (await route_records()).get(item["resource_id"]), True)}

        return await run(request, work, scope="my.s3:write", write=True, bucket=name,
                         feature="s3_bucket_domains")

    # ---------------------------------------------------------------- usage / cleanup
    async def usage(workspace_id: str) -> dict[str, Any]:
        names = await owned_buckets(workspace_id)
        if not names:
            return {"s3_bytes": 0, "s3_objects": 0}
        stats = await stats_for(names)
        if any(value is None for value in stats.values()):
            return {"s3_bytes": None, "s3_objects": None}
        return {"s3_bytes": sum(value["bytes"] for value in stats.values() if value),
                "s3_objects": sum(value["objects"] for value in stats.values() if value)}

    async def cleanup_bucket(item: dict[str, Any]) -> None:
        name = item["resource_id"]
        try:
            await admin_api().delete_bucket(name, force=True)
        except EngineError:
            pass
        try:
            await asyncio.to_thread(s3().delete_bucket_record, name)
        except S3Error:
            pass

    async def cleanup_identity(item: dict[str, Any]) -> None:
        try:
            identity = await identity_of(item["resource_id"])
        except TenancyError:
            return
        await asyncio.to_thread(s3().delete_identity, identity["id"], identity["name"])

    async def snapshot() -> None:
        from . import s3 as s3_module

        if s3_module.ACTIVE_STORE is not None:
            await asyncio.to_thread(s3_module.ACTIVE_STORE.write_snapshot)

    space.usage_providers.append(usage)
    space.cleanup["s3_bucket"] = cleanup_bucket
    space.cleanup["s3_identity"] = cleanup_identity

    async def cleanup_domain(item: dict[str, Any]) -> None:
        await unroute(item["resource_id"])

    space.cleanup["bucket_domain"] = cleanup_domain

    async def reroute() -> None:
        # Ownership moved or a workspace went away: drop routes nobody owns any more.
        routes = bucket_routes.active()
        if routes is not None:
            routes.reconcile_soon()

    space.after_quota_change.append(reroute)
    space.after_quota_change.append(snapshot)
