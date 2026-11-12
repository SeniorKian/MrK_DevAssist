"""S3 object storage module, control-plane side (Gate 18, docs/31 §3).

Manages the bucket registry, S3 identities/keys and settings, renders the engine snapshot
(``/data/modules/s3/config.json``) and proxies the panel file manager to ``s3-engine`` with
SigV4-signed calls as the hidden ``__mrk_panel__`` identity. Bytes are streamed both ways.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import math
import re
import time
from collections.abc import AsyncIterator, Awaitable, Callable
from typing import Any
from urllib.parse import quote, urlsplit

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, StreamingResponse
from sqlalchemy import select
from starlette.requests import ClientDisconnect

from ..auth import Principal
from ..models import SystemSetting
from ..module_context import ModuleContext
from . import bucket_routes as bucket_routes_module
from .dokploy_client import DokployError
from .domains_hosts import HostError, canonical_host
from .s3_client import (
    UNSIGNED_PAYLOAD,
    EngineAdmin,
    EngineError,
    EngineS3,
    engine_url,
)
from .s3_policy import object_key_error
from .s3_snippets import COMPOSE_HINT, connection_snippets
from .s3_store import S3Error, S3Store, links_root

LOGGER = logging.getLogger(__name__)
MODULE_NAME = "s3"
MiB = 1024 * 1024
MULTIPART_THRESHOLD = 64 * MiB
PART_SIZE = 16 * MiB
MAX_PARTS = 10000
MAX_SHARE_SECONDS = 7 * 86400
MAX_DELETE_KEYS = 1000
MAX_MOVE_OBJECTS = 10000
FALLBACK_ENDPOINT = "http://127.0.0.1:9000"
_STATS_CONCURRENCY = 8
S3_DOKPLOY_TARGET_KEY = "s3.dokploy_target"
# Sources that identify the S3 Compose for certain; anything else is a suggestion.
# "located": the Compose domain routing found through Dokploy (it defines mrk-s3).
DEPLOYABLE_TARGET_SOURCES = frozenset({"saved", "installer", "container", "located"})
_S3_NAME = re.compile(r"(?<![a-z0-9])s3(?![a-z0-9])")

ACTIVE_STORE: S3Store | None = None


class _BodyReader:
    """Pull-based reader over the request stream so parts can be streamed exactly."""

    def __init__(self, stream: AsyncIterator[bytes]) -> None:
        self._iterator = stream.__aiter__()
        self._buffer = b""
        self.eof = False
        self.consumed = 0

    async def _next(self) -> bytes:
        if self.eof:
            return b""
        try:
            chunk = await self._iterator.__anext__()
        except StopAsyncIteration:
            self.eof = True
            return b""
        return chunk

    async def read_up_to(self, size: int) -> bytes:
        pieces = [self._buffer]
        have = len(self._buffer)
        self._buffer = b""
        while have < size and not self.eof:
            chunk = await self._next()
            if chunk:
                pieces.append(chunk)
                have += len(chunk)
        data = b"".join(pieces)
        self._buffer = data[size:]
        result = data[:size]
        self.consumed += len(result)
        return result

    async def exactly(self, size: int) -> AsyncIterator[bytes]:
        remaining = size
        while remaining > 0:
            if self._buffer:
                chunk, self._buffer = self._buffer, b""
            else:
                chunk = await self._next()
                if not chunk:
                    if self.eof:
                        raise S3Error(
                            "incomplete_upload", 400, "the upload ended before Content-Length"
                        )
                    continue
            if len(chunk) > remaining:
                self._buffer = chunk[remaining:]
                chunk = chunk[:remaining]
            remaining -= len(chunk)
            self.consumed += len(chunk)
            yield chunk


def _content_disposition(key: str) -> str:
    filename = key.rstrip("/").rsplit("/", 1)[-1] or "download"
    fallback = "".join(
        char if 32 <= ord(char) < 127 and char not in '"\\;' else "_" for char in filename
    )
    return f"attachment; filename=\"{fallback}\"; filename*=UTF-8''{quote(filename, safe='')}"


async def _body(request: Request) -> Any:
    raw = await request.body()
    if not raw:
        return {}
    try:
        return json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        raise S3Error("invalid_json", 400, "request body must be JSON") from None


def _check_key(key: object, *, folder: bool = False) -> str:
    problem = object_key_error(key, folder=folder)
    if problem:
        raise S3Error("invalid_key", 422, problem)
    assert isinstance(key, str)
    return key


def build_router(ctx: ModuleContext, store: S3Store) -> APIRouter:
    router = APIRouter(prefix="/api/v1/s3", include_in_schema=False)
    admin_api = EngineAdmin(store.admin_token_path)

    def fail(exc: S3Error | EngineError) -> JSONResponse:
        extra = exc.payload_extra() if isinstance(exc, S3Error) else {}
        return ctx.error_payload(exc.code, exc.message, exc.status_code, **extra)  # type: ignore[call-arg]

    async def audit(
        principal: Principal,
        action: str,
        object_type: str,
        object_id: str | None,
        result: str = "success",
    ) -> None:
        await asyncio.to_thread(
            ctx.audit, principal.user_id, action, object_type, object_id, result
        )

    def reader_sync(request: Request, permission: str) -> Principal:
        return ctx.require_principal(request, permission)

    def writer_sync(request: Request, permission: str) -> Principal:
        principal = ctx.require_principal(request, permission)
        ctx.require_csrf(request, principal)
        return principal

    async def reader(request: Request, permission: str) -> Principal:
        return reader_sync(request, permission)

    async def writer(request: Request, permission: str) -> Principal:
        return writer_sync(request, permission)

    async def engine() -> tuple[EngineS3, dict[str, Any]]:
        def load() -> tuple[tuple[str, str], dict[str, Any]]:
            return store.panel_credentials(), store.get_settings()

        (akid, secret), settings = await asyncio.to_thread(load)
        return EngineS3(access_key=akid, secret=secret, region=settings["region"]), settings

    async def existing_bucket(name: str, *, write: bool = False) -> dict[str, Any]:
        bucket = await asyncio.to_thread(store.get_bucket, name)
        if write and bucket["mode"] == "linked" and bucket["link_mode"] == "ro":
            raise S3Error("bucket_read_only", 409, "bucket is a read-only linked folder")
        return bucket

    def bucket_routes() -> bucket_routes_module.BucketRoutes:
        routes = bucket_routes_module.active()
        if routes is None:
            raise S3Error("routing_unavailable", 503, "domain routing is not available")
        return routes

    async def admin_domain_items(name: str) -> list[dict[str, Any]]:
        listed = await bucket_routes().admin_list()
        return [
            item for item in listed["items"]
            if item.get("source") == "admin" and item.get("bucket") == name
        ]

    def stored_dokploy_target() -> str | None:
        with ctx.database.session() as db:
            row = db.get(SystemSetting, S3_DOKPLOY_TARGET_KEY)
            value = row.value if row is not None and isinstance(row.value, dict) else {}
            compose_id = value.get("compose_id")
            return compose_id if isinstance(compose_id, str) else None

    def save_dokploy_target(compose_id: str) -> None:
        now = int(time.time())
        with ctx.database.session() as db, db.begin():
            row = db.get(SystemSetting, S3_DOKPLOY_TARGET_KEY)
            value = {"compose_id": compose_id}
            if row is None:
                db.add(SystemSetting(key=S3_DOKPLOY_TARGET_KEY, value=value, updated_at=now))
            else:
                row.value = value
                row.updated_at = now

    def active_dokploy() -> Any:
        from . import dokploy as dokploy_module

        if dokploy_module.ACTIVE_SERVICE is None:
            raise S3Error("dokploy_not_configured", 409, "Dokploy is not connected")
        return dokploy_module.ACTIVE_SERVICE

    async def s3_dokploy_state() -> dict[str, Any]:
        service = active_dokploy()
        projects = await service.projects()
        candidates = [
            {
                "compose_id": item["id"],
                "name": item.get("name") or item["id"],
                "project": project.get("name") or project["id"],
                "environment": item.get("environment"),
                "status": item.get("status"),
                "domains": item.get("domains") or [],
            }
            for project in projects.get("items", [])
            for item in project.get("services", [])
            if item.get("type") == "compose" and isinstance(item.get("id"), str)
        ]
        by_id = {item["compose_id"]: item for item in candidates}

        selected_id = await asyncio.to_thread(stored_dokploy_target)
        source = "saved"
        if selected_id not in by_id:
            selected_id = None

        if selected_id is None:
            from .install_auto import deployment_for

            deployment = await asyncio.to_thread(deployment_for, ctx.data_dir, "s3")
            candidate = (deployment or {}).get("compose_id")
            if isinstance(candidate, str) and candidate in by_id:
                selected_id, source = candidate, "installer"

        # A manually-created Dokploy Compose can still be found safely: the Host Agent
        # sees mrk-s3's compose project label, which Dokploy maps back to a compose id.
        if selected_id is None:
            routes = bucket_routes_module.active()
            agent = routes.service.routing.agent() if routes is not None else None
            if agent is not None:
                try:
                    payload, index = await asyncio.gather(
                        agent.call("/v1/docker/containers"), service.app_index()
                    )
                    for item in payload.get("items", []):
                        labels = item.get("labels_subset") or {}
                        container_name = str(item.get("name") or "").lower()
                        compose_service = str(labels.get("com.docker.compose.service") or "")
                        if compose_service != "mrk-s3" and "mrk-s3" not in container_name:
                            continue
                        app_name = labels.get("com.docker.compose.project") or labels.get(
                            "com.docker.swarm.service.name"
                        )
                        ref = index.get(app_name) if isinstance(app_name, str) else None
                        if ref and ref.get("type") == "compose" and ref.get("id") in by_id:
                            selected_id, source = str(ref["id"]), "container"
                            break
                except Exception:  # noqa: BLE001 - candidates below remain usable
                    LOGGER.info("S3 Dokploy container detection skipped", exc_info=True)

        # The same resolver domain routing uses (dokploy_locate.find_compose: a Compose
        # that defines mrk-s3), so bucket domains and redeploys point at one Compose.
        if selected_id is None:
            routes = bucket_routes_module.active()
            if routes is not None:
                try:
                    located = await routes.service.routing.stack_compose("s3")
                except Exception:  # noqa: BLE001 - the weaker hints below remain
                    LOGGER.info("S3 Compose lookup skipped", exc_info=True)
                    located = None
                if located in by_id:
                    selected_id, source = str(located), "located"

        # Weaker hints, never used to deploy on their own: the Compose owns the configured
        # public S3 hostname, or exactly one Compose is named like S3. The admin saves
        # such a suggestion first; only then is it a redeploy target.
        suggestion: dict[str, Any] | None = None
        if selected_id is None:
            settings = await asyncio.to_thread(store.get_settings)
            public = str(settings.get("public_endpoint") or "")
            public_host = urlsplit(public).hostname if public else None
            domain_matches = [
                item for item in candidates
                if public_host and any(
                    str(domain).split("/", 1)[0].lower().rstrip(".") == public_host
                    for domain in item["domains"])
            ]
            name_matches = [
                item for item in candidates if _S3_NAME.search(str(item["name"]).lower())
            ]
            matches = domain_matches or name_matches
            if len(matches) == 1:
                suggestion = {**matches[0], "source": "domain" if domain_matches else "name"}

        return {
            "target": ({**by_id[selected_id], "source": source} if selected_id else None),
            "suggestion": suggestion,
            "candidates": candidates,
            "partial": bool(projects.get("partial")),
        }

    def public_endpoint(settings: dict[str, Any]) -> tuple[str, bool]:
        configured = settings.get("public_endpoint")
        if configured:
            return str(configured), False
        return FALLBACK_ENDPOINT, True

    async def with_stats(items: list[dict[str, Any]], reachable: bool) -> list[dict[str, Any]]:
        semaphore = asyncio.Semaphore(_STATS_CONCURRENCY)

        async def one(item: dict[str, Any]) -> dict[str, Any]:
            stats = None
            if reachable:
                async with semaphore:
                    stats = await admin_api.bucket_stats(item["name"])
            return {
                **item,
                "objects": None if stats is None else stats["objects"],
                "bytes": None if stats is None else stats["bytes"],
            }

        return list(await asyncio.gather(*(one(item) for item in items)))

    # ------------------------------------------------------------ settings / status

    @router.get("/settings")
    async def get_settings(request: Request) -> dict[str, Any]:
        reader_sync(request, "s3:read")
        return await asyncio.to_thread(store.get_settings)

    @router.put("/settings", response_model=None)
    async def put_settings(request: Request) -> dict[str, Any] | JSONResponse:
        principal = writer_sync(request, "s3:admin")
        try:
            value = await asyncio.to_thread(
                store.put_settings, await _body(request), principal.user_id
            )
        except S3Error as exc:
            await audit(principal, "s3.settings.update", "s3_settings", "s3", "failure")
            return fail(exc)
        await audit(principal, "s3.settings.update", "s3_settings", "s3")
        return value

    @router.get("/status")
    async def status(request: Request) -> dict[str, Any]:
        reader_sync(request, "s3:read")
        settings = await asyncio.to_thread(store.get_settings)
        buckets = await asyncio.to_thread(store.list_buckets)
        reachable = await admin_api.health()
        objects = size = None
        if reachable:
            items = await with_stats(buckets, True)
            known = [item for item in items if item["objects"] is not None]
            objects = sum(item["objects"] for item in known)
            size = sum(item["bytes"] for item in known)
        endpoint, fallback = public_endpoint(settings)
        return {
            "engine_reachable": reachable,
            "enabled": settings["enabled"],
            "buckets": len(buckets),
            "objects": objects,
            "bytes": size,
            "endpoint": endpoint,
            "endpoint_is_fallback": fallback,
        }

    # ------------------------------------------------------------ Dokploy deployment

    @router.get("/dokploy", response_model=None)
    async def get_s3_dokploy(request: Request) -> Any:
        reader_sync(request, "s3:admin")
        reader_sync(request, "dokploy:read")
        try:
            return await s3_dokploy_state()
        except (S3Error, DokployError) as exc:
            return ctx.error_payload(exc.code, exc.message, exc.status_code)

    def dokploy_object(compose_id: str | None) -> str:
        # Same object convention as the Dokploy module's own service actions.
        return f"compose:{compose_id}"[:255] if compose_id else "compose"

    @router.put("/dokploy", response_model=None)
    async def put_s3_dokploy(request: Request) -> Any:
        principal = writer_sync(request, "s3:admin")
        ctx.require_principal(request, "dokploy:deploy")
        compose_id: str | None = None
        try:
            body = await _body(request)
            if not isinstance(body, dict) or set(body) != {"compose_id"}:
                raise S3Error("invalid_request", 422, "body must contain only compose_id")
            raw_id = body.get("compose_id")
            if not isinstance(raw_id, str):
                raise S3Error("invalid_request", 422, "compose_id must be text")
            compose_id = raw_id
            detail = await active_dokploy().service("compose", compose_id)
            await asyncio.to_thread(save_dokploy_target, compose_id)
            routes = bucket_routes_module.active()
            if routes is not None:
                # Domain routing reads the saved Compose first: forget older lookups.
                routes.service.routing.invalidate()
        except (S3Error, DokployError) as exc:
            if exc.status_code != 422:
                await audit(principal, "s3.dokploy_target.update", "dokploy",
                            dokploy_object(compose_id), "failure")
            return ctx.error_payload(exc.code, exc.message, exc.status_code)
        await audit(principal, "s3.dokploy_target.update", "dokploy", dokploy_object(compose_id))
        return {
            "target": {
                "compose_id": compose_id,
                "name": detail.get("name") or compose_id,
                "project": (detail.get("project") or {}).get("name"),
                "environment": (detail.get("environment") or {}).get("name"),
                "status": detail.get("status"),
                "domains": detail.get("domains") or [],
                "source": "saved",
            }
        }

    @router.post("/dokploy/redeploy", response_model=None)
    async def redeploy_s3(request: Request) -> Any:
        principal = writer_sync(request, "s3:admin")
        ctx.require_principal(request, "dokploy:deploy")
        compose_id: str | None = None
        try:
            state = await s3_dokploy_state()
            target = state.get("target")
            # Only a saved, installer-recorded or container-detected Compose is redeployed;
            # a name/domain suggestion must be saved by the admin first.
            if (not isinstance(target, dict) or not isinstance(target.get("compose_id"), str)
                    or target.get("source") not in DEPLOYABLE_TARGET_SOURCES):
                raise S3Error(
                    "s3_dokploy_target_required", 409,
                    "Choose and save the Dokploy Compose that runs S3 first",
                )
            compose_id = str(target["compose_id"])
            await active_dokploy().action("compose", compose_id, "redeploy")
        except (S3Error, DokployError) as exc:
            await audit(principal, "dokploy.service.redeploy", "dokploy",
                        dokploy_object(compose_id), "failure")
            return ctx.error_payload(exc.code, exc.message, exc.status_code)
        await audit(principal, "dokploy.service.redeploy", "dokploy", dokploy_object(compose_id))
        return {"ok": True, "target": target, "started_at": int(time.time())}

    # ------------------------------------------------------------ buckets

    @router.get("/buckets")
    async def list_buckets(request: Request) -> dict[str, Any]:
        reader_sync(request, "s3:read")
        buckets = await asyncio.to_thread(store.list_buckets)
        reachable = await admin_api.health() if buckets else False
        return {"items": await with_stats(buckets, reachable), "engine_reachable": reachable}

    @router.post("/buckets", status_code=201, response_model=None)
    async def create_bucket(request: Request) -> dict[str, Any] | JSONResponse:
        principal = writer_sync(request, "s3:admin")
        body: Any = None
        try:
            body = await _body(request)
            item = await asyncio.to_thread(
                store.create_bucket, body, principal.user_id, is_owner=principal.allows("*")
            )
        except S3Error as exc:
            name = body.get("name") if isinstance(body, dict) else None
            await audit(
                principal,
                "s3.bucket.create",
                "s3_bucket",
                name if isinstance(name, str) else None,
                "denied" if exc.status_code == 403 else "failure",
            )
            return fail(exc)
        synced = await admin_api.ensure_bucket(item["name"])
        await audit(principal, "s3.bucket.create", "s3_bucket", item["name"])
        return {**item, "objects": 0, "bytes": 0, "engine_synced": synced}

    @router.patch("/buckets/{name}", response_model=None)
    async def update_bucket(name: str, request: Request) -> dict[str, Any] | JSONResponse:
        principal = writer_sync(request, "s3:admin")
        try:
            item = await asyncio.to_thread(
                store.update_bucket, name, await _body(request), is_owner=principal.allows("*")
            )
        except S3Error as exc:
            await audit(
                principal,
                "s3.bucket.update",
                "s3_bucket",
                name,
                "denied" if exc.status_code == 403 else "failure",
            )
            return fail(exc)
        await audit(principal, "s3.bucket.update", "s3_bucket", name)
        return item

    # ------------------------------------------------------------ custom bucket domains

    def domain_conflict(host: str) -> str | None:
        """Why ``host`` cannot become an admin bucket domain; None when it is free."""
        from ..models import ResourceOwner, ServiceDomain
        from ..tenancy import names_overlap

        with ctx.database.session() as db:
            if db.scalar(select(ServiceDomain.id).where(ServiceDomain.host == host)) is not None:
                return "this domain is already used by a service"
            if host in bucket_routes_module.read_admin_domains(db):
                return "this domain is already used by a bucket"
            # Workspace zones and bucket domains (verified or not) keep their whole
            # subtree, exactly as a workspace claim is checked against them.
            claimed = db.scalars(select(ResourceOwner.resource_id).where(
                ResourceOwner.kind.in_(["dns_zone", "bucket_domain"])))
            if any(names_overlap(host, other) for other in claimed):
                return "this domain belongs to a workspace"
        return None

    def path_host(raw: str) -> str:
        try:
            return canonical_host(raw)
        except HostError:
            raise S3Error("domain_not_found", 404, "bucket domain does not exist") from None

    def route_failed() -> S3Error:
        return S3Error("bucket_domain_route_failed", 502,
                       "the route of this bucket domain could not be updated")

    async def admin_domain_item(name: str, host: str) -> dict[str, Any]:
        for item in await admin_domain_items(name):
            if item["host"] == host:
                return item
        return {"host": host, "bucket": name, "verified": True, "source": "admin",
                "workspace_id": None, "workspace_slug": None,
                "route": {"state": "none", "error_code": None}}

    @router.get("/buckets/{name}/domains", response_model=None)
    async def list_bucket_domains(name: str, request: Request) -> Any:
        reader_sync(request, "s3:admin")
        try:
            await existing_bucket(name)
            return {"items": await admin_domain_items(name)}
        except S3Error as exc:
            return fail(exc)

    @router.post("/buckets/{name}/domains", status_code=201, response_model=None)
    async def add_bucket_domain(name: str, request: Request) -> Any:
        principal = writer_sync(request, "s3:admin")
        host: str | None = None
        try:
            await existing_bucket(name)
            body = await _body(request)
            if not isinstance(body, dict) or set(body) != {"host"}:
                raise S3Error("invalid_request", 422, "request body must contain only host")
            try:
                host = canonical_host(body.get("host"))
            except HostError as exc:
                raise S3Error("invalid_host", 422, exc.message) from None
            routes = bucket_routes()
            settings = await asyncio.to_thread(store.get_settings)
            suffix = str(settings.get("virtual_host_suffix") or "")
            if suffix and (host == suffix or host.endswith("." + suffix)):
                raise S3Error("domain_exists", 409, "this host is already an S3 virtual host")
            problem = await asyncio.to_thread(domain_conflict, host)
            if problem:
                raise S3Error("domain_exists", 409, problem)
            if not await asyncio.to_thread(routes.set_admin_domain, host, name,
                                           only_if_free=True):
                raise S3Error("domain_exists", 409, "this domain is already used by a bucket")
            try:
                await asyncio.to_thread(store.write_snapshot)
                await routes.ensure(host)
            except Exception:  # noqa: BLE001 - rolled back below, reported as a route error
                LOGGER.exception("routing the bucket domain %s failed", host)
                try:
                    await asyncio.to_thread(routes.set_admin_domain, host, None)
                    await asyncio.to_thread(store.write_snapshot)
                    await routes.remove(host)
                except Exception:  # noqa: BLE001 - reconcile removes leftovers later
                    LOGGER.exception("rolling back the bucket domain %s failed", host)
                    routes.reconcile_soon()
                raise route_failed() from None
            item = await admin_domain_item(name, host)
        except S3Error as exc:
            await audit(principal, "s3.bucket_domain.create", "bucket_domain", host, "failure")
            return fail(exc)
        await audit(principal, "s3.bucket_domain.create", "bucket_domain", f"{host}->{name}")
        return JSONResponse(status_code=201, content=item)

    @router.post("/buckets/{name}/domains/{host}/retry", response_model=None)
    async def retry_bucket_domain(name: str, host: str, request: Request) -> Any:
        principal = writer_sync(request, "s3:admin")
        canonical: str | None = None
        try:
            canonical = path_host(host)
            routes = bucket_routes()
            if (await asyncio.to_thread(routes.admin_domains)).get(canonical) != name:
                raise S3Error("domain_not_found", 404, "bucket domain does not exist")
            try:
                await routes.ensure(canonical, retry=True)
            except Exception:  # noqa: BLE001 - the route record keeps the last state
                LOGGER.exception("retrying the bucket domain %s failed", canonical)
                raise route_failed() from None
            item = await admin_domain_item(name, canonical)
        except S3Error as exc:
            await audit(principal, "s3.bucket_domain.retry", "bucket_domain", canonical, "failure")
            return fail(exc)
        await audit(principal, "s3.bucket_domain.retry", "bucket_domain", canonical)
        return item

    @router.delete("/buckets/{name}/domains/{host}", response_model=None)
    async def delete_bucket_domain(name: str, host: str, request: Request) -> Any:
        principal = writer_sync(request, "s3:admin")
        canonical: str | None = None
        try:
            canonical = path_host(host)
            routes = bucket_routes()
            if (await asyncio.to_thread(routes.admin_domains)).get(canonical) != name:
                raise S3Error("domain_not_found", 404, "bucket domain does not exist")
            try:
                # The engine stops serving the bucket on this host first; the public
                # route is removed after (a leftover shows as "stale" and is reconciled).
                await asyncio.to_thread(routes.set_admin_domain, canonical, None)
                await asyncio.to_thread(store.write_snapshot)
                await routes.remove(canonical)
            except Exception:  # noqa: BLE001 - reconcile finishes the removal
                LOGGER.exception("removing the bucket domain %s failed", canonical)
                routes.reconcile_soon()
                raise route_failed() from None
        except S3Error as exc:
            await audit(principal, "s3.bucket_domain.delete", "bucket_domain", canonical,
                        "failure")
            return fail(exc)
        await audit(principal, "s3.bucket_domain.delete", "bucket_domain", canonical)
        return {"deleted": canonical}

    @router.get("/buckets/{name}/lifecycle", response_model=None)
    async def bucket_lifecycle(name: str, request: Request) -> dict[str, Any] | JSONResponse:
        """Rules set through the S3 API (``PutBucketLifecycleConfiguration``) + last run."""
        reader_sync(request, "s3:read")
        try:
            await existing_bucket(name)
            return await admin_api.lifecycle(name)
        except (S3Error, EngineError) as exc:
            return fail(exc)

    @router.post("/buckets/{name}/lifecycle/preview", response_model=None)
    async def bucket_lifecycle_preview(
        name: str, request: Request
    ) -> dict[str, Any] | JSONResponse:
        principal = writer_sync(request, "s3:admin")
        try:
            await existing_bucket(name)
            preview = await admin_api.lifecycle_preview(name)
        except (S3Error, EngineError) as exc:
            await audit(principal, "s3.lifecycle.preview", "s3_bucket", name, "failure")
            return fail(exc)
        await audit(principal, "s3.lifecycle.preview", "s3_bucket", name)
        return preview

    @router.delete("/buckets/{name}", response_model=None)
    async def delete_bucket(name: str, request: Request) -> dict[str, Any] | JSONResponse:
        principal = writer_sync(request, "s3:admin")
        try:
            body = await _body(request)
            if not isinstance(body, dict):
                raise S3Error("invalid_request", 422, "request body must be a JSON object")
            force = body.get("force", False)
            if not isinstance(force, bool):
                raise S3Error("invalid_request", 422, "force must be true or false")
            bucket = await asyncio.to_thread(store.get_bucket, name)
            if body.get("confirmation") != name:
                raise S3Error(
                    "confirmation_mismatch", 422, "confirmation must equal the bucket name"
                )
            if bucket["mode"] == "managed":
                if not force:
                    stats = await admin_api.bucket_stats(name)
                    if stats is None and not await admin_api.health():
                        raise S3Error(
                            "engine_unreachable",
                            503,
                            "the S3 engine is not reachable; cannot check the bucket is empty",
                        )
                    if stats is not None and stats["objects"] > 0:
                        raise S3Error(
                            "bucket_not_empty",
                            409,
                            f"bucket holds {stats['objects']} object(s); delete with force",
                        )
                await admin_api.delete_bucket(name, force=force)
            else:
                # Linked folder: the engine only forgets its index; files are never removed.
                try:
                    await admin_api.delete_bucket(name, force=False)
                except EngineError:
                    pass
            await asyncio.to_thread(store.delete_bucket_record, name)
            routes = bucket_routes_module.active()
            if routes is not None:
                hosts = await asyncio.to_thread(routes.admin_domains_for, name)
                for host in hosts:
                    await asyncio.to_thread(routes.set_admin_domain, host, None)
                if hosts:
                    await asyncio.to_thread(store.write_snapshot)
                for host in hosts:
                    await routes.remove(host)
        except (S3Error, EngineError) as exc:
            await audit(principal, "s3.bucket.delete", "s3_bucket", name, "failure")
            return fail(exc)
        await audit(principal, "s3.bucket.delete", "s3_bucket", name)
        return {"deleted": True, "name": name, "files_removed": bucket["mode"] == "managed"}

    @router.get("/links")
    async def list_links(request: Request) -> dict[str, Any]:
        reader_sync(request, "s3:admin")
        items = await asyncio.to_thread(store.list_links)
        return {"items": items, "root": str(links_root()), "compose_hint": COMPOSE_HINT}

    # ------------------------------------------------------------ file manager

    add_file_routes(router, ctx, store, reader=reader, writer=writer, audit=audit)

    # ------------------------------------------------------------ identities / keys

    @router.get("/identities")
    async def list_identities(request: Request) -> dict[str, Any]:
        reader_sync(request, "s3:admin")
        return {"items": await asyncio.to_thread(store.list_identities)}

    @router.post("/identities", status_code=201, response_model=None)
    async def create_identity(request: Request) -> dict[str, Any] | JSONResponse:
        principal = writer_sync(request, "s3:admin")
        try:
            item = await asyncio.to_thread(
                store.create_identity, await _body(request), principal.user_id
            )
        except S3Error as exc:
            await audit(principal, "s3.identity.create", "s3_identity", None, "failure")
            return fail(exc)
        await audit(principal, "s3.identity.create", "s3_identity", item["id"])
        return item

    @router.patch("/identities/{identity_id}", response_model=None)
    async def update_identity(identity_id: str, request: Request) -> dict[str, Any] | JSONResponse:
        principal = writer_sync(request, "s3:admin")
        try:
            item = await asyncio.to_thread(store.update_identity, identity_id, await _body(request))
        except S3Error as exc:
            await audit(principal, "s3.identity.update", "s3_identity", identity_id, "failure")
            return fail(exc)
        await audit(principal, "s3.identity.update", "s3_identity", identity_id)
        return item

    @router.delete("/identities/{identity_id}", response_model=None)
    async def delete_identity(identity_id: str, request: Request) -> dict[str, Any] | JSONResponse:
        principal = writer_sync(request, "s3:admin")
        try:
            body = await _body(request)
            confirmation = body.get("confirmation") if isinstance(body, dict) else None
            item = await asyncio.to_thread(store.delete_identity, identity_id, confirmation)
        except S3Error as exc:
            await audit(principal, "s3.identity.delete", "s3_identity", identity_id, "failure")
            return fail(exc)
        await audit(principal, "s3.identity.delete", "s3_identity", identity_id)
        return {"deleted": True, **item}

    @router.post("/identities/{identity_id}/keys", status_code=201, response_model=None)
    async def create_key(identity_id: str, request: Request) -> dict[str, Any] | JSONResponse:
        principal = writer_sync(request, "s3:admin")
        try:
            body = await _body(request)
            if not isinstance(body, dict) or set(body) - {"secret_access_key"}:
                raise S3Error("invalid_request", 422,
                              'body must be {} or {"secret_access_key": "..."}')
            item = await asyncio.to_thread(
                store.create_key, identity_id, body.get("secret_access_key")
            )
        except S3Error as exc:
            await audit(principal, "s3.key.create", "s3_identity", identity_id, "failure")
            return fail(exc)
        await audit(principal, "s3.key.create", "s3_access_key", item["access_key_id"])
        return item

    @router.patch("/identities/{identity_id}/keys/{akid}", response_model=None)
    async def update_key(
        identity_id: str, akid: str, request: Request
    ) -> dict[str, Any] | JSONResponse:
        principal = writer_sync(request, "s3:admin")
        try:
            item = await asyncio.to_thread(
                store.update_key, identity_id, akid, await _body(request)
            )
        except S3Error as exc:
            await audit(principal, "s3.key.update", "s3_access_key", akid, "failure")
            return fail(exc)
        await audit(principal, "s3.key.update", "s3_access_key", akid)
        return item

    @router.post("/identities/{identity_id}/keys/{akid}/secret", response_model=None)
    async def reset_key_secret(
        identity_id: str, akid: str, request: Request
    ) -> dict[str, Any] | JSONResponse:
        principal = writer_sync(request, "s3:admin")
        try:
            body = await _body(request)
            if not isinstance(body, dict) or set(body) - {"secret_access_key"}:
                raise S3Error("invalid_request", 422,
                              'body must be {} or {"secret_access_key": "..."}')
            item = await asyncio.to_thread(
                store.set_key_secret, identity_id, akid, body.get("secret_access_key")
            )
        except S3Error as exc:
            await audit(principal, "s3.key.secret", "s3_access_key", akid, "failure")
            return fail(exc)
        # The secret is in this response only; the audit names the key, never the value.
        await audit(principal, "s3.key.secret", "s3_access_key", akid)
        return item

    @router.delete("/identities/{identity_id}/keys/{akid}", response_model=None)
    async def delete_key(
        identity_id: str, akid: str, request: Request
    ) -> dict[str, Any] | JSONResponse:
        principal = writer_sync(request, "s3:admin")
        try:
            await asyncio.to_thread(store.delete_key, identity_id, akid)
        except S3Error as exc:
            await audit(principal, "s3.key.delete", "s3_access_key", akid, "failure")
            return fail(exc)
        await audit(principal, "s3.key.delete", "s3_access_key", akid)
        return {"deleted": True, "access_key_id": akid}

    # ------------------------------------------------------------ connection info

    @router.get("/connection")
    async def connection(
        request: Request, bucket: str | None = None, access_key_id: str | None = None
    ) -> dict[str, Any]:
        reader_sync(request, "s3:read")
        settings = await asyncio.to_thread(store.get_settings)
        endpoint, fallback = public_endpoint(settings)
        safe_bucket = (
            bucket if bucket and object_key_error(bucket) is None and "/" not in bucket else None
        )
        safe_akid = access_key_id if access_key_id and access_key_id.isalnum() else None
        return {
            "endpoint": endpoint,
            "endpoint_is_fallback": fallback,
            "internal_endpoint": engine_url(),
            "region": settings["region"],
            "path_style": True,
            "snippets": connection_snippets(
                endpoint, settings["region"], bucket=safe_bucket, access_key_id=safe_akid
            ),
        }

    return router



def add_file_routes(
    router: APIRouter,
    ctx: ModuleContext,
    store: S3Store,
    *,
    reader: Callable[[Request, str], Awaitable[Any]],
    writer: Callable[[Request, str], Awaitable[Any]],
    audit: Callable[..., Awaitable[None]],
) -> None:
    """The file manager (list/upload/download/delete/folder/move/share) on ``router``.

    Shared by the admin API (``/api/v1/s3``) and «my space» (``/api/v1/my/s3``, docs/43):
    ``reader``/``writer`` authorize the request (and, for «my space», the bucket's
    ownership) and return the actor that ``audit`` receives.
    """

    def fail(exc: S3Error | EngineError) -> JSONResponse:
        extra = exc.payload_extra() if isinstance(exc, S3Error) else {}
        return ctx.error_payload(exc.code, exc.message, exc.status_code, **extra)  # type: ignore[call-arg]

    async def engine() -> tuple[EngineS3, dict[str, Any]]:
        def load() -> tuple[tuple[str, str], dict[str, Any]]:
            return store.panel_credentials(), store.get_settings()

        (akid, secret), settings = await asyncio.to_thread(load)
        return EngineS3(access_key=akid, secret=secret, region=settings["region"]), settings

    async def existing_bucket(name: str, *, write: bool = False) -> dict[str, Any]:
        bucket = await asyncio.to_thread(store.get_bucket, name)
        if write and bucket["mode"] == "linked" and bucket["link_mode"] == "ro":
            raise S3Error("bucket_read_only", 409, "bucket is a read-only linked folder")
        return bucket

    def public_endpoint(settings: dict[str, Any]) -> tuple[str, bool]:
        configured = settings.get("public_endpoint")
        if configured:
            return str(configured), False
        return FALLBACK_ENDPOINT, True

    async def share_endpoint(
        bucket: str, settings: dict[str, Any]
    ) -> tuple[str, bool, bool]:
        """Prefer a ready custom bucket host; otherwise keep the safe path-style URL."""
        routes = bucket_routes_module.active()
        if routes is not None:
            desired, records = await asyncio.gather(
                asyncio.to_thread(routes.desired),
                asyncio.to_thread(routes.records),
            )
            for host, owner in sorted(desired.items()):
                record = records.get(host) or {}
                if owner.get("bucket") == bucket and record.get("state") == "ok":
                    scheme = "https" if record.get("https", True) else "http"
                    return f"{scheme}://{host}", False, False
        endpoint, fallback = public_endpoint(settings)
        return endpoint, fallback, True

    @router.get("/buckets/{name}/objects", response_model=None)
    async def list_objects(
        name: str,
        request: Request,
        prefix: str = "",
        delimiter: str = "/",
        continuation: str = "",
        limit: int = 200,
    ) -> dict[str, Any] | JSONResponse:
        await reader(request, "s3:read")
        try:
            if not 1 <= limit <= 1000:
                raise S3Error("invalid_limit", 422, "limit must be between 1 and 1000")
            if delimiter not in {"", "/"}:
                raise S3Error("invalid_delimiter", 422, "delimiter must be '/' or empty")
            if prefix:
                problem = object_key_error(prefix.rstrip("/") or "x")
                if problem:
                    raise S3Error("invalid_key", 422, problem)
            await existing_bucket(name)
            client, _settings = await engine()
            async with client:
                return await client.list_objects(
                    name, prefix=prefix, delimiter=delimiter, continuation=continuation, limit=limit
                )
        except (S3Error, EngineError) as exc:
            return fail(exc)

    async def _multipart(
        client: EngineS3,
        bucket: str,
        key: str,
        content_type: str,
        body: _BodyReader,
        length: int | None,
        max_bytes: int,
        first: bytes | None = None,
    ) -> tuple[int, str]:
        part_size = PART_SIZE if length is None else max(PART_SIZE, math.ceil(length / MAX_PARTS))
        upload_id = await client.create_multipart(bucket, key, content_type)
        parts: list[tuple[int, str]] = []
        total = 0
        try:
            number = 0
            while True:
                number += 1
                if number > MAX_PARTS:
                    raise S3Error(
                        "object_too_large", 413, "upload exceeds the multipart part limit"
                    )
                if length is not None:
                    size = min(part_size, length - total)
                    if size <= 0:
                        break
                    etag = await client.upload_part(
                        bucket, key, upload_id, number, body.exactly(size), size
                    )
                else:
                    chunk = first if first is not None else await body.read_up_to(part_size)
                    first = None
                    if not chunk and parts:
                        break
                    size = len(chunk)
                    etag = await client.upload_part(bucket, key, upload_id, number, chunk, size)
                total += size
                if total > max_bytes:
                    raise S3Error("object_too_large", 413, f"object exceeds {max_bytes} bytes")
                parts.append((number, etag))
                if length is None and size < part_size:
                    break
            final = await client.complete_multipart(bucket, key, upload_id, parts)
        except BaseException:
            await client.abort_multipart(bucket, key, upload_id)
            raise
        return total, final

    @router.post("/buckets/{name}/objects", response_model=None)
    async def upload_object(
        name: str, request: Request, key: str = ""
    ) -> dict[str, Any] | JSONResponse:
        principal = await writer(request, "s3:write")
        try:
            key = _check_key(key)
            await existing_bucket(name, write=True)
            raw_length = request.headers.get("content-length")
            length: int | None = None
            if raw_length is not None:
                if not raw_length.isdigit():
                    raise S3Error("invalid_content_length", 400, "Content-Length is invalid")
                length = int(raw_length)
            content_type = request.headers.get("content-type") or "application/octet-stream"
            client, settings = await engine()
            max_bytes = int(settings["max_object_bytes"])
            if length is not None and length > max_bytes:
                raise S3Error("object_too_large", 413, f"object exceeds {max_bytes} bytes")
            body = _BodyReader(request.stream())
            async with client:
                headers = {"Content-Type": content_type}
                if length is not None and length <= MULTIPART_THRESHOLD:
                    headers["Content-Length"] = str(length)
                    response = await client.call(
                        "PUT",
                        name,
                        key,
                        headers=headers,
                        content=body.exactly(length) if length else b"",
                        payload_hash=UNSIGNED_PAYLOAD,
                    )
                    size, etag = length, response.headers.get("etag", "").strip('"')
                elif length is None:
                    first = await body.read_up_to(PART_SIZE)
                    if body.eof and len(first) < PART_SIZE:
                        headers["Content-Length"] = str(len(first))
                        response = await client.call(
                            "PUT",
                            name,
                            key,
                            headers=headers,
                            content=first,
                            payload_hash=UNSIGNED_PAYLOAD,
                        )
                        size, etag = len(first), response.headers.get("etag", "").strip('"')
                    else:
                        size, etag = await _multipart(
                            client, name, key, content_type, body, None, max_bytes, first
                        )
                else:
                    size, etag = await _multipart(
                        client, name, key, content_type, body, length, max_bytes
                    )
        except ClientDisconnect:
            await audit(principal, "s3.object.upload", "s3_object", f"{name}/{key}", "failure")
            return ctx.error_payload("upload_aborted", "the client disconnected", 400)
        except (S3Error, EngineError) as exc:
            await audit(principal, "s3.object.upload", "s3_object", f"{name}/{key}", "failure")
            return fail(exc)
        await audit(principal, "s3.object.upload", "s3_object", f"{name}/{key}")
        return {"key": key, "size": size, "etag": etag}

    @router.get("/buckets/{name}/objects/download", response_model=None)
    async def download_object(
        name: str, request: Request, key: str = ""
    ) -> StreamingResponse | JSONResponse:
        await reader(request, "s3:read")
        client: EngineS3 | None = None
        try:
            key = _check_key(key)
            await existing_bucket(name)
            client, _settings = await engine()
            headers = {}
            if request.headers.get("range"):
                headers["Range"] = request.headers["range"]
            response = await client.send("GET", name, key, headers=headers, stream=True)
        except (S3Error, EngineError) as exc:
            if client is not None:
                await client.aclose()
            return fail(exc)
        engine_client = client

        async def body() -> AsyncIterator[bytes]:
            try:
                if response.is_stream_consumed:  # already-buffered response (test transports)
                    yield response.content
                else:
                    async for chunk in response.aiter_raw():
                        yield chunk
            finally:
                await response.aclose()
                await engine_client.aclose()

        out = {"Content-Disposition": _content_disposition(key)}
        for header in ("content-length", "etag", "last-modified", "accept-ranges", "content-range"):
            if header in response.headers:
                out[header] = response.headers[header]
        return StreamingResponse(
            body(),
            status_code=response.status_code,
            media_type=response.headers.get("content-type") or "application/octet-stream",
            headers=out,
        )

    @router.delete("/buckets/{name}/objects", response_model=None)
    async def delete_objects(name: str, request: Request) -> dict[str, Any] | JSONResponse:
        principal = await writer(request, "s3:write")
        try:
            body = await _body(request)
            keys = body.get("keys") if isinstance(body, dict) else None
            if not isinstance(keys, list) or not 1 <= len(keys) <= MAX_DELETE_KEYS:
                raise S3Error(
                    "invalid_request", 422, f"keys must be a list of 1 to {MAX_DELETE_KEYS} keys"
                )
            for key in keys:
                _check_key(key, folder=isinstance(key, str) and key.endswith("/"))
            await existing_bucket(name, write=True)
            client, _settings = await engine()
        except (S3Error, EngineError) as exc:
            return fail(exc)
        deleted: list[str] = []
        errors: list[dict[str, str]] = []
        semaphore = asyncio.Semaphore(8)

        async def one(key: str) -> None:
            async with semaphore:
                try:
                    await client.delete(name, key)
                except EngineError as exc:
                    if exc.code == "object_not_found":
                        deleted.append(key)
                    else:
                        errors.append({"key": key, "code": exc.code, "message": exc.message})
                else:
                    deleted.append(key)

        async with client:
            await asyncio.gather(*(one(key) for key in dict.fromkeys(keys)))
        await audit(
            principal,
            "s3.object.delete",
            "s3_object",
            f"{name} ({len(deleted)} keys)",
            "success" if not errors else "failure",
        )
        return {"deleted": sorted(deleted), "errors": errors}

    @router.post("/buckets/{name}/folders", status_code=201, response_model=None)
    async def create_folder(name: str, request: Request) -> dict[str, Any] | JSONResponse:
        principal = await writer(request, "s3:write")
        try:
            body = await _body(request)
            prefix = body.get("prefix") if isinstance(body, dict) else None
            if isinstance(prefix, str) and prefix and not prefix.endswith("/"):
                prefix += "/"
            prefix = _check_key(prefix, folder=True)
            await existing_bucket(name, write=True)
            client, _settings = await engine()
            async with client:
                await client.call(
                    "PUT",
                    name,
                    prefix,
                    headers={"Content-Type": "application/x-directory"},
                    content=b"",
                )
        except (S3Error, EngineError) as exc:
            return fail(exc)
        await audit(principal, "s3.folder.create", "s3_object", f"{name}/{prefix}")
        return {"key": prefix}

    @router.post("/buckets/{name}/objects/move", response_model=None)
    async def move_objects(name: str, request: Request) -> dict[str, Any] | JSONResponse:
        principal = await writer(request, "s3:write")
        source = target = ""
        try:
            body = await _body(request)
            if not isinstance(body, dict):
                raise S3Error("invalid_request", 422, "body must be {from, to}")
            source, target = body.get("from"), body.get("to")
            folder = isinstance(source, str) and source.endswith("/")
            source = _check_key(source, folder=folder)
            target = _check_key(target, folder=folder)
            if folder != target.endswith("/"):
                raise S3Error(
                    "invalid_move", 422, "a folder must be moved to a folder ('/' suffix)"
                )
            if source == target:
                raise S3Error("invalid_move", 422, "source and destination are the same")
            if folder and target.startswith(source):
                raise S3Error("invalid_move", 422, "a folder cannot be moved into itself")
            await existing_bucket(name, write=True)
            client, _settings = await engine()
            async with client:
                pairs: list[tuple[str, str]] = []
                if folder:
                    continuation = ""
                    while True:
                        page = await client.list_objects(
                            name, prefix=source, continuation=continuation, limit=1000
                        )
                        pairs.extend(
                            (item["key"], target + item["key"][len(source) :])
                            for item in page["objects"]
                        )
                        if len(pairs) > MAX_MOVE_OBJECTS:
                            raise S3Error(
                                "too_many_objects",
                                409,
                                f"a folder move is limited to {MAX_MOVE_OBJECTS} objects",
                            )
                        continuation = page["next_continuation"] or ""
                        if not continuation:
                            break
                    if not pairs:
                        raise S3Error("object_not_found", 404, "the folder is empty or missing")
                else:
                    pairs.append((source, target))
                for old, new in pairs:
                    await client.copy(name, old, new)
                    await client.delete(name, old)
        except (S3Error, EngineError) as exc:
            await audit(principal, "s3.object.move", "s3_object", f"{name}/{source}", "failure")
            return fail(exc)
        await audit(principal, "s3.object.move", "s3_object", f"{name}/{source} -> {target}")
        return {"from": source, "to": target, "moved": len(pairs)}

    @router.post("/buckets/{name}/share", response_model=None)
    async def share_object(name: str, request: Request) -> dict[str, Any] | JSONResponse:
        principal = await writer(request, "s3:write")
        try:
            body = await _body(request)
            if not isinstance(body, dict):
                raise S3Error("invalid_request", 422, "body must be {key, expires_seconds}")
            key = _check_key(body.get("key"))
            expires = body.get("expires_seconds", 3600)
            if (
                isinstance(expires, bool)
                or not isinstance(expires, int)
                or not 1 <= expires <= MAX_SHARE_SECONDS
            ):
                raise S3Error(
                    "invalid_expiry",
                    422,
                    f"expires_seconds must be between 1 and {MAX_SHARE_SECONDS} (7 days)",
                )
            await existing_bucket(name)
            client, settings = await engine()
            async with client:
                await client.head(name, key)
            endpoint, fallback, path_style = await share_endpoint(name, settings)
            url = client.presign_get(endpoint, name, key, expires, path_style=path_style)
        except (S3Error, EngineError) as exc:
            return fail(exc)
        await audit(principal, "s3.object.share", "s3_object", f"{name}/{key}")
        return {
            "url": url,
            "expires_at": int(time.time()) + expires,
            "endpoint": endpoint,
            "warning": "public_endpoint_not_configured" if fallback else None,
        }


def register(ctx: ModuleContext) -> None:
    global ACTIVE_STORE
    store = S3Store(ctx.data_dir, ctx.database, ctx.secret_store)
    ACTIVE_STORE = store
    ctx.routers.append(build_router(ctx, store))

    from .s3_client import configure_remote, is_remote

    configure_remote(ctx.data_dir)
    retry: dict[str, asyncio.Task[None] | None] = {"task": None}

    async def resend_loop() -> None:
        # docs/44: a separate engine that missed a snapshot (down, restarted with an
        # empty volume) gets it again. Its health also says whether it has a config.
        while True:
            await asyncio.sleep(30)
            try:
                if not is_remote():
                    continue
                missing = store.push_pending
                if not missing:
                    health = await EngineAdmin(store.admin_token_path).json(
                        "GET", "/admin/health", timeout=3.0)
                    missing = isinstance(health, dict) and not health.get("config_loaded")
                if missing:
                    await asyncio.to_thread(store.push_snapshot)
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001 - engine trouble; try again next round
                logging.getLogger(__name__).debug("S3 snapshot resend failed", exc_info=True)

    async def start() -> None:
        # Regenerate the snapshot at every start so the engine always matches the database.
        await asyncio.to_thread(store.startup)
        retry["task"] = asyncio.create_task(resend_loop())

    async def stop() -> None:
        task = retry["task"]
        if task is not None:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task

    ctx.start_hooks.append(start)
    ctx.stop_hooks.append(stop)
