"""«My space» DNS (docs/43 §3): a workspace's own zones on the shared DNS engine.

The engine is unchanged; ownership lives in ``resource_owners`` (kind ``dns_zone``).
Every route calls the same validators and engine client as ``/api/v1/dns`` with an
ownership check first. Record bodies go through ``dns_validate.record_body`` (strict
type/value checks) and the plan's ``dns_record_types`` before anything reaches the engine.
"""

from __future__ import annotations

import asyncio
import secrets
import time
from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING, Any
from urllib.parse import quote

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from sqlalchemy import select

from .. import dns_client
from ..dns_client import DnsError
from ..models import ServiceDomain
from ..tenancy import TenancyError, WorkspaceContext, check_quota, names_overlap, not_found
from .dns_validate import DnsInputError, canonical_zone, entity_id, record_body, zone_patch_body

if TYPE_CHECKING:
    from .tenancy import MySpace

VERIFY_LABEL = "_devassist-verify"
VERIFY_PREFIX = "devassist-verify="


def _lookup(name: str, rtype: str) -> list[str]:
    """Public DNS answers (TXT strings / NS host names) via the system resolver."""
    import dns.exception
    import dns.resolver

    try:
        answer = dns.resolver.resolve(name, rtype, lifetime=5.0)
    except (dns.exception.DNSException, OSError):
        return []
    values: list[str] = []
    for item in answer:
        if rtype == "TXT":
            values.append(b"".join(item.strings).decode("utf-8", "replace"))
        else:
            values.append(str(item.target).rstrip(".").lower())
    return values


# Replaced in tests; (name, "TXT"|"NS") -> values.
LOOKUP: Callable[[str, str], list[str]] = _lookup


def _path(*parts: str) -> str:
    return "/" + "/".join(quote(part, safe="") for part in parts)


def verify_methods(name: str, token: str, targets: list[str]) -> list[dict[str, Any]]:
    return [
        {"kind": "txt", "name": f"{VERIFY_LABEL}.{name}", "value": f"{VERIFY_PREFIX}{token}"},
        {"kind": "ns", "targets": targets},
    ]


def txt_verified(name: str, token: str) -> bool:
    return f"{VERIFY_PREFIX}{token}" in LOOKUP(f"{VERIFY_LABEL}.{name}", "TXT")


def dns_fail(space: MySpace, exc: DnsError | DnsInputError) -> JSONResponse:
    extra = {key: value for key, value in (getattr(exc, "extra", {}) or {}).items()
             if value is not None}
    return space.ctx.error_payload(  # type: ignore[call-arg]
        exc.code, exc.message, exc.status_code, fields=exc.fields, **extra
    )


def register_routes(space: MySpace, router: APIRouter) -> None:
    store = space.store
    ctx = space.ctx

    def service() -> Any:
        from . import dns as dns_module

        if dns_module.ACTIVE_SERVICE is None:
            raise TenancyError("dns_not_installed", 503, "The DNS server is not available")
        return dns_module.ACTIVE_SERVICE

    async def run(
        request: Request,
        work: Callable[..., Awaitable[Any]],
        *,
        scope: str,
        write: bool = False,
        zone: str | None = None,
        feature: str = "dns",
    ) -> Any:
        token = None
        try:
            wctx = await space.context(request, write=write)
            name = owner = None
            if zone is not None:
                try:
                    name = canonical_zone(zone, "zone")
                except DnsInputError:
                    raise not_found() from None
                owner = await asyncio.to_thread(store.require_owned, wctx, "dns_zone", name)
            wctx.need(scope, feature=feature)
            body = await space.body(request) if write else None
            token = dns_client.CURRENT_ACTOR.set(wctx.principal.username)
            return await work(wctx, body, name, owner)
        except TenancyError as exc:
            return space.fail(exc)
        except (DnsError, DnsInputError) as exc:
            return dns_fail(space, exc)
        finally:
            if token is not None:
                dns_client.CURRENT_ACTOR.reset(token)

    def zone_view(engine_item: dict[str, Any] | None, owner: dict[str, Any]) -> dict[str, Any]:
        meta = owner.get("meta") or {}
        base = dict(engine_item or {"name": owner["resource_id"], "type": "primary"})
        base.pop("disabled", None)
        return {**base, "name": owner["resource_id"],
                "status": meta.get("status", "active"),
                "verified_at": meta.get("verified_at")}

    async def records_of(name: str) -> list[dict[str, Any]]:
        payload = await service().client.get(_path("v1", "zones", name, "records"))
        items = payload.get("items") if isinstance(payload, dict) else None
        return [item for item in items or [] if isinstance(item, dict)]

    async def ns_targets(name: str) -> list[str]:
        targets: list[str] = []
        for item in await records_of(name):
            if str(item.get("type")).upper() == "NS" and item.get("name") in ("@", "", name):
                data = item.get("data") or {}
                value = data.get("nameserver") or data.get("target") if isinstance(data, dict) \
                    else None
                if isinstance(value, str):
                    targets.append(value.rstrip(".").lower())
        return sorted(set(targets))

    def system_names() -> list[str]:
        from . import dns as dns_module
        from . import s3 as s3_module

        names = [dns_module.INTERNAL_ZONE]
        with ctx.database.session() as db:
            names.extend(db.scalars(select(ServiceDomain.host)))
            # A workspace zone must not cover a custom domain of an admin bucket.
            from . import bucket_routes

            names.extend(bucket_routes.read_admin_domains(db))
        if s3_module.ACTIVE_STORE is not None:
            suffix = s3_module.ACTIVE_STORE.get_settings().get("virtual_host_suffix")
            if suffix:
                names.append(str(suffix))
        return names

    async def check_available(wctx: WorkspaceContext, name: str) -> None:
        unavailable = TenancyError("zone_unavailable", 409,
                                   "This domain cannot be added here",
                                   fields=[{"field": "name", "reason_code": "unavailable"}])
        if "." not in name:
            raise unavailable
        mine = {item["resource_id"] for item in await asyncio.to_thread(
            store.owned, "dns_zone", wctx.workspace_id)}
        others = [item["resource_id"] for item in await asyncio.to_thread(
            store.all_owned, ("dns_zone", "bucket_domain"))
            if item["workspace_id"] != wctx.workspace_id]
        payload = await service().client.get("/v1/zones")
        engine_zones = [str(item.get("name", "")).rstrip(".").lower()
                        for item in (payload.get("items") if isinstance(payload, dict)
                                     else None) or [] if isinstance(item, dict)]
        system = await asyncio.to_thread(system_names)
        for other in [*others, *system, *(zone for zone in engine_zones if zone not in mine)]:
            if other and names_overlap(name, other):
                raise unavailable

    # ---------------------------------------------------------------- zones
    @router.get("/dns/zones", response_model=None)
    async def list_zones(request: Request) -> Any:
        async def work(wctx: WorkspaceContext, _body: Any, _name: Any, _owner: Any) -> Any:
            owned = await asyncio.to_thread(store.owned, "dns_zone", wctx.workspace_id)
            if not owned:
                return {"items": []}
            payload = await service().client.get("/v1/zones")
            engine = {str(item.get("name", "")).rstrip(".").lower(): item
                      for item in (payload.get("items") if isinstance(payload, dict) else None)
                      or [] if isinstance(item, dict)}
            return {"items": [zone_view(engine.get(item["resource_id"]), item)
                              for item in owned]}

        return await run(request, work, scope="my.dns:read")

    @router.get("/dns/templates", response_model=None)
    async def list_templates(request: Request) -> Any:
        async def work(_wctx: WorkspaceContext, _body: Any, _name: Any, _owner: Any) -> Any:
            svc = service()
            items = await asyncio.to_thread(svc.templates.list)
            return {"items": [{"id": item.get("id"), "name": item.get("name"),
                               "description": item.get("description", ""),
                               "builtin": bool(item.get("builtin")),
                               "variables": item.get("variables", [])} for item in items],
                    "default_id": svc.get_settings().get("default_template_id") or None}

        return await run(request, work, scope="my.dns:read")

    @router.post("/dns/zones", status_code=201, response_model=None)
    async def create_zone(request: Request) -> Any:
        async def work(wctx: WorkspaceContext, body: Any, _name: Any, _owner: Any) -> Any:
            from . import dns_final
            from .dns_templates import render as render_template

            if not isinstance(body, dict):
                raise DnsInputError("invalid_zone_name", "The zone must be an object",
                                    [{"field": "body", "reason_code": "invalid_type"}])
            unknown = sorted(set(body) - {"name", "template_id", "variables"})
            if unknown:
                raise DnsInputError("dns_record_invalid", "Unknown fields",
                                    [{"field": key, "reason_code": "unknown_field"}
                                     for key in unknown[:10]])
            name = canonical_zone(body.get("name"))
            svc = service()
            variables = body.get("variables")
            if body.get("template_id") not in (None, ""):
                wctx.feature("dns_templates")
                template = await asyncio.to_thread(svc.templates.require, str(body["template_id"]))
            else:
                default = svc.get_settings().get("default_template_id") or ""
                template = await asyncio.to_thread(svc.templates.get, default) if default \
                    else None
            if template is not None:
                render_template(template, name, variables, dns_final.server_ips(ctx, svc))
            verify = bool((await asyncio.to_thread(store.get_settings))["verify_domains"])
            meta = {"status": "pending_verification" if verify else "active",
                    "verify_token": secrets.token_hex(16)}
            async with store.alock(wctx.workspace_id):
                await check_available(wctx, name)
                await asyncio.to_thread(store.claim, wctx, "dns_zone", name, quota="dns_zones",
                                        meta=meta)
                try:
                    created = await svc.client.request("POST", "/v1/zones",
                                                       {"name": name, "type": "primary"})
                    if verify:
                        # Not served until the owner proves the domain (docs/43 §3).
                        await svc.client.request("PATCH", _path("v1", "zones", name),
                                                 {"disabled": True})
                except BaseException:
                    await asyncio.to_thread(store.release, "dns_zone", name)
                    raise
            applied: dict[str, Any] | None = None
            if template is not None:
                try:
                    applied = await dns_final.apply_template(svc, template, name, variables,
                                                             replace=True)
                except (DnsError, DnsInputError) as exc:
                    applied = {"template_id": template["id"], "applied": False,
                               "error": {"code": exc.code, "message": exc.message}}
            await space.audit(wctx, "my.dns.zone.create", "dns_zone", name)
            owner = await asyncio.to_thread(store.require_owned, wctx, "dns_zone", name)
            return JSONResponse(status_code=201, content={
                **zone_view(created if isinstance(created, dict) else None, owner),
                "template": applied})

        return await run(request, work, scope="my.dns:write", write=True)

    @router.get("/dns/zones/{zone}", response_model=None)
    async def get_zone(zone: str, request: Request) -> Any:
        async def work(_wctx: WorkspaceContext, _body: Any, name: str, owner: Any) -> Any:
            try:
                item = await service().client.get(_path("v1", "zones", name))
            except DnsError as exc:
                if exc.status_code != 404:
                    raise
                item = None
            return zone_view(item if isinstance(item, dict) else None, owner)

        return await run(request, work, scope="my.dns:read", zone=zone)

    @router.delete("/dns/zones/{zone}", response_model=None)
    async def delete_zone(zone: str, request: Request) -> Any:
        async def work(wctx: WorkspaceContext, body: Any, name: str, _owner: Any) -> Any:
            confirmation = body.get("confirmation") if isinstance(body, dict) else None
            if not isinstance(confirmation, str) or confirmation.strip().lower().rstrip(
                    ".") != name:
                raise DnsError("confirmation_mismatch", 422, "Type the zone name to confirm",
                               fields=[{"field": "confirmation", "reason_code": "incorrect"}],
                               expected_confirmation=name)
            try:
                await service().client.request("DELETE", _path("v1", "zones", name))
            except DnsError as exc:
                if exc.status_code != 404:
                    raise
            await asyncio.to_thread(store.release, "dns_zone", name)
            await space.audit(wctx, "my.dns.zone.delete", "dns_zone", name)
            return {"deleted": name}

        return await run(request, work, scope="my.dns:write", write=True, zone=zone)

    # ---------------------------------------------------------------- verification
    @router.get("/dns/zones/{zone}/verification", response_model=None)
    async def verification(zone: str, request: Request) -> Any:
        async def work(_wctx: WorkspaceContext, _body: Any, name: str, owner: Any) -> Any:
            meta = owner["meta"]
            return {"methods": verify_methods(name, meta.get("verify_token", ""),
                                              await ns_targets(name)),
                    "verified": meta.get("status", "active") == "active",
                    "status": meta.get("status", "active")}

        return await run(request, work, scope="my.dns:read", zone=zone)

    @router.post("/dns/zones/{zone}/verify", response_model=None)
    async def verify(zone: str, request: Request) -> Any:
        async def work(wctx: WorkspaceContext, _body: Any, name: str, owner: Any) -> Any:
            meta = owner["meta"]
            if meta.get("status", "active") == "active":
                return {"verified": True, "method": None, "status": "active"}
            method = None
            if await asyncio.to_thread(txt_verified, name, meta.get("verify_token", "")):
                method = "txt"
            else:
                targets = set(await ns_targets(name))
                public = set(await asyncio.to_thread(LOOKUP, name, "NS"))
                if targets and public and public <= targets:
                    method = "ns"
            if method is None:
                await space.audit(wctx, "my.dns.zone.verify", "dns_zone", name, "failure")
                return {"verified": False, "method": None, "status": meta.get("status")}
            await service().client.request("PATCH", _path("v1", "zones", name),
                                           {"disabled": False})
            await asyncio.to_thread(store.set_meta, "dns_zone", name, {
                "status": "active", "verified_at": int(time.time()), "verified_by": method})
            await space.audit(wctx, "my.dns.zone.verify", "dns_zone", f"{name}:{method}")
            return {"verified": True, "method": method, "status": "active"}

        return await run(request, work, scope="my.dns:write", write=True, zone=zone)

    # ---------------------------------------------------------------- records
    def checked_record(wctx: WorkspaceContext, body: Any, name: str, *, creating: bool
                       ) -> dict[str, Any]:
        if isinstance(body, dict) and "view" in body:
            raise DnsInputError("dns_record_invalid", "Unknown fields",
                                [{"field": "view", "reason_code": "unknown_field"}])
        payload = record_body(body, name, creating=creating)
        payload.pop("view", None)
        allowed = {item.upper() for item in wctx.limits["quotas"].get("dns_record_types") or []}
        if payload["type"] not in allowed:
            raise DnsInputError("dns_record_type_not_allowed",
                                "Your plan does not allow this record type",
                                [{"field": "type", "reason_code": "not_allowed",
                                  "params": {"choices": sorted(allowed)}}], 422)
        return payload

    @router.get("/dns/zones/{zone}/records", response_model=None)
    async def list_records(zone: str, request: Request) -> Any:
        async def work(_wctx: WorkspaceContext, _body: Any, name: str, _owner: Any) -> Any:
            return {"items": await records_of(name)}

        return await run(request, work, scope="my.dns:read", zone=zone)

    @router.post("/dns/zones/{zone}/records", status_code=201, response_model=None)
    async def create_record(zone: str, request: Request) -> Any:
        async def work(wctx: WorkspaceContext, body: Any, name: str, _owner: Any) -> Any:
            payload = checked_record(wctx, body, name, creating=True)
            async with store.alock(wctx.workspace_id):
                existing = [item for item in await records_of(name)
                            if str(item.get("type")).upper() != "SOA"]
                check_quota(wctx.limits, "dns_records_per_zone", len(existing))
                result = await service().client.request(
                    "POST", _path("v1", "zones", name, "records"), payload)
            await space.audit(wctx, "my.dns.record.create", "dns_record",
                              f"{name}:{payload['name']}:{payload['type']}")
            return JSONResponse(status_code=201, content=result)

        return await run(request, work, scope="my.dns:write", write=True, zone=zone)

    @router.put("/dns/zones/{zone}/records/{record_id}", response_model=None)
    async def update_record(zone: str, record_id: str, request: Request) -> Any:
        async def work(wctx: WorkspaceContext, body: Any, name: str, _owner: Any) -> Any:
            rid = entity_id(record_id)
            payload = checked_record(wctx, body, name, creating=False)
            result = await service().client.request(
                "PUT", _path("v1", "zones", name, "records", rid), payload)
            await space.audit(wctx, "my.dns.record.update", "dns_record", f"{name}:{rid}")
            return result

        return await run(request, work, scope="my.dns:write", write=True, zone=zone)

    @router.delete("/dns/zones/{zone}/records/{record_id}", response_model=None)
    async def delete_record(zone: str, record_id: str, request: Request) -> Any:
        async def work(wctx: WorkspaceContext, _body: Any, name: str, _owner: Any) -> Any:
            rid = entity_id(record_id)
            await service().client.request("DELETE", _path("v1", "zones", name, "records", rid))
            await space.audit(wctx, "my.dns.record.delete", "dns_record", f"{name}:{rid}")
            return {"deleted": rid}

        return await run(request, work, scope="my.dns:write", write=True, zone=zone)

    @router.post("/dns/zones/{zone}/apply-template", response_model=None)
    async def apply_template(zone: str, request: Request) -> Any:
        async def work(wctx: WorkspaceContext, body: Any, name: str, _owner: Any) -> Any:
            from . import dns_final

            if not isinstance(body, dict) or set(body) - {"template_id", "variables",
                                                          "replace_conflicts"}:
                raise DnsInputError("dns_template_invalid", "Unknown fields",
                                    [{"field": "body", "reason_code": "unknown_field"}])
            replace = body.get("replace_conflicts", False)
            if not isinstance(replace, bool) or body.get("template_id") in (None, ""):
                raise DnsInputError("dns_template_invalid", "Choose a template",
                                    [{"field": "template_id", "reason_code": "required"}])
            svc = service()
            template = await asyncio.to_thread(svc.templates.require, str(body["template_id"]))
            result = await dns_final.apply_template(svc, template, name, body.get("variables"),
                                                    replace=replace)
            await space.audit(wctx, "my.dns.zone.apply_template", "dns_zone",
                              f"{name}:{template['id']}")
            return result

        return await run(request, work, scope="my.dns:write", write=True, zone=zone,
                         feature="dns_templates")

    @router.get("/dns/zones/{zone}/dnssec", response_model=None)
    async def get_dnssec(zone: str, request: Request) -> Any:
        async def work(_wctx: WorkspaceContext, _body: Any, name: str, _owner: Any) -> Any:
            from .dns_validate_d5 import strip_secrets

            payload = await service().client.get(_path("v1", "zones", name, "dnssec"))
            return strip_secrets(payload, frozenset({"secret", "private_key", "private_key_pem",
                                                     "key_pem", "private"}))

        return await run(request, work, scope="my.dns:read", zone=zone)

    @router.put("/dns/zones/{zone}/dnssec", response_model=None)
    async def put_dnssec(zone: str, request: Request) -> Any:
        async def work(wctx: WorkspaceContext, body: Any, name: str, _owner: Any) -> Any:
            if not isinstance(body, dict) or set(body) != {"enabled"} or not isinstance(
                    body["enabled"], bool):
                raise DnsInputError("dns_zone_invalid", 'Send {"enabled": true|false}',
                                    [{"field": "enabled", "reason_code": "invalid_type"}])
            payload = zone_patch_body({"dnssec": {"enabled": body["enabled"]}})
            result = await service().client.request("PATCH", _path("v1", "zones", name),
                                                    payload)
            await space.audit(wctx, "my.dns.zone.dnssec", "dns_zone",
                              f"{name}:{'on' if body['enabled'] else 'off'}")
            return result

        return await run(request, work, scope="my.dns:write", write=True, zone=zone,
                         feature="dns_dnssec")

    # ---------------------------------------------------------------- workspace removal
    async def cleanup(item: dict[str, Any]) -> None:
        try:
            await service().client.request("DELETE", _path("v1", "zones", item["resource_id"]))
        except DnsError as exc:
            if exc.status_code != 404:
                raise

    space.cleanup["dns_zone"] = cleanup
