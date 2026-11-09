"""Final-phase panel routes of the DNS module (docs/41 §5, §6), under ``/api/v1/dns``.

Templates (``dns_templates``):

* ``GET templates`` / ``GET templates/{id}`` (dns:read)
* ``POST templates`` (body = template, or ``{copy_from, name?}``), ``PUT/DELETE
  templates/{id}``, ``PUT templates/default {template_id}`` (dns:admin)
* ``POST templates/{id}/preview {zone, variables?}`` (dns:read)
* ``POST zones/{zone}/apply-template {template_id, variables?, replace_conflicts?}``
  (dns:write); ``POST zones`` applies a template too (``dns.py``)

Engine proxies (docs/41 §2–§4):

* ``POST zones/{zone}/refresh`` (dns:write) - secondary refresh now
* ``GET zones/{zone}/dnssec`` (dns:read), ``POST zones/{zone}/dnssec/rollover`` (dns:write)
* ``GET tsig`` (dns:read), ``POST tsig`` / ``DELETE tsig/{name}`` (dns:admin)
* ``GET filtering/status|services`` (dns:read), ``POST filtering/refresh`` (dns:admin),
  ``POST filtering/check`` (dns:read)
* ``GET backup`` / ``POST restore`` (dns:admin)

Secrets (TSIG secrets, DNSSEC private keys) are never audited or logged and only the
TSIG create answer carries a secret back (once, as the engine returns it).
"""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import time
from collections.abc import Awaitable, Callable
from typing import Any
from urllib.parse import quote

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response

from ..dns_client import DnsError
from ..module_context import ModuleContext
from . import dns_templates as tpl
from .dns_validate import DnsInputError, canonical_zone, zone_from_path
from .dns_validate_d5 import check_body, key_name, rollover_body, strip_secrets, tsig_body

SECRET_KEYS = frozenset({"secret", "private_key", "private_key_pem", "key_pem", "private"})
BACKUP_MAX_BYTES = 128 * 1024 * 1024
BACKUP_TIMEOUT = 120.0
RESTORE_CONFIRMATION = "RESTORE"
BACKUP_MEDIA = "application/gzip"
IMPORT_TIMEOUT = 30.0

Work = Callable[[Any], Awaitable[tuple[Any, ...]]]


def _path(*parts: str) -> str:
    return "/" + "/".join(quote(part, safe="") for part in parts)


# ----------------------------------------------------------------------------- server IPs


def _global(text: Any) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        address = ipaddress.ip_address(str(text).strip().strip("[]"))
    except ValueError:
        return None
    return address if address.is_global else None


def _usable(text: Any) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        address = ipaddress.ip_address(str(text).strip().strip("[]"))
    except ValueError:
        return None
    if address.is_loopback or address.is_unspecified or address.is_multicast:
        return None
    return address


def server_ips(ctx: ModuleContext, service: Any) -> tuple[str | None, str | None]:
    """First IPv4/IPv6 of this server: ``domains.server_public_ips`` (as the owner set
    them), then global addresses the Host Agent saw DNS listening on (``port_53``)."""
    from .dns_encrypted import server_public_ips

    found: dict[int, str] = {}
    for value in server_public_ips(ctx):
        address = _usable(value)
        if address is not None and address.version not in found:
            found[address.version] = str(address)
    facts = service._facts[2] if getattr(service, "_facts", None) else None
    port_53 = facts.get("port_53") if isinstance(facts, dict) else None
    for item in (port_53.get("items") or []) if isinstance(port_53, dict) else []:
        address = _global(item.get("address")) if isinstance(item, dict) else None
        if address is not None and address.version not in found:
            found[address.version] = str(address)
    return found.get(4), found.get(6)


# ----------------------------------------------------------------------------- apply


async def plan(service: Any, template: dict[str, Any], zone: str, variables: Any,
               ) -> dict[str, Any]:
    """Preview of ``template`` on ``zone`` (the zone may not exist yet)."""
    rendered = tpl.render(template, zone, variables, server_ips(service.ctx, service))
    try:
        detail = await service.client.get(_path("v1", "zones", zone))
    except DnsError as exc:
        if exc.code != "dns_zone_not_found":
            raise
        detail = None
    if isinstance(detail, dict) and detail.get("type") not in (None, "primary"):
        raise DnsError("dns_zone_type_mismatch", 409,
                       "Templates can only be applied to primary zones",
                       fields=[{"field": "zone", "reason_code": "not_primary"}])
    existing: list[dict[str, Any]] = []
    if detail is not None:
        payload = await service.client.get(_path("v1", "zones", zone, "records"))
        existing = [item for item in (payload.get("items") or [] if isinstance(payload, dict)
                                      else []) if isinstance(item, dict)]
    current_soa = next((item for item in existing if str(item.get("type")).upper() == "SOA"),
                       None)
    items = tpl.compare(rendered, existing, current_soa)
    counts = tpl.summary(items)
    removing = {other.get("id") for item in items if item["status"] == "conflict"
                for other in item["conflicts"] if other.get("id") not in (None, "soa")}
    kept = [item for item in existing if str(item.get("type")).upper() != "SOA"
            and item.get("id") not in removing]
    effects = {
        "removes": len(removing),
        "comments_dropped": sum(1 for item in kept if item.get("comment")),
        "blocked": {"disabled": sum(1 for item in kept if item.get("disabled")),
                    "view": sum(1 for item in kept if item.get("view"))},
    }
    return {
        "template_id": template["id"], "zone": zone, "zone_exists": detail is not None,
        "variables": rendered.values, "items": items, "summary": counts,
        "can_apply": counts["conflict"] == 0, "replace_effects": effects,
        "warnings": rendered.warnings,
        "_existing": existing, "_current_soa": current_soa, "_removing": removing,
        "_soa": rendered.soa,
    }


def public_plan(value: dict[str, Any]) -> dict[str, Any]:
    return {key: item for key, item in value.items() if not key.startswith("_")}


async def apply_template(service: Any, template: dict[str, Any], zone: str, variables: Any,
                         *, replace: bool) -> dict[str, Any]:
    """One change set (one zone version) or ``dns_template_conflict`` 409."""
    preview = await plan(service, template, zone, variables)
    if not preview["zone_exists"]:
        raise DnsError("dns_zone_not_found", 404, "Zone not found")
    items = preview["items"]
    conflicts = [item for item in items if item["status"] == "conflict"]
    if conflicts and not replace:
        raise DnsError(
            "dns_template_conflict", 409,
            "Some template records clash with existing records; review and replace them",
            conflicts=[{"index": item["index"], "source": item["source"],
                        "name": item["record"]["name"], "type": item["record"]["type"]}
                       for item in conflicts[:50]],
            summary=preview["summary"],
        )
    new = [item["record"] for item in items
           if item["status"] in {"new", "conflict"} and item["source"] != "soa"]
    soa_change = any(item["source"] == "soa" and item["status"] == "conflict"
                     for item in items)
    result: dict[str, Any] = {
        "template_id": template["id"], "zone": zone, "applied": False, "mode": None,
        "added": len(new), "replaced": len(preview["_removing"]) + (1 if soa_change else 0),
        "summary": preview["summary"], "version": None, "serial": None,
        "warnings": list(preview["warnings"]),
    }
    if not new and not soa_change:
        return result
    if preview["_removing"] or soa_change:
        kept = [item for item in preview["_existing"]
                if str(item.get("type")).upper() != "SOA"
                and item.get("id") not in preview["_removing"]]
        blocked = preview["replace_effects"]["blocked"]
        if blocked["disabled"] or blocked["view"]:
            raise DnsError(
                "dns_template_replace_unsafe", 409,
                "This zone has turned-off or view-only records that a replace would lose",
                fields=[{"field": "replace_conflicts", "reason_code": "zone_has_special_records",
                         "params": blocked}],
            )
        current = preview["_current_soa"] or {}
        soa = preview["_soa"] if soa_change else {
            "ttl": current.get("ttl"), "data": current.get("data") or {}}
        try:
            text = tpl.zone_text(zone, kept + new, soa)
        except (KeyError, TypeError, ValueError):
            raise DnsError(
                "dns_template_replace_unsafe", 409,
                "This zone has records the panel cannot rewrite; remove the clashing records "
                "by hand", fields=[{"field": "replace_conflicts",
                                    "reason_code": "unsupported_record"}],
            ) from None
        mode = "replace"
        if preview["replace_effects"]["comments_dropped"]:
            result["warnings"].append({"code": "comments_dropped", "params": {
                "count": preview["replace_effects"]["comments_dropped"]}})
    else:
        text = tpl.zone_text(zone, new)
        mode = "add"
    answer = await service.client.request(
        "POST", _path("v1", "zones", zone, "import"), {"text": text, "replace": mode == "replace"},
        timeout=IMPORT_TIMEOUT,
    )
    answer = answer if isinstance(answer, dict) else {}
    result.update({"applied": True, "mode": mode, "version": answer.get("version"),
                   "serial": answer.get("serial")})
    return result


# ----------------------------------------------------------------------------- routes


def register_routes(
    ctx: ModuleContext,
    router: APIRouter,
    service: Any,
    *,
    fail: Callable[[Any], JSONResponse],
    change: Callable[..., Awaitable[Any]],
    read: Callable[..., Awaitable[Any]],
    body_of: Callable[[Request], Awaitable[Any]],
    audit: Callable[..., Awaitable[None]],
) -> None:
    store = service.templates

    def default_id() -> str:
        return str(service.get_settings().get("default_template_id") or "")

    def with_default(item: dict[str, Any]) -> dict[str, Any]:
        return {**item, "is_default": item["id"] == default_id()}

    # ---------------------------------------------------------------- templates
    @router.get("/templates", response_model=None)
    async def list_templates(request: Request) -> Any:
        async def work() -> Any:
            items = await asyncio.to_thread(store.list)
            return {"items": [with_default(item) for item in items],
                    "default_template_id": default_id() or None,
                    "variables": {"standard": list(tpl.STANDARD_VARIABLES),
                                  "automatic": list(tpl.AUTO_VARIABLES),
                                  "server": dict(zip(("ipv4", "ipv6"),
                                                     server_ips(ctx, service), strict=True))}}

        return await read(request, "dns:read", work)

    @router.put("/templates/default", response_model=None)
    async def put_default(request: Request) -> Any:
        async def work(body: Any) -> tuple[Any, str | None]:
            value = body.get("template_id") if isinstance(body, dict) else None
            if value not in (None, ""):
                await asyncio.to_thread(store.require, str(value))
            principal_id = getattr(request.state, "mrk_dns_user_id", None)
            await asyncio.to_thread(service.put_settings,
                                    {"default_template_id": value or ""}, principal_id)
            return {"default_template_id": value or None}, value or "none"

        return await change(request, "dns:admin", "dns.template.default", "dns_template", None,
                            work)

    @router.get("/templates/{identifier}", response_model=None)
    async def get_template(identifier: str, request: Request) -> Any:
        async def work() -> Any:
            return with_default(await asyncio.to_thread(store.require, identifier))

        return await read(request, "dns:read", work)

    @router.post("/templates", status_code=201, response_model=None)
    async def create_template(request: Request) -> Any:
        async def work(body: Any) -> tuple[Any, ...]:
            actor = getattr(request.state, "mrk_dns_user_id", None)
            if isinstance(body, dict) and "copy_from" in body:
                unknown = sorted(set(body) - {"copy_from", "name"})
                if unknown:
                    raise DnsInputError("dns_template_invalid", "Unknown fields",
                                        [{"field": key, "reason_code": "unknown_field"}
                                         for key in unknown])
                source = await asyncio.to_thread(store.require, str(body["copy_from"]))
                name = body.get("name") or f"{source['name_en']} (copy)"
                payload = {"name": name, "description": source["description_en"]
                           if source["builtin"] else source["description"],
                           "zone": source["zone"], "records": source["records"],
                           "variables": source["variables"]}
                clean = tpl.template_body(payload)
                created = await asyncio.to_thread(store.create, clean, actor, source["id"])
                return with_default(created), created["id"], [
                    ("dns.template.copy", "dns_template", f"{source['id']}->{created['id']}")]
            clean = tpl.template_body(body)
            created = await asyncio.to_thread(store.create, clean, actor)
            return with_default(created), created["id"]

        return await change(request, "dns:admin", "dns.template.create", "dns_template", None,
                            work)

    @router.put("/templates/{identifier}", response_model=None)
    async def update_template(identifier: str, request: Request) -> Any:
        async def work(body: Any) -> tuple[Any, str | None]:
            actor = getattr(request.state, "mrk_dns_user_id", None)
            tpl.TemplateStore._writable(identifier)
            clean = tpl.template_body(body)
            updated = await asyncio.to_thread(store.update, identifier, clean, actor)
            return with_default(updated), identifier

        return await change(request, "dns:admin", "dns.template.update", "dns_template",
                            identifier[:64], work)

    @router.delete("/templates/{identifier}", response_model=None)
    async def delete_template(identifier: str, request: Request) -> Any:
        async def work(_body: Any) -> tuple[Any, str | None]:
            await asyncio.to_thread(store.delete, identifier)
            if default_id() == identifier:
                # The default is gone: fall back to the simple website template.
                actor = getattr(request.state, "mrk_dns_user_id", None)
                await asyncio.to_thread(service.put_settings, {
                    "default_template_id": tpl.BUILTIN_IDS[0]}, actor)
            return {"deleted": identifier, "default_template_id": default_id() or None}, \
                identifier

        return await change(request, "dns:admin", "dns.template.delete", "dns_template",
                            identifier[:64], work)

    @router.post("/templates/{identifier}/preview", response_model=None)
    async def preview_template(identifier: str, request: Request) -> Any:
        principal = ctx.require_principal(request, "dns:read")
        ctx.require_csrf(request, principal)
        try:
            body = await body_of(request)
            if not isinstance(body, dict):
                raise DnsInputError("dns_template_invalid", "The request must be an object",
                                    [{"field": "body", "reason_code": "invalid_type"}])
            unknown = sorted(set(body) - {"zone", "variables"})
            if unknown:
                raise DnsInputError("dns_template_invalid", "Unknown fields",
                                    [{"field": key, "reason_code": "unknown_field"}
                                     for key in unknown])
            zone = canonical_zone(body.get("zone"), "zone")
            template = await asyncio.to_thread(store.require, identifier)
            return public_plan(await plan(service, template, zone, body.get("variables")))
        except (DnsInputError, DnsError) as exc:
            return fail(exc)

    @router.post("/zones/{zone}/apply-template", response_model=None)
    async def apply_route(zone: str, request: Request) -> Any:
        async def work(body: Any) -> tuple[Any, str | None]:
            name = zone_from_path(zone)
            if not isinstance(body, dict):
                raise DnsInputError("dns_template_invalid", "The request must be an object",
                                    [{"field": "body", "reason_code": "invalid_type"}])
            unknown = sorted(set(body) - {"template_id", "variables", "replace_conflicts"})
            if unknown:
                raise DnsInputError("dns_template_invalid", "Unknown fields",
                                    [{"field": key, "reason_code": "unknown_field"}
                                     for key in unknown])
            replace = body.get("replace_conflicts", False)
            if not isinstance(replace, bool):
                raise DnsInputError("dns_template_invalid", "replace_conflicts must be a bool",
                                    [{"field": "replace_conflicts",
                                      "reason_code": "invalid_type"}])
            if body.get("template_id") in (None, ""):
                raise DnsInputError("dns_template_invalid", "Choose a template",
                                    [{"field": "template_id", "reason_code": "required"}])
            template = await asyncio.to_thread(store.require, str(body["template_id"]))
            result = await apply_template(service, template, name, body.get("variables"),
                                          replace=replace)
            return result, f"{name}:{template['id']}"

        return await change(request, "dns:write", "dns.zone.apply_template", "dns_zone",
                            zone[:200], work)

    # ---------------------------------------------------------------- secondary / signing
    @router.post("/zones/{zone}/refresh", response_model=None)
    async def refresh_zone(zone: str, request: Request) -> Any:
        async def work(_body: Any) -> tuple[Any, str | None]:
            name = zone_from_path(zone)
            result = await service.client.request("POST", _path("v1", "zones", name, "refresh"),
                                                  {}, timeout=30.0)
            return result, name

        return await change(request, "dns:write", "dns.zone.refresh", "dns_zone", zone[:255],
                            work)

    @router.get("/zones/{zone}/dnssec", response_model=None)
    async def zone_dnssec(zone: str, request: Request) -> Any:
        async def work() -> Any:
            payload = await service.client.get(_path("v1", "zones", zone_from_path(zone),
                                                     "dnssec"))
            return strip_secrets(payload, SECRET_KEYS)

        return await read(request, "dns:read", work)

    @router.post("/zones/{zone}/dnssec/rollover", response_model=None)
    async def zone_rollover(zone: str, request: Request) -> Any:
        async def work(body: Any) -> tuple[Any, str | None]:
            name = zone_from_path(zone)
            payload = rollover_body(body)
            result = await service.client.request(
                "POST", _path("v1", "zones", name, "dnssec", "rollover"), payload, timeout=30.0)
            return strip_secrets(result, SECRET_KEYS), f"{name}:{payload['role']}"

        return await change(request, "dns:write", "dns.zone.dnssec_rollover", "dns_zone",
                            zone[:255], work)

    # ---------------------------------------------------------------- TSIG
    @router.get("/tsig", response_model=None)
    async def list_tsig(request: Request) -> Any:
        async def work() -> Any:
            return strip_secrets(await service.client.get("/v1/tsig"), SECRET_KEYS)

        return await read(request, "dns:read", work)

    @router.post("/tsig", status_code=201, response_model=None)
    async def create_tsig(request: Request) -> Any:
        async def work(body: Any) -> tuple[Any, str | None]:
            payload = tsig_body(body)
            # The answer carries the secret once (generated or echoed); never stored here.
            result = await service.client.request("POST", "/v1/tsig", payload)
            return result, payload["name"]

        return await change(request, "dns:admin", "dns.tsig.create", "dns_tsig", None, work)

    @router.delete("/tsig/{name}", response_model=None)
    async def delete_tsig(name: str, request: Request) -> Any:
        async def work(_body: Any) -> tuple[Any, str | None]:
            canonical = key_name(name)
            if canonical is None:
                raise DnsInputError("dns_tsig_invalid", "Invalid key name",
                                    [{"field": "name", "reason_code": "invalid_key_name"}])
            await service.client.request("DELETE", _path("v1", "tsig", canonical))
            return {"deleted": canonical}, canonical

        return await change(request, "dns:admin", "dns.tsig.delete", "dns_tsig", name[:255],
                            work)

    # ---------------------------------------------------------------- filtering
    @router.get("/filtering/status", response_model=None)
    async def filtering_status(request: Request) -> Any:
        return await read(request, "dns:read",
                          lambda: service.client.get("/v1/filtering/status"))

    @router.get("/filtering/services", response_model=None)
    async def filtering_services(request: Request) -> Any:
        return await read(request, "dns:read",
                          lambda: service.client.get("/v1/filtering/services"))

    @router.post("/filtering/refresh", response_model=None)
    async def filtering_refresh(request: Request) -> Any:
        async def work(_body: Any) -> tuple[Any, str | None]:
            result = await service.client.request("POST", "/v1/filtering/refresh", {},
                                                  timeout=90.0)
            return result, "lists"

        return await change(request, "dns:admin", "dns.filtering.refresh", "dns_filtering",
                            None, work)

    @router.post("/filtering/check", response_model=None)
    async def filtering_check(request: Request) -> Any:
        principal = ctx.require_principal(request, "dns:read")
        ctx.require_csrf(request, principal)
        try:
            payload = check_body(await body_of(request))
            return await service.client.request("POST", "/v1/filtering/check", payload)
        except (DnsInputError, DnsError) as exc:
            return fail(exc)

    # ---------------------------------------------------------------- backup / restore
    @router.get("/backup", response_model=None)
    async def download_backup(request: Request) -> Any:
        principal = ctx.require_principal(request, "dns:admin")
        try:
            data = await service.client.request("GET", "/v1/backup", raw=True,
                                                max_bytes=BACKUP_MAX_BYTES,
                                                timeout=BACKUP_TIMEOUT)
        except DnsError as exc:
            if exc.status_code not in {404, 422}:
                await audit(principal, "dns.backup.download", "dns_backup", None, "failure")
            return fail(exc)
        digest = hashlib.sha256(data).hexdigest()[:16]
        await audit(principal, "dns.backup.download", "dns_backup",
                    f"sha256:{digest},bytes={len(data)}")
        name = time.strftime("mrk-dns-backup-%Y%m%d-%H%M%S.tar.gz", time.gmtime())
        return Response(content=data, media_type=BACKUP_MEDIA,
                        headers={"Content-Disposition": f'attachment; filename="{name}"'})

    @router.post("/restore", response_model=None)
    async def restore_backup(request: Request) -> Any:
        principal = ctx.require_principal(request, "dns:admin")
        ctx.require_csrf(request, principal)
        confirmation = request.query_params.get("confirmation", "")
        if confirmation.strip().upper() != RESTORE_CONFIRMATION:
            return fail(DnsError(
                "confirmation_mismatch", 422, "Type RESTORE to confirm",
                fields=[{"field": "confirmation", "reason_code": "incorrect"}],
                expected_confirmation=RESTORE_CONFIRMATION,
            ))
        data = bytearray()
        async for chunk in request.stream():
            data.extend(chunk)
            if len(data) > BACKUP_MAX_BYTES:
                return fail(DnsInputError(
                    "dns_request_too_large", "The backup file is too large",
                    [{"field": "file", "reason_code": "too_large",
                      "params": {"max_bytes": BACKUP_MAX_BYTES}}], 413))
        if len(data) < 18 or bytes(data[:2]) != b"\x1f\x8b":
            return fail(DnsInputError(
                "dns_restore_invalid", "Choose a DNS backup file (.tar.gz)",
                [{"field": "file", "reason_code": "required" if not data else "not_gzip"}]))
        digest = hashlib.sha256(bytes(data)).hexdigest()[:16]
        object_id = f"sha256:{digest},bytes={len(data)}"
        try:
            result = await service.client.request(
                "POST", "/v1/restore", content=bytes(data), content_type=BACKUP_MEDIA,
                timeout=BACKUP_TIMEOUT,
            )
        except DnsError as exc:
            await audit(principal, "dns.backup.restore", "dns_backup", object_id, "failure")
            return fail(exc)
        service.invalidate_settings()
        service._setup = None
        service._status_at = 0.0
        await audit(principal, "dns.backup.restore", "dns_backup", object_id)
        return strip_secrets(result, SECRET_KEYS)
