"""D4 panel routes of the DNS module: DNSSEC, certificates, DoH tokens and device
guides for encrypted DNS (docs/40 §5).

* ``GET dnssec`` (dns:read), ``POST dnssec/refresh`` (dns:admin).
* ``GET tls`` (dns:read); ``PUT tls``, ``POST tls/self-signed``, ``DELETE tls``
  (dns:admin). The private key is forwarded once to the engine and never logged,
  audited or returned.
* ``GET doh/tokens`` (dns:read); ``POST doh/tokens``, ``PATCH/DELETE doh/tokens/{id}``
  (dns:admin). The token itself is in the create answer only.
* ``POST encrypted/apple-profile`` (dns:read) -> ``.mobileconfig``;
  ``GET encrypted/clients`` (dns:read) -> per-device setup state.
"""

from __future__ import annotations

import asyncio
import ipaddress
import time
from collections.abc import Awaitable, Callable
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response
from sqlalchemy import select

from ..dns_client import DnsError
from ..models import ServiceDomain
from ..module_context import ModuleContext
from .dns_validate import DnsInputError, entity_id
from .dns_validate_d4 import (
    apple_profile,
    apple_profile_body,
    listen_on,
    section_of,
    self_signed_body,
    tls_upload_body,
    token_create_body,
    token_patch_body,
)

DOH_SERVICE_ID = "dns-doh"
GUIDES = ("android", "ios", "windows", "macos", "linux", "firefox", "chrome")
# Keys an engine TLS answer must never carry back to a browser.
SECRET_KEYS = frozenset({"key_pem", "private_key", "key", "private_key_pem"})
PROFILE_FILE = "mrk-dns.mobileconfig"
PROFILE_MEDIA = "application/x-apple-aspen-config"


def public_tls(payload: Any) -> Any:
    if not isinstance(payload, dict):
        return payload
    return {key: value for key, value in payload.items() if key not in SECRET_KEYS}


def doh_domains(ctx: ModuleContext) -> list[dict[str, Any]]:
    """Domains of the ``dns-doh`` service (plain DoH behind Traefik), primary first."""
    with ctx.database.session() as db:
        rows = list(db.scalars(select(ServiceDomain).where(
            ServiceDomain.service_id == DOH_SERVICE_ID)))
    items = [{"host": row.host, "https": bool(row.https), "primary": bool(row.primary)}
             for row in rows]
    return sorted(items, key=lambda item: (not item["primary"], item["host"]))


def server_public_ips(ctx: ModuleContext) -> list[str]:
    from . import services as services_module

    service = services_module.ACTIVE_SERVICE
    if service is None or service.ctx is not ctx:
        return []
    try:
        values = service.get_settings().get("server_public_ips") or []
    except Exception:  # noqa: BLE001 - an optional hint
        return []
    return [str(item) for item in values if isinstance(item, str)]


def _cert_name(tls: dict[str, Any] | None) -> str | None:
    """First DNS name (no wildcard, no IP) of the engine certificate."""
    for name in (tls or {}).get("names") or []:
        if not isinstance(name, str) or not name or name.startswith("*"):
            continue
        try:
            ipaddress.ip_address(name)
        except ValueError:
            return name.lower().rstrip(".")
    return None


def _listen(section: dict[str, Any], default_port: int) -> list[tuple[Any, int]]:
    out = []
    for item in section.get("listen") or []:
        try:
            out.append(listen_on(item, default_port))
        except ValueError:
            continue
    return out


def _host(text: str) -> str:
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return text
    return f"[{address}]" if address.version == 6 else str(address)


def certificate_trusted(tls: dict[str, Any] | None, now: float | None = None) -> bool:
    """A present, CA-issued (not self-signed), unexpired certificate."""
    if not isinstance(tls, dict) or not tls.get("present"):
        return False
    if tls.get("self_signed") or tls.get("source") == "self_signed":
        return False
    not_after = tls.get("not_after")
    if isinstance(not_after, str) and not_after:
        from .dns_validate_d4 import rfc3339

        parsed = rfc3339(not_after)
        if parsed is not None and parsed.timestamp() <= (now or time.time()):
            return False
    return True


def clients_view(
    settings: dict[str, Any] | None, tls: dict[str, Any] | None,
    domains: list[dict[str, Any]], public_ips: list[str],
) -> dict[str, Any]:
    """What a device needs, from the engine's current settings and certificate."""
    settings = settings if isinstance(settings, dict) else {}
    dot, doq, doh = (section_of(settings, name) for name in ("dot", "doq", "doh"))
    dot_on, doq_on, doh_on = (item.get("enabled") is True for item in (dot, doq, doh))
    plain = doh.get("tls", True) is False
    path = doh.get("path") if isinstance(doh.get("path"), str) and doh.get("path") else (
        "/dns-query")
    name = _cert_name(tls)
    ip = public_ips[0] if public_ips else None
    if ip is None:
        for section, port in ((dot, 853), (doq, 853), (doh, 443)):
            for address, _port in _listen(section, port):
                if not (address.is_unspecified or address.is_loopback):
                    ip = str(address)
                    break
            if ip:
                break
    cert_ok = certificate_trusted(tls)
    doh_url: str | None = None
    doh_trusted = False
    if doh_on and plain:
        domain = next((item for item in domains if item["https"]), None)
        if domain is not None:
            doh_url = f"https://{domain['host']}{path}"
            doh_trusted = True  # Traefik's certificate (Let's Encrypt)
    elif doh_on:
        listen = _listen(doh, 443)
        reachable = [item for item in listen if not item[0].is_loopback]
        if reachable:
            address, port = reachable[0]
            host = name or ip or (None if address.is_unspecified else str(address))
            if host:
                netloc = _host(host) if port == 443 else f"{_host(host)}:{port}"
                doh_url = f"https://{netloc}{path}"
                doh_trusted = cert_ok
    view: dict[str, Any] = {
        "doh_url": doh_url,
        "dot_name": name if dot_on else None,
        "doq_name": name if doq_on else None,
        "ip": ip,
        "certificate": {
            "trusted": cert_ok or (doh_trusted and plain),
            "present": bool((tls or {}).get("present")),
            "self_signed": bool((tls or {}).get("self_signed")),
            "source": (tls or {}).get("source"),
            "not_after": (tls or {}).get("not_after"),
        },
        "enabled": {"dot": dot_on, "doh": doh_on, "doq": doq_on},
        "plain_doh": doh_on and plain,
    }
    any_on = dot_on or doh_on or doq_on
    dot_ready = dot_on and name is not None

    def guide(gid: str) -> dict[str, Any]:
        reason: str | None = None
        if not any_on:
            reason = "encrypted_disabled"
        elif gid == "android":
            reason = ("dot_disabled" if not dot_on else "no_hostname" if name is None
                      else None if cert_ok else "certificate_untrusted")
        elif gid in {"ios", "macos"}:
            if doh_url and doh_trusted or dot_ready and cert_ok:
                reason = None
            elif doh_url or dot_ready:
                reason = "certificate_untrusted"
            else:
                reason = "no_hostname"
        elif gid in {"windows", "firefox", "chrome"}:
            if not doh_on:
                reason = "doh_disabled"
            elif doh_url is None:
                reason = "no_doh_url"
            elif not doh_trusted:
                reason = "certificate_untrusted"
            elif gid == "windows" and ip is None:
                reason = "no_ip"
        elif gid == "linux":
            reason = ("dot_disabled" if not dot_on else "no_ip" if ip is None
                      else None if cert_ok else "certificate_untrusted")
        item: dict[str, Any] = {"id": gid, "available": reason is None}
        if reason:
            item["reason"] = reason
        return item

    view["guides"] = [guide(gid) for gid in GUIDES]
    return view


def register_routes(
    ctx: ModuleContext,
    router: APIRouter,
    service: Any,
    *,
    fail: Callable[[Any], JSONResponse],
    change: Callable[..., Awaitable[Any]],
    read: Callable[..., Awaitable[Any]],
    body_of: Callable[[Request], Awaitable[Any]],
) -> None:
    client = service.client

    async def current_clients() -> dict[str, Any]:
        settings = await service.current_settings(refresh=True)
        try:
            tls = await client.get("/v1/tls")
        except DnsError as exc:
            if exc.code in {"dns_unreachable", "dns_not_installed"}:
                raise
            tls = None
        domains = await asyncio.to_thread(doh_domains, ctx)
        return clients_view(settings, public_tls(tls), domains, server_public_ips(ctx))

    # ---------------------------------------------------------------- dnssec
    @router.get("/dnssec", response_model=None)
    async def get_dnssec(request: Request) -> Any:
        return await read(request, "dns:read", lambda: client.get("/v1/dnssec"))

    @router.post("/dnssec/refresh", response_model=None)
    async def refresh_dnssec(request: Request) -> Any:
        async def work(_body: Any) -> tuple[Any, str | None]:
            result = await client.request("POST", "/v1/dnssec/refresh", {}, timeout=30.0)
            return result, "trust_anchors"

        return await change(request, "dns:admin", "dns.dnssec.refresh", "dns_dnssec",
                            "trust_anchors", work)

    # ---------------------------------------------------------------- tls
    @router.get("/tls", response_model=None)
    async def get_tls(request: Request) -> Any:
        async def work() -> Any:
            return public_tls(await client.get("/v1/tls"))

        return await read(request, "dns:read", work)

    @router.put("/tls", response_model=None)
    async def put_tls(request: Request) -> Any:
        async def work(body: Any) -> tuple[Any, str | None]:
            payload = tls_upload_body(body)
            result = public_tls(await client.request("PUT", "/v1/tls", payload, timeout=15.0))
            fingerprint = result.get("fingerprint_sha256") if isinstance(result, dict) else None
            service.invalidate_settings()
            return result, str(fingerprint)[:255] if fingerprint else None

        return await change(request, "dns:admin", "dns.tls.upload", "dns_tls", None, work)

    @router.post("/tls/self-signed", response_model=None)
    async def self_signed(request: Request) -> Any:
        async def work(body: Any) -> tuple[Any, str | None]:
            payload = self_signed_body(body)
            result = public_tls(await client.request("POST", "/v1/tls/self-signed", payload,
                                                     timeout=15.0))
            service.invalidate_settings()
            return result, ",".join(payload["names"])[:255]

        return await change(request, "dns:admin", "dns.tls.self_signed", "dns_tls", None, work)

    @router.delete("/tls", response_model=None)
    async def delete_tls(request: Request) -> Any:
        async def work(_body: Any) -> tuple[Any, str | None]:
            await client.request("DELETE", "/v1/tls")
            service.invalidate_settings()
            return {"deleted": True}, "certificate"

        return await change(request, "dns:admin", "dns.tls.delete", "dns_tls", "certificate",
                            work)

    # ---------------------------------------------------------------- doh tokens
    @router.get("/doh/tokens", response_model=None)
    async def list_tokens(request: Request) -> Any:
        return await read(request, "dns:read", lambda: client.get("/v1/doh/tokens"))

    @router.post("/doh/tokens", status_code=201, response_model=None)
    async def create_token(request: Request) -> Any:
        async def work(body: Any) -> tuple[Any, str | None]:
            payload = token_create_body(body)
            result = await client.request("POST", "/v1/doh/tokens", payload)
            if not isinstance(result, dict):
                raise DnsError("dns_unreachable", 502, "The DNS engine answer is invalid",
                               reason="invalid_response")
            token = result.get("token")
            try:
                base = (await current_clients()).get("doh_url")
            except DnsError:
                base = None
            result = dict(result)
            result["urls"] = {
                "doh": f"{base.rstrip('/')}/{token}" if base and isinstance(token, str)
                and token else None,
            }
            return result, str(result.get("id") or "")[:255] or None

        return await change(request, "dns:admin", "dns.doh_token.create", "dns_doh_token",
                            None, work)

    @router.patch("/doh/tokens/{token_id}", response_model=None)
    async def patch_token(token_id: str, request: Request) -> Any:
        async def work(body: Any) -> tuple[Any, str | None]:
            tid = entity_id(token_id)
            payload = token_patch_body(body)
            result = await client.request("PATCH", f"/v1/doh/tokens/{tid}", payload)
            return result, tid

        return await change(request, "dns:admin", "dns.doh_token.update", "dns_doh_token",
                            token_id[:255], work)

    @router.delete("/doh/tokens/{token_id}", response_model=None)
    async def delete_token(token_id: str, request: Request) -> Any:
        async def work(_body: Any) -> tuple[Any, str | None]:
            tid = entity_id(token_id)
            await client.request("DELETE", f"/v1/doh/tokens/{tid}")
            return {"deleted": tid}, tid

        return await change(request, "dns:admin", "dns.doh_token.delete", "dns_doh_token",
                            token_id[:255], work)

    # ---------------------------------------------------------------- devices
    @router.get("/encrypted/clients", response_model=None)
    async def encrypted_clients(request: Request) -> Any:
        return await read(request, "dns:read", current_clients)

    @router.post("/encrypted/apple-profile", response_model=None)
    async def apple_profile_route(request: Request) -> Any:
        principal = ctx.require_principal(request, "dns:read")
        ctx.require_csrf(request, principal)
        try:
            inputs = apple_profile_body(await body_of(request))
            doh_url, dot_name = inputs["doh_url"], inputs["dot_name"]
            if not doh_url and not dot_name:
                view = await current_clients()
                doh_url, dot_name = view.get("doh_url"), view.get("dot_name")
            if not doh_url and not dot_name:
                raise DnsInputError(
                    "dns_profile_invalid", "Turn on DoH or DoT first, or enter an address",
                    [{"field": "doh_url", "reason_code": "required"}])
            content = apple_profile(doh_url=doh_url, dot_name=None if doh_url else dot_name,
                                    name=inputs["name"])
        except (DnsInputError, DnsError) as exc:
            return fail(exc)
        return Response(
            content=content, media_type=PROFILE_MEDIA,
            headers={"Content-Disposition": f'attachment; filename="{PROFILE_FILE}"'},
        )
