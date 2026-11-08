"""Panel API for outbound proxy profiles and the per-service proxy toggle.

GET    /api/v1/settings/proxies                       upstream:read
POST   /api/v1/settings/proxies                       upstream:write + CSRF
PATCH  /api/v1/settings/proxies/{id}                  upstream:write + CSRF
DELETE /api/v1/settings/proxies/{id}                  upstream:write + CSRF
PUT    /api/v1/settings/proxies/default               upstream:write + CSRF
POST   /api/v1/settings/proxies/{id}/test             upstream:write + CSRF
GET    /api/v1/settings/outbound-services             upstream:read (entries filtered by
                                                      each provider's read permission)
PUT    /api/v1/settings/outbound-services/{kind}/{id} provider write permission + CSRF
"""

from __future__ import annotations

import asyncio
import json
import time
from collections.abc import Callable
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from .middleware import correlation_id_context
from .netresolve import NetworkSettingsStore
from .outbound import (
    DEFAULT_TEST_URL,
    MAX_PROXIES,
    OutboundError,
    OutboundProvider,
    OutboundRegistry,
    ProxyProfile,
    check_reference,
    get_profile,
    list_profiles,
    new_proxy_id,
    probe_proxy,
    users_of,
    validate_host,
    validate_name,
    validate_no_proxy,
    validate_password,
    validate_port,
    validate_type,
    validate_username,
)
from .secret_store import SecretStore

_CREATE_FIELDS = {"name", "type", "host", "port", "username", "password", "enabled", "no_proxy"}


def _now() -> int:
    return int(time.time())


class ProxyService:
    """Blocking proxy-profile operations (run them with ``asyncio.to_thread``)."""

    def __init__(
        self,
        network: NetworkSettingsStore,
        secret_store: SecretStore,
        registry: OutboundRegistry,
    ) -> None:
        self.network = network
        self.secrets = secret_store
        self.registry = registry

    # ---- reads ----

    def list(self, can_read: Callable[[str], bool] = lambda _kind: True) -> dict[str, Any]:
        entries = self.registry.entries()
        default_id = self.network.default_proxy_id()
        visible = [entry for entry in entries if can_read(entry["kind"])]
        items = []
        for profile in list_profiles(self.network):
            item = profile.public()
            item["is_default"] = profile.id == default_id
            item["used_by"] = users_of(visible, profile.id, default_id)
            items.append(item)
        return {"items": items, "default_proxy_id": default_id}

    def get(self, proxy_id: str) -> ProxyProfile:
        return get_profile(self.network, proxy_id)

    def public(self, profile: ProxyProfile) -> dict[str, Any]:
        default_id = self.network.default_proxy_id()
        item = profile.public()
        item["is_default"] = profile.id == default_id
        item["used_by"] = users_of(self.registry.entries(), profile.id, default_id)
        return item

    # ---- compatibility ----

    def _check_users_accept(self, users: list[dict[str, Any]], proxy_type: str) -> None:
        entries = {(item["kind"], item["id"]): item for item in self.registry.entries()}
        for user in users:
            entry = entries.get((user["kind"], user["id"]))
            provider = self.registry.provider(user["kind"])
            if entry is None or provider is None:
                continue
            if proxy_type not in provider.supported_types(entry):
                raise OutboundError(
                    provider.unsupported_code,
                    f"{entry['name']} cannot use a {proxy_type} proxy",
                    409,
                )

    def affected(self, proxy_id: str, default_id: str | None = None) -> list[dict[str, Any]]:
        entries = self.registry.entries()
        current_default = self.network.default_proxy_id() if default_id is None else default_id
        users = users_of(entries, proxy_id, current_default)
        wanted = {(item["kind"], item["id"]) for item in users}
        return [entry for entry in entries if (entry["kind"], entry["id"]) in wanted]

    # ---- writes ----

    def create(self, payload: Any) -> ProxyProfile:
        if not isinstance(payload, dict):
            raise OutboundError("invalid_request", "body must be an object")
        unknown = set(payload) - _CREATE_FIELDS
        if unknown:
            raise OutboundError("invalid_request", f"unsupported field: {sorted(unknown)[0]}")
        enabled = payload.get("enabled", True)
        if not isinstance(enabled, bool):
            raise OutboundError("invalid_enabled", "enabled must be a boolean")
        username = payload.get("username") or None
        password = payload.get("password") or None
        now = _now()
        profile = ProxyProfile(
            id=new_proxy_id(),
            name=validate_name(payload.get("name")),
            type=validate_type(payload.get("type")),
            host=validate_host(payload.get("host")),
            port=validate_port(payload.get("port")),
            username=validate_username(username) if username is not None else None,
            enabled=enabled,
            no_proxy=validate_no_proxy(payload.get("no_proxy") or []),
            created_at=now,
            updated_at=now,
        )
        if password is not None:
            validate_password(password)
            if profile.username is None:
                raise OutboundError(
                    "proxy_password_without_username", "a password needs a username"
                )
        secret_ref = self.secrets.replace(None, {"password": password})[0] if password else None
        profile = ProxyProfile(**{**_fields(profile), "secret_ref": secret_ref})

        def change(
            items: list[dict[str, object]], default_id: str | None
        ) -> tuple[list[dict[str, object]], str | None, None]:
            if len(items) >= MAX_PROXIES:
                raise OutboundError("too_many_proxies", f"at most {MAX_PROXIES} proxies", 409)
            _ensure_unique_name(items, profile.name, None)
            return [*items, profile.stored()], default_id, None

        try:
            self.network.mutate_proxies(change)
        except Exception:
            if secret_ref:
                self.secrets.delete(secret_ref)
            raise
        return profile

    def update(self, proxy_id: str, payload: Any) -> ProxyProfile:
        if not isinstance(payload, dict):
            raise OutboundError("invalid_request", "body must be an object")
        unknown = set(payload) - _CREATE_FIELDS
        if unknown:
            raise OutboundError("invalid_request", f"unsupported field: {sorted(unknown)[0]}")
        current = self.get(proxy_id)
        values = _fields(current)
        if "name" in payload:
            values["name"] = validate_name(payload["name"])
        if "type" in payload:
            values["type"] = validate_type(payload["type"])
        if "host" in payload:
            values["host"] = validate_host(payload["host"])
        if "port" in payload:
            values["port"] = validate_port(payload["port"])
        if "enabled" in payload:
            if not isinstance(payload["enabled"], bool):
                raise OutboundError("invalid_enabled", "enabled must be a boolean")
            values["enabled"] = payload["enabled"]
        if "no_proxy" in payload:
            values["no_proxy"] = validate_no_proxy(payload["no_proxy"] or [])
        if "username" in payload:
            username = payload["username"] or None
            values["username"] = validate_username(username) if username is not None else None
        password_change: str | None = None  # None: keep; "": clear; else: replace
        if "password" in payload:
            raw = payload["password"]
            password_change = "" if raw is None else validate_password(raw)
        if values["username"] is None and current.secret_ref and password_change is None:
            password_change = ""  # dropping the username drops its password
        if password_change and values["username"] is None:
            raise OutboundError("proxy_password_without_username", "a password needs a username")
        moved = (values["host"], values["port"]) != (current.host, current.port)
        if moved and current.secret_ref and password_change is None:
            # Otherwise someone who cannot read the password could point the profile
            # at their own host and receive it with the next connection test.
            raise OutboundError(
                "proxy_credential_host_change",
                "re-enter or clear the password when moving a proxy to another host",
                409,
            )
        if values["type"] != current.type:
            self._check_users_accept(self.affected(proxy_id), str(values["type"]))
        new_ref: str | None = None
        old_ref_to_delete: str | None = None
        if password_change:
            new_ref = self.secrets.replace(current.secret_ref, {"password": password_change})[0]
            values["secret_ref"] = new_ref
        elif password_change == "":
            old_ref_to_delete = current.secret_ref
            values["secret_ref"] = None
        values["updated_at"] = _now()
        profile = ProxyProfile(**values)

        def change(
            items: list[dict[str, object]], default_id: str | None
        ) -> tuple[list[dict[str, object]], str | None, None]:
            index = next((i for i, item in enumerate(items) if item.get("id") == proxy_id), None)
            if index is None:
                raise KeyError(proxy_id)
            _ensure_unique_name(items, profile.name, proxy_id)
            items[index] = profile.stored()
            return items, default_id, None

        try:
            self.network.mutate_proxies(change)
        except Exception:
            if new_ref and not current.secret_ref:
                self.secrets.delete(new_ref)
            raise
        if old_ref_to_delete:
            self.secrets.delete(old_ref_to_delete)
        return profile

    def delete(self, proxy_id: str, confirmation: Any) -> ProxyProfile:
        current = self.get(proxy_id)
        if not isinstance(confirmation, str) or confirmation.strip() != current.name:
            raise OutboundError("confirmation_mismatch", "type the exact proxy name", 409)
        users = users_of(self.registry.entries(), proxy_id, self.network.default_proxy_id())
        if users:
            raise ProxyInUse(users)

        def change(
            items: list[dict[str, object]], default_id: str | None
        ) -> tuple[list[dict[str, object]], str | None, None]:
            remaining = [item for item in items if item.get("id") != proxy_id]
            if len(remaining) == len(items):
                raise KeyError(proxy_id)
            return remaining, None if default_id == proxy_id else default_id, None

        self.network.mutate_proxies(change)
        if current.secret_ref:
            self.secrets.delete(current.secret_ref)
        return current

    def set_default(self, proxy_id: Any) -> str | None:
        if proxy_id is not None and not isinstance(proxy_id, str):
            raise OutboundError("invalid_proxy_id", "proxy_id must be a proxy id or null")
        proxy_id = proxy_id or None
        entries = self.registry.entries()
        default_users = [entry for entry in entries if entry.get("proxy_id") == "default"]
        if proxy_id is None:
            if default_users:
                raise ProxyInUse(
                    [
                        {"kind": e["kind"], "id": e["id"], "name": e["name"], "via_default": True}
                        for e in default_users
                    ]
                )
        else:
            profile = self.get(proxy_id)
            self._check_users_accept(
                [{"kind": e["kind"], "id": e["id"]} for e in default_users], profile.type
            )

        def change(
            items: list[dict[str, object]], _default_id: str | None
        ) -> tuple[list[dict[str, object]], str | None, None]:
            if proxy_id is not None and not any(item.get("id") == proxy_id for item in items):
                raise KeyError(proxy_id)
            return items, proxy_id, None

        self.network.mutate_proxies(change)
        return proxy_id


class ProxyInUse(OutboundError):
    def __init__(self, users: list[dict[str, Any]]) -> None:
        super().__init__("proxy_in_use", "the proxy is used by other services", 409)
        self.users = users


def _fields(profile: ProxyProfile) -> dict[str, Any]:
    return {name: getattr(profile, name) for name in ProxyProfile.__slots__}


def _ensure_unique_name(items: list[dict[str, object]], name: str, exclude: str | None) -> None:
    if any(
        str(item.get("name", "")).lower() == name.lower() and item.get("id") != exclude
        for item in items
    ):
        raise OutboundError("proxy_name_taken", "a proxy with this name exists", 409)


async def _json(request: Request) -> Any:
    raw = await request.body()
    if not raw:
        return {}
    try:
        return json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        raise OutboundError("invalid_json", "request body must be JSON") from None


def build_router(
    *,
    network: NetworkSettingsStore,
    secret_store: SecretStore,
    registry: OutboundRegistry,
    require_principal: Callable[..., Any],
    require_csrf: Callable[..., None],
    error_payload: Callable[[str, str, int], JSONResponse],
    record_audit: Callable[..., None],
) -> APIRouter:
    router = APIRouter(prefix="/api/v1/settings", include_in_schema=False)
    service = ProxyService(network, secret_store, registry)

    def fail(exc: OutboundError) -> JSONResponse:
        response = error_payload(exc.code, exc.message, exc.status_code)
        if isinstance(exc, ProxyInUse):
            body = json.loads(response.body)
            body["error"]["used_by"] = exc.users
            response = JSONResponse(status_code=exc.status_code, content=body)
        return response

    async def audit(
        request: Request, user_id: int, action: str, object_id: str | None, result: str = "success"
    ) -> None:
        await asyncio.to_thread(
            record_audit,
            user_id,
            action,
            "proxy" if action.startswith("settings.proxy") else "outbound_service",
            None if object_id is None else object_id[:255],
            result,
            request.client.host if request.client else None,
            correlation_id_context.get(),
        )

    def writer(request: Request, permission: str = "upstream:write") -> Any:
        principal = require_principal(request, permission)
        require_csrf(request, principal)
        return principal

    def reader_filter(principal: Any) -> Callable[[str], bool]:
        def can_read(kind: str) -> bool:
            provider = registry.provider(kind)
            return provider is not None and principal.allows(provider.read_permission)

        return can_read

    async def notify(entries: list[dict[str, Any]]) -> None:
        by_kind: dict[str, list[dict[str, Any]]] = {}
        for entry in entries:
            by_kind.setdefault(entry["kind"], []).append(entry)
        for kind, items in by_kind.items():
            provider = registry.provider(kind)
            if provider is not None and provider.on_change is not None:
                await provider.on_change(items)

    @router.get("/proxies")
    async def list_proxies(request: Request) -> dict[str, Any]:
        principal = require_principal(request, "upstream:read")
        return await asyncio.to_thread(service.list, reader_filter(principal))

    @router.post("/proxies", status_code=201, response_model=None)
    async def create_proxy(request: Request) -> dict[str, Any] | JSONResponse:
        principal = writer(request)
        try:
            profile = await asyncio.to_thread(service.create, await _json(request))
        except OutboundError as exc:
            await audit(request, principal.user_id, "settings.proxy.create", None, "failure")
            return fail(exc)
        await audit(request, principal.user_id, "settings.proxy.create", profile.id)
        return await asyncio.to_thread(service.public, profile)

    @router.put("/proxies/default", response_model=None)
    async def set_default_proxy(request: Request) -> dict[str, Any] | JSONResponse:
        principal = writer(request)
        try:
            body = await _json(request)
            if not isinstance(body, dict) or "proxy_id" not in body:
                raise OutboundError("invalid_request", "proxy_id is required (null clears)")
            previous = network.default_proxy_id()
            before = await asyncio.to_thread(service.affected, previous) if previous else []
            value = await asyncio.to_thread(service.set_default, body["proxy_id"])
        except KeyError:
            raise StarletteHTTPException(status_code=404) from None
        except OutboundError as exc:
            await audit(request, principal.user_id, "settings.proxy.default", None, "failure")
            return fail(exc)
        after = await asyncio.to_thread(service.affected, value) if value else []
        await notify(_dedupe(before + after))
        await audit(request, principal.user_id, "settings.proxy.default", value or "none")
        return {"default_proxy_id": value}

    @router.patch("/proxies/{proxy_id}", response_model=None)
    async def update_proxy(proxy_id: str, request: Request) -> dict[str, Any] | JSONResponse:
        principal = writer(request)
        try:
            profile = await asyncio.to_thread(service.update, proxy_id, await _json(request))
        except KeyError:
            raise StarletteHTTPException(status_code=404) from None
        except OutboundError as exc:
            await audit(request, principal.user_id, "settings.proxy.update", proxy_id, "failure")
            return fail(exc)
        await notify(await asyncio.to_thread(service.affected, proxy_id))
        await audit(request, principal.user_id, "settings.proxy.update", proxy_id)
        return await asyncio.to_thread(service.public, profile)

    @router.delete("/proxies/{proxy_id}", response_model=None)
    async def delete_proxy(proxy_id: str, request: Request) -> dict[str, Any] | JSONResponse:
        principal = writer(request)
        try:
            body = await _json(request)
            confirmation = body.get("confirmation") if isinstance(body, dict) else None
            await asyncio.to_thread(service.delete, proxy_id, confirmation)
        except KeyError:
            raise StarletteHTTPException(status_code=404) from None
        except OutboundError as exc:
            await audit(request, principal.user_id, "settings.proxy.delete", proxy_id, "failure")
            return fail(exc)
        await audit(request, principal.user_id, "settings.proxy.delete", proxy_id)
        return {"deleted": True, "id": proxy_id}

    @router.post("/proxies/{proxy_id}/test", response_model=None)
    async def test_proxy_endpoint(
        proxy_id: str, request: Request
    ) -> dict[str, Any] | JSONResponse:
        principal = writer(request)
        try:
            body = await _json(request)
            if not isinstance(body, dict):
                raise OutboundError("invalid_request", "body must be an object")
            url = body.get("url") or DEFAULT_TEST_URL
            if not isinstance(url, str) or len(url) > 2000 or any(c in url for c in "\r\n\t "):
                raise OutboundError("invalid_url", "url must be an http(s) URL")
            profile = await asyncio.to_thread(service.get, proxy_id)
        except KeyError:
            raise StarletteHTTPException(status_code=404) from None
        except OutboundError as exc:
            return fail(exc)
        result = await probe_proxy(network, secret_store, profile, url)
        await audit(
            request,
            principal.user_id,
            "settings.proxy.test",
            proxy_id,
            "success" if result["ok"] else "failure",
        )
        return result

    @router.get("/outbound-services")
    async def outbound_services(request: Request) -> dict[str, Any]:
        principal = require_principal(request, "upstream:read")
        can_read = reader_filter(principal)
        entries = await asyncio.to_thread(registry.entries)
        return {
            "items": [entry for entry in entries if can_read(entry["kind"])],
            "default_proxy_id": network.default_proxy_id(),
        }

    @router.put("/outbound-services/{kind}/{entry_id}", response_model=None)
    async def set_service_proxy(
        kind: str, entry_id: str, request: Request
    ) -> dict[str, Any] | JSONResponse:
        provider: OutboundProvider | None = registry.provider(kind)
        if provider is None or provider.set_proxy is None:
            raise StarletteHTTPException(status_code=404)
        principal = writer(request, provider.write_permission)
        try:
            body = await _json(request)
            if not isinstance(body, dict) or "proxy_id" not in body:
                raise OutboundError("invalid_request", "proxy_id is required (null = direct)")
            entries = await asyncio.to_thread(registry.entries)
            entry = next(
                (item for item in entries if item["kind"] == kind and item["id"] == entry_id),
                None,
            )
            if entry is None:
                raise KeyError(entry_id)
            reference = check_reference(
                network,
                body["proxy_id"],
                provider.supported_types(entry),
                provider.unsupported_code,
            )
            await asyncio.to_thread(provider.set_proxy, entry_id, reference)
        except KeyError:
            raise StarletteHTTPException(status_code=404) from None
        except OutboundError as exc:
            await audit(
                request, principal.user_id, "settings.outbound_service.update",
                f"{kind}:{entry_id}", "failure",
            )
            return fail(exc)
        except ValueError as exc:
            await audit(
                request, principal.user_id, "settings.outbound_service.update",
                f"{kind}:{entry_id}", "failure",
            )
            return error_payload("invalid_proxy_id", str(exc), 409)
        updated = {**entry, "proxy_id": reference}
        if provider.on_change is not None:
            await provider.on_change([updated])
        await audit(
            request, principal.user_id, "settings.outbound_service.update", f"{kind}:{entry_id}"
        )
        return updated

    return router


def _dedupe(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: dict[tuple[str, str], dict[str, Any]] = {}
    for entry in entries:
        seen.setdefault((entry["kind"], entry["id"]), entry)
    return list(seen.values())
