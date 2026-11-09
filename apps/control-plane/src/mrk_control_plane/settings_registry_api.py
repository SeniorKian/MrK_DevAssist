"""HTTP API of the settings registry (docs/33 §4.3, docs/27 §1.6).

GET    /api/v1/settings/registry            groups + items the caller may read
PUT    /api/v1/settings/registry/{key}      {"value": ...}; per-entry permission + CSRF
DELETE /api/v1/settings/registry/{key}      reset to the default (removes an override)
GET    /api/v1/settings/registry/restart    which startup changes wait for a restart

Runtime keys are written through the owning module's own service object (its
validator runs too); startup keys go to the overrides file. Every write is audited
as ``settings.registry.update`` / ``settings.registry.reset`` with the key only,
never the value.
"""

from __future__ import annotations

import asyncio
import copy
import json
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from . import config
from .settings_registry import (
    GROUPS,
    OverridesFile,
    SettingError,
    SettingSpec,
    coerce,
    from_env_text,
    registry,
    resolve_startup,
    to_env_text,
)

MODULE_NAMES = (
    "monitoring", "updates", "vuln", "dbadmin", "notifications", "s3", "server_backups",
    "firewall", "dokploy", "services", "dns", "tenancy",
)
LOGGER = logging.getLogger(__name__)
RESTARTABLE = frozenset({"control-plane", "pypi-router", "s3-engine", "verdaccio", "devpi"})


def collect_module_services() -> dict[str, Any]:
    """The service objects the modules registered last (call right after register_all)."""
    import importlib

    services: dict[str, Any] = {}
    for name in MODULE_NAMES:
        try:
            module = importlib.import_module(f".modules.{name}", __package__)
        except Exception:  # noqa: BLE001 - an optional module that failed to import
            LOGGER.debug("settings registry: module %s unavailable", name)
            continue
        service = getattr(module, "ACTIVE_SERVICE", None)
        service = service or getattr(module, "ACTIVE_CENTER", None)
        service = service or getattr(module, "ACTIVE_STORE", None)
        if service is not None:
            services[name] = service
    return services


def _get_path(payload: Any, path: tuple[str, ...]) -> Any:
    value = payload
    for part in path:
        if not isinstance(value, dict) or part not in value:
            return None
        value = value[part]
    return value


def _nested(path: tuple[str, ...], value: Any) -> dict[str, Any]:
    patch: Any = value
    for part in reversed(path):
        patch = {part: patch}
    return patch


def _module_error(exc: Exception) -> SettingError:
    code = getattr(exc, "code", None) or "invalid_setting_value"
    message = getattr(exc, "message", None) or str(exc) or "invalid value"
    status = getattr(exc, "status_code", None)
    return SettingError(str(code), str(message), status if isinstance(status, int) else 422)


Reader = Callable[[], Awaitable[Any]]
Writer = Callable[[SettingSpec, Any, int], Awaitable[None]]


@dataclass(slots=True)
class Adapter:
    read: Reader
    write: Writer
    locked: Callable[[SettingSpec], bool] = lambda _spec: False


def _thread(function: Callable[..., Any], *args: Any) -> Awaitable[Any]:
    return asyncio.to_thread(function, *args)


def build_adapters(
    services: dict[str, Any], network: Any, auth_store: Any
) -> dict[str, Adapter]:
    adapters: dict[str, Adapter] = {}

    def simple(service: Any, attribute: str, save: Callable[[Any, dict[str, Any], int], Any]):
        async def read() -> Any:
            value = getattr(service, attribute)
            return await _thread(value) if callable(value) else copy.deepcopy(value)

        async def write(spec: SettingSpec, value: Any, user_id: int) -> None:
            await _thread(save, service, _nested(spec.path, value), user_id)

        return Adapter(read, write)

    if "monitoring" in services:
        adapters["monitoring"] = simple(
            services["monitoring"], "settings", lambda s, p, _u: s.save_settings(p)
        )
    for name in ("updates", "vuln"):
        if name in services:
            adapters[name] = simple(services[name], "settings", lambda s, p, _u: s.save_settings(p))
    if "dbadmin" in services:
        adapters["dbadmin"] = simple(
            services["dbadmin"], "settings", lambda s, p, _u: s.save_settings(p)
        )
    if "notifications" in services:
        adapters["notifications"] = simple(
            services["notifications"], "get_settings", lambda s, p, u: s.put_settings(p, u)
        )
    if "s3" in services:
        adapters["s3"] = simple(
            services["s3"], "get_settings", lambda s, p, u: s.put_settings(p, u)
        )
    if "services" in services:
        adapters["services"] = simple(
            services["services"], "get_settings", lambda s, p, u: s.put_settings(p, u)
        )
    if "dns" in services:
        adapters["dns"] = simple(
            services["dns"], "get_settings", lambda s, p, u: s.put_settings(p, u)
        )
    if "tenancy" in services:
        adapters["tenancy"] = simple(
            services["tenancy"], "get_settings", lambda s, p, u: s.put_settings(p, u)
        )
    if "server_backups" in services:
        adapters["server_backups"] = simple(
            services["server_backups"],
            "settings",
            lambda s, p, _u: s.save_settings(p["timezone"]),
        )
    if "firewall" in services:
        firewall = services["firewall"]

        async def firewall_read() -> Any:
            return await _thread(firewall.settings)

        async def firewall_write(spec: SettingSpec, value: Any, _user_id: int) -> None:
            from .modules.firewall_engine import merge_settings

            async with firewall.lock:
                current = await _thread(firewall.settings)
                updated = merge_settings(current, _nested(spec.path, value))
                await _thread(firewall.save_settings, updated)
                try:
                    await firewall.reconcile(force=True)
                except Exception:  # noqa: BLE001 - saved; the helper syncs on its next tick
                    LOGGER.warning("firewall reconcile after a registry change failed")

        adapters["firewall"] = Adapter(firewall_read, firewall_write)
    if "dokploy" in services:
        dokploy = services["dokploy"]

        async def dokploy_read() -> Any:
            return await _thread(dokploy.config_view)

        async def dokploy_write(spec: SettingSpec, value: Any, _user_id: int) -> None:
            if dokploy.env_managed():
                raise SettingError(
                    "setting_locked_by_env", "Dokploy is configured by environment variables", 409
                )
            stored = dokploy._panel_file()  # noqa: SLF001 - module's own config file accessor
            if not stored:
                raise SettingError(
                    "dokploy_not_configured", "Connect Dokploy first, then tune it", 409
                )
            stored[spec.path[0]] = value
            await _thread(dokploy._write_panel, stored)  # noqa: SLF001
            dokploy.client.set_rate(dokploy.tunable("rate_limit_per_second"))

        adapters["dokploy"] = Adapter(
            dokploy_read, dokploy_write, lambda _spec: bool(dokploy.env_managed())
        )

    async def network_read() -> Any:
        return {
            "dns": network.dns().public(),
            "upstream_policy": {"allow_private_upstreams": network.allow_private_upstreams()},
            "default_proxy_id": network.default_proxy_id(),
            "proxies": network.proxies_raw(),
        }

    async def network_write(spec: SettingSpec, value: Any, _user_id: int) -> None:
        from .netresolve import validate_config

        if spec.path[0] == "dns":
            payload = {**network.dns().public(), spec.path[1]: value}
            try:
                config_value = validate_config(payload)
            except (ValueError, TypeError) as exc:
                raise SettingError("invalid_dns_settings", str(exc)) from None
            await _thread(network.save_dns, config_value)
        elif spec.path == ("upstream_policy", "allow_private_upstreams"):
            await _thread(network.save_upstream_policy, bool(value))
        else:
            raise SettingError("setting_read_only", f"{spec.key} is edited on its own page", 409)

    adapters["network"] = Adapter(network_read, network_write)

    async def auth_read() -> Any:
        return {"registration_enabled": await _thread(auth_store.public_registration_enabled)}

    async def auth_write(_spec: SettingSpec, value: Any, user_id: int) -> None:
        await _thread(auth_store.set_public_registration, bool(value), user_id)

    adapters["auth"] = Adapter(auth_read, auth_write)
    return adapters


class RegistryService:
    def __init__(
        self,
        data_dir: Path,
        adapters: dict[str, Adapter],
        boot_overrides: dict[str, str] | None = None,
    ) -> None:
        self.registry = registry()
        self.overrides = OverridesFile(data_dir)
        self.adapters = adapters
        # Effective startup text per env name when this process started.
        values = self.overrides.values() if boot_overrides is None else boot_overrides
        self.boot = {
            spec.env: resolve_startup(spec, values)[0] for spec in self.registry.startup()
        }

    # ---- values --------------------------------------------------------------
    def startup_item(self, spec: SettingSpec, values: dict[str, str]) -> dict[str, Any]:
        text, source = resolve_startup(spec, values)
        locked = source == "env"
        payload: dict[str, Any] = {
            "effective_source": source,
            "locked_by_env": locked,
            "pending_restart": text != self.boot.get(spec.env or ""),
            "overridden": source == "override",
        }
        if spec.secret:
            payload["value"] = None
            payload["secret_configured"] = bool(text)
        else:
            payload["value"] = from_env_text(spec, text)
        return payload

    async def runtime_items(
        self, specs: list[SettingSpec]
    ) -> dict[str, dict[str, Any]]:
        cache: dict[str, Any] = {}
        result: dict[str, dict[str, Any]] = {}
        for spec in specs:
            adapter = self.adapters.get(spec.module or "")
            if adapter is None:
                result[spec.key] = {
                    "value": None, "effective_source": "runtime", "available": False,
                    "locked_by_env": False, "pending_restart": False, "overridden": False,
                }
                continue
            if spec.module not in cache:
                try:
                    cache[spec.module or ""] = await adapter.read()
                except Exception:  # noqa: BLE001 - one broken module must not hide the rest
                    cache[spec.module or ""] = None
            current = cache[spec.module or ""]
            value = _get_path(current, spec.path)
            item: dict[str, Any] = {
                "effective_source": "runtime",
                "available": current is not None,
                "locked_by_env": adapter.locked(spec),
                "pending_restart": False,
                "overridden": value != spec.default,
            }
            if spec.edit_in and isinstance(value, list):
                # Collections are edited on their page; never echo them (may hold secrets).
                item["value"] = None
                item["count"] = len(value)
            else:
                item["value"] = value
            result[spec.key] = item
        return result

    async def listing(self, allows: Callable[[str], bool]) -> dict[str, Any]:
        visible = [spec for spec in self.registry.specs.values() if allows(spec.read_permission)]
        values = self.overrides.values()
        runtime = await self.runtime_items([spec for spec in visible if spec.source == "runtime"])
        grouped: dict[str, list[dict[str, Any]]] = {group.id: [] for group in GROUPS}
        for spec in visible:
            item = spec.schema()
            if spec.source == "startup":
                item.update(self.startup_item(spec, values))
            elif spec.source == "runtime":
                item.update(runtime[spec.key])
            else:
                item.update(
                    {
                        "value": None if spec.secret else spec.default,
                        "effective_source": "constant" if spec.source == "constant" else "build",
                        "locked_by_env": False,
                        "pending_restart": False,
                        "overridden": False,
                    }
                )
                if spec.source == "build" and spec.env:
                    item["value"] = config.explicit_env(spec.env) or None
            writable = spec.write_permission is not None and allows(spec.write_permission)
            item["editable"] = bool(
                spec.editable and writable and not item.get("locked_by_env")
                and item.get("available", True)
            )
            grouped[spec.group].append(item)
        return {
            "groups": [
                {
                    "id": group.id,
                    "key": group.id,
                    "name_fa": group.name_fa,
                    "name_en": group.name_en,
                    "label": {"fa": group.name_fa, "en": group.name_en},
                    "nav": group.nav,
                    "items": grouped[group.id],
                }
                for group in GROUPS
                if grouped[group.id]
            ],
            "restart": self.restart_status(values),
        }

    def restart_status(self, values: dict[str, str] | None = None) -> dict[str, Any]:
        current = self.overrides.values() if values is None else values
        pending: list[str] = []
        processes: set[str] = set()
        for spec in self.registry.startup():
            text, _source = resolve_startup(spec, current)
            if text != self.boot.get(spec.env or ""):
                pending.append(spec.key)
                processes.update(spec.processes)
        restartable = sorted(processes & RESTARTABLE)
        return {
            "pending": bool(pending),
            "keys": sorted(pending),
            "processes": restartable,
            "container_restart_recommended": bool(pending),
        }

    # ---- writes ----------------------------------------------------------------
    def check_writable(self, spec: SettingSpec) -> None:
        if spec.source in {"constant", "build"}:
            raise SettingError("setting_read_only", f"{spec.key} cannot be changed yet", 409)
        if spec.source == "runtime" and spec.edit_in:
            raise SettingError(
                "setting_edited_elsewhere", f"{spec.key} is edited on {spec.edit_in}", 409
            )
        if spec.source == "startup" and not spec.overridable:
            raise SettingError(
                "setting_env_only", f"{spec.key} can only be set in the environment", 409
            )

    def _validate_startup(self, values: dict[str, str]) -> None:
        """Refuse an override set that would stop the control plane from starting."""
        def lookup(name: str, default: str | None) -> str | None:
            return config.resolve_env(name, default, overrides=values)[0]

        try:
            config.Settings.from_env(lookup=lookup)
        except ValueError as exc:
            raise SettingError("invalid_setting_value", str(exc)) from None

    async def update(self, key: str, raw: Any, user_id: int) -> dict[str, Any]:
        spec = self.registry.get(key)
        self.check_writable(spec)
        value = coerce(spec, raw)
        if spec.source == "startup":
            assert spec.env is not None
            if config.explicit_env(spec.env) is not None:
                raise SettingError(
                    "setting_locked_by_env", f"{spec.env} is set in the environment", 409
                )
            values = self.overrides.values()
            values[spec.env] = to_env_text(spec, value)
            self._validate_startup(values)
            await _thread(self.overrides.write, values, user_id)
        else:
            await self._runtime_write(spec, value, user_id)
        return await self.item(spec)

    async def reset(self, key: str, user_id: int) -> dict[str, Any]:
        spec = self.registry.get(key)
        self.check_writable(spec)
        if spec.source == "startup":
            assert spec.env is not None
            values = self.overrides.values()
            if values.pop(spec.env, None) is not None:
                self._validate_startup(values)
                await _thread(self.overrides.write, values, user_id)
        else:
            await self._runtime_write(spec, copy.deepcopy(spec.default), user_id)
        return await self.item(spec)

    async def _runtime_write(self, spec: SettingSpec, value: Any, user_id: int) -> None:
        adapter = self.adapters.get(spec.module or "")
        if adapter is None:
            raise SettingError("module_unavailable", f"module {spec.module} is not loaded", 503)
        if adapter.locked(spec):
            raise SettingError(
                "setting_locked_by_env", f"{spec.key} is set by the environment", 409
            )
        try:
            await adapter.write(spec, value, user_id)
        except SettingError:
            raise
        except (ValueError, TypeError, KeyError) as exc:
            raise _module_error(exc) from None
        except Exception as exc:
            if hasattr(exc, "code"):
                raise _module_error(exc) from None
            raise

    async def item(self, spec: SettingSpec) -> dict[str, Any]:
        payload = spec.schema()
        if spec.source == "startup":
            payload.update(self.startup_item(spec, self.overrides.values()))
        else:
            payload.update((await self.runtime_items([spec]))[spec.key])
        return payload


def build_registry_router(
    *,
    data_dir: Path,
    services: dict[str, Any],
    network: Any,
    auth_store: Any,
    require_principal: Callable[..., Any],
    require_csrf: Callable[..., None],
    error_payload: Callable[[str, str, int], JSONResponse],
    client_context: Callable[[Request], tuple[str | None, str | None]] = lambda _r: (None, None),
) -> APIRouter:
    service = RegistryService(data_dir, build_adapters(services, network, auth_store))
    router = APIRouter(prefix="/api/v1/settings/registry", include_in_schema=False)

    def fail(exc: SettingError) -> JSONResponse:
        return error_payload(exc.code, exc.message, exc.status_code)

    async def audit(request: Request, user_id: int, action: str, key: str, result: str) -> None:
        source_ip, request_id = client_context(request)
        await asyncio.to_thread(
            auth_store.record_audit, user_id, action, "setting", key[:255], result,
            source_ip, request_id,
        )

    async def body_value(request: Request) -> Any:
        try:
            payload = json.loads(await request.body() or b"{}")
        except (ValueError, UnicodeDecodeError):
            raise SettingError("invalid_json", "request body must be JSON") from None
        if not isinstance(payload, dict) or "value" not in payload:
            raise SettingError("invalid_setting_value", 'body must be {"value": ...}')
        return payload["value"]

    def writer(request: Request, key: str) -> Any:
        principal = require_principal(request, None)
        spec = service.registry.get(key)
        if not principal.allows(spec.read_permission):
            raise SettingError("forbidden", "permission denied", 403)
        if spec.write_permission is None:
            service.check_writable(spec)  # explains why (constant, env-only, ...)
        if spec.write_permission is None or not principal.allows(spec.write_permission):
            raise SettingError("forbidden", "permission denied", 403)
        require_csrf(request, principal)
        return principal

    @router.get("")
    async def list_settings(request: Request) -> dict[str, Any]:
        principal = require_principal(request, None)
        return await service.listing(principal.allows)

    @router.get("/restart")
    async def restart_status(request: Request) -> dict[str, Any]:
        require_principal(request, "system:read")
        return service.restart_status()

    @router.put("/{key}", response_model=None)
    async def update_setting(key: str, request: Request) -> dict[str, Any] | JSONResponse:
        try:
            principal = writer(request, key)
        except SettingError as exc:
            return fail(exc)
        try:
            value = await body_value(request)
            item = await service.update(key, value, principal.user_id)
        except SettingError as exc:
            await audit(request, principal.user_id, "settings.registry.update", key, "failure")
            return fail(exc)
        await audit(request, principal.user_id, "settings.registry.update", key, "success")
        return {"item": item, "restart": service.restart_status()}

    @router.delete("/{key}", response_model=None)
    async def reset_setting(key: str, request: Request) -> dict[str, Any] | JSONResponse:
        try:
            principal = writer(request, key)
        except SettingError as exc:
            return fail(exc)
        try:
            item = await service.reset(key, principal.user_id)
        except SettingError as exc:
            await audit(request, principal.user_id, "settings.registry.reset", key, "failure")
            return fail(exc)
        await audit(request, principal.user_id, "settings.registry.reset", key, "success")
        return {"item": item, "restart": service.restart_status()}

    return router
