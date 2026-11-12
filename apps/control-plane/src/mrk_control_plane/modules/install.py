"""Add-service wizard API (docs/44).

The panel boots alone. This module tells the operator how to add every other
service (its image, a ready Compose file and a filled ``.env``), and connects
the panel to it once it runs.

Flow per service:

1. ``GET  /api/v1/install/catalog``          what can be added, with live state;
2. ``POST /api/v1/install/{id}/bundle``      Compose + .env (+ a fresh pairing key);
3. operator deploys it (Dokploy, Coolify or ``docker compose``);
4. ``POST /api/v1/install/{id}/connect``     pair with the stored key and probe.

Storage: ``GET /api/v1/install/{id}/storage`` lists where the service keeps its data
(a Docker volume or a folder on the server, see install_storage); the bundle and the
automatic install take the admin's ``storage`` choices, and
``POST /api/v1/install/{id}/storage/check`` checks the folders through the Host Agent.

Pairing keys are generated here, kept only in the encrypted SecretStore and
shown once in the generated ``.env``. A new bundle replaces the pending key.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import secrets
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from fastapi import APIRouter, Request
from pydantic import BaseModel, ConfigDict, Field

from .. import remote_services
from ..agent.signing import encode_key, generate_key
from ..module_context import ModuleContext
from . import install_storage
from .install_catalog import (
    INSTALL_INDEX,
    INSTALLABLE,
    InstallDef,
    compose_for,
    default_url,
    panel_is_native,
    public_item,
    render_env,
    resolve_env,
)

STATE_FILE = "install.json"
LOGGER = logging.getLogger(__name__)
# Extra permission per service on top of services:operate (same as its own pair route).
WRITE_PERMISSION = {
    "agent": "agent:write", "firewall": "firewall:write", "dns": "dns:write", "s3": "s3:admin",
    "npm": "upstream:write", "pypi": "upstream:write",
    "git": "git:write", "registry": "registry:write",
}


class InstallError(Exception):
    def __init__(self, code: str, status_code: int, message: str, **extra: Any) -> None:
        super().__init__(message)
        self.code = code
        self.status_code = status_code
        self.message = message
        self.extra = extra


class StorageChoice(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: str = Field(pattern=r"^(volume|path)$")
    value: str = Field(default="", max_length=400)


class BundleRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    env: dict[str, str] = Field(default_factory=dict, max_length=32)
    method: str = Field(default="compose", pattern=r"^(dokploy|coolify|compose)$")
    storage: dict[str, StorageChoice] = Field(default_factory=dict, max_length=8)


class StorageCheckRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    storage: dict[str, StorageChoice] = Field(default_factory=dict, max_length=8)


class ConnectRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    url: str | None = Field(default=None, max_length=300)
    # S3 only: the S3 API address when it is not next to the admin API (docs/44).
    engine_url: str | None = Field(default=None, max_length=300)


class InstallService:
    def __init__(self, ctx: ModuleContext) -> None:
        self.ctx = ctx
        self.state_path: Path = ctx.data_dir / "control-plane" / STATE_FILE

    # ------------------------------------------------------------------ state file
    def _read(self) -> dict[str, Any]:
        try:
            payload = json.loads(self.state_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}
        return payload if isinstance(payload, dict) else {}

    def _write(self, payload: dict[str, Any]) -> None:
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.state_path.with_name(f".{STATE_FILE}.{secrets.token_hex(4)}.tmp")
        temporary.write_text(json.dumps(payload, sort_keys=True) + "\n", encoding="utf-8")
        temporary.chmod(0o600)
        os.replace(temporary, self.state_path)

    def pending(self, service_id: str) -> dict[str, Any] | None:
        entry = self._read().get(service_id)
        return entry if isinstance(entry, dict) else None

    # ------------------------------------------------------------------ helpers
    def _helper(self, service_id: str) -> Any | None:
        from .home import find_service

        if service_id == "agent":
            return find_service(self.ctx, "HostAgentService")
        if service_id == "firewall":
            return find_service(self.ctx, "FirewallService")
        if service_id == "dns":
            from . import dns as dns_module

            service = dns_module.ACTIVE_SERVICE
            return service if service is not None and service.ctx is self.ctx else None
        if service_id == "s3":
            from . import s3 as s3_module

            return s3_module.ACTIVE_STORE
        if service_id in {"npm", "pypi"}:
            return self.ctx.settings
        if service_id == "git":
            from . import git_service

            return git_service.ACTIVE_SERVICE
        if service_id == "registry":
            from . import registry_service

            return registry_service.ACTIVE_SERVICE
        return None

    def env_managed(self, service_id: str) -> bool:
        helper = self._helper(service_id)
        if helper is None:
            return False
        if service_id == "agent":
            return bool(helper.env_managed())
        if service_id == "firewall":
            return bool(helper.client.env_managed())
        if service_id == "s3":
            return bool(os.getenv("MRK_S3_ADMIN_URL", "").strip())
        return False

    async def connection_state(self, service_id: str) -> str:
        """``connected`` | ``unreachable`` | ``not_connected`` | ``unavailable``."""
        helper = self._helper(service_id)
        if helper is None:
            return "unavailable"
        if service_id == "agent":
            source, url, key = helper.resolve()
            if source is None or url is None or key is None:
                return "not_connected"
            ok, _latency, _error = await helper.probe()
            return "connected" if ok else "unreachable"
        if service_id == "firewall":
            source, url, key, _error = await asyncio.to_thread(helper.client.resolve)
            if source is None or url is None or key is None:
                return "not_connected"
            status = await helper.status()
            return "connected" if status.get("reachable") else "unreachable"
        if service_id == "dns":
            status = await helper.status(refresh=True)
            if not status.get("installed"):
                return "not_connected"
            return "connected" if status.get("reachable") else "unreachable"
        if service_id == "s3":
            from .s3_client import EngineAdmin, is_remote

            if not await asyncio.to_thread(is_remote):
                return "not_connected"
            healthy = await EngineAdmin(helper.admin_token_path).health()
            return "connected" if healthy else "unreachable"
        if service_id in {"npm", "pypi"}:
            if not remote_services.is_remote(service_id, self.ctx.data_dir):
                return "not_connected"
            return "connected" if await self._registry_healthy(service_id) else "unreachable"
        if service_id == "git":
            if helper.connected() is None:
                return "not_connected"
            return "connected" if (await helper.status())["reachable"] else "unreachable"
        if service_id == "registry":
            if helper.connected() is None:
                return "not_connected"
            return "connected" if await helper.reachable() else "unreachable"
        return "unavailable"

    async def _registry_healthy(self, service_id: str) -> bool:
        from ..components import check_http_component

        settings = self.ctx.settings
        if service_id == "npm":
            return await asyncio.to_thread(
                check_http_component, settings.npm_health_host, settings.npm_health_port,
                "/-/ping", 3.0)
        return await asyncio.to_thread(
            check_http_component, settings.pypi_health_host, settings.pypi_health_port,
            "/+status", 3.0)

    async def catalog(self) -> dict[str, Any]:
        items = []
        for item in INSTALLABLE:
            entry = public_item(item)
            if item.availability == "ready":
                entry["connection"] = await self.connection_state(item.id)
                entry["managed_by_environment"] = self.env_managed(item.id)
                pending = self.pending(item.id)
                entry["bundle_created_at"] = pending.get("created_at") if pending else None
            else:
                entry["connection"] = "planned"
                entry["managed_by_environment"] = False
                entry["bundle_created_at"] = None
            items.append(entry)
        return {"items": items}

    # ------------------------------------------------------------------ bundle
    def _ready(self, service_id: str) -> InstallDef:
        item = INSTALL_INDEX.get(service_id)
        if item is None:
            raise InstallError("service_not_found", 404, "Unknown service")
        if item.availability != "ready":
            raise InstallError("service_not_installable_yet", 409,
                               "This service is not available as its own install yet")
        return item

    # ------------------------------------------------------------------ storage
    def _agent(self) -> Any | None:
        from . import services as services_module

        service = services_module.ACTIVE_SERVICE
        if service is None or getattr(service, "ctx", None) is not self.ctx:
            return None
        try:
            return service.routing.agent()
        except Exception:  # noqa: BLE001 - the agent is optional
            return None

    async def panel_mounts(self) -> tuple[list[dict[str, Any]] | None, str]:
        """The panel container's mounts and where they came from (agent|dokploy|none)."""
        from . import services as services_module

        service = services_module.ACTIVE_SERVICE
        detected: dict[str, Any] = {}
        if service is not None and getattr(service, "ctx", None) is self.ctx:
            try:
                detected = await service.routing.detect_quick() or {}
            except Exception:  # noqa: BLE001 - detection is best effort
                detected = {}
        agent = self._agent()
        name = detected.get("container_name")
        if agent is not None and isinstance(name, str) and name:
            try:
                payload = await agent.call(f"/v1/docker/containers/{name}/mounts")
                items = payload.get("items") if isinstance(payload, dict) else None
                if isinstance(items, list):
                    return [item for item in items if isinstance(item, dict)], "agent"
            except Exception:  # noqa: BLE001 - older agent, or not reachable
                LOGGER.info("panel mounts not available from the agent", exc_info=True)
        compose_id = detected.get("dokploy_service_id")
        if detected.get("dokploy_service_type") == "compose" and isinstance(compose_id, str):
            from . import dokploy as dokploy_module
            from .dokploy_locate import compose_detail

            dokploy = dokploy_module.ACTIVE_SERVICE
            if dokploy is not None:
                try:
                    one = await compose_detail(dokploy, compose_id)
                except Exception:  # noqa: BLE001
                    one = None
                text = one.get("composeFile") if one else None
                del one
                if isinstance(text, str):
                    return install_storage.parse_compose_mounts(text), "dokploy"
        return None, "none"

    async def storage_view(self, service_id: str) -> dict[str, Any]:
        item = self._ready(service_id)
        recorded = (self.pending(service_id) or {}).get("storage") or {}
        mounts, source = (None, "none")
        if any(slot.panel_path for slot in install_storage.slots_for(item.id)):
            mounts, source = await self.panel_mounts()
        slots = []
        for slot in install_storage.slots_for(item.id):
            entry: dict[str, Any] = {
                "key": slot.key, "target": slot.target, "volume": slot.volume,
                "label_fa": slot.label_fa, "label_en": slot.label_en, "owner": slot.owner,
                "shared": slot.panel_path is not None, "panel_path": slot.panel_path,
                # Which earlier service's mount this one must match (the panel today).
                "shared_with": ({"service": install_storage.SHARED_WITH,
                                 "container": install_storage.SHARED_SERVICE_NAME,
                                 "path": slot.panel_path}
                                if slot.panel_path is not None else None),
                "suggested_path": install_storage.suggested_path(item.id, slot),
                "choice": recorded.get(slot.key) or {"kind": "volume", "value": slot.volume},
            }
            if slot.panel_path is not None:
                if panel_is_native():
                    entry["panel"] = {"kind": "native", "value": None}
                elif mounts is None:
                    entry["panel"] = {"kind": "unknown", "value": None}
                else:
                    entry["panel"] = install_storage.shared_source(mounts, slot.panel_path)
                found = entry["panel"]
                if found.get("kind") in {"path", "volume"}:
                    entry["choice"] = {"kind": found["kind"], "value": found["value"]}
            slots.append(entry)
        return {"id": item.id, "slots": slots, "panel_mounts_source": source,
                "checks_available": self._agent() is not None}

    async def resolve_storage(self, service_id: str,
                              choices: dict[str, Any]) -> dict[str, dict[str, str]]:
        """The admin's choices for own slots plus what shared slots must be (the panel's)."""
        view = await self.storage_view(service_id)
        resolved: dict[str, dict[str, str]] = {}
        for slot in view["slots"]:
            if slot["shared"]:
                resolved[slot["key"]] = dict(slot["choice"])
                continue
            raw = choices.get(slot["key"])
            choice = raw.model_dump() if hasattr(raw, "model_dump") else raw
            if not choice:
                continue
            kind, value = choice.get("kind"), str(choice.get("value") or "").strip()
            if kind == "path":
                if not install_storage.valid_path(value):
                    raise InstallError(
                        "validation_error", 422, "Give an absolute folder such as /opt/data",
                        fields=[{"field": f"storage.{slot['key']}", "reason_code": "invalid"}])
                resolved[slot["key"]] = {"kind": "path", "value": value}
            else:
                resolved[slot["key"]] = {"kind": "volume", "value": slot["volume"]}
        return resolved

    async def check_storage(self, service_id: str, choices: dict[str, Any]) -> dict[str, Any]:
        resolved = await self.resolve_storage(service_id, choices)
        slots = {slot.key: slot for slot in install_storage.slots_for(service_id)}
        paths = [choice["value"] for choice in resolved.values() if choice["kind"] == "path"]
        facts: dict[str, dict[str, Any]] = {}
        agent = self._agent()
        if paths and agent is not None:
            from urllib.parse import urlencode

            try:
                query = urlencode([("path", path) for path in paths])
                payload = await agent.call(f"/v1/host/paths?{query}")
                for fact in payload.get("items", []) if isinstance(payload, dict) else []:
                    if isinstance(fact, dict) and isinstance(fact.get("path"), str):
                        facts[fact["path"]] = fact
            except Exception:  # noqa: BLE001 - older agent: the folders stay unchecked
                facts = {}
        results = []
        for key, choice in resolved.items():
            slot = slots[key]
            if choice["kind"] != "path":
                results.append({"key": key, "kind": "volume", "status": "ok", "code": None})
                continue
            verdict = install_storage.evaluate(slot, choice["value"], facts.get(choice["value"]))
            results.append({"key": key, "kind": "path", "path": choice["value"], **verdict})
        blocking = [item for item in results if item["status"] == "error"]
        return {"id": service_id, "items": results, "ok": not blocking,
                "checked": bool(facts) or not paths}

    def bundle(self, service_id: str, overrides: dict[str, str],
               storage: dict[str, dict[str, str]] | None = None) -> dict[str, Any]:
        item = self._ready(service_id)
        if self.env_managed(service_id):
            raise InstallError("managed_by_environment", 409,
                               "This connection is managed by environment variables")
        try:
            values = resolve_env(item, overrides)
        except ValueError as exc:
            raise InstallError("validation_error", 422, "Invalid value",
                               fields=[{"field": f"env.{exc}", "reason_code": "invalid"}]) from exc
        key_text: str | None = None
        state = self._read()
        previous_entry = state.get(service_id) if isinstance(state.get(service_id), dict) else {}
        if service_id == "s3":
            # The engine uses the token the panel already has (docs/44), so files made
            # again never break a running engine.
            store = self._helper("s3")
            if store is None:
                raise InstallError("module_unavailable", 503, "The S3 module is not loaded")
            key_text = store.admin_token()
            state[service_id] = {"created_at": int(time.time())}
        elif item.pairing_env:
            key_text = encode_key(generate_key())
            previous = state.get(service_id)
            reference = previous.get("secret_ref") if isinstance(previous, dict) else None
            reference = reference if isinstance(reference, str) else None
            reference, _version = self.ctx.secret_store.replace(reference, {"key": key_text})
            state[service_id] = {"secret_ref": reference, "created_at": int(time.time())}
        else:
            state[service_id] = {"created_at": int(time.time())}
        # Non-secret values the panel reads later (public addresses, ports).
        state[service_id]["env"] = values
        # The image these files run; the versions page compares it with the panel's own.
        state[service_id]["image"] = public_item(item)["image"]
        if storage is None and isinstance(previous_entry.get("storage"), dict):
            storage = previous_entry["storage"]
        if storage:
            # Kept so updates write the same folders again (releases.py).
            state[service_id]["storage"] = storage
        if isinstance(previous_entry.get("deployment"), dict):
            # Where the panel deployed it (Dokploy/Coolify): domains are routed there.
            state[service_id]["deployment"] = previous_entry["deployment"]
        if service_id == "registry":
            # Zot starts from the config the panel writes into the shared volume.
            helper = self._helper("registry")
            if helper is None:
                raise InstallError("module_unavailable", 503, "The registry module is not loaded")
            helper.write_files()
        if service_id == "npm":
            # The npm container waits for this config in the shared volume (docs/44).
            remote_services.write_npm_config(self.ctx.data_dir)
        self._write(state)
        return {
            "id": item.id,
            "image": public_item(item)["image"],
            "compose": install_storage.apply(compose_for(item, self.ctx.data_dir),
                                             item.id, storage or {}),
            "env": render_env(item, values, key_text),
            "storage": storage or {},
            "file_names": {"compose": "compose.yaml", "env": ".env"},
            "pairing": key_text is not None,
        }

    # ------------------------------------------------------------------ connect
    async def connect(
        self, service_id: str, url: str | None, engine_url: str | None = None
    ) -> dict[str, Any]:
        item = self._ready(service_id)
        helper = self._helper(service_id)
        if helper is None:
            raise InstallError("module_unavailable", 503, "This part of the panel is not loaded")
        if self.env_managed(service_id):
            raise InstallError("managed_by_environment", 409,
                               "This connection is managed by environment variables")
        if service_id == "registry":
            from .registry_service import RegistryError

            try:
                await asyncio.to_thread(helper.connect, (url or "").strip() or default_url(item))
            except RegistryError as exc:
                raise InstallError(exc.code, exc.status_code, exc.message, **exc.extra) from exc
            return {"id": service_id, "connection": await self.connection_state(service_id)}
        if service_id == "git":
            from .git_service import GitError

            pending = self.pending(service_id)
            reference = pending.get("secret_ref") if pending else None
            if not isinstance(reference, str):
                raise InstallError("bundle_required", 409,
                                   "Create the install files first; they carry the admin password")
            try:
                password = self.ctx.secret_store.get(reference)["key"]
                await helper.connect((url or "").strip() or default_url(item) or "", password)
            except GitError as exc:
                if exc.code in {"git_unreachable", "git_auth_failed"}:
                    return {"id": service_id, "connection": "unreachable"}
                raise InstallError(exc.code, exc.status_code, exc.message, **exc.extra) from exc
            except (KeyError, ValueError) as exc:
                raise InstallError("bundle_required", 409,
                                   "Create the install files again") from exc
            return {"id": service_id, "connection": await self.connection_state(service_id)}
        if service_id in {"npm", "pypi"}:
            target = urlsplit((url or "").strip() or default_url(item) or "")
            if target.scheme != "http" or not target.hostname or target.path not in {"", "/"}:
                raise InstallError("invalid_url", 422, "Use http://host:port",
                                   fields=[{"field": "url", "reason_code": "invalid"}])
            port = target.port or (4873 if service_id == "npm" else 3141)
            try:
                await asyncio.to_thread(
                    remote_services.connect, self.ctx.settings, service_id, target.hostname, port)
            except ValueError as exc:
                raise InstallError("invalid_url", 422, str(exc),
                                   fields=[{"field": "url", "reason_code": "invalid"}]) from exc
            if service_id == "npm":
                await asyncio.to_thread(remote_services.write_npm_config, self.ctx.data_dir)
            return {"id": service_id, "connection": await self.connection_state(service_id)}
        if service_id == "s3":
            from .install_catalog import S3_DEFAULT_ENGINE_URL
            from .s3_client import save_remote

            admin = (url or "").strip() or default_url(item) or ""
            native = default_url(item) != item.default_url
            fallback_engine = "http://127.0.0.1:9000" if native else S3_DEFAULT_ENGINE_URL
            engine = (engine_url or "").strip() or fallback_engine
            try:
                await asyncio.to_thread(save_remote, engine, admin)
            except ValueError as exc:
                raise InstallError("invalid_url", 422, str(exc),
                                   fields=[{"field": "url", "reason_code": "invalid"}]) from exc
            pushed = await asyncio.to_thread(helper.push_snapshot)
            connection = await self.connection_state(service_id)
            if connection == "connected" and not pushed:
                connection = "unreachable"
            return {"id": service_id, "connection": connection}
        if item.pairing_env:
            pending = self.pending(service_id)
            reference = pending.get("secret_ref") if pending else None
            if not isinstance(reference, str):
                raise InstallError("bundle_required", 409,
                                   "Create the install files first; they carry the pairing key")
            try:
                key_text = self.ctx.secret_store.get(reference)["key"]
            except (KeyError, ValueError) as exc:
                raise InstallError("bundle_required", 409,
                                   "Create the install files again") from exc
            target = (url or "").strip() or default_url(item) or ""
            try:
                if service_id == "agent":
                    await asyncio.to_thread(helper.save, target, key_text)
                else:
                    await asyncio.to_thread(helper.client.save, target, key_text)
            except ValueError as exc:
                raise InstallError("invalid_url", 422, str(exc),
                                   fields=[{"field": "url", "reason_code": "invalid"}]) from exc
            except Exception as exc:  # module-specific errors (AgentError, HelperError)
                code = getattr(exc, "code", "connect_failed")
                status = getattr(exc, "status_code", 422)
                raise InstallError(str(code), int(status), "Could not save the connection") from exc
        connection = await self.connection_state(service_id)
        return {"id": service_id, "connection": connection}


def register(ctx: ModuleContext) -> None:
    service = InstallService(ctx)
    router = APIRouter(prefix="/api/v1/install", tags=["install"])

    def failure(exc: InstallError):
        return ctx.error_payload(exc.code, exc.message, exc.status_code, **exc.extra)  # type: ignore[call-arg]

    def operator(request: Request, service_id: str):
        principal = ctx.require_principal(request, "services:operate")
        extra = WRITE_PERMISSION.get(service_id)
        if extra:
            ctx.require_principal(request, extra)
        ctx.require_csrf(request, principal)
        return principal

    @router.get("/catalog")
    async def install_catalog(request: Request):
        ctx.require_principal(request, "services:read")
        return await service.catalog()

    @router.get("/{service_id}/storage")
    async def install_storage_view(service_id: str, request: Request):
        ctx.require_principal(request, "services:read")
        try:
            return await service.storage_view(service_id)
        except InstallError as exc:
            return failure(exc)

    @router.post("/{service_id}/storage/check")
    async def install_storage_check(service_id: str, request: Request,
                                    body: StorageCheckRequest):
        operator(request, service_id)
        try:
            return await service.check_storage(service_id, body.storage)
        except InstallError as exc:
            return failure(exc)

    @router.post("/{service_id}/bundle")
    async def install_bundle(service_id: str, request: Request, body: BundleRequest):
        principal = operator(request, service_id)
        try:
            storage = await service.resolve_storage(service_id, body.storage)
            result = await asyncio.to_thread(service.bundle, service_id, body.env, storage)
        except InstallError as exc:
            return failure(exc)
        await asyncio.to_thread(
            ctx.audit, principal.user_id, "install.bundle", "service", service_id
        )
        return result

    @router.post("/{service_id}/connect")
    async def install_connect(service_id: str, request: Request, body: ConnectRequest):
        principal = operator(request, service_id)
        try:
            result = await service.connect(service_id, body.url, body.engine_url)
        except InstallError as exc:
            await asyncio.to_thread(
                ctx.audit, principal.user_id, "install.connect", "service", service_id, "failure"
            )
            return failure(exc)
        await asyncio.to_thread(
            ctx.audit, principal.user_id, "install.connect", "service", service_id,
            "success" if result["connection"] == "connected" else "failure",
        )
        return result

    ctx.routers.append(router)
