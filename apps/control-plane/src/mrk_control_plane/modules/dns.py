"""MRK DNS: panel API for the DNS engine (docs/37 §4).

Routes (all under ``/api/v1/dns``; every change needs CSRF and is audited):

* ``GET status``, ``GET setup`` (dns:read)
* ``GET/PUT settings`` (dns:admin) - the engine's own settings object
* ``GET/PUT integration`` (dns:read / dns:admin) - panel-side switches
  (services overrides, internal zone ``mrk.internal``)
* ``zones``, ``zones/{zone}``, ``.../export``, ``.../import``, ``.../history``,
  ``.../rollback``, ``.../records[/{id}]`` (read: dns:read, change: dns:write)
* ``overrides[/{id}]`` (dns:read / dns:write)
* ``POST resolve`` (dns:read), ``POST cache/flush`` (dns:write)
* D2 (docs/38 §4, ``dns_logs``): ``logs[/status|/stream|/export]`` (dns:logs),
  ``DELETE logs`` (dns:admin), ``stats``/``pressure`` (dns:read),
  ``mitigations[/{id}]`` (dns:write); background work in ``dns_monitor``.

The engine runs in its own container (compose profile ``dns``) and is reached
over its admin unix socket (``dns_client``). Without the socket every engine
route answers 503 ``dns_not_installed`` and the setup guide explains how to
start it.
"""

from __future__ import annotations

import asyncio
import copy
import ipaddress
import json
import logging
import time
from typing import Any
from urllib.parse import quote

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from sqlalchemy import select

from .. import dns_client
from ..config import setting_env
from ..dns_client import DnsClient, DnsError
from ..models import ServiceDomain, SystemSetting
from ..module_context import Event, ModuleContext
from . import dns_logs, dns_setup
from .dns_monitor import DnsMonitor
from .dns_validate import (
    MAX_IMPORT_BYTES,
    DnsInputError,
    engine_settings,
    entity_id,
    override_body,
    record_body,
    resolve_body,
    zone_create_body,
    zone_from_path,
    zone_patch_body,
)

LOGGER = logging.getLogger(__name__)
MODULE_NAME = "dns"
SETTINGS_KEY = "dns.settings"
INTERNAL_ZONE = "mrk.internal"
INTERNAL_NAMES = ("panel", "npm", "pypi", "s3")
MANAGED_COMMENT = "managed by MRK: services"
SERVICES_SOURCE = "services"
STATUS_TTL_SECONDS = 10.0
SETUP_TTL_SECONDS = 60.0
FACTS_TTL_SECONDS = 30.0
LOOP_SECONDS = 60.0
SYNC_EVERY_SECONDS = 600.0
SYNC_TIMEOUT_SECONDS = 10.0
MAX_BODY_BYTES = 4 * 1024 * 1024
OVERRIDE_TTL = 60

DEFAULT_SETTINGS: dict[str, Any] = {
    "services_overrides": False,
    "services_override_target": "",
    "internal_zone_enabled": False,
    "fallback_servers": ["1.1.1.1", "9.9.9.9"],
}


class SettingsError(ValueError):
    def __init__(self, message: str, field: str) -> None:
        super().__init__(message)
        self.code = "invalid_settings"
        self.message = message
        self.status_code = 422
        self.field = field


def validate_settings(payload: Any, current: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise SettingsError("settings must be a JSON object", "body")
    unknown = sorted(set(payload) - set(DEFAULT_SETTINGS))
    if unknown:
        raise SettingsError(f"unknown setting(s): {', '.join(unknown)}", unknown[0])
    merged = dict(current)
    for key, value in payload.items():
        if key in {"services_overrides", "internal_zone_enabled"}:
            if not isinstance(value, bool):
                raise SettingsError(f"{key} must be true or false", key)
            merged[key] = value
        elif key == "services_override_target":
            if value in (None, ""):
                merged[key] = ""
                continue
            try:
                address = ipaddress.ip_address(str(value).strip())
            except ValueError:
                raise SettingsError(f"{key} must be an IP address", key) from None
            if address.is_unspecified or address.is_multicast:
                raise SettingsError(f"{key} must be a usable address", key)
            merged[key] = str(address)
        elif key == "fallback_servers":
            if isinstance(value, str):
                value = [item for item in value.split(",") if item.strip()]
            if not isinstance(value, list) or not 1 <= len(value) <= 4:
                raise SettingsError("fallback_servers must list 1..4 IP addresses", key)
            servers: list[str] = []
            for item in value:
                try:
                    address = ipaddress.ip_address(str(item).strip())
                except ValueError:
                    raise SettingsError(f"{str(item)[:60]!r} is not an IP address", key) from None
                if address.is_loopback or address.is_unspecified:
                    raise SettingsError("a fallback must not be this server", key)
                if str(address) not in servers:
                    servers.append(str(address))
            merged[key] = servers
    return merged


class DnsSettingsStore:
    def __init__(self, ctx: ModuleContext) -> None:
        self.ctx = ctx

    def _stored(self) -> dict[str, Any]:
        with self.ctx.database.session() as db:
            row = db.get(SystemSetting, SETTINGS_KEY)
            return dict(row.value) if row is not None and isinstance(row.value, dict) else {}

    def get_settings(self) -> dict[str, Any]:
        effective = copy.deepcopy(DEFAULT_SETTINGS)
        for key, value in self._stored().items():
            if key in DEFAULT_SETTINGS:
                try:
                    effective = validate_settings({key: value}, effective)
                except SettingsError:
                    continue
        return effective

    def put_settings(self, payload: Any, actor: int | None) -> dict[str, Any]:
        merged = validate_settings(payload, self.get_settings())
        stored = self._stored()
        stored.update({key: merged[key] for key in payload})
        now = int(time.time())
        with self.ctx.database.session() as db, db.begin():
            row = db.get(SystemSetting, SETTINGS_KEY)
            if row is None:
                db.add(SystemSetting(key=SETTINGS_KEY, value=stored, updated_at=now,
                                     updated_by_user_id=actor))
            else:
                row.value = stored
                row.updated_at = now
                row.updated_by_user_id = actor
        return self.get_settings()


def _path(*parts: str) -> str:
    return "/" + "/".join(quote(part, safe="") for part in parts)


class DnsService:
    def __init__(self, ctx: ModuleContext) -> None:
        self.ctx = ctx
        self.store = DnsSettingsStore(ctx)
        self.client = DnsClient()
        self.monitor = DnsMonitor(ctx, self.client)
        self.last_status: dict[str, Any] | None = None
        self._status_at = 0.0
        self._setup: tuple[float, dict[str, Any]] | None = None
        self._facts: tuple[float, str, dict[str, Any] | None] | None = None
        self.last_sync: dict[str, Any] | None = None
        self._sync_lock = asyncio.Lock()
        self._task: asyncio.Task[None] | None = None
        self._last_sync_at = 0.0

    # ------------------------------------------------------------------ settings
    def get_settings(self) -> dict[str, Any]:
        return self.store.get_settings()

    def put_settings(self, payload: Any, actor_user_id: int | None) -> dict[str, Any]:
        value = self.store.put_settings(payload, actor_user_id)
        self._setup = None
        return value

    def agent(self) -> Any | None:
        from .home import find_service

        return find_service(self.ctx, "HostAgentService")

    # ------------------------------------------------------------------ status
    async def status(self, *, refresh: bool = True) -> dict[str, Any]:
        fresh = time.monotonic() - self._status_at < STATUS_TTL_SECONDS
        if self.last_status is not None and (fresh or not refresh):
            return self.last_status
        result: dict[str, Any] = {
            "installed": dns_client.installed(),
            "reachable": False,
            "error_code": None,
            "engine": None,
            "setup_complete": False,
            "checked_at": int(time.time()),
        }
        if not result["installed"]:
            result["error_code"] = "dns_not_installed"
        else:
            try:
                result["engine"] = await self.client.status()
                result["reachable"] = True
            except DnsError as exc:
                result["error_code"] = exc.code
                result["reason"] = exc.extra.get("reason")
        cached = self._setup[1] if self._setup else None
        result["setup_complete"] = bool(cached and cached.get("complete"))
        self._publish_transition(self.last_status, result)
        self.last_status = result
        self._status_at = time.monotonic()
        return result

    def cached_status(self) -> dict[str, Any] | None:
        return self.last_status

    def _publish_transition(self, before: dict[str, Any] | None, after: dict[str, Any]) -> None:
        if before is None or not after["installed"]:
            return
        if before.get("reachable") and not after["reachable"]:
            self.ctx.events.publish(Event(
                type="dns.unreachable", severity="error",
                title="MRK DNS is not answering",
                message=str(after.get("reason") or after.get("error_code")),
                module=MODULE_NAME, dedupe_key="dns.reachability",
                details={"error_code": after.get("error_code"), "reason": after.get("reason")},
            ))
        elif not before.get("reachable") and after["reachable"] and before.get("installed"):
            self.ctx.events.publish(Event(
                type="dns.recovered", severity="info", title="MRK DNS answers again",
                module=MODULE_NAME, dedupe_key="dns.reachability",
            ))

    # ------------------------------------------------------------------ setup
    async def _agent_facts(self, refresh: bool) -> tuple[str, dict[str, Any] | None]:
        cached = self._facts
        if cached and not refresh and time.monotonic() - cached[0] < FACTS_TTL_SECONDS:
            return cached[1], cached[2]
        agent = self.agent()
        state, facts = "not_configured", None
        if agent is not None:
            try:
                source, url, _key = agent.resolve()
            except Exception:  # noqa: BLE001 - a broken config counts as not configured
                source, url = None, None
            if source is not None and url is not None:
                try:
                    payload = await agent.request("GET", "/v1/dns/facts", timeout=8.0)
                except Exception as exc:  # noqa: BLE001 - mapped to a state
                    code = getattr(exc, "code", None)
                    state = "unsupported" if code in {"agent_not_found"} else "unreachable"
                else:
                    if isinstance(payload, dict):
                        state, facts = "ok", payload
                    else:
                        state = "unreachable"
        self._facts = (time.monotonic(), state, facts)
        return state, facts

    async def setup_view(self, *, refresh: bool = False) -> dict[str, Any]:
        cached = self._setup
        if cached and not refresh and time.monotonic() - cached[0] < SETUP_TTL_SECONDS:
            return cached[1]
        status = await self.status(refresh=True)
        engine_settings_value = None
        answer = None
        resolve_error = None
        if status["reachable"]:
            try:
                engine_settings_value = await self.client.get("/v1/settings")
            except DnsError:
                engine_settings_value = None
            try:
                answer = await self.client.request(
                    "POST", "/v1/resolve",
                    {"name": dns_setup.TEST_NAME, "type": "A", "client_ip": "127.0.0.1"},
                    timeout=6.0,
                )
            except DnsError as exc:
                resolve_error = exc.code
        agent_state, facts = await self._agent_facts(refresh)
        settings = self.get_settings()
        inputs = dns_setup.SetupInputs(
            installed=status["installed"],
            reachable=status["reachable"],
            engine_error=status.get("reason") or status.get("error_code"),
            status=status.get("engine"),
            settings=engine_settings_value if isinstance(engine_settings_value, dict) else None,
            agent_state=agent_state,
            facts=facts,
            resolve=answer if isinstance(answer, dict) else None,
            resolve_error=resolve_error,
            gateway=settings["services_override_target"] or None,
            fallbacks=list(settings["fallback_servers"]),
            default_listen=self.default_listen(),
        )
        steps = dns_setup.build_steps(inputs)
        complete = dns_setup.setup_complete(steps)
        view = {
            "steps": steps,
            "complete": complete,
            "agent": agent_state,
            "gateway": dns_setup.docker_gateway(inputs),
            "fallback": dns_setup.fallbacks(inputs),
            "checked_at": int(time.time()),
        }
        self._setup = (time.monotonic(), view)
        if self.last_status is not None:
            self.last_status["setup_complete"] = complete
        return view

    @staticmethod
    def default_listen() -> list[str]:
        raw = setting_env("MRK_DNS_LISTEN", ",".join(dns_setup.DEFAULT_LISTEN)) or ""
        return [item.strip() for item in raw.split(",") if item.strip()] or list(
            dns_setup.DEFAULT_LISTEN
        )

    # ------------------------------------------------------------------ services sync
    def effective_target(self) -> str:
        settings = self.get_settings()
        if settings["services_override_target"]:
            return str(settings["services_override_target"])
        facts = self._facts[2] if self._facts else None
        gateway = (facts or {}).get("docker_bridge_gateway")
        return gateway if isinstance(gateway, str) and gateway else dns_setup.DEFAULT_GATEWAY

    def _service_hosts(self) -> list[str]:
        with self.ctx.database.session() as db:
            return sorted({row.host for row in db.scalars(select(ServiceDomain))})

    async def sync_services(self, hosts: list[str] | None = None) -> dict[str, Any]:
        """Keep source=services overrides and the internal zone in line with settings."""
        settings = self.get_settings()
        target = self.effective_target()
        result: dict[str, Any] = {
            "status": "applied",
            "enabled": bool(settings["services_overrides"]),
            "internal_zone": bool(settings["internal_zone_enabled"]),
            "target": target,
            "created": 0, "updated": 0, "deleted": 0, "skipped": [],
            "error_code": None,
            "at": int(time.time()),
        }
        if not dns_client.installed():
            result["status"] = "not_installed"
            self.last_sync = result
            return result
        async with self._sync_lock:
            try:
                if hosts is None:
                    hosts = await asyncio.to_thread(self._service_hosts)
                await self._sync_overrides(
                    hosts if settings["services_overrides"] else [], target, result
                )
                await self._sync_internal_zone(bool(settings["internal_zone_enabled"]),
                                               target, result)
            except DnsError as exc:
                result["status"] = "unreachable" if exc.code == "dns_unreachable" else "failed"
                result["error_code"] = exc.code
        if not result["enabled"] and not result["internal_zone"] and result["status"] == "applied":
            result["status"] = "disabled"
        self.last_sync = result
        self._last_sync_at = time.monotonic()
        return result

    async def _sync_overrides(
        self, hosts: list[str], target: str, result: dict[str, Any]
    ) -> None:
        rtype = "AAAA" if ipaddress.ip_address(target).version == 6 else "A"
        payload = await self.client.get("/v1/overrides")
        items = payload.get("items", []) if isinstance(payload, dict) else []
        managed = {
            str(item.get("name")): item for item in items
            if isinstance(item, dict) and item.get("source") == SERVICES_SOURCE
        }
        user_names = {
            str(item.get("name")) for item in items
            if isinstance(item, dict) and item.get("source") != SERVICES_SOURCE
        }
        desired = {host for host in hosts if host not in user_names}
        result["skipped"] = sorted(set(hosts) & user_names)
        for host in sorted(desired):
            body = {"name": host, "type": rtype, "value": target, "ttl": OVERRIDE_TTL,
                    "source": SERVICES_SOURCE, "disabled": False}
            current = managed.get(host)
            if current is None:
                await self.client.request("POST", "/v1/overrides", body)
                result["created"] += 1
            elif (current.get("type"), current.get("value"), bool(current.get("disabled"))) != (
                rtype, target, False
            ):
                await self.client.request("PUT", _path("v1", "overrides", str(current["id"])),
                                          body)
                result["updated"] += 1
        for name, current in managed.items():
            if name not in desired:
                try:
                    await self.client.request(
                        "DELETE", _path("v1", "overrides", str(current["id"]))
                    )
                except DnsError as exc:
                    if exc.code != "dns_override_not_found":
                        raise
                result["deleted"] += 1

    async def _sync_internal_zone(self, enabled: bool, target: str, result: dict[str, Any]) -> None:
        zone_path = _path("v1", "zones", INTERNAL_ZONE)
        try:
            await self.client.get(zone_path)
            exists = True
        except DnsError as exc:
            if exc.code != "dns_zone_not_found":
                raise
            exists = False
        if not enabled and not exists:
            return
        if enabled and not exists:
            await self.client.request("POST", "/v1/zones",
                                      {"name": INTERNAL_ZONE, "type": "primary"})
        payload = await self.client.get(zone_path + "/records")
        records = [item for item in (payload.get("items", []) if isinstance(payload, dict)
                                     else []) if isinstance(item, dict)]
        managed = {
            str(item.get("name")): item for item in records
            if item.get("comment") == MANAGED_COMMENT
        }
        rtype = "AAAA" if ipaddress.ip_address(target).version == 6 else "A"
        desired = set(INTERNAL_NAMES) if enabled else set()
        for name in sorted(desired):
            body = {"name": name, "type": rtype, "ttl": OVERRIDE_TTL,
                    "data": {"address": target}, "disabled": False, "comment": MANAGED_COMMENT}
            current = managed.get(name)
            if current is None:
                await self.client.request("POST", zone_path + "/records", body)
                result["created"] += 1
            elif current.get("type") != rtype or (current.get("data") or {}).get(
                "address"
            ) != target:
                await self.client.request("PUT", zone_path + "/records/" + quote(
                    str(current["id"]), safe=""), body)
                result["updated"] += 1
        for name, current in managed.items():
            if name not in desired:
                await self.client.request("DELETE", zone_path + "/records/" + quote(
                    str(current["id"]), safe=""))
                result["deleted"] += 1
        if not enabled:
            others = [
                item for item in records
                if item.get("comment") != MANAGED_COMMENT and item.get("type") not in {"SOA", "NS"}
            ]
            if not others:
                await self.client.request("DELETE", zone_path)

    async def safe_sync(self, hosts: list[str] | None = None) -> dict[str, Any]:
        try:
            return await asyncio.wait_for(self.sync_services(hosts), SYNC_TIMEOUT_SECONDS)
        except TimeoutError:
            result = {"status": "timeout", "error_code": "dns_unreachable",
                      "at": int(time.time())}
            self.last_sync = result
            return result
        except Exception:  # noqa: BLE001 - never break a domain change
            LOGGER.exception("dns services sync failed")
            return {"status": "failed", "error_code": "dns_sync_failed", "at": int(time.time())}

    def integration_view(self) -> dict[str, Any]:
        return {
            "settings": self.get_settings(),
            "effective_target": self.effective_target(),
            "internal_zone": INTERNAL_ZONE,
            "internal_names": [f"{name}.{INTERNAL_ZONE}" for name in INTERNAL_NAMES],
            "last_sync": self.last_sync,
        }

    # ------------------------------------------------------------------ lifecycle
    async def _tick(self) -> None:
        await self.status(refresh=True)
        settings = self.get_settings()
        wanted = settings["services_overrides"] or settings["internal_zone_enabled"]
        due = time.monotonic() - self._last_sync_at >= SYNC_EVERY_SECONDS
        if (wanted or self.last_sync is None) and due and (self.last_status or {}).get(
            "reachable"
        ):
            await self.safe_sync()

    async def _loop(self) -> None:
        while True:
            try:
                await self._tick()
            except asyncio.CancelledError:
                raise
            except Exception:
                LOGGER.exception("dns status loop failed")
            await asyncio.sleep(LOOP_SECONDS)

    async def start(self) -> None:
        self._task = asyncio.create_task(self._loop(), name="mrk-dns-status")
        await self.monitor.start()

    async def stop(self) -> None:
        await self.monitor.stop()
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None


ACTIVE_SERVICE: DnsService | None = None


def register(ctx: ModuleContext) -> None:
    global ACTIVE_SERVICE
    service = DnsService(ctx)
    ACTIVE_SERVICE = service
    router = APIRouter(prefix="/api/v1/dns", tags=["dns"])

    def fail(exc: DnsError | DnsInputError) -> JSONResponse:
        extra = dict(getattr(exc, "extra", {}) or {})
        extra = {key: value for key, value in extra.items() if value is not None}
        return ctx.error_payload(  # type: ignore[call-arg]
            exc.code, exc.message, exc.status_code, fields=exc.fields, **extra
        )

    async def audit(principal: Any, action: str, object_type: str, object_id: str | None,
                    result: str = "success") -> None:
        await asyncio.to_thread(ctx.audit, principal.user_id, action, object_type, object_id,
                                result)

    async def body_of(request: Request) -> Any:
        raw = await request.body()
        if len(raw) > MAX_BODY_BYTES:
            raise DnsInputError("dns_request_too_large", "The request is too large",
                                [{"field": "body", "reason_code": "too_large"}], 413)
        if not raw.strip():
            return {}
        try:
            return json.loads(raw)
        except ValueError:
            raise DnsInputError("validation_error", "Invalid JSON body",
                                [{"field": "body", "reason_code": "invalid_json"}]) from None

    async def change(
        request: Request,
        permission: str,
        action: str,
        object_type: str,
        object_id: str | None,
        work: Any,
    ) -> Any:
        """Auth + CSRF + run + audit for every mutating route."""
        principal = ctx.require_principal(request, permission)
        ctx.require_csrf(request, principal)
        token = dns_client.CURRENT_ACTOR.set(getattr(principal, "username", None))
        try:
            result, final_id = await work(await body_of(request))
        except DnsInputError as exc:
            return fail(exc)
        except DnsError as exc:
            if exc.status_code not in {404, 422}:
                await audit(principal, action, object_type, object_id, "failure")
            return fail(exc)
        finally:
            dns_client.CURRENT_ACTOR.reset(token)
        await audit(principal, action, object_type, final_id or object_id)
        service._setup = None
        return result

    async def read(request: Request, permission: str, work: Any) -> Any:
        ctx.require_principal(request, permission)
        try:
            return await work()
        except (DnsInputError, DnsError) as exc:
            return fail(exc)

    # ---------------------------------------------------------------- status/setup
    @router.get("/status")
    async def get_status(request: Request) -> dict[str, Any]:
        ctx.require_principal(request, "dns:read")
        return await service.status(refresh=True)

    @router.get("/setup", response_model=None)
    async def get_setup(request: Request, refresh: bool = False) -> dict[str, Any]:
        ctx.require_principal(request, "dns:read")
        return await service.setup_view(refresh=refresh)

    # ---------------------------------------------------------------- engine settings
    @router.get("/settings", response_model=None)
    async def get_settings(request: Request) -> Any:
        return await read(request, "dns:admin", lambda: service.client.get("/v1/settings"))

    @router.put("/settings", response_model=None)
    async def put_settings(request: Request) -> Any:
        async def work(body: Any) -> tuple[Any, str | None]:
            payload = engine_settings(body)
            return await service.client.request("PUT", "/v1/settings", payload), "engine"

        return await change(request, "dns:admin", "dns.settings.update", "dns_settings",
                            "engine", work)

    # ---------------------------------------------------------------- integration
    @router.get("/integration")
    async def get_integration(request: Request) -> dict[str, Any]:
        ctx.require_principal(request, "dns:read")
        return service.integration_view()

    @router.put("/integration", response_model=None)
    async def put_integration(request: Request) -> Any:
        principal = ctx.require_principal(request, "dns:admin")
        ctx.require_csrf(request, principal)
        try:
            body = await body_of(request)
            await asyncio.to_thread(service.put_settings, body, principal.user_id)
        except DnsInputError as exc:
            return fail(exc)
        except SettingsError as exc:
            return ctx.error_payload(  # type: ignore[call-arg]
                "invalid_settings", exc.message, 422,
                fields=[{"field": exc.field, "reason_code": "invalid_value"}],
            )
        await audit(principal, "dns.integration.update", "dns_integration",
                    ",".join(sorted(body)) if isinstance(body, dict) else None)
        await service.safe_sync()
        return service.integration_view()

    # ---------------------------------------------------------------- zones
    @router.get("/zones", response_model=None)
    async def list_zones(request: Request) -> Any:
        return await read(request, "dns:read", lambda: service.client.get("/v1/zones"))

    @router.post("/zones", status_code=201, response_model=None)
    async def create_zone(request: Request) -> Any:
        async def work(body: Any) -> tuple[Any, str | None]:
            payload = zone_create_body(body)
            return await service.client.request("POST", "/v1/zones", payload), payload["name"]

        return await change(request, "dns:write", "dns.zone.create", "dns_zone", None, work)

    @router.get("/zones/{zone}", response_model=None)
    async def get_zone(zone: str, request: Request) -> Any:
        async def work() -> Any:
            return await service.client.get(_path("v1", "zones", zone_from_path(zone)))

        return await read(request, "dns:read", work)

    @router.patch("/zones/{zone}", response_model=None)
    async def patch_zone(zone: str, request: Request) -> Any:
        async def work(body: Any) -> tuple[Any, str | None]:
            name = zone_from_path(zone)
            payload = zone_patch_body(body)
            return await service.client.request("PATCH", _path("v1", "zones", name),
                                                payload), name

        return await change(request, "dns:write", "dns.zone.update", "dns_zone", zone[:255],
                            work)

    @router.delete("/zones/{zone}", response_model=None)
    async def delete_zone(zone: str, request: Request) -> Any:
        async def work(body: Any) -> tuple[Any, str | None]:
            name = zone_from_path(zone)
            confirmation = body.get("confirmation") if isinstance(body, dict) else None
            if not isinstance(confirmation, str) or confirmation.strip().lower().rstrip(
                "."
            ) != name:
                raise DnsError(
                    "confirmation_mismatch", 422, "Type the zone name to confirm",
                    fields=[{"field": "confirmation", "reason_code": "incorrect"}],
                    expected_confirmation=name,
                )
            await service.client.request("DELETE", _path("v1", "zones", name))
            return {"deleted": name}, name

        return await change(request, "dns:write", "dns.zone.delete", "dns_zone", zone[:255],
                            work)

    @router.get("/zones/{zone}/export", response_model=None)
    async def export_zone(zone: str, request: Request) -> Any:
        async def work() -> Any:
            name = zone_from_path(zone)
            text = await service.client.request(
                "GET", _path("v1", "zones", name, "export"), expect_json=False
            )
            return {"zone": name, "text": text}

        return await read(request, "dns:read", work)

    @router.post("/zones/{zone}/import", response_model=None)
    async def import_zone(zone: str, request: Request) -> Any:
        async def work(body: Any) -> tuple[Any, str | None]:
            name = zone_from_path(zone)
            text = body.get("text") if isinstance(body, dict) else None
            replace = body.get("replace", False) if isinstance(body, dict) else False
            unknown = sorted(set(body) - {"text", "replace"}) if isinstance(body, dict) else []
            if unknown:
                raise DnsInputError("dns_record_invalid", "Unknown fields",
                                    [{"field": item, "reason_code": "unknown_field"}
                                     for item in unknown[:10]])
            if not isinstance(text, str) or not text.strip():
                raise DnsInputError("dns_import_invalid", "Paste the zone file text",
                                    [{"field": "text", "reason_code": "required"}])
            if len(text.encode()) > MAX_IMPORT_BYTES:
                raise DnsInputError("dns_import_invalid", "The zone file is too large",
                                    [{"field": "text", "reason_code": "too_large",
                                      "params": {"max_bytes": MAX_IMPORT_BYTES}}])
            if not isinstance(replace, bool):
                raise DnsInputError("dns_import_invalid", "replace must be true or false",
                                    [{"field": "replace", "reason_code": "invalid_type"}])
            return await service.client.request(
                "POST", _path("v1", "zones", name, "import"),
                {"text": text, "replace": replace}, timeout=30.0,
            ), name

        return await change(request, "dns:write", "dns.zone.import", "dns_zone", zone[:255],
                            work)

    @router.get("/zones/{zone}/history", response_model=None)
    async def zone_history(zone: str, request: Request) -> Any:
        async def work() -> Any:
            return await service.client.get(_path("v1", "zones", zone_from_path(zone),
                                                  "history"))

        return await read(request, "dns:read", work)

    @router.post("/zones/{zone}/rollback", response_model=None)
    async def zone_rollback(zone: str, request: Request) -> Any:
        async def work(body: Any) -> tuple[Any, str | None]:
            name = zone_from_path(zone)
            version = body.get("version") if isinstance(body, dict) else None
            valid = (isinstance(version, int) and not isinstance(version, bool)
                     and version >= 0) or (isinstance(version, str) and bool(version)
                                           and len(version) <= 64 and version.isprintable())
            if not valid:
                raise DnsInputError("dns_record_invalid", "Choose a version",
                                    [{"field": "version", "reason_code": "required"}])
            result = await service.client.request(
                "POST", _path("v1", "zones", name, "rollback"), {"version": version}
            )
            return result, f"{name}@{version}"

        return await change(request, "dns:write", "dns.zone.rollback", "dns_zone", zone[:255],
                            work)

    # ---------------------------------------------------------------- records
    @router.get("/zones/{zone}/records", response_model=None)
    async def list_records(zone: str, request: Request) -> Any:
        async def work() -> Any:
            return await service.client.get(_path("v1", "zones", zone_from_path(zone),
                                                  "records"))

        return await read(request, "dns:read", work)

    @router.post("/zones/{zone}/records", status_code=201, response_model=None)
    async def create_record(zone: str, request: Request) -> Any:
        async def work(body: Any) -> tuple[Any, str | None]:
            name = zone_from_path(zone)
            payload = record_body(body, name, creating=True)
            result = await service.client.request(
                "POST", _path("v1", "zones", name, "records"), payload
            )
            return result, f"{name}:{payload['name']}:{payload['type']}"

        return await change(request, "dns:write", "dns.record.create", "dns_record",
                            zone[:255], work)

    @router.put("/zones/{zone}/records/{record_id}", response_model=None)
    async def update_record(zone: str, record_id: str, request: Request) -> Any:
        async def work(body: Any) -> tuple[Any, str | None]:
            name = zone_from_path(zone)
            rid = entity_id(record_id)
            payload = record_body(body, name, creating=False)
            result = await service.client.request(
                "PUT", _path("v1", "zones", name, "records", rid), payload
            )
            return result, f"{name}:{rid}"

        return await change(request, "dns:write", "dns.record.update", "dns_record",
                            f"{zone}:{record_id}"[:255], work)

    @router.delete("/zones/{zone}/records/{record_id}", response_model=None)
    async def delete_record(zone: str, record_id: str, request: Request) -> Any:
        async def work(_body: Any) -> tuple[Any, str | None]:
            name = zone_from_path(zone)
            rid = entity_id(record_id)
            await service.client.request("DELETE", _path("v1", "zones", name, "records", rid))
            return {"deleted": rid}, f"{name}:{rid}"

        return await change(request, "dns:write", "dns.record.delete", "dns_record",
                            f"{zone}:{record_id}"[:255], work)

    # ---------------------------------------------------------------- overrides
    async def managed_guard(override_id: str) -> None:
        payload = await service.client.get("/v1/overrides")
        items = payload.get("items", []) if isinstance(payload, dict) else []
        current = next((item for item in items if isinstance(item, dict)
                        and str(item.get("id")) == override_id), None)
        if current is None:
            raise DnsError("dns_override_not_found", 404, "Override not found")
        if current.get("source") == SERVICES_SOURCE:
            raise DnsError(
                "dns_override_managed", 409,
                "This name is managed by «My services»; change the domain or turn off the sync",
                source=SERVICES_SOURCE,
            )

    @router.get("/overrides", response_model=None)
    async def list_overrides(request: Request) -> Any:
        return await read(request, "dns:read", lambda: service.client.get("/v1/overrides"))

    @router.post("/overrides", status_code=201, response_model=None)
    async def create_override(request: Request) -> Any:
        async def work(body: Any) -> tuple[Any, str | None]:
            payload = {**override_body(body), "source": "user"}
            return await service.client.request("POST", "/v1/overrides", payload), payload[
                "name"
            ]

        return await change(request, "dns:write", "dns.override.create", "dns_override", None,
                            work)

    @router.put("/overrides/{override_id}", response_model=None)
    async def update_override(override_id: str, request: Request) -> Any:
        async def work(body: Any) -> tuple[Any, str | None]:
            oid = entity_id(override_id)
            payload = {**override_body(body), "source": "user"}
            await managed_guard(oid)
            result = await service.client.request("PUT", _path("v1", "overrides", oid), payload)
            return result, f"{oid}:{payload['name']}"

        return await change(request, "dns:write", "dns.override.update", "dns_override",
                            override_id[:255], work)

    @router.delete("/overrides/{override_id}", response_model=None)
    async def delete_override(override_id: str, request: Request) -> Any:
        async def work(_body: Any) -> tuple[Any, str | None]:
            oid = entity_id(override_id)
            await managed_guard(oid)
            await service.client.request("DELETE", _path("v1", "overrides", oid))
            return {"deleted": oid}, oid

        return await change(request, "dns:write", "dns.override.delete", "dns_override",
                            override_id[:255], work)

    # ---------------------------------------------------------------- tools
    @router.post("/resolve", response_model=None)
    async def resolve(request: Request) -> Any:
        principal = ctx.require_principal(request, "dns:read")
        ctx.require_csrf(request, principal)
        try:
            payload = resolve_body(await body_of(request))
            return await service.client.request("POST", "/v1/resolve", payload, timeout=8.0)
        except (DnsInputError, DnsError) as exc:
            return fail(exc)

    @router.post("/cache/flush", response_model=None)
    async def flush_cache(request: Request) -> Any:
        async def work(body: Any) -> tuple[Any, str | None]:
            payload: dict[str, Any] = {}
            name = body.get("name") if isinstance(body, dict) else None
            if name not in (None, ""):
                from .dns_validate import name_problem

                canonical, problem = name_problem(name, allow_underscore=True,
                                                  allow_wildcard=False)
                if problem:
                    raise DnsInputError("dns_record_invalid", "Invalid name",
                                        [{"field": "name", "reason_code": problem}])
                payload["name"] = canonical
            result = await service.client.request("POST", "/v1/cache/flush", payload)
            return result, payload.get("name") or "*"

        return await change(request, "dns:write", "dns.cache.flush", "dns_cache", None, work)

    # D2 (docs/38 §4): query log, stats, pressure, mitigations.
    dns_logs.register_routes(ctx, router, service, fail=fail, audit=audit, change=change,
                             read=read)

    ctx.routers.append(router)
    ctx.start_hooks.append(service.start)
    ctx.stop_hooks.append(service.stop)
