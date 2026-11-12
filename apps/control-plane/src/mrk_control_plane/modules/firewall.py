"""Firewall & anti-attack module (Gate 19, S7). See docs/32 §3 for the final API.

The control plane owns all logic: rules, sliding windows, allowlist, safety checks,
decision history, RBAC and audit. The optional privileged helper ``mrk-firewall``
(same image, ``network_mode: host``, only ``CAP_NET_ADMIN``) only tails read-only log
files into signals and applies the desired state to its own nftables table
``inet mrk``. Dry-run is the default; enforce needs the typed confirmation "ENFORCE".
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import secrets
import time
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from starlette.exceptions import HTTPException as StarletteHTTPException

from ..components import Reachability
from ..firewall.addresses import AddressError, parse_network
from ..firewall.nft import Block, DesiredState, render_ruleset
from ..module_context import Event, ModuleContext
from .firewall_client import DEFAULT_URL, HelperClient, HelperError
from .firewall_engine import (
    CLEAR_CONFIRMATION,
    ENFORCE_CONFIRMATION,
    FILE_SOURCES,
    Detector,
    FirewallError,
    Hit,
    effective_allowlist,
    load_settings,
    merge_settings,
    parse_requester,
    refusal,
    validate_rule,
)
from .firewall_ports_api import PortPolicyState, register_port_routes
from .firewall_store import DECISION_ACTIONS, FirewallStore

LOGGER = logging.getLogger(__name__)
MODULE_NAME = "firewall"
SETTINGS_FILE = "firewall.json"
RESYNC_SECONDS = 600
# Hysteresis: the helper counts as unreachable (and firewall.helper_offline is
# published) only after this many failed calls in a row spanning this long. The
# 15 s signals poll, the reconcile and status probes all feed it.
OFFLINE_AFTER_FAILURES = 3
OFFLINE_AFTER_SECONDS = 25.0
# A rejected key will not fix itself on a retry.
DEFINITE_ERRORS = frozenset({"firewall_auth_failed"})
PRUNE_EVERY_SECONDS = 3600
ACTIVE_SERVICE: FirewallService | None = None
_SENT: Any = object()  # desired(): use the applied port policy snapshot


class ConfigRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    url: str = Field(default=DEFAULT_URL, min_length=6, max_length=2048)
    key: str | None = Field(default=None, min_length=40, max_length=64)


class ConfirmRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    confirmation: str = Field(min_length=1, max_length=32)


class FirewallService:
    def __init__(self, ctx: ModuleContext) -> None:
        self.ctx = ctx
        self.store = FirewallStore(ctx.database)
        self.client = HelperClient(ctx)
        self.settings_path = ctx.data_dir / "control-plane" / SETTINGS_FILE
        self.detector = Detector()
        self.lock = asyncio.Lock()
        self._task: asyncio.Task[None] | None = None
        self.last_audit_id: int | None = None
        self.health = Reachability(OFFLINE_AFTER_FAILURES, OFFLINE_AFTER_SECONDS)
        self.last_checked_at: float | None = None
        self.last_error: str | None = None
        self.last_error_code: str | None = None
        self.info: dict[str, Any] | None = None
        self.helper_hash: str | None = None
        self.applied_hash: str | None = None
        self.last_apply_at: float | None = None
        self.last_apply_error: str | None = None
        self.last_poll_at: float | None = None
        self.sources: dict[str, Any] = {}
        self._last_prune = 0.0
        self.ports = PortPolicyState(self)

    @property
    def reachable(self) -> bool | None:
        return self.health.reachable

    @property
    def last_ok_at(self) -> float | None:
        return self.health.last_ok_at

    # ----- settings --------------------------------------------------------
    def settings(self) -> dict[str, Any]:
        try:
            stored = json.loads(self.settings_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            stored = None
        return load_settings(stored)

    def save_settings(self, settings: dict[str, Any]) -> None:
        self.settings_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.settings_path.with_name(f".{SETTINGS_FILE}.{secrets.token_hex(4)}.tmp")
        temporary.write_text(json.dumps(settings, indent=2) + "\n", encoding="utf-8")
        os.replace(temporary, self.settings_path)

    def local_addresses(self) -> list[str]:
        info = self.info or {}
        values = info.get("local_addresses")
        return [item for item in values if isinstance(item, str)] if isinstance(values, list) \
            else []

    # ----- desired state ---------------------------------------------------
    def desired(self, settings: dict[str, Any], *, mode: str | None = None,
                ports: Any = _SENT) -> DesiredState:
        """Dynamic defense from settings + DB; the port policy is the applied snapshot
        (``ports`` overrides it for preview/apply; never the editable draft)."""
        blocks: list[Block] = []
        for item in self.store.active_blocks(include_simulated=False):
            try:
                blocks.append(Block(parse_network(item["cidr"]), item["expires_at"]))
            except AddressError:
                continue
        return DesiredState(mode=mode or settings["mode"], allow=effective_allowlist(settings),
                            blocks=blocks,
                            ports=self.ports.sent_policy() if ports is _SENT else ports)

    def configured(self) -> bool:
        source, url, _key, _error = self.client.resolve()
        return source is not None and url is not None

    async def reconcile(self, *, force: bool = False) -> dict[str, Any]:
        """Push the desired state when it differs from what the helper holds."""
        if not self.configured():
            return {"applied": False, "error": "firewall_not_configured"}
        settings = await asyncio.to_thread(self.settings)
        state = await asyncio.to_thread(self.desired, settings)
        digest = state.state_hash()
        stale = self.last_apply_at is None or time.time() - self.last_apply_at > RESYNC_SECONDS
        if not force and not stale and digest == self.applied_hash == (
            self.helper_hash or digest
        ):
            return {"applied": False, "in_sync": True, "state_hash": digest}
        try:
            try:
                result = await self.client.request("POST", "/v1/apply", state.to_payload())
            except HelperError as exc:
                if exc.code != "rollback_required":
                    raise
                # The helper rolled back (timer, restart or console recovery) while we
                # still pushed the unconfirmed policy: follow it, then retry once.
                await self.probe()
                state = await asyncio.to_thread(self.desired, settings)
                digest = state.state_hash()
                result = await self.client.request("POST", "/v1/apply", state.to_payload())
        except HelperError as exc:
            self.last_apply_error = exc.code
            if exc.status_code != 409:
                self._mark(False, exc.message, exc.code)
            return {"applied": False, "error": exc.code, "message": exc.message}
        self._mark(True, None)
        self.applied_hash = self.helper_hash = str(result.get("state_hash") or digest)
        self.last_apply_at = time.time()
        self.last_apply_error = None
        # The cached helper info (mode, table present) is now stale; re-probe on
        # the next status read instead of showing the pre-apply state.
        self.last_checked_at = None
        return {"applied": True, "state_hash": self.applied_hash,
                "effective_mode": result.get("effective_mode"), "action": result.get("action")}

    # ----- helper reachability --------------------------------------------
    def _mark(self, ok: bool, error: str | None, code: str | None = None) -> None:
        self.last_checked_at = time.time()
        self.last_error = error
        self.last_error_code = None if ok else code
        transition = self.health.record(ok, immediate=code in DEFINITE_ERRORS)
        if transition == "online":
            self.ctx.events.publish(Event(
                type="firewall.helper_online", severity="info",
                title="Firewall helper is reachable again", module=MODULE_NAME,
                dedupe_key="firewall.helper"))
        elif transition == "offline":
            self.ctx.events.publish(Event(
                type="firewall.helper_offline", severity="error",
                title="Firewall helper is unreachable", message=error or "",
                module=MODULE_NAME, dedupe_key="firewall.helper",
                details={"error_code": code,
                         "consecutive_failures": self.health.failures}))

    async def probe(self) -> tuple[bool, float, str | None]:
        started = time.perf_counter()
        try:
            info = await self.client.request("GET", "/v1/info")
            if not isinstance(info, dict):
                raise HelperError("firewall_unreachable", 502, "unexpected helper payload")
        except HelperError as exc:
            if exc.code == "firewall_not_configured":
                self.health.reset()
                return False, 0.0, exc.code
            self._mark(False, exc.message, exc.code)
            return False, round((time.perf_counter() - started) * 1000, 1), exc.code
        self.info = info
        self.helper_hash = info.get("state_hash") if isinstance(info.get("state_hash"), str) \
            else None
        self._mark(True, None)
        try:
            await asyncio.to_thread(self.ports.adopt, info.get("ports"))
        except Exception:  # pragma: no cover - never break the probe
            LOGGER.exception("port policy sync failed")
        return True, round((time.perf_counter() - started) * 1000, 1), None

    # ----- detection -------------------------------------------------------
    async def collect_signals(self, settings: dict[str, Any]) -> list[dict[str, Any]]:
        signals: list[dict[str, Any]] = []
        sources = settings["sources"]
        files = [
            {"name": name, "kind": kind, "path": sources[name]["path"]}
            for name, kind in FILE_SOURCES.items() if sources.get(name, {}).get("enabled")
        ]
        try:
            result = await self.client.request("POST", "/v1/signals", {
                "sources": files, "sensitive_paths": settings["sensitive_paths"]})
            self._mark(True, None)
            if isinstance(result, dict):
                self.sources = result.get("sources") or {}
                if isinstance(result.get("state_hash"), str):
                    self.helper_hash = result["state_hash"]
                items = result.get("signals")
                if isinstance(items, list):
                    signals.extend(item for item in items if isinstance(item, dict))
        except HelperError as exc:
            if exc.code != "firewall_not_configured":
                self._mark(False, exc.message, exc.code)
        if sources.get("mrk", {}).get("enabled"):
            start = self.last_audit_id or 0
            last, login = await asyncio.to_thread(self.store.login_failures_after, start)
            self.last_audit_id = last
            signals.extend(login)
        return signals

    def handle_hit(self, hit: Hit, settings: dict[str, Any]) -> dict[str, Any] | None:
        mode = settings["mode"]
        target = parse_requester(hit.ip)
        if target is None:
            return None
        if self.store.covering_block(target) is not None:
            return None
        network = parse_network(hit.ip)
        reason = f"{hit.rule.name}: {hit.count} signals in {hit.rule.window_seconds}s"
        details = {"count": hit.count, "sources": list(hit.sources), "sample": hit.sample,
                   "rule": hit.rule.name}
        refused = refusal(network, settings=settings, local_addresses=self.local_addresses())
        if refused is not None:
            self.store.record("skipped", mode=mode, ip=str(network.network_address),
                              rule_id=hit.rule.id, reason=refused[0], details=details)
            return None
        counts = self.store.count_active()
        if counts["enforced"] + counts["simulated"] >= settings["max_blocks"]:
            self.store.record("skipped", mode=mode, ip=hit.ip, rule_id=hit.rule.id,
                              reason="max_blocks", details=details)
            return None
        simulated = mode != "enforce"
        block = self.store.add_block(
            cidr=str(network), origin="auto", reason=reason, simulated=simulated,
            expires_at=int(time.time()) + hit.rule.ban_seconds, rule_id=hit.rule.id)
        self.store.record("would_block" if simulated else "block", mode=mode, ip=hit.ip,
                          rule_id=hit.rule.id, reason=reason,
                          details={**details, "block_id": block["id"],
                                   "expires_at": block["expires_at"]})
        if settings["notify"]:
            self.ctx.events.publish(Event(
                type="firewall.would_block" if simulated else "firewall.blocked",
                severity="info" if simulated else "warning",
                title=(f"Dry run: would block {hit.ip}" if simulated else f"Blocked {hit.ip}"),
                message=reason, module=MODULE_NAME, dedupe_key=f"firewall.blocked:{hit.ip}",
                details={"ip": hit.ip, "rule_id": hit.rule.id, "block_id": block["id"],
                         "expires_at": block["expires_at"], "simulated": simulated}))
        return block

    async def tick(self) -> None:
        async with self.lock:
            settings = await asyncio.to_thread(self.settings)
            now = time.time()
            expired = await asyncio.to_thread(self.store.expire)
            for item in expired:
                await asyncio.to_thread(self.store.record, "expire", mode=settings["mode"],
                                        ip=item["cidr"], rule_id=item["rule_id"],
                                        details={"block_id": item["id"]})
            if self.configured() and settings["mode"] != "off":
                if self.info is None:
                    await self.probe()
                signals = await self.collect_signals(settings)
                self.last_poll_at = now
                rules = await asyncio.to_thread(self.store.rule_specs)
                hits = self.detector.observe(rules, signals, now)
                for hit in hits:
                    await asyncio.to_thread(self.handle_hit, hit, settings)
                if rules:
                    self.detector.prune(now, max(rule.window_seconds for rule in rules))
            elif settings["mode"] != "off" and settings["sources"]["mrk"]["enabled"]:
                # Unpaired: still judge MRK logins so dry-run history is useful.
                start = self.last_audit_id or 0
                last, login = await asyncio.to_thread(self.store.login_failures_after, start)
                self.last_audit_id = last
                rules = await asyncio.to_thread(self.store.rule_specs)
                for hit in self.detector.observe(rules, login, now):
                    await asyncio.to_thread(self.handle_hit, hit, settings)
            await self.reconcile()
            if now - self._last_prune > PRUNE_EVERY_SECONDS:
                self._last_prune = now
                await asyncio.to_thread(self.store.prune, settings["history_retention_days"])

    # ----- status ----------------------------------------------------------
    async def status(self) -> dict[str, Any]:
        source, url, _key, env_error = self.client.resolve()
        configured = source is not None and url is not None
        if configured and (self.last_checked_at is None
                           or time.time() - self.last_checked_at > 10):
            await self.probe()
        settings = await asyncio.to_thread(self.settings)
        counts = await asyncio.to_thread(self.store.count_active)
        rules = await asyncio.to_thread(self.store.list_rules)
        decisions = await asyncio.to_thread(self.store.count_decisions_since,
                                            int(time.time()) - 86400)
        desired = await asyncio.to_thread(self.desired, settings)
        info = self.info if configured and self.reachable else None
        return {
            "configured": configured,
            "source": source,
            "url": url,
            "reachable": self.reachable if configured else None,
            "last_checked_at": self.last_checked_at,
            "last_error": (self.last_error or env_error) if configured else None,
            "error_code": self.last_error_code if configured else None,
            "consecutive_failures": self.health.failures if configured else 0,
            "last_ok_at": self.health.last_ok_at if configured else None,
            "mode": settings["mode"],
            "helper": None if info is None else {
                "version": info.get("version"),
                "nft_available": info.get("nft_available"),
                "force_dry_run": info.get("force_dry_run"),
                "mode": info.get("mode"),
                "effective_mode": info.get("effective_mode"),
                "table": info.get("table"),
                "local_addresses": info.get("local_addresses"),
                "last_error": info.get("last_error"),
            },
            "counts": {
                "active_blocks": counts["enforced"],
                "simulated_blocks": counts["simulated"],
                "rules_enabled": sum(1 for item in rules if item["enabled"]),
                "decisions_24h": decisions,
                "allowlist": len(settings["allowlist"]),
            },
            "desired_state_hash": desired.state_hash(),
            "applied_state_hash": self.applied_hash,
            "in_sync": configured and self.applied_hash == desired.state_hash(),
            "last_poll_at": self.last_poll_at,
            "last_apply_at": self.last_apply_at,
            "last_apply_error": self.last_apply_error,
            "sources": self.sources,
            "poll_interval_seconds": settings["poll_interval_seconds"],
        }

    # ----- background ------------------------------------------------------
    async def _loop(self) -> None:
        while True:
            try:
                interval = (await asyncio.to_thread(self.settings))["poll_interval_seconds"]
            except Exception:
                interval = 15
            await asyncio.sleep(interval)
            try:
                await self.tick()
            except asyncio.CancelledError:
                raise
            except Exception:
                LOGGER.exception("firewall tick failed")

    async def start(self) -> None:
        await asyncio.to_thread(self.store.seed_rules)
        self.last_audit_id = await asyncio.to_thread(self.store.last_audit_id)
        self._task = asyncio.create_task(self._loop(), name="mrk-firewall-engine")

    async def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None


async def _body(request: Request) -> Any:
    raw = await request.body()
    if not raw.strip():
        return {}
    try:
        return json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        raise FirewallError("invalid_json", "request body must be JSON") from None


def _query_int(request: Request, name: str, low: int, high: int) -> int | None:
    value = request.query_params.get(name)
    if value is None or value == "":
        return None
    if not value.isdigit() or not low <= int(value) <= high:
        raise FirewallError("invalid_query", f"{name} must be an integer {low}..{high}")
    return int(value)


def register(ctx: ModuleContext) -> None:
    global ACTIVE_SERVICE
    service = FirewallService(ctx)
    ACTIVE_SERVICE = service
    router = APIRouter(prefix="/api/v1/firewall", include_in_schema=False)

    def fail(exc: FirewallError | HelperError) -> JSONResponse:
        return ctx.error_payload(exc.code, exc.message, exc.status_code)

    def reader(request: Request) -> Any:
        return ctx.require_principal(request, "firewall:read")

    def writer(request: Request) -> Any:
        principal = ctx.require_principal(request, "firewall:write")
        ctx.require_csrf(request, principal)
        return principal

    async def audit(user_id: int, action: str, object_id: str | None,
                    result: str = "success") -> None:
        await asyncio.to_thread(ctx.audit, user_id, action, "firewall", object_id, result)

    # ---- status & pairing ----

    @router.get("/status")
    async def firewall_status(request: Request):
        reader(request)
        return await service.status()

    @router.put("/config")
    async def firewall_config(request: Request, body: ConfigRequest):
        principal = writer(request)
        if service.client.env_managed():
            return ctx.error_payload("firewall_managed_by_environment",
                                     "The firewall helper is managed by environment variables",
                                     409)
        try:
            await asyncio.to_thread(service.client.save, body.url, body.key)
        except HelperError as exc:
            return fail(exc)
        except ValueError as exc:
            message = str(exc)
            code = "invalid_firewall_key" if "key" in message else "invalid_firewall_url"
            return ctx.error_payload(code, message, 422)
        service.info = None
        service.applied_hash = service.helper_hash = None
        service.health.reset()
        await audit(principal.user_id, "firewall.config.update", "mrk-firewall")
        await service.probe()
        async with service.lock:
            await service.reconcile(force=True)
        return await service.status()

    @router.delete("/config")
    async def firewall_unpair(request: Request, body: ConfirmRequest):
        principal = writer(request)
        if body.confirmation != "UNPAIR":
            return ctx.error_payload("confirmation_required", 'Type "UNPAIR" to confirm', 422)
        if service.client.env_managed():
            return ctx.error_payload("firewall_managed_by_environment",
                                     "The firewall helper is managed by environment variables",
                                     409)
        await asyncio.to_thread(service.client.unpair)
        service.info = None
        service.health.reset()
        service.applied_hash = service.helper_hash = None
        await audit(principal.user_id, "firewall.unpair", "mrk-firewall")
        return await service.status()

    @router.post("/test")
    async def firewall_test(request: Request):
        principal = writer(request)
        if not service.configured():
            return ctx.error_payload("firewall_not_configured",
                                     "The firewall helper is not paired", 409)
        ok, latency, error_code = await service.probe()
        await audit(principal.user_id, "firewall.test", "mrk-firewall",
                    "success" if ok else "failure")
        result: dict[str, Any] = {"ok": ok, "latency_ms": latency}
        if error_code:
            result["error_code"] = error_code
        return result

    # ---- settings ----

    @router.get("/settings")
    async def get_settings(request: Request):
        reader(request)
        return await asyncio.to_thread(service.settings)

    @router.put("/settings", response_model=None)
    async def put_settings(request: Request):
        principal = writer(request)
        try:
            body = await _body(request)
            if not isinstance(body, dict):
                raise FirewallError("invalid_settings", "settings must be an object")
            patch = dict(body)
            confirmation = patch.pop("confirmation", None)
            async with service.lock:
                current = await asyncio.to_thread(service.settings)
                updated = merge_settings(current, patch)
                enabling = updated["mode"] == "enforce" and current["mode"] != "enforce"
                if enabling and confirmation != ENFORCE_CONFIRMATION:
                    raise FirewallError("confirmation_required",
                                        f'Type "{ENFORCE_CONFIRMATION}" to enable enforce mode')
                requester = parse_requester(request.client.host if request.client else None)
                if updated["mode"] == "enforce" and requester is not None:
                    allow = effective_allowlist(updated)
                    if not any(net.version == requester.version and requester in net
                               for net in allow):
                        updated["allowlist"].append({
                            "cidr": str(parse_network(str(requester))),
                            "note": f"auto: requester of {principal.username} enabling enforce",
                            "added_at": int(time.time()), "auto": True})
                await asyncio.to_thread(service.save_settings, updated)
                if updated["mode"] != current["mode"]:
                    await asyncio.to_thread(
                        service.store.record, "mode", mode=updated["mode"],
                        user_id=principal.user_id,
                        reason=f"{current['mode']} -> {updated['mode']}")
                sync = await service.reconcile(force=True)
        except FirewallError as exc:
            await audit(principal.user_id, "firewall.settings.update", None, "failure")
            return fail(exc)
        await audit(principal.user_id, "firewall.settings.update", None)
        if updated["mode"] != current["mode"]:
            await audit(principal.user_id, "firewall.mode.change", updated["mode"])
        return {**updated, "sync": sync}

    # ---- rules ----

    @router.get("/rules")
    async def list_rules(request: Request):
        reader(request)
        return {"items": await asyncio.to_thread(service.store.list_rules)}

    @router.post("/rules", status_code=201, response_model=None)
    async def create_rule(request: Request):
        principal = writer(request)
        try:
            values = validate_rule(await _body(request))
            settings = await asyncio.to_thread(service.settings)
            item = await asyncio.to_thread(service.store.create_rule, values,
                                           settings["default_ban_seconds"])
        except FirewallError as exc:
            await audit(principal.user_id, "firewall.rule.create", None, "failure")
            return fail(exc)
        await audit(principal.user_id, "firewall.rule.create", item["id"])
        return item

    @router.patch("/rules/{rule_id}", response_model=None)
    async def update_rule(rule_id: str, request: Request):
        principal = writer(request)
        try:
            values = validate_rule(await _body(request), partial=True)
            item = await asyncio.to_thread(service.store.update_rule, rule_id, values)
        except KeyError:
            raise StarletteHTTPException(status_code=404) from None
        except FirewallError as exc:
            await audit(principal.user_id, "firewall.rule.update", rule_id, "failure")
            return fail(exc)
        await audit(principal.user_id, "firewall.rule.update", rule_id)
        return item

    @router.delete("/rules/{rule_id}", response_model=None)
    async def delete_rule(rule_id: str, request: Request):
        principal = writer(request)
        try:
            await asyncio.to_thread(service.store.delete_rule, rule_id)
        except KeyError:
            raise StarletteHTTPException(status_code=404) from None
        except FirewallError as exc:
            return fail(exc)
        await audit(principal.user_id, "firewall.rule.delete", rule_id)
        return {"deleted": True, "id": rule_id}

    # ---- blocks ----

    @router.get("/blocks")
    async def list_blocks(request: Request):
        reader(request)
        include = request.query_params.get("include_simulated", "true").lower() != "false"
        return {"items": await asyncio.to_thread(service.store.active_blocks,
                                                 include_simulated=include)}

    @router.post("/blocks", status_code=201, response_model=None)
    async def create_block(request: Request):
        principal = writer(request)
        try:
            body = await _body(request)
            if not isinstance(body, dict) or set(body) - {"ip", "cidr", "duration_seconds",
                                                          "reason"}:
                raise FirewallError("invalid_block",
                                    "body is {ip|cidr, duration_seconds, reason}")
            if ("ip" in body) == ("cidr" in body):
                raise FirewallError("invalid_block", "give exactly one of ip or cidr")
            reason = body.get("reason")
            if not isinstance(reason, str) or not 1 <= len(reason.strip()) <= 500:
                raise FirewallError("invalid_block", "reason must be 1..500 characters")
            try:
                network = parse_network(body.get("ip", body.get("cidr")))
            except AddressError as exc:
                raise FirewallError(exc.code, str(exc)) from exc
            if "ip" in body and network.prefixlen != network.max_prefixlen:
                raise FirewallError("invalid_block", "ip must be a single address; use cidr")
            async with service.lock:
                settings = await asyncio.to_thread(service.settings)
                if "duration_seconds" not in body:
                    duration: int | None = settings["default_ban_seconds"]
                else:
                    duration = body["duration_seconds"]
                    if duration is not None and (
                        not isinstance(duration, int) or isinstance(duration, bool)
                        or not 60 <= duration <= settings["max_ban_seconds"]
                    ):
                        raise FirewallError(
                            "invalid_block",
                            f"duration_seconds must be null or 60..{settings['max_ban_seconds']}")
                requester = parse_requester(request.client.host if request.client else None)
                refused = refusal(network, settings=settings, requester=requester,
                                  local_addresses=service.local_addresses())
                if refused is not None:
                    raise FirewallError(refused[0], refused[1])
                active = await asyncio.to_thread(service.store.active_blocks,
                                                 include_simulated=False)
                if any(item["cidr"] == str(network) for item in active):
                    raise FirewallError("already_blocked", "this address is already blocked", 409)
                counts = await asyncio.to_thread(service.store.count_active)
                if counts["enforced"] + counts["simulated"] >= settings["max_blocks"]:
                    raise FirewallError("max_blocks_reached",
                                        "the maximum number of blocks is reached", 409)
                expires = None if duration is None else int(time.time()) + duration
                item = await asyncio.to_thread(
                    lambda: service.store.add_block(
                        cidr=str(network), origin="manual", reason=reason.strip(),
                        simulated=False, expires_at=expires, user_id=principal.user_id))
                await asyncio.to_thread(
                    lambda: service.store.record(
                        "manual_block", mode=settings["mode"], ip=str(network),
                        user_id=principal.user_id, reason=reason.strip(),
                        details={"block_id": item["id"], "expires_at": expires}))
                sync = await service.reconcile(force=True)
        except FirewallError as exc:
            await audit(principal.user_id, "firewall.block.create", None, "failure")
            return fail(exc)
        await audit(principal.user_id, "firewall.block.create", item["cidr"])
        return {**item, "sync": sync}

    @router.delete("/blocks/{block_id}", response_model=None)
    async def delete_block(block_id: str, request: Request):
        principal = writer(request)
        try:
            body = await _body(request)
        except FirewallError as exc:
            return fail(exc)
        reason = body.get("reason") if isinstance(body, dict) else None
        async with service.lock:
            try:
                item = await asyncio.to_thread(service.store.remove_block, block_id, "manual")
            except KeyError:
                raise StarletteHTTPException(status_code=404) from None
            settings = await asyncio.to_thread(service.settings)
            await asyncio.to_thread(
                lambda: service.store.record(
                    "unblock", mode=settings["mode"], ip=item["cidr"],
                    user_id=principal.user_id,
                    reason=reason[:500] if isinstance(reason, str) else "",
                    details={"block_id": block_id}))
            sync = await service.reconcile(force=True)
        await audit(principal.user_id, "firewall.block.delete", item["cidr"])
        return {**item, "sync": sync}

    @router.post("/blocks/clear", response_model=None)
    async def clear_blocks(request: Request):
        principal = writer(request)
        try:
            body = await _body(request)
        except FirewallError as exc:
            return fail(exc)
        if not isinstance(body, dict) or body.get("confirmation") != CLEAR_CONFIRMATION:
            return ctx.error_payload("confirmation_required",
                                     f'Type "{CLEAR_CONFIRMATION}" to confirm', 422)
        async with service.lock:
            removed = await asyncio.to_thread(service.store.remove_all, "cleared")
            settings = await asyncio.to_thread(service.settings)
            await asyncio.to_thread(
                lambda: service.store.record("clear", mode=settings["mode"],
                                             user_id=principal.user_id,
                                             details={"removed": len(removed)}))
            sync = await service.reconcile(force=True)
        await audit(principal.user_id, "firewall.blocks.clear", str(len(removed)))
        return {"removed": len(removed), "sync": sync}

    # ---- history & preview ----

    @router.get("/events", response_model=None)
    async def list_events(request: Request):
        reader(request)
        try:
            action = request.query_params.get("action") or None
            if action is not None and action not in DECISION_ACTIONS:
                raise FirewallError("invalid_query", f"action must be one of {DECISION_ACTIONS}")
            ip = request.query_params.get("ip") or None
            if ip is not None and len(ip) > 64:
                raise FirewallError("invalid_query", "ip is too long")
            limit = _query_int(request, "limit", 1, 500) or 100
            since = _query_int(request, "since", 0, 10**11)
            before_id = _query_int(request, "before_id", 1, 2**62)
        except FirewallError as exc:
            return fail(exc)
        items = await asyncio.to_thread(
            lambda: service.store.list_decisions(ip=ip, action=action, since=since,
                                                 before_id=before_id, limit=limit))
        return {"items": items, "next_before_id": items[-1]["id"] if len(items) == limit
                else None}

    @router.get("/preview")
    async def preview(request: Request):
        reader(request)
        settings = await asyncio.to_thread(service.settings)
        state = await asyncio.to_thread(service.desired, settings, mode="enforce")
        simulated = [item for item in await asyncio.to_thread(service.store.active_blocks)
                     if item["simulated"]]
        payload = state.to_payload()
        return {
            "mode": settings["mode"],
            "would_apply": {"allow": payload["allow"], "blocks": payload["blocks"]},
            "ruleset": render_ruleset(state),
            "simulated": simulated,
            "state_hash": DesiredState(settings["mode"], state.allow, state.blocks).state_hash(),
        }

    register_port_routes(router, ctx, service, reader=reader, writer=writer, body=_body,
                         audit=audit)
    ctx.routers.append(router)
    ctx.start_hooks.append(service.start)
    ctx.stop_hooks.append(service.stop)
