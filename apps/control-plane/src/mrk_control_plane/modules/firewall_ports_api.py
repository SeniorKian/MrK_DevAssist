"""Port policy API and its helper synchronisation (docs/45).

The draft (rules, lists, settings) is edited freely; nothing reaches the server until an
operator applies it with the typed confirmation. An apply that changes the policy runs
with an automatic rollback timer in the helper; "Keep these rules" confirms it. The
panel keeps the applied snapshot (``confirmed`` + ``pending``) and always pushes that,
never the draft, so the dynamic-defense reconcile loop cannot undo a rollback.
"""

from __future__ import annotations

import asyncio
import json
import os
import secrets
import time
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from .. import dns_client
from ..firewall.ports import CHAIN_INPUT, PortError, PortPolicy, TempAllow, port_in, risk_key
from ..module_context import Event, ModuleContext
from .firewall_client import HelperError
from .firewall_engine import ENFORCE_CONFIRMATION, FirewallError, parse_requester
from .firewall_ports import (
    RULE_ORIGINS,
    compile_policy,
    load_port_settings,
    lockout_problems,
    management_probes,
    merge_port_settings,
    relevant_protected,
    ruleset_diff,
    ruleset_text,
    validate_port_rule,
    validate_source_list,
)
from .firewall_ports_store import PortStore

if TYPE_CHECKING:
    from .firewall import FirewallService

SETTINGS_FILE = "firewall-ports.json"
STATE_FILE = "firewall-ports-state.json"
MAX_IMPORT = 256
EMPTY_STATE: dict[str, Any] = {"confirmed": None, "pending": None, "last_rollback": None,
                               "applied_at": None}


class LockoutError(FirewallError):
    def __init__(self, problems: list[dict[str, Any]]) -> None:
        first = problems[0]["code"]
        messages = {
            "lockout_ssh": "SSH would be closed for the management address",
            "lockout_panel": "the panel port would be closed for the management address",
            "protected_port_closed": "a protected port (Swarm, Dokploy or DNS) would be closed",
        }
        super().__init__(first, messages.get(first, "this change could lock you out"), 422)
        self.problems = problems


def _write_json(path: Any, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(4)}.tmp")
    temporary.write_bytes((json.dumps(payload, indent=2) + "\n").encode("utf-8"))
    os.replace(temporary, path)


def _read_json(path: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def panel_ports(request: Request) -> list[int]:
    """The port the browser used to reach the panel (proxy header first)."""
    forwarded = request.headers.get("x-forwarded-port", "").split(",")[0].strip()
    if forwarded.isdigit() and 1 <= int(forwarded) <= 65535:
        return [int(forwarded)]
    if request.url.port:
        return [int(request.url.port)]
    scheme = request.headers.get("x-forwarded-proto", "").split(",")[0].strip() \
        or request.url.scheme
    return [443 if scheme == "https" else 80]


class PortPolicyState:
    def __init__(self, service: FirewallService) -> None:
        self.service = service
        self.ctx: ModuleContext = service.ctx
        self.store = PortStore(service.ctx.database)
        base = service.ctx.data_dir / "control-plane"
        self.settings_path = base / SETTINGS_FILE
        self.state_path = base / STATE_FILE
        # Quick actions (firewall_quick_api.QuickJournal) register themselves here.
        self.quick: Any = None

    # ----- files -------------------------------------------------------------------
    def settings(self) -> dict[str, Any]:
        return load_port_settings(_read_json(self.settings_path))

    def save_settings(self, settings: dict[str, Any]) -> None:
        _write_json(self.settings_path, settings)

    def state(self) -> dict[str, Any]:
        stored = _read_json(self.state_path)
        state = dict(EMPTY_STATE)
        if isinstance(stored, dict):
            state.update({key: stored.get(key) for key in EMPTY_STATE})
        return state

    def save_state(self, state: dict[str, Any]) -> None:
        _write_json(self.state_path, state)

    def sent_policy(self, now: float | None = None) -> PortPolicy | None:
        """What the panel pushes: the pending change, else the confirmed policy."""
        state = self.state()
        payload = (state["pending"] or {}).get("payload") if state["pending"] else \
            state["confirmed"]
        if payload is None:
            return None
        try:
            return PortPolicy.from_payload(payload, now=now)
        except PortError:
            return None

    # ----- helper sync -------------------------------------------------------------
    def adopt(self, info: object) -> str | None:
        """Follow the helper after a rollback/recovery or a confirmation we did not see."""
        if not isinstance(info, dict):
            return None
        state = self.state()
        helper_pending = info.get("pending") if isinstance(info.get("pending"), dict) else None
        lkg = info.get("lkg") if isinstance(info.get("lkg"), dict) else None
        lkg_key = info.get("lkg_key")
        pending = state["pending"]
        outcome: str | None = None
        if pending:
            if helper_pending and helper_pending.get("token") == pending.get("token"):
                return None
            pending_key = _payload_key(pending.get("payload"))
            if lkg_key == pending_key:
                state["confirmed"], outcome = pending.get("payload"), "confirmed"
            else:
                state["confirmed"], outcome = lkg, "rolled_back"
            state["pending"] = None
        elif not helper_pending and lkg_key is not None \
                and _payload_key(state["confirmed"]) != lkg_key:
            state["confirmed"], outcome = lkg, "recovered"
        if outcome is None:
            return None
        if outcome != "confirmed":
            last = info.get("last_rollback")
            state["last_rollback"] = last if isinstance(last, dict) else {
                "at": int(time.time()), "reason": "helper", "outcome": "restored"}
        self.save_state(state)
        if outcome != "confirmed" and pending and pending.get("change_id") \
                and self.quick is not None:
            # A quick change that was not kept: take its rules out of the draft too.
            self.quick.revert_draft(str(pending["change_id"]), "rolled_back")
        if outcome != "confirmed":
            reason = str((state["last_rollback"] or {}).get("reason", "helper"))
            self.service.store.record("ports_rollback", mode=self.service.settings()["mode"],
                                      reason=reason, details={"outcome": outcome})
            self.ctx.events.publish(Event(
                type="firewall.ports.rolled_back", severity="warning",
                title="Firewall port rules were rolled back",
                message=f"The last port policy change was not kept ({reason}).",
                module="firewall", dedupe_key="firewall.ports.rollback"))
        return outcome

    def cleanup_expired(self, now: int | None = None) -> list[dict[str, Any]]:
        """Take temporary rules out of the draft once their time is over. The helper
        already stopped enforcing them; the applied snapshot drops them on the next apply
        (expired rules never count as a difference)."""
        removed = self.store.delete_expired(int(time.time()) if now is None else now)
        for item in removed:
            self.service.store.record(
                "ports_expire", mode=self.service.settings()["mode"],
                reason=item["name"][:200],
                details={"rule_id": item["id"], "expires_at": item["expires_at"]})
        return removed

    # ----- planning ------------------------------------------------------------------
    def context(self, request: Request) -> dict[str, Any]:
        info = self.service.info or {}
        settings = self.settings()
        detected = detected_ssh(info.get("ssh"))
        if settings["ssh_ports"]:
            ssh_ports, ssh_source = list(settings["ssh_ports"]), "admin"
        else:
            ssh_ports, ssh_source = detected["ports"], detected["source"]
        listening = info.get("listening") if isinstance(info.get("listening"), list) else None
        try:
            dns_installed = dns_client.installed()
        except Exception:  # noqa: BLE001 - optional service
            dns_installed = False
        requester = parse_requester(request.client.host if request.client else None)
        return {
            "settings": settings,
            "ssh_ports": ssh_ports,
            "ssh_source": ssh_source,
            "ssh_detected": detected,
            "panel_ports": sorted(set(panel_ports(request)) | set(settings["panel_ports"])),
            "protected": relevant_protected(listening, dns_installed),
            "listening": listening,
            "requester": requester,
        }

    def plan(self, request: Request, *, temp_allow: bool | None = None,
             now: int | None = None, rules: list[dict[str, Any]] | None = None
             ) -> dict[str, Any]:
        """Compile the draft (or ``rules`` instead of it) and run the lockout check."""
        stamp = int(time.time()) if now is None else now
        context = self.context(request)
        settings = context["settings"]
        lists = self.store.list_lists()
        use_temp = settings["temp_allow_requester"] if temp_allow is None else temp_allow
        requester = context["requester"]
        temp = [] if not use_temp or requester is None else [
            TempAllow(_host_network(requester), stamp + settings["temp_allow_seconds"])]
        policy, warnings = compile_policy(self.store.list_rules() if rules is None else rules,
                                          {item["id"]: item for item in lists}, settings,
                                          temp_allow=temp, now=stamp)
        problems = lockout_problems(
            policy, probes=management_probes(requester, lists), ssh_ports=context["ssh_ports"],
            panel_ports=context["panel_ports"], protected=context["protected"],
            allowed_closed=settings["allow_closed_protected"],
            ssh_require_all=context["ssh_source"] == "admin", now=stamp)
        return {**context, "policy": policy, "warnings": warnings, "problems": problems,
                "lists": lists}

    # ----- status ------------------------------------------------------------------
    async def status(self, request: Request) -> dict[str, Any]:
        service = self.service
        state = await asyncio.to_thread(self.state)
        now = time.time()
        pending = state["pending"]
        stale = service.last_checked_at is None or now - service.last_checked_at > 10
        if service.configured() and (service.info is None or stale or (
                pending and now >= float(pending.get("deadline", 0)))):
            await service.probe()
            state = await asyncio.to_thread(self.state)
            pending = state["pending"]
        plan = await asyncio.to_thread(self.plan, request)
        sent = await asyncio.to_thread(self.sent_policy)
        info = service.info or {}
        rules = await asyncio.to_thread(self.store.list_rules)
        return {
            "configured": service.configured(),
            "reachable": service.reachable,
            "force_dry_run": bool(info.get("force_dry_run")),
            "nft_available": info.get("nft_available"),
            "settings": plan["settings"],
            "active": sent is not None and sent.enabled,
            "applied_rules": 0 if sent is None else len(sent.rules),
            "pending": None if not pending else {
                "deadline": pending.get("deadline"), "started_at": pending.get("started_at"),
                "remaining": max(0, int(float(pending.get("deadline", 0)) - now)),
            },
            "last_rollback": state["last_rollback"],
            "applied_at": state["applied_at"],
            "draft": {"rules": len(rules), "enabled": sum(1 for r in rules if r["enabled"]),
                      "differs": not draft_matches_applied(plan["policy"], sent, now)},
            "ssh": {"ports": plan["ssh_ports"], "source": plan["ssh_source"],
                    "admin_ports": plan["settings"]["ssh_ports"],
                    "detected": plan["ssh_detected"]},
            "panel_ports": plan["panel_ports"],
            "requester": None if plan["requester"] is None else str(plan["requester"]),
            "problems": plan["problems"],
            "warnings": plan["warnings"],
            "protected": sorted(plan["protected"]),
            "helper": info.get("ports"),
        }


SSH_SOURCES = ("listener", "ssh_socket", "sshd_config", "assumed")


def detected_ssh(raw: object) -> dict[str, Any]:
    """The helper's SSH facts -> {ports, source, listener, sshd_config, ssh_socket, mounts}.

    Understands the older helper shape ``{detected, ports}`` (sshd_config only) too; a
    missing or unreadable answer means 22 is assumed.
    """
    facts = raw if isinstance(raw, dict) else {}
    ports = [int(p) for p in facts.get("ports") or []
             if isinstance(p, int) and not isinstance(p, bool) and 1 <= p <= 65535][:16]
    source = facts.get("source")
    if source not in SSH_SOURCES:
        source = "sshd_config" if facts.get("detected") and ports else "assumed"
    if source == "assumed" or not ports:
        ports, source = [22], "assumed"
    sources = facts.get("sources") if isinstance(facts.get("sources"), dict) else {}
    listener = sources.get("listener") if isinstance(sources.get("listener"), dict) else {}
    config = sources.get("sshd_config") if isinstance(sources.get("sshd_config"), dict) else {}
    unit = sources.get("ssh_socket") if isinstance(sources.get("ssh_socket"), dict) else {}
    mounts = facts.get("mounts") if isinstance(facts.get("mounts"), dict) else {}

    def port_list(value: object) -> list[int]:
        return [p for p in value if isinstance(p, int) and not isinstance(p, bool)][:16] \
            if isinstance(value, list) else []

    return {
        "ports": ports,
        "source": source,
        "listener": {"available": bool(listener.get("available")),
                     "ports": port_list(listener.get("ports")),
                     "other": [item for item in listener.get("other") or []
                               if isinstance(item, dict)][:16]},
        "sshd_config": {"readable": bool(config.get("readable", facts.get("detected"))),
                        "ports": port_list(config.get("ports"))},
        "ssh_socket": {"readable": bool(unit.get("readable")),
                       "enabled": unit.get("enabled") if isinstance(unit.get("enabled"), bool)
                       else None,
                       "ports": port_list(unit.get("ports"))},
        "mounts": {"ssh": bool(mounts.get("ssh", facts.get("detected"))),
                   "systemd": bool(mounts.get("systemd"))},
    }


def draft_matches_applied(draft: PortPolicy, sent: PortPolicy | None, now: float) -> bool:
    """True when the draft has no unapplied edits (an empty draft equals "off")."""
    if sent is None or not sent.enabled:
        current = draft.without_expired(now)
        return not current.rules and current.input_policy == "accept" \
            and current.forward_policy == "accept"
    return policy_key(draft, now) == policy_key(sent, now)


def policy_key(policy: PortPolicy | None, now: float) -> str:
    """Identity of what is loaded at ``now`` (rules that already expired do not count)."""
    return "off" if policy is None else policy.effective_key(now)


def _host_network(address: Any) -> Any:
    from ..firewall.addresses import parse_network

    return parse_network(str(address))


def _payload_key(payload: object) -> str | None:
    if not isinstance(payload, dict):
        return "off" if payload is None else None
    try:
        return PortPolicy.from_payload(payload).risk_key()
    except PortError:
        return None


def _rule_signature(values: dict[str, Any]) -> tuple[Any, ...]:
    return (values.get("protocol"), tuple(values.get("ports", [])), values.get("scope"),
            values.get("action", "accept"), values.get("source_kind", "public"),
            tuple(values.get("source_cidrs", [])), values.get("source_list_id"))


def _proposal_values(item: dict[str, Any]) -> dict[str, Any] | None:
    try:
        return validate_port_rule({key: item[key] for key in (
            "name", "description", "protocol", "ports", "source", "scope", "action")
            if key in item})
    except (FirewallError, KeyError, TypeError):
        return None


async def push_policy(service: FirewallService, state_ports: Any, *,
                      rollback_seconds: int | None) -> dict[str, Any]:
    """Send dynamic defense + this port policy to the helper (caller holds the lock)."""
    settings = await asyncio.to_thread(service.settings)
    state = await asyncio.to_thread(service.desired, settings, ports=state_ports)
    payload = state.to_payload()
    if rollback_seconds is not None:
        payload["rollback_seconds"] = rollback_seconds
    result = await service.client.request("POST", "/v1/apply", payload)
    service.applied_hash = service.helper_hash = str(result.get("state_hash"))
    service.last_apply_at = time.time()
    service.last_apply_error = None
    service.last_checked_at = None
    return result


def register_port_routes(router: APIRouter, ctx: ModuleContext, service: FirewallService, *,
                         reader: Callable[[Request], Any], writer: Callable[[Request], Any],
                         body: Callable[[Request], Any],
                         audit: Callable[..., Any]) -> None:
    ports = service.ports

    def fail(exc: FirewallError | HelperError) -> JSONResponse:
        if isinstance(exc, LockoutError):
            return ctx.error_payload(  # type: ignore[call-arg]
                exc.code, exc.message, exc.status_code, problems=exc.problems)
        return ctx.error_payload(exc.code, exc.message, exc.status_code)

    async def push(state_ports: Any, *, rollback_seconds: int | None) -> dict[str, Any]:
        return await push_policy(service, state_ports, rollback_seconds=rollback_seconds)

    # ---- draft: rules ----

    @router.get("/ports/rules")
    async def list_port_rules(request: Request):
        reader(request)
        return {"items": await asyncio.to_thread(ports.store.list_rules)}

    @router.post("/ports/rules", status_code=201, response_model=None)
    async def create_port_rule(request: Request):
        principal = writer(request)
        try:
            values = validate_port_rule(await body(request))
            item = await asyncio.to_thread(
                lambda: ports.store.create_rule(values, user_id=principal.user_id))
        except FirewallError as exc:
            await audit(principal.user_id, "firewall.port_rule.create", None, "failure")
            return fail(exc)
        await audit(principal.user_id, "firewall.port_rule.create", item["id"])
        return item

    @router.patch("/ports/rules/{rule_id}", response_model=None)
    async def update_port_rule(rule_id: str, request: Request):
        principal = writer(request)
        try:
            values = validate_port_rule(await body(request), partial=True)
            item = await asyncio.to_thread(ports.store.update_rule, rule_id, values)
        except KeyError:
            raise StarletteHTTPException(status_code=404) from None
        except FirewallError as exc:
            await audit(principal.user_id, "firewall.port_rule.update", rule_id, "failure")
            return fail(exc)
        await audit(principal.user_id, "firewall.port_rule.update", rule_id)
        return item

    @router.delete("/ports/rules/{rule_id}", response_model=None)
    async def delete_port_rule(rule_id: str, request: Request):
        principal = writer(request)
        try:
            await asyncio.to_thread(ports.store.delete_rule, rule_id)
        except KeyError:
            raise StarletteHTTPException(status_code=404) from None
        await audit(principal.user_id, "firewall.port_rule.delete", rule_id)
        return {"deleted": True, "id": rule_id}

    # ---- draft: named source lists ----

    @router.get("/ports/lists")
    async def list_source_lists(request: Request):
        reader(request)
        return {"items": await asyncio.to_thread(ports.store.list_lists)}

    @router.post("/ports/lists", status_code=201, response_model=None)
    async def create_source_list(request: Request):
        principal = writer(request)
        try:
            values = validate_source_list(await body(request))
            item = await asyncio.to_thread(ports.store.create_list, values)
        except FirewallError as exc:
            await audit(principal.user_id, "firewall.source_list.create", None, "failure")
            return fail(exc)
        await audit(principal.user_id, "firewall.source_list.create", item["id"])
        return item

    @router.patch("/ports/lists/{list_id}", response_model=None)
    async def update_source_list(list_id: str, request: Request):
        principal = writer(request)
        try:
            values = validate_source_list(await body(request), partial=True)
            item = await asyncio.to_thread(ports.store.update_list, list_id, values)
        except KeyError:
            raise StarletteHTTPException(status_code=404) from None
        except FirewallError as exc:
            await audit(principal.user_id, "firewall.source_list.update", list_id, "failure")
            return fail(exc)
        await audit(principal.user_id, "firewall.source_list.update", list_id)
        return item

    @router.delete("/ports/lists/{list_id}", response_model=None)
    async def delete_source_list(list_id: str, request: Request):
        principal = writer(request)
        try:
            await asyncio.to_thread(ports.store.delete_list, list_id)
        except KeyError:
            raise StarletteHTTPException(status_code=404) from None
        except FirewallError as exc:
            return fail(exc)
        await audit(principal.user_id, "firewall.source_list.delete", list_id)
        return {"deleted": True, "id": list_id}

    # ---- draft: policy settings ----

    @router.get("/ports/settings")
    async def get_port_settings(request: Request):
        reader(request)
        return await asyncio.to_thread(ports.settings)

    @router.put("/ports/settings", response_model=None)
    async def put_port_settings(request: Request):
        principal = writer(request)
        try:
            patch = await body(request)
            updated = merge_port_settings(await asyncio.to_thread(ports.settings), patch)
            await asyncio.to_thread(ports.save_settings, updated)
        except FirewallError as exc:
            await audit(principal.user_id, "firewall.port_settings.update", None, "failure")
            return fail(exc)
        await audit(principal.user_id, "firewall.port_settings.update", None)
        return updated

    # ---- status, preview, apply, confirm, undo, disable ----

    @router.get("/ports/status")
    async def port_status(request: Request):
        reader(request)
        return await ports.status(request)

    @router.get("/ports/preview")
    async def port_preview(request: Request):
        reader(request)
        if service.configured() and service.info is None:
            await service.probe()
        plan = await asyncio.to_thread(ports.plan, request)
        settings = await asyncio.to_thread(service.settings)
        now = int(time.time())
        current_state = await asyncio.to_thread(service.desired, settings)
        next_state = await asyncio.to_thread(service.desired, settings, ports=plan["policy"])
        current = ruleset_text(current_state, now)
        following = ruleset_text(next_state, now)
        return {
            "current": current,
            "next": following,
            "diff": ruleset_diff(current, following),
            "changed": risk_key(current_state.ports) != risk_key(next_state.ports),
            "problems": plan["problems"],
            "warnings": plan["warnings"],
            "rules": len(plan["policy"].rules),
            "ssh_ports": plan["ssh_ports"],
            "panel_ports": plan["panel_ports"],
            "requester": None if plan["requester"] is None else str(plan["requester"]),
            "temp_allow": [str(item.network) for item in plan["policy"].temp_allow],
        }

    @router.post("/ports/apply", response_model=None)
    async def port_apply(request: Request):
        principal = writer(request)
        try:
            payload = await body(request)
            if not isinstance(payload, dict) or set(payload) - {
                    "confirmation", "temp_allow", "rollback_seconds"}:
                raise FirewallError("invalid_request",
                                    "body is {confirmation, temp_allow, rollback_seconds}")
            if payload.get("confirmation") != ENFORCE_CONFIRMATION:
                raise FirewallError("confirmation_required",
                                    f'Type "{ENFORCE_CONFIRMATION}" to apply the port rules')
            temp_allow = payload.get("temp_allow")
            if temp_allow is not None and not isinstance(temp_allow, bool):
                raise FirewallError("invalid_request", "temp_allow must be true or false")
            if not service.configured():
                raise FirewallError("firewall_not_configured",
                                    "The firewall helper is not paired", 409)
            settings = await asyncio.to_thread(ports.settings)
            rollback = payload.get("rollback_seconds", settings["rollback_seconds"])
            if not isinstance(rollback, int) or isinstance(rollback, bool) \
                    or not 30 <= rollback <= 900:
                raise FirewallError("invalid_request", "rollback_seconds must be 30..900")
            async with service.lock:
                if service.info is None:
                    await service.probe()
                plan = await asyncio.to_thread(lambda: ports.plan(request, temp_allow=temp_allow))
                if plan["problems"]:
                    raise LockoutError(plan["problems"])
                policy: PortPolicy = plan["policy"]
                result = await push(policy, rollback_seconds=rollback)
                helper_ports = result.get("ports") if isinstance(result.get("ports"), dict) \
                    else {}
                pending = helper_ports.get("pending")
                state = await asyncio.to_thread(ports.state)
                if isinstance(pending, dict):
                    state["pending"] = {
                        "payload": policy.to_payload(), "token": pending.get("token"),
                        "deadline": pending.get("deadline"),
                        "started_at": pending.get("started_at"), "by": principal.user_id}
                else:
                    state["confirmed"], state["pending"] = policy.to_payload(), None
                state["applied_at"] = int(time.time())
                await asyncio.to_thread(ports.save_state, state)
                await asyncio.to_thread(
                    lambda: service.store.record(
                        "ports_apply", mode=service.settings()["mode"],
                        user_id=principal.user_id,
                        reason=f"{len(policy.rules)} port rules",
                        details={"pending": isinstance(pending, dict),
                                 "rollback_seconds": rollback,
                                 "temp_allow": [str(t.network) for t in policy.temp_allow]}))
        except (FirewallError, HelperError) as exc:
            await audit(principal.user_id, "firewall.ports.apply", None, "failure")
            return fail(exc)
        await audit(principal.user_id, "firewall.ports.apply", str(len(policy.rules)))
        return await ports.status(request)

    @router.post("/ports/confirm", response_model=None)
    async def port_confirm(request: Request):
        principal = writer(request)
        try:
            async with service.lock:
                state = await asyncio.to_thread(ports.state)
                pending = state["pending"]
                if not pending:
                    raise FirewallError("no_pending_change",
                                        "there is no port policy change waiting", 409)
                try:
                    await service.client.request("POST", "/v1/confirm",
                                                 {"token": pending.get("token")})
                except HelperError as exc:
                    if exc.code in {"no_pending_change", "token_mismatch"}:
                        await service.probe()  # adopt what the helper did (rolled back?)
                        raise FirewallError("no_pending_change",
                                            "the change was already rolled back", 409) from exc
                    raise
                state["confirmed"], state["pending"] = pending.get("payload"), None
                await asyncio.to_thread(ports.save_state, state)
                await asyncio.to_thread(
                    lambda: service.store.record("ports_confirm",
                                                 mode=service.settings()["mode"],
                                                 user_id=principal.user_id))
        except (FirewallError, HelperError) as exc:
            await audit(principal.user_id, "firewall.ports.confirm", None, "failure")
            return fail(exc)
        await audit(principal.user_id, "firewall.ports.confirm", None)
        return await ports.status(request)

    @router.post("/ports/rollback", response_model=None)
    async def port_rollback(request: Request):
        principal = writer(request)
        try:
            async with service.lock:
                result = await service.client.request("POST", "/v1/recover",
                                                      {"open": False, "reason": "undo"})
                state = await asyncio.to_thread(ports.state)
                lkg = (result.get("ports") or {}).get("lkg") if isinstance(result, dict) else None
                change_id = (state["pending"] or {}).get("change_id")
                if change_id and ports.quick is not None:
                    # "Undo now" on a quick change also takes it out of the draft.
                    await asyncio.to_thread(ports.quick.revert_draft, str(change_id), "undone")
                state["pending"], state["confirmed"] = None, lkg
                state["last_rollback"] = result.get("rollback") if isinstance(result, dict) \
                    else None
                await asyncio.to_thread(ports.save_state, state)
                await asyncio.to_thread(
                    lambda: service.store.record("ports_rollback",
                                                 mode=service.settings()["mode"],
                                                 user_id=principal.user_id, reason="undo"))
                service.last_checked_at = None
                service.applied_hash = None
        except (FirewallError, HelperError) as exc:
            await audit(principal.user_id, "firewall.ports.rollback", None, "failure")
            return fail(exc)
        await audit(principal.user_id, "firewall.ports.rollback", None)
        async with service.lock:
            await service.reconcile(force=True)
        return await ports.status(request)

    @router.post("/ports/disable", response_model=None)
    async def port_disable(request: Request):
        principal = writer(request)
        try:
            async with service.lock:
                await push(None, rollback_seconds=None)
                state = await asyncio.to_thread(ports.state)
                state["confirmed"], state["pending"] = None, None
                state["applied_at"] = int(time.time())
                await asyncio.to_thread(ports.save_state, state)
                await asyncio.to_thread(
                    lambda: service.store.record("ports_disable",
                                                 mode=service.settings()["mode"],
                                                 user_id=principal.user_id))
        except (FirewallError, HelperError) as exc:
            await audit(principal.user_id, "firewall.ports.disable", None, "failure")
            return fail(exc)
        await audit(principal.user_id, "firewall.ports.disable", None)
        return await ports.status(request)

    # ---- read-only import (UFW, PAASIFY-DOCKER-FW) ----

    @router.get("/ports/import", response_model=None)
    async def port_import_preview(request: Request):
        reader(request)
        try:
            found = await service.client.request("GET", "/v1/import")
        except HelperError as exc:
            return fail(exc)
        if not isinstance(found, dict):
            return ctx.error_payload("firewall_unreachable", "unexpected helper payload", 502)
        existing = {_rule_signature(_flatten(rule))
                    for rule in await asyncio.to_thread(ports.store.list_rules)}
        ufw_accepts: list[dict[str, Any]] = []
        for section in ("ufw", "legacy"):
            data = found.get(section)
            if not isinstance(data, dict) or not isinstance(data.get("rules"), list):
                continue
            for item in data["rules"]:
                if not isinstance(item, dict):
                    continue
                values = _proposal_values(item)
                item["valid"] = values is not None
                item["imported"] = values is not None and _rule_signature(values) in existing
                if section == "ufw" and values and values.get("action") == "accept":
                    ufw_accepts.append(values)
        plan = await asyncio.to_thread(lambda: ports.plan(request, temp_allow=False))
        policy: PortPolicy = plan["policy"]
        listening = found.get("listening") if isinstance(found.get("listening"), list) else []
        comparison = []
        for entry in listening[:500]:
            if not isinstance(entry, dict) or entry.get("loopback_only"):
                continue
            port, protocol = entry.get("port"), entry.get("protocol")
            if not isinstance(port, int) or protocol not in {"tcp", "udp"}:
                continue
            comparison.append({
                "port": port, "protocol": protocol,
                "panel": policy.reachable_somewhere(CHAIN_INPUT, protocol, port),
                "ufw": any(protocol in _protocols(v["protocol"]) and v["scope"] != "docker"
                           and port_in(_ranges(v["ports"]), port) for v in ufw_accepts),
            })
        return {**found, "comparison": comparison}

    @router.post("/ports/import", status_code=201, response_model=None)
    async def port_import(request: Request):
        principal = writer(request)
        try:
            payload = await body(request)
            items = payload.get("items") if isinstance(payload, dict) else None
            if not isinstance(items, list) or not 1 <= len(items) <= MAX_IMPORT \
                    or set(payload) - {"items"}:
                raise FirewallError("invalid_request", f"body is {{items: [1..{MAX_IMPORT}]}}")
            prepared = []
            for item in items:
                if not isinstance(item, dict) or item.get("origin") not in RULE_ORIGINS:
                    raise FirewallError("invalid_port_rule", "each item needs a known origin")
                values = validate_port_rule({key: value for key, value in item.items()
                                             if key not in {"origin", "raw", "valid",
                                                            "imported"}})
                # Imported rules always start DISABLED: review, then enable and apply.
                prepared.append((item["origin"], {**values, "enabled": False}))
            created = []
            for origin, values in prepared:
                created.append(await asyncio.to_thread(
                    lambda o=origin, v=values: ports.store.create_rule(
                        v, origin=o, user_id=principal.user_id, unique_name=True)))
        except FirewallError as exc:
            await audit(principal.user_id, "firewall.port_rule.import", None, "failure")
            return fail(exc)
        await audit(principal.user_id, "firewall.port_rule.import", str(len(created)))
        return {"items": created}


def _flatten(rule: dict[str, Any]) -> dict[str, Any]:
    source = rule.get("source") or {}
    return {"protocol": rule["protocol"], "ports": rule["ports"], "scope": rule["scope"],
            "action": rule["action"], "source_kind": source.get("kind", "public"),
            "source_cidrs": source.get("cidrs", []), "source_list_id": source.get("list_id")}


def _protocols(value: str) -> tuple[str, ...]:
    return ("tcp", "udp") if value == "both" else (value,)


def _ranges(ports: list[str]) -> list[tuple[int, int]]:
    from ..firewall.ports import parse_ports

    try:
        return list(parse_ports(ports))
    except PortError:
        return []
