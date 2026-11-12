"""Quick firewall actions API (docs/45): preview + one-click apply + undo of shortcuts.

* ``GET  /ports/my-ip``           the address this request comes from (trusted proxies
  are resolved by the server, as for every other address check of the panel).
* ``GET  /ports/quick/overview``  listening ports with owner and exposure, SSH facts.
* ``POST /ports/quick``           ``{text | intents, apply, override}``: without ``apply``
  a preview (parsed actions, rule changes, ruleset diff, lockout problems); with it the
  change is written to the draft and applied through the usual helper pipeline.
* ``POST /ports/quick/undo``      ``{change_id}`` puts the draft back and applies again.
* ``GET  /ports/quick/history``   the last quick changes (for undo).

Safety is the one of the full editor: lockout check (an SSH lockout can be overridden
only with the typed confirmation), the helper's rollback timer for anything that can
close a port, temporary rules that the helper stops enforcing on time. A change that can
only *open* (adds allows, removes denies) cannot lock anyone out and is kept at once.
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

from ..firewall.addresses import parse_network
from ..firewall.ports import CHAIN_INPUT, CHAIN_PUBLISHED, PortPolicy
from ..module_context import ModuleContext
from .firewall_client import HelperError
from .firewall_engine import ENFORCE_CONFIRMATION, FirewallError, parse_requester
from .firewall_ports import ruleset_diff, ruleset_text
from .firewall_ports_api import LockoutError, draft_matches_applied, push_policy
from .firewall_quick import (
    MAX_INTENTS,
    Plan,
    opens_only,
    parse_commands,
    plan_changes,
    requester_network,
    validate_intent,
)

if TYPE_CHECKING:
    from .firewall import FirewallService

JOURNAL_FILE = "firewall-ports-quick.json"
MAX_JOURNAL = 30
OWNERS_CACHE_SECONDS = 30.0
# Names for well-known ports when nothing better is known (shown as a hint only).
WELL_KNOWN = {
    21: "FTP", 22: "SSH", 25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
    443: "HTTPS", 465: "SMTP", 587: "SMTP", 993: "IMAP", 995: "POP3", 2377: "Swarm",
    3000: "Dokploy", 3306: "MySQL", 4789: "Swarm", 5000: "Registry", 5432: "PostgreSQL",
    6379: "Redis", 7946: "Swarm", 8080: "HTTP", 8443: "HTTPS", 9000: "MinIO",
    9001: "MinIO", 27017: "MongoDB",
}


def _write_json(path: Any, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(4)}.tmp")
    temporary.write_bytes((json.dumps(payload, indent=2) + "\n").encode("utf-8"))
    os.replace(temporary, path)


class QuickJournal:
    """Undo journal of quick changes (a small JSON file next to the port settings)."""

    def __init__(self, service: FirewallService) -> None:
        self.service = service
        self.ports = service.ports
        self.path = service.ctx.data_dir / "control-plane" / JOURNAL_FILE
        self.owners: dict[str, Any] = {"at": 0.0, "value": {}}

    def entries(self) -> list[dict[str, Any]]:
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return []
        items = payload.get("items") if isinstance(payload, dict) else None
        return [item for item in items or [] if isinstance(item, dict)]

    def save_entry(self, entry: dict[str, Any]) -> None:
        items = [item for item in self.entries() if item.get("id") != entry["id"]]
        items.insert(0, entry)
        _write_json(self.path, {"items": items[:MAX_JOURNAL]})

    def get(self, change_id: str) -> dict[str, Any] | None:
        return next((item for item in self.entries() if item.get("id") == change_id), None)

    # ----- draft writes ------------------------------------------------------------
    def write_plan(self, plan: Plan, *, user_id: int) -> dict[str, Any]:
        """Put a plan into the draft; returns the journal entry that undoes it."""
        store = self.ports.store
        current = {rule["id"]: rule for rule in store.list_rules()}
        entry: dict[str, Any] = {
            "id": secrets.token_hex(6), "at": int(time.time()), "by": user_id,
            "status": "draft", "created": [], "removed": [], "priorities": {},
            "blocks": [], "kept": None,
        }
        for rule in plan.removed:
            try:
                entry["removed"].append(store.delete_rule(rule["id"]))
            except KeyError:
                continue
        entry["priorities"] = {rule_id: current[rule_id]["priority"]
                               for rule_id in plan.priorities if rule_id in current}
        store.set_priorities(plan.priorities)
        for rule in plan.created:
            values = {
                "name": rule["name"], "description": rule["description"],
                "protocol": rule["protocol"], "ports": rule["ports"], "scope": rule["scope"],
                "action": rule["action"], "source_kind": rule["source"]["kind"],
                "source_cidrs": rule["source"].get("cidrs", []),
                "source_list_id": rule["source"].get("list_id"), "enabled": True,
                "priority": rule["priority"], "log": False, "log_rate": 10,
                "expires_at": rule["expires_at"],
            }
            created = store.create_rule(values, origin="quick", user_id=user_id,
                                        unique_name=True, rule_id=rule["id"])
            entry["created"].append(created["id"])
        return entry

    def reverted_rules(self, entry: dict[str, Any]) -> list[dict[str, Any]]:
        """The draft as it would be after undoing ``entry`` (nothing is written)."""
        created = set(entry.get("created") or [])
        priorities = entry.get("priorities") or {}
        rules = []
        for rule in self.ports.store.list_rules():
            if rule["id"] in created:
                continue
            if rule["id"] in priorities:
                rule = {**rule, "priority": int(priorities[rule["id"]])}
            rules.append(rule)
        existing = {rule["id"] for rule in rules}
        now = time.time()
        for rule in entry.get("removed") or []:
            if rule.get("id") not in existing and (
                    rule.get("expires_at") is None or rule["expires_at"] > now):
                rules.append(rule)
        return rules

    def revert_draft(self, change_id: str, status: str) -> bool:
        """Undo the draft part of a change (its rules); blocks are handled separately."""
        entry = self.get(change_id)
        if entry is None or entry.get("status") not in {"applied", "draft"}:
            return False
        store = self.ports.store
        for rule_id in entry.get("created") or []:
            try:
                store.delete_rule(rule_id)
            except KeyError:
                continue
        store.set_priorities({key: int(value) for key, value in
                              (entry.get("priorities") or {}).items()})
        now = time.time()
        existing = {rule["id"] for rule in store.list_rules()}
        for rule in entry.get("removed") or []:
            if rule.get("id") in existing or (
                    rule.get("expires_at") is not None and rule["expires_at"] <= now):
                continue
            source = rule.get("source") or {}
            values = {
                "name": rule["name"], "description": rule.get("description", ""),
                "protocol": rule["protocol"], "ports": rule["ports"], "scope": rule["scope"],
                "action": rule["action"], "source_kind": source.get("kind", "public"),
                "source_cidrs": source.get("cidrs", []), "source_list_id": source.get("list_id"),
                "enabled": rule.get("enabled", True), "priority": rule["priority"],
                "log": rule.get("log", False), "log_rate": rule.get("log_rate", 10),
                "expires_at": rule.get("expires_at"), "created_at": rule.get("created_at"),
            }
            try:
                store.create_rule(values, origin=rule.get("origin", "manual"),
                                  user_id=rule.get("created_by_user_id"), unique_name=True,
                                  rule_id=rule["id"])
            except FirewallError:
                continue  # e.g. its named list is gone meanwhile
        entry["status"] = status
        self.save_entry(entry)
        return True


def _summary(entry: dict[str, Any]) -> dict[str, Any]:
    return {key: entry.get(key) for key in ("id", "at", "by", "status", "kept", "intents",
                                            "blocks")} | {
        "rules": len(entry.get("created") or []), "removed": len(entry.get("removed") or [])}


def register_quick_routes(router: APIRouter, ctx: ModuleContext, service: FirewallService, *,
                          reader: Callable[[Request], Any], writer: Callable[[Request], Any],
                          body: Callable[[Request], Any], audit: Callable[..., Any]) -> None:
    ports = service.ports
    journal = QuickJournal(service)
    ports.quick = journal

    def fail(exc: FirewallError | HelperError):
        if isinstance(exc, LockoutError):
            return ctx.error_payload(  # type: ignore[call-arg]
                exc.code, exc.message, exc.status_code, problems=exc.problems)
        return ctx.error_payload(exc.code, exc.message, exc.status_code)

    def requester_of(request: Request):
        return parse_requester(request.client.host if request.client else None)

    # ---- my address -----------------------------------------------------------

    @router.get("/ports/my-ip")
    async def my_ip(request: Request):
        reader(request)
        requester = requester_of(request)
        return {"ip": None if requester is None else str(requester),
                "network": requester_network(requester),
                "version": None if requester is None else requester.version}

    # ---- overview: listening ports, owners, exposure ----------------------------

    async def container_owners() -> dict[str, str]:
        """``"<proto>/<public port>"`` -> container name, from the Host Agent (optional)."""
        if time.monotonic() - journal.owners["at"] < OWNERS_CACHE_SECONDS:
            return journal.owners["value"]
        owners: dict[str, str] = {}
        try:
            from .host_agent import HostAgentService

            payload = await asyncio.wait_for(
                HostAgentService(ctx).call("/v1/docker/containers"), 4)
            for item in (payload or {}).get("items") or []:
                if not isinstance(item, dict) or item.get("state") not in (None, "running"):
                    continue
                labels = item.get("labels_subset") or {}
                name = labels.get("com.docker.compose.service") or labels.get(
                    "com.docker.swarm.service.name") or item.get("name") or ""
                for port in item.get("ports") or []:
                    if isinstance(port, dict) and isinstance(port.get("public"), int):
                        owners.setdefault(f"{port.get('type') or 'tcp'}/{port['public']}",
                                          str(name)[:80])
        except Exception:  # noqa: BLE001 - owners are a hint; the agent is optional
            owners = {}
        journal.owners = {"at": time.monotonic(), "value": owners}
        return owners

    def exposure(policy: PortPolicy | None, chain: str, protocol: str, port: int,
                 requester: Any, now: float) -> dict[str, Any]:
        if policy is None or not policy.enabled:
            return {"exposure": "open", "me": True}
        if policy.verdict(chain, protocol, port, None, now=now) == "accept":
            state = "open"
        elif policy.reachable_somewhere(chain, protocol, port, now=now):
            state = "restricted"
        else:
            state = "closed"
        me = requester is not None and policy.verdict(
            chain, protocol, port, requester, include_temp=True, now=now) == "accept"
        return {"exposure": state, "me": me}

    @router.get("/ports/quick/overview")
    async def quick_overview(request: Request):
        reader(request)
        if service.configured() and (service.info is None or service.last_checked_at is None
                                     or time.time() - service.last_checked_at > 10):
            await service.probe()
        plan = await asyncio.to_thread(ports.plan, request)
        sent = await asyncio.to_thread(ports.sent_policy)
        rules = await asyncio.to_thread(ports.store.list_rules)
        owners = await container_owners()
        now = time.time()
        requester = plan["requester"]
        info = service.info or {}
        listening = info.get("listening") if isinstance(info.get("listening"), list) else []
        ssh_ports = set(plan["ssh_ports"])
        other_ssh = {item.get("port") for item in plan["ssh_detected"]["listener"]["other"]}
        items = []
        for entry in listening[:300]:
            if not isinstance(entry, dict) or entry.get("loopback_only"):
                continue
            port, protocol = entry.get("port"), entry.get("protocol")
            if not isinstance(port, int) or protocol not in {"tcp", "udp"}:
                continue
            container = owners.get(f"{protocol}/{port}")
            if protocol == "tcp" and port in ssh_ports and not container:
                owner = {"kind": "ssh", "name": "SSH"}
            elif protocol == "tcp" and port in plan["panel_ports"]:
                owner = {"kind": "panel", "name": "DevAssist"}
            elif container:
                owner = {"kind": "container", "name": container}
            elif protocol == "tcp" and port in other_ssh:
                owner = {"kind": "guess", "name": "SSH"}
            elif port in WELL_KNOWN:
                owner = {"kind": "guess", "name": WELL_KNOWN[port]}
            else:
                owner = {"kind": "unknown", "name": None}
            chain = CHAIN_PUBLISHED if owner["kind"] == "container" else CHAIN_INPUT
            matching = [rule["id"] for rule in rules if rule["enabled"]
                        and protocol in (("tcp", "udp") if rule["protocol"] == "both"
                                         else (rule["protocol"],))
                        and _covers_port(rule["ports"], port)]
            items.append({"port": port, "protocol": protocol, "owner": owner,
                          "scope": "docker" if chain == CHAIN_PUBLISHED else "host",
                          **exposure(sent, chain, protocol, port, requester, now),
                          "draft": exposure(plan["policy"], chain, protocol, port, requester,
                                            now)["exposure"],
                          "rules": matching[:20],
                          "ssh": owner["kind"] == "ssh",
                          "panel": owner["kind"] == "panel"})
        return {
            "configured": service.configured(),
            "active": sent is not None and sent.enabled,
            "force_dry_run": bool(info.get("force_dry_run")),
            "dynamic_mode": (await asyncio.to_thread(service.settings))["mode"],
            "requester": None if requester is None else str(requester),
            "my_network": requester_network(requester),
            "ssh": {"ports": plan["ssh_ports"], "source": plan["ssh_source"],
                    "admin_ports": plan["settings"]["ssh_ports"],
                    "detected": plan["ssh_detected"]},
            "panel_ports": plan["panel_ports"],
            "listening": items,
            "listening_known": bool(listening),
            "lists": [{"id": item["id"], "name": item["name"], "count": len(item["cidrs"])}
                      for item in plan["lists"]],
            "draft_differs": not draft_matches_applied(plan["policy"], sent, now),
        }

    # ---- preview / apply ----------------------------------------------------------

    def prepare(request: Request, payload: Any) -> dict[str, Any]:
        """Parse + validate + plan (no writes). Raises FirewallError on bad input."""
        if not isinstance(payload, dict) or set(payload) - {"text", "intents", "apply",
                                                            "override"}:
            raise FirewallError("invalid_request",
                                "body is {text | intents, apply, override}")
        if ("text" in payload) == ("intents" in payload):
            raise FirewallError("invalid_request", "give exactly one of text or intents")
        lists = {item["id"]: item for item in ports.store.list_lists()}
        requester = requester_of(request)
        errors: list[dict[str, Any]] = []
        if "text" in payload:
            parsed = parse_commands(payload["text"], lists.values())
            raw_intents, errors = parsed.intents, parsed.errors
        else:
            raw_intents = payload["intents"]
            if not isinstance(raw_intents, list) or not 1 <= len(raw_intents) <= MAX_INTENTS:
                raise FirewallError("invalid_request", f"intents is a list of 1..{MAX_INTENTS}")
        intents: list[dict[str, Any]] = []
        for index, raw in enumerate(raw_intents):
            try:
                intents.append(validate_intent(raw, lists=lists, requester=requester))
            except FirewallError as exc:
                errors.append({"index": index, "error": exc.code, "message": exc.message})
        version = (service.info or {}).get("version")
        if service.configured() and not helper_supports_expiry(version):
            for index, intent in enumerate(intents):
                if intent["kind"] == "port" and intent["expires_in"] is not None:
                    errors.append({"index": index, "error": "helper_too_old",
                                   "message": "temporary rules need mrk-firewall 0.2.0+"})
        now = int(time.time())
        rules = ports.store.list_rules()
        plan = plan_changes(rules, intents, now=now, new_id=lambda: secrets.token_hex(8))
        settings = service.settings()
        blocks = []
        for intent in plan.blocks:
            duration = intent["expires_in"] or settings["default_ban_seconds"]
            refused = None
            if not 60 <= duration <= settings["max_ban_seconds"]:
                refused = "invalid_block"
            else:
                try:
                    service.check_manual_block(parse_network(intent["cidr"]), settings=settings,
                                               requester=requester)
                except FirewallError as exc:
                    refused = exc.code
            blocks.append({**intent, "duration": duration, "refused": refused})
        port_change = bool(plan.created or plan.removed or plan.priorities)
        current = ports.plan(request, now=now)
        planned = ports.plan(request, now=now, rules=plan.rules) if port_change else current
        sent = ports.sent_policy(now)
        return {
            "intents": intents, "errors": errors, "plan": plan, "blocks": blocks,
            "port_change": port_change, "planned": planned, "sent": sent, "now": now,
            "other_changes": not draft_matches_applied(current["policy"], sent, now),
            "opens_only": opens_only(sent, planned["policy"], now) if port_change else True,
            "settings": settings,
        }

    def preview_payload(prepared: dict[str, Any]) -> dict[str, Any]:
        plan: Plan = prepared["plan"]
        planned = prepared["planned"]
        problems = planned["problems"] if prepared["port_change"] else []
        settings = prepared["settings"]
        now = prepared["now"]
        diff: list[str] = []
        if prepared["port_change"]:
            current = ruleset_text(service.desired(settings), now)
            following = ruleset_text(service.desired(settings, ports=planned["policy"]), now)
            diff = ruleset_diff(current, following)
        info = service.info or {}
        return {
            "intents": [{**intent, "unchanged": index in plan.unchanged}
                        for index, intent in enumerate(prepared["intents"])],
            "errors": prepared["errors"],
            "created": plan.created, "removed": plan.removed,
            "moved": len(plan.priorities), "blocks": prepared["blocks"],
            "empty": plan.empty,
            "problems": problems,
            "overridable": bool(problems) and all(p["code"] == "lockout_ssh" for p in problems),
            "warnings": planned["warnings"],
            "diff": diff,
            "opens_only": prepared["opens_only"],
            "trial": prepared["port_change"] and not (
                prepared["opens_only"] and not prepared["other_changes"]),
            "other_changes": prepared["other_changes"],
            "configured": service.configured(),
            "force_dry_run": bool(info.get("force_dry_run")),
            "dynamic_mode": settings["mode"],
            "rollback_seconds": ports.settings()["rollback_seconds"],
            "ssh_ports": planned["ssh_ports"], "ssh_source": planned["ssh_source"],
            "requester": None if planned["requester"] is None else str(planned["requester"]),
        }

    async def apply_policy(request: Request, *, change_id: str | None, keep: bool
                           ) -> dict[str, Any]:
        """Push the compiled draft; returns {pending, kept}. Caller holds the lock.
        ``change_id`` ties a trial to its quick change (a rollback then reverts the draft)."""
        planned = await asyncio.to_thread(ports.plan, request)
        settings = await asyncio.to_thread(ports.settings)
        result = await push_policy(service, planned["policy"],
                                   rollback_seconds=settings["rollback_seconds"])
        helper_ports = result.get("ports") if isinstance(result.get("ports"), dict) else {}
        pending = helper_ports.get("pending")
        state = await asyncio.to_thread(ports.state)
        policy: PortPolicy = planned["policy"]
        kept = False
        if isinstance(pending, dict) and keep:
            # Only opens: nobody can be locked out, keep it without a trial period.
            await service.client.request("POST", "/v1/confirm", {"token": pending.get("token")})
            state["confirmed"], state["pending"], kept = policy.to_payload(), None, True
        elif isinstance(pending, dict):
            state["pending"] = {
                "payload": policy.to_payload(), "token": pending.get("token"),
                "deadline": pending.get("deadline"), "started_at": pending.get("started_at"),
                "by": None, "change_id": change_id}
        else:
            state["confirmed"], state["pending"], kept = policy.to_payload(), None, True
        state["applied_at"] = int(time.time())
        await asyncio.to_thread(ports.save_state, state)
        return {"pending": isinstance(pending, dict) and not kept, "kept": kept,
                "rules": len(policy.rules)}

    def unblock(block_ids: list[str], user_id: int) -> None:
        settings = service.settings()
        for block_id in block_ids:
            try:
                item = service.store.remove_block(block_id, "manual")
            except KeyError:
                continue
            service.store.record("unblock", mode=settings["mode"], ip=item["cidr"],
                                 user_id=user_id, reason="quick action undone",
                                 details={"block_id": block_id})

    @router.post("/ports/quick", response_model=None)
    async def quick_action(request: Request):
        payload = await body(request)
        if not (isinstance(payload, dict) and payload.get("apply") is True):
            reader(request)
            try:
                if service.configured() and service.info is None:
                    await service.probe()
                prepared = await asyncio.to_thread(prepare, request, payload)
                return await asyncio.to_thread(preview_payload, prepared)
            except FirewallError as exc:
                return fail(exc)
        principal = writer(request)
        try:
            if not service.configured():
                raise FirewallError("firewall_not_configured",
                                    "The firewall helper is not paired", 409)
            override = payload.get("override")
            async with service.lock:
                if service.info is None:
                    await service.probe()
                prepared = await asyncio.to_thread(prepare, request, payload)
                if prepared["errors"]:
                    raise FirewallError("invalid_quick_action",
                                        "some actions could not be understood", 422)
                plan: Plan = prepared["plan"]
                if plan.empty:
                    return {"change_id": None, "nothing": True,
                            "status": await ports.status(request)}
                problems = prepared["planned"]["problems"] if prepared["port_change"] else []
                ssh_only = all(p["code"] == "lockout_ssh" for p in problems)
                if problems and not (ssh_only and override == ENFORCE_CONFIRMATION):
                    raise LockoutError(problems)
                refused = [b for b in prepared["blocks"] if b["refused"]]
                if refused:
                    raise FirewallError(refused[0]["refused"],
                                        f"{refused[0]['cidr']} cannot be blocked", 422)
                entry = await asyncio.to_thread(
                    lambda: journal.write_plan(plan, user_id=principal.user_id))
                entry["intents"] = prepared["intents"]
                try:
                    settings = prepared["settings"]
                    for block in prepared["blocks"]:
                        item = await asyncio.to_thread(
                            service.manual_block, parse_network(block["cidr"]),
                            settings=settings, duration=block["duration"],
                            reason=block["note"] or "quick action",
                            requester=requester_of(request), user_id=principal.user_id)
                        entry["blocks"].append(item["id"])
                    if prepared["port_change"]:
                        outcome = await apply_policy(
                            request, change_id=entry["id"],
                            keep=prepared["opens_only"] and not prepared["other_changes"])
                    else:
                        await service.reconcile(force=True)
                        outcome = {"pending": False, "kept": True, "rules": None}
                except (FirewallError, HelperError):
                    entry["status"] = "draft"
                    await asyncio.to_thread(journal.save_entry, entry)
                    await asyncio.to_thread(journal.revert_draft, entry["id"], "failed")
                    await asyncio.to_thread(unblock, entry["blocks"], principal.user_id)
                    raise
                entry["status"], entry["kept"] = "applied", outcome["kept"]
                await asyncio.to_thread(journal.save_entry, entry)
                await asyncio.to_thread(
                    lambda: service.store.record(
                        "ports_quick", mode=service.settings()["mode"],
                        user_id=principal.user_id,
                        reason=f"{len(plan.created)} rules, {len(entry['blocks'])} blocks",
                        details={"change_id": entry["id"], "kept": outcome["kept"],
                                 "created": entry["created"],
                                 "removed": [r["id"] for r in entry["removed"]],
                                 "blocks": entry["blocks"],
                                 "override": bool(problems)}))
        except (FirewallError, HelperError) as exc:
            await audit(principal.user_id, "firewall.ports.quick", None, "failure")
            return fail(exc)
        await audit(principal.user_id, "firewall.ports.quick", entry["id"])
        return {"change_id": entry["id"], "pending": outcome["pending"],
                "kept": outcome["kept"], "status": await ports.status(request)}

    @router.post("/ports/quick/undo", response_model=None)
    async def quick_undo(request: Request):
        principal = writer(request)
        try:
            payload = await body(request)
            change_id = payload.get("change_id") if isinstance(payload, dict) else None
            if not isinstance(change_id, str) or not change_id or set(payload) - {"change_id"}:
                raise FirewallError("invalid_request", "body is {change_id}")
            async with service.lock:
                entry = await asyncio.to_thread(journal.get, change_id)
                if entry is None or entry.get("status") != "applied":
                    raise FirewallError("nothing_to_undo", "this change cannot be undone", 409)
                state = await asyncio.to_thread(ports.state)
                pending = state["pending"] or {}
                port_part = bool(entry.get("created") or entry.get("removed")
                                 or entry.get("priorities"))
                outcome: dict[str, Any] = {"pending": False, "kept": True}
                if port_part and pending.get("change_id") == change_id:
                    # Still on trial: the helper goes back to the last confirmed rules.
                    result = await service.client.request("POST", "/v1/recover",
                                                          {"open": False, "reason": "undo"})
                    lkg = (result.get("ports") or {}).get("lkg") \
                        if isinstance(result, dict) else None
                    await asyncio.to_thread(journal.revert_draft, change_id, "undone")
                    state["pending"], state["confirmed"] = None, lkg
                    state["last_rollback"] = result.get("rollback") \
                        if isinstance(result, dict) else None
                    await asyncio.to_thread(ports.save_state, state)
                    service.last_checked_at = None
                    service.applied_hash = None
                elif port_part:
                    reverted = await asyncio.to_thread(journal.reverted_rules, entry)
                    check = await asyncio.to_thread(
                        lambda: ports.plan(request, rules=reverted))
                    if check["problems"]:
                        raise LockoutError(check["problems"])
                    sent = await asyncio.to_thread(ports.sent_policy)
                    keep = opens_only(sent, check["policy"], time.time())
                    await asyncio.to_thread(journal.revert_draft, change_id, "undone")
                    try:
                        outcome = await apply_policy(request, change_id=None, keep=keep)
                    except (FirewallError, HelperError):
                        entry_now = await asyncio.to_thread(journal.get, change_id)
                        if entry_now is not None:
                            entry_now["status"] = "undo_failed"
                            await asyncio.to_thread(journal.save_entry, entry_now)
                        raise
                else:
                    entry["status"] = "undone"
                    await asyncio.to_thread(journal.save_entry, entry)
                if entry.get("blocks"):
                    await asyncio.to_thread(unblock, list(entry["blocks"]), principal.user_id)
                if entry.get("blocks") or (port_part and pending.get("change_id") == change_id):
                    await service.reconcile(force=True)
                await asyncio.to_thread(
                    lambda: service.store.record(
                        "ports_undo", mode=service.settings()["mode"],
                        user_id=principal.user_id, reason=f"quick change {change_id}",
                        details={"change_id": change_id}))
        except (FirewallError, HelperError) as exc:
            await audit(principal.user_id, "firewall.ports.quick_undo", None, "failure")
            return fail(exc)
        await audit(principal.user_id, "firewall.ports.quick_undo", change_id)
        return {"change_id": change_id, "pending": outcome["pending"],
                "kept": outcome["kept"], "status": await ports.status(request)}

    @router.get("/ports/quick/history")
    async def quick_history(request: Request):
        reader(request)
        return {"items": [_summary(item) for item in
                          await asyncio.to_thread(journal.entries)]}


def helper_supports_expiry(version: object) -> bool:
    """Temporary port rules (``expires_at``) need mrk-firewall 0.2.0 or newer."""
    if not isinstance(version, str):
        return False
    parts = []
    for item in version.split(".")[:3]:
        digits = "".join(ch for ch in item if ch.isdigit())
        parts.append(int(digits) if digits else 0)
    return tuple(parts + [0] * (3 - len(parts))) >= (0, 2, 0)


def _covers_port(ports: list[str], port: int) -> bool:
    for item in ports:
        low, _, high = str(item).partition("-")
        try:
            if int(low) <= port <= int(high or low):
                return True
        except ValueError:
            continue
    return False
