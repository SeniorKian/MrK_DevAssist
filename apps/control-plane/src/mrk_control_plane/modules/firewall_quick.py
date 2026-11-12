"""Quick firewall actions (docs/45): one-line commands and shortcuts -> draft rule changes.

Pure logic, no I/O. A command line such as ``open 8080``, ``close 3306``,
``allow 10.0.0.0/8 -> 5432``, ``block 1.2.3.4`` or ``allow 443 from IR only`` (also in
Persian) becomes a list of *intents*; :func:`plan_changes` turns intents into concrete
changes of the port-rule draft (rules to create, exact contradictions to remove, the
priorities that put each new rule where it decides). The API layer then compiles the
new draft, runs the lockout check, applies it through the usual helper pipeline and
keeps an undo journal.

Placement ("first match wins"): a new rule goes in front of every overlapping rule with
the opposite verdict that is *as general or more general* (public), and behind the more
specific ones, so ``open 22`` never unblocks an address that was blocked on 22, while
``allow 10.0.0.0/8 -> 5432`` wins over ``close 5432``. "Only" (exclusive) intents add a
public drop right behind the allow, as one block.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any

from ..firewall.addresses import AddressError, IPAddress, check_allow_shape, parse_network
from ..firewall.ports import (
    MAX_PORT_ITEMS,
    PortError,
    PortPolicy,
    PortRule,
    format_ports,
    parse_ports,
)
from .firewall_engine import FirewallError
from .firewall_ports import MAX_DESCRIPTION, MAX_PRIORITY, MAX_RULE_LIFETIME

MAX_INTENTS = 16
MAX_COMMAND = 2000
MIN_EXPIRY, MAX_EXPIRY = 60, MAX_RULE_LIFETIME
PROTOCOLS = ("tcp", "udp", "both")
SCOPES = ("host", "docker", "both")
STEP = 10

# ----- command words (English and Persian) ------------------------------------------

_ALLOW = {"open", "allow", "permit", "accept", "باز", "بازکن", "اجازه", "مجاز"}
_DENY = {"close", "deny", "drop", "block", "reject", "ببند", "بستن", "بسته", "مسدود"}
_ONLY = {"only", "just", "فقط", "تنها"}
_FROM = {"from", "از"}
_TO = {"to", "on", "port", "ports", "به", "روی", "پورت", "پورت‌های", "پورتهای"}
_FOR = {"for", "during", "برای", "به‌مدت", "بمدت", "مدت"}
_ME = {"me", "my", "myip", "my-ip", "mine", "من", "خودم"}
_PUBLIC = {"everyone", "anyone", "any", "all", "public", "internet", "همه", "همگان",
           "اینترنت"}
_FILLER = {"کن", "کنید", "کردن", "شود", "بشود", "را", "the", "a", "ip", "address", "and", "و",
           "نشانی", "آدرس", "temporary", "temp", "موقت", "please", "لطفا", "لطفاً"}
_SCOPE_WORDS = {"host": "host", "server": "host", "سرور": "host", "docker": "docker",
                "container": "docker", "containers": "docker", "کانتینر": "docker",
                "داکر": "docker"}
_PROTO_WORDS = {"tcp": "tcp", "udp": "udp", "both": "both", "tcp+udp": "both",
                "tcp/udp": "both", "udp+tcp": "both"}
_UNITS = {
    "s": 1, "sec": 1, "secs": 1, "second": 1, "seconds": 1, "ثانیه": 1,
    "m": 60, "min": 60, "mins": 60, "minute": 60, "minutes": 60, "دقیقه": 60,
    "h": 3600, "hr": 3600, "hrs": 3600, "hour": 3600, "hours": 3600, "ساعت": 3600,
    "d": 86400, "day": 86400, "days": 86400, "روز": 86400,
    "w": 604800, "week": 604800, "weeks": 604800, "هفته": 604800,
}
_PERSIAN_DIGITS = str.maketrans("۰۱۲۳۴۵۶۷۸۹٠١٢٣٤٥٦٧٨٩", "01234567890123456789")
_PORTS_TOKEN = re.compile(r"^\d{1,5}(?:[-:]\d{1,5})?(?:,\d{1,5}(?:[-:]\d{1,5})?)*"
                          r"(?:/(tcp|udp|both))?$")
_DURATION_TOKEN = re.compile(r"^(\d{1,4})([a-z؀-ۿ]+)$")


@dataclass(slots=True)
class ParseResult:
    intents: list[dict[str, Any]] = field(default_factory=list)
    errors: list[dict[str, Any]] = field(default_factory=list)


def _normalize(text: str) -> str:
    text = text.translate(_PERSIAN_DIGITS).replace("،", ",").replace("‌", " ")
    for arrow in ("→", "->", "=>", "⟶", "←", "<-"):
        text = text.replace(arrow, " to ")
    return text


def _address(token: str) -> list[str] | None:
    """``1.2.3.4`` / ``10.0.0.0/8`` / ``2001:db8::/32`` / comma lists -> networks."""
    if not any(ch in token for ch in ".:") or _PORTS_TOKEN.fullmatch(token):
        return None
    out: list[str] = []
    for part in token.split(","):
        if not part:
            continue
        try:
            out.append(str(parse_network(part)))
        except AddressError:
            return None
    return out or None


def _split_commands(text: str) -> list[str]:
    parts = re.split(r"[;؛\n]+", text)
    return [part.strip() for part in parts if part.strip()]


def parse_command_line(line: str, lists: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """One command -> one raw intent (validated later) or ``{"error": code, ...}``."""
    by_name = {item["name"].strip().lower(): item for item in lists}
    note = ""
    if "#" in line:
        line, note = line.split("#", 1)
        note = note.strip()
    quoted = re.search(r'"([^"]*)"', line)
    if quoted:
        note = note or quoted.group(1).strip()
        line = line[:quoted.start()] + line[quoted.end():]
    tokens = [token for token in _normalize(line).lower().split() if token]
    if not tokens:
        return {"error": "empty"}
    verbs = _ALLOW | _DENY
    # Persian puts the verb last («8080 را باز کن»): take the first verb word anywhere.
    at = next((i for i, token in enumerate(tokens) if token in verbs), None)
    if at is None:
        at = next((i for i, token in enumerate(tokens) if token in _ONLY), 0)
    verb = tokens.pop(at)
    exclusive = False
    if verb in _ONLY:
        action, exclusive = "accept", True
    elif verb in _ALLOW:
        action = "accept"
    elif verb in _DENY:
        action = "drop"
    else:
        return {"error": "unknown_verb", "word": verb[:40]}
    ports: list[str] = []
    protocol: str | None = None
    scope: str | None = None
    cidrs: list[str] = []
    source_kind: str | None = None
    list_id: str | None = None
    expires_in: int | None = None
    expecting_source = False
    expecting_duration = False
    index = 0
    while index < len(tokens):
        token = tokens[index].strip(".")
        index += 1
        if not token or token in _FILLER:
            continue
        if expecting_duration:
            expecting_duration = False
            amount = token
            unit = tokens[index] if index < len(tokens) else ""
            if amount.isdigit() and unit in _UNITS:
                index += 1
                expires_in = int(amount) * _UNITS[unit]
                continue
            match = _DURATION_TOKEN.fullmatch(token)
            if match and match.group(2) in _UNITS:
                expires_in = int(match.group(1)) * _UNITS[match.group(2)]
                continue
            return {"error": "bad_duration", "word": token[:40]}
        if token in _ONLY:
            exclusive = True
            continue
        if token in _FROM:
            expecting_source = True
            continue
        if token in _TO:
            expecting_source = False
            continue
        if token in _FOR:
            expecting_duration = True
            continue
        if token in _PROTO_WORDS:
            protocol = _PROTO_WORDS[token]
            continue
        if token in _SCOPE_WORDS:
            scope = _SCOPE_WORDS[token]
            continue
        if token in _ME:
            source_kind, expecting_source = "me", False
            continue
        if token in _PUBLIC:
            source_kind, expecting_source = "public", False
            continue
        networks = _address(token)
        if networks is not None:
            cidrs.extend(networks)
            source_kind, expecting_source = "cidrs", False
            continue
        match = _PORTS_TOKEN.fullmatch(token)
        if match and not expecting_source:
            ports.append(token.split("/", 1)[0])
            if match.group(1):
                protocol = match.group(1)
            continue
        duration = _DURATION_TOKEN.fullmatch(token)
        if duration and duration.group(2) in _UNITS and not expecting_source:
            expires_in = int(duration.group(1)) * _UNITS[duration.group(2)]
            continue
        if expecting_source or token in by_name:
            listed = by_name.get(token)
            if listed is None:
                return {"error": "unknown_list", "word": token[:40]}
            source_kind, list_id, expecting_source = "list", listed["id"], False
            continue
        if token.isdigit():
            return {"error": "bad_port", "word": token[:40]}
        return {"error": "unknown_word", "word": token[:40]}
    if expecting_duration:
        return {"error": "bad_duration", "word": ""}
    if not ports:
        if action == "drop" and source_kind == "cidrs":
            return {"kind": "block", "cidrs": cidrs, "expires_in": expires_in, "note": note}
        return {"error": "need_ports"}
    source: dict[str, Any]
    if source_kind == "cidrs":
        source = {"kind": "cidrs", "cidrs": cidrs}
    elif source_kind == "list":
        source = {"kind": "list", "list_id": list_id}
    elif source_kind == "me":
        source = {"kind": "me"}
    else:
        source = {"kind": "public"}
    return {"kind": "port", "action": action, "ports": ",".join(ports),
            "protocol": protocol or "tcp", "scope": scope or "both", "source": source,
            "exclusive": exclusive, "expires_in": expires_in, "note": note}


def parse_commands(text: object, lists: Iterable[dict[str, Any]]) -> ParseResult:
    if not isinstance(text, str) or len(text) > MAX_COMMAND:
        raise FirewallError("invalid_command", f"command must be text up to {MAX_COMMAND}")
    result = ParseResult()
    known = list(lists)
    for line in _split_commands(text)[:MAX_INTENTS]:
        parsed = parse_command_line(line, known)
        if "error" in parsed:
            result.errors.append({"line": line[:200], **parsed})
        elif parsed["kind"] == "block":
            for cidr in parsed["cidrs"]:
                result.intents.append({"kind": "block", "cidr": cidr,
                                       "expires_in": parsed["expires_in"],
                                       "note": parsed["note"]})
        else:
            result.intents.append(parsed)
    return result


# ----- intent validation ---------------------------------------------------------------


def requester_network(requester: IPAddress | None) -> str | None:
    """The admin's own address as a rule source: the host for IPv4, its /64 for IPv6
    (privacy addresses change inside the prefix)."""
    if requester is None:
        return None
    if requester.version == 4:
        return f"{requester}/32"
    return str(ipaddress.ip_network(f"{requester}/64", strict=False))


def _err(message: str, code: str = "invalid_quick_action") -> FirewallError:
    return FirewallError(code, message, 422)


def _expiry(value: object) -> int | None:
    if value is None:
        return None
    if not isinstance(value, int) or isinstance(value, bool) \
            or not MIN_EXPIRY <= value <= MAX_EXPIRY:
        raise _err(f"expires_in must be null or {MIN_EXPIRY}..{MAX_EXPIRY} seconds",
                   "invalid_expiry")
    return value


def _note(value: object) -> str:
    if value is None:
        return ""
    if not isinstance(value, str):
        raise _err("note must be text")
    text = "".join(ch for ch in value.strip() if ch.isprintable())
    return text[:MAX_DESCRIPTION]


def validate_intent(raw: object, *, lists: dict[str, dict[str, Any]],
                    requester: IPAddress | None) -> dict[str, Any]:
    """Strict check of one intent (from the parser or the shortcut forms)."""
    if not isinstance(raw, dict):
        raise _err("each action must be an object")
    kind = raw.get("kind", "port")
    if kind == "block":
        if set(raw) - {"kind", "cidr", "expires_in", "note"}:
            raise _err("block is {cidr, expires_in, note}")
        try:
            network = parse_network(raw.get("cidr"))
        except AddressError as exc:
            raise _err(str(exc), "invalid_sources") from exc
        return {"kind": "block", "cidr": str(network), "expires_in": _expiry(
            raw.get("expires_in")), "note": _note(raw.get("note"))}
    if kind != "port":
        raise _err("kind is port or block")
    allowed = {"kind", "action", "ports", "protocol", "scope", "source", "exclusive",
               "expires_in", "note"}
    if set(raw) - allowed:
        raise _err(f"unknown field: {sorted(set(raw) - allowed)[0]}")
    action = raw.get("action")
    if action not in ("accept", "drop"):
        raise _err("action is accept or drop")
    try:
        ports = format_ports(parse_ports(raw.get("ports")))
    except PortError as exc:
        raise _err(str(exc), exc.code) from exc
    if len(ports) > MAX_PORT_ITEMS:
        raise _err("too many ports", "invalid_ports")
    protocol = raw.get("protocol", "tcp")
    scope = raw.get("scope", "both")
    if protocol not in PROTOCOLS or scope not in SCOPES:
        raise _err("protocol is tcp|udp|both and scope host|docker|both")
    source_raw = raw.get("source", {"kind": "public"})
    if not isinstance(source_raw, dict):
        raise _err("source is an object", "invalid_sources")
    source_kind = source_raw.get("kind")
    label: str | None = None
    if source_kind == "public":
        source: dict[str, Any] = {"kind": "public"}
    elif source_kind == "me":
        mine = requester_network(requester)
        if mine is None:
            raise _err("your address is not known to the panel", "requester_unknown")
        source, label = {"kind": "cidrs", "cidrs": [mine]}, "me"
    elif source_kind == "cidrs":
        cidrs = source_raw.get("cidrs")
        if not isinstance(cidrs, list) or not 1 <= len(cidrs) <= 64:
            raise _err("give 1..64 addresses", "invalid_sources")
        networks = []
        try:
            for item in cidrs:
                network = parse_network(item)
                check_allow_shape(network)
                networks.append(str(network))
        except AddressError as exc:
            raise _err(str(exc), "invalid_sources") from exc
        source = {"kind": "cidrs", "cidrs": sorted(set(networks), key=networks.index)}
    elif source_kind == "list":
        list_id = source_raw.get("list_id")
        if not isinstance(list_id, str) or list_id not in lists:
            raise _err("the named address list does not exist", "source_list_not_found")
        source, label = {"kind": "list", "list_id": list_id}, lists[list_id]["name"]
    else:
        raise _err("source kind is public, me, cidrs or list", "invalid_sources")
    exclusive = raw.get("exclusive", False)
    if not isinstance(exclusive, bool):
        raise _err("exclusive must be true or false")
    # "Only" means something for an allow from specific sources only.
    exclusive = exclusive and action == "accept" and source["kind"] != "public"
    return {"kind": "port", "action": action, "ports": ports, "protocol": protocol,
            "scope": scope, "source": source, "source_label": label, "exclusive": exclusive,
            "expires_in": _expiry(raw.get("expires_in")), "note": _note(raw.get("note"))}


# ----- planning -------------------------------------------------------------------------


def _protocols(value: str) -> set[str]:
    return {"tcp", "udp"} if value == "both" else {value}


def _scopes(value: str) -> set[str]:
    return {"host", "docker"} if value == "both" else {value}


def _ranges(ports: list[str]) -> tuple[tuple[int, int], ...]:
    try:
        return parse_ports(ports)
    except PortError:
        return ()


def overlaps(a: dict[str, Any], b: dict[str, Any]) -> bool:
    if not _protocols(a["protocol"]) & _protocols(b["protocol"]):
        return False
    if not _scopes(a["scope"]) & _scopes(b["scope"]):
        return False
    return any(low <= other_high and other_low <= high
               for low, high in _ranges(a["ports"])
               for other_low, other_high in _ranges(b["ports"]))


def _specific(rule: dict[str, Any]) -> bool:
    return rule["source"]["kind"] != "public"


def _signature(rule: dict[str, Any]) -> tuple[Any, ...]:
    source = rule["source"]
    return (rule["protocol"], tuple(rule["ports"]), rule["scope"], source["kind"],
            tuple(source.get("cidrs", [])), source.get("list_id"))


def _order_key(rule: dict[str, Any]) -> tuple[Any, ...]:
    return (rule["priority"], rule["created_at"], rule["id"])


def rule_name(rule: dict[str, Any], label: str | None) -> str:
    verb = "allow" if rule["action"] == "accept" else "deny"
    protocol = "tcp+udp" if rule["protocol"] == "both" else rule["protocol"]
    source = rule["source"]
    if source["kind"] == "public":
        who = "everyone"
    elif label:
        who = label
    else:
        who = ",".join(source.get("cidrs", []))
    return f"quick: {verb} {','.join(rule['ports'])}/{protocol} from {who}"[:80]


@dataclass(slots=True)
class Plan:
    rules: list[dict[str, Any]]            # the whole new draft, in order
    created: list[dict[str, Any]]          # new rules (subset of ``rules``)
    removed: list[dict[str, Any]]          # rules taken out (exact contradictions)
    priorities: dict[str, int]             # existing rule id -> new priority (re-order)
    blocks: list[dict[str, Any]]           # block intents (handled by dynamic defense)
    unchanged: list[int]                   # indexes of intents that were already so

    @property
    def empty(self) -> bool:
        return not (self.created or self.removed or self.priorities or self.blocks)


def _covers(rule: dict[str, Any], action: str, expires: int | None) -> bool:
    if rule["action"] != action:
        return False
    current = rule.get("expires_at")
    if current is None or expires is None:
        return current is None and expires is None
    return current >= expires


def _insert_index(ordered: list[dict[str, Any]], candidate: dict[str, Any]) -> int:
    opposite = [index for index, rule in enumerate(ordered)
                if rule["enabled"] and rule["action"] != candidate["action"]
                and overlaps(rule, candidate)]
    if _specific(candidate):
        before = opposite
        after: list[int] = []
    else:
        before = [index for index in opposite if not _specific(ordered[index])]
        after = [index for index in opposite if _specific(ordered[index])]
    if before:
        return min(before)
    return max(after) + 1 if after else len(ordered)


def plan_changes(rules: list[dict[str, Any]], intents: list[dict[str, Any]], *, now: int,
                 new_id: Callable[[], str]) -> Plan:
    """Validated intents + the current draft -> the new draft and what changed."""
    ordered = sorted((dict(rule) for rule in rules), key=_order_key)
    original_priority = {rule["id"]: rule["priority"] for rule in ordered}
    created: list[dict[str, Any]] = []
    removed: list[dict[str, Any]] = []
    blocks: list[dict[str, Any]] = []
    unchanged: list[int] = []
    for position, intent in enumerate(intents):
        if intent["kind"] == "block":
            blocks.append(intent)
            continue
        expires = None if intent["expires_in"] is None else now + intent["expires_in"]
        base = {"protocol": intent["protocol"], "ports": list(intent["ports"]),
                "scope": intent["scope"], "source": dict(intent["source"])}
        group = [{**base, "action": intent["action"]}]
        if intent["exclusive"]:
            group.append({**base, "action": "drop", "source": {"kind": "public"}})
        changed = False
        to_insert: list[dict[str, Any]] = []
        for candidate in group:
            same = [rule for rule in ordered if rule["enabled"]
                    and _signature(rule) == _signature(candidate)]
            if any(_covers(rule, candidate["action"], expires) for rule in same):
                continue  # exactly this rule is already there (and lasts long enough)
            for rule in same:  # contradiction or the other kind (temporary/permanent)
                ordered.remove(rule)
                if rule["id"] in original_priority:
                    removed.append(rule)
                else:
                    created.remove(rule)
            label = intent["source_label"] if candidate["source"] == intent["source"] else None
            rule = {
                **candidate, "id": new_id(), "name": rule_name(candidate, label),
                "description": intent["note"], "enabled": True, "log": False, "log_rate": 10,
                "origin": "quick", "created_at": now, "priority": 0, "expires_at": expires,
            }
            to_insert.append(rule)
            changed = True
        if to_insert:
            index = min(_insert_index(ordered, rule) for rule in to_insert)
            ordered[index:index] = to_insert
            created.extend(to_insert)
        if not changed:
            unchanged.append(position)
    priorities = _assign_priorities(ordered, {rule["id"] for rule in created})
    moved = {rule_id: value for rule_id, value in priorities.items()
             if rule_id in original_priority and original_priority[rule_id] != value}
    for rule in ordered:
        rule["priority"] = priorities[rule["id"]]
    return Plan(rules=ordered, created=created, removed=removed, priorities=moved,
                blocks=blocks, unchanged=unchanged)


def _assign_priorities(ordered: list[dict[str, Any]], new_ids: set[str]) -> dict[str, int]:
    """Keep existing priorities, slot new rules in between; renumber when no gap left."""
    result: dict[str, int] = {}
    previous = 0
    for index, rule in enumerate(ordered):
        if rule["id"] not in new_ids:
            if rule["priority"] <= previous and index:
                return _renumber(ordered)
            result[rule["id"]] = previous = rule["priority"]
            continue
        following = next((item["priority"] for item in ordered[index + 1:]
                          if item["id"] not in new_ids), None)
        if following is None:
            value = previous + STEP
        elif following - previous >= 2:
            value = previous + max(1, min(STEP, (following - previous) // 2))
            if value >= following:
                return _renumber(ordered)
        else:
            return _renumber(ordered)
        result[rule["id"]] = previous = value
    if previous > MAX_PRIORITY:
        return _renumber(ordered)
    return result


def _renumber(ordered: list[dict[str, Any]]) -> dict[str, int]:
    return {rule["id"]: (index + 1) * STEP for index, rule in enumerate(ordered)}


# ----- risk of a change -----------------------------------------------------------------


def opens_only(old: PortPolicy | None, new: PortPolicy, now: float) -> bool:
    """True when ``new`` can only accept more than ``old`` (added allows, removed denies,
    same defaults). Such a change cannot lock anyone out, so it needs no trial period."""
    if not new.enabled:
        return True
    current = new.without_expired(now)
    if old is None or not old.enabled:
        return current.input_policy == "accept" and current.forward_policy == "accept" \
            and all(rule.action == "accept" for rule in current.rules)
    before = old.without_expired(now)
    fields = ("input_policy", "forward_policy", "trust_docker_bridges", "allow_icmp")
    if any(getattr(before, name) != getattr(current, name) for name in fields):
        return False
    old_ids = {rule.id for rule in before.rules}
    new_ids = {rule.id for rule in current.rules}

    def kept(rules: list[PortRule], other: set[str], extra_action: str) -> list[Any]:
        return [rule.to_payload() for rule in rules
                if not (rule.action == extra_action and rule.id not in other)]

    return kept(before.rules, new_ids, "drop") == kept(current.rules, old_ids, "accept")
