"""Port policy (docs/45) on the panel side: validation, settings, compilation, lockout checks.

Pure logic, no I/O. Port rules in the database are a *draft*; ``compile_policy`` turns
the enabled rules (in priority order) plus the policy settings into the payload the
helper enforces. ``lockout_problems`` is asked before every apply; the helper adds the
second safety net (nft --check, atomic load, automatic rollback to the last-known-good).
"""

from __future__ import annotations

import copy
import difflib
import ipaddress
from collections.abc import Iterable
from typing import Any

from ..firewall.addresses import IPAddress
from ..firewall.nft import DesiredState, render_effective
from ..firewall.ports import (
    ACTIONS,
    CHAIN_INPUT,
    CHAIN_PUBLISHED,
    MAX_LOG_RATE,
    MAX_RULES,
    MIN_LOG_RATE,
    PROTOCOLS,
    SCOPES,
    PortError,
    PortPolicy,
    PortRule,
    TempAllow,
    format_ports,
    parse_ports,
    parse_sources,
)
from .firewall_engine import FirewallError

MAX_NAME = 80
MAX_DESCRIPTION = 500
MAX_PRIORITY = 100_000
MAX_LISTS = 64
SOURCE_KINDS = ("public", "cidrs", "list")
RULE_ORIGINS = ("manual", "ufw", "paasify")
MANAGEMENT_LIST = "management"
DEFAULT_ROLLBACK_SECONDS = 120

DEFAULT_PORT_SETTINGS: dict[str, Any] = {
    # Default deny per scope. Off = the chains accept what no rule matches, so turning
    # the port policy on never closes anything by itself.
    "default_deny_host": False,
    "default_deny_docker": False,
    "trust_docker_bridges": True,
    "allow_icmp": True,
    "log_drops": True,
    "log_rate_per_minute": 10,
    # [] = detect from the server's sshd_config (22 when unknown).
    "ssh_ports": [],
    # Ports the panel is reached on besides the one of the current request.
    "panel_ports": [],
    "temp_allow_requester": True,
    "temp_allow_seconds": 3600,
    "rollback_seconds": DEFAULT_ROLLBACK_SECONDS,
    # Protected ports (Swarm, Dokploy, DNS) the operator knowingly lets the policy close.
    "allow_closed_protected": [],
}

# key, ports, protocol, chain, group (relevance)
PROTECTED_PORTS: tuple[tuple[str, int, str, str, str], ...] = (
    ("swarm-manager", 2377, "tcp", CHAIN_INPUT, "swarm"),
    ("swarm-gossip-tcp", 7946, "tcp", CHAIN_INPUT, "swarm"),
    ("swarm-gossip-udp", 7946, "udp", CHAIN_INPUT, "swarm"),
    ("swarm-overlay", 4789, "udp", CHAIN_INPUT, "swarm"),
    ("dokploy", 3000, "tcp", CHAIN_PUBLISHED, "dokploy"),
    ("dns-udp", 53, "udp", CHAIN_INPUT, "dns"),
    ("dns-tcp", 53, "tcp", CHAIN_INPUT, "dns"),
)
PROTECTED_KEYS = tuple(item[0] for item in PROTECTED_PORTS)


def _err(code: str, message: str, status: int = 422) -> FirewallError:
    return FirewallError(code, message, status)


def _text(value: object, name: str, limit: int, *, required: bool) -> str:
    if value is None and not required:
        return ""
    if not isinstance(value, str):
        raise _err("invalid_port_rule", f"{name} must be text")
    text = "".join(ch for ch in value.strip() if ch.isprintable())
    if (required and not text) or len(text) > limit:
        raise _err("invalid_port_rule", f"{name} must be 1..{limit} characters")
    return text


def _bool(value: object, name: str, code: str = "invalid_port_rule") -> bool:
    if not isinstance(value, bool):
        raise _err(code, f"{name} must be true or false")
    return value


def _int(value: object, name: str, low: int, high: int, code: str = "invalid_port_rule") -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not low <= value <= high:
        raise _err(code, f"{name} must be an integer {low}..{high}")
    return value


def normalize_cidrs(value: object, code: str = "invalid_sources") -> list[str]:
    try:
        networks = parse_sources(value)
    except PortError as exc:
        raise _err(code, str(exc)) from exc
    if networks is None:
        raise _err(code, "give at least one address")
    return [str(item) for item in networks]


def validate_port_rule(payload: object, *, partial: bool = False) -> dict[str, Any]:
    """API body -> database columns (strict). ``source`` is {kind, cidrs?, list_id?}."""
    if not isinstance(payload, dict):
        raise _err("invalid_port_rule", "rule must be an object")
    fields = {"name", "description", "protocol", "ports", "source", "scope", "action",
              "enabled", "priority", "log", "log_rate"}
    unknown = set(payload) - fields
    if unknown:
        raise _err("invalid_port_rule", f"unknown field: {sorted(unknown)[0]}")
    if not partial:
        missing = {"name", "protocol", "ports", "scope"} - set(payload)
        if missing:
            raise _err("invalid_port_rule", f"missing field: {sorted(missing)[0]}")
    out: dict[str, Any] = {}
    if "name" in payload:
        out["name"] = _text(payload["name"], "name", MAX_NAME, required=True)
    if "description" in payload:
        out["description"] = _text(payload["description"], "description", MAX_DESCRIPTION,
                                   required=False)
    if "protocol" in payload:
        if payload["protocol"] not in PROTOCOLS:
            raise _err("invalid_port_rule", "protocol must be tcp, udp or both")
        out["protocol"] = payload["protocol"]
    if "ports" in payload:
        try:
            out["ports"] = format_ports(parse_ports(payload["ports"]))
        except PortError as exc:
            raise _err(exc.code, str(exc)) from exc
    if "scope" in payload:
        if payload["scope"] not in SCOPES:
            raise _err("invalid_port_rule", "scope must be host, docker or both")
        out["scope"] = payload["scope"]
    if "action" in payload:
        if payload["action"] not in ACTIONS:
            raise _err("invalid_port_rule", "action must be accept or drop")
        out["action"] = payload["action"]
    if "source" in payload or not partial:
        source = payload.get("source", {"kind": "public"})
        if not isinstance(source, dict) or source.get("kind") not in SOURCE_KINDS:
            raise _err("invalid_sources", "source is {kind: public|cidrs|list}")
        kind = source["kind"]
        allowed = {"public": {"kind"}, "cidrs": {"kind", "cidrs"},
                   "list": {"kind", "list_id"}}[kind]
        if set(source) - allowed:
            raise _err("invalid_sources", f"unknown source field for {kind}")
        out["source_kind"] = kind
        out["source_cidrs"] = normalize_cidrs(source.get("cidrs")) if kind == "cidrs" else []
        list_id = source.get("list_id")
        if kind == "list" and (not isinstance(list_id, str) or not 1 <= len(list_id) <= 32):
            raise _err("invalid_sources", "pick a named address list")
        out["source_list_id"] = list_id if kind == "list" else None
    if "enabled" in payload:
        out["enabled"] = _bool(payload["enabled"], "enabled")
    if "priority" in payload:
        out["priority"] = _int(payload["priority"], "priority", 0, MAX_PRIORITY)
    if "log" in payload:
        out["log"] = _bool(payload["log"], "log")
    if "log_rate" in payload:
        out["log_rate"] = _int(payload["log_rate"], "log_rate", MIN_LOG_RATE, MAX_LOG_RATE)
    return out


def validate_source_list(payload: object, *, partial: bool = False) -> dict[str, Any]:
    if not isinstance(payload, dict) or set(payload) - {"name", "note", "cidrs"}:
        raise _err("invalid_source_list", "list is {name, note, cidrs}")
    if not partial and {"name", "cidrs"} - set(payload):
        raise _err("invalid_source_list", "name and cidrs are required")
    out: dict[str, Any] = {}
    try:
        if "name" in payload:
            out["name"] = _text(payload["name"], "name", MAX_NAME, required=True)
        if "note" in payload:
            out["note"] = _text(payload["note"], "note", MAX_DESCRIPTION, required=False)
    except FirewallError as exc:
        raise _err("invalid_source_list", exc.message) from exc
    if "cidrs" in payload:
        out["cidrs"] = normalize_cidrs(payload["cidrs"])
    return out


# ----- settings ----------------------------------------------------------------------


def _port_list(value: object, name: str) -> list[int]:
    if not isinstance(value, list) or len(value) > 16 or any(
        not isinstance(item, int) or isinstance(item, bool) or not 1 <= item <= 65535
        for item in value
    ):
        raise _err("invalid_port_settings", f"{name} must be a list of up to 16 ports")
    return sorted(set(value))


def merge_port_settings(current: dict[str, Any], patch: object) -> dict[str, Any]:
    if not isinstance(patch, dict):
        raise _err("invalid_port_settings", "settings must be an object")
    unknown = set(patch) - set(DEFAULT_PORT_SETTINGS)
    if unknown:
        raise _err("invalid_port_settings", f"unknown setting: {sorted(unknown)[0]}")
    result = copy.deepcopy(current)
    code = "invalid_port_settings"
    for key, value in patch.items():
        if key in {"default_deny_host", "default_deny_docker", "trust_docker_bridges",
                   "allow_icmp", "log_drops", "temp_allow_requester"}:
            result[key] = _bool(value, key, code)
        elif key == "log_rate_per_minute":
            result[key] = _int(value, key, MIN_LOG_RATE, MAX_LOG_RATE, code)
        elif key in {"ssh_ports", "panel_ports"}:
            result[key] = _port_list(value, key)
        elif key == "temp_allow_seconds":
            result[key] = _int(value, key, 300, 7 * 86400, code)
        elif key == "rollback_seconds":
            result[key] = _int(value, key, 30, 900, code)
        elif key == "allow_closed_protected":
            if not isinstance(value, list) or any(item not in PROTECTED_KEYS for item in value):
                raise _err(code, f"allow_closed_protected is a subset of {PROTECTED_KEYS}")
            result[key] = sorted(set(value))
    return result


def load_port_settings(stored: object) -> dict[str, Any]:
    settings = copy.deepcopy(DEFAULT_PORT_SETTINGS)
    if not isinstance(stored, dict):
        return settings
    for key in DEFAULT_PORT_SETTINGS:
        if key in stored:
            try:
                settings = merge_port_settings(settings, {key: stored[key]})
            except FirewallError:
                continue
    return settings


# ----- compilation -------------------------------------------------------------------


def compile_policy(rules: Iterable[dict[str, Any]], lists: dict[str, dict[str, Any]],
                   settings: dict[str, Any], *, temp_allow: Iterable[TempAllow] = ()
                   ) -> tuple[PortPolicy, list[dict[str, Any]]]:
    """Enabled draft rules in (priority, created) order -> (policy, warnings)."""
    ordered = sorted((rule for rule in rules if rule["enabled"]),
                     key=lambda item: (item["priority"], item["created_at"], item["id"]))
    compiled: list[PortRule] = []
    warnings: list[dict[str, Any]] = []
    for rule in ordered[:MAX_RULES]:
        sources: list[str] | None
        if rule["source"]["kind"] == "public":
            sources = None
        elif rule["source"]["kind"] == "cidrs":
            sources = list(rule["source"]["cidrs"])
        else:
            listed = lists.get(rule["source"].get("list_id") or "")
            if listed is None or not listed["cidrs"]:
                warnings.append({"code": "empty_source_list", "rule_id": rule["id"],
                                 "name": rule["name"]})
                continue
            sources = list(listed["cidrs"])
        compiled.append(PortRule.from_payload({
            "id": rule["id"], "protocol": rule["protocol"], "ports": rule["ports"],
            "sources": sources, "scope": rule["scope"], "action": rule["action"],
            "log": rule["log"], "log_rate": rule["log_rate"],
        }))
    if len(ordered) > MAX_RULES:
        warnings.append({"code": "too_many_rules", "max": MAX_RULES})
    policy = PortPolicy(
        enabled=True,
        input_policy="drop" if settings["default_deny_host"] else "accept",
        forward_policy="drop" if settings["default_deny_docker"] else "accept",
        trust_docker_bridges=settings["trust_docker_bridges"],
        allow_icmp=settings["allow_icmp"],
        log_drops=settings["log_drops"],
        log_rate=settings["log_rate_per_minute"],
        rules=compiled,
        temp_allow=list(temp_allow),
    )
    return policy, warnings


# ----- lockout protection ------------------------------------------------------------


def management_probes(requester: IPAddress | None, lists: Iterable[dict[str, Any]]
                      ) -> list[IPAddress | None]:
    """Addresses that must keep SSH and the panel: the requester and the first address of
    every network in the list named "management". [None] = only public rules count."""
    probes: list[IPAddress | None] = []
    if requester is not None:
        probes.append(requester)
    for item in lists:
        if item["name"].strip().lower() != MANAGEMENT_LIST:
            continue
        for cidr in item["cidrs"]:
            network = ipaddress.ip_network(cidr, strict=False)
            address = network.network_address if network.num_addresses == 1 else next(
                network.hosts(), network.network_address)
            if address not in probes:
                probes.append(address)
    return probes or [None]


def relevant_protected(listening: list[dict[str, Any]] | None, dns_installed: bool
                       ) -> set[str]:
    """Which protected ports matter on this server (all of them when unknown)."""
    groups: set[str] = {"dns"} if dns_installed else set()
    if listening is None:
        groups |= {"swarm", "dokploy"}
    else:
        open_ports = {(item.get("protocol"), item.get("port")) for item in listening
                      if isinstance(item, dict) and not item.get("loopback_only")}
        if ("tcp", 2377) in open_ports or ("tcp", 7946) in open_ports:
            groups |= {"swarm", "dokploy"}  # Dokploy runs on Swarm
        if ("tcp", 3000) in open_ports:
            groups.add("dokploy")
        if ("udp", 53) in open_ports or ("tcp", 53) in open_ports:
            groups.add("dns")
    return {key for key, _port, _proto, _chain, group in PROTECTED_PORTS if group in groups}


def lockout_problems(policy: PortPolicy, *, probes: list[IPAddress | None],
                     ssh_ports: list[int], panel_ports: list[int], protected: set[str],
                     allowed_closed: Iterable[str] = ()) -> list[dict[str, Any]]:
    """Everything that would lock an admin or a protected service out. The temporary
    allow of the requester is deliberately ignored: a permanent rule must exist."""
    if not policy.enabled:
        return []
    problems: list[dict[str, Any]] = []
    for probe in probes:
        label = "public" if probe is None else str(probe)
        if not any(policy.verdict(CHAIN_INPUT, "tcp", port, probe) == "accept"
                   for port in ssh_ports):
            problems.append({"code": "lockout_ssh", "address": label, "ports": ssh_ports})
        for port in panel_ports:
            for chain, scope in ((CHAIN_INPUT, "host"), (CHAIN_PUBLISHED, "docker")):
                if policy.verdict(chain, "tcp", port, probe) != "accept":
                    problems.append({"code": "lockout_panel", "address": label, "port": port,
                                     "scope": scope})
    skip = set(allowed_closed)
    for key, port, protocol, chain, _group in PROTECTED_PORTS:
        if key in protected and key not in skip \
                and not policy.reachable_somewhere(chain, protocol, port):
            problems.append({"code": "protected_port_closed", "key": key, "port": port,
                             "protocol": protocol,
                             "scope": "host" if chain == CHAIN_INPUT else "docker"})
    return problems


# ----- preview ----------------------------------------------------------------------

NO_TABLE = "# Nothing of ours is loaded: table inet mrk is absent.\n"


def ruleset_text(state: DesiredState, now: int) -> str:
    text = render_effective(state, now=now)
    return NO_TABLE if text is None else text


def ruleset_diff(current: str, following: str) -> list[str]:
    return list(difflib.unified_diff(current.splitlines(), following.splitlines(),
                                     "current", "next", lineterm="", n=3))
