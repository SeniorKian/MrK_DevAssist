"""Port policy (docs/45): inbound rules for host services and Docker-published ports.

Shared by the helper (strict re-validation + nft rendering) and the control plane
(compilation, lockout checks, preview). Everything rendered into nft text comes from
validated integers, ``ipaddress`` objects and ids matching ``RULE_ID``.

Chains (all inside ``table inet mrk``; Docker/Dokploy chains are never touched):

* ``mrk_input``     hook input: host services. ``policy drop`` only with default deny.
* ``mrk_forward``   hook forward, always ``policy accept``: established/related first,
  then only DNAT-ed connections (= Docker/Swarm published ports) jump to
* ``mrk_published`` matches the *original* destination port (``ct original proto-dst``,
  the published port before Docker's DNAT) and ends with ``drop`` only with default
  deny. Container egress and other routed traffic are never filtered.

An ``accept`` here only ends our chain: UFW, Docker and the legacy PAASIFY chain still
see the packet, so until the migration is finished an allow rule alone does not open a
port that another firewall closes.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from .addresses import (
    AddressError,
    IPAddress,
    IPNetwork,
    check_allow_shape,
    contains,
    drop_covered,
    element,
    parse_network,
)

PROTOCOLS = ("tcp", "udp", "both")
SCOPES = ("host", "docker", "both")
ACTIONS = ("accept", "drop")
POLICIES = ("accept", "drop")
MAX_RULES = 512
MAX_PORT_ITEMS = 64
MAX_SOURCES = 64
MAX_TEMP_ALLOW = 64
MIN_LOG_RATE, MAX_LOG_RATE = 1, 600  # log lines per minute
MAX_TEMP_SECONDS = 7 * 24 * 3600
RULE_ID = re.compile(r"^[a-z0-9][a-z0-9-]{0,31}$")
CHAIN_INPUT = "mrk_input"
CHAIN_FORWARD = "mrk_forward"
CHAIN_PUBLISHED = "mrk_published"
SET_MGMT_V4 = "mrk_mgmt_v4"
SET_MGMT_V6 = "mrk_mgmt_v6"
DOCKER_BRIDGES = ("docker0", "br-*", "docker_gwbridge")
_PORT_TEXT = re.compile(r"^\s*(\d{1,5})\s*(?:[-:]\s*(\d{1,5})\s*)?$")

PortRange = tuple[int, int]


class PortError(ValueError):
    """Invalid port policy; ``code`` is a stable API error code."""

    def __init__(self, message: str, code: str = "invalid_port_rule") -> None:
        super().__init__(message)
        self.code = code


def parse_ports(value: object) -> tuple[PortRange, ...]:
    """``"22, 80,14000-14999"`` / ``[22, "9000:9001"]`` -> merged, sorted ranges."""
    if isinstance(value, str):
        items: list[object] = [part for part in value.split(",") if part.strip()]
    elif isinstance(value, list):
        items = list(value)
    else:
        raise PortError("ports must be a list or a comma separated text", "invalid_ports")
    if not items:
        raise PortError("give at least one port", "invalid_ports")
    if len(items) > MAX_PORT_ITEMS:
        raise PortError(f"at most {MAX_PORT_ITEMS} ports or ranges per rule", "invalid_ports")
    ranges: list[PortRange] = []
    for item in items:
        if isinstance(item, int) and not isinstance(item, bool):
            low = high = item
        elif isinstance(item, str):
            match = _PORT_TEXT.fullmatch(item)
            if match is None:
                raise PortError(f"invalid port: {item[:20]!r}", "invalid_ports")
            low = int(match.group(1))
            high = int(match.group(2)) if match.group(2) else low
        else:
            raise PortError("ports must be numbers or ranges like 14000-14999", "invalid_ports")
        if not 1 <= low <= 65535 or not 1 <= high <= 65535:
            raise PortError("ports must be between 1 and 65535", "invalid_ports")
        if high < low:
            raise PortError("a range must go from low to high", "invalid_ports")
        ranges.append((low, high))
    ranges.sort()
    merged: list[PortRange] = [ranges[0]]
    for low, high in ranges[1:]:
        last_low, last_high = merged[-1]
        if low <= last_high + 1:
            merged[-1] = (last_low, max(last_high, high))
        else:
            merged.append((low, high))
    return tuple(merged)


def format_ports(ranges: Iterable[PortRange]) -> list[str]:
    return [str(low) if low == high else f"{low}-{high}" for low, high in ranges]


def port_in(ranges: Iterable[PortRange], port: int) -> bool:
    return any(low <= port <= high for low, high in ranges)


def parse_sources(value: object) -> tuple[IPNetwork, ...] | None:
    """None (or [] / "public") = any source; else a list of IPs/CIDRs (never /0)."""
    if value is None or value == "public":
        return None
    if not isinstance(value, list) or len(value) > MAX_SOURCES:
        raise PortError(f"sources must be a list of at most {MAX_SOURCES} addresses",
                        "invalid_sources")
    if not value:
        raise PortError("give at least one source address", "invalid_sources")
    networks: list[IPNetwork] = []
    try:
        for item in value:
            network = parse_network(item)
            check_allow_shape(network)
            networks.append(network)
    except AddressError as exc:
        raise PortError(f"source: {exc}", "invalid_sources") from exc
    return tuple(drop_covered(networks))


def _flag(payload: dict[str, Any], name: str, default: bool) -> bool:
    value = payload.get(name, default)
    if not isinstance(value, bool):
        raise PortError(f"{name} must be true or false", "invalid_port_policy")
    return value


def _choice(payload: dict[str, Any], name: str, choices: tuple[str, ...], default: str) -> str:
    value = payload.get(name, default)
    if value not in choices:
        raise PortError(f"{name} must be one of {', '.join(choices)}", "invalid_port_policy")
    return str(value)


def _rate(value: object, name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not (
        MIN_LOG_RATE <= value <= MAX_LOG_RATE
    ):
        raise PortError(f"{name} must be {MIN_LOG_RATE}..{MAX_LOG_RATE} per minute",
                        "invalid_port_policy")
    return value


@dataclass(frozen=True, slots=True)
class PortRule:
    id: str
    protocol: str
    ports: tuple[PortRange, ...]
    sources: tuple[IPNetwork, ...] | None
    scope: str
    action: str = "accept"
    log: bool = False
    log_rate: int = 10
    # Temporary rule: rendered only while ``now < expires_at`` (None = permanent). The
    # expiry is part of the policy identity, so an expiring rule never needs a rollback.
    expires_at: int | None = None

    @classmethod
    def from_payload(cls, payload: object) -> PortRule:
        if not isinstance(payload, dict):
            raise PortError("each rule must be an object")
        unknown = set(payload) - {"id", "protocol", "ports", "sources", "scope", "action",
                                  "log", "log_rate", "expires_at"}
        if unknown:
            raise PortError(f"unknown rule field: {sorted(unknown)[0]}")
        rule_id = payload.get("id")
        if not isinstance(rule_id, str) or not RULE_ID.fullmatch(rule_id):
            raise PortError("rule id must be 1..32 of a-z 0-9 -")
        expires = payload.get("expires_at")
        if expires is not None and (not isinstance(expires, int) or isinstance(expires, bool)
                                    or not 0 < expires < 2**40):
            raise PortError("expires_at must be a unix time or null")
        return cls(
            id=rule_id,
            protocol=_choice(payload, "protocol", PROTOCOLS, "tcp"),
            ports=parse_ports(payload.get("ports")),
            sources=parse_sources(payload.get("sources")),
            scope=_choice(payload, "scope", SCOPES, "host"),
            action=_choice(payload, "action", ACTIONS, "accept"),
            log=_flag(payload, "log", False),
            log_rate=_rate(payload.get("log_rate", 10), "log_rate"),
            expires_at=expires,
        )

    def to_payload(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "id": self.id, "protocol": self.protocol, "ports": format_ports(self.ports),
            "sources": None if self.sources is None else [str(item) for item in self.sources],
            "scope": self.scope, "action": self.action, "log": self.log,
            "log_rate": self.log_rate,
        }
        if self.expires_at is not None:  # omitted when permanent: keeps older keys stable
            payload["expires_at"] = self.expires_at
        return payload

    def active(self, now: float | None) -> bool:
        return self.expires_at is None or now is None or now < self.expires_at

    def protocols(self) -> tuple[str, ...]:
        return ("tcp", "udp") if self.protocol == "both" else (self.protocol,)

    def in_chain(self, chain: str) -> bool:
        wanted = "host" if chain == CHAIN_INPUT else "docker"
        return self.scope in (wanted, "both")

    def matches(self, protocol: str, port: int, address: IPAddress | None) -> bool:
        if protocol not in self.protocols() or not port_in(self.ports, port):
            return False
        if self.sources is None:
            return True
        return address is not None and any(contains(net, address) for net in self.sources)


@dataclass(frozen=True, slots=True)
class TempAllow:
    network: IPNetwork
    expires_at: int


@dataclass(slots=True)
class PortPolicy:
    enabled: bool = True
    input_policy: str = "accept"
    forward_policy: str = "accept"
    trust_docker_bridges: bool = True
    allow_icmp: bool = True
    log_drops: bool = True
    log_rate: int = 10
    rules: list[PortRule] = field(default_factory=list)
    temp_allow: list[TempAllow] = field(default_factory=list)

    @classmethod
    def from_payload(cls, payload: object, *, now: float | None = None) -> PortPolicy:
        if not isinstance(payload, dict):
            raise PortError("ports must be an object", "invalid_port_policy")
        unknown = set(payload) - {"enabled", "input_policy", "forward_policy",
                                  "trust_docker_bridges", "allow_icmp", "log_drops",
                                  "log_rate", "rules", "temp_allow"}
        if unknown:
            raise PortError(f"unknown ports field: {sorted(unknown)[0]}", "invalid_port_policy")
        rules_raw = payload.get("rules", [])
        if not isinstance(rules_raw, list) or len(rules_raw) > MAX_RULES:
            raise PortError(f"rules must be a list of at most {MAX_RULES}", "invalid_port_policy")
        rules = [PortRule.from_payload(item) for item in rules_raw]
        if len({rule.id for rule in rules}) != len(rules):
            raise PortError("rule ids must be unique", "invalid_port_policy")
        temp_raw = payload.get("temp_allow", [])
        if not isinstance(temp_raw, list) or len(temp_raw) > MAX_TEMP_ALLOW:
            raise PortError(f"temp_allow must be a list of at most {MAX_TEMP_ALLOW}",
                            "invalid_port_policy")
        current = int(time.time() if now is None else now)
        temp: list[TempAllow] = []
        for item in temp_raw:
            if not isinstance(item, dict) or set(item) != {"cidr", "expires_at"}:
                raise PortError("temp_allow entries are {cidr, expires_at}",
                                "invalid_port_policy")
            expires = item["expires_at"]
            if not isinstance(expires, int) or isinstance(expires, bool):
                raise PortError("expires_at must be an integer", "invalid_port_policy")
            try:
                network = parse_network(item["cidr"])
                check_allow_shape(network)
            except AddressError as exc:
                raise PortError(f"temp_allow: {exc}", "invalid_port_policy") from exc
            if expires > current:
                temp.append(TempAllow(network, min(expires, current + MAX_TEMP_SECONDS)))
        return cls(
            enabled=_flag(payload, "enabled", True),
            input_policy=_choice(payload, "input_policy", POLICIES, "accept"),
            forward_policy=_choice(payload, "forward_policy", POLICIES, "accept"),
            trust_docker_bridges=_flag(payload, "trust_docker_bridges", True),
            allow_icmp=_flag(payload, "allow_icmp", True),
            log_drops=_flag(payload, "log_drops", True),
            log_rate=_rate(payload.get("log_rate", 10), "log_rate"),
            rules=rules,
            temp_allow=temp,
        )

    def to_payload(self) -> dict[str, Any]:
        return {
            **self._policy_payload(),
            "temp_allow": sorted(
                ({"cidr": str(item.network), "expires_at": item.expires_at}
                 for item in self.temp_allow),
                key=lambda entry: (entry["cidr"], entry["expires_at"]),
            ),
        }

    def _policy_payload(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "input_policy": self.input_policy,
            "forward_policy": self.forward_policy,
            "trust_docker_bridges": self.trust_docker_bridges,
            "allow_icmp": self.allow_icmp,
            "log_drops": self.log_drops,
            "log_rate": self.log_rate,
            "rules": [rule.to_payload() for rule in self.rules],
        }

    def risk_key(self) -> str:
        """Identity of what can lock someone out: everything except the temporary allows."""
        if not self.enabled:
            return "off"
        canonical = json.dumps(self._policy_payload(), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode()).hexdigest()

    def without_expired(self, now: float) -> PortPolicy:
        """The same policy minus rules whose expiry has passed (what is really loaded)."""
        return PortPolicy(
            enabled=self.enabled, input_policy=self.input_policy,
            forward_policy=self.forward_policy, trust_docker_bridges=self.trust_docker_bridges,
            allow_icmp=self.allow_icmp, log_drops=self.log_drops, log_rate=self.log_rate,
            rules=[rule for rule in self.rules if rule.active(now)],
            temp_allow=list(self.temp_allow),
        )

    def effective_key(self, now: float) -> str:
        """``risk_key`` of what is loaded at ``now``: equal for two policies that differ
        only by rules that already expired (the panel's "draft differs" check)."""
        return self.without_expired(now).risk_key()

    def next_expiry(self, after: float) -> int | None:
        """The first rule expiry later than ``after`` (the helper re-renders then)."""
        times = [rule.expires_at for rule in self.rules
                 if rule.expires_at is not None and rule.expires_at > after]
        return min(times) if times else None

    def permanent(self) -> PortPolicy:
        """The policy once every temporary rule has expired."""
        return self.without_expired(float(2**41))

    # ----- simulation (lockout checks) -------------------------------------------
    def verdict(self, chain: str, protocol: str, port: int, address: IPAddress | None, *,
                include_temp: bool = False, now: float | None = None) -> str:
        """What a NEW connection gets from our chain (first match wins, like nft).
        With ``now``, rules that expired by then are skipped."""
        if not self.enabled:
            return "accept"
        if include_temp and address is not None and any(
            contains(item.network, address) for item in self.temp_allow
        ):
            return "accept"
        for rule in self.rules:
            if rule.active(now) and rule.in_chain(chain) and rule.matches(protocol, port,
                                                                           address):
                return rule.action
        return self.input_policy if chain == CHAIN_INPUT else self.forward_policy

    def reachable_somewhere(self, chain: str, protocol: str, port: int, *,
                            now: float | None = None) -> bool:
        """True when at least one source can open a new connection to this port."""
        if not self.enabled:
            return True
        for rule in self.rules:
            if not rule.active(now) or not rule.in_chain(chain) \
                    or protocol not in rule.protocols() or not port_in(rule.ports, port):
                continue
            if rule.action == "accept":
                return True
            if rule.sources is None:
                return False
        policy = self.input_policy if chain == CHAIN_INPUT else self.forward_policy
        return policy == "accept"


def risk_key(policy: PortPolicy | None) -> str:
    return "off" if policy is None else policy.risk_key()


# ----- rendering -------------------------------------------------------------------


def _anon(items: list[str]) -> str:
    return items[0] if len(items) == 1 else "{ " + ", ".join(items) + " }"


def _timeout_set(name: str, kind: str, elements: list[str]) -> str:
    lines = [f"\tset {name} {{", f"\t\ttype {kind}", "\t\tflags interval, timeout"]
    if elements:
        joined = ",\n".join(f"\t\t\t{item}" for item in elements)
        lines.append(f"\t\telements = {{\n{joined}\n\t\t}}")
    lines.append("\t}")
    return "\n".join(lines)


def render_sets(policy: PortPolicy, now: int) -> list[str]:
    temp = drop_covered(item.network for item in policy.temp_allow)
    expiry = {item.network: item.expires_at for item in policy.temp_allow}

    def elem(network: IPNetwork) -> str:
        expires = max((value for net, value in expiry.items() if contains(network, net)),
                      default=now + 60)
        remaining = min(max(expires - now, 1), MAX_TEMP_SECONDS)
        return f"{element(network)} timeout {remaining}s"

    return [
        _timeout_set(SET_MGMT_V4, "ipv4_addr", [elem(n) for n in temp if n.version == 4]),
        _timeout_set(SET_MGMT_V6, "ipv6_addr", [elem(n) for n in temp if n.version == 6]),
    ]


def _rule_lines(rule: PortRule, chain: str) -> list[str]:
    ports = _anon(format_ports(rule.ports))
    if rule.sources is None:
        sources = [""]
    else:
        v4 = [element(net) for net in rule.sources if net.version == 4]
        v6 = [element(net) for net in rule.sources if net.version == 6]
        sources = ([f"ip saddr {{ {', '.join(v4)} }} "] if v4 else []) + (
            [f"ip6 saddr {{ {', '.join(v6)} }} "] if v6 else [])
    verdict = "accept" if rule.action == "accept" else "counter drop"
    tag = "a" if rule.action == "accept" else "d"
    lines: list[str] = []
    for protocol in rule.protocols():
        match = (f"{protocol} dport {ports}" if chain == CHAIN_INPUT
                 else f"meta l4proto {protocol} ct original proto-dst {ports}")
        for source in sources:
            text = f"{source}{match}"
            if rule.log:
                lines.append(f"\t\t{text} limit rate {rule.log_rate}/minute burst 5 packets "
                             f'log prefix "mrk-{tag}-{rule.id} "')
            lines.append(f'\t\t{text} {verdict} comment "{rule.id}"')
    return lines


def render_chains(policy: PortPolicy, now: float | None = None) -> list[str]:
    """Chains of the policy; with ``now``, expired temporary rules are left out."""
    if now is not None:
        policy = policy.without_expired(now)
    drop_log = f'limit rate {policy.log_rate}/minute burst 5 packets log prefix'
    lines = [
        f"\tchain {CHAIN_INPUT} {{",
        f"\t\ttype filter hook input priority filter; policy {policy.input_policy};",
        "\t\tct state established,related accept",
        '\t\tiifname "lo" accept',
    ]
    if policy.trust_docker_bridges:
        lines.extend(f'\t\tiifname "{name}" accept' for name in DOCKER_BRIDGES)
    if policy.allow_icmp:
        lines.append("\t\tmeta l4proto { icmp, ipv6-icmp } accept")
    else:  # IPv6 needs neighbour discovery even when ping is closed.
        lines.append("\t\ticmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, "
                     "nd-router-advert } accept")
    lines += [f"\t\tip saddr @{SET_MGMT_V4} accept", f"\t\tip6 saddr @{SET_MGMT_V6} accept"]
    for rule in policy.rules:
        if rule.in_chain(CHAIN_INPUT):
            lines.extend(_rule_lines(rule, CHAIN_INPUT))
    if policy.input_policy == "drop":
        if policy.log_drops:
            lines.append(f'\t\t{drop_log} "mrk-drop-in "')
        lines.append("\t\tcounter")
    lines += [
        "\t}",
        f"\tchain {CHAIN_FORWARD} {{",
        "\t\ttype filter hook forward priority filter; policy accept;",
        "\t\tct state established,related accept",
        f"\t\tct status dnat jump {CHAIN_PUBLISHED}",
        "\t}",
        f"\tchain {CHAIN_PUBLISHED} {{",
        f"\t\tip saddr @{SET_MGMT_V4} accept",
        f"\t\tip6 saddr @{SET_MGMT_V6} accept",
    ]
    for rule in policy.rules:
        if rule.in_chain(CHAIN_PUBLISHED):
            lines.extend(_rule_lines(rule, CHAIN_PUBLISHED))
    if policy.forward_policy == "drop":
        if policy.log_drops:
            lines.append(f'\t\t{drop_log} "mrk-drop-fwd "')
        lines.append("\t\tcounter drop")
    lines.append("\t}")
    return lines
