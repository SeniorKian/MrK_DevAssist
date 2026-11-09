"""Firewall detection engine, settings/rule validation and safety checks (pure logic).

No I/O here: the module service feeds signals in, gets hits out, and asks
``refusal()`` before any block is stored.
"""

from __future__ import annotations

import copy
import ipaddress
import re
import time
from collections import OrderedDict, deque
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from ..firewall.addresses import (
    LOOPBACK,
    PRIVATE_RANGES,
    AddressError,
    IPAddress,
    IPNetwork,
    check_allow_shape,
    check_block_shape,
    contains,
    covered_by,
    is_private,
    parse_network,
)
from ..firewall.nft import MODES
from ..firewall.parsers import DEFAULT_SENSITIVE_PATHS, SIGNAL_KINDS, validate_patterns

ENFORCE_CONFIRMATION = "ENFORCE"
CLEAR_CONFIRMATION = "UNBLOCK ALL"
MAX_ALLOWLIST = 256
MAX_NOTE = 200
MAX_BAN_SECONDS = 365 * 24 * 3600
HARD_MAX_BLOCKS = 65536
_LOG_PATH = re.compile(r"^/host/log/[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+){0,7}$")
FILE_SOURCES = {"sshd": "sshd", "traefik": "traefik"}

DEFAULT_SETTINGS: dict[str, Any] = {
    # off = no detection, our nft table removed; dry_run = detect & record only
    # (default); enforce = apply blocks (needs the typed confirmation "ENFORCE").
    "mode": "dry_run",
    "allowlist": [],  # [{cidr, note, added_at, auto}]
    # Add RFC1918/CGNAT/link-local/ULA + loopback to the nft allow sets.
    "allowlist_private": True,
    # Permit blocking private ranges at all (refused by default).
    "allow_private_blocks": False,
    "default_ban_seconds": 3600,
    "max_ban_seconds": 30 * 24 * 3600,
    "max_blocks": 10000,
    "poll_interval_seconds": 15,
    "history_retention_days": 30,
    "notify": True,
    "sources": {
        # Paths are as seen inside mrk-firewall (read-only mounts under /host/log).
        "sshd": {"enabled": True, "path": "/host/log/system/auth.log"},
        "traefik": {"enabled": False, "path": "/host/log/traefik/access.log"},
        # MRK's own failed logins, read from the audit log of this control plane.
        "mrk": {"enabled": True},
    },
    "sensitive_paths": list(DEFAULT_SENSITIVE_PATHS),
}

BUILTIN_RULES: tuple[dict[str, Any], ...] = (
    {"id": "ssh-bruteforce", "name": "SSH brute force",
     "signal_kinds": ["ssh_failed_password", "ssh_invalid_user"],
     "threshold": 5, "window_seconds": 600, "ban_seconds": 3600},
    {"id": "mrk-login", "name": "Pishkar login failures", "signal_kinds": ["mrk_login_failure"],
     "threshold": 10, "window_seconds": 600, "ban_seconds": 1800},
    {"id": "http-auth", "name": "HTTP 401/403 burst", "signal_kinds": ["http_401", "http_403"],
     "threshold": 30, "window_seconds": 60, "ban_seconds": 900},
    {"id": "http-404", "name": "HTTP 404 burst", "signal_kinds": ["http_404"],
     "threshold": 120, "window_seconds": 60, "ban_seconds": 900},
    {"id": "http-probe", "name": "Sensitive path probes",
     "signal_kinds": ["http_sensitive_path"],
     "threshold": 3, "window_seconds": 300, "ban_seconds": 86400},
)


class FirewallError(Exception):
    def __init__(self, code: str, message: str, status_code: int = 422) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code


def _int(value: object, name: str, low: int, high: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not low <= value <= high:
        raise FirewallError("invalid_settings", f"{name} must be an integer {low}..{high}")
    return value


def _bool(value: object, name: str) -> bool:
    if not isinstance(value, bool):
        raise FirewallError("invalid_settings", f"{name} must be true or false")
    return value


def _note(value: object) -> str:
    if value is None:
        return ""
    if not isinstance(value, str) or len(value) > MAX_NOTE:
        raise FirewallError("invalid_settings", f"note must be a string of at most {MAX_NOTE}")
    return "".join(ch for ch in value.strip() if ch.isprintable())


def normalize_allow_entry(item: object, now: int) -> dict[str, Any]:
    if isinstance(item, str):
        item = {"cidr": item}
    if not isinstance(item, dict) or set(item) - {"cidr", "note", "added_at", "auto"}:
        raise FirewallError("invalid_settings", "allowlist entries are {cidr, note}")
    try:
        network = parse_network(item.get("cidr"))
        check_allow_shape(network)
    except AddressError as exc:
        raise FirewallError("invalid_address", f"allowlist: {exc}") from exc
    added = item.get("added_at")
    return {
        "cidr": str(network),
        "note": _note(item.get("note")),
        "added_at": added if isinstance(added, int) and not isinstance(added, bool) else now,
        "auto": bool(item.get("auto", False)),
    }


def merge_settings(current: dict[str, Any], patch: object, *, now: int | None = None
                   ) -> dict[str, Any]:
    """Validate a partial update against the full schema; return the new settings."""
    if not isinstance(patch, dict):
        raise FirewallError("invalid_settings", "settings must be an object")
    unknown = set(patch) - set(DEFAULT_SETTINGS)
    if unknown:
        raise FirewallError("invalid_settings", f"unknown setting: {sorted(unknown)[0]}")
    stamp = int(time.time() if now is None else now)
    result = copy.deepcopy(current)
    for key, value in patch.items():
        if key == "mode":
            if value not in MODES:
                raise FirewallError("invalid_mode", "mode must be off, dry_run or enforce")
            result["mode"] = value
        elif key == "allowlist":
            if not isinstance(value, list) or len(value) > MAX_ALLOWLIST:
                raise FirewallError("invalid_settings",
                                    f"allowlist must be a list of at most {MAX_ALLOWLIST}")
            entries: dict[str, dict[str, Any]] = {}
            for item in value:
                entry = normalize_allow_entry(item, stamp)
                entries.setdefault(entry["cidr"], entry)
            result["allowlist"] = list(entries.values())
        elif key in {"allowlist_private", "allow_private_blocks", "notify"}:
            result[key] = _bool(value, key)
        elif key == "default_ban_seconds":
            result[key] = _int(value, key, 60, MAX_BAN_SECONDS)
        elif key == "max_ban_seconds":
            result[key] = _int(value, key, 60, MAX_BAN_SECONDS)
        elif key == "max_blocks":
            result[key] = _int(value, key, 1, HARD_MAX_BLOCKS)
        elif key == "poll_interval_seconds":
            result[key] = _int(value, key, 5, 3600)
        elif key == "history_retention_days":
            result[key] = _int(value, key, 1, 3650)
        elif key == "sensitive_paths":
            if not isinstance(value, list):
                raise FirewallError("invalid_settings", "sensitive_paths must be a list")
            try:
                result[key] = validate_patterns(value)
            except ValueError as exc:
                raise FirewallError("invalid_settings", str(exc)) from exc
        elif key == "sources":
            result[key] = _merge_sources(result.get("sources", {}), value)
    if result["default_ban_seconds"] > result["max_ban_seconds"]:
        raise FirewallError("invalid_settings", "default_ban_seconds exceeds max_ban_seconds")
    return result


def _merge_sources(current: dict[str, Any], patch: object) -> dict[str, Any]:
    if not isinstance(patch, dict) or set(patch) - set(DEFAULT_SETTINGS["sources"]):
        raise FirewallError("invalid_settings", "sources are sshd, traefik and mrk")
    merged = copy.deepcopy(current)
    for name, value in patch.items():
        if not isinstance(value, dict):
            raise FirewallError("invalid_settings", f"sources.{name} must be an object")
        allowed = {"enabled"} if name == "mrk" else {"enabled", "path"}
        if set(value) - allowed:
            raise FirewallError("invalid_settings", f"sources.{name}: unknown field")
        entry = dict(merged.get(name, DEFAULT_SETTINGS["sources"][name]))
        if "enabled" in value:
            entry["enabled"] = _bool(value["enabled"], f"sources.{name}.enabled")
        if "path" in value:
            path = value["path"]
            if not isinstance(path, str) or not _LOG_PATH.fullmatch(path) or any(
                part in {".", ".."} for part in path.split("/")
            ):
                raise FirewallError(
                    "invalid_settings",
                    f"sources.{name}.path must be a file under /host/log/ (as mounted in "
                    "mrk-firewall)",
                )
            entry["path"] = path
        merged[name] = entry
    return merged


def load_settings(stored: object) -> dict[str, Any]:
    """Defaults + stored values; unreadable entries fall back to defaults."""
    settings = copy.deepcopy(DEFAULT_SETTINGS)
    if not isinstance(stored, dict):
        return settings
    for key in DEFAULT_SETTINGS:
        if key in stored:
            try:
                settings = merge_settings(settings, {key: stored[key]})
            except FirewallError:
                continue
    return settings


def validate_rule(payload: object, *, partial: bool = False) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise FirewallError("invalid_rule", "rule must be an object")
    fields = {"name", "signal_kinds", "threshold", "window_seconds", "ban_seconds", "enabled"}
    unknown = set(payload) - fields
    if unknown:
        raise FirewallError("invalid_rule", f"unknown field: {sorted(unknown)[0]}")
    if not partial:
        missing = {"name", "signal_kinds", "threshold", "window_seconds"} - set(payload)
        if missing:
            raise FirewallError("invalid_rule", f"missing field: {sorted(missing)[0]}")
    out: dict[str, Any] = {}
    if "name" in payload:
        name = payload["name"]
        if not isinstance(name, str) or not 1 <= len(name.strip()) <= 80:
            raise FirewallError("invalid_rule", "name must be 1..80 characters")
        out["name"] = "".join(ch for ch in name.strip() if ch.isprintable())
    if "signal_kinds" in payload:
        kinds = payload["signal_kinds"]
        if not isinstance(kinds, list) or not kinds or any(k not in SIGNAL_KINDS for k in kinds):
            raise FirewallError("invalid_rule",
                                f"signal_kinds must be a non-empty subset of {SIGNAL_KINDS}")
        out["signal_kinds"] = sorted(set(kinds))
    try:
        if "threshold" in payload:
            out["threshold"] = _int(payload["threshold"], "threshold", 1, 100000)
        if "window_seconds" in payload:
            out["window_seconds"] = _int(payload["window_seconds"], "window_seconds", 10, 86400)
        if "ban_seconds" in payload:
            out["ban_seconds"] = _int(payload["ban_seconds"], "ban_seconds", 60, MAX_BAN_SECONDS)
        if "enabled" in payload:
            out["enabled"] = _bool(payload["enabled"], "enabled")
    except FirewallError as exc:
        raise FirewallError("invalid_rule", exc.message) from exc
    return out


# ----- detection ----------------------------------------------------------


@dataclass(frozen=True, slots=True)
class RuleSpec:
    id: str
    name: str
    kinds: frozenset[str]
    threshold: int
    window_seconds: int
    ban_seconds: int


@dataclass(frozen=True, slots=True)
class Hit:
    rule: RuleSpec
    ip: str
    count: int
    sources: tuple[str, ...]
    sample: str


class Detector:
    """Sliding-window counters per (rule, ip); a hit resets that window."""

    MAX_KEYS = 50_000

    def __init__(self) -> None:
        self.windows: OrderedDict[tuple[str, str], deque[tuple[float, str, str]]] = OrderedDict()

    def observe(self, rules: Iterable[RuleSpec], signals: Iterable[dict[str, Any]],
                now: float | None = None) -> list[Hit]:
        current = time.time() if now is None else now
        rule_list = list(rules)
        hits: list[Hit] = []
        for signal in signals:
            kind = signal.get("kind")
            ip = signal.get("ip")
            if not isinstance(kind, str) or not isinstance(ip, str):
                continue
            ts = signal.get("ts")
            stamp = float(ts) if isinstance(ts, int | float) and ts <= current + 5 else current
            for rule in rule_list:
                if kind not in rule.kinds:
                    continue
                key = (rule.id, ip)
                window = self.windows.get(key)
                if window is None:
                    window = deque()
                    self.windows[key] = window
                    if len(self.windows) > self.MAX_KEYS:
                        self.windows.popitem(last=False)
                else:
                    self.windows.move_to_end(key)
                window.append((stamp, str(signal.get("source", "")), str(signal.get("detail", ""))))
                cutoff = stamp - rule.window_seconds
                while window and window[0][0] < cutoff:
                    window.popleft()
                if len(window) >= rule.threshold:
                    sources = tuple(sorted({item[1] for item in window if item[1]}))
                    hits.append(Hit(rule, ip, len(window), sources, window[-1][2][:120]))
                    del self.windows[key]
        return hits

    def prune(self, now: float, max_window: int) -> None:
        cutoff = now - max_window
        for key in [k for k, v in self.windows.items() if not v or v[-1][0] < cutoff]:
            del self.windows[key]


# ----- safety ----------------------------------------------------------------


def effective_allowlist(settings: dict[str, Any]) -> list[IPNetwork]:
    networks: list[IPNetwork] = list(LOOPBACK)
    if settings.get("allowlist_private", True):
        networks.extend(PRIVATE_RANGES)
    for entry in settings.get("allowlist", []):
        try:
            networks.append(parse_network(entry["cidr"]))
        except (AddressError, KeyError, TypeError):
            continue
    unique: list[IPNetwork] = []
    for network in networks:
        if network not in unique:
            unique.append(network)
    return unique


def parse_requester(value: str | None) -> IPAddress | None:
    if not value:
        return None
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return None
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return address.ipv4_mapped
    return address


def refusal(
    network: IPNetwork,
    *,
    settings: dict[str, Any],
    requester: IPAddress | None = None,
    local_addresses: Iterable[str] = (),
) -> tuple[str, str] | None:
    """Return (code, message) when this network must not be blocked, else None."""
    try:
        check_block_shape(network)
    except AddressError as exc:
        return exc.code, str(exc)
    if requester is not None and contains(network, requester):
        return "requester_ip", "refusing to block the address of the current request"
    for text in local_addresses:
        local = parse_requester(text)
        if local is not None and contains(network, local):
            return "host_address", "refusing to block an address of this host (or a Docker bridge)"
    if is_private(network) and not settings.get("allow_private_blocks", False):
        return "private_range", "private ranges are not blockable unless allow_private_blocks"
    allow = effective_allowlist(settings)
    if covered_by(network, allow):
        return "allowlisted", "the address is on the allowlist"
    return None
