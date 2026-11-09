"""Panel-side validation of DNS inputs before they reach the engine (docs/37 §4).

The engine validates everything again; these checks give precise ``fields``
early and keep obviously bad or dangerous values (an open resolver ACL, a
malformed name) from ever being forwarded. Names are canonical: IDNA A-labels,
lowercase, no trailing dot.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any
from urllib.parse import urlsplit

RECORD_TYPES = ("A", "AAAA", "CNAME", "MX", "TXT", "SRV", "NS", "PTR", "CAA", "SOA")
OVERRIDE_TYPES = ("A", "AAAA", "CNAME")
ZONE_TYPES = ("primary", "forwarder", "secondary")  # secondary: docs/41 §2.1
STRATEGIES = ("fastest", "parallel", "in_order")
TTL_MAX = 604800
TXT_MAX = 4000
MAX_FORWARDERS = 16
MAX_IMPORT_BYTES = 2 * 1024 * 1024

# Named fields of ``data`` per record type (the contract between panel and engine).
RECORD_FIELDS: dict[str, tuple[str, ...]] = {
    "A": ("address",),
    "AAAA": ("address",),
    "CNAME": ("target",),
    "NS": ("nameserver",),
    "PTR": ("target",),
    "MX": ("preference", "exchange"),
    "TXT": ("text",),
    "SRV": ("priority", "weight", "port", "target"),
    "CAA": ("flags", "tag", "value"),
    "SOA": ("mname", "rname", "refresh", "retry", "expire", "minimum"),
}

_LDH = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_RECORD_LABEL = re.compile(r"^(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?|\*)$")
_CAA_TAG = re.compile(r"^[a-z0-9]{1,15}$")
_ID = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")


class DnsInputError(ValueError):
    def __init__(
        self, code: str, message: str, fields: list[dict[str, Any]], status_code: int = 422
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.fields = fields
        self.status_code = status_code


def _field(field: str, reason: str, **params: Any) -> dict[str, Any]:
    item: dict[str, Any] = {"field": field, "reason_code": reason}
    if params:
        item["params"] = params
    return item


def _to_ascii(label: str) -> str:
    if label.isascii():
        return label
    try:
        return label.encode("idna").decode("ascii")
    except UnicodeError:
        raise ValueError("invalid label") from None


def _is_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(text.strip("[]"))
    except ValueError:
        return False
    return True


def name_problem(
    raw: Any, *, allow_underscore: bool, allow_wildcard: bool, min_labels: int = 1
) -> tuple[str | None, str | None]:
    """(canonical, None) or (None, reason_code) for an absolute DNS name."""
    if not isinstance(raw, str):
        return None, "invalid_type"
    text = raw.strip()
    if not text:
        return None, "required"
    if len(text) > 300:
        return None, "too_long"
    if any(ch.isspace() or ord(ch) < 32 for ch in text) or any(
        mark in text for mark in ("://", "/", "?", "#", "@", ":")
    ):
        return None, "invalid_format"
    if _is_ip(text):
        return None, "ip_not_allowed"
    text = text.lower()
    if text.endswith("."):
        text = text[:-1]
    labels = text.split(".")
    if any(not label for label in labels) or len(labels) < min_labels:
        return None, "invalid_format"
    try:
        encoded = [_to_ascii(label) for label in labels]
    except ValueError:
        return None, "invalid_format"
    for index, label in enumerate(encoded):
        if label == "*":
            if not allow_wildcard or index != 0:
                return None, "wildcard_not_allowed"
            continue
        if allow_underscore:
            if not _RECORD_LABEL.fullmatch(label) or len(label) > 63:
                return None, "invalid_format"
        elif not _LDH.fullmatch(label):
            return None, "invalid_format"
    name = ".".join(encoded)
    if len(name) > 253:
        return None, "too_long"
    return name, None


def canonical_zone(raw: Any, field: str = "name") -> str:
    name, problem = name_problem(raw, allow_underscore=False, allow_wildcard=False)
    if problem or name is None:
        raise DnsInputError(
            "invalid_zone_name", "Enter a zone name such as example.com", [
                _field(field, problem or "invalid_format")
            ],
        )
    return name


def zone_from_path(raw: str) -> str:
    return canonical_zone(raw, "zone")


def canonical_target(raw: Any, field: str, *, allow_root: bool = False) -> str:
    """An absolute host name used inside record data (no trailing dot; '.' = root)."""
    if allow_root and isinstance(raw, str) and raw.strip() == ".":
        return "."
    name, problem = name_problem(raw, allow_underscore=True, allow_wildcard=False)
    if problem or name is None:
        raise DnsInputError("dns_record_invalid", "Invalid host name", [
            _field(field, problem or "invalid_format")
        ])
    return name


def relative_name(raw: Any, zone: str) -> str:
    """Owner name relative to the zone: '@' (apex), '*', 'www', '_sip._tcp', ... ."""
    if raw is None or (isinstance(raw, str) and raw.strip() in {"", "@"}):
        return "@"
    if not isinstance(raw, str):
        raise DnsInputError("dns_record_invalid", "Invalid record name",
                            [_field("name", "invalid_type")])
    text = raw.strip().lower()
    if text.endswith("."):
        absolute, problem = name_problem(text, allow_underscore=True, allow_wildcard=True)
        if problem or absolute is None:
            raise DnsInputError("dns_record_invalid", "Invalid record name",
                                [_field("name", problem or "invalid_format")])
        if absolute == zone:
            return "@"
        if not absolute.endswith("." + zone):
            raise DnsInputError("dns_record_invalid", "The name is outside this zone",
                                [_field("name", "outside_zone", zone=zone)])
        return absolute[: -len(zone) - 1]
    name, problem = name_problem(text, allow_underscore=True, allow_wildcard=True)
    if problem or name is None:
        raise DnsInputError("dns_record_invalid", "Invalid record name",
                            [_field("name", problem or "invalid_format")])
    if len(name) + len(zone) + 1 > 253:
        raise DnsInputError("dns_record_invalid", "The full name is too long",
                            [_field("name", "too_long")])
    return name


def _int(value: Any, field: str, low: int, high: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise DnsInputError("dns_record_invalid", f"{field} must be {low}..{high}",
                            [_field(field, "out_of_range", min=low, max=high)])
    return value


def ttl_value(raw: Any, default: int, field: str = "ttl") -> int:
    if raw is None:
        return default
    return _int(raw, field, 0, TTL_MAX)


def _address(value: Any, field: str, version: int) -> str:
    try:
        parsed = ipaddress.ip_address(str(value).strip()) if isinstance(value, str) else None
    except ValueError:
        parsed = None
    if parsed is None or parsed.version != version:
        raise DnsInputError(
            "dns_record_invalid", f"Enter an IPv{version} address",
            [_field(field, "invalid_ipv4" if version == 4 else "invalid_ipv6")],
        )
    return str(parsed)


def record_data(rtype: str, data: Any) -> dict[str, Any]:
    if not isinstance(data, dict):
        raise DnsInputError("dns_record_invalid", "data must be an object",
                            [_field("data", "invalid_type")])
    allowed = RECORD_FIELDS[rtype]
    unknown = sorted(set(data) - set(allowed))
    if unknown:
        raise DnsInputError("dns_record_invalid", "Unknown data fields",
                            [_field(f"data.{name}", "unknown_field") for name in unknown[:10]])
    missing = [name for name in allowed if data.get(name) is None]
    if missing:
        raise DnsInputError("dns_record_invalid", "Missing data fields",
                            [_field(f"data.{name}", "required") for name in missing])
    if rtype in {"A", "AAAA"}:
        return {"address": _address(data["address"], "data.address", 4 if rtype == "A" else 6)}
    if rtype in {"CNAME", "PTR"}:
        return {"target": canonical_target(data["target"], "data.target")}
    if rtype == "NS":
        return {"nameserver": canonical_target(data["nameserver"], "data.nameserver")}
    if rtype == "MX":
        return {
            "preference": _int(data["preference"], "data.preference", 0, 65535),
            "exchange": canonical_target(data["exchange"], "data.exchange", allow_root=True),
        }
    if rtype == "TXT":
        text = data["text"]
        if not isinstance(text, str) or not text or len(text) > TXT_MAX:
            raise DnsInputError("dns_record_invalid", "TXT text is empty or too long",
                                [_field("data.text", "too_long" if text else "required",
                                        max=TXT_MAX)])
        if any(ord(ch) < 32 and ch != "\t" for ch in text):
            raise DnsInputError("dns_record_invalid", "TXT text has control characters",
                                [_field("data.text", "invalid_format")])
        return {"text": text}
    if rtype == "SRV":
        return {
            "priority": _int(data["priority"], "data.priority", 0, 65535),
            "weight": _int(data["weight"], "data.weight", 0, 65535),
            "port": _int(data["port"], "data.port", 0, 65535),
            "target": canonical_target(data["target"], "data.target", allow_root=True),
        }
    if rtype == "CAA":
        tag = data["tag"]
        value = data["value"]
        if not isinstance(tag, str) or not _CAA_TAG.fullmatch(tag.lower()):
            raise DnsInputError("dns_record_invalid", "CAA tag is invalid",
                                [_field("data.tag", "invalid_format")])
        if not isinstance(value, str) or len(value) > 1024 or any(
            ord(ch) < 32 for ch in value
        ):
            raise DnsInputError("dns_record_invalid", "CAA value is invalid",
                                [_field("data.value", "invalid_format")])
        return {"flags": _int(data["flags"], "data.flags", 0, 255), "tag": tag.lower(),
                "value": value}
    # SOA: serial is automatic (YYYYMMDDnn); only these fields may be edited.
    return {
        "mname": canonical_target(data["mname"], "data.mname"),
        "rname": canonical_target(data["rname"], "data.rname"),
        "refresh": _int(data["refresh"], "data.refresh", 1, 2**31 - 1),
        "retry": _int(data["retry"], "data.retry", 1, 2**31 - 1),
        "expire": _int(data["expire"], "data.expire", 1, 2**31 - 1),
        "minimum": _int(data["minimum"], "data.minimum", 0, 86400),
    }


def _comment(raw: Any) -> str:
    if raw is None:
        return ""
    if not isinstance(raw, str) or len(raw) > 255 or any(ord(ch) < 32 for ch in raw):
        raise DnsInputError("dns_record_invalid", "The comment is invalid",
                            [_field("comment", "invalid_format", max=255)])
    return raw


def record_body(payload: Any, zone: str, *, creating: bool) -> dict[str, Any]:
    """{name, type, ttl, data, disabled, comment} in canonical form."""
    if not isinstance(payload, dict):
        raise DnsInputError("dns_record_invalid", "The record must be an object",
                            [_field("body", "invalid_type")])
    unknown = sorted(set(payload) - {"name", "type", "ttl", "data", "disabled", "comment", "id",
                                     "view"})
    if unknown:
        raise DnsInputError("dns_record_invalid", "Unknown fields",
                            [_field(name, "unknown_field") for name in unknown[:10]])
    rtype = payload.get("type")
    if not isinstance(rtype, str) or rtype.upper() not in RECORD_TYPES:
        raise DnsInputError("dns_record_invalid", "Unknown record type",
                            [_field("type", "invalid_choice", choices=list(RECORD_TYPES))])
    rtype = rtype.upper()
    if rtype == "SOA" and creating:
        raise DnsInputError("dns_record_invalid", "The SOA record is created automatically",
                            [_field("type", "soa_managed")])
    name = relative_name(payload.get("name"), zone)
    if rtype == "SOA" and name != "@":
        raise DnsInputError("dns_record_invalid", "SOA belongs to the zone apex",
                            [_field("name", "soa_apex_only")])
    if rtype == "CNAME" and name == "@":
        raise DnsInputError("dns_record_invalid", "A CNAME cannot be at the zone apex",
                            [_field("name", "cname_at_apex")])
    disabled = payload.get("disabled", False)
    if not isinstance(disabled, bool):
        raise DnsInputError("dns_record_invalid", "disabled must be true or false",
                            [_field("disabled", "invalid_type")])
    body = {
        "name": name,
        "type": rtype,
        "ttl": ttl_value(payload.get("ttl"), 3600),
        "data": record_data(rtype, payload.get("data")),
        "disabled": disabled,
        "comment": _comment(payload.get("comment")),
    }
    if "view" in payload:
        # Split horizon (docs/41 §3.3): a client-group id, "" = everyone.
        from .dns_validate_d5 import record_view

        body["view"] = record_view(payload.get("view"))
    return body


def override_body(payload: Any) -> dict[str, Any]:
    """{name, type, value, ttl, disabled} (source is set by the panel, never the client)."""
    if not isinstance(payload, dict):
        raise DnsInputError("dns_record_invalid", "The override must be an object",
                            [_field("body", "invalid_type")])
    unknown = sorted(set(payload) - {"name", "type", "value", "ttl", "disabled", "id", "source"})
    if unknown:
        raise DnsInputError("dns_record_invalid", "Unknown fields",
                            [_field(name, "unknown_field") for name in unknown[:10]])
    name, problem = name_problem(payload.get("name"), allow_underscore=True, allow_wildcard=True)
    if problem or name is None:
        raise DnsInputError("dns_record_invalid", "Enter a name such as app.example.com",
                            [_field("name", problem or "invalid_format")])
    rtype = payload.get("type", "A")
    if not isinstance(rtype, str) or rtype.upper() not in OVERRIDE_TYPES:
        raise DnsInputError("dns_record_invalid", "Override type must be A, AAAA or CNAME",
                            [_field("type", "invalid_choice", choices=list(OVERRIDE_TYPES))])
    rtype = rtype.upper()
    raw_value = payload.get("value")
    if rtype in {"A", "AAAA"}:
        try:
            value = _address(raw_value, "value", 4 if rtype == "A" else 6)
        except DnsInputError:
            raise DnsInputError("dns_record_invalid", "Enter an IP address", [
                _field("value", "invalid_ipv4" if rtype == "A" else "invalid_ipv6")
            ]) from None
    else:
        value = canonical_target(raw_value, "value")
        if value == name:
            raise DnsInputError("dns_record_invalid", "A name cannot point to itself",
                                [_field("value", "self_reference")])
    disabled = payload.get("disabled", False)
    if not isinstance(disabled, bool):
        raise DnsInputError("dns_record_invalid", "disabled must be true or false",
                            [_field("disabled", "invalid_type")])
    return {"name": name, "type": rtype, "value": value,
            "ttl": ttl_value(payload.get("ttl"), 300), "disabled": disabled}


def _forwarder(value: Any, field: str) -> str:
    try:
        return upstream_address(value)
    except ValueError:
        raise DnsInputError("dns_record_invalid", "Invalid forwarder address",
                            [_field(field, "invalid_upstream")]) from None


def zone_create_body(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise DnsInputError("invalid_zone_name", "The zone must be an object",
                            [_field("body", "invalid_type")])
    from .dns_validate_d5 import SECONDARY_KEYS, secondary_fields

    unknown = sorted(set(payload) - {"name", "type", "forwarders", *SECONDARY_KEYS})
    if unknown:
        raise DnsInputError("dns_record_invalid", "Unknown fields",
                            [_field(name, "unknown_field") for name in unknown[:10]])
    name = canonical_zone(payload.get("name"))
    ztype = payload.get("type", "primary")
    if ztype not in ZONE_TYPES:
        raise DnsInputError("dns_record_invalid", "Unknown zone type",
                            [_field("type", "invalid_choice", choices=list(ZONE_TYPES))])
    body: dict[str, Any] = {"name": name, "type": ztype}
    if ztype == "secondary":
        errors: list[dict[str, Any]] = []
        if payload.get("forwarders") is not None:
            errors.append(_field("forwarders", "not_allowed"))
        body.update(secondary_fields(payload, errors, creating=True))
        if errors:
            raise DnsInputError("dns_zone_invalid", "The secondary zone is invalid", errors)
        return body
    misplaced = [key for key in SECONDARY_KEYS if payload.get(key) is not None]
    if misplaced:
        raise DnsInputError("dns_zone_invalid", "Only secondary zones have primaries",
                            [_field(key, "not_allowed") for key in misplaced])
    forwarders = forwarder_list(payload.get("forwarders"), required=ztype == "forwarder")
    if forwarders is not None:
        body["forwarders"] = forwarders
    return body


def forwarder_list(raw: Any, *, required: bool) -> list[str] | None:
    if raw is None:
        if required:
            raise DnsInputError("dns_record_invalid", "A forwarder zone needs forwarders",
                                [_field("forwarders", "required")])
        return None
    if not isinstance(raw, list) or len(raw) > MAX_FORWARDERS:
        raise DnsInputError("dns_record_invalid", "forwarders must be a list",
                            [_field("forwarders", "invalid_type", max=MAX_FORWARDERS)])
    if required and not raw:
        raise DnsInputError("dns_record_invalid", "A forwarder zone needs forwarders",
                            [_field("forwarders", "required")])
    return [_forwarder(item, f"forwarders.{index}") for index, item in enumerate(raw)]


def zone_patch_body(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict) or not payload:
        raise DnsInputError("dns_record_invalid", "Nothing to change",
                            [_field("body", "required")])
    from .dns_validate_d5 import SECONDARY_KEYS, ZONE_SECTIONS, secondary_fields, zone_sections

    unknown = sorted(set(payload) - {"disabled", "forwarders", *SECONDARY_KEYS, *ZONE_SECTIONS})
    if unknown:
        raise DnsInputError("dns_record_invalid", "Unknown fields",
                            [_field(name, "unknown_field") for name in unknown[:10]])
    body: dict[str, Any] = {}
    # docs/41 §2: secondary sources and the transfer/notify/update/dnssec/views sections.
    errors: list[dict[str, Any]] = []
    body.update(secondary_fields(payload, errors, creating=False))
    body.update(zone_sections(payload, errors))
    if errors:
        raise DnsInputError("dns_zone_invalid", "Some zone settings are invalid", errors[:50])
    if "disabled" in payload:
        if not isinstance(payload["disabled"], bool):
            raise DnsInputError("dns_record_invalid", "disabled must be true or false",
                                [_field("disabled", "invalid_type")])
        body["disabled"] = payload["disabled"]
    if "forwarders" in payload:
        body["forwarders"] = forwarder_list(payload["forwarders"], required=False)
    return body


def entity_id(raw: str, field: str = "id") -> str:
    if not _ID.fullmatch(raw or ""):
        raise DnsInputError("dns_record_invalid", "Invalid id", [_field(field, "invalid_format")])
    return raw


# ----------------------------------------------------------------------------- settings


def _host_port(value: Any, default_port: int) -> tuple[str, int]:
    if not isinstance(value, str) or not value or len(value) > 300:
        raise ValueError("invalid")
    text = value.strip()
    if text.startswith("["):
        host, _, rest = text[1:].partition("]")
        port_text = rest[1:] if rest.startswith(":") else ""
        if rest and not rest.startswith(":"):
            raise ValueError("invalid")
    elif text.count(":") == 1:
        host, port_text = text.split(":")
    elif text.count(":") > 1:
        host, port_text = text, ""
    else:
        host, port_text = text, ""
    port = int(port_text) if port_text else default_port
    if not 1 <= port <= 65535:
        raise ValueError("invalid")
    return host, port


def listen_address(value: Any) -> str:
    host, port = _host_port(value, 53)
    address = ipaddress.ip_address(host)
    return f"[{address}]:{port}" if address.version == 6 else f"{address}:{port}"


def upstream_address(value: Any) -> str:
    """``ip[:port]``, ``tls://ip[:port][#sni]``, ``quic://host[:port][#sni]`` (D4, DoQ) or
    ``https://host/path`` (no credentials)."""
    if not isinstance(value, str) or not value.strip() or len(value) > 512:
        raise ValueError("invalid")
    text = value.strip()
    if any(ch.isspace() for ch in text):
        raise ValueError("invalid")
    if text.startswith("https://"):
        parts = urlsplit(text)
        if not parts.hostname or parts.username or parts.password or parts.fragment:
            raise ValueError("invalid")
        return text
    if text.startswith("tls://"):
        rest = text[len("tls://"):]
        address, _, sni = rest.partition("#")
        host, _port = _host_port(address, 853)
        ipaddress.ip_address(host)
        if sni:
            name, problem = name_problem(sni, allow_underscore=False, allow_wildcard=False)
            if problem:
                raise ValueError("invalid")
        return text
    if text.startswith("quic://"):
        rest = text[len("quic://"):]
        address, _, sni = rest.partition("#")
        host, _port = _host_port(address, 853)
        if not _is_ip(host):
            name, problem = name_problem(host, allow_underscore=False, allow_wildcard=False)
            if problem:
                raise ValueError("invalid")
        if sni:
            name, problem = name_problem(sni, allow_underscore=False, allow_wildcard=False)
            if problem:
                raise ValueError("invalid")
        return text
    host, _port = _host_port(text, 53)
    ipaddress.ip_address(host)
    return text


def _cidrs(value: Any, field: str, errors: list[dict[str, Any]]) -> None:
    if not isinstance(value, list) or len(value) > 256:
        errors.append(_field(field, "invalid_type"))
        return
    for index, item in enumerate(value):
        try:
            network = ipaddress.ip_network(str(item), strict=False)
        except ValueError:
            errors.append(_field(f"{field}.{index}", "invalid_cidr"))
            continue
        if network.prefixlen == 0:
            errors.append(_field(f"{field}.{index}", "open_resolver"))


def _bounded(
    payload: dict[str, Any], field: str, key: str, low: int, high: int,
    errors: list[dict[str, Any]],
) -> None:
    if key not in payload:
        return
    value = payload[key]
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        errors.append(_field(f"{field}.{key}", "out_of_range", min=low, max=high))


LIMIT_RANGES: dict[str, tuple[int, int]] = {
    "client_qps": (0, 1_000_000),
    "client_burst": (0, 2_000_000),
    "rrl_responses_per_second": (0, 100_000),
    "rrl_slip": (0, 10),
    "rrl_ipv4_prefix": (8, 32),
    "rrl_ipv6_prefix": (16, 128),
    "max_tcp_connections": (1, 100_000),
    "tcp_idle_timeout_ms": (100, 600_000),
    "udp_max_size": (512, 4096),
    "max_inflight_upstream": (1, 1_000_000),
}
CACHE_RANGES: dict[str, tuple[int, int]] = {
    "max_bytes": (0, 8 * 1024 * 1024 * 1024),
    "min_ttl": (0, 86400),
    "max_ttl": (0, TTL_MAX),
    "negative_max_ttl": (0, 86400),
    "stale_ttl": (0, TTL_MAX),
}


def engine_settings(payload: Any) -> dict[str, Any]:
    """Check the parts that matter for safety and shape; the engine checks the rest."""
    if not isinstance(payload, dict):
        raise DnsInputError("dns_settings_invalid", "Settings must be an object",
                            [_field("body", "invalid_type")])
    # ``warnings`` is panel advice added to GET/PUT answers (docs/40 §5), not a setting.
    if "warnings" in payload:
        payload = {key: value for key, value in payload.items() if key != "warnings"}
    errors: list[dict[str, Any]] = []
    version = payload.get("config_version")
    if version is None or isinstance(version, bool) or not isinstance(version, int | str):
        errors.append(_field("config_version", "required"))
    listen = payload.get("listen")
    if listen is not None:
        if not isinstance(listen, list) or not listen or len(listen) > 32:
            errors.append(_field("listen", "invalid_type"))
        else:
            for index, item in enumerate(listen):
                try:
                    if not isinstance(item, dict):
                        raise ValueError("invalid")
                    listen_address(item.get("address"))
                except ValueError:
                    errors.append(_field(f"listen.{index}.address", "invalid_address"))
                    continue
                for flag in ("udp", "tcp"):
                    if flag in item and not isinstance(item[flag], bool):
                        errors.append(_field(f"listen.{index}.{flag}", "invalid_type"))
    recursion = payload.get("recursion")
    if recursion is not None:
        if not isinstance(recursion, dict):
            errors.append(_field("recursion", "invalid_type"))
        else:
            if "enabled" in recursion and not isinstance(recursion["enabled"], bool):
                errors.append(_field("recursion.enabled", "invalid_type"))
            if "allow" in recursion:
                _cidrs(recursion["allow"], "recursion.allow", errors)
    if "query_allow" in payload:
        _cidrs(payload["query_allow"], "query_allow", errors)
    upstreams = payload.get("upstreams")
    if upstreams is not None:
        if not isinstance(upstreams, list) or len(upstreams) > 32:
            errors.append(_field("upstreams", "invalid_type"))
        else:
            seen: set[str] = set()
            for index, item in enumerate(upstreams):
                if not isinstance(item, dict):
                    errors.append(_field(f"upstreams.{index}", "invalid_type"))
                    continue
                try:
                    upstream_address(item.get("address"))
                except ValueError:
                    errors.append(_field(f"upstreams.{index}.address", "invalid_upstream"))
                identifier = item.get("id")
                if identifier is not None:
                    if not isinstance(identifier, str) or not _ID.fullmatch(identifier):
                        errors.append(_field(f"upstreams.{index}.id", "invalid_format"))
                    elif identifier in seen:
                        errors.append(_field(f"upstreams.{index}.id", "duplicate"))
                    else:
                        seen.add(identifier)
                if "enabled" in item and not isinstance(item["enabled"], bool):
                    errors.append(_field(f"upstreams.{index}.enabled", "invalid_type"))
    strategy = payload.get("upstream_strategy")
    if strategy is not None and strategy not in STRATEGIES:
        errors.append(_field("upstream_strategy", "invalid_choice", choices=list(STRATEGIES)))
    cache = payload.get("cache")
    if cache is not None:
        if not isinstance(cache, dict):
            errors.append(_field("cache", "invalid_type"))
        else:
            for key, (low, high) in CACHE_RANGES.items():
                _bounded(cache, "cache", key, low, high, errors)
            for flag in ("serve_stale", "prefetch"):
                if flag in cache and not isinstance(cache[flag], bool):
                    errors.append(_field(f"cache.{flag}", "invalid_type"))
            if isinstance(cache.get("min_ttl"), int) and isinstance(cache.get("max_ttl"), int) \
                    and cache["min_ttl"] > cache["max_ttl"]:
                errors.append(_field("cache.min_ttl", "greater_than_max"))
    limits = payload.get("limits")
    if limits is not None:
        if not isinstance(limits, dict):
            errors.append(_field("limits", "invalid_type"))
        else:
            for key, (low, high) in LIMIT_RANGES.items():
                _bounded(limits, "limits", key, low, high, errors)
    for flag in ("minimal_any", "refuse_any", "rebinding_protection"):
        if flag in payload and not isinstance(payload[flag], bool):
            errors.append(_field(flag, "invalid_type"))
    overrides = payload.get("overrides")
    if overrides is not None and (
        not isinstance(overrides, dict)
        or ("enabled" in overrides and not isinstance(overrides["enabled"], bool))
    ):
        errors.append(_field("overrides.enabled", "invalid_type"))
    errors.extend(d2_settings_errors(payload))
    from .dns_validate_d4 import d4_settings_errors

    errors.extend(d4_settings_errors(payload))
    from .dns_validate_d5 import d5_settings_errors

    errors.extend(d5_settings_errors(payload))
    if errors:
        raise DnsInputError("dns_settings_invalid", "Some DNS settings are invalid", errors[:50])
    return payload


def resolve_body(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise DnsInputError("dns_record_invalid", "The query must be an object",
                            [_field("body", "invalid_type")])
    name, problem = name_problem(payload.get("name"), allow_underscore=True,
                                 allow_wildcard=False)
    if problem or name is None:
        raise DnsInputError("dns_record_invalid", "Enter a name to look up",
                            [_field("name", problem or "invalid_format")])
    qtype = payload.get("type", "A")
    allowed = (*RECORD_TYPES, "ANY")
    if not isinstance(qtype, str) or qtype.upper() not in allowed:
        raise DnsInputError("dns_record_invalid", "Unknown query type",
                            [_field("type", "invalid_choice", choices=list(allowed))])
    body: dict[str, Any] = {"name": name, "type": qtype.upper()}
    client_ip = payload.get("client_ip")
    if client_ip not in (None, ""):
        try:
            body["client_ip"] = str(ipaddress.ip_address(str(client_ip).strip()))
        except ValueError:
            raise DnsInputError("dns_record_invalid", "client_ip must be an IP address",
                                [_field("client_ip", "invalid_ip")]) from None
    return body


# ----------------------------------------------------------------------------- D2 settings
# docs/38 §2: querylog / stats / pressure sections of the engine settings object.

QUERYLOG_MODES = ("all", "sample", "errors_only", "off")
CLIENT_IP_MODES = ("full", "mask", "hash", "none")
ATTACK_MODES = ("off", "suggest", "auto")
PRESSURE_LEVELS = ("warning", "critical", "emergency")
PRESSURE_METRICS = ("cpu", "memory", "qps_percent", "host_cpu", "host_memory")
PRESSURE_ACTIONS = ("log_sampling", "disable_prefetch", "prefer_stale", "tighten_client_qps",
                    "refuse_heavy_clients", "minimal_any")
MAX_EXCLUDES = 1000
QUERYLOG_RANGES: dict[str, tuple[int, int]] = {
    "sample_percent": (1, 100),
    "max_age_days": (1, 365),
    "max_bytes": (64 * 1024 * 1024, 1024 * 1024 * 1024 * 1024),
    "min_free_disk_percent": (1, 50),
    "stream_max_eps": (1, 10_000),
}
STATS_RANGES: dict[str, tuple[int, int]] = {
    "minute_retention_hours": (1, 168),
    "hour_retention_days": (1, 365),
    "day_retention_days": (1, 3650),
    "top_k": (10, 1000),
}
PRESSURE_RANGES: dict[str, tuple[int, int]] = {
    "capacity_qps": (100, 10_000_000),
    "dwell_seconds": (5, 3600),
    "exit_margin_percent": (0, 50),
}
THRESHOLD_RANGES: dict[str, tuple[int, int]] = {
    "cpu": (1, 100), "memory": (1, 100), "qps_percent": (1, 1000),
    "host_cpu": (1, 100), "host_memory": (1, 100),
}
ATTACK_RANGES: dict[str, tuple[int, int]] = {
    "nxdomain_unique_per_minute": (10, 1_000_000),
    "mitigation_minutes": (1, 10080),
}


def _number(
    payload: dict[str, Any], field: str, key: str, low: int, high: int,
    errors: list[dict[str, Any]],
) -> None:
    """Like ``_bounded`` but integral floats (70.0) are fine too."""
    if key not in payload:
        return
    value = payload[key]
    ok = isinstance(value, int | float) and not isinstance(value, bool) and low <= value <= high
    if not ok:
        errors.append(_field(f"{field}.{key}", "out_of_range", min=low, max=high))


def _unknown(section: dict[str, Any], field: str, allowed: set[str],
             errors: list[dict[str, Any]]) -> None:
    for key in sorted(set(section) - allowed)[:10]:
        errors.append(_field(f"{field}.{key}", "unknown_field"))


def _section(payload: dict[str, Any], key: str,
             errors: list[dict[str, Any]]) -> dict[str, Any] | None:
    if key not in payload:
        return None
    value = payload[key]
    if not isinstance(value, dict):
        errors.append(_field(key, "invalid_type"))
        return None
    return value


def _flag(section: dict[str, Any], field: str, key: str, errors: list[dict[str, Any]]) -> None:
    if key in section and not isinstance(section[key], bool):
        errors.append(_field(f"{field}.{key}", "invalid_type"))


def _querylog(payload: dict[str, Any], errors: list[dict[str, Any]]) -> None:
    section = _section(payload, "querylog", errors)
    if section is None:
        return
    _flag(section, "querylog", "enabled", errors)
    if "mode" in section and section["mode"] not in QUERYLOG_MODES:
        errors.append(_field("querylog.mode", "invalid_choice", choices=list(QUERYLOG_MODES)))
    if "client_ip" in section and section["client_ip"] not in CLIENT_IP_MODES:
        errors.append(_field("querylog.client_ip", "invalid_choice",
                             choices=list(CLIENT_IP_MODES)))
    for key, (low, high) in QUERYLOG_RANGES.items():
        _bounded(section, "querylog", key, low, high, errors)
    if "exclude_names" in section:
        names = section["exclude_names"]
        if not isinstance(names, list) or len(names) > MAX_EXCLUDES:
            errors.append(_field("querylog.exclude_names", "invalid_type", max=MAX_EXCLUDES))
        else:
            for index, item in enumerate(names):
                text = item[2:] if isinstance(item, str) and item.startswith("*.") else item
                _name, problem = name_problem(text, allow_underscore=True, allow_wildcard=False)
                if problem:
                    errors.append(_field(f"querylog.exclude_names.{index}", problem))
    if "exclude_clients" in section:
        clients = section["exclude_clients"]
        if not isinstance(clients, list) or len(clients) > MAX_EXCLUDES:
            errors.append(_field("querylog.exclude_clients", "invalid_type", max=MAX_EXCLUDES))
        else:
            for index, item in enumerate(clients):
                try:
                    if not isinstance(item, str):
                        raise ValueError("invalid")
                    ipaddress.ip_network(item.strip(), strict=False)
                except ValueError:
                    errors.append(_field(f"querylog.exclude_clients.{index}", "invalid_cidr"))


def _stats(payload: dict[str, Any], errors: list[dict[str, Any]]) -> None:
    section = _section(payload, "stats", errors)
    if section is None:
        return
    for key, (low, high) in STATS_RANGES.items():
        _bounded(section, "stats", key, low, high, errors)


def _thresholds(thresholds: Any, errors: list[dict[str, Any]]) -> None:
    if not isinstance(thresholds, dict):
        errors.append(_field("pressure.thresholds", "invalid_type"))
        return
    _unknown(thresholds, "pressure.thresholds", set(PRESSURE_LEVELS), errors)
    for level in PRESSURE_LEVELS:
        values = thresholds.get(level)
        if values is None:
            continue
        field = f"pressure.thresholds.{level}"
        if not isinstance(values, dict):
            errors.append(_field(field, "invalid_type"))
            continue
        _unknown(values, field, set(THRESHOLD_RANGES), errors)
        for metric, (low, high) in THRESHOLD_RANGES.items():
            _number(values, field, metric, low, high, errors)
    # warning <= critical <= emergency for every metric given at more than one level.
    for metric in PRESSURE_METRICS:
        previous: tuple[str, float] | None = None
        for level in PRESSURE_LEVELS:
            values = thresholds.get(level)
            value = values.get(metric) if isinstance(values, dict) else None
            if not isinstance(value, int | float) or isinstance(value, bool):
                continue
            if previous is not None and value < previous[1]:
                errors.append(_field(f"pressure.thresholds.{level}.{metric}",
                                     "below_lower_level", level=previous[0]))
            previous = (level, value)


def _pressure(payload: dict[str, Any], errors: list[dict[str, Any]]) -> None:
    section = _section(payload, "pressure", errors)
    if section is None:
        return
    _flag(section, "pressure", "enabled", errors)
    for key, (low, high) in PRESSURE_RANGES.items():
        _bounded(section, "pressure", key, low, high, errors)
    if section.get("thresholds") is not None:
        _thresholds(section["thresholds"], errors)
    actions = section.get("actions")
    if actions is not None:
        if not isinstance(actions, dict):
            errors.append(_field("pressure.actions", "invalid_type"))
        else:
            for key in PRESSURE_ACTIONS:
                _flag(actions, "pressure.actions", key, errors)
    attack = section.get("attack_detection")
    if attack is not None:
        if not isinstance(attack, dict):
            errors.append(_field("pressure.attack_detection", "invalid_type"))
        else:
            if "mode" in attack and attack["mode"] not in ATTACK_MODES:
                errors.append(_field("pressure.attack_detection.mode", "invalid_choice",
                                     choices=list(ATTACK_MODES)))
            for key, (low, high) in ATTACK_RANGES.items():
                _bounded(attack, "pressure.attack_detection", key, low, high, errors)


def d2_settings_errors(payload: dict[str, Any]) -> list[dict[str, Any]]:
    """Field errors for the querylog / stats / pressure sections (docs/38 §2)."""
    errors: list[dict[str, Any]] = []
    _querylog(payload, errors)
    _stats(payload, errors)
    _pressure(payload, errors)
    return errors
