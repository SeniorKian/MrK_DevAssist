"""Panel-side checks for the final DNS phase (docs/41 §2–§4, §6).

* zone bodies: ``secondary`` zones (``primaries``, ``tsig_key``, ``notify_allow``) and
  the per-zone sections ``transfer``, ``notify``, ``update``, ``dnssec`` and ``views``
  that ``PATCH zones/{zone}`` forwards;
* TSIG key bodies (the secret is checked for shape only and never logged);
* the ``filtering`` and ``client_groups`` sections of the engine settings;
* ``filtering/check``.

Errors are ``DnsInputError`` with dotted ``fields`` like the D1/D2/D4 validators.
The engine checks everything again; these give precise fields early and refuse
the clearly dangerous (zone transfer or dynamic update open to ``/0``).
"""

from __future__ import annotations

import base64
import binascii
import ipaddress
import re
from typing import Any
from urllib.parse import urlsplit

from .dns_validate import DnsInputError, name_problem

TSIG_ALGORITHMS = ("hmac-sha256", "hmac-sha512")
DNSSEC_ALGORITHMS = ("ECDSAP256SHA256", "ED25519")
DENIAL_MODES = ("nsec", "nsec3")
ROLLOVER_ROLES = ("zsk", "ksk")
FILTER_FORMATS = ("hosts", "domains", "adblock", "rpz")
FILTER_ACTIONS = ("nxdomain", "null_ip", "refuse")
GROUP_FILTERING = ("inherit", "on", "off")
MAX_PRIMARIES = 8  # engine limits (docs/41 §0.1)
MAX_NOTIFY_TARGETS = 16
MAX_CIDRS = 64
MAX_FILTER_LISTS = 64
MAX_FILTER_NAMES = 10_000
MAX_GROUPS = 64
MAX_VIEWS = 32
MAX_BLOCKED_SERVICES = 100
TSIG_SECRET_BYTES = (16, 128)
ZONE_SECTIONS = ("transfer", "notify", "update", "dnssec", "views")
SECONDARY_KEYS = ("primaries", "tsig_key", "notify_allow")

_ID = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
_VIEW = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")  # engine view ids (docs/41 §0.2)
_HEX = re.compile(r"^(?:[0-9a-fA-F]{2}){0,127}$")


def _field(field: str, reason: str, **params: Any) -> dict[str, Any]:
    item: dict[str, Any] = {"field": field, "reason_code": reason}
    if params:
        item["params"] = params
    return item


def _unknown(section: dict[str, Any], field: str, allowed: set[str] | tuple[str, ...],
             errors: list[dict[str, Any]]) -> None:
    for key in sorted(set(section) - set(allowed))[:10]:
        errors.append(_field(f"{field}.{key}" if field else key, "unknown_field"))


def _flag(section: dict[str, Any], field: str, key: str, errors: list[dict[str, Any]]) -> None:
    if key in section and not isinstance(section[key], bool):
        errors.append(_field(f"{field}.{key}", "invalid_type"))


def _int(section: dict[str, Any], field: str, key: str, low: int, high: int,
         errors: list[dict[str, Any]]) -> None:
    if key not in section:
        return
    value = section[key]
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        errors.append(_field(f"{field}.{key}", "out_of_range", min=low, max=high))


def _choice(section: dict[str, Any], field: str, key: str, choices: tuple[str, ...],
            errors: list[dict[str, Any]]) -> None:
    if key in section and section[key] not in choices:
        errors.append(_field(f"{field}.{key}", "invalid_choice", choices=list(choices)))


def _object(value: Any, field: str, errors: list[dict[str, Any]]) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        errors.append(_field(field, "invalid_type"))
        return None
    return value


def cidr_list(value: Any, field: str, errors: list[dict[str, Any]], *,
              allow_all: bool = False, limit: int = MAX_CIDRS) -> list[str] | None:
    """Canonical networks; ``/0`` is ``too_broad`` unless ``allow_all``."""
    if not isinstance(value, list) or len(value) > limit:
        errors.append(_field(field, "invalid_type", max=limit))
        return None
    out: list[str] = []
    for index, item in enumerate(value):
        try:
            if not isinstance(item, str):
                raise ValueError("invalid")
            network = ipaddress.ip_network(item.strip(), strict=False)
        except ValueError:
            errors.append(_field(f"{field}.{index}", "invalid_cidr"))
            continue
        if network.prefixlen == 0 and not allow_all:
            errors.append(_field(f"{field}.{index}", "too_broad"))
            continue
        out.append(str(network))
    return out


def ip_port(value: Any, default_port: int = 53) -> str:
    """``ip`` or ``ip:port`` / ``[v6]:port`` → canonical ``ip:port`` (IP literals only)."""
    if not isinstance(value, str) or not value.strip() or len(value) > 64:
        raise ValueError("invalid")
    text = value.strip()
    port_text = ""
    if text.startswith("["):
        host, _, rest = text[1:].partition("]")
        if rest:
            if not rest.startswith(":"):
                raise ValueError("invalid")
            port_text = rest[1:]
    elif text.count(":") == 1:
        host, port_text = text.split(":")
    else:
        host = text
    address = ipaddress.ip_address(host)
    if address.is_unspecified or address.is_multicast:
        raise ValueError("invalid")
    if port_text and not port_text.isdigit():
        raise ValueError("invalid")
    port = int(port_text) if port_text else default_port
    if not 1 <= port <= 65535:
        raise ValueError("invalid")
    return f"[{address}]:{port}" if address.version == 6 else f"{address}:{port}"


def _ip_ports(value: Any, field: str, limit: int, errors: list[dict[str, Any]], *,
              required: bool) -> list[str] | None:
    if not isinstance(value, list) or len(value) > limit:
        errors.append(_field(field, "invalid_type", max=limit))
        return None
    if required and not value:
        errors.append(_field(field, "required"))
        return None
    out: list[str] = []
    for index, item in enumerate(value):
        try:
            canonical = ip_port(item)
        except ValueError:
            errors.append(_field(f"{field}.{index}", "invalid_address"))
            continue
        if canonical in out:
            errors.append(_field(f"{field}.{index}", "duplicate"))
            continue
        out.append(canonical)
    return out


def key_name(value: Any) -> str | None:
    """A TSIG key name (a DNS name, lowercase, no trailing dot) or None."""
    name, problem = name_problem(value, allow_underscore=True, allow_wildcard=False)
    return None if problem else name


def _key_ref(section: dict[str, Any], field: str, key: str,
             errors: list[dict[str, Any]]) -> None:
    """Optional reference to a TSIG key; ``null``/``""`` clears it."""
    if key not in section or section[key] in (None, ""):
        if key in section:
            section[key] = None
        return
    name = key_name(section[key])
    if name is None:
        errors.append(_field(f"{field}.{key}" if field else key, "invalid_key_name"))
    else:
        section[key] = name


# ----------------------------------------------------------------------------- zones


def secondary_fields(payload: dict[str, Any], errors: list[dict[str, Any]], *,
                     creating: bool) -> dict[str, Any]:
    out: dict[str, Any] = {}
    if creating and payload.get("primaries") is None:
        errors.append(_field("primaries", "required"))
    elif "primaries" in payload:
        primaries = _ip_ports(payload.get("primaries"), "primaries", MAX_PRIMARIES, errors,
                              required=True)
        if primaries is not None:
            out["primaries"] = primaries
    if "tsig_key" in payload:
        holder = {"tsig_key": payload["tsig_key"]}
        _key_ref(holder, "", "tsig_key", errors)
        out["tsig_key"] = holder["tsig_key"]
    if "notify_allow" in payload and payload["notify_allow"] is not None:
        allowed = cidr_list(payload["notify_allow"], "notify_allow", errors)
        if allowed is not None:
            out["notify_allow"] = allowed
    return out


def _transfer(value: Any, errors: list[dict[str, Any]]) -> dict[str, Any] | None:
    section = _object(value, "transfer", errors)
    if section is None:
        return None
    section = dict(section)
    _unknown(section, "transfer", ("allow", "tsig_key"), errors)
    if "allow" in section:
        # A zone transfer hands out every record: never to the whole internet.
        allowed = cidr_list(section["allow"], "transfer.allow", errors)
        if allowed is not None:
            section["allow"] = allowed
    _key_ref(section, "transfer", "tsig_key", errors)
    return section


def _notify(value: Any, errors: list[dict[str, Any]]) -> dict[str, Any] | None:
    section = _object(value, "notify", errors)
    if section is None:
        return None
    section = dict(section)
    _unknown(section, "notify", ("targets", "enabled", "tsig_key"), errors)
    _flag(section, "notify", "enabled", errors)
    _key_ref(section, "notify", "tsig_key", errors)
    if "targets" in section:
        targets = _ip_ports(section["targets"], "notify.targets", MAX_NOTIFY_TARGETS, errors,
                            required=False)
        if targets is not None:
            section["targets"] = targets
            if section.get("enabled") is True and not targets:
                errors.append(_field("notify.targets", "required"))
    return section


def _update(value: Any, errors: list[dict[str, Any]]) -> dict[str, Any] | None:
    section = _object(value, "update", errors)
    if section is None:
        return None
    section = dict(section)
    _unknown(section, "update", ("enabled", "allow", "tsig_key", "require_tsig"), errors)
    _flag(section, "update", "enabled", errors)
    _flag(section, "update", "require_tsig", errors)
    if "allow" in section:
        allowed = cidr_list(section["allow"], "update.allow", errors)
        if allowed is not None:
            section["allow"] = allowed
    _key_ref(section, "update", "tsig_key", errors)
    if section.get("require_tsig") is True and section.get("enabled") is True and \
            "tsig_key" in section and section["tsig_key"] is None:
        errors.append(_field("update.tsig_key", "required"))
    if section.get("require_tsig") is False and section.get("allow") == []:
        # Without TSIG and without an address list anyone could change the zone.
        errors.append(_field("update.allow", "open_update"))
    return section


def _dnssec(value: Any, errors: list[dict[str, Any]]) -> dict[str, Any] | None:
    section = _object(value, "dnssec", errors)
    if section is None:
        return None
    section = dict(section)
    _unknown(section, "dnssec", ("enabled", "algorithm", "denial", "nsec3",
                                 "signature_validity_days", "refresh_days"), errors)
    _flag(section, "dnssec", "enabled", errors)
    _choice(section, "dnssec", "algorithm", DNSSEC_ALGORITHMS, errors)
    _choice(section, "dnssec", "denial", DENIAL_MODES, errors)
    _int(section, "dnssec", "signature_validity_days", 2, 365, errors)
    _int(section, "dnssec", "refresh_days", 1, 364, errors)
    validity, refresh = section.get("signature_validity_days"), section.get("refresh_days")
    if isinstance(validity, int) and isinstance(refresh, int) and not isinstance(
        validity, bool
    ) and not isinstance(refresh, bool) and refresh >= validity:
        errors.append(_field("dnssec.refresh_days", "not_below_validity", max=validity - 1))
    if "nsec3" in section:
        nsec3 = _object(section["nsec3"], "dnssec.nsec3", errors)
        if nsec3 is not None:
            _unknown(nsec3, "dnssec.nsec3", ("iterations", "salt", "opt_out"), errors)
            # RFC 9276: 0 extra iterations; the engine caps validators at 150.
            _int(nsec3, "dnssec.nsec3", "iterations", 0, 100, errors)
            _flag(nsec3, "dnssec.nsec3", "opt_out", errors)
            salt = nsec3.get("salt")
            if "salt" in nsec3 and (not isinstance(salt, str) or not _HEX.fullmatch(salt)):
                errors.append(_field("dnssec.nsec3.salt", "invalid_format"))
    return section


def _views(value: Any, errors: list[dict[str, Any]]) -> list[dict[str, Any]] | None:
    if not isinstance(value, list) or len(value) > MAX_VIEWS:
        errors.append(_field("views", "invalid_type", max=MAX_VIEWS))
        return None
    seen: set[str] = set()
    out: list[dict[str, Any]] = []
    for index, item in enumerate(value):
        field = f"views.{index}"
        if not isinstance(item, dict):
            errors.append(_field(field, "invalid_type"))
            continue
        _unknown(item, field, ("group_id", "records_override"), errors)
        group = item.get("group_id")
        if not isinstance(group, str) or not _VIEW.fullmatch(group):
            errors.append(_field(f"{field}.group_id", "required" if group in (None, "")
                                 else "invalid_format"))
            continue
        if group in seen:
            errors.append(_field(f"{field}.group_id", "duplicate"))
            continue
        seen.add(group)
        _flag(item, field, "records_override", errors)
        out.append(dict(item))
    return out


ZONE_SECTION_CHECKS = {"transfer": _transfer, "notify": _notify, "update": _update,
                       "dnssec": _dnssec, "views": _views}


def zone_sections(payload: dict[str, Any], errors: list[dict[str, Any]]) -> dict[str, Any]:
    """The docs/41 per-zone sections of a PATCH body, checked and canonical."""
    out: dict[str, Any] = {}
    for key, check in ZONE_SECTION_CHECKS.items():
        if key in payload:
            value = check(payload[key], errors)
            if value is not None:
                out[key] = value
    return out


def record_view(value: Any) -> str | None:
    """The optional ``view`` of a record: a client-group id, or "" for everyone."""
    if value in (None, ""):
        return ""
    if not isinstance(value, str) or not _VIEW.fullmatch(value):
        raise DnsInputError("dns_record_invalid", "Invalid view",
                            [_field("view", "invalid_format")])
    return value


def rollover_body(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise DnsInputError("dns_zone_invalid", "The request must be an object",
                            [_field("body", "invalid_type")])
    errors: list[dict[str, Any]] = []
    _unknown(payload, "", ("role",), errors)
    if payload.get("role") not in ROLLOVER_ROLES:
        errors.append(_field("role", "invalid_choice", choices=list(ROLLOVER_ROLES)))
    if errors:
        raise DnsInputError("dns_zone_invalid", "Choose zsk or ksk", errors)
    return {"role": payload["role"]}


# ----------------------------------------------------------------------------- TSIG


def tsig_body(payload: Any) -> dict[str, Any]:
    """``{name, algorithm, secret?}``; the engine generates the secret when absent."""
    if not isinstance(payload, dict):
        raise DnsInputError("dns_tsig_invalid", "The key must be an object",
                            [_field("body", "invalid_type")])
    errors: list[dict[str, Any]] = []
    _unknown(payload, "", ("name", "algorithm", "secret"), errors)
    name = key_name(payload.get("name"))
    if name is None:
        errors.append(_field("name", "required" if payload.get("name") in (None, "")
                             else "invalid_key_name"))
    algorithm = payload.get("algorithm", "hmac-sha256")
    if algorithm not in TSIG_ALGORITHMS:
        errors.append(_field("algorithm", "invalid_choice", choices=list(TSIG_ALGORITHMS)))
    body: dict[str, Any] = {"name": name, "algorithm": algorithm}
    secret = payload.get("secret")
    if secret not in (None, ""):
        try:
            if not isinstance(secret, str) or len(secret) > 512:
                raise ValueError("invalid")
            decoded = base64.b64decode(secret.strip(), validate=True)
        except (ValueError, binascii.Error):
            errors.append(_field("secret", "invalid_base64"))
        else:
            low, high = TSIG_SECRET_BYTES
            if not low <= len(decoded) <= high:
                errors.append(_field("secret", "out_of_range", min=low, max=high))
            body["secret"] = secret.strip()
    if errors:
        raise DnsInputError("dns_tsig_invalid", "The TSIG key is invalid", errors)
    return body


def strip_secrets(payload: Any, keys: frozenset[str]) -> Any:
    """Copy of an engine answer with secret keys removed at any depth."""
    if isinstance(payload, dict):
        return {key: strip_secrets(value, keys) for key, value in payload.items()
                if key not in keys}
    if isinstance(payload, list):
        return [strip_secrets(item, keys) for item in payload]
    return payload


# ----------------------------------------------------------------------------- filtering


def _filter_name(value: Any) -> str | None:
    text = value[2:] if isinstance(value, str) and value.startswith("*.") else value
    name, problem = name_problem(text, allow_underscore=True, allow_wildcard=False)
    if problem or name is None:
        return None
    return f"*.{name}" if isinstance(value, str) and value.startswith("*.") else name


def _filter_url(value: Any) -> str | None:
    if not isinstance(value, str) or not value or len(value) > 2048 or any(
        ch.isspace() for ch in value
    ):
        return "invalid_url"
    parts = urlsplit(value)
    if parts.scheme != "https":
        return "https_required"
    if not parts.hostname or parts.username or parts.password:
        return "invalid_url"
    return None


def _filter_lists(value: Any, errors: list[dict[str, Any]]) -> set[str]:
    ids: set[str] = set()
    if not isinstance(value, list) or len(value) > MAX_FILTER_LISTS:
        errors.append(_field("filtering.lists", "invalid_type", max=MAX_FILTER_LISTS))
        return ids
    for index, item in enumerate(value):
        field = f"filtering.lists.{index}"
        if not isinstance(item, dict):
            errors.append(_field(field, "invalid_type"))
            continue
        _unknown(item, field, ("id", "name", "url", "format", "enabled", "update_hours"),
                 errors)
        identifier = item.get("id")
        if not isinstance(identifier, str) or not _ID.fullmatch(identifier):
            errors.append(_field(f"{field}.id", "invalid_format"))
        elif identifier in ids:
            errors.append(_field(f"{field}.id", "duplicate"))
        else:
            ids.add(identifier)
        name = item.get("name")
        if "name" in item and (not isinstance(name, str) or not 1 <= len(name.strip()) <= 100):
            errors.append(_field(f"{field}.name", "invalid_format"))
        problem = _filter_url(item.get("url"))
        if problem:
            errors.append(_field(f"{field}.url", problem))
        _choice(item, field, "format", FILTER_FORMATS, errors)
        _flag(item, field, "enabled", errors)
        _int(item, field, "update_hours", 1, 168, errors)
    return ids


def _filter_names(value: Any, field: str, errors: list[dict[str, Any]]) -> None:
    if not isinstance(value, list) or len(value) > MAX_FILTER_NAMES:
        errors.append(_field(field, "invalid_type", max=MAX_FILTER_NAMES))
        return
    for index, item in enumerate(value):
        canonical = _filter_name(item)
        if canonical is None:
            errors.append(_field(f"{field}.{index}", "invalid_name"))
            if len(errors) > 40:
                return
        else:
            value[index] = canonical


def _filtering(payload: dict[str, Any], errors: list[dict[str, Any]]) -> set[str] | None:
    if "filtering" not in payload:
        return None
    section = payload["filtering"]
    if not isinstance(section, dict):
        errors.append(_field("filtering", "invalid_type"))
        return None
    _unknown(section, "filtering", ("enabled", "lists", "allow", "block", "action",
                                    "safe_search"), errors)
    _flag(section, "filtering", "enabled", errors)
    _flag(section, "filtering", "safe_search", errors)
    _choice(section, "filtering", "action", FILTER_ACTIONS, errors)
    ids = _filter_lists(section["lists"], errors) if "lists" in section else None
    for key in ("allow", "block"):
        if key in section:
            _filter_names(section[key], f"filtering.{key}", errors)
    return ids


def _id_refs(value: Any, field: str, known: set[str] | None, reason: str,
             errors: list[dict[str, Any]]) -> None:
    if value is None:
        return
    if not isinstance(value, list) or len(value) > 64:
        errors.append(_field(field, "invalid_type", max=64))
        return
    for index, item in enumerate(value):
        if not isinstance(item, str) or not _ID.fullmatch(item):
            errors.append(_field(f"{field}.{index}", "invalid_format"))
        elif known is not None and item not in known:
            errors.append(_field(f"{field}.{index}", reason))


def _client_groups(payload: dict[str, Any], list_ids: set[str] | None,
                   errors: list[dict[str, Any]]) -> None:
    if "client_groups" not in payload:
        return
    groups = payload["client_groups"]
    if not isinstance(groups, list) or len(groups) > MAX_GROUPS:
        errors.append(_field("client_groups", "invalid_type", max=MAX_GROUPS))
        return
    upstreams = payload.get("upstreams")
    upstream_ids = {item.get("id") for item in upstreams if isinstance(item, dict)} if \
        isinstance(upstreams, list) else None
    seen: set[str] = set()
    for index, group in enumerate(groups):
        field = f"client_groups.{index}"
        if not isinstance(group, dict):
            errors.append(_field(field, "invalid_type"))
            continue
        _unknown(group, field, ("id", "name", "networks", "filtering", "lists", "upstreams",
                                "blocked_services"), errors)
        identifier = group.get("id")
        if not isinstance(identifier, str) or not _ID.fullmatch(identifier):
            errors.append(_field(f"{field}.id", "invalid_format"))
        elif identifier in seen:
            errors.append(_field(f"{field}.id", "duplicate"))
        else:
            seen.add(identifier)
        name = group.get("name")
        if not isinstance(name, str) or not 1 <= len(name.strip()) <= 64 or any(
            ord(ch) < 32 for ch in name
        ):
            errors.append(_field(f"{field}.name", "invalid_format"))
        networks = group.get("networks")
        if not isinstance(networks, list) or not networks:
            errors.append(_field(f"{field}.networks", "required"))
        else:
            canonical = cidr_list(networks, f"{field}.networks", errors, allow_all=True)
            if canonical is not None and len(canonical) == len(networks):
                group["networks"] = canonical
        _choice(group, field, "filtering", GROUP_FILTERING, errors)
        _id_refs(group.get("lists"), f"{field}.lists", list_ids, "unknown_list", errors)
        _id_refs(group.get("upstreams"), f"{field}.upstreams", upstream_ids,
                 "unknown_upstream", errors)
        services = group.get("blocked_services")
        if services is not None and (
            not isinstance(services, list) or len(services) > MAX_BLOCKED_SERVICES
            or not all(isinstance(item, str) and 0 < len(item) <= 64 for item in services)
        ):
            errors.append(_field(f"{field}.blocked_services", "invalid_type",
                                 max=MAX_BLOCKED_SERVICES))


def d5_settings_errors(payload: dict[str, Any]) -> list[dict[str, Any]]:
    """Field errors for ``filtering`` and ``client_groups`` (docs/41 §3)."""
    errors: list[dict[str, Any]] = []
    list_ids = _filtering(payload, errors)
    _client_groups(payload, list_ids, errors)
    return errors


def check_body(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise DnsInputError("dns_query_invalid", "The request must be an object",
                            [_field("body", "invalid_type")])
    unknown = sorted(set(payload) - {"name", "client_ip"})
    if unknown:
        raise DnsInputError("dns_query_invalid", "Unknown fields",
                            [_field(key, "unknown_field") for key in unknown[:10]])
    name, problem = name_problem(payload.get("name"), allow_underscore=True,
                                 allow_wildcard=False)
    if problem or name is None:
        raise DnsInputError("dns_query_invalid", "Enter a name such as ads.example.com",
                            [_field("name", problem or "invalid_format")])
    body: dict[str, Any] = {"name": name}
    client_ip = payload.get("client_ip")
    if client_ip not in (None, ""):
        try:
            body["client_ip"] = str(ipaddress.ip_address(str(client_ip).strip()))
        except ValueError:
            raise DnsInputError("dns_query_invalid", "client_ip must be an IP address",
                                [_field("client_ip", "invalid_ip")]) from None
    return body
