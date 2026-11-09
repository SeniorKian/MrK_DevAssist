"""DNS domain templates (docs/41 §5): storage, variables, preview and the change set.

A template is ``{id, name, description, builtin, zone:{ttl, soa, ns}, records:[{name,
type, ttl?, data, comment?}], variables:[{key, label_fa, label_en, default?, required}]}``.
Built-ins live in ``dns_templates_builtin`` (read-only, can be copied); user templates
in the ``dns_templates`` table.

Applying never overwrites silently. Against the zone's current records every
template record is:

* ``new``: nothing at that name/type stands in its way;
* ``duplicate``: the same name, type and data already exist (skipped);
* ``conflict``: it would clash with existing records: a CNAME next to other data,
  a different address/MX/NS set at the same name, a second SPF or DMARC record, or
  a different SOA. Applying fails unless ``replace_conflicts`` is true, which removes
  the clashing records in the same change;
* ``skipped``: one of its placeholders has no value (an optional DKIM key, AAAA on a
  server without IPv6).

The change is one engine call, so one zone version: new records only ⇒ zone-file
import with ``replace:false``; with replacements ⇒ import with ``replace:true`` of the
whole resulting zone (kept records + SOA + new records).
"""

from __future__ import annotations

import copy
import ipaddress
import re
import secrets
import time
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import func, select

from ..models import DnsTemplate
from ..module_context import ModuleContext
from .dns_templates_builtin import BUILTIN_IDS, BUILTIN_TEMPLATES
from .dns_validate import (
    RECORD_FIELDS,
    RECORD_TYPES,
    TTL_MAX,
    DnsInputError,
    canonical_target,
    record_body,
    record_data,
)

# Filled by the panel; ``server_ipv4/6`` may be overridden by the user.
AUTO_VARIABLES = ("domain", "domain_dashed", "server_ipv4", "server_ipv6")
FIXED_VARIABLES = ("domain", "domain_dashed")
# Usable in any template without declaring them (empty unless given).
STANDARD_VARIABLES = (*AUTO_VARIABLES, "mail_host", "dkim_value")
TEMPLATE_TYPES = tuple(item for item in RECORD_TYPES if item != "SOA")
NAME_FIELDS = frozenset({"target", "nameserver", "exchange", "mname", "rname"})
INT_FIELDS = frozenset({"preference", "priority", "weight", "port", "flags", "refresh", "retry",
                        "expire", "minimum"})
EXCLUSIVE_TYPES = frozenset({"A", "AAAA", "MX", "NS"})
MAX_TEMPLATES = 200
MAX_RECORDS = 200
MAX_VARIABLES = 20
MAX_NS = 13
MAX_VALUE = 1000
SOA_DEFAULTS = {"refresh": 3600, "retry": 600, "expire": 604800, "minimum": 300}
SAMPLE = {"domain": "example.com", "domain_dashed": "example-com",
          "server_ipv4": "192.0.2.10", "server_ipv6": "2001:db8::10"}

PLACEHOLDER = re.compile(r"\{([a-z][a-z0-9_]{0,31})\}")
_KEY = re.compile(r"^[a-z][a-z0-9_]{0,31}$")
_TEMPLATE_ID = re.compile(r"^[A-Za-z0-9_-]{1,32}$")


def _field(field_name: str, reason: str, **params: Any) -> dict[str, Any]:
    item: dict[str, Any] = {"field": field_name, "reason_code": reason}
    if params:
        item["params"] = params
    return item


def invalid(errors: list[dict[str, Any]], message: str = "The template is invalid") -> None:
    if errors:
        raise DnsInputError("dns_template_invalid", message, errors[:50])


def template_id(raw: str) -> str:
    if not isinstance(raw, str) or not _TEMPLATE_ID.fullmatch(raw):
        raise DnsInputError("dns_template_not_found", "Template not found",
                            [_field("id", "invalid_format")], 404)
    return raw


def _text(value: Any, limit: int) -> bool:
    return isinstance(value, str) and len(value) <= limit and not any(
        ord(ch) < 32 and ch != "\t" for ch in value
    )


# ----------------------------------------------------------------------------- shape


def _variables(raw: Any, errors: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if raw is None:
        return []
    if not isinstance(raw, list) or len(raw) > MAX_VARIABLES:
        errors.append(_field("variables", "invalid_type", max=MAX_VARIABLES))
        return []
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, item in enumerate(raw):
        where = f"variables.{index}"
        if not isinstance(item, dict):
            errors.append(_field(where, "invalid_type"))
            continue
        for key in sorted(set(item) - {"key", "label_fa", "label_en", "default", "required"}):
            errors.append(_field(f"{where}.{key}", "unknown_field"))
        key = item.get("key")
        if not isinstance(key, str) or not _KEY.fullmatch(key):
            errors.append(_field(f"{where}.key", "invalid_format"))
            continue
        if key in AUTO_VARIABLES:
            errors.append(_field(f"{where}.key", "reserved"))
            continue
        if key in seen:
            errors.append(_field(f"{where}.key", "duplicate"))
            continue
        seen.add(key)
        label_fa = item.get("label_fa")
        label_en = item.get("label_en", label_fa)
        for name, label in (("label_fa", label_fa), ("label_en", label_en)):
            if not _text(label, 200) or not str(label).strip():
                errors.append(_field(f"{where}.{name}", "required"))
        default = item.get("default")
        if default is not None:
            if not _text(default, MAX_VALUE):
                errors.append(_field(f"{where}.default", "invalid_format", max=MAX_VALUE))
            elif any(name not in AUTO_VARIABLES for name in PLACEHOLDER.findall(default)):
                errors.append(_field(f"{where}.default", "unknown_variable",
                                     allowed=list(AUTO_VARIABLES)))
        required = item.get("required", False)
        if not isinstance(required, bool):
            errors.append(_field(f"{where}.required", "invalid_type"))
        out.append({"key": key, "label_fa": label_fa, "label_en": label_en,
                    "default": default if default not in ("",) else None,
                    "required": required is True})
    return out


def _zone_section(raw: Any, errors: list[dict[str, Any]]) -> dict[str, Any]:
    if raw is None:
        return {"ttl": 3600, "soa": None, "ns": []}
    if not isinstance(raw, dict):
        errors.append(_field("zone", "invalid_type"))
        return {"ttl": 3600, "soa": None, "ns": []}
    for key in sorted(set(raw) - {"ttl", "soa", "ns"}):
        errors.append(_field(f"zone.{key}", "unknown_field"))
    ttl = raw.get("ttl", 3600)
    if isinstance(ttl, bool) or not isinstance(ttl, int) or not 0 <= ttl <= TTL_MAX:
        errors.append(_field("zone.ttl", "out_of_range", min=0, max=TTL_MAX))
        ttl = 3600
    soa = raw.get("soa")
    if soa is not None:
        if not isinstance(soa, dict):
            errors.append(_field("zone.soa", "invalid_type"))
            soa = None
        else:
            for key in sorted(set(soa) - {"hostmaster", *SOA_DEFAULTS}):
                errors.append(_field(f"zone.soa.{key}", "unknown_field"))
            hostmaster = soa.get("hostmaster")
            if hostmaster not in (None, "") and not _text(hostmaster, 253):
                errors.append(_field("zone.soa.hostmaster", "invalid_format"))
            ranges = {"refresh": (1, 2**31 - 1), "retry": (1, 2**31 - 1),
                      "expire": (1, 2**31 - 1), "minimum": (0, 86400)}
            clean: dict[str, Any] = {"hostmaster": hostmaster or None}
            for key, (low, high) in ranges.items():
                value = soa.get(key, SOA_DEFAULTS[key])
                if isinstance(value, bool) or not isinstance(value, int) or not (
                    low <= value <= high
                ):
                    errors.append(_field(f"zone.soa.{key}", "out_of_range", min=low, max=high))
                clean[key] = value
            soa = clean
    ns = raw.get("ns") or []
    if not isinstance(ns, list) or len(ns) > MAX_NS or not all(_text(item, 253) and item
                                                               for item in ns):
        errors.append(_field("zone.ns", "invalid_type", max=MAX_NS))
        ns = []
    return {"ttl": ttl, "soa": soa, "ns": list(ns)}


def _records(raw: Any, errors: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if raw is None:
        return []
    if not isinstance(raw, list) or len(raw) > MAX_RECORDS:
        errors.append(_field("records", "invalid_type", max=MAX_RECORDS))
        return []
    out: list[dict[str, Any]] = []
    for index, item in enumerate(raw):
        where = f"records.{index}"
        if not isinstance(item, dict):
            errors.append(_field(where, "invalid_type"))
            continue
        for key in sorted(set(item) - {"name", "type", "ttl", "data", "comment"}):
            errors.append(_field(f"{where}.{key}", "unknown_field"))
        name = item.get("name", "@")
        if name in (None, ""):
            name = "@"
        if not _text(name, 300):
            errors.append(_field(f"{where}.name", "invalid_format"))
        rtype = item.get("type")
        rtype = rtype.upper() if isinstance(rtype, str) else rtype
        if rtype not in TEMPLATE_TYPES:
            errors.append(_field(f"{where}.type", "invalid_choice",
                                 choices=list(TEMPLATE_TYPES)))
            continue
        ttl = item.get("ttl")
        if ttl is not None and (isinstance(ttl, bool) or not isinstance(ttl, int)
                                or not 0 <= ttl <= TTL_MAX):
            errors.append(_field(f"{where}.ttl", "out_of_range", min=0, max=TTL_MAX))
        data = item.get("data")
        if not isinstance(data, dict):
            errors.append(_field(f"{where}.data", "invalid_type"))
            continue
        allowed = RECORD_FIELDS[rtype]
        for key in sorted(set(data) - set(allowed)):
            errors.append(_field(f"{where}.data.{key}", "unknown_field"))
        for key in allowed:
            value = data.get(key)
            if key in INT_FIELDS:
                if isinstance(value, bool) or not isinstance(value, int):
                    errors.append(_field(f"{where}.data.{key}", "invalid_type"))
            elif not _text(value, 4000) or not value:
                errors.append(_field(f"{where}.data.{key}", "required"))
        comment = item.get("comment")
        if comment not in (None, "") and not _text(comment, 255):
            errors.append(_field(f"{where}.comment", "invalid_format", max=255))
        out.append({"name": name, "type": rtype, "ttl": ttl,
                    "data": {key: data.get(key) for key in allowed},
                    "comment": comment or ""})
    return out


def _placeholders(template: dict[str, Any]) -> Iterable[tuple[str, str]]:
    zone = template["zone"]
    for index, value in enumerate(zone["ns"]):
        yield f"zone.ns.{index}", value
    if zone["soa"] and zone["soa"].get("hostmaster"):
        yield "zone.soa.hostmaster", zone["soa"]["hostmaster"]
    for index, record in enumerate(template["records"]):
        yield f"records.{index}.name", record["name"]
        for key, value in record["data"].items():
            if isinstance(value, str):
                yield f"records.{index}.data.{key}", value


def template_body(payload: Any) -> dict[str, Any]:
    """Check a user template; returns ``{name, description, zone, records, variables}``."""
    if not isinstance(payload, dict):
        raise DnsInputError("dns_template_invalid", "The template must be an object",
                            [_field("body", "invalid_type")])
    errors: list[dict[str, Any]] = []
    for key in sorted(set(payload) - {"name", "description", "zone", "records", "variables",
                                      "id", "builtin"}):
        errors.append(_field(key, "unknown_field"))
    name = payload.get("name")
    if not _text(name, 100) or not str(name).strip():
        errors.append(_field("name", "required", max=100))
    description = payload.get("description") or ""
    if not _text(description, 500):
        errors.append(_field("description", "invalid_format", max=500))
    template = {
        "name": name.strip() if isinstance(name, str) else "",
        "description": description.strip() if isinstance(description, str) else "",
        "zone": _zone_section(payload.get("zone"), errors),
        "records": _records(payload.get("records"), errors),
        "variables": _variables(payload.get("variables"), errors),
    }
    known = set(STANDARD_VARIABLES) | {item["key"] for item in template["variables"]}
    for where, value in _placeholders(template):
        for key in PLACEHOLDER.findall(value):
            if key not in known:
                errors.append(_field(where, "unknown_variable", variable=key))
    invalid(errors)
    # Static check with sample values: records whose variables have no default are skipped.
    sample = {item["key"]: item["default"] for item in template["variables"]}
    try:
        render(template, "example.com", {}, (SAMPLE["server_ipv4"], SAMPLE["server_ipv6"]),
               defaults_only=sample)
    except DnsInputError as exc:
        if exc.code == "dns_template_invalid":
            raise
    return template


# ----------------------------------------------------------------------------- view


def builtin_view(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": item["id"], "builtin": True,
        "name": item["name_fa"], "description": item["description_fa"],
        "name_fa": item["name_fa"], "name_en": item["name_en"],
        "description_fa": item["description_fa"], "description_en": item["description_en"],
        "zone": copy.deepcopy(item["zone"]), "records": copy.deepcopy(item["records"]),
        "variables": copy.deepcopy(item["variables"]),
        "copied_from": None, "created_at": None, "updated_at": None,
    }


def row_view(row: DnsTemplate) -> dict[str, Any]:
    body = row.body if isinstance(row.body, dict) else {}
    return {
        "id": row.id, "builtin": False,
        "name": row.name, "description": row.description or "",
        "name_fa": row.name, "name_en": row.name,
        "description_fa": row.description or "", "description_en": row.description or "",
        "zone": body.get("zone") or {"ttl": 3600, "soa": None, "ns": []},
        "records": body.get("records") or [], "variables": body.get("variables") or [],
        "copied_from": row.copied_from, "created_at": row.created_at,
        "updated_at": row.updated_at,
    }


BUILTINS = {item["id"]: item for item in BUILTIN_TEMPLATES}


class TemplateStore:
    def __init__(self, ctx: ModuleContext) -> None:
        self.ctx = ctx

    def list(self) -> list[dict[str, Any]]:
        with self.ctx.database.session() as db:
            rows = list(db.scalars(select(DnsTemplate).order_by(DnsTemplate.name)))
            users = [row_view(row) for row in rows]
        return [builtin_view(item) for item in BUILTIN_TEMPLATES] + users

    def get(self, identifier: str) -> dict[str, Any] | None:
        if identifier in BUILTINS:
            return builtin_view(BUILTINS[identifier])
        with self.ctx.database.session() as db:
            row = db.get(DnsTemplate, identifier)
            return row_view(row) if row is not None else None

    def require(self, identifier: str) -> dict[str, Any]:
        found = self.get(template_id(identifier))
        if found is None:
            raise DnsInputError("dns_template_not_found", "Template not found",
                                [_field("template_id", "not_found")], 404)
        return found

    def create(self, body: dict[str, Any], actor: int | None,
               copied_from: str | None = None) -> dict[str, Any]:
        now = int(time.time())
        identifier = "tpl_" + secrets.token_hex(6)
        with self.ctx.database.session() as db, db.begin():
            count = int(db.scalar(select(func.count()).select_from(DnsTemplate)) or 0)
            if count >= MAX_TEMPLATES:
                raise DnsInputError("dns_template_limit", "Too many templates",
                                    [_field("body", "too_many", max=MAX_TEMPLATES)], 409)
            db.add(DnsTemplate(
                id=identifier, name=body["name"], description=body["description"],
                body={key: body[key] for key in ("zone", "records", "variables")},
                copied_from=copied_from, created_at=now, updated_at=now,
                created_by_user_id=actor, updated_by_user_id=actor,
            ))
        return self.get(identifier) or {}

    def update(self, identifier: str, body: dict[str, Any], actor: int | None) -> dict[str, Any]:
        self._writable(identifier)
        with self.ctx.database.session() as db, db.begin():
            row = db.get(DnsTemplate, identifier)
            if row is None:
                raise DnsInputError("dns_template_not_found", "Template not found",
                                    [_field("id", "not_found")], 404)
            row.name = body["name"]
            row.description = body["description"]
            row.body = {key: body[key] for key in ("zone", "records", "variables")}
            row.updated_at = int(time.time())
            row.updated_by_user_id = actor
        return self.get(identifier) or {}

    def delete(self, identifier: str) -> None:
        self._writable(identifier)
        with self.ctx.database.session() as db, db.begin():
            row = db.get(DnsTemplate, identifier)
            if row is None:
                raise DnsInputError("dns_template_not_found", "Template not found",
                                    [_field("id", "not_found")], 404)
            db.delete(row)

    @staticmethod
    def _writable(identifier: str) -> None:
        template_id(identifier)
        if identifier in BUILTIN_IDS:
            raise DnsInputError("dns_template_builtin",
                                "Built-in templates cannot be changed; make a copy",
                                [_field("id", "builtin")], 409)


# ----------------------------------------------------------------------------- render


@dataclass(slots=True)
class Rendered:
    zone: str
    values: dict[str, str]
    records: list[dict[str, Any]] = field(default_factory=list)  # {index, source, record}
    skipped: list[dict[str, Any]] = field(default_factory=list)
    soa: dict[str, Any] | None = None
    warnings: list[dict[str, Any]] = field(default_factory=list)


def variable_values(
    template: dict[str, Any], zone: str, provided: Any,
    server_ips: tuple[str | None, str | None],
) -> dict[str, str]:
    """Final values for every placeholder (``dns_template_variables_invalid`` on bad input)."""
    if provided is None:
        provided = {}
    if not isinstance(provided, dict):
        raise DnsInputError("dns_template_variables_invalid", "variables must be an object",
                            [_field("variables", "invalid_type")])
    declared = {item["key"]: item for item in template["variables"]}
    allowed = set(declared) | (set(STANDARD_VARIABLES) - set(FIXED_VARIABLES))
    errors: list[dict[str, Any]] = []
    for key in sorted(set(provided) - allowed)[:10]:
        errors.append(_field(f"variables.{key}", "unknown_field"))
    clean: dict[str, str] = {}
    for key, value in provided.items():
        if key not in allowed:
            continue
        if value is None:
            value = ""
        if not isinstance(value, str) or not _text(value, MAX_VALUE):
            errors.append(_field(f"variables.{key}", "invalid_format", max=MAX_VALUE))
            continue
        clean[key] = value.strip()
    auto = {"domain": zone, "domain_dashed": zone.replace(".", "-"),
            "server_ipv4": server_ips[0] or "", "server_ipv6": server_ips[1] or ""}
    for key, version in (("server_ipv4", 4), ("server_ipv6", 6)):
        if clean.get(key):
            try:
                address = ipaddress.ip_address(clean[key])
            except ValueError:
                address = None
            if address is None or address.version != version:
                errors.append(_field(f"variables.{key}", f"invalid_ipv{version}"))
            else:
                auto[key] = str(address)
    values = dict(auto)
    for key in ("mail_host", "dkim_value"):
        values[key] = clean.get(key, "")
    for key, spec in declared.items():
        if key in clean:
            values[key] = clean[key]
        else:
            default = spec.get("default") or ""
            values[key] = PLACEHOLDER.sub(lambda match: auto.get(match.group(1), ""), default)
        if spec.get("required") and not values[key]:
            errors.append(_field(f"variables.{key}", "required"))
    if errors:
        raise DnsInputError("dns_template_variables_invalid", "Some template values are missing "
                            "or invalid", errors)
    return values


def _substitute(text: str, values: dict[str, str]) -> tuple[str, str | None]:
    """(text, first empty variable or None)."""
    empty: list[str] = []

    def one(match: re.Match[str]) -> str:
        value = values.get(match.group(1), "")
        if not value:
            empty.append(match.group(1))
        return value

    return PLACEHOLDER.sub(one, text), (empty[0] if empty else None)


def _prefixed(exc: DnsInputError, prefix: str) -> list[dict[str, Any]]:
    out = []
    for item in exc.fields or [{"field": "body", "reason_code": "invalid_format"}]:
        name = item.get("field", "body")
        out.append({**item, "field": prefix if name == "body" else f"{prefix}.{name}"})
    return out


def _hostmaster(text: str) -> str:
    if "@" in text:
        local, _, domain = text.partition("@")
        if "." in local or not local or not domain:
            raise ValueError("invalid")
        return f"{local}.{domain}"
    return text


def render(
    template: dict[str, Any], zone: str, provided: Any,
    server_ips: tuple[str | None, str | None], *,
    defaults_only: dict[str, Any] | None = None,
) -> Rendered:
    """Template + values → canonical records for ``zone`` (``record_body`` shapes)."""
    if defaults_only is not None:
        values = {"domain": zone, "domain_dashed": zone.replace(".", "-"),
                  "server_ipv4": server_ips[0] or "", "server_ipv6": server_ips[1] or "",
                  "mail_host": "", "dkim_value": ""}
        for key, default in defaults_only.items():
            values[key] = PLACEHOLDER.sub(lambda match: values.get(match.group(1), ""),
                                          default or "")
    else:
        values = variable_values(template, zone, provided, server_ips)
    out = Rendered(zone=zone, values=values)
    errors: list[dict[str, Any]] = []
    section = template["zone"]
    ns_names: list[str] = []
    for index, raw in enumerate(section.get("ns") or []):
        text, empty = _substitute(raw, values)
        if empty:
            continue
        try:
            ns_names.append(canonical_target(text, "nameserver"))
        except DnsInputError:
            errors.append(_field(f"zone.ns.{index}", "invalid_name"))
    for index, name in enumerate(ns_names):
        out.records.append({"index": index, "source": "ns", "record": {
            "name": "@", "type": "NS", "ttl": section["ttl"], "data": {"nameserver": name},
            "disabled": False, "comment": ""}})
    soa = section.get("soa")
    if soa:
        hostmaster = soa.get("hostmaster") or "hostmaster.{domain}"
        text, _empty = _substitute(hostmaster, values)
        try:
            out.soa = {"ttl": section["ttl"], "data": record_data("SOA", {
                "mname": ns_names[0] if ns_names else f"ns1.{zone}",
                "rname": _hostmaster(text or f"hostmaster.{zone}"),
                **{key: soa[key] for key in SOA_DEFAULTS},
            })}
        except (DnsInputError, ValueError):
            errors.append(_field("zone.soa.hostmaster", "invalid_name"))
    seen: set[tuple[str, str, str]] = set()
    for index, item in enumerate(template["records"]):
        name, empty = _substitute(item["name"], values)
        data: dict[str, Any] = {}
        for key, value in item["data"].items():
            if isinstance(value, str) and empty is None:
                value, empty = _substitute(value, values)
            data[key] = value
        if empty is not None:
            out.skipped.append({"index": index, "source": "record", "status": "skipped",
                                "reason": "variable_empty", "variable": empty,
                                "record": {"name": item["name"], "type": item["type"]}})
            continue
        try:
            record = record_body({"name": name, "type": item["type"],
                                  "ttl": item.get("ttl") if item.get("ttl") is not None
                                  else section["ttl"], "data": data,
                                  "comment": item.get("comment") or ""}, zone, creating=True)
        except DnsInputError as exc:
            errors.extend(_prefixed(exc, f"records.{index}"))
            continue
        key = record_key(record)
        if key in seen:
            continue  # the same record twice in one template is harmless
        seen.add(key)
        out.records.append({"index": index, "source": "record", "record": record})
    names: dict[str, set[str]] = {}
    for entry in out.records:
        names.setdefault(entry["record"]["name"], set()).add(entry["record"]["type"])
    for name, types in names.items():
        if "CNAME" in types and len(types) > 1:
            errors.append(_field("records", "cname_conflict", name=name))
    if not values.get("server_ipv4") and _uses(template, "server_ipv4"):
        out.warnings.append({"code": "server_ipv4_unknown"})
    invalid(errors, "The template gives invalid records for this domain")
    return out


def _uses(template: dict[str, Any], key: str) -> bool:
    needle = "{" + key + "}"
    return any(needle in value for _where, value in _placeholders(template))


# ----------------------------------------------------------------------------- compare


def _norm_value(key: str, value: Any) -> Any:
    if isinstance(value, bool):
        return value
    if key in INT_FIELDS:
        try:
            return int(value)
        except (TypeError, ValueError):
            return value
    if not isinstance(value, str):
        return value
    if key in NAME_FIELDS:
        text = value.strip().lower()
        return text if text == "." else text.rstrip(".")
    if key == "address":
        try:
            return str(ipaddress.ip_address(value.strip()))
        except ValueError:
            return value
    if key == "tag":
        return value.lower()
    return value


def norm_data(rtype: str, data: Any) -> tuple[tuple[str, Any], ...]:
    if not isinstance(data, dict):
        return ()
    data = dict(data)
    if rtype == "TXT" and "text" not in data and isinstance(data.get("strings"), list):
        data["text"] = "".join(str(item) for item in data["strings"])
    keys = RECORD_FIELDS.get(rtype, tuple(sorted(data)))
    return tuple((key, _norm_value(key, data.get(key))) for key in keys if key != "serial")


def record_key(record: dict[str, Any]) -> tuple[str, str, str]:
    rtype = str(record.get("type", "")).upper()
    return (str(record.get("name", "@")).lower(), rtype, repr(norm_data(rtype, record.get(
        "data"))))


def _txt(record: dict[str, Any]) -> str:
    data = record.get("data") if isinstance(record.get("data"), dict) else {}
    text = data.get("text")
    if text is None and isinstance(data.get("strings"), list):
        text = "".join(str(item) for item in data["strings"])
    return text if isinstance(text, str) else ""


def _group(record: dict[str, Any]) -> str | None:
    """Records of one group at one name must not mix sources (exclusive sets)."""
    rtype = str(record.get("type", "")).upper()
    if rtype in EXCLUSIVE_TYPES:
        return rtype
    if rtype == "TXT":
        text = _txt(record).strip().lower()
        if text.startswith("v=spf1"):
            return "spf"
        if text.startswith("v=dmarc1"):
            return "dmarc"
    return None


def _public(record: dict[str, Any]) -> dict[str, Any]:
    keys = ("id", "name", "type", "ttl", "data", "disabled", "comment", "view")
    return {key: record[key] for key in keys if key in record}


def compare(rendered: Rendered, existing: list[dict[str, Any]],
            current_soa: dict[str, Any] | None) -> list[dict[str, Any]]:
    """Preview items in template order: new / duplicate / conflict / skipped."""
    records = [item for item in existing if isinstance(item, dict)
               and str(item.get("type", "")).upper() != "SOA" and item.get("id") != "soa"]
    by_key = {record_key(item): item for item in records}
    by_name: dict[str, list[dict[str, Any]]] = {}
    for item in records:
        by_name.setdefault(str(item.get("name", "@")).lower(), []).append(item)
    wanted: dict[tuple[str, str], set[tuple[str, str, str]]] = {}
    template_types: dict[str, set[str]] = {}
    for entry in rendered.records:
        record = entry["record"]
        template_types.setdefault(record["name"], set()).add(record["type"])
        group = _group(record)
        if group:
            wanted.setdefault((record["name"], group), set()).add(record_key(record))
    items: list[dict[str, Any]] = []
    if rendered.soa is not None:
        item: dict[str, Any] = {"index": None, "source": "soa", "record": {
            "name": "@", "type": "SOA", "ttl": rendered.soa["ttl"], "data": rendered.soa["data"]},
            "conflicts": []}
        same = current_soa is not None and norm_data("SOA", current_soa.get("data")) == \
            norm_data("SOA", rendered.soa["data"])
        item["status"] = "duplicate" if same else ("conflict" if current_soa else "new")
        if current_soa is not None and not same:
            item["conflicts"] = [_public(current_soa)]
        items.append(item)
    for entry in rendered.records:
        record = entry["record"]
        key = record_key(record)
        item = {"index": entry["index"], "source": entry["source"], "record": record,
                "conflicts": []}
        if key in by_key:
            item["status"] = "duplicate"
            items.append(item)
            continue
        at_name = by_name.get(record["name"], [])
        clashes: list[dict[str, Any]] = []
        if record["type"] == "CNAME":
            clashes = [other for other in at_name if record_key(other) != key]
        else:
            clashes = [other for other in at_name if str(other.get("type")).upper() == "CNAME"
                       and "CNAME" not in template_types.get(record["name"], set())]
            group = _group(record)
            if group:
                accepted = wanted.get((record["name"], group), set())
                clashes += [other for other in at_name if _group(other) == group
                            and record_key(other) not in accepted]
        item["status"] = "conflict" if clashes else "new"
        item["conflicts"] = [_public(other) for other in clashes]
        items.append(item)
    for skipped in rendered.skipped:
        items.append({**skipped, "conflicts": []})
    return items


def summary(items: list[dict[str, Any]]) -> dict[str, int]:
    counts = {"new": 0, "duplicate": 0, "conflict": 0, "skipped": 0}
    for item in items:
        counts[item["status"]] += 1
    return counts


# ----------------------------------------------------------------------------- zone file


def _fqdn(name: str) -> str:
    return "." if name == "." else name.rstrip(".") + "."


def _owner(name: str, zone: str) -> str:
    return f"{zone}." if name == "@" else f"{name}.{zone}."


def _quoted(raw: bytes) -> str:
    out = []
    for byte in raw:
        if byte in (0x22, 0x5C):
            out.append("\\" + chr(byte))
        elif 0x20 <= byte < 0x7F:
            out.append(chr(byte))
        else:
            out.append(f"\\{byte:03d}")
    return '"' + "".join(out) + '"'


def rdata(rtype: str, data: dict[str, Any]) -> str:
    """RFC 1035 presentation of panel-shaped ``data`` (``ValueError`` if unsupported)."""
    if rtype in {"A", "AAAA"}:
        return str(ipaddress.ip_address(str(data["address"])))
    if rtype in {"CNAME", "PTR"}:
        return _fqdn(str(data["target"]))
    if rtype == "NS":
        return _fqdn(str(data["nameserver"]))
    if rtype == "MX":
        return f"{int(data['preference'])} {_fqdn(str(data['exchange']))}"
    if rtype == "TXT":
        text = data.get("text")
        if text is None and isinstance(data.get("strings"), list):
            text = "".join(str(item) for item in data["strings"])
        raw = str(text).encode("utf-8")
        chunks = [raw[start:start + 255] for start in range(0, len(raw), 255)] or [b""]
        return " ".join(_quoted(chunk) for chunk in chunks)
    if rtype == "SRV":
        return (f"{int(data['priority'])} {int(data['weight'])} {int(data['port'])} "
                f"{_fqdn(str(data['target']))}")
    if rtype == "CAA":
        return f"{int(data['flags'])} {str(data['tag']).lower()} " + _quoted(
            str(data["value"]).encode("utf-8"))
    if rtype == "SOA":
        return (f"{_fqdn(str(data['mname']))} {_fqdn(str(data['rname']))} 0 "
                f"{int(data['refresh'])} {int(data['retry'])} {int(data['expire'])} "
                f"{int(data['minimum'])}")
    raise ValueError(f"unsupported type {rtype}")


def zone_line(zone: str, record: dict[str, Any], default_ttl: int = 3600) -> str:
    rtype = str(record["type"]).upper()
    ttl = record.get("ttl")
    ttl = ttl if isinstance(ttl, int) and not isinstance(ttl, bool) else default_ttl
    data = record.get("data") if isinstance(record.get("data"), dict) else {}
    return f"{_owner(str(record['name']), zone)} {ttl} IN {rtype} {rdata(rtype, data)}"


def zone_text(zone: str, records: list[dict[str, Any]],
              soa: dict[str, Any] | None = None) -> str:
    lines = [f"; MRK domain template for {zone}", f"$ORIGIN {zone}."]
    if soa is not None:
        lines.append(zone_line(zone, {"name": "@", "type": "SOA", **soa}))
    lines.extend(zone_line(zone, record) for record in records)
    return "\n".join(lines) + "\n"
