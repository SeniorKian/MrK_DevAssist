"""Panel-side checks for the D2 DNS query-log filters and mitigations (docs/38 §3-§4).

Filters arrive as query parameters and are forwarded to the engine in canonical
form (times as unix milliseconds, client as canonical IP/CIDR, names
lowercase IDNA). Anything unknown or malformed is refused with
``dns_query_invalid`` (422) and per-field ``fields`` before the engine sees it.
"""

from __future__ import annotations

import ipaddress
import re
import time
from datetime import datetime
from typing import Any
from urllib.parse import urlencode

from .dns_validate import DnsInputError, name_problem

FILTER_KEYS = ("from", "to", "client", "name", "qtype", "rcode", "source", "blocked", "min_ms",
               "dnssec", "proto")
SOURCES = ("authoritative", "override", "cache", "upstream", "refused", "rate_limited",
           "mitigated", "forwarder", "recursive")
PROTOS = ("udp", "tcp", "dot", "doh", "doq")
DNSSEC_STATES = ("secure", "insecure", "bogus", "none")
RCODES = ("NOERROR", "NXDOMAIN", "SERVFAIL", "REFUSED", "FORMERR", "NOTIMP", "YXDOMAIN",
          "YXRRSET", "NXRRSET", "NOTAUTH", "NOTZONE", "BADVERS")
QTYPES = ("A", "AAAA", "CNAME", "MX", "TXT", "SRV", "NS", "PTR", "CAA", "SOA", "ANY", "HTTPS",
          "SVCB", "DS", "DNSKEY", "RRSIG", "NSEC", "NSEC3", "NAPTR", "TLSA", "SSHFP", "AXFR",
          "IXFR", "HINFO", "NULL", "OPT")
STATS_RANGES = ("1h", "6h", "24h", "7d", "30d", "1y")
EXPORT_FORMATS = ("ndjson", "csv")
MITIGATION_KINDS = ("client", "domain")
MITIGATION_ACTIONS = ("throttle", "block", "refuse")
SEARCH_LIMIT_MAX = 1000
SEARCH_LIMIT_DEFAULT = 100
EXPORT_LIMIT_MAX = 1_000_000
MIN_MS_MAX = 600_000
MITIGATION_MINUTES = (1, 10080)
MITIGATION_QPS = (1, 1_000_000)
DELETE_CONFIRMATION = "DELETE LOGS"
# A timestamp before 2000-01-01 or more than a day ahead is a typo, not a filter.
_TS_MIN_MS = 946_684_800_000
_CURSOR = re.compile(r"^[A-Za-z0-9_\-=.:~+/]{1,512}$")
_QTYPE_NUMBER = re.compile(r"^TYPE\d{1,5}$")


def _field(field: str, reason: str, **params: Any) -> dict[str, Any]:
    item: dict[str, Any] = {"field": field, "reason_code": reason}
    if params:
        item["params"] = params
    return item


def _fail(fields: list[dict[str, Any]], message: str = "Some filters are invalid") -> None:
    raise DnsInputError("dns_query_invalid", message, fields[:50])


def parse_time_ms(raw: str) -> int | None:
    """Unix milliseconds (digits) or RFC 3339 -> unix ms; None when invalid."""
    text = raw.strip()
    if not text or len(text) > 40:
        return None
    if text.isdigit():
        value = int(text)
    else:
        try:
            parsed = datetime.fromisoformat(text.replace("Z", "+00:00").replace("z", "+00:00"))
        except ValueError:
            return None
        if parsed.tzinfo is None:
            return None
        value = int(parsed.timestamp() * 1000)
    if value < _TS_MIN_MS or value > int(time.time() * 1000) + 86_400_000:
        return None
    return value


def client_match(raw: Any) -> str | None:
    """Canonical IP or CIDR (host bits cleared), else None."""
    if not isinstance(raw, str) or not raw.strip() or len(raw) > 64:
        return None
    text = raw.strip()
    try:
        if "/" in text:
            return str(ipaddress.ip_network(text, strict=False))
        return str(ipaddress.ip_address(text))
    except ValueError:
        return None


def name_filter(raw: str) -> str | None:
    """A substring of a name, or a suffix written ``*.example.com``."""
    text = raw.strip().lower()
    if not text or len(text) > 253 or any(ch.isspace() or ord(ch) < 32 for ch in text):
        return None
    suffix = text.startswith("*.")
    body = text[2:] if suffix else text
    if body.endswith("."):
        body = body[:-1]
    if not body or "*" in body:
        return None
    if not body.isascii():
        canonical, problem = name_problem(body, allow_underscore=True, allow_wildcard=False)
        if problem or canonical is None:
            return None
        body = canonical
    if not re.fullmatch(r"[a-z0-9_.-]+", body):
        return None
    return f"*.{body}" if suffix else body


def query_filters(
    params: Any, *, mode: str = "search"
) -> dict[str, str]:
    """Validate query-log filters; ``mode`` is search | stream | export.

    Returns the canonical parameters to forward (all strings).
    """
    allowed = set(FILTER_KEYS)
    if mode == "search":
        allowed |= {"limit", "cursor"}
    elif mode == "export":
        allowed |= {"limit", "format"}
    errors: list[dict[str, Any]] = []
    out: dict[str, str] = {}
    pairs = params.multi_items() if hasattr(params, "multi_items") else list(params.items())
    keys = [key for key, _value in pairs]
    for key in dict.fromkeys(keys):
        if key == "_":  # cache buster
            continue
        if key not in allowed:
            errors.append(_field(key[:40], "unknown_field"))
        elif keys.count(key) > 1:
            errors.append(_field(key, "duplicate"))
    if errors:
        _fail(errors)
    get = params.get
    for key in ("from", "to"):
        raw = get(key)
        if raw in (None, ""):
            continue
        value = parse_time_ms(raw)
        if value is None:
            errors.append(_field(key, "invalid_time"))
        else:
            out[key] = str(value)
    if "from" in out and "to" in out and int(out["from"]) > int(out["to"]):
        errors.append(_field("from", "after_to"))
    raw = get("client")
    if raw not in (None, ""):
        value = client_match(raw)
        if value is None:
            errors.append(_field("client", "invalid_client"))
        else:
            out["client"] = value
    raw = get("name")
    if raw not in (None, ""):
        value = name_filter(raw)
        if value is None:
            errors.append(_field("name", "invalid_name"))
        else:
            out["name"] = value
    raw = get("qtype")
    if raw not in (None, ""):
        value = raw.strip().upper()
        if value in QTYPES or _QTYPE_NUMBER.fullmatch(value):
            out["qtype"] = value
        else:
            errors.append(_field("qtype", "invalid_choice", choices=list(QTYPES)))
    raw = get("rcode")
    if raw not in (None, ""):
        value = raw.strip().upper()
        if value in RCODES:
            out["rcode"] = value
        else:
            errors.append(_field("rcode", "invalid_choice", choices=list(RCODES)))
    raw = get("source")
    if raw not in (None, ""):
        value = raw.strip().lower()
        if value in SOURCES:
            out["source"] = value
        else:
            errors.append(_field("source", "invalid_choice", choices=list(SOURCES)))
    for key, choices in (("proto", PROTOS), ("dnssec", DNSSEC_STATES)):
        raw = get(key)
        if raw not in (None, ""):
            value = raw.strip().lower()
            if value in choices:
                out[key] = value
            else:
                errors.append(_field(key, "invalid_choice", choices=list(choices)))
    raw = get("blocked")
    if raw not in (None, ""):
        value = raw.strip().lower()
        if value in {"true", "1"}:
            out["blocked"] = "true"
        elif value in {"false", "0"}:
            out["blocked"] = "false"
        else:
            errors.append(_field("blocked", "invalid_type"))
    raw = get("min_ms")
    if raw not in (None, ""):
        if raw.strip().isdigit() and int(raw) <= MIN_MS_MAX:
            out["min_ms"] = str(int(raw))
        else:
            errors.append(_field("min_ms", "out_of_range", min=0, max=MIN_MS_MAX))
    if mode in {"search", "export"}:
        high = SEARCH_LIMIT_MAX if mode == "search" else EXPORT_LIMIT_MAX
        raw = get("limit")
        if raw in (None, ""):
            if mode == "search":
                out["limit"] = str(SEARCH_LIMIT_DEFAULT)
        elif raw.strip().isdigit() and 1 <= int(raw) <= high:
            out["limit"] = str(int(raw))
        else:
            errors.append(_field("limit", "out_of_range", min=1, max=high))
    if mode == "search":
        raw = get("cursor")
        if raw not in (None, ""):
            if _CURSOR.fullmatch(raw):
                out["cursor"] = raw
            else:
                errors.append(_field("cursor", "invalid_format"))
    if mode == "export":
        raw = (get("format") or "ndjson").strip().lower()
        if raw in EXPORT_FORMATS:
            out["format"] = raw
        else:
            errors.append(_field("format", "invalid_choice", choices=list(EXPORT_FORMATS)))
    if errors:
        _fail(errors)
    return out


def encode(params: dict[str, str]) -> str:
    return ("?" + urlencode(params)) if params else ""


def stats_range(raw: str | None) -> str:
    value = (raw or "24h").strip()
    if value not in STATS_RANGES:
        _fail([_field("range", "invalid_choice", choices=list(STATS_RANGES))])
    return value


def delete_body(payload: Any) -> tuple[dict[str, Any], str]:
    """(engine body {client?, before?}, expected confirmation)."""
    if not isinstance(payload, dict):
        _fail([_field("body", "invalid_type")], "The request must be an object")
    unknown = sorted(set(payload) - {"client", "before", "confirmation"})
    if unknown:
        _fail([_field(name[:40], "unknown_field") for name in unknown[:10]])
    errors: list[dict[str, Any]] = []
    body: dict[str, Any] = {}
    client = payload.get("client")
    if client not in (None, ""):
        value = client_match(client)
        if value is None:
            errors.append(_field("client", "invalid_client"))
        else:
            body["client"] = value
    before = payload.get("before")
    if before not in (None, ""):
        value_ms = None
        if isinstance(before, int) and not isinstance(before, bool):
            value_ms = parse_time_ms(str(before))
        elif isinstance(before, str):
            value_ms = parse_time_ms(before)
        if value_ms is None:
            errors.append(_field("before", "invalid_time"))
        else:
            body["before"] = value_ms
    if errors:
        _fail(errors)
    expected = body.get("client") or DELETE_CONFIRMATION
    return body, expected


def confirmation_ok(raw: Any, expected: str, client: str | None) -> bool:
    if not isinstance(raw, str):
        return False
    text = raw.strip()
    if text == DELETE_CONFIRMATION:
        return True
    if client is None:
        return False
    return client_match(text) == client or text == client


def mitigation_body(payload: Any) -> dict[str, Any]:
    """{kind, match, action, qps?, minutes, reason?} in canonical form."""
    if not isinstance(payload, dict):
        raise DnsInputError("dns_mitigation_invalid", "The request must be an object",
                            [_field("body", "invalid_type")])
    unknown = sorted(set(payload) - {"kind", "match", "action", "qps", "minutes", "reason"})
    if unknown:
        raise DnsInputError("dns_mitigation_invalid", "Unknown fields",
                            [_field(name[:40], "unknown_field") for name in unknown[:10]])
    errors: list[dict[str, Any]] = []
    kind = payload.get("kind")
    if kind not in MITIGATION_KINDS:
        errors.append(_field("kind", "invalid_choice", choices=list(MITIGATION_KINDS)))
    action = payload.get("action")
    if action not in MITIGATION_ACTIONS:
        errors.append(_field("action", "invalid_choice", choices=list(MITIGATION_ACTIONS)))
    match: str | None = None
    raw = payload.get("match")
    if kind == "client":
        match = client_match(raw)
        if match is None:
            errors.append(_field("match", "invalid_client"))
        elif ipaddress.ip_network(match, strict=False).prefixlen == 0:
            errors.append(_field("match", "too_broad"))
            match = None
    elif kind == "domain":
        text = raw.strip() if isinstance(raw, str) else raw
        if isinstance(text, str) and text.startswith("*."):
            text = text[2:]
        name, problem = name_problem(text, allow_underscore=True, allow_wildcard=False)
        if problem or name is None:
            errors.append(_field("match", problem or "invalid_name"))
        else:
            match = name
    minutes = payload.get("minutes")
    low, high = MITIGATION_MINUTES
    if isinstance(minutes, bool) or not isinstance(minutes, int) or not low <= minutes <= high:
        errors.append(_field("minutes", "out_of_range", min=low, max=high))
    qps = payload.get("qps")
    if action == "throttle":
        qlow, qhigh = MITIGATION_QPS
        if isinstance(qps, bool) or not isinstance(qps, int) or not qlow <= qps <= qhigh:
            errors.append(_field("qps", "out_of_range", min=qlow, max=qhigh))
    elif qps is not None:
        errors.append(_field("qps", "only_for_throttle"))
    reason = payload.get("reason")
    if reason is not None and (
        not isinstance(reason, str) or len(reason) > 200 or any(ord(ch) < 32 for ch in reason)
    ):
        errors.append(_field("reason", "invalid_format", max=200))
    if errors:
        raise DnsInputError("dns_mitigation_invalid", "The limit is not valid", errors)
    body: dict[str, Any] = {"kind": kind, "match": match, "action": action, "minutes": minutes}
    if action == "throttle":
        body["qps"] = qps
    if reason:
        body["reason"] = reason
    return body
