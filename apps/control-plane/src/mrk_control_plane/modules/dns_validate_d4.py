"""Panel-side checks for the D4 DNS inputs (docs/40 §2, §3, §5).

* ``d4_settings_errors``: the ``resolution`` / ``dnssec`` / ``encrypted`` sections
  of the engine settings object (field errors, same shape as D1/D2).
* ``resolve_flags``: the new ``dnssec`` / ``cd`` / ``trace`` / ``no_cache`` inputs.
* ``tls_upload_body`` / ``self_signed_body``: certificate inputs (the private key
  is only checked for shape and size here; it never appears in errors or logs).
* ``token_create_body`` / ``token_patch_body``: DoH access tokens.
* ``apple_profile_body`` + ``apple_profile``: an unsigned ``.mobileconfig`` with a
  ``com.apple.dnsSettings.managed`` payload.

The engine validates everything again; these checks give precise ``fields`` early
and keep dangerous values (an open resolver, a public plain-HTTP DoH listener)
from being forwarded at all.
"""

from __future__ import annotations

import ipaddress
import plistlib
import re
import uuid
from datetime import datetime
from typing import Any
from urllib.parse import urlsplit

from .dns_validate import DnsInputError, _host_port, name_problem

RESOLUTION_MODES = ("forward", "recursive", "forward_then_recursive")
QNAME_MIN = ("off", "relaxed", "strict")
IP_VERSIONS = ("ipv4", "ipv6", "both")
DNSSEC_MODES = ("off", "validate", "log_only")
MAX_ROOT_HINTS = 26
MAX_NTAS = 500
MAX_LISTEN = 16
RESOLUTION_RANGES: dict[str, tuple[int, int]] = {
    "max_referrals": (1, 64),
    "max_queries_per_resolution": (10, 500),
    "max_ns_per_zone": (1, 32),
    "query_timeout_ms": (200, 10_000),
    "resolve_timeout_ms": (1000, 30_000),
    "infra_cache_entries": (100, 1_000_000),
}
DNSSEC_RANGES: dict[str, tuple[int, int]] = {
    "nsec3_max_iterations": (0, 2500),
    "bogus_ttl": (0, 3600),
    "sig_skew_seconds": (0, 86400),
}
ENCRYPTED_RANGES: dict[str, tuple[int, int]] = {
    "max_connections": (10, 100_000),
    "max_connections_per_client": (1, 10_000),
    "idle_timeout_ms": (1000, 600_000),
    "max_streams_per_connection": (1, 1000),
    "handshake_timeout_ms": (500, 30_000),
}
RESOLUTION_KEYS = {"mode", "qname_minimization", "ip_versions", "case_randomization",
                   "root_hints", "allow_private_ns", *RESOLUTION_RANGES}
DNSSEC_KEYS = {"mode", "trust_anchor_auto_update", "negative_trust_anchors",
               "auto_insecure_local", "aggressive_nsec", *DNSSEC_RANGES}
ENCRYPTED_KEYS = {"dot", "doq", "doh", "allow", *ENCRYPTED_RANGES}
LISTENER_KEYS = {"enabled", "listen"}
DOH_KEYS = {"enabled", "listen", "tls", "path", "allow_get", "trusted_proxies"}
# Default ports per encrypted protocol (docs/40 §2.3).
DEFAULT_PORTS = {"dot": 853, "doq": 853, "doh": 443}
# The transport each protocol binds (dot and doq may share :853).
TRANSPORT = {"dot": "tcp", "doq": "udp", "doh": "tcp"}

TOKEN_NAME_MAX = 64
TOKEN_QPS = (1, 10_000)
TLS_MAX_BYTES = 64 * 1024
SELF_SIGNED_MAX_NAMES = 20
PROFILE_NAME_MAX = 64
_DOH_PATH = re.compile(r"^/[A-Za-z0-9._~\-/]{0,127}$")
_URL_PATH = re.compile(r"^/[A-Za-z0-9._~\-/%]{0,255}$")
_PEM_CERT = "-----BEGIN CERTIFICATE-----"
_PEM_KEY = re.compile(r"-----BEGIN (?:RSA |EC |ENCRYPTED )?PRIVATE KEY-----")


def _field(field: str, reason: str, **params: Any) -> dict[str, Any]:
    item: dict[str, Any] = {"field": field, "reason_code": reason}
    if params:
        item["params"] = params
    return item


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _ranges(section: dict[str, Any], prefix: str, ranges: dict[str, tuple[int, int]],
            errors: list[dict[str, Any]]) -> None:
    for key, (low, high) in ranges.items():
        if key in section and not (_is_int(section[key]) and low <= section[key] <= high):
            errors.append(_field(f"{prefix}.{key}", "out_of_range", min=low, max=high))


def _flags(section: dict[str, Any], prefix: str, keys: tuple[str, ...],
           errors: list[dict[str, Any]]) -> None:
    for key in keys:
        if key in section and not isinstance(section[key], bool):
            errors.append(_field(f"{prefix}.{key}", "invalid_type"))


def _unknown(section: dict[str, Any], prefix: str, allowed: set[str],
             errors: list[dict[str, Any]]) -> None:
    for key in sorted(set(section) - allowed)[:10]:
        errors.append(_field(f"{prefix}.{str(key)[:40]}", "unknown_field"))


def _choice(section: dict[str, Any], prefix: str, key: str, choices: tuple[str, ...],
            errors: list[dict[str, Any]]) -> None:
    if key in section and section[key] not in choices:
        errors.append(_field(f"{prefix}.{key}", "invalid_choice", choices=list(choices)))


def _section(payload: dict[str, Any], key: str,
             errors: list[dict[str, Any]]) -> dict[str, Any] | None:
    if key not in payload or payload[key] is None:
        return None
    if not isinstance(payload[key], dict):
        errors.append(_field(key, "invalid_type"))
        return None
    return payload[key]


def rfc3339(raw: str) -> datetime | None:
    """An RFC 3339 time with a zone, else None."""
    text = raw.strip()
    if not text or len(text) > 40 or "T" not in text.upper():
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00").replace("z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else None


# ----------------------------------------------------------------------------- resolution


def _root_hints(value: Any, errors: list[dict[str, Any]]) -> None:
    field = "resolution.root_hints"
    if not isinstance(value, list):
        errors.append(_field(field, "invalid_type"))
        return
    if len(value) > MAX_ROOT_HINTS:
        errors.append(_field(field, "too_many", max=MAX_ROOT_HINTS))
        return
    seen: set[str] = set()
    for index, item in enumerate(value):
        prefix = f"{field}.{index}"
        if not isinstance(item, dict):
            errors.append(_field(prefix, "invalid_type"))
            continue
        _unknown(item, prefix, {"name", "ipv4", "ipv6"}, errors)
        name, problem = name_problem(item.get("name"), allow_underscore=False,
                                     allow_wildcard=False)
        if problem or name is None:
            errors.append(_field(f"{prefix}.name", "invalid_name"))
        elif name in seen:
            errors.append(_field(f"{prefix}.name", "duplicate"))
        else:
            seen.add(name)
        ipv4, ipv6 = item.get("ipv4"), item.get("ipv6")
        if ipv4 in (None, "") and ipv6 in (None, ""):
            errors.append(_field(prefix, "address_required"))
        for key, version in (("ipv4", 4), ("ipv6", 6)):
            raw = item.get(key)
            if raw in (None, ""):
                continue
            try:
                address = ipaddress.ip_address(raw.strip()) if isinstance(raw, str) else None
            except ValueError:
                address = None
            if address is None or address.version != version:
                errors.append(_field(f"{prefix}.{key}", "invalid_address"))


def _resolution(payload: dict[str, Any], errors: list[dict[str, Any]]) -> None:
    section = _section(payload, "resolution", errors)
    if section is None:
        return
    prefix = "resolution"
    _unknown(section, prefix, RESOLUTION_KEYS, errors)
    _choice(section, prefix, "mode", RESOLUTION_MODES, errors)
    _choice(section, prefix, "qname_minimization", QNAME_MIN, errors)
    _choice(section, prefix, "ip_versions", IP_VERSIONS, errors)
    _flags(section, prefix, ("case_randomization", "allow_private_ns"), errors)
    _ranges(section, prefix, RESOLUTION_RANGES, errors)
    if "root_hints" in section:
        _root_hints(section["root_hints"], errors)
    query, total = section.get("query_timeout_ms"), section.get("resolve_timeout_ms")
    if _is_int(query) and _is_int(total) and total < query:
        errors.append(_field("resolution.resolve_timeout_ms", "less_than_query_timeout"))


# ----------------------------------------------------------------------------- dnssec


def _ntas(value: Any, errors: list[dict[str, Any]]) -> None:
    field = "dnssec.negative_trust_anchors"
    if not isinstance(value, list):
        errors.append(_field(field, "invalid_type"))
        return
    if len(value) > MAX_NTAS:
        errors.append(_field(field, "too_many", max=MAX_NTAS))
        return
    seen: set[str] = set()
    for index, item in enumerate(value):
        prefix = f"{field}.{index}"
        if not isinstance(item, dict):
            errors.append(_field(prefix, "invalid_type"))
            continue
        _unknown(item, prefix, {"domain", "reason", "expires_at"}, errors)
        domain, problem = name_problem(item.get("domain"), allow_underscore=True,
                                       allow_wildcard=False)
        if problem or domain is None:
            errors.append(_field(f"{prefix}.domain", "invalid_name"))
        elif domain in seen:
            errors.append(_field(f"{prefix}.domain", "duplicate"))
        else:
            seen.add(domain)
        reason = item.get("reason")
        if reason is not None:
            if not isinstance(reason, str) or any(ord(ch) < 32 for ch in reason):
                errors.append(_field(f"{prefix}.reason", "invalid_format"))
            elif len(reason) > 256:
                errors.append(_field(f"{prefix}.reason", "too_long", max=256))
        expires = item.get("expires_at")
        if expires not in (None, "") and (not isinstance(expires, str) or rfc3339(expires)
                                          is None):
            errors.append(_field(f"{prefix}.expires_at", "invalid_time"))


def _dnssec(payload: dict[str, Any], errors: list[dict[str, Any]]) -> None:
    section = _section(payload, "dnssec", errors)
    if section is None:
        return
    prefix = "dnssec"
    _unknown(section, prefix, DNSSEC_KEYS, errors)
    _choice(section, prefix, "mode", DNSSEC_MODES, errors)
    _flags(section, prefix, ("trust_anchor_auto_update", "auto_insecure_local",
                             "aggressive_nsec"), errors)
    _ranges(section, prefix, DNSSEC_RANGES, errors)
    if "negative_trust_anchors" in section:
        _ntas(section["negative_trust_anchors"], errors)


# ----------------------------------------------------------------------------- encrypted


def listen_on(value: Any, default_port: int) -> tuple[ipaddress.IPv4Address
                                                       | ipaddress.IPv6Address, int]:
    """``ip:port`` / ``[ip6]:port`` / bare IP -> (address, port); ValueError when invalid."""
    host, port = _host_port(value, default_port)
    return ipaddress.ip_address(host), port


def private_listen(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Loopback or a private / Docker network (never the unspecified address)."""
    if address.is_unspecified:
        return False
    return bool(address.is_loopback or address.is_private or address.is_link_local)


def _cidr_list(value: Any, field: str, errors: list[dict[str, Any]], *,
               open_check: bool, broad_reason: str = "open_resolver") -> None:
    if not isinstance(value, list) or len(value) > 256:
        errors.append(_field(field, "invalid_type"))
        return
    for index, item in enumerate(value):
        try:
            if not isinstance(item, str):
                raise ValueError("invalid")
            network = ipaddress.ip_network(item.strip(), strict=False)
        except ValueError:
            errors.append(_field(f"{field}.{index}", "invalid_cidr"))
            continue
        if open_check and network.prefixlen == 0:
            errors.append(_field(f"{field}.{index}", broad_reason))


def _listener(section: dict[str, Any], proto: str, errors: list[dict[str, Any]],
              taken: dict[tuple[str, str, int], str]) -> list[tuple[Any, int]]:
    prefix = f"encrypted.{proto}"
    _unknown(section, prefix, DOH_KEYS if proto == "doh" else LISTENER_KEYS, errors)
    _flags(section, prefix, ("enabled",), errors)
    addresses: list[tuple[Any, int]] = []
    if "listen" not in section:
        return addresses
    listen = section["listen"]
    if not isinstance(listen, list) or len(listen) > MAX_LISTEN or (
        section.get("enabled") is True and not listen
    ):
        errors.append(_field(f"{prefix}.listen", "invalid_type", max=MAX_LISTEN))
        return addresses
    for index, item in enumerate(listen):
        field = f"{prefix}.listen.{index}"
        try:
            address, port = listen_on(item, DEFAULT_PORTS[proto])
        except ValueError:
            errors.append(_field(field, "invalid_address"))
            continue
        if _conflict(taken, TRANSPORT[proto], address, port, f"{prefix}.listen"):
            errors.append(_field(field, "listen_conflict"))
        addresses.append((address, port))
    return addresses


def _conflict(taken: dict[tuple[str, str, int], str], transport: str, address: Any,
              port: int, owner: str) -> bool:
    """True when ``transport`` ``address:port`` is already bound by another list (an
    unspecified address of the same family overlaps every address of it)."""
    found = False
    for other_transport, other, other_port in taken:
        if other_transport != transport or other_port != port:
            continue
        other_address = ipaddress.ip_address(other)
        if other_address.version == address.version and (
            other_address == address or other_address.is_unspecified or address.is_unspecified
        ):
            found = True
            break
    taken.setdefault((transport, str(address), port), owner)
    return found


def _main_listen(payload: dict[str, Any]) -> dict[tuple[str, str, int], str]:
    """Plain DNS listeners (``listen``) as taken (transport, address, port) slots."""
    taken: dict[tuple[str, str, int], str] = {}
    for item in payload.get("listen") or [] if isinstance(payload.get("listen"), list) else []:
        if not isinstance(item, dict):
            continue
        try:
            address, port = listen_on(item.get("address"), 53)
        except ValueError:
            continue
        for transport in ("udp", "tcp"):
            if item.get(transport, True) is not False:
                taken[(transport, str(address), port)] = "listen"
    return taken


def _encrypted(payload: dict[str, Any], errors: list[dict[str, Any]]) -> None:
    section = _section(payload, "encrypted", errors)
    if section is None:
        return
    prefix = "encrypted"
    _unknown(section, prefix, ENCRYPTED_KEYS, errors)
    _ranges(section, prefix, ENCRYPTED_RANGES, errors)
    if section.get("allow") is not None:
        _cidr_list(section["allow"], "encrypted.allow", errors, open_check=True)
    taken = _main_listen(payload)
    for proto in ("dot", "doq", "doh"):
        sub = section.get(proto)
        if sub is None:
            continue
        if not isinstance(sub, dict):
            errors.append(_field(f"{prefix}.{proto}", "invalid_type"))
            continue
        addresses = _listener(sub, proto, errors, taken)
        if proto != "doh":
            continue
        _flags(sub, "encrypted.doh", ("tls", "allow_get"), errors)
        if "path" in sub and (not isinstance(sub["path"], str)
                              or not _DOH_PATH.fullmatch(sub["path"])
                              or "//" in sub["path"] or "/." in sub["path"]
                              or (len(sub["path"]) > 1 and sub["path"].endswith("/"))):
            errors.append(_field("encrypted.doh.path", "invalid_format"))
        if "trusted_proxies" in sub:
            _cidr_list(sub["trusted_proxies"], "encrypted.doh.trusted_proxies", errors,
                       open_check=True, broad_reason="too_broad")
        if sub.get("tls") is False:
            # Plain HTTP only behind a local reverse proxy (Traefik/Dokploy).
            for index, (address, _port) in enumerate(addresses):
                if not private_listen(address):
                    errors.append(_field(f"encrypted.doh.listen.{index}", "plain_doh_public"))


def d4_settings_errors(payload: dict[str, Any]) -> list[dict[str, Any]]:
    """Field errors for the resolution / dnssec / encrypted sections (docs/40 §2)."""
    errors: list[dict[str, Any]] = []
    _resolution(payload, errors)
    _dnssec(payload, errors)
    _encrypted(payload, errors)
    return errors


# ----------------------------------------------------------------------------- warnings


def _networks(value: Any) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    networks = []
    for item in value if isinstance(value, list) else []:
        try:
            networks.append(ipaddress.ip_network(str(item).strip(), strict=False))
        except ValueError:
            continue
    return networks


def effective_allow(settings: dict[str, Any]) -> list[Any]:
    encrypted = settings.get("encrypted") if isinstance(settings.get("encrypted"), dict) else {}
    allow = encrypted.get("allow")
    if allow is None:
        recursion = settings.get("recursion") if isinstance(settings.get("recursion"),
                                                            dict) else {}
        allow = recursion.get("allow")
    return _networks(allow)


def only_private(networks: list[Any]) -> bool:
    return all(net.is_private or net.is_loopback or net.is_link_local for net in networks)


def doh_public(settings: dict[str, Any], plain_domains: int) -> bool:
    """DoH reachable from the Internet: TLS on a public/unspecified address, or plain
    HTTP published through a Traefik domain (``dns-doh`` service)."""
    doh = section_of(settings, "doh")
    if doh.get("enabled") is not True:
        return False
    if doh.get("tls", True) is False:
        return plain_domains > 0
    for item in doh.get("listen") or []:
        try:
            address, _port = listen_on(item, 443)
        except ValueError:
            continue
        if not private_listen(address):
            return True
    return False


def section_of(settings: dict[str, Any], proto: str) -> dict[str, Any]:
    encrypted = settings.get("encrypted") if isinstance(settings.get("encrypted"), dict) else {}
    value = encrypted.get(proto)
    return value if isinstance(value, dict) else {}


def tls_listeners_enabled(settings: dict[str, Any]) -> bool:
    if section_of(settings, "dot").get("enabled") is True:
        return True
    if section_of(settings, "doq").get("enabled") is True:
        return True
    doh = section_of(settings, "doh")
    return doh.get("enabled") is True and doh.get("tls", True) is not False


def settings_warnings(
    settings: dict[str, Any], *, tokens: int | None, certificate: dict[str, Any] | None,
    plain_domains: int,
) -> list[dict[str, str]]:
    """Non-blocking advice for a settings document (docs/40 §5)."""
    warnings: list[dict[str, str]] = []
    resolution = settings.get("resolution") if isinstance(settings.get("resolution"),
                                                          dict) else {}
    if resolution.get("mode") in {"recursive", "forward_then_recursive"}:
        warnings.append({"code": "recursive_needs_outbound_53"})
    if tokens == 0 and doh_public(settings, plain_domains) and only_private(
        effective_allow(settings)
    ):
        warnings.append({"code": "doh_public_needs_token"})
    if tls_listeners_enabled(settings) and isinstance(certificate, dict) and (
        certificate.get("present") and (certificate.get("self_signed")
                                        or certificate.get("source") == "self_signed")
    ):
        warnings.append({"code": "self_signed_certificate"})
    return warnings


# ----------------------------------------------------------------------------- resolve


def resolve_flags(payload: dict[str, Any]) -> dict[str, bool]:
    """The D4 switches of ``POST resolve`` (only the ones given are forwarded)."""
    flags: dict[str, bool] = {}
    errors = []
    for key in ("dnssec", "cd", "trace", "no_cache"):
        if key not in payload or payload[key] is None:
            continue
        if not isinstance(payload[key], bool):
            errors.append(_field(key, "invalid_type"))
        else:
            flags[key] = payload[key]
    if errors:
        raise DnsInputError("dns_record_invalid", "Some switches are invalid", errors)
    return flags


# ----------------------------------------------------------------------------- tls


def _object(payload: Any, code: str, allowed: set[str]) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise DnsInputError(code, "The request must be an object",
                            [_field("body", "invalid_type")])
    unknown = sorted(set(payload) - allowed)
    if unknown:
        raise DnsInputError(code, "Unknown fields",
                            [_field(str(name)[:40], "unknown_field") for name in unknown[:10]])
    return payload


def tls_upload_body(payload: Any) -> dict[str, str]:
    """{cert_pem, key_pem}: PEM shape and the 64 KiB cap; the engine checks the rest."""
    body = _object(payload, "dns_tls_invalid", {"cert_pem", "key_pem"})
    errors = []
    for key, marker in (("cert_pem", _PEM_CERT), ("key_pem", None)):
        value = body.get(key)
        if not isinstance(value, str) or not value.strip():
            errors.append(_field(key, "required"))
        elif len(value.encode("utf-8", errors="replace")) > TLS_MAX_BYTES:
            errors.append(_field(key, "too_large", max_bytes=TLS_MAX_BYTES))
        elif not value.isascii() or (marker and marker not in value) or (
            marker is None and not _PEM_KEY.search(value)
        ):
            errors.append(_field(key, "bad_pem"))
    if errors:
        raise DnsInputError("dns_tls_invalid", "The certificate or key is not valid", errors)
    return {"cert_pem": body["cert_pem"], "key_pem": body["key_pem"]}


def certificate_name(raw: Any) -> tuple[str | None, str | None]:
    """(canonical, None) for a host name (``*.`` allowed) or IP, else (None, reason)."""
    if not isinstance(raw, str):
        return None, "invalid_type"
    text = raw.strip()
    try:
        return str(ipaddress.ip_address(text)), None
    except ValueError:
        pass
    name, problem = name_problem(text, allow_underscore=False, allow_wildcard=True)
    return name, problem


def self_signed_body(payload: Any) -> dict[str, list[str]]:
    body = _object(payload, "dns_tls_invalid", {"names"})
    names = body.get("names")
    if not isinstance(names, list) or not names:
        raise DnsInputError("dns_tls_invalid", "Enter at least one name",
                            [_field("names", "required")])
    if len(names) > SELF_SIGNED_MAX_NAMES:
        raise DnsInputError("dns_tls_invalid", "Too many names",
                            [_field("names", "too_many", max=SELF_SIGNED_MAX_NAMES)])
    clean: list[str] = []
    errors = []
    for index, item in enumerate(names):
        name, problem = certificate_name(item)
        if problem or name is None:
            errors.append(_field(f"names.{index}", problem or "invalid_format"))
        elif name not in clean:
            clean.append(name)
    if errors:
        raise DnsInputError("dns_tls_invalid", "Some names are invalid", errors)
    return {"names": clean}


# ----------------------------------------------------------------------------- tokens


def _token_name(value: Any, errors: list[dict[str, Any]]) -> str | None:
    if not isinstance(value, str) or not value.strip():
        errors.append(_field("name", "required"))
        return None
    text = value.strip()
    if len(text) > TOKEN_NAME_MAX:
        errors.append(_field("name", "too_long", max=TOKEN_NAME_MAX))
        return None
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in text):
        errors.append(_field("name", "invalid_format"))
        return None
    return text


def _token_qps(value: Any, errors: list[dict[str, Any]]) -> int | None:
    low, high = TOKEN_QPS
    if not _is_int(value) or not low <= value <= high:
        errors.append(_field("qps", "out_of_range", min=low, max=high))
        return None
    return int(value)


def token_create_body(payload: Any) -> dict[str, Any]:
    body = _object(payload, "dns_token_invalid", {"name", "qps"})
    errors: list[dict[str, Any]] = []
    out: dict[str, Any] = {"name": _token_name(body.get("name"), errors)}
    if body.get("qps") is not None:
        out["qps"] = _token_qps(body["qps"], errors)
    if errors:
        raise DnsInputError("dns_token_invalid", "The token is not valid", errors)
    return out


def token_patch_body(payload: Any) -> dict[str, Any]:
    body = _object(payload, "dns_token_invalid", {"name", "qps"})
    if not body:
        raise DnsInputError("dns_token_invalid", "Nothing to change",
                            [_field("body", "required")])
    errors: list[dict[str, Any]] = []
    out: dict[str, Any] = {}
    if "name" in body:
        out["name"] = _token_name(body["name"], errors)
    if "qps" in body:
        out["qps"] = _token_qps(body["qps"], errors)
    if errors:
        raise DnsInputError("dns_token_invalid", "The token is not valid", errors)
    return out


# ----------------------------------------------------------------------------- apple profile


def https_url(raw: Any) -> tuple[str | None, str | None]:
    """A DoH server URL: https, host name or IP, optional port and path, nothing else."""
    if not isinstance(raw, str):
        return None, "invalid_type"
    text = raw.strip()
    if not text:
        return None, "required"
    if len(text) > 512 or not text.isascii() or any(ch.isspace() or ord(ch) < 33
                                                    for ch in text):
        return None, "invalid_url"
    try:
        parts = urlsplit(text)
        port = parts.port
    except ValueError:
        return None, "invalid_url"
    if parts.scheme != "https" or not parts.hostname or parts.username or parts.password:
        return None, "invalid_url"
    if parts.query or parts.fragment or "@" in parts.netloc:
        return None, "invalid_url"
    host = parts.hostname
    try:
        address = ipaddress.ip_address(host)
        host_text = f"[{address}]" if address.version == 6 else str(address)
    except ValueError:
        name, problem = name_problem(host, allow_underscore=False, allow_wildcard=False)
        if problem or name is None:
            return None, "invalid_url"
        host_text = name
    path = parts.path or "/dns-query"
    if not _URL_PATH.fullmatch(path) or ".." in path:
        return None, "invalid_url"
    netloc = host_text if port in (None, 443) else f"{host_text}:{port}"
    return f"https://{netloc}{path}", None


def server_name(raw: Any) -> tuple[str | None, str | None]:
    """A DoT server name (a host name; Apple's ServerName is checked against the cert)."""
    name, problem = name_problem(raw, allow_underscore=False, allow_wildcard=False)
    if problem == "ip_not_allowed":
        return None, "hostname_required"
    return name, problem


def apple_profile_body(payload: Any) -> dict[str, str | None]:
    body = _object(payload, "dns_profile_invalid", {"doh_url", "dot_name", "name"})
    errors: list[dict[str, Any]] = []
    out: dict[str, str | None] = {"doh_url": None, "dot_name": None, "name": None}
    if body.get("doh_url") not in (None, ""):
        out["doh_url"], problem = https_url(body["doh_url"])
        if problem:
            errors.append(_field("doh_url", problem))
    if body.get("dot_name") not in (None, ""):
        out["dot_name"], problem = server_name(body["dot_name"])
        if problem:
            errors.append(_field("dot_name", problem))
    name = body.get("name")
    if name not in (None, ""):
        if not isinstance(name, str) or len(name.strip()) > PROFILE_NAME_MAX or any(
            ord(ch) < 32 or ord(ch) == 127 for ch in name
        ):
            errors.append(_field("name", "invalid_format", max=PROFILE_NAME_MAX))
        else:
            out["name"] = name.strip()
    if errors:
        raise DnsInputError("dns_profile_invalid", "The profile inputs are not valid", errors)
    return out


def apple_profile(*, doh_url: str | None, dot_name: str | None, name: str | None,
                  addresses: list[str] | None = None) -> bytes:
    """An unsigned configuration profile with one ``com.apple.dnsSettings.managed``
    payload (DoH when ``doh_url`` is given, else DoT). Built with plistlib, so every
    value is escaped."""
    if not doh_url and not dot_name:
        raise ValueError("doh_url or dot_name is required")
    title = name or "Pishkar DNS"
    settings: dict[str, Any]
    if doh_url:
        settings = {"DNSProtocol": "HTTPS", "ServerURL": doh_url}
    else:
        settings = {"DNSProtocol": "TLS", "ServerName": dot_name}
    if addresses:
        settings["ServerAddresses"] = list(addresses)
    inner_uuid = str(uuid.uuid4()).upper()
    outer_uuid = str(uuid.uuid4()).upper()
    payload = {
        "PayloadType": "com.apple.dnsSettings.managed",
        "PayloadVersion": 1,
        "PayloadIdentifier": f"com.mrk.devassist.dns.settings.{inner_uuid}",
        "PayloadUUID": inner_uuid,
        "PayloadDisplayName": title,
        "PayloadDescription": "Encrypted DNS through Pishkar DevAssist",
        "DNSSettings": settings,
    }
    document = {
        "PayloadType": "Configuration",
        "PayloadVersion": 1,
        "PayloadIdentifier": f"com.mrk.devassist.dns.{outer_uuid}",
        "PayloadUUID": outer_uuid,
        "PayloadDisplayName": title,
        "PayloadDescription": "Sends this device's DNS queries to Pishkar DevAssist, encrypted.",
        "PayloadOrganization": "Pishkar DevAssist",
        "PayloadRemovalDisallowed": False,
        "PayloadContent": [payload],
    }
    return plistlib.dumps(document, fmt=plistlib.FMT_XML, sort_keys=True)
