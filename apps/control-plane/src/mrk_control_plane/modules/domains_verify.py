"""Real checks for one service domain: DNS, TLS certificate and "does it reach us" (docs/35 §5).

``verify_domain`` returns the ``health`` object stored on the domain row::

    {"dns": {"ok", "addresses", "expected"},
     "tls": {"ok", "expires_at", "issuer", "hostname_match", "days_left"} | None,
     "reach": {"ok", "status_code", "matched_service"},
     "checked_at", "problem_code", "problems": [...]}

problem codes (first one wins as ``problem_code``): dns_missing, dns_wrong_ip,
unreachable, tls_missing, tls_invalid, wrong_service, tls_expiring.

Connections go straight to the resolved address (with the real Host/SNI), not
through an outbound proxy: the point is to see what the internet sees at the
server's own public address. Loopback, link-local (cloud metadata), multicast and
unspecified addresses are never contacted.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
import ssl
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC
from typing import Any

import httpx

from ..netresolve import DnsConfig, resolve_host

PROBLEM_ORDER = (
    "dns_missing",
    "dns_wrong_ip",
    "unreachable",
    "tls_missing",
    "tls_invalid",
    "wrong_service",
    "tls_expiring",
)
TIMEOUT_SECONDS = 6.0

# Path per service and how its answer is recognised.
PROBE_PATHS = {"panel": "/health/live", "npm": "/-/ping", "pypi": "/+api", "s3": "/",
               # docs/40 §5: an RFC 8484 GET for ". NS" (id 0, RD) on the default path.
               "dns-doh": "/dns-query?dns=AAABAAABAAAAAAAAAAACAAE"}


def identify(headers: httpx.Headers, body: bytes) -> str | None:
    """Which MRK service produced this response (None = not ours / unknown)."""
    if headers.get("x-mrk-service", "").strip().lower() == "panel":
        return "panel"
    if headers.get("content-type", "").split(";")[0].strip().lower() == "application/dns-message":
        return "dns-doh"
    if "verdaccio" in headers.get("x-powered-by", "").lower():
        return "npm"
    if headers.get("server", "").strip() == "MRK" and "x-amz-request-id" in headers:
        return "s3"
    if (
        b'"apiconfig"' in body[:4096]
        or "x-devpi-uuid" in headers
        or "x-devpi-server-version" in headers
    ):
        return "pypi"
    return None


@dataclass(slots=True)
class Probes:
    """Network operations, replaceable in tests."""

    resolve: Callable[[str], Awaitable[list[str]]]
    tls: Callable[[str, str], Awaitable[dict[str, Any]]]
    http: Callable[[str, str, str, bool], Awaitable[dict[str, Any]]]


def safe_target(address: str) -> bool:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return not (ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified)


def default_probes(dns: Callable[[], DnsConfig]) -> Probes:
    async def resolve(host: str) -> list[str]:
        try:
            return await asyncio.to_thread(resolve_host, host, 443, dns())
        except (OSError, UnicodeError):
            return []

    async def tls(host: str, address: str) -> dict[str, Any]:
        return await asyncio.to_thread(_tls_probe, host, address)

    async def http(host: str, address: str, path: str, https: bool) -> dict[str, Any]:
        return await _http_probe(host, address, path, https)

    return Probes(resolve, tls, http)


def _cert_details(der: bytes, host: str) -> dict[str, Any]:
    from cryptography import x509
    from cryptography.x509.oid import ExtensionOID, NameOID

    cert = x509.load_der_x509_certificate(der)
    expires = cert.not_valid_after_utc.astimezone(UTC).timestamp()
    issuer_parts = cert.issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME) or (
        cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
    )
    issuer = str(issuer_parts[0].value)[:120] if issuer_parts else None
    names: list[str] = []
    try:
        san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        names = [str(name).lower() for name in san.value.get_values_for_type(x509.DNSName)]
    except x509.ExtensionNotFound:
        names = []
    return {"expires_at": int(expires), "issuer": issuer, "hostname_match": _matches(host, names)}


def _matches(host: str, names: list[str]) -> bool:
    for name in names:
        if name == host:
            return True
        if name.startswith("*.") and host.count(".") == name.count(".") and host.endswith(name[1:]):
            return True
    return False


def _tls_probe(host: str, address: str) -> dict[str, Any]:
    """{connected, verified, error, expires_at, issuer, hostname_match}."""
    result: dict[str, Any] = {"connected": False, "verified": False, "error": None}
    der: bytes | None = None
    try:
        with socket.create_connection((address, 443), timeout=TIMEOUT_SECONDS) as raw:
            context = ssl.create_default_context()
            try:
                with context.wrap_socket(raw, server_hostname=host) as tls:
                    result["connected"] = True
                    result["verified"] = True
                    der = tls.getpeercert(binary_form=True)
            except ssl.SSLCertVerificationError as exc:
                result["connected"] = True
                result["error"] = (exc.verify_message or "verify_failed")[:120]
            except ssl.SSLError as exc:
                result["connected"] = True
                result["error"] = f"ssl_error:{exc.reason or ''}"[:120]
        if (
            der is None
            and result["connected"]
            and result["error"]
            and not str(result["error"]).startswith("ssl_error")
        ):
            with socket.create_connection((address, 443), timeout=TIMEOUT_SECONDS) as raw:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE  # only to read the bad certificate's details
                with context.wrap_socket(raw, server_hostname=host) as tls:
                    der = tls.getpeercert(binary_form=True)
    except (OSError, ssl.SSLError) as exc:
        if not result["connected"]:
            result["error"] = type(exc).__name__
    if der:
        try:
            result.update(_cert_details(der, host))
        except Exception:  # noqa: BLE001 - unreadable certificate counts as invalid
            result["verified"] = False
            result["error"] = result["error"] or "unreadable_certificate"
    return result


async def _http_probe(host: str, address: str, path: str, https: bool) -> dict[str, Any]:
    scheme = "https" if https else "http"
    port = 443 if https else 80
    literal = f"[{address}]" if ":" in address else address
    url = f"{scheme}://{literal}:{port}{path}"
    try:
        async with httpx.AsyncClient(
            verify=False,  # noqa: S501 - the TLS check is separate; this only asks "who answers"
            timeout=httpx.Timeout(TIMEOUT_SECONDS, connect=4.0),
            follow_redirects=False,
            trust_env=False,
        ) as client:
            request = client.build_request(
                "GET",
                url,
                headers={
                    "Host": host,
                    "User-Agent": "mrk-domain-check/1",
                    "Accept": "application/json",
                },
                extensions={"sni_hostname": host} if https else {},
            )
            response = await client.send(request, stream=True)
            try:
                body = b""
                async for chunk in response.aiter_bytes():
                    body += chunk
                    if len(body) > 8192:
                        break
            finally:
                await response.aclose()
    except httpx.HTTPError as exc:
        return {
            "ok": False,
            "status_code": None,
            "matched_service": None,
            "error": type(exc).__name__,
        }
    return {
        "ok": True,
        "status_code": response.status_code,
        "matched_service": identify(response.headers, body),
        "error": None,
    }


async def verify_domain(
    *,
    host: str,
    service_id: str,
    https: bool,
    expected_ips: list[str],
    probes: Probes,
    expiry_warning_days: int = 14,
    now: Callable[[], float] = time.time,
) -> dict[str, Any]:
    problems: list[str] = []
    addresses = await probes.resolve(host)
    expected = sorted(set(expected_ips))
    dns_ok = bool(addresses)
    if not addresses:
        problems.append("dns_missing")
    elif expected and not set(addresses) & set(expected):
        dns_ok = False
        problems.append("dns_wrong_ip")
    targets = [item for item in addresses if safe_target(item)]
    if addresses and not targets and "dns_wrong_ip" not in problems:
        dns_ok = False
        problems.append("dns_wrong_ip")
    if expected:
        preferred = [item for item in targets if item in expected]
        targets = preferred or targets
    health: dict[str, Any] = {
        "dns": {"ok": dns_ok, "addresses": addresses[:16], "expected": expected},
        "tls": None,
        "reach": {"ok": False, "status_code": None, "matched_service": None},
        "checked_at": int(now()),
    }
    if not targets:
        health["problems"] = problems
        health["problem_code"] = _first(problems)
        return health
    address = targets[0]
    if https:
        tls = await probes.tls(host, address)
        expires_at = tls.get("expires_at")
        days_left = None if expires_at is None else int((expires_at - now()) // 86400)
        tls_ok = bool(tls.get("verified")) and (days_left is None or days_left >= 0)
        health["tls"] = {
            "ok": tls_ok,
            "expires_at": expires_at,
            "issuer": tls.get("issuer"),
            "hostname_match": tls.get("hostname_match"),
            "days_left": days_left,
            "error": tls.get("error"),
        }
        if not tls.get("connected"):
            problems.append("tls_missing")
        elif not tls_ok:
            problems.append("tls_invalid")
        elif days_left is not None and days_left < expiry_warning_days:
            problems.append("tls_expiring")
    reach = await probes.http(host, address, PROBE_PATHS.get(service_id, "/"), https)
    matched = reach.get("matched_service")
    health["reach"] = {
        "ok": bool(reach.get("ok")) and matched == service_id,
        "status_code": reach.get("status_code"),
        "matched_service": matched,
    }
    if not reach.get("ok"):
        if "tls_missing" not in problems:
            problems.append("unreachable")
    elif matched != service_id:
        problems.append("wrong_service")
    health["problems"] = sorted(set(problems), key=PROBLEM_ORDER.index)
    health["problem_code"] = _first(health["problems"])
    return health


def _first(problems: list[str]) -> str | None:
    ordered = sorted(set(problems), key=PROBLEM_ORDER.index)
    return ordered[0] if ordered else None
