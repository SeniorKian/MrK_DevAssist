from __future__ import annotations

import asyncio
import ssl
import time
from urllib.parse import urlsplit

import httpx

from .netresolve import DnsConfig, pinned_request, resolve_host, upstream_address_allowed
from .outbound import (
    OutboundClient,
    OutboundError,
    ProxyRoute,
    check_via_proxy,
    error_code,
    vetted_addresses,
)
from .upstream_store import UpstreamStore


def _public_address(value: str, allow_private: bool = False) -> bool:
    return upstream_address_allowed(value, allow_private)


async def reject_private_destination(
    url: str,
    dns: DnsConfig | None = None,
    timeout_seconds: float = 3.0,
    allow_private: bool = False,
    proxied: bool = False,
) -> None:
    """Refuse an upstream whose host resolves to a non-public address.

    Verdaccio connects to npm uplinks itself, without the PyPI router's
    per-request check, so this runs when an npm upstream is saved. A name that
    does not resolve yet is accepted (Verdaccio will simply fail to reach it).
    ``proxied``: the proxy resolves the name, so only the proxy policy applies
    (local private answers from a filtering resolver are ignored).
    """
    host = urlsplit(url).hostname or ""
    if proxied:
        try:
            await check_via_proxy(
                host, urlsplit(url).port or 443, dns or DnsConfig(), allow_private, timeout_seconds
            )
        except OutboundError as exc:
            raise ValueError("upstream host resolves to a private or local address") from exc
        return
    try:
        resolved = await asyncio.wait_for(
            asyncio.to_thread(resolve_host, host, urlsplit(url).port or 443, dns or DnsConfig()),
            timeout=timeout_seconds,
        )
    except (OSError, ValueError, TimeoutError):
        return
    if any(not _public_address(item, allow_private) for item in resolved):
        raise ValueError("upstream host resolves to a private or local address")


async def probe_upstream(
    url: str,
    timeout_seconds: int,
    authorization: str | None = None,
    dns: DnsConfig | None = None,
    allow_private: bool = False,
    proxy: ProxyRoute | None = None,
) -> dict[str, object]:
    normalized = UpstreamStore.validate_url(url, allow_private)
    parsed = urlsplit(normalized)
    host = parsed.hostname or ""
    port = parsed.port or 443
    if proxy is not None and not proxy.bypasses(host):
        return await _probe_via_proxy(
            normalized,
            host,
            port,
            timeout_seconds,
            authorization,
            dns or DnsConfig(),
            allow_private,
            proxy,
        )
    stages: list[dict[str, object]] = []

    started = time.perf_counter()
    try:
        config = dns or DnsConfig()
        resolved = await asyncio.wait_for(
            asyncio.to_thread(resolve_host, host, port, config),
            timeout=timeout_seconds,
        )
        if not resolved or not all(_public_address(item, allow_private) for item in resolved):
            raise ValueError("DNS returned a private or non-routable address")
        stages.append(
            {
                "name": "dns",
                "status": "ok",
                "latency_ms": round((time.perf_counter() - started) * 1000, 1),
                "detail": f"{len(resolved)} permitted address(es) via {config.mode} DNS",
            }
        )
        # Every later stage connects to the vetted address, never re-resolving.
        address = resolved[0]
    except (OSError, ValueError, TimeoutError) as exc:
        stages.append(
            {
                "name": "dns",
                "status": "failed",
                "latency_ms": round((time.perf_counter() - started) * 1000, 1),
                "detail": type(exc).__name__,
            }
        )
        return {"ok": False, "url": normalized, "stages": stages}

    started = time.perf_counter()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(address, port), timeout=timeout_seconds
        )
        del reader
        writer.close()
        await writer.wait_closed()
        stages.append(
            {
                "name": "tcp",
                "status": "ok",
                "latency_ms": round((time.perf_counter() - started) * 1000, 1),
            }
        )
    except (OSError, TimeoutError) as exc:
        stages.append(
            {
                "name": "tcp",
                "status": "failed",
                "latency_ms": round((time.perf_counter() - started) * 1000, 1),
                "detail": type(exc).__name__,
            }
        )
        return {"ok": False, "url": normalized, "stages": stages}

    started = time.perf_counter()
    context = ssl.create_default_context()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(address, port, ssl=context, server_hostname=host),
            timeout=timeout_seconds,
        )
        del reader
        certificate = writer.get_extra_info("peercert") or {}
        writer.close()
        await writer.wait_closed()
        stages.append(
            {
                "name": "tls",
                "status": "ok",
                "latency_ms": round((time.perf_counter() - started) * 1000, 1),
                "detail": certificate.get("notAfter", "verified"),
            }
        )
    except (OSError, ssl.SSLError, TimeoutError) as exc:
        stages.append(
            {
                "name": "tls",
                "status": "failed",
                "latency_ms": round((time.perf_counter() - started) * 1000, 1),
                "detail": type(exc).__name__,
            }
        )
        return {"ok": False, "url": normalized, "stages": stages}

    started = time.perf_counter()
    try:
        timeout = httpx.Timeout(timeout_seconds)
        headers = {"Accept": "text/html", "Range": "bytes=0-0"}
        if authorization is not None:
            headers["Authorization"] = authorization
        async with httpx.AsyncClient(
            timeout=timeout, follow_redirects=False, trust_env=False
        ) as client:
            request = pinned_request(client, "GET", normalized, address, headers)
            response = await client.send(request, stream=True)
            status_code = response.status_code
            await response.aclose()
        ok = 200 <= status_code < 400
        stages.append(
            {
                "name": "http",
                "status": "ok" if ok else "failed",
                "latency_ms": round((time.perf_counter() - started) * 1000, 1),
                "detail": f"HTTP {status_code}",
            }
        )
        return {"ok": ok, "url": normalized, "stages": stages}
    except (httpx.HTTPError, TimeoutError) as exc:
        stages.append(
            {
                "name": "http",
                "status": "failed",
                "latency_ms": round((time.perf_counter() - started) * 1000, 1),
                "detail": type(exc).__name__,
            }
        )
        return {"ok": False, "url": normalized, "stages": stages}


def _ms(started: float) -> float:
    return round((time.perf_counter() - started) * 1000, 1)


async def _probe_via_proxy(
    url: str,
    host: str,
    port: int,
    timeout_seconds: float,
    authorization: str | None,
    dns: DnsConfig,
    allow_private: bool,
    proxy: ProxyRoute,
) -> dict[str, object]:
    """Stages dns (policy), proxy (TCP to the proxy), http (TLS inside the tunnel)."""
    profile = proxy.profile
    summary = {"id": profile.id, "name": profile.name, "type": profile.type}
    stages: list[dict[str, object]] = []
    started = time.perf_counter()
    try:
        if proxy.pins_locally:
            resolved = await vetted_addresses(host, port, dns, allow_private, timeout_seconds)
            detail = f"{len(resolved)} permitted address(es) via {dns.mode} DNS"
        else:
            await check_via_proxy(host, port, dns, allow_private, timeout_seconds)
            detail = "resolved by the proxy"
        stages.append({"name": "dns", "status": "ok", "latency_ms": _ms(started), "detail": detail})
    except OutboundError as exc:
        stages.append(
            {"name": "dns", "status": "failed", "latency_ms": _ms(started), "detail": exc.code}
        )
        return {"ok": False, "url": url, "proxy": summary, "stages": stages}

    started = time.perf_counter()
    try:
        _reader, writer = await asyncio.wait_for(
            asyncio.open_connection(profile.host, profile.port), timeout=timeout_seconds
        )
        writer.close()
        await writer.wait_closed()
        stages.append(
            {
                "name": "proxy",
                "status": "ok",
                "latency_ms": _ms(started),
                "detail": f"{profile.type} {profile.name}",
            }
        )
    except (OSError, TimeoutError) as exc:
        stages.append(
            {
                "name": "proxy",
                "status": "failed",
                "latency_ms": _ms(started),
                "detail": type(exc).__name__,
            }
        )
        return {"ok": False, "url": url, "proxy": summary, "stages": stages}

    started = time.perf_counter()
    headers = {"Accept": "text/html", "Range": "bytes=0-0"}
    if authorization is not None:
        headers["Authorization"] = authorization
    client = OutboundClient(
        None, proxy, timeout_seconds, dns=dns, allow_private=allow_private, honour_no_proxy=False
    )
    try:
        response = await client.send("GET", url, headers=headers, stream=True)
        status_code = response.status_code
        await response.aclose()
    except Exception as exc:  # codes only: messages may contain URLs
        stages.append(
            {
                "name": "http",
                "status": "failed",
                "latency_ms": _ms(started),
                "detail": error_code(exc),
            }
        )
        return {"ok": False, "url": url, "proxy": summary, "stages": stages}
    finally:
        await client.aclose()
    ok = 200 <= status_code < 400
    stages.append(
        {
            "name": "http",
            "status": "ok" if ok else "failed",
            "latency_ms": _ms(started),
            "detail": f"HTTP {status_code}",
        }
    )
    return {"ok": ok, "url": url, "proxy": summary, "stages": stages}
