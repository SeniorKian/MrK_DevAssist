from __future__ import annotations

import asyncio
import ipaddress
import socket
import ssl
import time
from urllib.parse import urlsplit

import httpx

from .upstream_store import UpstreamStore


def _public_address(value: str) -> bool:
    return ipaddress.ip_address(value).is_global


async def probe_upstream(
    url: str, timeout_seconds: int, authorization: str | None = None
) -> dict[str, object]:
    normalized = UpstreamStore.validate_url(url)
    parsed = urlsplit(normalized)
    host = parsed.hostname or ""
    port = parsed.port or 443
    stages: list[dict[str, object]] = []

    started = time.perf_counter()
    try:
        addresses = await asyncio.wait_for(
            asyncio.get_running_loop().getaddrinfo(
                host, port, type=socket.SOCK_STREAM
            ),
            timeout=timeout_seconds,
        )
        resolved = sorted({str(item[4][0]) for item in addresses})
        if not resolved or not all(_public_address(item) for item in resolved):
            raise ValueError("DNS returned a private or non-routable address")
        stages.append(
            {
                "name": "dns",
                "status": "ok",
                "latency_ms": round((time.perf_counter() - started) * 1000, 1),
                "detail": f"{len(resolved)} public address(es)",
            }
        )
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
            asyncio.open_connection(host, port), timeout=timeout_seconds
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
            asyncio.open_connection(host, port, ssl=context, server_hostname=host),
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
            async with client.stream(
                "GET",
                normalized,
                headers=headers,
            ) as response:
                status_code = response.status_code
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
