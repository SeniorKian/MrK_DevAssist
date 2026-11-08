from __future__ import annotations

import asyncio
import hashlib
import html
import ipaddress
import json
import logging
import os
import re
import shutil
import socket
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import quote, unquote, urljoin, urlsplit

import httpx
import uvicorn
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response, StreamingResponse
from starlette.background import BackgroundTask

from .config import setting_env
from .logging_config import configure_logging
from .netresolve import DnsConfig, NetworkSettingsStore, resolve_host, upstream_address_allowed
from .netresolve import pinned_request as _pinned_request
from .outbound import (
    ClientPool,
    OutboundError,
    ProxyRoute,
    ProxyUnavailable,
    check_via_proxy,
    resolve_route,
)
from .outbound import DestinationRejected as ProxyDestinationRejected
from .package_policy import QuarantineCache
from .secret_store import SecretStore

LOGGER = logging.getLogger(__name__)
HREF_PATTERN = re.compile(r"(?i)(href\s*=\s*[\"'])([^\"']+)([\"'])")
FORWARDED_HEADERS = (
    "content-type",
    "etag",
    "last-modified",
    "x-pypi-last-serial",
)
RETRYABLE_STATUS = {408, 425, 429, 500, 502, 503, 504}
# Geo-blocks and expired credentials: try the next upstream instead of
# handing the error to pip. 404 is deliberately not here (dependency confusion).
FAILOVER_STATUS = RETRYABLE_STATUS | {401, 403}
SPOOL_PREFIX = "mrk-pypi-"
SPOOL_SUFFIX = ".artifact"
# Free space kept back so a spool can never fill the shared /data volume.
SPOOL_RESERVE_BYTES = 256 * 1024 * 1024
REDIRECT_STATUS = {301, 302, 303, 307, 308}


@dataclass(frozen=True, slots=True)
class Upstream:
    name: str
    simple_url: str
    allowed_artifact_hosts: frozenset[str]
    credential_ref: str | None = None
    credential_type: str | None = None
    upstream_id: str | None = None
    # None = direct; "default" or a proxy profile id (see outbound.py).
    proxy_id: str | None = None

    @property
    def circuit_key(self) -> str:
        # Keyed by id: two upstreams renamed to the same name must not share a breaker.
        return self.upstream_id or self.name


@dataclass(frozen=True, slots=True)
class RouterSettings:
    upstreams: tuple[Upstream, ...]
    offline_file: Path
    config_file: Path | None = None
    data_dir: Path | None = None
    connect_timeout: float = 3.0
    read_timeout: float = 90.0
    failure_threshold: int = 2
    cooldown_seconds: float = 30.0
    max_redirects: int = 3
    max_artifact_bytes: int = 2 * 1024 * 1024 * 1024
    artifact_deadline_seconds: float = 840.0
    spool_dir: Path | None = None
    allow_private_networks: bool = False
    host: str = "127.0.0.1"
    port: int = 3142

    @classmethod
    def from_env(cls) -> RouterSettings:
        environment = setting_env("MRK_ENV", "development").strip().lower()
        configured_data_dir = setting_env("MRK_DATA_DIR", "").strip()
        data_dir = (
            Path(configured_data_dir).resolve()
            if configured_data_dir
            else (
                Path("/data")
                if environment == "production"
                else (Path.cwd() / ".data").resolve()
            )
        )
        primary = _normalized_simple_url(
            setting_env("MRK_PYPI_PRIMARY_UPSTREAM", "https://pypi.org/simple/")
        )
        fallback = _normalized_simple_url(
            setting_env(
                "MRK_PYPI_FALLBACK_UPSTREAM",
                "https://package-mirror.liara.ir/repository/pypi/simple/",
            )
        )
        primary_host = (urlsplit(primary).hostname or "").lower()
        fallback_host = (urlsplit(fallback).hostname or "").lower()
        return cls(
            upstreams=(
                Upstream(
                    "pypi.org",
                    primary,
                    frozenset({primary_host, "files.pythonhosted.org"}),
                ),
                Upstream(
                    "Liara",
                    fallback,
                    frozenset({fallback_host}),
                ),
            ),
            offline_file=Path(
                setting_env(
                    "MRK_PYPI_OFFLINE_FILE",
                    str(data_dir / "control-plane" / "pypi-offline"),
                )
            ).resolve(),
            config_file=Path(
                setting_env(
                    "MRK_UPSTREAM_CONFIG_FILE",
                    str(data_dir / "control-plane" / "upstreams.json"),
                )
            ).resolve(),
            data_dir=data_dir,
            connect_timeout=float(setting_env("MRK_PYPI_ROUTER_CONNECT_TIMEOUT", "3")),
            read_timeout=float(setting_env("MRK_PYPI_ROUTER_READ_TIMEOUT", "90")),
            failure_threshold=int(setting_env("MRK_PYPI_ROUTER_FAILURE_THRESHOLD", "2")),
            cooldown_seconds=float(setting_env("MRK_PYPI_ROUTER_COOLDOWN", "30")),
            max_artifact_bytes=int(
                setting_env("MRK_PYPI_ROUTER_MAX_ARTIFACT_BYTES", str(2 * 1024**3))
            ),
            artifact_deadline_seconds=float(
                setting_env("MRK_PYPI_ROUTER_ARTIFACT_DEADLINE", "840")
            ),
            spool_dir=Path(
                setting_env(
                    "MRK_PYPI_ROUTER_SPOOL_DIR", str(data_dir / "tmp" / "pypi-router")
                )
            ).resolve(),
            allow_private_networks=setting_env(
                "MRK_PYPI_ROUTER_ALLOW_PRIVATE", "false"
            ).lower()
            in {"1", "true", "yes"},
            host=setting_env("MRK_PYPI_ROUTER_HOST", "127.0.0.1"),
            port=int(setting_env("MRK_PYPI_ROUTER_PORT", "3142")),
        )


@dataclass(slots=True)
class CircuitState:
    failures: int = 0
    opened_until: float = 0.0
    last_error: str | None = None
    last_success_at: float | None = None


class ArtifactIntegrityError(ValueError):
    """An upstream artifact cannot be trusted and must never reach a client."""


class DestinationRejected(ValueError):
    """A URL is outside the allowlist; a per-request refusal, not an upstream outage."""


class LocalSpoolError(RuntimeError):
    """The appliance itself cannot store the artifact; the upstream is not at fault."""


def prepare_spool_dir(settings: RouterSettings) -> Path | None:
    """Create the private spool directory and remove files left by a crash."""
    if settings.spool_dir is None:
        return None
    settings.spool_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    for stale in settings.spool_dir.glob(f"{SPOOL_PREFIX}*{SPOOL_SUFFIX}"):
        stale.unlink(missing_ok=True)
    return settings.spool_dir


@dataclass(slots=True)
class RouterRuntime:
    settings: RouterSettings
    circuits: dict[str, CircuitState] = field(default_factory=dict)
    last_selected: str | None = None
    secret_store: SecretStore | None = field(default=None, init=False)
    quarantine: QuarantineCache | None = field(default=None, init=False)
    _last_good: tuple[float, tuple[Upstream, ...]] | None = field(default=None, init=False)
    _blocked_until: dict[str, int] = field(default_factory=dict, init=False)

    def __post_init__(self) -> None:
        self.circuits = {item.circuit_key: CircuitState() for item in self.settings.upstreams}
        if self.settings.data_dir is not None:
            self.secret_store = SecretStore(self.settings.data_dir)
        self.quarantine = QuarantineCache(self.settings.data_dir)

    def circuit(self, upstream: Upstream) -> CircuitState:
        return self.circuits.setdefault(upstream.circuit_key, CircuitState())

    def is_quarantined(self, project: str) -> bool:
        return self.quarantine is not None and self.quarantine.is_quarantined_pypi(project)

    def _filter_blocked(self, items: tuple[Upstream, ...]) -> tuple[Upstream, ...]:
        now = int(time.time())
        return tuple(
            item for item in items if self._blocked_until.get(item.circuit_key, 0) <= now
        )

    def upstreams(self) -> tuple[Upstream, ...]:
        path = self.settings.config_file
        if path is None or not path.is_file():
            return self.settings.upstreams
        try:
            mtime = path.stat().st_mtime
            if self._last_good is not None and self._last_good[0] == mtime:
                return self._filter_blocked(self._last_good[1])
            payload = json.loads(path.read_text(encoding="utf-8"))
            configured: list[Upstream] = []
            blocked: dict[str, int] = {}
            for item in sorted(payload, key=lambda value: int(value["priority"])):
                if item.get("ecosystem") != "pypi" or not item.get("enabled", True):
                    continue
                blocked_until = item.get("blocked_until")
                url = _normalized_simple_url(str(item["url"]))
                host = (urlsplit(url).hostname or "").lower()
                allowed_hosts = {host}
                if host == "pypi.org":
                    allowed_hosts.add("files.pythonhosted.org")
                upstream = Upstream(
                    str(item["name"]),
                    url,
                    frozenset(allowed_hosts),
                    str(item["credential_ref"]) if item.get("credential_ref") else None,
                    str(item["credential_type"]) if item.get("credential_type") else None,
                    str(item["id"]) if item.get("id") else None,
                    str(item["proxy_id"]) if item.get("proxy_id") else None,
                )
                configured.append(upstream)
                blocked[upstream.circuit_key] = (
                    int(blocked_until) if blocked_until is not None else 0
                )
                self.circuit(upstream)
            parsed = tuple(configured)
            self._blocked_until = blocked
            self._last_good = (mtime, parsed)
            return self._filter_blocked(parsed)
        except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
            if self._last_good is not None:
                # Fail closed to the last configuration the operator saved; the env
                # defaults could re-enable upstreams that were blocked or disabled.
                LOGGER.exception("invalid dynamic upstream configuration; keeping last good")
                return self._filter_blocked(self._last_good[1])
            LOGGER.exception("invalid dynamic upstream configuration; using static defaults")
            return self.settings.upstreams

    def available(self, upstream: Upstream) -> bool:
        return self.circuit(upstream).opened_until <= time.monotonic()

    def success(self, upstream: Upstream) -> None:
        state = self.circuit(upstream)
        state.failures = 0
        state.opened_until = 0.0
        state.last_error = None
        state.last_success_at = time.time()
        self.last_selected = upstream.name

    def failure(self, upstream: Upstream, error_code: str) -> None:
        state = self.circuit(upstream)
        state.failures += 1
        state.last_error = error_code
        if state.failures >= self.settings.failure_threshold:
            state.opened_until = time.monotonic() + self.settings.cooldown_seconds

    def proxy_route(self, upstream: Upstream) -> ProxyRoute | None:
        """The upstream's proxy (re-read from network.json); raises ProxyUnavailable."""
        if upstream.proxy_id is None:
            return None
        store = _network_store(self.settings)
        if store is None:
            raise ProxyUnavailable("network settings are unavailable")
        return resolve_route(store, self.secret_store, upstream.proxy_id)

    def authorization_header(self, upstream: Upstream) -> str | None:
        if upstream.credential_ref is None or upstream.credential_type is None:
            return None
        if self.secret_store is None:
            raise ValueError("upstream credential store is unavailable")
        return self.secret_store.authorization_header(
            upstream.credential_ref, upstream.credential_type
        )


def _normalized_simple_url(value: str) -> str:
    parsed = urlsplit(value)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("PyPI upstream URLs must be credential-free HTTPS URLs")
    if parsed.query or parsed.fragment:
        raise ValueError("PyPI upstream URLs cannot contain query strings or fragments")
    return value.rstrip("/") + "/"


def _public_ip(address: str) -> bool:
    ip = ipaddress.ip_address(address)
    # is_global also excludes shared/CGNAT space (100.64.0.0/10) and similar ranges.
    return ip.is_global and not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


_NETWORK_STORES: dict[Path, NetworkSettingsStore] = {}


def _network_store(settings: RouterSettings) -> NetworkSettingsStore | None:
    if settings.data_dir is None:
        return None
    return _NETWORK_STORES.setdefault(settings.data_dir, NetworkSettingsStore(settings.data_dir))


def _dns_config(settings: RouterSettings) -> DnsConfig:
    """Operator DNS choice, re-read when network.json changes (no restart needed)."""
    store = _network_store(settings)
    return store.dns() if store is not None else DnsConfig()


def _allow_private_upstreams(settings: RouterSettings) -> bool:
    """The panel's allow_private_upstreams setting (re-read on change)."""
    store = _network_store(settings)
    return store.allow_private_upstreams() if store is not None else False


def _check_allowlist(url: str, allowed_hosts: frozenset[str]) -> None:
    parsed = urlsplit(url)
    hostname = (parsed.hostname or "").lower()
    if parsed.scheme != "https" or hostname not in allowed_hosts:
        raise DestinationRejected("destination is outside the configured HTTPS host allowlist")
    if parsed.username or parsed.password:
        raise DestinationRejected("credentials in upstream URLs are forbidden")


async def _validate_destination(
    url: str,
    allowed_hosts: frozenset[str],
    allow_private: bool,
    dns: DnsConfig | None = None,
    allow_private_ranges: bool = False,
) -> list[str]:
    """Check the URL and return the vetted addresses to connect to."""
    parsed = urlsplit(url)
    hostname = (parsed.hostname or "").lower()
    if parsed.scheme != "https" or hostname not in allowed_hosts:
        raise DestinationRejected("destination is outside the configured HTTPS host allowlist")
    if parsed.username or parsed.password:
        raise DestinationRejected("credentials in upstream URLs are forbidden")
    addresses = await asyncio.to_thread(
        resolve_host, hostname, parsed.port or 443, dns or DnsConfig()
    )
    if not addresses:
        raise socket.gaierror(socket.EAI_NONAME, "no addresses")
    # allow_private (MRK_PYPI_ROUTER_ALLOW_PRIVATE) is the old all-or-nothing
    # escape hatch; allow_private_ranges (panel setting) admits RFC1918/ULA/CGNAT
    # but never loopback, link-local or the metadata address.
    if not allow_private and any(
        not (_public_ip(item) or upstream_address_allowed(item, allow_private_ranges))
        for item in addresses
    ):
        raise DestinationRejected("destination resolved to a non-public address")
    return addresses


def _upstream_request_headers(
    url: str, authorization: str | None, credential_host: str | None
) -> dict[str, str]:
    headers = {"Accept": "text/html"}
    if (
        authorization is not None
        and (urlsplit(url).hostname or "").lower() == credential_host
    ):
        headers["Authorization"] = authorization
    return headers


async def _request(
    settings: RouterSettings,
    method: str,
    url: str,
    allowed_hosts: frozenset[str],
    *,
    stream: bool = False,
    authorization: str | None = None,
    credential_host: str | None = None,
    proxy: ProxyRoute | None = None,
) -> tuple[ClientPool, httpx.Response]:
    """Follow redirects hop by hop; each hop is checked, then pinned or proxied.

    Returns the ClientPool to close once the response is consumed.
    """
    timeout = httpx.Timeout(settings.read_timeout, connect=settings.connect_timeout)
    pool = ClientPool(timeout)
    current = url
    try:
        dns = _dns_config(settings)
        allow_ranges = _allow_private_upstreams(settings)
        for _attempt in range(settings.max_redirects + 1):
            hop_host = (urlsplit(current).hostname or "").lower()
            hop_proxy = None if proxy is None or proxy.bypasses(hop_host) else proxy
            client = pool.get(hop_proxy)
            headers = _upstream_request_headers(current, authorization, credential_host)
            response = None
            if hop_proxy is not None and not hop_proxy.pins_locally:
                # The proxy resolves the name: no pinning, best-effort policy instead.
                _check_allowlist(current, allowed_hosts)
                if not settings.allow_private_networks:
                    try:
                        await check_via_proxy(
                            hop_host,
                            urlsplit(current).port or 443,
                            dns,
                            allow_ranges,
                            settings.connect_timeout,
                        )
                    except ProxyDestinationRejected as exc:
                        raise DestinationRejected(str(exc)) from None
                request = client.build_request(method, current, headers=headers)
                response = await client.send(request, stream=stream)
            else:
                addresses = await _validate_destination(
                    current, allowed_hosts, settings.allow_private_networks, dns, allow_ranges
                )
                for index, address in enumerate(addresses[:3]):
                    request = _pinned_request(client, method, current, address, headers)
                    try:
                        response = await client.send(request, stream=stream)
                        break
                    except (httpx.ConnectError, httpx.ConnectTimeout):
                        if index + 1 >= min(len(addresses), 3):
                            raise
            if response is None:  # pragma: no cover - loop always sets or raises
                raise httpx.ConnectError("no address could be reached")
            if response.status_code not in REDIRECT_STATUS:
                return pool, response
            location = response.headers.get("location")
            await response.aclose()
            if not location:
                raise httpx.RemoteProtocolError("redirect response omitted Location")
            current = urljoin(current, location)
        raise httpx.TooManyRedirects("upstream redirect limit exceeded")
    except Exception:
        await pool.aclose()
        raise


async def _read_response(
    settings: RouterSettings,
    url: str,
    allowed_hosts: frozenset[str],
    authorization: str | None = None,
    credential_host: str | None = None,
    proxy: ProxyRoute | None = None,
) -> httpx.Response:
    client, response = await _request(
        settings,
        "GET",
        url,
        allowed_hosts,
        authorization=authorization,
        credential_host=credential_host,
        proxy=proxy,
    )
    try:
        await response.aread()
        return response
    finally:
        await client.aclose()


def _artifact_links(page_url: str, body: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for match in HREF_PATTERN.finditer(body):
        absolute = urljoin(page_url, html.unescape(match.group(2)))
        filename = unquote(urlsplit(absolute).path.rsplit("/", 1)[-1])
        if filename:
            result.setdefault(filename, absolute)
    return result


def _expected_sha256(url: str) -> str | None:
    fragment = urlsplit(url).fragment
    for item in fragment.split("&"):
        key, separator, value = item.partition("=")
        if key.lower() != "sha256":
            continue
        if not separator or not re.fullmatch(r"[0-9a-fA-F]{64}", value):
            raise ArtifactIntegrityError("upstream advertised an invalid SHA-256 hash")
        return value.lower()
    return None


async def _spool_verified_artifact(
    response: httpx.Response,
    client: httpx.AsyncClient | ClientPool,
    expected_sha256: str | None,
    max_bytes: int,
    spool_dir: Path | None = None,
) -> tuple[Path, int, str]:
    """Download once to a private temporary file and expose only verified bytes."""
    try:
        if spool_dir is not None:
            spool_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        declared = response.headers.get("content-length", "")
        if declared.isdigit():
            if int(declared) > max_bytes:
                raise ArtifactIntegrityError("artifact exceeds the configured size limit")
            free = shutil.disk_usage(spool_dir or tempfile.gettempdir()).free
            if int(declared) + SPOOL_RESERVE_BYTES > free:
                raise LocalSpoolError("not enough local space to spool the artifact")
        handle = tempfile.NamedTemporaryFile(
            prefix=SPOOL_PREFIX, suffix=SPOOL_SUFFIX, dir=spool_dir, delete=False
        )
    except OSError as exc:
        await response.aclose()
        await client.aclose()
        raise LocalSpoolError("cannot create the local artifact spool") from exc
    except BaseException:
        await response.aclose()
        await client.aclose()
        raise
    path = Path(handle.name)
    digest = hashlib.sha256()
    size = 0
    try:
        async for chunk in response.aiter_bytes():
            size += len(chunk)
            if size > max_bytes:
                raise ArtifactIntegrityError("artifact exceeds the configured size limit")
            digest.update(chunk)
            try:
                await asyncio.to_thread(handle.write, chunk)
            except OSError as exc:
                raise LocalSpoolError("cannot write the local artifact spool") from exc
        try:
            await asyncio.to_thread(handle.flush)
            await asyncio.to_thread(os.fsync, handle.fileno())
        except OSError as exc:
            raise LocalSpoolError("cannot write the local artifact spool") from exc
        actual_sha256 = digest.hexdigest()
        if expected_sha256 is not None and actual_sha256 != expected_sha256:
            raise ArtifactIntegrityError("artifact SHA-256 does not match upstream metadata")
        return path, size, actual_sha256
    except BaseException:
        # BaseException: the artifact deadline cancels this coroutine with
        # CancelledError, and the partial spool must not be left on /data.
        handle.close()
        path.unlink(missing_ok=True)
        raise
    finally:
        if not handle.closed:
            handle.close()
        await response.aclose()
        await client.aclose()


def _rewrite_project_page(project: str, page_url: str, body: str) -> str:
    def replace(match: re.Match[str]) -> str:
        absolute = urljoin(page_url, html.unescape(match.group(2)))
        parsed = urlsplit(absolute)
        filename = unquote(parsed.path.rsplit("/", 1)[-1])
        if not filename:
            return match.group(0)
        local = f"/files/{quote(project, safe='')}/{quote(filename, safe='')}"
        if parsed.fragment:
            local = f"{local}#{parsed.fragment}"
        return f"{match.group(1)}{html.escape(local, quote=True)}{match.group(3)}"

    return HREF_PATTERN.sub(replace, body)


def _response_headers(response: httpx.Response) -> dict[str, str]:
    return {
        name: response.headers[name]
        for name in FORWARDED_HEADERS
        if name in response.headers
    }


def _error_code(exc: Exception) -> str:
    if isinstance(exc, ArtifactIntegrityError):
        return "checksum_mismatch"
    if isinstance(exc, OutboundError):
        return exc.code
    if isinstance(exc, httpx.ProxyError):
        return "proxy_error"
    if isinstance(exc, httpx.ConnectTimeout):
        return "connect_timeout"
    if isinstance(exc, httpx.ReadTimeout):
        return "read_timeout"
    if isinstance(exc, socket.gaierror):
        return "dns_error"
    if isinstance(exc, DestinationRejected):
        return "ssrf_rejected"
    if isinstance(exc, KeyError):
        return "credential_error"
    if isinstance(exc, ValueError):
        return "invalid_response"
    return "network_error"


async def _fetch_page(
    runtime: RouterRuntime, relative_path: str
) -> tuple[Upstream, httpx.Response] | None:
    if runtime.settings.offline_file.exists():
        return None
    for upstream in runtime.upstreams():
        if not runtime.available(upstream):
            continue
        url = urljoin(upstream.simple_url, relative_path)
        allowed_hosts = upstream.allowed_artifact_hosts | frozenset(
            {(urlsplit(upstream.simple_url).hostname or "").lower()}
        )
        try:
            proxy = await asyncio.to_thread(runtime.proxy_route, upstream)
        except OutboundError:
            # Never fall back to a direct connection the operator did not choose.
            runtime.failure(upstream, "proxy_unavailable")
            LOGGER.warning(
                "PyPI upstream proxy unavailable",
                extra={"upstream": upstream.name, "code": "proxy_unavailable"},
            )
            continue
        try:
            authorization = runtime.authorization_header(upstream)
        except (KeyError, ValueError):
            runtime.failure(upstream, "credential_error")
            continue
        try:
            response = await _read_response(
                runtime.settings,
                url,
                allowed_hosts,
                authorization,
                (urlsplit(upstream.simple_url).hostname or "").lower(),
                proxy,
            )
        except DestinationRejected:
            LOGGER.warning(
                "PyPI upstream destination rejected",
                extra={"upstream": upstream.name, "code": "ssrf_rejected"},
            )
            continue
        except (httpx.HTTPError, OSError, ValueError) as exc:
            code = _error_code(exc)
            runtime.failure(upstream, code)
            LOGGER.warning("PyPI upstream failed", extra={"upstream": upstream.name, "code": code})
            continue
        if 200 <= response.status_code < 300:
            runtime.success(upstream)
            return upstream, response
        if response.status_code in FAILOVER_STATUS:
            runtime.failure(upstream, f"http_{response.status_code}")
            continue
        runtime.success(upstream)
        return upstream, response
    return None


def create_router_app(settings: RouterSettings | None = None) -> FastAPI:
    runtime = RouterRuntime(settings or RouterSettings.from_env())
    try:
        prepare_spool_dir(runtime.settings)
    except OSError:
        LOGGER.exception("cannot prepare the PyPI artifact spool directory")
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    app.state.runtime = runtime

    @app.get("/health", include_in_schema=False)
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/status", include_in_schema=False)
    async def status() -> JSONResponse:
        now = time.monotonic()
        return JSONResponse(
            {
                "offline": runtime.settings.offline_file.exists(),
                "last_selected": runtime.last_selected,
                "upstreams": [
                    {
                        "name": upstream.name,
                        "url": upstream.simple_url,
                        "state": "open"
                        if runtime.circuit(upstream).opened_until > now
                        else "closed",
                        "failures": runtime.circuit(upstream).failures,
                        "last_error": runtime.circuit(upstream).last_error,
                        "last_success_at": runtime.circuit(upstream).last_success_at,
                    }
                    for upstream in runtime.upstreams()
                ],
            }
        )

    @app.get("/simple/", include_in_schema=False)
    async def projects() -> Response:
        fetched = await _fetch_page(runtime, "")
        if fetched is None:
            raise HTTPException(503, "No PyPI upstream is currently available")
        _upstream, response = fetched
        return Response(
            content=response.content,
            status_code=response.status_code,
            headers=_response_headers(response),
            media_type=response.headers.get("content-type", "text/html"),
        )

    @app.get("/simple/{project}/", include_in_schema=False)
    async def project(project: str) -> HTMLResponse:
        if runtime.is_quarantined(project):
            raise HTTPException(404, "Project is quarantined")
        fetched = await _fetch_page(runtime, f"{quote(project, safe='')}/")
        if fetched is None:
            raise HTTPException(503, "No PyPI upstream is currently available")
        upstream, response = fetched
        if response.status_code >= 400:
            return HTMLResponse(response.text, status_code=response.status_code)
        page_url = urljoin(upstream.simple_url, f"{quote(project, safe='')}/")
        rewritten = _rewrite_project_page(project, page_url, response.text)
        headers = _response_headers(response)
        return HTMLResponse(rewritten, headers=headers)

    @app.get("/files/{project}/{filename:path}", include_in_schema=False)
    async def artifact(project: str, filename: str, request: Request) -> StreamingResponse:
        if runtime.is_quarantined(project):
            raise HTTPException(404, "Project is quarantined")
        if runtime.settings.offline_file.exists():
            raise HTTPException(503, "PyPI router is in cache-only mode")
        for upstream in runtime.upstreams():
            if not runtime.available(upstream):
                continue
            page_url = urljoin(upstream.simple_url, f"{quote(project, safe='')}/")
            allowed_hosts = upstream.allowed_artifact_hosts | frozenset(
                {(urlsplit(upstream.simple_url).hostname or "").lower()}
            )
            try:
                proxy = await asyncio.to_thread(runtime.proxy_route, upstream)
            except OutboundError:
                runtime.failure(upstream, "proxy_unavailable")
                continue
            try:
                authorization = runtime.authorization_header(upstream)
            except (KeyError, ValueError):
                runtime.failure(upstream, "credential_error")
                continue
            try:
                credential_host = (urlsplit(upstream.simple_url).hostname or "").lower()
                page = await _read_response(
                    runtime.settings,
                    page_url,
                    allowed_hosts,
                    authorization,
                    credential_host,
                    proxy,
                )
                if page.status_code != 200:
                    if page.status_code in FAILOVER_STATUS:
                        runtime.failure(upstream, f"http_{page.status_code}")
                    continue
                artifact_url = _artifact_links(page_url, page.text).get(unquote(filename))
                if not artifact_url:
                    continue
                expected_sha256 = _expected_sha256(artifact_url)
                client, response = await _request(
                    runtime.settings,
                    "GET",
                    artifact_url,
                    allowed_hosts,
                    stream=True,
                    authorization=authorization,
                    credential_host=credential_host,
                    proxy=proxy,
                )
                if response.status_code in FAILOVER_STATUS:
                    await response.aclose()
                    await client.aclose()
                    runtime.failure(upstream, f"http_{response.status_code}")
                    continue
                if response.status_code >= 400:
                    await response.aclose()
                    await client.aclose()
                    continue
                response_headers = _response_headers(response)
                media_type = response.headers.get("content-type")
                try:
                    async with asyncio.timeout(runtime.settings.artifact_deadline_seconds):
                        artifact_path, artifact_size, _actual_sha256 = (
                            await _spool_verified_artifact(
                                response,
                                client,
                                expected_sha256,
                                runtime.settings.max_artifact_bytes,
                                runtime.settings.spool_dir,
                            )
                        )
                except TimeoutError as exc:
                    raise httpx.ReadTimeout("artifact download deadline exceeded") from exc
                runtime.success(upstream)

                async def body(
                    verified_path: Path = artifact_path,
                ):
                    try:
                        with verified_path.open("rb") as source:
                            while chunk := await asyncio.to_thread(source.read, 64 * 1024):
                                if await request.is_disconnected():
                                    break
                                yield chunk
                    finally:
                        verified_path.unlink(missing_ok=True)

                response_headers["content-length"] = str(artifact_size)

                # The generator's finally only runs if the body is iterated; the
                # background task also removes the spool when sending fails early.
                return StreamingResponse(
                    body(),
                    status_code=200,
                    headers=response_headers,
                    media_type=media_type,
                    background=BackgroundTask(artifact_path.unlink, missing_ok=True),
                )
            except LocalSpoolError:
                LOGGER.exception(
                    "PyPI artifact could not be spooled locally",
                    extra={"upstream": upstream.name, "code": "local_spool_error"},
                )
                raise HTTPException(
                    507, "The appliance has no local space for this artifact"
                ) from None
            except DestinationRejected:
                # e.g. a private index redirecting to an unlisted CDN host: refuse
                # this request without opening the circuit for the whole upstream.
                LOGGER.warning(
                    "PyPI artifact destination rejected",
                    extra={"upstream": upstream.name, "code": "ssrf_rejected"},
                )
            except (httpx.HTTPError, OSError, ValueError, KeyError) as exc:
                code = _error_code(exc)
                runtime.failure(upstream, code)
                LOGGER.warning(
                    "PyPI artifact upstream failed",
                    extra={"upstream": upstream.name, "code": code},
                )
        raise HTTPException(503, "Artifact is unavailable from all PyPI upstreams")

    return app


app = create_router_app()


def run() -> None:
    configure_logging((setting_env("MRK_LOG_LEVEL", "INFO") or "INFO").strip().upper() or "INFO")
    settings = RouterSettings.from_env()
    LOGGER.info(
        "starting PyPI upstream router",
        extra={"upstreams": json.dumps([item.name for item in settings.upstreams])},
    )
    uvicorn.run(
        "mrk_control_plane.pypi_router:app",
        host=settings.host,
        port=settings.port,
        log_config=None,
        access_log=False,
    )
