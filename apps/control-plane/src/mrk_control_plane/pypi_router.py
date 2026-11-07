from __future__ import annotations

import asyncio
import hashlib
import html
import ipaddress
import json
import logging
import os
import re
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

from .secret_store import SecretStore

LOGGER = logging.getLogger(__name__)
HREF_PATTERN = re.compile(r"(?i)(href\s*=\s*[\"'])([^\"']+)([\"'])")
FORWARDED_HEADERS = (
    "content-type",
    "content-length",
    "etag",
    "last-modified",
    "x-pypi-last-serial",
)
RETRYABLE_STATUS = {408, 425, 429, 500, 502, 503, 504}
REDIRECT_STATUS = {301, 302, 303, 307, 308}


@dataclass(frozen=True, slots=True)
class Upstream:
    name: str
    simple_url: str
    allowed_artifact_hosts: frozenset[str]
    credential_ref: str | None = None
    credential_type: str | None = None


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
    allow_private_networks: bool = False
    host: str = "127.0.0.1"
    port: int = 3142

    @classmethod
    def from_env(cls) -> RouterSettings:
        primary = _normalized_simple_url(
            os.getenv("MRK_PYPI_PRIMARY_UPSTREAM", "https://pypi.org/simple/")
        )
        fallback = _normalized_simple_url(
            os.getenv(
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
                os.getenv(
                    "MRK_PYPI_OFFLINE_FILE",
                    "/data/control-plane/pypi-offline",
                )
            ).resolve(),
            config_file=Path(
                os.getenv(
                    "MRK_UPSTREAM_CONFIG_FILE",
                    "/data/control-plane/upstreams.json",
                )
            ).resolve(),
            data_dir=Path(os.getenv("MRK_DATA_DIR", "/data")).resolve(),
            connect_timeout=float(os.getenv("MRK_PYPI_ROUTER_CONNECT_TIMEOUT", "3")),
            read_timeout=float(os.getenv("MRK_PYPI_ROUTER_READ_TIMEOUT", "90")),
            failure_threshold=int(os.getenv("MRK_PYPI_ROUTER_FAILURE_THRESHOLD", "2")),
            cooldown_seconds=float(os.getenv("MRK_PYPI_ROUTER_COOLDOWN", "30")),
            max_artifact_bytes=int(
                os.getenv("MRK_PYPI_ROUTER_MAX_ARTIFACT_BYTES", str(2 * 1024**3))
            ),
            allow_private_networks=os.getenv(
                "MRK_PYPI_ROUTER_ALLOW_PRIVATE", "false"
            ).lower()
            in {"1", "true", "yes"},
            host=os.getenv("MRK_PYPI_ROUTER_HOST", "127.0.0.1"),
            port=int(os.getenv("MRK_PYPI_ROUTER_PORT", "3142")),
        )


@dataclass(slots=True)
class CircuitState:
    failures: int = 0
    opened_until: float = 0.0
    last_error: str | None = None
    last_success_at: float | None = None


class ArtifactIntegrityError(ValueError):
    """An upstream artifact cannot be trusted and must never reach a client."""


@dataclass(slots=True)
class RouterRuntime:
    settings: RouterSettings
    circuits: dict[str, CircuitState] = field(default_factory=dict)
    last_selected: str | None = None
    secret_store: SecretStore | None = field(default=None, init=False)

    def __post_init__(self) -> None:
        self.circuits = {item.name: CircuitState() for item in self.settings.upstreams}
        if self.settings.data_dir is not None:
            self.secret_store = SecretStore(self.settings.data_dir)

    def upstreams(self) -> tuple[Upstream, ...]:
        path = self.settings.config_file
        if path is None or not path.is_file():
            return self.settings.upstreams
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            now = int(time.time())
            configured: list[Upstream] = []
            for item in sorted(payload, key=lambda value: int(value["priority"])):
                if item.get("ecosystem") != "pypi" or not item.get("enabled", True):
                    continue
                blocked_until = item.get("blocked_until")
                if blocked_until is not None and int(blocked_until) > now:
                    continue
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
                )
                configured.append(upstream)
                self.circuits.setdefault(upstream.name, CircuitState())
            return tuple(configured)
        except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
            LOGGER.exception("invalid dynamic upstream configuration; using static defaults")
            return self.settings.upstreams

    def available(self, upstream: Upstream) -> bool:
        return self.circuits[upstream.name].opened_until <= time.monotonic()

    def success(self, upstream: Upstream) -> None:
        state = self.circuits[upstream.name]
        state.failures = 0
        state.opened_until = 0.0
        state.last_error = None
        state.last_success_at = time.time()
        self.last_selected = upstream.name

    def failure(self, upstream: Upstream, error_code: str) -> None:
        state = self.circuits[upstream.name]
        state.failures += 1
        state.last_error = error_code
        if state.failures >= self.settings.failure_threshold:
            state.opened_until = time.monotonic() + self.settings.cooldown_seconds

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
    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


async def _validate_destination(
    url: str, allowed_hosts: frozenset[str], allow_private: bool
) -> None:
    parsed = urlsplit(url)
    hostname = (parsed.hostname or "").lower()
    if parsed.scheme != "https" or hostname not in allowed_hosts:
        raise ValueError("destination is outside the configured HTTPS host allowlist")
    if parsed.username or parsed.password:
        raise ValueError("credentials in upstream URLs are forbidden")
    if allow_private:
        return
    addresses = await asyncio.to_thread(
        socket.getaddrinfo,
        hostname,
        parsed.port or 443,
        0,
        socket.SOCK_STREAM,
    )
    if not addresses or any(not _public_ip(item[4][0]) for item in addresses):
        raise ValueError("destination resolved to a non-public address")


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
) -> tuple[httpx.AsyncClient, httpx.Response]:
    timeout = httpx.Timeout(settings.read_timeout, connect=settings.connect_timeout)
    client = httpx.AsyncClient(timeout=timeout, follow_redirects=False, trust_env=False)
    current = url
    try:
        for _attempt in range(settings.max_redirects + 1):
            await _validate_destination(current, allowed_hosts, settings.allow_private_networks)
            headers = _upstream_request_headers(current, authorization, credential_host)
            request = client.build_request(method, current, headers=headers)
            response = await client.send(request, stream=stream)
            if response.status_code not in REDIRECT_STATUS:
                return client, response
            location = response.headers.get("location")
            await response.aclose()
            if not location:
                raise httpx.RemoteProtocolError("redirect response omitted Location")
            current = urljoin(current, location)
        raise httpx.TooManyRedirects("upstream redirect limit exceeded")
    except Exception:
        await client.aclose()
        raise


async def _read_response(
    settings: RouterSettings,
    url: str,
    allowed_hosts: frozenset[str],
    authorization: str | None = None,
    credential_host: str | None = None,
) -> httpx.Response:
    client, response = await _request(
        settings,
        "GET",
        url,
        allowed_hosts,
        authorization=authorization,
        credential_host=credential_host,
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
    client: httpx.AsyncClient,
    expected_sha256: str | None,
    max_bytes: int,
) -> tuple[Path, int, str]:
    """Download once to a private temporary file and expose only verified bytes."""
    handle = tempfile.NamedTemporaryFile(prefix="mrk-pypi-", suffix=".artifact", delete=False)
    path = Path(handle.name)
    digest = hashlib.sha256()
    size = 0
    try:
        async for chunk in response.aiter_bytes():
            size += len(chunk)
            if size > max_bytes:
                raise ArtifactIntegrityError("artifact exceeds the configured size limit")
            digest.update(chunk)
            await asyncio.to_thread(handle.write, chunk)
        await asyncio.to_thread(handle.flush)
        await asyncio.to_thread(os.fsync, handle.fileno())
        actual_sha256 = digest.hexdigest()
        if expected_sha256 is not None and actual_sha256 != expected_sha256:
            raise ArtifactIntegrityError("artifact SHA-256 does not match upstream metadata")
        return path, size, actual_sha256
    except Exception:
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
    if isinstance(exc, httpx.ConnectTimeout):
        return "connect_timeout"
    if isinstance(exc, httpx.ReadTimeout):
        return "read_timeout"
    if isinstance(exc, socket.gaierror):
        return "dns_error"
    if isinstance(exc, ValueError):
        return "ssrf_rejected"
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
            )
        except (httpx.HTTPError, OSError, ValueError) as exc:
            code = _error_code(exc)
            runtime.failure(upstream, code)
            LOGGER.warning("PyPI upstream failed", extra={"upstream": upstream.name, "code": code})
            continue
        if 200 <= response.status_code < 300:
            runtime.success(upstream)
            return upstream, response
        if response.status_code in RETRYABLE_STATUS:
            runtime.failure(upstream, f"http_{response.status_code}")
            continue
        runtime.success(upstream)
        return upstream, response
    return None


def create_router_app(settings: RouterSettings | None = None) -> FastAPI:
    runtime = RouterRuntime(settings or RouterSettings.from_env())
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
                        if runtime.circuits[upstream.name].opened_until > now
                        else "closed",
                        "failures": runtime.circuits[upstream.name].failures,
                        "last_error": runtime.circuits[upstream.name].last_error,
                        "last_success_at": runtime.circuits[upstream.name].last_success_at,
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
        fetched = await _fetch_page(runtime, f"{quote(project, safe='')}/")
        if fetched is None:
            raise HTTPException(503, "No PyPI upstream is currently available")
        upstream, response = fetched
        if response.status_code >= 400:
            return HTMLResponse(response.text, status_code=response.status_code)
        page_url = urljoin(upstream.simple_url, f"{quote(project, safe='')}/")
        rewritten = _rewrite_project_page(project, page_url, response.text)
        headers = _response_headers(response)
        headers.pop("content-length", None)
        return HTMLResponse(rewritten, headers=headers)

    @app.get("/files/{project}/{filename:path}", include_in_schema=False)
    async def artifact(project: str, filename: str, request: Request) -> StreamingResponse:
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
                authorization = runtime.authorization_header(upstream)
                credential_host = (urlsplit(upstream.simple_url).hostname or "").lower()
                page = await _read_response(
                    runtime.settings,
                    page_url,
                    allowed_hosts,
                    authorization,
                    credential_host,
                )
                if page.status_code != 200:
                    if page.status_code in RETRYABLE_STATUS:
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
                )
                if response.status_code in RETRYABLE_STATUS:
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
                artifact_path, artifact_size, _actual_sha256 = (
                    await _spool_verified_artifact(
                        response,
                        client,
                        expected_sha256,
                        runtime.settings.max_artifact_bytes,
                    )
                )
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

                return StreamingResponse(
                    body(),
                    status_code=200,
                    headers=response_headers,
                    media_type=media_type,
                )
            except (httpx.HTTPError, OSError, ValueError) as exc:
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
