"""Central outbound proxy support for every external connection the appliance makes.

The operator defines proxy *profiles* (HTTP, HTTPS, SOCKS5, SOCKS5h) in the panel;
they live in ``network.json`` under ``proxies`` / ``default_proxy_id`` and their
passwords live in the encrypted ``SecretStore``. Each outbound consumer (npm and
PyPI upstreams, notification channels, future modules) stores a ``proxy_id``:

* ``None`` – direct connection (the historic behaviour: operator DNS, destination
  policy, connection pinned to the vetted IP);
* ``"default"`` – whichever profile is the current default;
* a profile id.

A reference that cannot be honoured (unknown, disabled, no default) raises
``ProxyUnavailable`` (``proxy_unavailable``): traffic never silently goes direct.

Destination policy through a proxy: ``socks5`` resolves the name locally with the
operator DNS, so the full direct policy applies and the connection is pinned to
the vetted address. ``http``/``https``/``socks5h`` let the proxy resolve; literal
IPs and local names are still refused, and if the name *also* resolves locally
those answers must not be loopback/link-local/metadata. A local DNS failure is
not fatal there (the proxy is often needed precisely because local DNS is
filtered), and RFC1918 answers are ignored because filtering resolvers commonly
answer blocked names with a private address (e.g. 10.10.34.x).

Proxy URLs carry credentials: they are never logged, never returned by the API
and ``ProxyRoute`` keeps them out of its ``repr``.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import re
import secrets
import socket
import ssl
import threading
import time
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlsplit

import httpx

from .netresolve import DnsConfig, NetworkSettingsStore, resolve_host, upstream_address_allowed
from .secret_store import SecretStore

LOGGER = logging.getLogger(__name__)

PROXY_TYPES = ("http", "https", "socks5", "socks5h")
HTTP_PROXY_TYPES = frozenset({"http", "https"})
SOCKS_PROXY_TYPES = frozenset({"socks5", "socks5h"})
ALL_PROXY_TYPES = frozenset(PROXY_TYPES)
DEFAULT_REF = "default"
MAX_PROXIES = 32
MAX_NO_PROXY = 32
DEFAULT_TEST_URL = "https://api.telegram.org"

_NAME = re.compile(r"^[^\x00-\x1f\x7f]{1,80}$")
_REF = re.compile(r"^[A-Za-z0-9]{1,64}$")
_HOSTNAME = re.compile(
    r"^(?=.{1,253}$)([A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)"
    r"(\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$"
)
_NO_PROXY_NAME = re.compile(
    r"^(\*\.|\.)?([A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)"
    r"(\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$"
)
# LAN-style names; allowed as destinations only with allow_private_upstreams.
_LOCAL_SUFFIXES = (".local", ".internal", ".lan", ".home.arpa", ".intranet")


class OutboundError(ValueError):
    """A refusal with a stable, secret-free error code."""

    def __init__(self, code: str, message: str, status_code: int = 422) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code


class ProxyUnavailable(OutboundError):
    def __init__(self, message: str = "the selected proxy is missing or disabled") -> None:
        super().__init__("proxy_unavailable", message, 409)


class DestinationRejected(OutboundError):
    def __init__(self, message: str = "destination is not allowed") -> None:
        super().__init__("destination_not_allowed", message, 422)


class DnsFailed(OutboundError):
    def __init__(self, message: str = "destination name could not be resolved") -> None:
        super().__init__("dns_failed", message, 502)


# --- profiles ------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ProxyProfile:
    id: str
    name: str
    type: str
    host: str
    port: int
    username: str | None = None
    secret_ref: str | None = None
    enabled: bool = True
    no_proxy: tuple[str, ...] = ()
    created_at: int = 0
    updated_at: int = 0

    @classmethod
    def from_raw(cls, raw: dict[str, object]) -> ProxyProfile:
        identifier = raw.get("id")
        if not isinstance(identifier, str) or _REF.fullmatch(identifier) is None:
            raise ValueError("invalid proxy id")
        if identifier == DEFAULT_REF:
            raise ValueError("reserved proxy id")
        port = raw.get("port")
        if not isinstance(port, int) or isinstance(port, bool):
            raise ValueError("invalid proxy port")
        username = raw.get("username")
        secret_ref = raw.get("secret_ref")
        enabled = raw.get("enabled", True)
        return cls(
            id=identifier,
            name=validate_name(raw.get("name")),
            type=validate_type(raw.get("type")),
            host=validate_host(raw.get("host")),
            port=validate_port(port),
            username=validate_username(username) if username else None,
            secret_ref=str(secret_ref) if isinstance(secret_ref, str) and secret_ref else None,
            enabled=enabled if isinstance(enabled, bool) else False,
            no_proxy=validate_no_proxy(raw.get("no_proxy") or []),
            created_at=int(str(raw.get("created_at") or 0)),
            updated_at=int(str(raw.get("updated_at") or 0)),
        )

    def stored(self) -> dict[str, object]:
        return {
            "id": self.id,
            "name": self.name,
            "type": self.type,
            "host": self.host,
            "port": self.port,
            "username": self.username,
            "secret_ref": self.secret_ref,
            "enabled": self.enabled,
            "no_proxy": list(self.no_proxy),
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    def public(self) -> dict[str, object]:
        return {
            "id": self.id,
            "name": self.name,
            "type": self.type,
            "host": self.host,
            "port": self.port,
            "username": self.username,
            "secret_configured": self.secret_ref is not None,
            "enabled": self.enabled,
            "no_proxy": list(self.no_proxy),
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


def validate_name(value: object) -> str:
    if not isinstance(value, str) or _NAME.fullmatch(value.strip()) is None:
        raise OutboundError("invalid_proxy_name", "name must be 1-80 printable characters")
    return value.strip()


def validate_type(value: object) -> str:
    if value not in PROXY_TYPES:
        raise OutboundError("invalid_proxy_type", f"type must be one of {', '.join(PROXY_TYPES)}")
    return str(value)


def validate_port(value: object) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= 65535:
        raise OutboundError("invalid_proxy_port", "port must be 1-65535")
    return value


def validate_host(value: object) -> str:
    """A proxy host is operator-chosen: LAN and loopback (local tunnels) are fine."""
    if not isinstance(value, str) or not value.strip():
        raise OutboundError("invalid_proxy_host", "host is required")
    text = value.strip().lower().rstrip(".")
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1]
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        address = None
    if address is not None:
        if address.is_unspecified or address.is_multicast or address.is_link_local:
            # Link-local covers the 169.254.169.254 metadata service.
            raise OutboundError("invalid_proxy_host", "proxy address is not usable")
        return str(address)
    if _HOSTNAME.fullmatch(text) is None:
        raise OutboundError("invalid_proxy_host", "host must be a host name or IP address")
    return text


def validate_username(value: object) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= 255
        or any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in value)
    ):
        raise OutboundError("invalid_proxy_username", "username must be 1-255 printable characters")
    return value


def validate_password(value: object) -> str:
    if (
        not isinstance(value, str)
        or len(value) > 1024
        or any(ch in value for ch in "\r\n\x00")
    ):
        raise OutboundError("invalid_proxy_password", "password must be at most 1024 characters")
    return value


def validate_no_proxy(value: object) -> tuple[str, ...]:
    if not isinstance(value, list | tuple) or len(value) > MAX_NO_PROXY:
        raise OutboundError(
            "invalid_no_proxy", f"no_proxy must be a list of at most {MAX_NO_PROXY} patterns"
        )
    patterns: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item.strip():
            raise OutboundError("invalid_no_proxy", "no_proxy patterns must be strings")
        text = item.strip().lower().rstrip(".")
        try:
            network = ipaddress.ip_network(text, strict=False)
        except ValueError:
            network = None
        if network is not None:
            patterns.append(str(network) if "/" in text else str(network.network_address))
            continue
        if _NO_PROXY_NAME.fullmatch(text) is None:
            raise OutboundError(
                "invalid_no_proxy", "no_proxy pattern is not a host, *.domain or CIDR"
            )
        if text.startswith("*."):
            text = text[1:]
        patterns.append(text)
    return tuple(dict.fromkeys(patterns))


def no_proxy_matches(patterns: tuple[str, ...], host: str) -> bool:
    """curl-style: ``example.com`` and ``.example.com`` match the name and its subdomains."""
    name = host.lower().rstrip(".").strip("[]")
    try:
        address = ipaddress.ip_address(name)
    except ValueError:
        address = None
    for pattern in patterns:
        if address is not None:
            try:
                if address in ipaddress.ip_network(pattern, strict=False):
                    return True
            except ValueError:
                pass
            continue
        bare = pattern.lstrip(".")
        if name == bare or name.endswith("." + bare):
            return True
    return False


def validate_reference(value: object) -> str | None:
    """Shape check for a consumer's ``proxy_id`` (existence is checked separately)."""
    if value is None or value == "":
        return None
    if not isinstance(value, str) or _REF.fullmatch(value) is None:
        raise OutboundError("invalid_proxy_id", "proxy_id must be null, \"default\" or a proxy id")
    return value


def list_profiles(network: NetworkSettingsStore) -> list[ProxyProfile]:
    profiles: list[ProxyProfile] = []
    for raw in network.proxies_raw():
        try:
            profiles.append(ProxyProfile.from_raw(raw))
        except (ValueError, TypeError):
            # A hand-edited broken entry is skipped (and so unavailable), never fatal.
            LOGGER.warning("ignoring invalid proxy profile in network.json")
    return profiles


def get_profile(network: NetworkSettingsStore, proxy_id: str) -> ProxyProfile:
    for profile in list_profiles(network):
        if profile.id == proxy_id:
            return profile
    raise KeyError(proxy_id)


def referenced_profile(
    network: NetworkSettingsStore, proxy_ref: str | None
) -> ProxyProfile | None:
    """The profile a reference points at right now (enabled or not); None for direct."""
    if not proxy_ref:
        return None
    target = network.default_proxy_id() if proxy_ref == DEFAULT_REF else proxy_ref
    if not target:
        raise ProxyUnavailable("no default proxy is configured")
    try:
        return get_profile(network, target)
    except KeyError:
        raise ProxyUnavailable() from None


def resolve_profile(network: NetworkSettingsStore, proxy_ref: str | None) -> ProxyProfile | None:
    profile = referenced_profile(network, proxy_ref)
    if profile is not None and not profile.enabled:
        raise ProxyUnavailable("the selected proxy is disabled")
    return profile


def check_reference(
    network: NetworkSettingsStore,
    proxy_ref: object,
    supported_types: frozenset[str],
    unsupported_code: str,
) -> str | None:
    """Validate a consumer's proxy_id when it is saved."""
    reference = validate_reference(proxy_ref)
    if reference is None:
        return None
    try:
        profile = referenced_profile(network, reference)
    except ProxyUnavailable:
        if reference == DEFAULT_REF:
            raise OutboundError("no_default_proxy", "no default proxy is configured") from None
        raise OutboundError("proxy_not_found", "proxy does not exist") from None
    assert profile is not None  # noqa: S101 - reference is not None here
    if profile.type not in supported_types:
        raise OutboundError(
            unsupported_code,
            f"this service cannot use a {profile.type} proxy "
            f"(supported: {', '.join(sorted(supported_types)) or 'none'})",
        )
    return reference


# --- routes --------------------------------------------------------------------


def proxy_url(profile: ProxyProfile, password: str | None, *, credentials: bool = True) -> str:
    host = f"[{profile.host}]" if ":" in profile.host else profile.host
    userinfo = ""
    if credentials and profile.username:
        userinfo = quote(profile.username, safe="")
        if password:
            userinfo += ":" + quote(password, safe="")
        userinfo += "@"
    return f"{profile.type}://{userinfo}{host}:{profile.port}"


@dataclass(frozen=True, slots=True)
class ProxyRoute:
    profile: ProxyProfile
    # Contains credentials: never log it, never return it.
    url: str = field(repr=False)
    password: str | None = field(default=None, repr=False)

    @property
    def pins_locally(self) -> bool:
        """socks5 (not socks5h) resolves names locally, so the IP can be pinned."""
        return self.profile.type == "socks5"

    def bypasses(self, host: str) -> bool:
        return no_proxy_matches(self.profile.no_proxy, host)

    @property
    def redacted_url(self) -> str:
        return proxy_url(self.profile, None, credentials=False)


def build_route(profile: ProxyProfile, secret_store: SecretStore | None) -> ProxyRoute:
    password: str | None = None
    if profile.secret_ref:
        if secret_store is None:
            raise ProxyUnavailable("proxy credential store is unavailable")
        try:
            password = secret_store.get(profile.secret_ref).get("password") or None
        except (KeyError, ValueError):
            raise ProxyUnavailable("the proxy credential cannot be read") from None
    return ProxyRoute(profile, proxy_url(profile, password), password)


def resolve_route(
    network: NetworkSettingsStore, secret_store: SecretStore | None, proxy_ref: str | None
) -> ProxyRoute | None:
    profile = resolve_profile(network, proxy_ref)
    return None if profile is None else build_route(profile, secret_store)


# --- destination policy ------------------------------------------------------


def literal_address(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    name = host.lower().rstrip(".").strip("[]")
    try:
        return ipaddress.ip_address(name)
    except ValueError:
        pass
    if name[:1].isdigit():
        # Shorthand IPv4 ("127.1", "2130706433", "0x7f.1") is an IP to every resolver.
        try:
            return ipaddress.IPv4Address(socket.inet_aton(name))
        except OSError:
            return None
    return None


def check_target_name(host: str, allow_private: bool) -> None:
    """Checks that need no DNS: literal IPs and obviously local names."""
    name = host.lower().rstrip(".")
    if not name:
        raise DestinationRejected("destination has no host")
    address = literal_address(name)
    if address is not None:
        if not upstream_address_allowed(str(address), allow_private):
            raise DestinationRejected("destination address is not allowed")
        return
    if name == "localhost" or name.endswith(".localhost"):
        raise DestinationRejected("destination is a local name")
    if not allow_private and ("." not in name or name.endswith(_LOCAL_SUFFIXES)):
        raise DestinationRejected("destination is a LAN name")


Resolver = Callable[[str, int, DnsConfig], list[str]]


async def vetted_addresses(
    host: str,
    port: int,
    dns: DnsConfig,
    allow_private: bool,
    timeout: float,
    resolver: Resolver | None = None,
) -> list[str]:
    """Resolve with the operator DNS; every answer must be an allowed address."""
    try:
        resolved = await asyncio.wait_for(
            asyncio.to_thread(resolver or resolve_host, host, port, dns), timeout=timeout
        )
    except (OSError, ValueError, TimeoutError):
        raise DnsFailed() from None
    if not resolved:
        raise DnsFailed("no addresses")
    for item in resolved:
        if not upstream_address_allowed(item, allow_private):
            raise DestinationRejected("destination resolves to an address that is not allowed")
    return resolved


async def check_via_proxy(
    host: str,
    port: int,
    dns: DnsConfig,
    allow_private: bool,
    timeout: float,
    resolver: Resolver | None = None,
) -> None:
    """Best-effort policy when the proxy resolves the destination name."""
    check_target_name(host, allow_private)
    if literal_address(host) is not None:
        return
    try:
        resolved = await asyncio.wait_for(
            asyncio.to_thread(resolver or resolve_host, host, port, dns),
            timeout=min(timeout, 3.0),
        )
    except (OSError, ValueError, TimeoutError):
        return  # Local DNS may be the very thing the proxy works around.
    for item in resolved:
        try:
            # Private answers are ignored (filtering resolvers return 10.10.34.x);
            # loopback, link-local/metadata and reserved answers are refused.
            allowed = upstream_address_allowed(item, allow_private=True)
        except ValueError:
            continue
        if not allowed:
            raise DestinationRejected("destination resolves to a local address")


# --- clients -------------------------------------------------------------------


def new_httpx_client(
    proxy: str | None,
    timeout: httpx.Timeout | float,
    transport: httpx.AsyncBaseTransport | None = None,
) -> httpx.AsyncClient:
    """The one place an outbound httpx client is built (tests patch this)."""
    if proxy is not None:
        return httpx.AsyncClient(
            proxy=proxy, timeout=timeout, follow_redirects=False, trust_env=False
        )
    return httpx.AsyncClient(
        timeout=timeout, follow_redirects=False, trust_env=False, transport=transport
    )


class ClientPool:
    """One httpx client per route (direct + at most one proxy), closed together."""

    def __init__(
        self,
        timeout: httpx.Timeout | float,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.timeout = timeout
        self.transport = transport
        self._clients: dict[str | None, httpx.AsyncClient] = {}

    def get(self, route: ProxyRoute | None) -> httpx.AsyncClient:
        key = None if route is None else route.profile.id
        client = self._clients.get(key)
        if client is None:
            client = new_httpx_client(
                None if route is None else route.url, self.timeout, self.transport
            )
            self._clients[key] = client
        return client

    async def aclose(self) -> None:
        clients, self._clients = list(self._clients.values()), {}
        for client in clients:
            await client.aclose()

    async def __aenter__(self) -> ClientPool:
        return self

    async def __aexit__(self, *_exc: object) -> None:
        await self.aclose()


def pinned(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    address: str,
    headers: dict[str, str],
    content: bytes | None = None,
) -> httpx.Request:
    """Request to a vetted IP that keeps the real Host header, SNI and TLS check."""
    parsed = urlsplit(url)
    default_port = 443 if parsed.scheme == "https" else 80
    host_literal = f"[{address}]" if ":" in address else address
    target = parsed._replace(netloc=f"{host_literal}:{parsed.port or default_port}").geturl()
    hostname = parsed.hostname or ""
    host_header = f"[{hostname}]" if ":" in hostname else hostname
    if parsed.port:
        host_header = f"{host_header}:{parsed.port}"
    extensions: dict[str, Any] = {}
    if parsed.scheme == "https":
        extensions["sni_hostname"] = hostname
    return client.build_request(
        method,
        target,
        headers={**headers, "Host": host_header},
        content=content,
        extensions=extensions,
    )


class OutboundClient:
    """Send requests directly or through a proxy, always under the destination policy."""

    def __init__(
        self,
        network: NetworkSettingsStore | None,
        route: ProxyRoute | None,
        timeout: float,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
        resolver: Resolver | None = None,
        honour_no_proxy: bool = True,
        dns: DnsConfig | None = None,
        allow_private: bool | None = None,
    ) -> None:
        """``dns``/``allow_private`` override the live network settings when given."""
        self.network = network
        self.route = route
        self.timeout = timeout
        self.resolver = resolver
        self.honour_no_proxy = honour_no_proxy
        self._dns = dns
        self._allow_private = allow_private
        self.pool = ClientPool(timeout, transport)

    def _policy(self) -> tuple[DnsConfig, bool]:
        dns = self._dns
        allow_private = self._allow_private
        if dns is None:
            dns = self.network.dns() if self.network is not None else DnsConfig()
        if allow_private is None:
            allow_private = (
                self.network.allow_private_upstreams() if self.network is not None else False
            )
        return dns, allow_private

    def route_for(self, host: str) -> ProxyRoute | None:
        if self.route is None:
            return None
        if self.honour_no_proxy and self.route.bypasses(host):
            return None
        return self.route

    async def send(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        content: bytes | None = None,
        stream: bool = False,
    ) -> httpx.Response:
        parsed = urlsplit(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise DestinationRejected("destination must be an http(s) URL")
        if parsed.username or parsed.password:
            raise DestinationRejected("credentials in destination URLs are forbidden")
        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        dns, allow_private = self._policy()
        check_target_name(host, allow_private)
        route = self.route_for(host)
        client = self.pool.get(route)
        request_headers = dict(headers or {})
        if route is not None and not route.pins_locally:
            await check_via_proxy(host, port, dns, allow_private, self.timeout, self.resolver)
            request = client.build_request(
                method, url, headers=request_headers, content=content
            )
            return await client.send(request, stream=stream)
        addresses = await vetted_addresses(
            host, port, dns, allow_private, self.timeout, self.resolver
        )
        last_error: Exception | None = None
        for address in addresses[:3]:
            request = pinned(client, method, url, address, request_headers, content)
            try:
                return await client.send(request, stream=stream)
            except (httpx.ConnectError, httpx.ConnectTimeout) as exc:
                last_error = exc
        assert last_error is not None  # noqa: S101 - addresses is never empty
        raise last_error

    async def aclose(self) -> None:
        await self.pool.aclose()


@asynccontextmanager
async def outbound_client(
    network: NetworkSettingsStore,
    secret_store: SecretStore | None,
    proxy_ref: str | None,
    *,
    timeout: float,
    transport: httpx.AsyncBaseTransport | None = None,
    resolver: Resolver | None = None,
) -> AsyncIterator[OutboundClient]:
    """``proxy_ref``: None (direct), ``"default"`` or a proxy id.

    Raises ProxyUnavailable before any connection if the reference cannot be honoured.
    """
    route = await asyncio.to_thread(resolve_route, network, secret_store, proxy_ref)
    client = OutboundClient(network, route, timeout, transport=transport, resolver=resolver)
    try:
        yield client
    finally:
        await client.aclose()


def error_code(exc: BaseException) -> str:
    """Stable, secret-free code for an outbound failure."""
    if isinstance(exc, OutboundError):
        return exc.code
    if isinstance(exc, httpx.ProxyError):
        return "proxy_error"
    if isinstance(exc, httpx.TimeoutException | TimeoutError):
        return "timeout"
    if isinstance(exc, httpx.ConnectError):
        cause = exc.__cause__ or exc.__context__
        if isinstance(cause, ssl.SSLError) or "SSL" in type(cause).__name__:
            return "tls_error"
        return "connect_failed"
    if isinstance(exc, httpx.HTTPError):
        return "http_error"
    return "send_failed"


async def probe_proxy(
    network: NetworkSettingsStore,
    secret_store: SecretStore | None,
    profile: ProxyProfile,
    url: str,
    timeout: float = 10.0,
) -> dict[str, object]:
    """One HEAD-like GET through the proxy (no_proxy ignored; disabled profiles allowed)."""
    started = time.perf_counter()
    try:
        route = await asyncio.to_thread(build_route, profile, secret_store)
        client = OutboundClient(network, route, timeout, honour_no_proxy=False)
        try:
            response = await client.send(
                "GET", url, headers={"User-Agent": "MRK-ProxyTest/1"}, stream=True
            )
            status_code = response.status_code
            await response.aclose()
        finally:
            await client.aclose()
    except Exception as exc:  # never echo the message: it may contain the URL
        return {
            "ok": False,
            "latency_ms": round((time.perf_counter() - started) * 1000, 1),
            "error_code": error_code(exc),
        }
    result: dict[str, object] = {
        "ok": status_code < 500,
        "status_code": status_code,
        "latency_ms": round((time.perf_counter() - started) * 1000, 1),
    }
    if status_code >= 500:
        result["error_code"] = f"http_{status_code}"
    return result


# --- blocking SOCKS5 connect (SMTP) -----------------------------------------


def _recv_some(sock: socket.socket) -> bytes:
    data = sock.recv(4096)
    if not data:
        raise ConnectionError("SOCKS proxy closed the connection")
    return data


def socks_connect(
    route: ProxyRoute, host: str, port: int, timeout: float, address: str | None = None
) -> socket.socket:
    """Open a TCP stream to host:port through a SOCKS5 proxy (blocking, for smtplib).

    ``address`` (a vetted IP) is sent instead of the name for ``socks5``; with
    ``socks5h`` the proxy resolves ``host``.
    """
    from socksio import socks5  # optional dependency (httpx[socks])

    profile = route.profile
    if profile.type not in SOCKS_PROXY_TYPES:
        raise OutboundError("proxy_type_unsupported", "only SOCKS5 proxies can carry raw TCP")
    sock = socket.create_connection((profile.host, profile.port), timeout)
    try:
        conn = socks5.SOCKS5Connection()
        method = (
            socks5.SOCKS5AuthMethod.USERNAME_PASSWORD
            if profile.username
            else socks5.SOCKS5AuthMethod.NO_AUTH_REQUIRED
        )
        conn.send(socks5.SOCKS5AuthMethodsRequest([method]))
        sock.sendall(conn.data_to_send())
        reply = conn.receive_data(_recv_some(sock))
        if not isinstance(reply, socks5.SOCKS5AuthReply) or reply.method != method:
            raise ConnectionError("SOCKS proxy refused the authentication method")
        if method == socks5.SOCKS5AuthMethod.USERNAME_PASSWORD:
            conn.send(
                socks5.SOCKS5UsernamePasswordRequest(
                    (profile.username or "").encode("utf-8"),
                    (route.password or "").encode("utf-8"),
                )
            )
            sock.sendall(conn.data_to_send())
            auth = conn.receive_data(_recv_some(sock))
            if not isinstance(auth, socks5.SOCKS5UsernamePasswordReply) or not auth.success:
                raise ConnectionError("SOCKS proxy rejected the credentials")
        target = address if address is not None and route.pins_locally else host
        conn.send(
            socks5.SOCKS5CommandRequest.from_address(socks5.SOCKS5Command.CONNECT, (target, port))
        )
        sock.sendall(conn.data_to_send())
        response = conn.receive_data(_recv_some(sock))
        if (
            not isinstance(response, socks5.SOCKS5Reply)
            or response.reply_code != socks5.SOCKS5ReplyCode.SUCCEEDED
        ):
            raise ConnectionError("SOCKS proxy could not reach the destination")
        sock.settimeout(timeout)
        return sock
    except BaseException:
        sock.close()
        raise


# --- registry of outbound consumers -------------------------------------------


@dataclass(slots=True)
class OutboundProvider:
    """A family of outbound consumers (e.g. upstreams) that can carry a proxy_id.

    ``list_entries`` (blocking) returns ``[{"id", "name", "group", "proxy_id"}]``;
    ``supported_types(entry)`` the proxy types the consumer can use;
    ``set_proxy(id, proxy_id)`` (blocking) persists a new choice (KeyError if the
    id is unknown, OutboundError/ValueError for validation); ``on_change(entries)``
    runs after a change that affects these entries (e.g. reload Verdaccio).

    Example for a future module::

        outbound_registry(ctx.data_dir).register(OutboundProvider(
            kind="uptime_check", list_entries=..., supported_types=lambda _e: ALL_PROXY_TYPES,
            set_proxy=..., read_permission="monitoring:read",
            write_permission="monitoring:write"))
    """

    kind: str
    list_entries: Callable[[], list[dict[str, Any]]]
    supported_types: Callable[[dict[str, Any]], frozenset[str]]
    unsupported_code: str = "proxy_type_unsupported"
    set_proxy: Callable[[str, str | None], Any] | None = None
    read_permission: str = "upstream:read"
    write_permission: str = "upstream:write"
    on_change: Callable[[list[dict[str, Any]]], Awaitable[None]] | None = None


class OutboundRegistry:
    def __init__(self) -> None:
        self._providers: dict[str, OutboundProvider] = {}
        self._lock = threading.Lock()

    def register(self, provider: OutboundProvider) -> None:
        with self._lock:
            self._providers[provider.kind] = provider

    def provider(self, kind: str) -> OutboundProvider | None:
        with self._lock:
            return self._providers.get(kind)

    def entries(self) -> list[dict[str, Any]]:
        """Every consumer with its proxy setting; a failing provider is skipped."""
        with self._lock:
            providers = list(self._providers.values())
        result: list[dict[str, Any]] = []
        for provider in providers:
            try:
                items = provider.list_entries()
            except Exception:
                LOGGER.exception("outbound provider failed", extra={"kind": provider.kind})
                continue
            for item in items:
                entry = {
                    "kind": provider.kind,
                    "id": str(item["id"]),
                    "name": str(item.get("name") or item["id"]),
                    "group": item.get("group"),
                    "proxy_id": item.get("proxy_id") or None,
                }
                entry["supported_proxy_types"] = sorted(provider.supported_types(entry))
                result.append(entry)
        return result


_REGISTRIES: dict[Path, OutboundRegistry] = {}
_REGISTRIES_LOCK = threading.Lock()


def outbound_registry(data_dir: Path) -> OutboundRegistry:
    """Per data directory, so modules can contribute without a shared app object."""
    key = data_dir.resolve()
    with _REGISTRIES_LOCK:
        registry = _REGISTRIES.get(key)
        if registry is None:
            registry = _REGISTRIES[key] = OutboundRegistry()
        return registry


def users_of(
    entries: list[dict[str, Any]], proxy_id: str, default_proxy_id: str | None
) -> list[dict[str, Any]]:
    """Consumers that resolve to ``proxy_id`` (directly or through ``default``)."""
    users: list[dict[str, Any]] = []
    for entry in entries:
        reference = entry.get("proxy_id")
        if reference == proxy_id or (reference == DEFAULT_REF and default_proxy_id == proxy_id):
            users.append(
                {
                    "kind": entry["kind"],
                    "id": entry["id"],
                    "name": entry["name"],
                    "via_default": reference == DEFAULT_REF,
                }
            )
    return users


def new_proxy_id() -> str:
    return secrets.token_hex(6)
