"""Operator-configurable DNS resolution for outbound upstream traffic.

The operator chooses, from the panel and without a restart, whether upstream
hostnames are resolved by the container's system resolver or by their own list
of DNS servers (useful when the host resolver is filtered or poisoned). The
setting lives in ``/data/control-plane/network.json`` so every process (control
plane, PyPI router) sees changes on its next request.

The DNS client below is a small stdlib-only stub resolver: it sends one
recursive query per record type to the configured servers (UDP, TCP fallback on
truncation) and reads A/AAAA answers. It is intentionally minimal; the future
DNS module builds its own full engine.
"""

from __future__ import annotations

import ipaddress
import json
import os
import secrets
import socket
import struct
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import TypeVar
from urllib.parse import urlsplit

import httpx

TYPE_A = 1
TYPE_AAAA = 28
CLASS_IN = 1
MAX_SERVERS = 6
T = TypeVar("T")


@dataclass(frozen=True, slots=True)
class DnsServer:
    address: str
    port: int = 53

    def label(self) -> str:
        host = f"[{self.address}]" if ":" in self.address else self.address
        return host if self.port == 53 else f"{host}:{self.port}"


@dataclass(frozen=True, slots=True)
class DnsConfig:
    mode: str = "system"  # "system" or "custom"
    servers: tuple[DnsServer, ...] = field(default_factory=tuple)
    timeout_seconds: float = 2.0
    prefer_ipv4: bool = True

    def public(self) -> dict[str, object]:
        return {
            "mode": self.mode,
            "servers": [item.label() for item in self.servers],
            "timeout_seconds": self.timeout_seconds,
            "prefer_ipv4": self.prefer_ipv4,
        }


def parse_server(value: str) -> DnsServer:
    text = value.strip()
    port = 53
    if text.startswith("["):
        host, _, rest = text[1:].partition("]")
        if rest.startswith(":"):
            port = int(rest[1:])
        elif rest:
            raise ValueError("unexpected text after the IPv6 address")
        text = host
    elif text.count(":") == 1:
        text, port_text = text.split(":")
        port = int(port_text)
    address = ipaddress.ip_address(text)
    if not 1 <= port <= 65535:
        raise ValueError("DNS server port is out of range")
    if address.is_unspecified or address.is_multicast:
        raise ValueError("DNS server address is not usable")
    return DnsServer(str(address), port)


def validate_config(payload: dict[str, object]) -> DnsConfig:
    mode = str(payload.get("mode", "system"))
    if mode not in {"system", "custom"}:
        raise ValueError("DNS mode must be system or custom")
    raw_servers = payload.get("servers", [])
    if not isinstance(raw_servers, list):
        raise ValueError("DNS servers must be a list")
    try:
        servers = tuple(dict.fromkeys(parse_server(str(item)) for item in raw_servers))
    except (ValueError, TypeError) as exc:
        raise ValueError(f"invalid DNS server: {exc}") from None
    if len(servers) > MAX_SERVERS:
        raise ValueError(f"at most {MAX_SERVERS} DNS servers are supported")
    if mode == "custom" and not servers:
        raise ValueError("custom DNS mode needs at least one server")
    timeout = float(str(payload.get("timeout_seconds", 2.0)))
    if not 0.2 <= timeout <= 10:
        raise ValueError("DNS timeout must be between 0.2 and 10 seconds")
    prefer_ipv4 = payload.get("prefer_ipv4", True)
    if not isinstance(prefer_ipv4, bool):
        # bool("false") is True; only real booleans are accepted.
        raise ValueError("prefer_ipv4 must be a boolean")
    return DnsConfig(mode, servers, timeout, prefer_ipv4)


# Ranges an operator may opt into for internal mirrors (allow_private_upstreams).
# Loopback, link-local (incl. 169.254.169.254 metadata), multicast, reserved and
# unspecified addresses stay forbidden whatever the setting says.
PRIVATE_UPSTREAM_NETWORKS = tuple(
    ipaddress.ip_network(item)
    for item in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7")
)


def upstream_address_allowed(value: str, allow_private: bool = False) -> bool:
    """Whether an upstream may be reached at this IP address."""
    address = ipaddress.ip_address(value)
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    if (
        address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_unspecified
        or address.is_reserved
    ):
        return False
    if address.is_global:
        return True
    return allow_private and any(address in network for network in PRIVATE_UPSTREAM_NETWORKS)


@dataclass(frozen=True, slots=True)
class _NetworkSnapshot:
    dns: DnsConfig
    allow_private: bool
    proxies: tuple[dict[str, object], ...]
    default_proxy_id: str | None


class NetworkSettingsStore:
    """``network.json``: DNS, the private-upstream policy and outbound proxy profiles.

    Proxy profiles are stored raw here; ``outbound`` owns their validation.
    """

    def __init__(self, data_dir: Path) -> None:
        self.path = data_dir / "control-plane" / "network.json"
        self._lock = threading.RLock()
        self._cache: tuple[float, _NetworkSnapshot] | None = None

    def _snapshot(self) -> _NetworkSnapshot:
        try:
            mtime = self.path.stat().st_mtime
        except OSError:
            return _NetworkSnapshot(DnsConfig(), False, (), None)
        cached = self._cache
        if cached is not None and cached[0] == mtime:
            return cached[1]
        payload = self._read_payload()
        try:
            config = validate_config(dict(payload.get("dns", {})))
        except (ValueError, TypeError, AttributeError):
            # A broken file must not break traffic; fall back to the system resolver.
            config = DnsConfig()
        policy = payload.get("upstream_policy")
        allow_private = (
            isinstance(policy, dict) and policy.get("allow_private_upstreams") is True
        )
        raw_proxies = payload.get("proxies")
        proxies = tuple(
            dict(item)
            for item in (raw_proxies if isinstance(raw_proxies, list) else [])
            if isinstance(item, dict)
        )
        default_id = payload.get("default_proxy_id")
        snapshot = _NetworkSnapshot(
            config,
            allow_private,
            proxies,
            default_id if isinstance(default_id, str) and default_id else None,
        )
        self._cache = (mtime, snapshot)
        return snapshot

    def _load(self) -> tuple[DnsConfig, bool]:
        snapshot = self._snapshot()
        return snapshot.dns, snapshot.allow_private

    def _read_payload(self) -> dict[str, object]:
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}
        return dict(payload) if isinstance(payload, dict) else {}

    def dns(self) -> DnsConfig:
        return self._snapshot().dns

    def allow_private_upstreams(self) -> bool:
        """Operator opt-in for RFC1918/ULA/CGNAT and LAN-style upstream hosts."""
        return self._snapshot().allow_private

    def proxies_raw(self) -> list[dict[str, object]]:
        """Stored proxy profiles (unvalidated dicts; see ``outbound``)."""
        return [dict(item) for item in self._snapshot().proxies]

    def default_proxy_id(self) -> str | None:
        return self._snapshot().default_proxy_id

    def _write_locked(self, changes: dict[str, object]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        payload = self._read_payload() if self.path.exists() else {}
        payload.update(changes)
        temporary = self.path.with_name(f".{self.path.name}.{secrets.token_hex(4)}.tmp")
        temporary.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        temporary.chmod(0o600)
        os.replace(temporary, self.path)
        self._cache = None

    def _update(self, key: str, value: object) -> None:
        with self._lock:
            self._write_locked({key: value})

    def mutate_proxies(
        self,
        change: Callable[
            [list[dict[str, object]], str | None],
            tuple[list[dict[str, object]], str | None, T],
        ],
    ) -> T:
        """Read-modify-write the proxy list and default id under one lock."""
        with self._lock:
            self._cache = None
            snapshot = self._snapshot()
            items, default_id, result = change(
                [dict(item) for item in snapshot.proxies], snapshot.default_proxy_id
            )
            self._write_locked({"proxies": items, "default_proxy_id": default_id})
            return result

    def save_dns(self, config: DnsConfig) -> DnsConfig:
        self._update("dns", config.public())
        return config

    def save_upstream_policy(self, allow_private_upstreams: bool) -> bool:
        self._update("upstream_policy", {"allow_private_upstreams": allow_private_upstreams})
        return allow_private_upstreams


# --- minimal DNS stub client -------------------------------------------------


def _encode_name(name: str) -> bytes:
    encoded = b""
    for label in name.rstrip(".").split("."):
        raw = label.encode("idna")
        if not 0 < len(raw) < 64:
            raise ValueError("invalid DNS name")
        encoded += bytes([len(raw)]) + raw
    if len(encoded) + 1 > 255:
        raise ValueError("DNS name is too long")
    return encoded + b"\x00"


def _build_query(name: str, qtype: int) -> tuple[int, bytes]:
    query_id = secrets.randbelow(65536)
    header = struct.pack("!HHHHHH", query_id, 0x0100, 1, 0, 0, 0)  # RD set
    return query_id, header + _encode_name(name) + struct.pack("!HH", qtype, CLASS_IN)


class _ForeignPacket(ValueError):
    """A datagram that is not the answer to our query (wrong ID or not a response)."""


# Small positive cache for custom-DNS answers: every upstream request resolves
# the host again, and without it each one paid full DNS latency.
_CACHE_MAX_ENTRIES = 1024
_CACHE_MAX_TTL = 60
_cache_lock = threading.Lock()
_cache: dict[tuple[str, tuple[DnsServer, ...], bool], tuple[float, list[str]]] = {}


def _skip_name(message: bytes, offset: int) -> int:
    while True:
        if offset >= len(message):
            raise ValueError("truncated DNS name")
        length = message[offset]
        if length == 0:
            return offset + 1
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(message):
                raise ValueError("truncated DNS compression pointer")
            return offset + 2
        if length & 0xC0:
            raise ValueError("unsupported DNS label type")
        offset += 1 + length


def _parse_answer(
    message: bytes, query_id: int, qtype: int
) -> tuple[list[str], bool, int]:
    """Return (addresses, truncated, min_ttl). Never raises struct.error."""
    if len(message) < 12:
        raise _ForeignPacket("short DNS response")
    response_id, flags, qdcount, ancount, _ns, _ar = struct.unpack("!HHHHHH", message[:12])
    if response_id != query_id or not flags & 0x8000:
        raise _ForeignPacket("unexpected DNS response")
    rcode = flags & 0x000F
    if rcode == 3:
        raise socket.gaierror(socket.EAI_NONAME, "name does not exist")
    if rcode != 0:
        raise ValueError(f"DNS server returned rcode {rcode}")
    if flags & 0x0200:
        # Truncated: the answer section may be cut mid-record; retry over TCP.
        return [], True, 0
    offset = 12
    for _ in range(qdcount):
        offset = _skip_name(message, offset) + 4
    addresses: list[str] = []
    min_ttl = _CACHE_MAX_TTL
    for _ in range(ancount):
        offset = _skip_name(message, offset)
        if offset + 10 > len(message):
            raise ValueError("truncated DNS answer")
        rtype, _rclass, ttl, rdlength = struct.unpack("!HHIH", message[offset : offset + 10])
        offset += 10
        if offset + rdlength > len(message):
            raise ValueError("truncated DNS answer data")
        rdata = message[offset : offset + rdlength]
        offset += rdlength
        if rtype == qtype == TYPE_A and rdlength == 4:
            addresses.append(str(ipaddress.IPv4Address(rdata)))
            min_ttl = min(min_ttl, ttl)
        elif rtype == qtype == TYPE_AAAA and rdlength == 16:
            addresses.append(str(ipaddress.IPv6Address(rdata)))
            min_ttl = min(min_ttl, ttl)
    return addresses, False, min_ttl


def _parse_addresses(message: bytes, query_id: int, qtype: int) -> tuple[list[str], bool]:
    addresses, truncated, _ttl = _parse_answer(message, query_id, qtype)
    return addresses, truncated


def _query_server(
    server: DnsServer, name: str, qtype: int, timeout: float
) -> tuple[list[str], int]:
    query_id, packet = _build_query(name, qtype)
    family = socket.AF_INET6 if ":" in server.address else socket.AF_INET
    deadline = time.monotonic() + timeout
    with socket.socket(family, socket.SOCK_DGRAM) as udp:
        udp.settimeout(timeout)
        udp.connect((server.address, server.port))
        udp.send(packet)
        while True:
            udp.settimeout(max(deadline - time.monotonic(), 0.01))
            message = udp.recv(4096)
            try:
                addresses, truncated, ttl = _parse_answer(message, query_id, qtype)
                break
            except _ForeignPacket:
                # Only stray datagrams are skipped; a real error answer
                # (SERVFAIL, REFUSED, malformed) fails over immediately.
                if time.monotonic() >= deadline:
                    raise
    if not truncated:
        return addresses, ttl
    remaining = max(deadline - time.monotonic(), 0.2)
    with socket.create_connection((server.address, server.port), timeout=remaining) as tcp:
        tcp.sendall(struct.pack("!H", len(packet)) + packet)
        size = struct.unpack("!H", _recv_exact(tcp, 2, deadline))[0]
        addresses, _truncated, ttl = _parse_answer(
            _recv_exact(tcp, size, deadline), query_id, qtype
        )
    return addresses, ttl


def _recv_exact(sock: socket.socket, size: int, deadline: float | None = None) -> bytes:
    data = b""
    while len(data) < size:
        if deadline is not None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("DNS TCP response deadline exceeded")
            sock.settimeout(remaining)
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ValueError("DNS TCP connection closed early")
        data += chunk
    return data


def clear_dns_cache() -> None:
    with _cache_lock:
        _cache.clear()


def resolve_custom(name: str, config: DnsConfig) -> list[str]:
    """Resolve A and AAAA through the operator's servers, trying each in order."""
    key = (name.lower().rstrip("."), config.servers, config.prefer_ipv4)
    now = time.monotonic()
    with _cache_lock:
        cached = _cache.get(key)
        if cached is not None and cached[0] > now:
            return list(cached[1])
    last_error: Exception | None = None
    for server in config.servers:
        found: list[str] = []
        ttl = _CACHE_MAX_TTL
        for qtype in (TYPE_A, TYPE_AAAA):
            if qtype == TYPE_AAAA and found and config.prefer_ipv4:
                # IPv4 is preferred and present; an AAAA query that a filtering
                # resolver drops would only add a full timeout to every request.
                break
            try:
                addresses, record_ttl = _query_server(
                    server, name, qtype, config.timeout_seconds
                )
            except socket.gaierror:
                raise
            except (TimeoutError, OSError, ValueError) as exc:
                last_error = exc
                continue
            if addresses:
                ttl = min(ttl, record_ttl)
            found.extend(addresses)
        if found:
            if ttl > 0:
                with _cache_lock:
                    if len(_cache) >= _CACHE_MAX_ENTRIES:
                        _cache.clear()
                    _cache[key] = (time.monotonic() + ttl, list(found))
            return found
    raise socket.gaierror(socket.EAI_AGAIN, f"DNS lookup failed: {last_error!r}")


def resolve_host(host: str, port: int, config: DnsConfig) -> list[str]:
    """Return IP addresses for host using the configured resolver mode."""
    try:
        ipaddress.ip_address(host)
        return [host]
    except ValueError:
        pass
    if config.mode == "custom":
        addresses = resolve_custom(host, config)
    else:
        addresses = [
            str(item[4][0])
            for item in socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM)
        ]
    unique = list(dict.fromkeys(addresses))
    if config.prefer_ipv4:
        unique.sort(key=lambda item: ":" in item)
    return unique


def pinned_request(
    client: httpx.AsyncClient, method: str, url: str, address: str, headers: dict[str, str]
) -> httpx.Request:
    """Connect to an already-vetted IP while keeping the real Host, SNI and TLS check.

    Connecting by name would resolve again, allowing DNS rebinding between the
    check and the connection, and would ignore the operator's DNS servers.
    """
    parsed = urlsplit(url)
    host_literal = f"[{address}]" if ":" in address else address
    pinned = parsed._replace(netloc=f"{host_literal}:{parsed.port or 443}").geturl()
    host_header = parsed.hostname or ""
    if parsed.port:
        host_header = f"{host_header}:{parsed.port}"
    return client.build_request(
        method,
        pinned,
        headers={**headers, "Host": host_header},
        extensions={"sni_hostname": parsed.hostname or ""},
    )
