"""Host-local addresses (incl. Docker bridge gateways) from the host network namespace.

The helper runs with ``network_mode: host``, so ``/proc/net`` is the host's. These
addresses are never blockable: blocking ``docker0``/``br-*`` gateways or the host's own
IPs would cut containers or the host off from itself.
"""

from __future__ import annotations

import ipaddress
from pathlib import Path


def parse_fib_trie(text: str) -> set[str]:
    found: set[str] = set()
    last: str | None = None
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("|-- "):
            last = line[4:].strip()
        elif last and line.startswith("/32 host LOCAL"):
            try:
                found.add(str(ipaddress.IPv4Address(last)))
            except ValueError:
                pass
    return found


def parse_if_inet6(text: str) -> set[str]:
    found: set[str] = set()
    for line in text.splitlines():
        parts = line.split()
        if not parts or len(parts[0]) != 32:
            continue
        try:
            found.add(str(ipaddress.IPv6Address(int(parts[0], 16))))
        except ValueError:
            continue
    return found


def local_addresses(proc_net: Path = Path("/proc/net")) -> list[str]:
    addresses: set[str] = set()
    for name, parser in (("fib_trie", parse_fib_trie), ("if_inet6", parse_if_inet6)):
        try:
            addresses |= parser((proc_net / name).read_text(encoding="ascii", errors="ignore"))
        except OSError:
            continue
    return sorted(addresses, key=lambda item: (":" in item, item))


def _hex_address(text: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        raw = bytes.fromhex(text)
    except ValueError:
        return None
    if len(raw) == 4:
        return ipaddress.IPv4Address(raw[::-1])
    if len(raw) == 16:
        # /proc/net/*6 prints four host-order 32-bit words.
        words = b"".join(raw[index:index + 4][::-1] for index in range(0, 16, 4))
        return ipaddress.IPv6Address(words)
    return None


def parse_proc_net_sockets(text: str, protocol: str) -> list[dict[str, object]]:
    """Listening TCP (state 0A) / bound UDP (state 07) sockets of /proc/net/{tcp,udp}[6]."""
    wanted = "0A" if protocol == "tcp" else "07"
    found: list[dict[str, object]] = []
    for line in text.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 4 or parts[3] != wanted or ":" not in parts[1]:
            continue
        address_hex, _, port_hex = parts[1].rpartition(":")
        try:
            port = int(port_hex, 16)
        except ValueError:
            continue
        address = _hex_address(address_hex)
        if address is None or port == 0:
            continue
        mapped = getattr(address, "ipv4_mapped", None)
        if mapped is not None:
            address = mapped
        found.append({"protocol": protocol, "port": port,
                      "loopback_only": address.is_loopback})
    return found


def parse_tcp_listeners(text: str) -> list[tuple[int, str]]:
    """(port, bound address) of every LISTEN socket in /proc/net/tcp[6]."""
    found: list[tuple[int, str]] = []
    for line in text.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 4 or parts[3] != "0A" or ":" not in parts[1]:
            continue
        address_hex, _, port_hex = parts[1].rpartition(":")
        try:
            port = int(port_hex, 16)
        except ValueError:
            continue
        address = _hex_address(address_hex)
        if address is None or port == 0:
            continue
        mapped = getattr(address, "ipv4_mapped", None)
        found.append((port, str(mapped if mapped is not None else address)))
    return found


def tcp_listeners(proc_net: Path = Path("/proc/net")) -> list[tuple[int, str]] | None:
    """Unique (port, address) LISTEN sockets of the host, IPv4 and IPv6 (None when
    /proc/net cannot be read at all)."""
    seen: set[tuple[int, str]] = set()
    readable = False
    for name in ("tcp", "tcp6"):
        try:
            text = (proc_net / name).read_text(encoding="ascii", errors="ignore")
        except OSError:
            continue
        readable = True
        seen.update(parse_tcp_listeners(text))
    return sorted(seen) if readable else None


def listening_ports(proc_net: Path = Path("/proc/net")) -> list[dict[str, object]]:
    """Ports open on the host: [{protocol, port, loopback_only}] (loopback_only when every
    listener of that port binds a loopback address)."""
    merged: dict[tuple[str, int], bool] = {}
    for name, protocol in (("tcp", "tcp"), ("tcp6", "tcp"), ("udp", "udp"), ("udp6", "udp")):
        try:
            text = (proc_net / name).read_text(encoding="ascii", errors="ignore")
        except OSError:
            continue
        for item in parse_proc_net_sockets(text, protocol):
            key = (protocol, int(item["port"]))  # type: ignore[call-overload]
            merged[key] = merged.get(key, True) and bool(item["loopback_only"])
    return [{"protocol": protocol, "port": port, "loopback_only": loopback}
            for (protocol, port), loopback in sorted(merged.items())]
