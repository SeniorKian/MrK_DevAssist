"""Address parsing and safety classification shared by the helper and the control plane.

Everything that ends up in an nftables element is produced by ``parse_network`` from
``ipaddress`` objects, never from raw user text.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network
IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

# A block wider than this is refused: one typo must not drop half the internet.
MIN_BLOCK_PREFIX = {4: 16, 6: 32}
MIN_ALLOW_PREFIX = {4: 1, 6: 1}
MAX_TEXT = 64

LOOPBACK = (ipaddress.ip_network("127.0.0.0/8"), ipaddress.ip_network("::1/128"))
PRIVATE_RANGES: tuple[IPNetwork, ...] = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
)


class AddressError(ValueError):
    """Invalid address text; ``code`` is a stable API error code."""

    def __init__(self, message: str, code: str = "invalid_address") -> None:
        super().__init__(message)
        self.code = code


def _unmap(network: IPNetwork) -> IPNetwork:
    if isinstance(network, ipaddress.IPv6Network) and network.prefixlen >= 96:
        mapped = network.network_address.ipv4_mapped
        if mapped is not None:
            return ipaddress.ip_network(f"{mapped}/{network.prefixlen - 96}")
    return network


def parse_network(value: object) -> IPNetwork:
    """Parse an IP or CIDR; host bits are cleared, IPv4-mapped IPv6 becomes IPv4."""
    if not isinstance(value, str):
        raise AddressError("address must be a string")
    text = value.strip()
    if not text or len(text) > MAX_TEXT or any(ch.isspace() for ch in text):
        raise AddressError("address is invalid")
    if "%" in text:
        raise AddressError("scoped IPv6 addresses are not supported")
    try:
        network = ipaddress.ip_network(text, strict=False)
    except ValueError as exc:
        raise AddressError("address is not a valid IP or CIDR") from exc
    return _unmap(network)


def parse_ip(value: object) -> IPAddress | None:
    """Parse a single client address from a log line; None when it is not an IP."""
    if not isinstance(value, str) or not value or len(value) > MAX_TEXT:
        return None
    try:
        address = ipaddress.ip_address(value.strip().strip("[]"))
    except ValueError:
        return None
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return address.ipv4_mapped
    return address


def element(network: IPNetwork) -> str:
    """nft element text: a bare address for full-length prefixes, else CIDR."""
    if network.prefixlen == network.max_prefixlen:
        return str(network.network_address)
    return str(network)


def is_loopback(network: IPNetwork) -> bool:
    return any(_overlaps(network, item) for item in LOOPBACK)


def is_private(network: IPNetwork) -> bool:
    return any(_overlaps(network, item) for item in PRIVATE_RANGES)


def _overlaps(a: IPNetwork, b: IPNetwork) -> bool:
    return a.version == b.version and a.overlaps(b)  # type: ignore[arg-type]


def contains(container: IPNetwork, inner: IPNetwork | IPAddress) -> bool:
    if container.version != inner.version:
        return False
    if isinstance(inner, ipaddress.IPv4Address | ipaddress.IPv6Address):
        return inner in container
    return inner.subnet_of(container)  # type: ignore[arg-type]


def covered_by(target: IPNetwork | IPAddress, networks: Iterable[IPNetwork]) -> bool:
    return any(contains(network, target) for network in networks)


def check_block_shape(network: IPNetwork) -> None:
    """Shape rules every block must satisfy, enforced by both processes."""
    if network.prefixlen < MIN_BLOCK_PREFIX[network.version]:
        raise AddressError(
            f"blocks wider than /{MIN_BLOCK_PREFIX[network.version]} are refused",
            "prefix_too_broad",
        )
    if is_loopback(network):
        raise AddressError("loopback cannot be blocked", "loopback")
    address = network.network_address
    if address.is_unspecified or address.is_multicast or address.is_reserved:
        raise AddressError("unspecified, multicast and reserved ranges cannot be blocked",
                           "reserved_address")


def check_allow_shape(network: IPNetwork) -> None:
    if network.prefixlen < MIN_ALLOW_PREFIX[network.version]:
        raise AddressError("an allowlist entry cannot cover every address", "prefix_too_broad")


def drop_covered(networks: Iterable[IPNetwork]) -> list[IPNetwork]:
    """Remove networks contained in another one (nft interval sets reject overlaps)."""
    unique = sorted(set(networks), key=lambda item: (item.version, item.prefixlen,
                                                     int(item.network_address)))
    kept: list[IPNetwork] = []
    for network in unique:
        if not any(contains(existing, network) for existing in kept):
            kept.append(network)
    return sorted(kept, key=lambda item: (item.version, int(item.network_address),
                                          item.prefixlen))
