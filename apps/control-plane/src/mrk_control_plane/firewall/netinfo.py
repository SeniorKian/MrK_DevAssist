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
