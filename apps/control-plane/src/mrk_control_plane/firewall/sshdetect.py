"""Which TCP ports the host's SSH server really listens on (the lockout guard needs it).

Sources, best first:

1. **listener** - the helper shares the host network namespace, so ``/proc/net/tcp{,6}``
   lists the host's LISTEN sockets. Each one gets a short non-blocking connection (one
   ``select`` loop for all of them, ~0.5 s in total) and the first bytes are read: a
   server that greets with ``SSH-`` is an SSH server. OpenSSH/Dropbear banners are the
   host's sshd; other SSH servers (for example Gitea's built-in one published by a
   container) are reported separately and never used for the lockout check.
2. **ssh_socket** - systemd socket activation (Ubuntu 22.10+): ``ListenStream=`` of
   ``ssh.socket`` overrides in ``/etc/systemd/system``; with socket activation the
   ``Port`` lines of sshd_config are ignored.
3. **sshd_config** - ``Port`` / ``ListenAddress`` lines, ``Include`` files included.
4. **assumed** - nothing readable: 22.

Only the facts are collected here; nothing is ever written.
"""

from __future__ import annotations

import selectors
import socket
import time
from collections.abc import Callable, Iterable
from typing import Any

from . import importers

PROBE_TIMEOUT = 0.5
MAX_PROBES = 64
# Re-probe when the set of listeners changes, else at most this often.
PROBE_MAX_AGE = 300.0
_HOST_SSHD = ("openssh", "dropbear", "tinyssh")
_LIKELY_SSH = (22, 2222, 6022, 22222)
# A wildcard bind is reached through loopback (never sends anything off the host).
_WILDCARD = {"0.0.0.0": "127.0.0.1", "::": "::1"}  # noqa: S104 - matched, not bound

BannerReader = Callable[[list[tuple[int, str]], float], dict[int, str]]


def probe_targets(listeners: Iterable[tuple[int, str]]) -> list[tuple[int, str]]:
    """One connect address per port: wildcard binds via loopback, else the bound address.
    Ports bound to loopback only are skipped (not reachable from outside anyway)."""
    chosen: dict[int, str] = {}
    for port, address in listeners:
        if address in _WILDCARD:
            target = _WILDCARD[address]
        elif address.startswith("127.") or address == "::1":
            continue
        else:
            target = address
        current = chosen.get(port)
        # Prefer loopback targets: they work for wildcard binds and never leave the host.
        if current is None or (target in {"127.0.0.1", "::1"}
                               and current not in {"127.0.0.1", "::1"}):
            chosen[port] = target
    ordered = sorted(chosen.items(), key=lambda item: (item[0] not in _LIKELY_SSH, item[0]))
    return ordered[:MAX_PROBES]


def read_banners(targets: list[tuple[int, str]], timeout: float = PROBE_TIMEOUT
                 ) -> dict[int, str]:
    """Connect to every target at once and collect the first line each server sends
    within ``timeout`` seconds in total. Servers that wait for the client stay silent."""
    selector = selectors.DefaultSelector()
    sockets: list[socket.socket] = []
    banners: dict[int, str] = {}
    deadline = time.monotonic() + timeout
    try:
        for port, address in targets:
            family = socket.AF_INET6 if ":" in address else socket.AF_INET
            try:
                sock = socket.socket(family, socket.SOCK_STREAM)
            except OSError:
                continue
            sockets.append(sock)
            sock.setblocking(False)
            try:
                sock.connect_ex((address, port))
                selector.register(sock, selectors.EVENT_READ, (port, bytearray()))
            except OSError:
                continue
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            for key, _events in selector.select(remaining):
                port, buffer = key.data
                try:
                    chunk = key.fileobj.recv(256)  # type: ignore[union-attr]
                except (BlockingIOError, InterruptedError):
                    continue
                except OSError:
                    chunk = b""
                buffer.extend(chunk)
                if not chunk or b"\n" in buffer or len(buffer) >= 255:
                    selector.unregister(key.fileobj)
                    line = bytes(buffer).split(b"\n", 1)[0].strip()
                    if line:
                        banners[port] = line[:200].decode("ascii", errors="replace")
    finally:
        for sock in sockets:
            try:
                sock.close()
            except OSError:
                pass
        selector.close()
    return banners


def classify(banners: dict[int, str]) -> dict[str, Any]:
    host: list[int] = []
    other: list[dict[str, Any]] = []
    for port, banner in sorted(banners.items()):
        if not banner.startswith("SSH-"):
            continue
        software = banner.split("-", 2)[2] if banner.count("-") >= 2 else ""
        if any(name in software.lower() for name in _HOST_SSHD):
            host.append(port)
        else:
            other.append({"port": port, "software": software[:60]})
    return {"ports": host, "other": other}


class ListenerProbe:
    """Cached SSH banner detection (the probes cost a connection each)."""

    def __init__(self, reader: BannerReader | None = None,
                 clock: Callable[[], float] = time.monotonic) -> None:
        self.reader = reader or read_banners
        self.clock = clock
        self._key: tuple[tuple[int, str], ...] | None = None
        self._at = 0.0
        self._value: dict[str, Any] | None = None

    def detect(self, listeners: list[tuple[int, str]] | None) -> dict[str, Any]:
        if listeners is None:
            return {"available": False, "ports": [], "other": [], "probed": 0}
        targets = probe_targets(listeners)
        key = tuple(targets)
        now = self.clock()
        if self._value is not None and key == self._key and now - self._at < PROBE_MAX_AGE:
            return self._value
        try:
            banners = self.reader(targets, PROBE_TIMEOUT) if targets else {}
        except OSError:
            banners = {}
        self._value = {"available": True, **classify(banners), "probed": len(targets)}
        self._key, self._at = key, now
        return self._value


def ssh_facts(etc_root: Any, listener: dict[str, Any]) -> dict[str, Any]:
    """All SSH port sources plus the winner (``ports`` + ``source``)."""
    config = importers.read_sshd_config(etc_root)
    unit = importers.read_ssh_socket(etc_root)
    if listener.get("available") and listener.get("ports"):
        ports, source = list(listener["ports"]), "listener"
    elif unit.get("enabled") and unit.get("explicit") and unit.get("ports"):
        ports, source = list(unit["ports"]), "ssh_socket"
    elif config["readable"]:
        ports, source = list(config["ports"]), "sshd_config"
    else:
        ports, source = [22], "assumed"
    return {
        # ``detected``/``ports`` keep the shape older panels read.
        "detected": source != "assumed",
        "ports": ports or [22],
        "source": source,
        "sources": {"listener": listener, "sshd_config": config, "ssh_socket": unit},
        "mounts": {"ssh": config["readable"], "systemd": unit["readable"]},
    }
