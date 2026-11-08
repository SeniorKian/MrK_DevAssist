"""Read-only host facts for the DNS setup guide (docs/37 §4).

Only fixed paths are ever read, all below the read-only host mounts:

* ``<proc>/1/net/{udp,udp6,tcp,tcp6}`` - sockets bound to port 53 in the host
  network namespace (pid 1 is the host's init because ``/proc`` is bind-mounted);
* ``<proc>/<pid>/fd`` and ``<proc>/<pid>/comm`` - only to name the process that
  owns one of those sockets (best effort; needs permission to list the fds);
* ``<root>/etc/resolv.conf``, ``<root>/etc/systemd/resolved.conf``,
  ``<root>/etc/systemd/resolved.conf.d/*.conf`` and ``<root>/etc/docker/daemon.json``.

Symlinks (``/etc/resolv.conf`` usually is one) are resolved by hand and clamped
inside the host root, every file is size-capped and only parsed facts are
returned - never raw file contents.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import time
from pathlib import Path, PurePosixPath
from typing import Any

MAX_FILE_BYTES = 64 * 1024
MAX_NET_BYTES = 4 * 1024 * 1024
MAX_PIDS = 16384
MAX_FDS_PER_PID = 4096
SCAN_BUDGET_SECONDS = 1.5
MAX_DROPINS = 32
MAX_LIST = 16
DNS_PORT = 53
_DROPIN_RE = re.compile(r"^[A-Za-z0-9_.@-]{1,64}\.conf$")
_COMM_RE = re.compile(r"[^A-Za-z0-9_.:@/+-]")
_KEY_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
_SOCKET_RE = re.compile(r"^socket:\[(\d{1,20})\]$")
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
RESOLVED_STUB_ADDRESSES = frozenset({"127.0.0.53", "127.0.0.54"})


# ----------------------------------------------------------------------------- files


def resolve_in_root(root: Path, relative: str, max_hops: int = 8) -> Path | None:
    """Follow symlinks of ``relative`` as the host would, never leaving ``root``.

    Returns the final path (inside root) or None when the chain is too long or a
    component cannot be read. ``..`` at the top of the root stays at the root.
    """
    parts = [part for part in PurePosixPath(relative).parts if part not in {"/", ""}]
    current: list[str] = []
    hops = 0
    while parts:
        part = parts.pop(0)
        if part == ".":
            continue
        if part == "..":
            if current:
                current.pop()
            continue
        candidate = root.joinpath(*current, part)
        try:
            is_link = candidate.is_symlink()
        except OSError:
            return None
        if not is_link:
            current.append(part)
            continue
        hops += 1
        if hops > max_hops:
            return None
        try:
            target = os.readlink(candidate)
        except OSError:
            return None
        target_path = PurePosixPath(str(target).replace("\\", "/"))
        if target_path.is_absolute():
            current = []
        parts = [item for item in target_path.parts if item not in {"/", ""}] + parts
    return root.joinpath(*current) if current else root


def _read_text(path: Path, limit: int = MAX_FILE_BYTES) -> tuple[str | None, bool]:
    """(text, truncated) of a regular file; None if missing/unreadable/not a file."""
    try:
        fd = os.open(path, os.O_RDONLY | _O_NOFOLLOW)
    except OSError:
        return None, False
    try:
        if not os.path.isfile(path):
            return None, False
        with os.fdopen(fd, "rb", closefd=False) as handle:
            data = handle.read(limit + 1)
    except OSError:
        return None, False
    finally:
        os.close(fd)
    truncated = len(data) > limit
    return data[:limit].decode("utf-8", errors="replace"), truncated


def _symlink_target(root: Path, relative: str) -> str | None:
    path = root / relative
    try:
        if not path.is_symlink():
            return None
        target = os.readlink(path)
    except OSError:
        return None
    text = str(target).replace("\\", "/")
    return "".join(ch for ch in text if ch.isprintable())[:256]


def ip_text(value: str) -> str | None:
    text = value.strip()
    if "%" in text:  # fe80::1%eth0
        text = text.split("%", 1)[0]
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return None


def _resolved_server(value: str) -> str | None:
    """systemd-resolved DNS= entry: ``ip``, ``ip:port``, ``[ip]:port``, ``ip#name``."""
    text = value.split("#", 1)[0].strip()
    if text.startswith("["):
        text = text[1:].split("]", 1)[0]
    elif text.count(":") == 1:
        text = text.split(":", 1)[0]
    return ip_text(text)


def parse_resolv_conf(text: str) -> dict[str, Any]:
    nameservers: list[str] = []
    search: list[str] = []
    options: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped[0] in "#;":
            continue
        words = stripped.split()
        keyword, values = words[0], words[1:]
        if keyword == "nameserver" and values:
            address = ip_text(values[0])
            if address and address not in nameservers and len(nameservers) < MAX_LIST:
                nameservers.append(address)
        elif keyword in {"search", "domain"}:
            search = [item[:253] for item in values[:6] if item.isprintable()]
        elif keyword == "options":
            options.extend(item[:64] for item in values if item.isprintable())
    return {"nameservers": nameservers, "search": search, "options": options[:MAX_LIST]}


def parse_resolved_conf(text: str) -> dict[str, Any]:
    """Keys of the [Resolve] section that matter here. Empty value resets a list."""
    section = None
    result: dict[str, Any] = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped[0] in "#;":
            continue
        if stripped.startswith("[") and stripped.endswith("]"):
            section = stripped[1:-1].strip()
            continue
        if section != "Resolve" or "=" not in stripped:
            continue
        key, value = (part.strip() for part in stripped.split("=", 1))
        if key in {"DNS", "FallbackDNS"}:
            servers = [item for item in (_resolved_server(word) for word in value.split()) if item]
            result[key] = servers[:MAX_LIST] if value else []
        elif key == "DNSStubListener":
            result[key] = value.lower()[:16]
        elif key == "Domains":
            result[key] = [item[:253] for item in value.split()[:8] if item.isprintable()]
    return result


def resolved_facts(root: Path) -> dict[str, Any]:
    main_text, _ = _read_text(root / "etc" / "systemd" / "resolved.conf")
    effective: dict[str, Any] = {}
    if main_text is not None:
        effective.update(parse_resolved_conf(main_text))
    dropins: list[str] = []
    directory = root / "etc" / "systemd" / "resolved.conf.d"
    try:
        if directory.is_dir() and not directory.is_symlink():
            names = sorted(
                entry.name for entry in os.scandir(directory) if _DROPIN_RE.fullmatch(entry.name)
            )[:MAX_DROPINS]
        else:
            names = []
    except OSError:
        names = []
    for name in names:
        text, _ = _read_text(directory / name)
        if text is None:
            continue
        dropins.append(name)
        effective.update(parse_resolved_conf(text))
    stub = effective.get("DNSStubListener")
    return {
        "present": main_text is not None or bool(dropins),
        "dns": effective.get("DNS", []),
        "fallback_dns": effective.get("FallbackDNS", []),
        "dns_stub_listener": stub,
        "stub_disabled": stub in {"no", "false", "0", "off"},
        "domains": effective.get("Domains", []),
        "dropins": dropins,
        "mrk_dropin": "mrk.conf" in dropins,
    }


def resolv_conf_facts(root: Path) -> dict[str, Any]:
    target = _symlink_target(root, "etc/resolv.conf")
    final = resolve_in_root(root, "etc/resolv.conf")
    text, truncated = _read_text(final) if final is not None else (None, False)
    parsed = parse_resolv_conf(text) if text is not None else {
        "nameservers": [], "search": [], "options": []
    }
    managed_by = None
    if target and "systemd/resolve" in target:
        managed_by = "systemd-resolved"
    elif target and "NetworkManager" in target:
        managed_by = "NetworkManager"
    elif target and "resolvconf" in target:
        managed_by = "resolvconf"
    elif target is None and text is not None:
        managed_by = "static"
    mode = None
    if target and target.endswith("stub-resolv.conf"):
        mode = "stub"
    elif target and target.endswith("systemd/resolve/resolv.conf"):
        mode = "uplink"
    return {
        "present": text is not None,
        "symlink": target,
        "managed_by": managed_by,
        "resolved_mode": mode,
        "truncated": truncated,
        **parsed,
    }


def docker_daemon_facts(root: Path) -> dict[str, Any]:
    text, truncated = _read_text(root / "etc" / "docker" / "daemon.json")
    if text is None:
        return {"present": False, "valid": None, "dns": None, "keys": []}
    if truncated:
        return {"present": True, "valid": False, "dns": None, "keys": []}
    try:
        payload = json.loads(text) if text.strip() else {}
    except ValueError:
        return {"present": True, "valid": False, "dns": None, "keys": []}
    if not isinstance(payload, dict):
        return {"present": True, "valid": False, "dns": None, "keys": []}
    raw_dns = payload.get("dns")
    dns = None
    if isinstance(raw_dns, list):
        dns = [item for item in (ip_text(str(value)) for value in raw_dns[:MAX_LIST]) if item]
    keys = sorted(key for key in payload if isinstance(key, str) and _KEY_RE.fullmatch(key))[:64]
    return {"present": True, "valid": True, "dns": dns, "keys": keys}


# ----------------------------------------------------------------------------- sockets


def _hex_ipv4(text: str) -> str:
    return str(ipaddress.IPv4Address(bytes.fromhex(text)[::-1]))


def _hex_ipv6(text: str) -> str:
    raw = bytes.fromhex(text)
    words = b"".join(raw[index : index + 4][::-1] for index in range(0, 16, 4))
    return str(ipaddress.IPv6Address(words))


def parse_proc_net(
    text: str, proto: str, family: int, port: int = DNS_PORT
) -> list[dict[str, Any]]:
    """Bound sockets on ``port``: TCP in LISTEN (0A), UDP unconnected (07)."""
    wanted_state = "0A" if proto == "tcp" else "07"
    result: list[dict[str, Any]] = []
    for line in text.splitlines()[1:]:
        fields = line.split()
        if len(fields) < 10:
            continue
        local, state, inode = fields[1], fields[3], fields[9]
        if state.upper() != wanted_state or ":" not in local:
            continue
        address_hex, port_hex = local.rsplit(":", 1)
        try:
            if int(port_hex, 16) != port:
                continue
            address = _hex_ipv4(address_hex) if family == 4 else _hex_ipv6(address_hex)
        except ValueError:
            continue
        result.append({
            "proto": proto,
            "family": family,
            "address": address,
            "port": port,
            "inode": int(inode) if inode.isdigit() else None,
            "process": None,
        })
    return result


def _comm(proc: Path, pid: str) -> str | None:
    text, _ = _read_text(proc / pid / "comm", 64)
    if text is None:
        return None
    return _COMM_RE.sub("", text.strip())[:32] or None


def owners(proc: Path, inodes: set[int]) -> tuple[dict[int, dict[str, Any]], bool]:
    """inode -> {pid, comm} by scanning fd links; (owners, complete)."""
    found: dict[int, dict[str, Any]] = {}
    if not inodes:
        return found, True
    deadline = time.monotonic() + SCAN_BUDGET_SECONDS
    complete = True
    try:
        pids = [entry.name for entry in os.scandir(proc) if entry.name.isdigit()][:MAX_PIDS]
    except OSError:
        return found, False
    for pid in pids:
        if time.monotonic() > deadline:
            complete = False
            break
        fd_dir = proc / pid / "fd"
        try:
            with os.scandir(fd_dir) as entries:
                for count, entry in enumerate(entries):
                    if count >= MAX_FDS_PER_PID:
                        break
                    try:
                        link = os.readlink(entry.path)
                    except OSError:
                        continue
                    match = _SOCKET_RE.match(str(link))
                    if match and int(match.group(1)) in inodes:
                        inode = int(match.group(1))
                        found.setdefault(inode, {"pid": int(pid), "comm": _comm(proc, pid)})
        except OSError:
            complete = False  # no permission to list this process's fds
            continue
        if len(found) == len(inodes):
            break
    return found, complete


def resolved_running(proc: Path) -> bool | None:
    try:
        pids = [entry.name for entry in os.scandir(proc) if entry.name.isdigit()][:MAX_PIDS]
    except OSError:
        return None
    for pid in pids:
        if _comm(proc, pid) == "systemd-resolve":  # comm is truncated to 15 chars
            return True
    return False


def listener_facts(proc: Path) -> dict[str, Any]:
    listeners: list[dict[str, Any]] = []
    readable = False
    for name, proto, family in (
        ("udp", "udp", 4), ("udp6", "udp", 6), ("tcp", "tcp", 4), ("tcp6", "tcp", 6),
    ):
        text, _ = _read_text(proc / "1" / "net" / name, MAX_NET_BYTES)
        if text is None:
            continue
        readable = True
        listeners.extend(parse_proc_net(text, proto, family))
    inodes = {item["inode"] for item in listeners if item["inode"]}
    found, complete = owners(proc, inodes)
    for item in listeners:
        owner = found.get(item["inode"] or -1)
        if owner is not None:
            item["process"] = owner
        if item["address"] in RESOLVED_STUB_ADDRESSES and owner is None:
            item["process_hint"] = "systemd-resolved"
        item.pop("inode", None)
    unique: list[dict[str, Any]] = []
    for item in listeners:
        if item not in unique:
            unique.append(item)
    return {"readable": readable, "owners_complete": complete, "items": unique[:64]}


def collect(proc: Path | None, root: Path | None) -> dict[str, Any]:
    """Everything the setup guide needs; each part degrades independently."""
    proc_ok = proc is not None and proc != Path("/proc") and (proc / "1").is_dir()
    root_ok = root is not None and root.is_dir()
    return {
        "host_proc": proc_ok,
        "host_root": root_ok,
        "port_53": listener_facts(proc) if proc_ok and proc is not None else {
            "readable": False, "owners_complete": False, "items": []
        },
        "systemd_resolved_running": resolved_running(proc) if proc_ok and proc else None,
        "resolv_conf": resolv_conf_facts(root) if root_ok and root else None,
        "resolved": resolved_facts(root) if root_ok and root else None,
        "docker_daemon": docker_daemon_facts(root) if root_ok and root else None,
    }
