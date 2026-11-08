"""Per-container counters from a read-only cgroup v2 hierarchy (no Docker stats stream).

The host's ``/sys/fs/cgroup`` is mounted at ``MRK_AGENT_HOST_CGROUP`` (default
``/host/cgroup``). Docker places a container either at
``system.slice/docker-<full id>.scope`` (systemd cgroup driver) or
``docker/<full id>`` (cgroupfs driver); both are tried.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

DEFAULT_HOST_CGROUP = "/host/cgroup"
_FULL_ID = re.compile(r"^[0-9a-f]{64}$")


def resolve_cgroup_dir(configured: str | None = None) -> Path:
    return Path(configured or os.getenv("MRK_AGENT_HOST_CGROUP", "") or DEFAULT_HOST_CGROUP)


def available(root: Path) -> bool:
    """cgroup v2 exposes ``cgroup.controllers`` at its root (v1 does not)."""
    return (root / "cgroup.controllers").is_file()


def container_dir(root: Path, container_id: str) -> Path | None:
    if not _FULL_ID.fullmatch(container_id):
        return None
    for candidate in (
        root / "system.slice" / f"docker-{container_id}.scope",
        root / "docker" / container_id,
    ):
        if candidate.is_dir():
            return candidate
    return None


def _read(path: Path, limit: int = 65536) -> str | None:
    try:
        with path.open("r", encoding="ascii", errors="replace") as handle:
            return handle.read(limit)
    except OSError:
        return None


def _int_text(text: str | None) -> int | None:
    if text is None:
        return None
    value = text.strip()
    return int(value) if value.isdigit() else None


def parse_cpu_stat(text: str) -> int | None:
    for line in text.splitlines():
        key, _, value = line.partition(" ")
        if key == "usage_usec" and value.strip().isdigit():
            return int(value.strip())
    return None


def parse_io_stat(text: str) -> tuple[int, int]:
    """Sum ``rbytes``/``wbytes`` over every device line of io.stat."""
    read_total = write_total = 0
    for line in text.splitlines():
        for item in line.split()[1:]:
            key, _, value = item.partition("=")
            if not value.isdigit():
                continue
            if key == "rbytes":
                read_total += int(value)
            elif key == "wbytes":
                write_total += int(value)
    return read_total, write_total


def read_container(root: Path, container_id: str) -> dict[str, Any] | None:
    directory = container_dir(root, container_id)
    if directory is None:
        return None
    cpu_text = _read(directory / "cpu.stat")
    max_text = _read(directory / "memory.max", 64)
    io_text = _read(directory / "io.stat")
    io_read, io_write = parse_io_stat(io_text) if io_text else (0, 0)
    return {
        "cpu_usage_usec": (parse_cpu_stat(cpu_text) if cpu_text else None) or 0,
        "mem_bytes": _int_text(_read(directory / "memory.current", 64)) or 0,
        # "max" means unlimited.
        "mem_limit_bytes": _int_text(max_text),
        "io_read_bytes": io_read,
        "io_write_bytes": io_write,
    }
