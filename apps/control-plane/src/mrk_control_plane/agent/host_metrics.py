"""Read-only host metrics from a (bind-mounted) host /proc and statvfs."""

from __future__ import annotations

import os
import threading
from pathlib import Path
from typing import Any

DEFAULT_HOST_PROC = "/host/proc"
DEFAULT_HOST_ROOT = "/host/root"


def resolve_proc_dir(configured: str | None = None) -> Path:
    candidate = Path(configured or os.getenv("MRK_AGENT_HOST_PROC", "") or DEFAULT_HOST_PROC)
    if (candidate / "meminfo").is_file():
        return candidate
    return Path("/proc")


def resolve_root_paths(configured: str | None = None) -> list[Path]:
    """MRK_AGENT_HOST_ROOT is a comma-separated list of paths to report disk usage for."""
    raw = configured if configured is not None else os.getenv("MRK_AGENT_HOST_ROOT", "")
    paths = [Path(item.strip()) for item in raw.split(",") if item.strip()]
    if paths:
        return paths
    return [Path(DEFAULT_HOST_ROOT)] if Path(DEFAULT_HOST_ROOT).is_dir() else [Path("/")]


def _read(path: Path, limit: int = 65536) -> str | None:
    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            return handle.read(limit)
    except OSError:
        return None


def parse_meminfo(text: str) -> dict[str, int]:
    values: dict[str, int] = {}
    for line in text.splitlines():
        key, _, rest = line.partition(":")
        parts = rest.split()
        if parts and parts[0].isdigit():
            multiplier = 1024 if len(parts) > 1 and parts[1].lower() == "kb" else 1
            values[key.strip()] = int(parts[0]) * multiplier
    return values


def parse_loadavg(text: str) -> list[float] | None:
    parts = text.split()
    try:
        return [float(parts[0]), float(parts[1]), float(parts[2])]
    except (IndexError, ValueError):
        return None


def parse_cpu_count(text: str) -> int | None:
    count = sum(
        1
        for line in text.splitlines()
        if line.startswith("cpu") and len(line) > 3 and line[3].isdigit()
    )
    return count or None


def disk_usage(path: Path) -> dict[str, Any] | None:
    try:
        stats = os.statvfs(path)  # type: ignore[attr-defined,unused-ignore]
    except (OSError, AttributeError):
        return None
    total = stats.f_blocks * stats.f_frsize
    free = stats.f_bavail * stats.f_frsize
    return {
        "path": str(path),
        "total_bytes": total,
        "free_bytes": free,
        "used_bytes": max(total - stats.f_bfree * stats.f_frsize, 0),
    }


def collect(proc_dir: Path, root_paths: list[Path]) -> dict[str, Any]:
    hostname = None
    for root in root_paths:
        text = _read(root / "etc" / "hostname", 256)
        if text and text.strip():
            hostname = text.strip()[:253]
            break
    if hostname is None:
        text = _read(proc_dir / "sys" / "kernel" / "hostname", 256)
        hostname = text.strip()[:253] if text and text.strip() else None
    kernel_text = _read(proc_dir / "sys" / "kernel" / "osrelease", 256)
    uptime_text = _read(proc_dir / "uptime", 256)
    uptime = None
    if uptime_text:
        try:
            uptime = float(uptime_text.split()[0])
        except (IndexError, ValueError):
            uptime = None
    meminfo = parse_meminfo(_read(proc_dir / "meminfo") or "")
    stat_text = _read(proc_dir / "stat", 262144)
    cpu_count = parse_cpu_count(stat_text) if stat_text else None
    return {
        "hostname": hostname,
        "kernel": kernel_text.strip()[:128] if kernel_text else None,
        "uptime_seconds": uptime,
        "cpu_count": cpu_count or os.cpu_count(),
        "loadavg": parse_loadavg(_read(proc_dir / "loadavg", 256) or ""),
        "memory": {
            "total_bytes": meminfo.get("MemTotal"),
            "available_bytes": meminfo.get("MemAvailable"),
        },
        "disks": [usage for path in root_paths if (usage := disk_usage(path)) is not None],
        "source": str(proc_dir),
    }


def available(proc_dir: Path) -> bool:
    return (proc_dir / "meminfo").is_file()


# ----- Gate 17: /v1/metrics -------------------------------------------------

# Virtual interfaces are skipped so container traffic (veth -> bridge -> uplink) is
# not counted two or three times; what remains approximates the host's uplinks.
_VIRTUAL_INTERFACE_PREFIXES = ("lo", "veth", "docker", "br-", "virbr", "cni", "flannel", "vxlan")


def parse_cpu_times(text: str) -> tuple[int, int] | None:
    """Return (total, idle) jiffies from the aggregate ``cpu`` line of /proc/stat.

    guest/guest_nice are already included in user/nice, so they are not added again.
    """
    for line in text.splitlines():
        if not line.startswith("cpu "):
            continue
        fields = line.split()[1:]
        try:
            values = [int(value) for value in fields[:8]]
        except ValueError:
            return None
        if len(values) < 4:
            return None
        values += [0] * (8 - len(values))
        idle = values[3] + values[4]  # idle + iowait
        return sum(values), idle
    return None


class CpuSampler:
    """Host CPU percent from the delta to the previous /proc/stat sample (first: None)."""

    def __init__(self) -> None:
        self._previous: tuple[int, int] | None = None
        self._lock = threading.Lock()

    def sample(self, stat_text: str | None) -> float | None:
        current = parse_cpu_times(stat_text) if stat_text else None
        if current is None:
            return None
        with self._lock:
            previous, self._previous = self._previous, current
        if previous is None:
            return None
        total_delta = current[0] - previous[0]
        idle_delta = current[1] - previous[1]
        if total_delta <= 0 or idle_delta < 0:
            return None
        busy = max(total_delta - idle_delta, 0)
        return round(min(busy * 100.0 / total_delta, 100.0), 2)


def parse_net_dev(text: str) -> tuple[int, int] | None:
    """Sum rx/tx bytes over non-virtual interfaces of a /proc/<pid>/net/dev file."""
    rx_total = tx_total = 0
    seen = False
    for line in text.splitlines():
        name, separator, rest = line.partition(":")
        if not separator:
            continue
        interface = name.strip()
        fields = rest.split()
        if len(fields) < 9 or not interface or interface.startswith(_VIRTUAL_INTERFACE_PREFIXES):
            continue
        try:
            rx_total += int(fields[0])
            tx_total += int(fields[8])
        except ValueError:
            continue
        seen = True
    return (rx_total, tx_total) if seen else None


def net_dev_path(proc_dir: Path) -> Path:
    """Host network counters.

    ``<proc>/net/dev`` is a symlink to ``self/net/dev``: it shows the *reader's* network
    namespace (the agent's private compose network), not the host's. ``<proc>/1/net/dev``
    is PID 1 of the mounted procfs, i.e. the host init process and its (host) network
    namespace when the host's /proc is mounted. Falls back to ``net/dev`` otherwise.
    """
    candidate = proc_dir / "1" / "net" / "dev"
    if candidate.is_file():
        return candidate
    return proc_dir / "net" / "dev"


def collect_metrics_host(
    proc_dir: Path, root_paths: list[Path], sampler: CpuSampler
) -> dict[str, Any]:
    meminfo = parse_meminfo(_read(proc_dir / "meminfo") or "")
    total = meminfo.get("MemTotal")
    available_bytes = meminfo.get("MemAvailable")
    load = parse_loadavg(_read(proc_dir / "loadavg", 256) or "")
    net = parse_net_dev(_read(net_dev_path(proc_dir), 262144) or "")
    disks = []
    for path in root_paths:
        usage = disk_usage(path)
        if usage is not None:
            disks.append(
                {
                    "path": usage["path"],
                    "total_bytes": usage["total_bytes"],
                    "used_bytes": usage["used_bytes"],
                }
            )
    return {
        "cpu_percent": sampler.sample(_read(proc_dir / "stat", 262144)),
        "load1": load[0] if load else None,
        "mem_total_bytes": total,
        "mem_used_bytes": max(total - available_bytes, 0)
        if total is not None and available_bytes is not None
        else None,
        "disks": disks,
        "net_rx_bytes": net[0] if net else None,
        "net_tx_bytes": net[1] if net else None,
    }
