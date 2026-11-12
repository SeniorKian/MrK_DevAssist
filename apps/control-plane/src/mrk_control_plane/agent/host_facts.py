"""Read-only facts about the machine (what it is) and raw live counters (what it does).

Everything is read from fixed paths under the mounted host ``/proc`` (``proc_dir``),
the host's ``/sys`` (``sys_dir``) and the read-only host root (``host_root``). Nothing
is written, no command is run, and every read is size-limited. Values that a server
does not expose (no temperature sensors on most VPSes, no DMI data on some ARM boards)
are reported as missing, never guessed.

``collect_facts`` changes rarely and is cached by the caller; ``collect_live`` returns
monotonic counters (CPU jiffies, disk sectors, network bytes) so the panel can turn two
samples into rates without the agent keeping per-client state.
"""

from __future__ import annotations

import ipaddress
import os
import platform
import re
import shutil
import socket
import struct
from pathlib import Path
from typing import Any

from .host_metrics import parse_loadavg, parse_meminfo

DEFAULT_HOST_SYS = "/host/sys"

MAX_CPUS = 512
MAX_BLOCK_DEVICES = 32
MAX_FILESYSTEMS = 24
MAX_INTERFACES = 32
MAX_ADDRESSES = 8
MAX_HWMON = 16
MAX_SENSORS = 48
_SMALL = 4096
_TEXT_LIMIT = 128

# Interfaces that only carry container/bridge traffic (the same list as /v1/metrics).
VIRTUAL_INTERFACE_PREFIXES = (
    "lo", "veth", "docker", "br-", "virbr", "cni", "flannel", "vxlan", "cali", "kube-ipvs",
)
_WHOLE_DISK = re.compile(
    r"^(?:sd[a-z]{1,3}|vd[a-z]{1,3}|xvd[a-z]{1,3}|hd[a-z]{1,3}|nvme\d+n\d+|mmcblk\d+|md\d+)$"
)
_SKIPPED_FS = frozenset({"squashfs", "iso9660", "tmpfs", "devtmpfs", "overlay", "ramfs", "udf"})
_SKIPPED_MOUNT_PREFIXES = ("/var/lib/docker/", "/snap/", "/run/", "/var/snap/")
_SIZE_TEXT = re.compile(r"^\s*(\d{1,12})\s*([KMG]?)\s*(?:B|iB)?\s*$", re.IGNORECASE)

# Lower-cased DMI vendor/product fragments -> virtualization technology.
_VIRT_SIGNATURES = (
    ("qemu", "kvm"),
    ("kvm", "kvm"),
    ("bochs", "kvm"),
    ("vmware", "vmware"),
    ("innotek", "virtualbox"),
    ("virtualbox", "virtualbox"),
    ("xen", "xen"),
    ("amazon ec2", "amazon"),
    ("google compute engine", "google"),
    ("parallels", "parallels"),
    ("openstack", "openstack"),
    ("bhyve", "bhyve"),
    ("apple virtualization", "apple"),
)


def resolve_sys_dir(configured: str | None = None, host_root: Path | None = None) -> Path:
    """The host's sysfs: an explicit mount, else the one under the host root, else ours.

    Most of sysfs (DMI, block, thermal, hwmon, cpu) is the host's even inside a
    container; only ``class/net`` follows the reader's network namespace, which is why
    a host view (``/host/sys`` or ``/host/root/sys``) is preferred when present.
    """
    explicit = configured or os.getenv("MRK_AGENT_HOST_SYS", "").strip()
    if explicit:
        return Path(explicit)
    for candidate in (Path(DEFAULT_HOST_SYS), host_root / "sys" if host_root else None):
        if candidate is not None and (candidate / "class").is_dir():
            return candidate
    return Path("/sys")


def _read(path: Path, limit: int = _SMALL) -> str | None:
    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            return handle.read(limit)
    except (OSError, ValueError):
        return None


def _text(path: Path, limit: int = _TEXT_LIMIT) -> str | None:
    value = _read(path, 512)
    if value is None:
        return None
    cleaned = "".join(ch for ch in value.strip() if ch.isprintable())[:limit].strip()
    return cleaned or None


def _int(path: Path) -> int | None:
    value = _read(path, 64)
    if value is None:
        return None
    value = value.strip()
    if re.fullmatch(r"-?\d{1,20}", value):
        return int(value)
    return None


def _listdir(path: Path, limit: int) -> list[str]:
    try:
        names = sorted(os.listdir(path))
    except OSError:
        return []
    return names[:limit]


# ----- OS ----------------------------------------------------------------------------


def parse_os_release(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in text.splitlines():
        key, sep, value = line.strip().partition("=")
        if not sep or not re.fullmatch(r"[A-Z_]{1,32}", key):
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        values[key] = value.replace('\\"', '"')[:_TEXT_LIMIT]
    return values


def _inside_root(root: Path, relative: str) -> Path | None:
    """Resolve ``relative`` under ``root`` following at most a few symlinks, never escaping."""
    current = root / relative.lstrip("/")
    for _ in range(4):
        if not current.is_symlink():
            break
        try:
            target = os.readlink(current)
        except OSError:
            return None
        current = root / target.lstrip("/") if target.startswith("/") else current.parent / target
        normalized = Path(os.path.normpath(current))
        if normalized != root and root not in normalized.parents:
            return None
        current = normalized
    return current


def read_os(host_root: Path | None) -> dict[str, Any]:
    if host_root is None:
        return {"pretty_name": None, "id": None, "version_id": None}
    for name in ("etc/os-release", "usr/lib/os-release"):
        path = _inside_root(host_root, name)
        text = _read(path, 8192) if path is not None else None
        if text:
            values = parse_os_release(text)
            pretty = values.get("PRETTY_NAME") or " ".join(
                part for part in (values.get("NAME"), values.get("VERSION")) if part
            )
            return {
                "pretty_name": pretty or None,
                "id": values.get("ID") or None,
                "version_id": values.get("VERSION_ID") or None,
            }
    return {"pretty_name": None, "id": None, "version_id": None}


# ----- CPU ---------------------------------------------------------------------------


def parse_cpuinfo(text: str) -> dict[str, Any]:
    blocks: list[dict[str, str]] = []
    current: dict[str, str] = {}
    for line in text.splitlines():
        if not line.strip():
            if current:
                blocks.append(current)
                current = {}
            continue
        key, sep, value = line.partition(":")
        if sep:
            current[key.strip().lower()] = value.strip()
    if current:
        blocks.append(current)
    processors = [block for block in blocks if "processor" in block]
    header = {key: value for block in blocks for key, value in block.items()}
    first = processors[0] if processors else header
    model = None
    for key in ("model name", "cpu model", "hardware", "model", "cpu"):
        value = first.get(key) or header.get(key)
        if value and not value.isdigit():
            model = " ".join(value.split())[:_TEXT_LIMIT]
            break
    vendor = (first.get("vendor_id") or first.get("cpu implementer") or "")[:64] or None
    sockets = {block.get("physical id") for block in processors if block.get("physical id")}
    core_ids = {
        (block.get("physical id"), block.get("core id"))
        for block in processors
        if block.get("core id") is not None
    }
    threads = len(processors)
    cores: int | None = len(core_ids) or None
    if cores is None:
        per_socket = first.get("cpu cores")
        if per_socket and per_socket.isdigit():
            cores = int(per_socket) * max(len(sockets), 1)
    mhz_values = []
    for block in processors:
        try:
            mhz_values.append(float(block.get("cpu mhz", "")))
        except ValueError:
            continue
    flags = set((first.get("flags") or first.get("features") or "").split())
    return {
        "model": model,
        "vendor": vendor,
        "sockets": len(sockets) or (1 if threads else None),
        "cores": cores or (threads or None),
        "threads": threads or None,
        "mhz": round(sum(mhz_values) / len(mhz_values), 1) if mhz_values else None,
        "cache_text": (first.get("cache size") or "")[:32] or None,
        "hypervisor_flag": "hypervisor" in flags,
        "virtualization_flags": sorted(flags & {"vmx", "svm"}),
    }


def size_text_bytes(text: str | None) -> int | None:
    match = _SIZE_TEXT.match(text or "")
    if not match:
        return None
    unit = {"": 1, "K": 1024, "M": 1024**2, "G": 1024**3}[match.group(2).upper()]
    return int(match.group(1)) * unit


def read_cpu_caches(sys_dir: Path) -> list[dict[str, Any]]:
    base = sys_dir / "devices" / "system" / "cpu" / "cpu0" / "cache"
    caches = []
    for name in _listdir(base, 8):
        if not name.startswith("index"):
            continue
        level = _int(base / name / "level")
        kind = _text(base / name / "type", 16)
        size = size_text_bytes(_text(base / name / "size", 16))
        if level is None or size is None:
            continue
        label = f"L{level}" + ("d" if kind == "Data" else "i" if kind == "Instruction" else "")
        caches.append({"level": label, "size_bytes": size})
    return caches


def read_cpu_frequency(sys_dir: Path) -> dict[str, float | None]:
    base = sys_dir / "devices" / "system" / "cpu"
    max_khz = _int(base / "cpu0" / "cpufreq" / "cpuinfo_max_freq")
    min_khz = _int(base / "cpu0" / "cpufreq" / "cpuinfo_min_freq")
    return {
        "max_mhz": round(max_khz / 1000, 1) if max_khz and max_khz > 0 else None,
        "min_mhz": round(min_khz / 1000, 1) if min_khz and min_khz > 0 else None,
    }


def current_cpu_mhz(sys_dir: Path, count: int) -> float | None:
    """Average current clock from cpufreq (absent on most VPSes)."""
    base = sys_dir / "devices" / "system" / "cpu"
    values = []
    for index in range(min(count, MAX_CPUS)):
        khz = _int(base / f"cpu{index}" / "cpufreq" / "scaling_cur_freq")
        if khz and khz > 0:
            values.append(khz)
    return round(sum(values) / len(values) / 1000, 1) if values else None


# ----- machine / virtualization -------------------------------------------------------


def read_machine(sys_dir: Path, cpu: dict[str, Any]) -> dict[str, Any]:
    dmi = sys_dir / "class" / "dmi" / "id"
    vendor = _text(dmi / "sys_vendor")
    product = _text(dmi / "product_name")
    board = _text(dmi / "board_name")
    bios_vendor = _text(dmi / "bios_vendor")
    hypervisor_type = _text(sys_dir / "hypervisor" / "type", 32)
    if vendor is None and product is None:
        # ARM boards describe themselves in the device tree instead of DMI.
        product = _text(sys_dir / "firmware" / "devicetree" / "base" / "model")
    haystack = " ".join(
        value.lower() for value in (vendor, product, board, bios_vendor) if value
    )
    technology = None
    for fragment, name in _VIRT_SIGNATURES:
        if fragment in haystack:
            technology = name
            break
    if technology is None and "microsoft" in haystack and "virtual" in haystack:
        technology = "microsoft"
    if technology is None and hypervisor_type:
        technology = hypervisor_type.lower()[:16]
    if technology is not None or cpu.get("hypervisor_flag"):
        kind = "vm"
    elif vendor or product:
        kind = "bare_metal"
    else:
        kind = "unknown"
    return {
        "vendor": vendor,
        "product": product,
        "board": board,
        "virtualization": kind,
        "technology": technology,
    }


# ----- storage -----------------------------------------------------------------------


def _unescape_mount(value: str) -> str:
    return re.sub(r"\\([0-7]{3})", lambda match: chr(int(match.group(1), 8)), value)


def parse_mounts(text: str) -> list[dict[str, str]]:
    """Real block-device file systems from a mounts table, one entry per device."""
    seen: set[str] = set()
    result = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        device, mountpoint, fstype = parts[0], _unescape_mount(parts[1]), parts[2]
        if not device.startswith("/dev/") or fstype in _SKIPPED_FS:
            continue
        if device.startswith("/dev/loop") or mountpoint.startswith(_SKIPPED_MOUNT_PREFIXES):
            continue
        if device in seen or len(mountpoint) > 256:
            continue
        seen.add(device)
        result.append({"device": device[:128], "mountpoint": mountpoint, "fstype": fstype[:32]})
    return result


def _usage(path: Path) -> tuple[int, int, int] | None:
    """(total, used, free-for-users) like ``df``; shutil uses statvfs on Linux."""
    try:
        usage = shutil.disk_usage(path)
    except OSError:
        return None
    return int(usage.total), int(usage.used), int(usage.free)


def read_filesystems(proc_dir: Path, host_root: Path | None) -> list[dict[str, Any]]:
    text = _read(proc_dir / "1" / "mounts", 262144) or _read(proc_dir / "mounts", 262144) or ""
    entries = parse_mounts(text)
    root_device: int | None = None
    if host_root is not None:
        try:
            root_device = os.stat(host_root).st_dev
        except OSError:
            root_device = None
    result = []
    for entry in entries[:MAX_FILESYSTEMS]:
        usage = None
        if host_root is not None:
            target = host_root / entry["mountpoint"].lstrip("/")
            visible = True
            if entry["mountpoint"] != "/":
                # A sub-mount the bind mount does not show would report the parent's
                # numbers; skip those rather than show a wrong size.
                try:
                    visible = os.stat(target).st_dev != root_device
                except OSError:
                    visible = False
            usage = _usage(target) if visible else None
        result.append(
            {
                **entry,
                "total_bytes": usage[0] if usage else None,
                "used_bytes": usage[1] if usage else None,
                "free_bytes": usage[2] if usage else None,
            }
        )
    return result


def block_kind(name: str, rotational: int | None, model: str | None) -> str:
    lowered = (model or "").lower()
    if name.startswith("nvme"):
        return "nvme"
    if name.startswith("mmcblk"):
        return "mmc"
    if name.startswith("md"):
        return "raid"
    if name.startswith(("vd", "xvd")) or any(
        word in lowered for word in ("qemu", "virtual", "vbox", "vmware", "harddisk ")
    ):
        return "virtual"
    if rotational == 1:
        return "hdd"
    if rotational == 0:
        return "ssd"
    return "unknown"


def read_block_devices(sys_dir: Path) -> list[dict[str, Any]]:
    base = sys_dir / "block"
    result = []
    for name in _listdir(base, 256):
        if not _WHOLE_DISK.fullmatch(name):
            continue
        device = base / name
        sectors = _int(device / "size")
        if not sectors:
            continue
        rotational = _int(device / "queue" / "rotational")
        model = _text(device / "device" / "model", 64)
        result.append(
            {
                "name": name,
                "size_bytes": sectors * 512,
                "model": model,
                "vendor": _text(device / "device" / "vendor", 32),
                "rotational": None if rotational is None else rotational == 1,
                "removable": _int(device / "removable") == 1,
                "kind": block_kind(name, rotational, model),
            }
        )
        if len(result) >= MAX_BLOCK_DEVICES:
            break
    return result


# ----- network -----------------------------------------------------------------------


def is_virtual_interface(name: str) -> bool:
    return name.startswith(VIRTUAL_INTERFACE_PREFIXES)


def net_dev_text(proc_dir: Path) -> str:
    """The host network namespace's counters (see host_metrics.net_dev_path)."""
    return _read(proc_dir / "1" / "net" / "dev", 262144) or _read(
        proc_dir / "net" / "dev", 262144
    ) or ""


def parse_net_interfaces(text: str) -> dict[str, list[int]]:
    """iface -> [rx_bytes, rx_packets, rx_errors, tx_bytes, tx_packets, tx_errors]."""
    result: dict[str, list[int]] = {}
    for line in text.splitlines():
        name, sep, rest = line.partition(":")
        if not sep:
            continue
        name = name.strip()
        fields = rest.split()
        if not name or len(fields) < 11 or is_virtual_interface(name):
            continue
        if not re.fullmatch(r"[A-Za-z0-9_.@-]{1,32}", name):
            continue
        try:
            values = [int(fields[i]) for i in (0, 1, 2, 8, 9, 10)]
        except ValueError:
            continue
        result[name] = values
        if len(result) >= MAX_INTERFACES:
            break
    return result


def parse_fib_trie_locals(text: str) -> list[str]:
    """IPv4 addresses the host owns (``/32 host LOCAL`` leaves of the main table)."""
    found: list[str] = []
    previous = ""
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("/32 host LOCAL") and previous:
            candidate = previous.split()[-1]
            try:
                ip = ipaddress.IPv4Address(candidate)
            except ValueError:
                candidate = ""
            else:
                if not ip.is_loopback and candidate not in found:
                    found.append(candidate)
        if stripped.startswith("|--"):
            previous = stripped
    return found[:64]


def parse_routes(text: str) -> list[tuple[str, int, int, bool]]:
    """(iface, destination, mask, is_default) from /proc/net/route (little-endian hex)."""
    routes = []
    for line in text.splitlines()[1:]:
        fields = line.split()
        if len(fields) < 8:
            continue
        try:
            # The kernel prints the in-memory (network byte order) u32 as hex, so the
            # value equals the little-endian reading of the address bytes.
            destination = int(fields[1], 16)
            gateway = int(fields[2], 16)
            mask = int(fields[7], 16)
        except ValueError:
            continue
        is_default = destination == 0 and mask == 0 and gateway != 0
        routes.append((fields[0], destination, mask, is_default))
    return routes


def _ipv4_int(text: str) -> int:
    return int(struct.unpack("<I", socket.inet_aton(text))[0])


def assign_ipv4(
    locals_: list[str], routes: list[tuple[str, int, int, bool]]
) -> dict[str, list[str]]:
    by_iface: dict[str, list[str]] = {}
    defaults = {iface for iface, _d, _m, is_default in routes if is_default}
    for ip in locals_:
        value = _ipv4_int(ip)
        best: tuple[int, str] | None = None
        for iface, destination, mask, is_default in routes:
            if is_default or mask == 0:
                continue
            if value & mask == destination & mask:
                bits = bin(mask).count("1")
                if best is None or bits > best[0]:
                    best = (bits, iface)
        iface = best[1] if best else (next(iter(defaults)) if len(defaults) == 1 else None)
        if iface:
            by_iface.setdefault(iface, []).append(ip)
    return by_iface


def parse_if_inet6(text: str) -> dict[str, list[str]]:
    """Global-scope IPv6 addresses per interface (link-local and loopback left out)."""
    result: dict[str, list[str]] = {}
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 6 or len(fields[0]) != 32:
            continue
        if fields[3] != "00":  # scope: 00 = global
            continue
        try:
            address = ipaddress.IPv6Address(bytes.fromhex(fields[0]))
        except ValueError:
            continue
        result.setdefault(fields[5][:32], []).append(str(address))
    return result


def read_interfaces(proc_dir: Path, sys_dir: Path) -> list[dict[str, Any]]:
    counters = parse_net_interfaces(net_dev_text(proc_dir))
    net = proc_dir / "1" / "net"
    if not (net / "dev").is_file():
        net = proc_dir / "net"
    ipv4 = assign_ipv4(
        parse_fib_trie_locals(_read(net / "fib_trie", 524288) or ""),
        parse_routes(_read(net / "route", 65536) or ""),
    )
    ipv6 = parse_if_inet6(_read(net / "if_inet6", 65536) or "")
    result = []
    for name in counters:
        base = sys_dir / "class" / "net" / name
        speed = _int(base / "speed") if base.is_dir() else None
        result.append(
            {
                "name": name,
                "speed_mbps": speed if speed and 0 < speed < 10_000_000 else None,
                "state": _text(base / "operstate", 16) if base.is_dir() else None,
                "mtu": _int(base / "mtu") if base.is_dir() else None,
                "ipv4": ipv4.get(name, [])[:MAX_ADDRESSES],
                "ipv6": ipv6.get(name, [])[:MAX_ADDRESSES],
            }
        )
    return result


# ----- temperatures ------------------------------------------------------------------


def _celsius(raw: int | None) -> float | None:
    if raw is None:
        return None
    value = raw / 1000.0
    return round(value, 1) if -50.0 <= value <= 200.0 else None


def read_temperatures(sys_dir: Path) -> list[dict[str, Any]]:
    sensors: list[dict[str, Any]] = []
    hwmon = sys_dir / "class" / "hwmon"
    for entry in _listdir(hwmon, MAX_HWMON):
        chip_dir = hwmon / entry
        chip = _text(chip_dir / "name", 32) or entry
        inputs = sorted(
            (name for name in _listdir(chip_dir, 256) if re.fullmatch(r"temp\d{1,2}_input", name)),
            key=lambda name: int(name[4:-6]),
        )
        for name in inputs:
            prefix = name[: -len("_input")]
            value = _celsius(_int(chip_dir / name))
            if value is None:
                continue
            sensors.append(
                {
                    "chip": chip,
                    "label": _text(chip_dir / f"{prefix}_label", 48) or prefix,
                    "celsius": value,
                    "high": _celsius(_int(chip_dir / f"{prefix}_max")),
                    "critical": _celsius(_int(chip_dir / f"{prefix}_crit")),
                }
            )
            if len(sensors) >= MAX_SENSORS:
                return sensors
    if sensors:
        return sensors
    thermal = sys_dir / "class" / "thermal"
    for entry in _listdir(thermal, 64):
        if not entry.startswith("thermal_zone"):
            continue
        value = _celsius(_int(thermal / entry / "temp"))
        if value is None:
            continue
        critical = None
        for index in range(8):
            if _text(thermal / entry / f"trip_point_{index}_type", 16) == "critical":
                critical = _celsius(_int(thermal / entry / f"trip_point_{index}_temp"))
                break
        sensors.append(
            {
                "chip": "thermal",
                "label": _text(thermal / entry / "type", 48) or entry,
                "celsius": value,
                "high": None,
                "critical": critical,
            }
        )
        if len(sensors) >= MAX_SENSORS:
            break
    return sensors


# ----- live counters -----------------------------------------------------------------


def parse_stat(text: str) -> dict[str, Any]:
    """Per-CPU jiffies [user, nice, system, idle, iowait, irq, softirq, steal] + procs."""
    total: list[int] | None = None
    cores: list[list[int]] = []
    running = blocked = None
    for line in text.splitlines():
        if line.startswith("cpu"):
            name, _, rest = line.partition(" ")
            try:
                values = [int(value) for value in rest.split()[:8]]
            except ValueError:
                continue
            values += [0] * (8 - len(values))
            if name == "cpu":
                total = values
            elif name[3:].isdigit() and len(cores) < MAX_CPUS:
                cores.append(values)
        elif line.startswith("procs_running "):
            running = int(line.split()[1]) if line.split()[1].isdigit() else None
        elif line.startswith("procs_blocked "):
            blocked = int(line.split()[1]) if line.split()[1].isdigit() else None
    return {"total": total, "cores": cores, "procs_running": running, "procs_blocked": blocked}


def parse_diskstats(text: str) -> dict[str, list[int]]:
    """Whole disks -> [reads, sectors_read, writes, sectors_written, io_ms]."""
    result: dict[str, list[int]] = {}
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 13 or not _WHOLE_DISK.fullmatch(fields[2]):
            continue
        try:
            values = [int(fields[i]) for i in (3, 5, 7, 9, 12)]
        except ValueError:
            continue
        result[fields[2]] = values
        if len(result) >= MAX_BLOCK_DEVICES:
            break
    return result


def memory_breakdown(meminfo: dict[str, int]) -> dict[str, int | None]:
    total = meminfo.get("MemTotal")
    free = meminfo.get("MemFree")
    buffers = meminfo.get("Buffers", 0)
    cache = meminfo.get("Cached", 0) + meminfo.get("SReclaimable", 0)
    available = meminfo.get("MemAvailable")
    used = None
    if total is not None and free is not None:
        used = max(total - free - buffers - cache, 0)
    swap_total = meminfo.get("SwapTotal")
    swap_free = meminfo.get("SwapFree")
    return {
        "total": total,
        "free": free,
        "available": available,
        "used": used,
        "buffers": buffers,
        "cache": cache,
        "shared": meminfo.get("Shmem"),
        "swap_total": swap_total,
        "swap_used": max(swap_total - swap_free, 0)
        if swap_total is not None and swap_free is not None
        else None,
    }


def read_uptime(proc_dir: Path) -> float | None:
    text = _read(proc_dir / "uptime", 256)
    try:
        return float(text.split()[0]) if text else None
    except (IndexError, ValueError):
        return None


def collect_live(proc_dir: Path, sys_dir: Path) -> dict[str, Any]:
    stat = parse_stat(_read(proc_dir / "stat", 262144) or "")
    loadavg_text = _read(proc_dir / "loadavg", 256) or ""
    tasks = loadavg_text.split()[3] if len(loadavg_text.split()) > 3 else ""
    return {
        "cpu": stat,
        "cpu_mhz": current_cpu_mhz(sys_dir, len(stat["cores"])),
        "memory": memory_breakdown(parse_meminfo(_read(proc_dir / "meminfo", 65536) or "")),
        "loadavg": parse_loadavg(loadavg_text),
        "tasks_total": int(tasks.split("/")[1]) if re.fullmatch(r"\d+/\d+", tasks) else None,
        "uptime_seconds": read_uptime(proc_dir),
        "disks": parse_diskstats(_read(proc_dir / "diskstats", 262144) or ""),
        "net": parse_net_interfaces(net_dev_text(proc_dir)),
        "temperatures": read_temperatures(sys_dir),
    }


def collect_facts(proc_dir: Path, sys_dir: Path, host_root: Path | None) -> dict[str, Any]:
    cpu = parse_cpuinfo(_read(proc_dir / "cpuinfo", 1048576) or "")
    cpu.update(read_cpu_frequency(sys_dir))
    cpu["caches"] = read_cpu_caches(sys_dir)
    meminfo = parse_meminfo(_read(proc_dir / "meminfo", 65536) or "")
    hostname = None
    if host_root is not None:
        hostname = _text(host_root / "etc" / "hostname", 253)
    if hostname is None:
        hostname = _text(proc_dir / "sys" / "kernel" / "hostname", 253)
    temperatures = read_temperatures(sys_dir)
    return {
        "hostname": hostname,
        "os": read_os(host_root),
        "kernel": _text(proc_dir / "sys" / "kernel" / "osrelease"),
        "architecture": platform.machine()[:32] or None,
        "machine": read_machine(sys_dir, cpu),
        "cpu": cpu,
        "memory": {
            "total_bytes": meminfo.get("MemTotal"),
            "swap_total_bytes": meminfo.get("SwapTotal"),
        },
        "filesystems": read_filesystems(proc_dir, host_root),
        "block_devices": read_block_devices(sys_dir),
        "interfaces": read_interfaces(proc_dir, sys_dir),
        "temperatures": temperatures,
        "sensors_available": bool(temperatures),
        "loadavg": parse_loadavg(_read(proc_dir / "loadavg", 256) or ""),
        "uptime_seconds": read_uptime(proc_dir),
    }
