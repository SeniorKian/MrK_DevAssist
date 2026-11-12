"""Server overview: agent machine facts / live counters and the panel's live history."""

from __future__ import annotations

import asyncio
import os
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient
from mrk_control_plane.agent import host_facts
from mrk_control_plane.agent.app import AgentConfig, create_agent_app
from mrk_control_plane.agent.docker_client import container_health
from mrk_control_plane.config import Settings
from mrk_control_plane.main import create_app
from mrk_control_plane.modules import host_agent, server_live
from mrk_control_plane.modules.host_agent import AgentError

from .helpers import login_owner
from .test_host_agent import KEY, KEY_TEXT, fake_docker_handler, fake_proc, signed_get

CPUINFO = "".join(
    f"processor\t: {index}\nvendor_id\t: GenuineIntel\n"
    "model name\t: Intel(R) Xeon(R) Gold 6248R CPU @ 3.00GHz\n"
    f"physical id\t: 0\ncore id\t\t: {index // 2}\ncpu cores\t: 2\n"
    f"cpu MHz\t\t: {2990 + index}.000\ncache size\t: 36608 KB\n"
    "flags\t\t: fpu vme sse2 hypervisor avx2\n\n"
    for index in range(4)
)
STAT = (
    "cpu  100 0 50 800 10 0 0 40 0 0\n"
    "cpu0 25 0 12 200 3 0 0 10 0 0\n"
    "cpu1 25 0 13 200 2 0 0 10 0 0\n"
    "cpu2 25 0 12 200 3 0 0 10 0 0\n"
    "cpu3 25 0 13 200 2 0 0 10 0 0\n"
    "intr 1\nprocs_running 3\nprocs_blocked 1\n"
)
MEMINFO = (
    "MemTotal: 8000000 kB\nMemFree: 1000000 kB\nMemAvailable: 5000000 kB\n"
    "Buffers: 200000 kB\nCached: 2500000 kB\nSReclaimable: 300000 kB\nShmem: 1000 kB\n"
    "SwapTotal: 2000000 kB\nSwapFree: 1500000 kB\n"
)
NET_DEV = (
    "Inter-|   Receive                                                |  Transmit\n"
    " face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs"
    " drop fifo colls carrier compressed\n"
    "    lo: 500 5 0 0 0 0 0 0 500 5 0 0 0 0 0 0\n"
    "  eth0: 1000000 900 0 0 0 0 0 0 2000000 800 1 0 0 0 0 0\n"
    "docker0: 10 1 0 0 0 0 0 0 10 1 0 0 0 0 0 0\n"
    "veth12ab: 10 1 0 0 0 0 0 0 10 1 0 0 0 0 0 0\n"
)
DISKSTATS = (
    "   8       0 sda 100 0 2000 0 50 0 4000 0 0 300 0\n"
    "   8       1 sda1 90 0 1800 0 40 0 3000 0 0 250 0\n"
    " 259       0 nvme0n1 10 0 80 0 5 0 40 0 0 20 0\n"
    "   7       0 loop0 1 0 2 0 0 0 0 0 0 0 0\n"
)
FIB_TRIE = """Main:
  +-- 0.0.0.0/0 3 0 5
     |-- 0.0.0.0
        /0 universe UNICAST
     +-- 10.0.0.0/24 2 0 2
        |-- 10.0.0.0
           /24 link UNICAST
        |-- 10.0.0.5
           /32 host LOCAL
     |-- 172.17.0.1
        /32 host LOCAL
  +-- 127.0.0.0/8 2 0 2
     |-- 127.0.0.1
        /32 host LOCAL
"""
ROUTE = (
    "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"
    "eth0\t00000000\t0100000A\t0003\t0\t0\t0\t00000000\t0\t0\t0\n"
    "eth0\t0000000A\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n"
    "docker0\t000011AC\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0\n"
)
IF_INET6 = (
    "20010db8000000000000000000000005 02 40 00 80     eth0\n"
    "fe800000000000000000000000000001 02 40 20 80     eth0\n"
    "00000000000000000000000000000001 01 80 10 80       lo\n"
)


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def fake_host(tmp_path: Path, *, sensors: bool = True) -> tuple[Path, Path, Path]:
    proc, root = fake_proc(tmp_path)
    write(proc / "cpuinfo", CPUINFO)
    write(proc / "stat", STAT)
    write(proc / "meminfo", MEMINFO)
    write(proc / "diskstats", DISKSTATS)
    write(proc / "1" / "net" / "dev", NET_DEV)
    write(proc / "1" / "net" / "fib_trie", FIB_TRIE)
    write(proc / "1" / "net" / "route", ROUTE)
    write(proc / "1" / "net" / "if_inet6", IF_INET6)
    write(proc / "1" / "mounts", (
        "/dev/sda1 / ext4 rw,relatime 0 0\n"
        "proc /proc proc rw 0 0\n"
        "/dev/sda1 /var/lib/docker ext4 rw 0 0\n"
        "/dev/loop3 /snap/core/1 squashfs ro 0 0\n"
        "/dev/nvme0n1p1 /mnt/fast\\040disk xfs rw 0 0\n"
    ))
    write(root / "usr" / "lib" / "os-release",
          'NAME="Ubuntu"\nVERSION_ID="24.04"\nPRETTY_NAME="Ubuntu 24.04.1 LTS"\nID=ubuntu\n')
    try:
        os.symlink("../usr/lib/os-release", root / "etc" / "os-release")
    except OSError:  # no symlink privilege (Windows): a plain copy tests the same parsing
        write(root / "etc" / "os-release", (root / "usr" / "lib" / "os-release").read_text())
    sys_dir = tmp_path / "sys"
    dmi = sys_dir / "class" / "dmi" / "id"
    write(dmi / "sys_vendor", "QEMU\n")
    write(dmi / "product_name", "Standard PC (Q35 + ICH9, 2009)\n")
    cpu0 = sys_dir / "devices" / "system" / "cpu" / "cpu0"
    write(cpu0 / "cache" / "index0" / "level", "1\n")
    write(cpu0 / "cache" / "index0" / "type", "Data\n")
    write(cpu0 / "cache" / "index0" / "size", "32K\n")
    write(cpu0 / "cache" / "index3" / "level", "3\n")
    write(cpu0 / "cache" / "index3" / "type", "Unified\n")
    write(cpu0 / "cache" / "index3" / "size", "36608K\n")
    for name, size, rotational, model in (
        ("sda", "419430400", "1", "QEMU HARDDISK"),
        ("nvme0n1", "1953525168", "0", "Samsung SSD 980 PRO"),
        ("loop0", "100", "0", None),
    ):
        write(sys_dir / "block" / name / "size", size + "\n")
        write(sys_dir / "block" / name / "queue" / "rotational", rotational + "\n")
        if model:
            write(sys_dir / "block" / name / "device" / "model", model + "   \n")
    write(sys_dir / "class" / "net" / "eth0" / "speed", "10000\n")
    write(sys_dir / "class" / "net" / "eth0" / "operstate", "up\n")
    write(sys_dir / "class" / "net" / "eth0" / "mtu", "1500\n")
    write(sys_dir / "class" / "net" / "eth0" / "address", "52:54:00:12:34:56\n")
    if sensors:
        hwmon = sys_dir / "class" / "hwmon" / "hwmon0"
        write(hwmon / "name", "coretemp\n")
        write(hwmon / "temp1_input", "45000\n")
        write(hwmon / "temp1_label", "Package id 0\n")
        write(hwmon / "temp1_max", "80000\n")
        write(hwmon / "temp1_crit", "100000\n")
        write(hwmon / "temp2_input", "999999\n")  # nonsense reading: dropped
    else:
        (sys_dir / "class" / "thermal").mkdir(parents=True)
    return proc, root, sys_dir


# ----- agent parsing ----------------------------------------------------------------


def test_machine_facts_from_fake_host(tmp_path: Path) -> None:
    proc, root, sys_dir = fake_host(tmp_path)
    facts = host_facts.collect_facts(proc, sys_dir, root)
    assert facts["hostname"] == "prod-node-1"
    assert facts["os"] == {"pretty_name": "Ubuntu 24.04.1 LTS", "id": "ubuntu",
                           "version_id": "24.04"}
    assert facts["kernel"] == "6.8.0-45-generic"
    cpu = facts["cpu"]
    assert cpu["model"] == "Intel(R) Xeon(R) Gold 6248R CPU @ 3.00GHz"
    assert (cpu["sockets"], cpu["cores"], cpu["threads"]) == (1, 2, 4)
    assert cpu["mhz"] == 2991.5 and cpu["hypervisor_flag"] is True
    assert {"level": "L1d", "size_bytes": 32768} in cpu["caches"]
    assert {"level": "L3", "size_bytes": 36608 * 1024} in cpu["caches"]
    assert facts["machine"]["virtualization"] == "vm"
    assert facts["machine"]["technology"] == "kvm"
    assert facts["memory"] == {"total_bytes": 8000000 * 1024, "swap_total_bytes": 2000000 * 1024}
    devices = {item["name"]: item for item in facts["block_devices"]}
    assert set(devices) == {"sda", "nvme0n1"}  # loop devices are not disks
    assert devices["sda"]["kind"] == "virtual" and devices["sda"]["rotational"] is True
    assert devices["sda"]["size_bytes"] == 419430400 * 512
    assert devices["nvme0n1"]["kind"] == "nvme" and devices["nvme0n1"]["model"] == (
        "Samsung SSD 980 PRO"
    )
    mounts = [(item["device"], item["mountpoint"]) for item in facts["filesystems"]]
    assert mounts == [("/dev/sda1", "/"), ("/dev/nvme0n1p1", "/mnt/fast disk")]
    root_fs = facts["filesystems"][0]
    assert root_fs["total_bytes"] and root_fs["fstype"] == "ext4"
    # Not visible through the bind mount: no numbers rather than the parent's numbers.
    assert facts["filesystems"][1]["total_bytes"] is None
    interfaces = facts["interfaces"]
    assert [item["name"] for item in interfaces] == ["eth0"]  # lo/docker/veth filtered
    eth0 = interfaces[0]
    assert eth0["ipv4"] == ["10.0.0.5"] and eth0["ipv6"] == ["2001:db8::5"]
    assert eth0["speed_mbps"] == 10000 and eth0["state"] == "up" and eth0["mtu"] == 1500
    assert "52:54" not in repr(facts)  # MAC addresses are never read
    assert facts["temperatures"] == [{
        "chip": "coretemp", "label": "Package id 0", "celsius": 45.0, "high": 80.0,
        "critical": 100.0,
    }]
    assert facts["sensors_available"] is True
    assert facts["loadavg"] == [0.52, 0.40, 0.31]


def test_no_sensors_and_no_dmi_are_reported_as_missing(tmp_path: Path) -> None:
    proc, root, sys_dir = fake_host(tmp_path, sensors=False)
    for name in ("sys_vendor", "product_name"):
        (sys_dir / "class" / "dmi" / "id" / name).unlink()
    write(proc / "cpuinfo", CPUINFO.replace(" hypervisor", ""))
    facts = host_facts.collect_facts(proc, sys_dir, root)
    assert facts["temperatures"] == [] and facts["sensors_available"] is False
    assert facts["machine"]["virtualization"] == "unknown"
    assert facts["machine"]["technology"] is None


def test_thermal_zone_fallback_and_bare_metal(tmp_path: Path) -> None:
    proc, root, sys_dir = fake_host(tmp_path, sensors=False)
    write(sys_dir / "class" / "dmi" / "id" / "sys_vendor", "Dell Inc.\n")
    write(sys_dir / "class" / "dmi" / "id" / "product_name", "PowerEdge R640\n")
    write(proc / "cpuinfo", CPUINFO.replace(" hypervisor", ""))
    zone = sys_dir / "class" / "thermal" / "thermal_zone0"
    write(zone / "type", "x86_pkg_temp\n")
    write(zone / "temp", "51500\n")
    write(zone / "trip_point_0_type", "critical\n")
    write(zone / "trip_point_0_temp", "105000\n")
    facts = host_facts.collect_facts(proc, sys_dir, root)
    assert facts["machine"]["virtualization"] == "bare_metal"
    assert facts["temperatures"][0]["label"] == "x86_pkg_temp"
    assert facts["temperatures"][0]["celsius"] == 51.5
    assert facts["temperatures"][0]["critical"] == 105.0


def test_parsers_reject_garbage_and_limit_sizes() -> None:
    assert host_facts.parse_cpuinfo("") ["threads"] is None
    assert host_facts.parse_net_interfaces("garbage\n x: 1 2\n") == {}
    many = "".join(f" eth{i}: 1 1 0 0 0 0 0 0 1 1 0 0 0 0 0 0\n" for i in range(100))
    assert len(host_facts.parse_net_interfaces(many)) == host_facts.MAX_INTERFACES
    assert host_facts.parse_diskstats("8 0 sda x y z\n") == {}
    assert host_facts.parse_os_release("lower=1\nPRETTY_NAME='A B'\n") == {"PRETTY_NAME": "A B"}
    assert host_facts.size_text_bytes("1024K") == 1024 * 1024
    assert host_facts.size_text_bytes("bogus") is None
    assert host_facts.block_kind("sdb", 0, "WDC SSD") == "ssd"
    assert host_facts.block_kind("sdb", 1, "WDC WD40") == "hdd"


def test_live_counters(tmp_path: Path) -> None:
    proc, _root, sys_dir = fake_host(tmp_path)
    live = host_facts.collect_live(proc, sys_dir)
    assert live["cpu"]["total"] == [100, 0, 50, 800, 10, 0, 0, 40]
    assert len(live["cpu"]["cores"]) == 4 and live["cpu"]["procs_running"] == 3
    assert live["memory"]["used"] == (8000000 - 1000000 - 200000 - 2800000) * 1024
    assert live["memory"]["cache"] == 2800000 * 1024
    assert live["memory"]["swap_used"] == 500000 * 1024
    assert live["disks"] == {"sda": [100, 2000, 50, 4000, 300], "nvme0n1": [10, 80, 5, 40, 20]}
    assert live["net"] == {"eth0": [1000000, 900, 0, 2000000, 800, 1]}
    assert live["tasks_total"] == 523 and live["uptime_seconds"] == 12345.67
    assert live["temperatures"][0]["celsius"] == 45.0


def test_container_health_from_status() -> None:
    assert container_health({"Status": "Up 3 hours (healthy)"}) == "healthy"
    assert container_health({"Status": "Up 1 minute (unhealthy)"}) == "unhealthy"
    assert container_health({"Status": "Up 2 seconds (health: starting)"}) == "starting"
    assert container_health({"Status": "Up 3 days"}) is None


def test_agent_facts_and_live_routes_are_signed(tmp_path: Path) -> None:
    proc, root, sys_dir = fake_host(tmp_path)
    config = AgentConfig(key=KEY, proc_dir=proc, root_paths=[root], host_root=root,
                         sys_dir=sys_dir, cgroup_dir=tmp_path / "no-cgroup")
    app = create_agent_app(config, docker_transport=httpx.MockTransport(fake_docker_handler([])))
    with TestClient(app) as client:
        assert client.get("/v1/host/facts").status_code == 401
        assert client.get("/v1/host/live").status_code == 401
        facts = signed_get(client, "/v1/host/facts").json()
        assert facts["available"] is True and facts["cpu"]["threads"] == 4
        assert facts["docker"]["version"] == "27.3.1"
        assert facts["docker"]["containers_running"] == 2
        live = signed_get(client, "/v1/host/live").json()
        assert live["available"] is True and live["mono"] > 0
        assert live["containers"] is None  # no cgroup v2 mounted
        assert client.post("/v1/host/live").status_code == 405


# ----- panel: rates and history -----------------------------------------------------


def raw_sample(mono: float, step: int) -> dict[str, Any]:
    """Two seconds of a 2-core host per step: 50% busy, 1 MB/s read, 100 kB/s rx."""
    busy, idle = 100 * step, 100 * step
    return {
        "available": True,
        "ts": 1_700_000_000.0 + mono,
        "mono": mono,
        "cpu": {
            "total": [busy, 0, 0, idle, 0, 0, 0, 0],
            "cores": [[busy, 0, 0, 0, 0, 0, 0, 0], [0, 0, 0, idle, 0, 0, 0, 0]],
        },
        "memory": {"total": 1000, "used": 400, "cache": 300, "buffers": 50, "available": 550,
                   "swap_total": 0, "swap_used": 0},
        "loadavg": [0.5, 0.4, 0.3],
        "disks": {"sda": [10 * step, 4096 * step, 5 * step, 0, 500 * step]},
        "net": {"eth0": [200_000 * step, 0, 0, 50_000 * step, 0, 0]},
        "temperatures": [{"label": "cpu", "celsius": 40.0 + step}],
        "containers": [
            {"id": "a" * 64, "name": "web", "protected": False,
             "cpu_usage_usec": 1_000_000 * step, "mem_bytes": 100, "mem_limit_bytes": None},
        ],
    }


def test_compute_point_rates() -> None:
    point = server_live.compute_point(raw_sample(2.0, 1), raw_sample(4.0, 2))
    assert point is not None
    assert point["cpu"] == 50.0 and point["cores"] == [100.0, 0.0]
    assert point["disk"]["sda"] == [1024 * 1024, 0, 5.0, 2.5, 25.0]
    assert point["net"]["eth0"] == [100_000, 25_000]
    assert (point["rx"], point["tx"], point["dr"]) == (100_000, 25_000, 1024 * 1024)
    assert point["temp"] == 42.0 and point["load1"] == 0.5
    # Same instant, or a counter that went backwards (reboot): no fake numbers.
    assert server_live.compute_point(raw_sample(2.0, 1), raw_sample(2.0, 2)) is None
    reset = server_live.compute_point(raw_sample(2.0, 5), raw_sample(4.0, 1))
    assert reset is not None and reset["cpu"] is None and reset["disk"] == {}
    rates = server_live.container_rates(raw_sample(2.0, 1), raw_sample(4.0, 2), 2)
    assert rates == [{"id": "a" * 64, "name": "web", "protected": False, "cpu": 25.0,
                      "mem_bytes": 100, "mem_limit_bytes": None}]


class FakeAgent:
    def __init__(self, payloads: list[Any]) -> None:
        self.payloads = payloads

    def resolve(self):
        return ("panel", "http://agent:7070", b"k")

    async def call(self, path: str) -> Any:
        assert path == "/v1/host/live"
        if not self.payloads:
            raise AgentError("agent_not_found", 404, "missing")
        return self.payloads.pop(0)


def test_service_history_windows_and_outdated_agent() -> None:
    clock = [1000.0]
    samples = [raw_sample(2.0 * index, index) for index in range(1, 92)]  # ~3 minutes
    service = server_live.ServerLiveService(
        SimpleNamespace(), agent=FakeAgent(samples), clock=lambda: clock[0]
    )

    async def scenario() -> None:
        for _ in range(91):
            await service.sample()
        await service.sample()  # payloads exhausted -> the agent has no such route

    asyncio.run(scenario())
    assert service.last_error == "agent_outdated"
    fine = service.snapshot("15m", None)
    assert len(fine["points"]) == 90 and fine["latest"]["containers"][0]["cpu"] == 25.0
    newest = fine["points"][-1]["t"]
    assert service.snapshot("15m", newest - 3)["points"] == fine["points"][-2:]
    coarse = service.snapshot("24h", None)["points"]
    assert 3 <= len(coarse) <= 5 and all(row["cpu"] == 50.0 for row in coarse)
    assert all(row["t"] % 60 == 0 for row in coarse)
    assert service.next_delay() == server_live.ERROR_BACKOFF_SECONDS
    service.touch()
    assert service.viewing() and service.next_delay() == server_live.IDLE_SECONDS


def test_fine_history_drops_points_older_than_the_window() -> None:
    samples = [raw_sample(60.0 * index, index) for index in range(1, 25)]  # 23 minutes
    service = server_live.ServerLiveService(SimpleNamespace(), agent=FakeAgent(samples))

    async def scenario() -> None:
        for _ in range(24):
            await service.sample()

    asyncio.run(scenario())
    points = service.snapshot("15m", None)["points"]
    assert points[-1]["t"] - points[0]["t"] <= server_live.FINE_WINDOW_SECONDS
    assert len(points) == 16


# ----- panel API --------------------------------------------------------------------


@pytest.fixture
def paired_agent(tmp_path: Path, monkeypatch):
    proc, root, sys_dir = fake_host(tmp_path / "agent")
    config = AgentConfig(key=KEY, proc_dir=proc, root_paths=[root], host_root=root,
                         sys_dir=sys_dir, cgroup_dir=tmp_path / "no-cgroup")
    agent = create_agent_app(config, docker_transport=httpx.MockTransport(fake_docker_handler([])))

    class Transport(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            return await httpx.ASGITransport(app=agent).handle_async_request(request)

    monkeypatch.setattr(host_agent, "TRANSPORT_FACTORY", Transport)
    monkeypatch.delenv("MRK_AGENT_URL", raising=False)
    monkeypatch.delenv("MRK_AGENT_KEY_FILE", raising=False)


def test_panel_facts_and_live_endpoints(tmp_path: Path, paired_agent) -> None:
    app = create_app(Settings.for_test(tmp_path / "cp"))
    with TestClient(app) as client:
        assert client.get("/api/v1/agent/host/facts").status_code == 401
        assert client.get("/api/v1/agent/host/live").status_code == 401
        headers = {"X-CSRF-Token": str(login_owner(client)["csrf_token"])}
        not_paired = client.get("/api/v1/agent/host/facts").json()
        assert not_paired["error"]["code"] == "agent_not_configured"
        paired = client.put("/api/v1/agent/config", headers=headers,
                            json={"url": "http://mrk-agent:7070", "key": KEY_TEXT})
        assert paired.status_code == 200
        facts = client.get("/api/v1/agent/host/facts").json()
        assert facts["os"]["pretty_name"] == "Ubuntu 24.04.1 LTS"
        assert facts["machine"]["technology"] == "kvm"
        assert facts["docker"]["version"] == "27.3.1"
        service = server_live.ACTIVE_SERVICE
        assert service is not None
        service.previous = None
        service.latest = None
        service.last_error = None
        live = client.get("/api/v1/agent/host/live").json()
        assert live["error_code"] is None and live["available"] is True
        # The fake counters do not move: rates are zero, the shape is complete.
        assert live["latest"]["memory"]["total"] == 8000000 * 1024
        assert live["latest"]["loadavg"] == [0.52, 0.40, 0.31]
        assert live["latest"]["temperatures"][0]["celsius"] == 45.0
        assert live["interval"] == server_live.FAST_SECONDS
        bad = client.get("/api/v1/agent/host/live?window=1y")
        assert bad.status_code == 422
        day = client.get("/api/v1/agent/host/live?window=24h").json()
        assert day["window"] == "24h" and isinstance(day["points"], list)
