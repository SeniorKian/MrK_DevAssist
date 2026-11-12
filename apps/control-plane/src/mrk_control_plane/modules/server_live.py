"""Server overview: machine facts and a live, in-memory history of the host's load.

A background sampler reads the host agent's ``/v1/host/live`` counters every
``IDLE_SECONDS`` (``FAST_SECONDS`` while someone has the overview open) and turns
consecutive samples into rates: CPU (total, per core, iowait, steal), memory
breakdown, swap, disk throughput/IOPS/busy time per device, network per interface,
temperatures and per-container CPU/memory. Two rings are kept in memory only (the
monitoring module already stores long-term minute/hour rows in the database):

- fine:   every sample of the last ``FINE_WINDOW_SECONDS`` (15 min), per device;
- coarse: one-minute averages of the totals for the last 24 hours.

Routes (``agent:read``):

- GET /api/v1/agent/host/facts    what the machine is (proxied, the agent caches it)
- GET /api/v1/agent/host/live     ?window=15m|24h&since=<ts> -> latest + points
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from collections import deque
from collections.abc import Callable
from typing import Any

from fastapi import APIRouter, Query, Request

from ..module_context import ModuleContext
from .host_agent import AgentError, HostAgentService

LOGGER = logging.getLogger(__name__)
MODULE_NAME = "server_live"

FAST_SECONDS = 2.0
IDLE_SECONDS = 5.0
ERROR_BACKOFF_SECONDS = 30.0
VIEWER_TTL_SECONDS = 30.0
FINE_WINDOW_SECONDS = 15 * 60
COARSE_WINDOW_SECONDS = 24 * 3600
MAX_CONTAINERS = 50
SECTOR_BYTES = 512
WINDOWS = ("15m", "24h")

# Coarse (per-minute) fields: averaged, except the ``*_max`` ones.
COARSE_FIELDS = ("cpu", "iowait", "steal", "mem_used", "mem_cache", "swap_used", "load1",
                 "rx", "tx", "dr", "dw", "temp")


def _number(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    return float(value)


def _counts(value: Any, length: int) -> list[int] | None:
    if not isinstance(value, list) or len(value) < length:
        return None
    if not all(isinstance(item, int) and not isinstance(item, bool) for item in value[:length]):
        return None
    return value[:length]


def cpu_split(previous: Any, current: Any) -> dict[str, float] | None:
    """Busy/user/system/iowait/steal percent between two jiffy vectors."""
    old = _counts(previous, 8)
    new = _counts(current, 8)
    if old is None or new is None:
        return None
    delta = [b - a for a, b in zip(old, new, strict=True)]
    if any(value < 0 for value in delta):
        return None
    total = sum(delta)
    if total <= 0:
        return None
    idle = delta[3] + delta[4]

    def share(value: float) -> float:
        return round(min(max(value * 100.0 / total, 0.0), 100.0), 1)

    return {
        "busy": share(total - idle),
        "user": share(delta[0] + delta[1]),
        "system": share(delta[2] + delta[5] + delta[6]),
        "iowait": share(delta[4]),
        "steal": share(delta[7]),
    }


def _rate(previous: int, current: int, seconds: float) -> float | None:
    if current < previous:
        return None  # counter reset (device re-attached, agent host rebooted)
    return (current - previous) / seconds


def compute_point(previous: dict[str, Any], current: dict[str, Any]) -> dict[str, Any] | None:
    """One history point from two raw agent samples, or None if they cannot be compared."""
    seconds = (_number(current.get("mono")) or 0.0) - (_number(previous.get("mono")) or 0.0)
    if not 0.2 <= seconds <= 300:
        return None
    ts = _number(current.get("ts")) or time.time()
    cpu_old = previous.get("cpu") if isinstance(previous.get("cpu"), dict) else {}
    cpu_new = current.get("cpu") if isinstance(current.get("cpu"), dict) else {}
    total = cpu_split(cpu_old.get("total"), cpu_new.get("total"))
    old_cores = cpu_old.get("cores") if isinstance(cpu_old.get("cores"), list) else []
    new_cores = cpu_new.get("cores") if isinstance(cpu_new.get("cores"), list) else []
    cores = []
    if len(old_cores) == len(new_cores):
        for old, new in zip(old_cores, new_cores, strict=True):
            split = cpu_split(old, new)
            cores.append(split["busy"] if split else None)
    memory = current.get("memory") if isinstance(current.get("memory"), dict) else {}

    disks: dict[str, list[float]] = {}
    old_disks = previous.get("disks") if isinstance(previous.get("disks"), dict) else {}
    new_disks = current.get("disks") if isinstance(current.get("disks"), dict) else {}
    for name, values in new_disks.items():
        new_values = _counts(values, 5)
        old_values = _counts(old_disks.get(name), 5)
        if new_values is None or old_values is None:
            continue
        rates = [_rate(a, b, seconds) for a, b in zip(old_values, new_values, strict=True)]
        if any(rate is None for rate in rates):
            continue
        reads, sectors_read, writes, sectors_written, io_ms = (float(r or 0) for r in rates)
        disks[str(name)[:32]] = [
            round(sectors_read * SECTOR_BYTES),
            round(sectors_written * SECTOR_BYTES),
            round(reads, 1),
            round(writes, 1),
            round(min(io_ms / 10.0, 100.0), 1),  # ms busy per second -> percent
        ]

    net: dict[str, list[float]] = {}
    old_net = previous.get("net") if isinstance(previous.get("net"), dict) else {}
    new_net = current.get("net") if isinstance(current.get("net"), dict) else {}
    for name, values in new_net.items():
        new_values = _counts(values, 6)
        old_values = _counts(old_net.get(name), 6)
        if new_values is None or old_values is None:
            continue
        rx = _rate(old_values[0], new_values[0], seconds)
        tx = _rate(old_values[3], new_values[3], seconds)
        if rx is None or tx is None:
            continue
        net[str(name)[:32]] = [round(rx), round(tx)]

    temps = current.get("temperatures") if isinstance(current.get("temperatures"), list) else []
    readings = [
        value
        for item in temps
        if isinstance(item, dict) and (value := _number(item.get("celsius"))) is not None
    ]
    load = current.get("loadavg") if isinstance(current.get("loadavg"), list) else None
    return {
        "t": round(ts, 3),
        "cpu": total["busy"] if total else None,
        "user": total["user"] if total else None,
        "system": total["system"] if total else None,
        "iowait": total["iowait"] if total else None,
        "steal": total["steal"] if total else None,
        "cores": cores,
        "mem_used": memory.get("used"),
        "mem_cache": memory.get("cache"),
        "mem_buffers": memory.get("buffers"),
        "mem_available": memory.get("available"),
        "swap_used": memory.get("swap_used"),
        "load1": _number(load[0]) if load else None,
        "rx": sum(item[0] for item in net.values()) if net else None,
        "tx": sum(item[1] for item in net.values()) if net else None,
        "dr": sum(item[0] for item in disks.values()) if disks else None,
        "dw": sum(item[1] for item in disks.values()) if disks else None,
        "temp": max(readings) if readings else None,
        "net": net,
        "disk": disks,
    }


def container_rates(
    previous: dict[str, Any], current: dict[str, Any], cpu_count: int
) -> list[dict[str, Any]] | None:
    items = current.get("containers")
    if not isinstance(items, list):
        return None
    seconds = (_number(current.get("mono")) or 0.0) - (_number(previous.get("mono")) or 0.0)
    old_usage: dict[str, int] = {}
    for item in previous.get("containers") or []:
        if isinstance(item, dict) and isinstance(item.get("cpu_usage_usec"), int):
            old_usage[str(item.get("id"))] = item["cpu_usage_usec"]
    result = []
    for item in items:
        if not isinstance(item, dict):
            continue
        usage = item.get("cpu_usage_usec")
        before = old_usage.get(str(item.get("id")))
        cpu = None
        if isinstance(usage, int) and before is not None and seconds > 0 and usage >= before:
            one_core = (usage - before) / (seconds * 1_000_000) * 100.0
            cpu = round(min(one_core / max(cpu_count, 1), 100.0), 2)
        mem = item.get("mem_bytes")
        limit = item.get("mem_limit_bytes")
        result.append(
            {
                "id": str(item.get("id", ""))[:64],
                "name": str(item.get("name", ""))[:128],
                "protected": bool(item.get("protected")),
                "cpu": cpu,
                "mem_bytes": mem if isinstance(mem, int) else None,
                "mem_limit_bytes": limit if isinstance(limit, int) else None,
            }
        )
    result.sort(key=lambda entry: (-(entry["cpu"] or 0.0), -(entry["mem_bytes"] or 0)))
    return result[:MAX_CONTAINERS]


class MinuteRoller:
    """Averages fine points into one-minute buckets."""

    def __init__(self) -> None:
        self.minute: int | None = None
        self.sums: dict[str, float] = {}
        self.counts: dict[str, int] = {}
        self.cpu_max: float | None = None

    def add(self, point: dict[str, Any]) -> dict[str, Any] | None:
        minute = int(point["t"] // 60)
        finished = None
        if self.minute is not None and minute != self.minute:
            finished = self.flush()
        self.minute = minute
        for key in COARSE_FIELDS:
            value = _number(point.get(key))
            if value is not None:
                self.sums[key] = self.sums.get(key, 0.0) + value
                self.counts[key] = self.counts.get(key, 0) + 1
        cpu = _number(point.get("cpu"))
        if cpu is not None:
            self.cpu_max = cpu if self.cpu_max is None else max(self.cpu_max, cpu)
        return finished

    def flush(self) -> dict[str, Any] | None:
        if self.minute is None or not self.counts:
            return None
        row: dict[str, Any] = {"t": self.minute * 60}
        for key in COARSE_FIELDS:
            count = self.counts.get(key)
            row[key] = round(self.sums[key] / count, 2) if count else None
        row["cpu_max"] = self.cpu_max
        self.sums, self.counts, self.cpu_max = {}, {}, None
        return row


class ServerLiveService:
    def __init__(
        self,
        ctx: ModuleContext,
        agent: HostAgentService | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.ctx = ctx
        self.agent = agent or HostAgentService(ctx)
        self.clock = clock
        fine_points = int(FINE_WINDOW_SECONDS / FAST_SECONDS) + 60
        self.fine: deque[dict[str, Any]] = deque(maxlen=fine_points)
        self.coarse: deque[dict[str, Any]] = deque(maxlen=COARSE_WINDOW_SECONDS // 60)
        self.roller = MinuteRoller()
        self.previous: dict[str, Any] | None = None
        self.latest: dict[str, Any] | None = None
        self.last_error: str | None = None
        self.available: bool | None = None
        self.last_viewed: float | None = None
        self._task: asyncio.Task[None] | None = None
        self._wake: asyncio.Event | None = None
        self._sample_lock = asyncio.Lock()

    # ----- sampling -------------------------------------------------------------
    def ingest(self, raw: Any) -> None:
        if not isinstance(raw, dict):
            return
        if raw.get("available") is False:
            self.available = False
            return
        self.available = True
        previous, self.previous = self.previous, raw
        if previous is None:
            return
        point = compute_point(previous, raw)
        if point is None:
            return
        cutoff = point["t"] - FINE_WINDOW_SECONDS
        if self.fine and self.fine[-1]["t"] >= point["t"]:
            return
        self.fine.append(point)
        while self.fine and self.fine[0]["t"] < cutoff:
            self.fine.popleft()
        finished = self.roller.add(point)
        if finished is not None:
            self.coarse.append(finished)
        cpu = raw.get("cpu") if isinstance(raw.get("cpu"), dict) else {}
        cores = cpu.get("cores") if isinstance(cpu.get("cores"), list) else []
        memory = raw.get("memory") if isinstance(raw.get("memory"), dict) else {}
        temps = raw.get("temperatures") if isinstance(raw.get("temperatures"), list) else []
        self.latest = {
            **point,
            "interval": FAST_SECONDS if self.viewing() else IDLE_SECONDS,
            "memory": {key: memory.get(key) for key in (
                "total", "free", "available", "used", "buffers", "cache", "shared",
                "swap_total", "swap_used")},
            "loadavg": raw.get("loadavg") if isinstance(raw.get("loadavg"), list) else None,
            "uptime_seconds": _number(raw.get("uptime_seconds")),
            "tasks_total": raw.get("tasks_total"),
            "procs_running": cpu.get("procs_running"),
            "procs_blocked": cpu.get("procs_blocked"),
            "cpu_mhz": _number(raw.get("cpu_mhz")),
            "temperatures": [item for item in temps if isinstance(item, dict)][:48],
            "containers": container_rates(previous, raw, len(cores) or 1),
        }

    async def sample(self) -> None:
        async with self._sample_lock:
            await self._sample()

    async def _sample(self) -> None:
        _source, url, _key = self.agent.resolve()
        if url is None:
            self.last_error = "agent_not_configured"
            return
        try:
            raw = await self.agent.call("/v1/host/live")
        except AgentError as exc:
            # An agent older than this panel has no /v1/host/live.
            self.last_error = "agent_outdated" if exc.code == "agent_not_found" else exc.code
            return
        self.last_error = None
        self.ingest(raw)

    def viewing(self) -> bool:
        return self.last_viewed is not None and self.clock() - self.last_viewed < VIEWER_TTL_SECONDS

    def touch(self) -> None:
        idle = not self.viewing()
        self.last_viewed = self.clock()
        if idle and self._wake is not None:
            self._wake.set()

    def next_delay(self) -> float:
        if self.last_error is None:
            return FAST_SECONDS if self.viewing() else IDLE_SECONDS
        # Not paired, or the agent is down/outdated: check rarely unless someone is looking.
        return IDLE_SECONDS if self.viewing() else ERROR_BACKOFF_SECONDS

    # ----- queries ----------------------------------------------------------------
    def snapshot(self, window: str, since: float | None) -> dict[str, Any]:
        if window == "24h":
            points = list(self.coarse)
            partial = self.roller.minute
            if partial is not None and self.roller.counts:
                current = MinuteRoller()
                current.minute, current.cpu_max = partial, self.roller.cpu_max
                current.sums, current.counts = dict(self.roller.sums), dict(self.roller.counts)
                row = current.flush()
                if row is not None:
                    points.append(row)
        else:
            points = [point for point in self.fine if since is None or point["t"] > since]
        return {
            "window": window,
            "available": self.available,
            "error_code": self.last_error,
            "interval": FAST_SECONDS if self.viewing() else IDLE_SECONDS,
            "latest": self.latest,
            "points": points,
        }

    # ----- background -------------------------------------------------------------
    async def _loop(self) -> None:
        assert self._wake is not None
        while True:
            started = time.monotonic()
            try:
                await self.sample()
            except asyncio.CancelledError:
                raise
            except Exception:
                LOGGER.exception("server live sample failed")
            delay = max(0.5, self.next_delay() - (time.monotonic() - started))
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(self._wake.wait(), timeout=delay)
            self._wake.clear()

    async def start(self) -> None:
        self._wake = asyncio.Event()
        self._task = asyncio.create_task(self._loop(), name="mrk-server-live")

    async def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
            self._task = None


ACTIVE_SERVICE: ServerLiveService | None = None


def build_router(ctx: ModuleContext, service: ServerLiveService) -> APIRouter:
    router = APIRouter(prefix="/api/v1/agent/host", tags=["host-agent"])

    @router.get("/facts", response_model=None)
    async def host_facts(request: Request) -> Any:
        ctx.require_principal(request, "agent:read")
        try:
            facts = await service.agent.call("/v1/host/facts")
        except AgentError as exc:
            if exc.code == "agent_not_found":
                return ctx.error_payload(
                    "agent_outdated", "The server helper is older than the panel; update it", 409
                )
            return ctx.error_payload(exc.code, exc.message, exc.status_code)
        if not isinstance(facts, dict):
            return ctx.error_payload("agent_unreachable", "unexpected agent payload", 502)
        return facts

    @router.get("/live", response_model=None)
    async def host_live(
        request: Request,
        window: str = Query(default="15m"),
        since: float | None = Query(default=None, ge=0),
    ) -> Any:
        ctx.require_principal(request, "agent:read")
        if window not in WINDOWS:
            return ctx.error_payload("invalid_window", "window must be 15m or 24h", 422)
        service.touch()
        if service.latest is None and service.last_error is None:
            # First visit after start: take two quick samples so the page has numbers.
            await service.sample()
            if service.latest is None and service.last_error is None:
                await asyncio.sleep(0.5)
                await service.sample()
        return service.snapshot(window, since)

    return router


def register(ctx: ModuleContext) -> None:
    global ACTIVE_SERVICE
    service = ServerLiveService(ctx)
    ACTIVE_SERVICE = service
    ctx.routers.append(build_router(ctx, service))
    ctx.start_hooks.append(service.start)
    ctx.stop_hooks.append(service.stop)
