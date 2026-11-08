"""Resource monitoring module (Gate 17, docs/29 §3 "مانیتورینگ").

A background collector polls the host agent's ``/v1/metrics`` every
``interval_seconds``, turns counters into rates, keeps the current minute in
memory and writes **one batch insert per minute**. Complete hours are rolled up
into ``metric_hours`` and old rows are pruned per the retention settings.
Sustained cpu/mem/disk thresholds publish ``metrics.*_high`` / ``*_recovered``
events. Settings live in ``data_dir/control-plane/monitoring.json``.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import secrets
import time
from collections.abc import Callable
from typing import Any

from fastapi import APIRouter, Query, Request
from fastapi.responses import JSONResponse

from ..models import MetricHour, MetricMinute
from ..module_context import Event, ModuleContext
from . import monitoring_store as store
from .host_agent import AgentError, HostAgentService
from .monitoring_math import (
    RANGES,
    AlertTracker,
    MinuteAggregator,
    RateTracker,
    Sample,
    SettingsError,
    downsample,
    normalize_metrics,
    percent,
    pick_resolution,
    validate_settings,
)

LOGGER = logging.getLogger(__name__)
MODULE_NAME = "monitoring"
SETTINGS_FILE = "monitoring.json"
CPU_COUNT_REFRESH_SECONDS = 600.0
LATEST_LOOKBACK_SECONDS = 600
MAX_CONTAINER_SERIES = 100
HOST_POINT_FIELDS = (
    "cpu_percent",
    "mem_percent",
    "disk_percent",
    "load1",
    "net_rx_bps",
    "net_tx_bps",
)


def _byte_count(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int | float) or value < 0:
        return None
    return int(value)


def host_snapshot(payload: Any, ts: float) -> dict[str, Any] | None:
    """Absolute host totals from one agent /v1/metrics payload (for ``latest``).

    The minute rows only keep percentages for disks, so the byte totals of the
    newest poll are kept in memory. ``disk_*`` describe the fullest disk.
    """
    host = payload.get("host") if isinstance(payload, dict) else None
    if not isinstance(host, dict):
        return None
    mem_total = _byte_count(host.get("mem_total_bytes"))
    mem_used = _byte_count(host.get("mem_used_bytes"))
    fullest: dict[str, Any] | None = None
    fullest_percent = -1.0
    disks = host.get("disks")
    for disk in disks if isinstance(disks, list) else []:
        if not isinstance(disk, dict):
            continue
        total = _byte_count(disk.get("total_bytes"))
        used = _byte_count(disk.get("used_bytes"))
        value = percent(used, total)
        if value is not None and value > fullest_percent:
            path = disk.get("path")
            fullest_percent = value
            fullest = {
                "disk_path": path[:256] if isinstance(path, str) else None,
                "disk_total_bytes": total,
                "disk_used_bytes": used,
                "disk_percent": value,
            }
    cpu = host.get("cpu_percent")
    load1 = host.get("load1")
    return {
        "ts": int(ts),
        "source": "agent",
        "cpu_percent": round(float(cpu), 2)
        if isinstance(cpu, int | float) and not isinstance(cpu, bool)
        else None,
        "load1": float(load1)
        if isinstance(load1, int | float) and not isinstance(load1, bool)
        else None,
        "mem_total_bytes": mem_total,
        "mem_used_bytes": mem_used,
        "mem_percent": percent(mem_used, mem_total),
        **(
            fullest
            or {
                "disk_path": None,
                "disk_total_bytes": None,
                "disk_used_bytes": None,
                "disk_percent": None,
            }
        ),
    }


ALERT_TITLES = {
    ("cpu", "high"): "Host CPU usage is high",
    ("mem", "high"): "Host memory usage is high",
    ("disk", "high"): "Host disk usage is high",
    ("cpu", "recovered"): "Host CPU usage is back to normal",
    ("mem", "recovered"): "Host memory usage is back to normal",
    ("disk", "recovered"): "Host disk usage is back to normal",
}

ACTIVE_SERVICE: MonitoringService | None = None


class MonitoringService:
    def __init__(
        self,
        ctx: ModuleContext,
        agent: HostAgentService | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.ctx = ctx
        self.database = ctx.database
        self.agent = agent or HostAgentService(ctx)
        self.clock = clock
        self.settings_path = ctx.data_dir / "control-plane" / SETTINGS_FILE
        self.settings = self._load_settings()
        self.rates = RateTracker()
        self.aggregator = MinuteAggregator()
        self.alerts = AlertTracker(self._emit)
        self.last_error: str | None = None
        self.last_sample_at: float | None = None
        self.last_host: dict[str, Any] | None = None
        self._cpu_count: int | None = None
        self._cpu_count_at: float | None = None
        self._maintained_hour: int | None = None
        self._task: asyncio.Task[None] | None = None
        self._wake: asyncio.Event | None = None

    # ----- settings --------------------------------------------------------
    def _load_settings(self) -> dict[str, Any]:
        try:
            payload = json.loads(self.settings_path.read_text(encoding="utf-8"))
            return validate_settings(payload)
        except FileNotFoundError:
            return validate_settings({})
        except (OSError, ValueError):
            LOGGER.warning("monitoring settings file is invalid; using defaults")
            return validate_settings({})

    def save_settings(self, payload: Any) -> dict[str, Any]:
        value = validate_settings(payload, base=self.settings)
        self.settings_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.settings_path.with_name(
            f".{SETTINGS_FILE}.{secrets.token_hex(4)}.tmp"
        )
        temporary.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
        with contextlib.suppress(OSError):
            temporary.chmod(0o600)
        os.replace(temporary, self.settings_path)
        self.settings = value
        if self._wake is not None:
            self._wake.set()
        return value

    # ----- collection ------------------------------------------------------
    async def _cpu_count_for(self, payload: Any, now: float) -> int | None:
        host = payload.get("host") if isinstance(payload, dict) else None
        reported = host.get("cpu_count") if isinstance(host, dict) else None
        if isinstance(reported, int) and not isinstance(reported, bool) and reported > 0:
            self._cpu_count, self._cpu_count_at = reported, now
            return reported
        if self._cpu_count_at is None or now - self._cpu_count_at > CPU_COUNT_REFRESH_SECONDS:
            self._cpu_count_at = now
            try:
                info = await self.agent.call("/v1/info")
            except AgentError:
                info = None
            host_info = info.get("host") if isinstance(info, dict) else None
            count = host_info.get("cpu_count") if isinstance(host_info, dict) else None
            if isinstance(count, int) and not isinstance(count, bool) and count > 0:
                self._cpu_count = count
        return self._cpu_count

    def ingest(self, payload: Any, now: float, cpu_count: int | None) -> list[dict[str, Any]]:
        """Feed one agent payload; returns finished minute rows (if the minute rolled)."""
        agent_ts = payload.get("ts") if isinstance(payload, dict) else None
        ts = float(agent_ts) if isinstance(agent_ts, int | float) and agent_ts > 0 else now
        samples = normalize_metrics(payload, ts, self.rates, cpu_count)
        snapshot = host_snapshot(payload, ts)
        if snapshot is not None:
            self.last_host = snapshot
        host: Sample | None = next((s for s in samples if s.kind == "host"), None)
        self.alerts.observe(host, self.settings, now)
        self.last_sample_at = now
        return self.aggregator.add(samples, now)

    async def write_rows(self, rows: list[dict[str, Any]]) -> None:
        if not rows:
            return
        try:
            await asyncio.to_thread(store.insert_rows, self.database, MetricMinute, rows)
        except Exception:
            LOGGER.exception("monitoring minute batch insert failed")

    async def poll(self) -> None:
        now = self.clock()
        rows: list[dict[str, Any]] = []
        payload: Any = None
        if self.settings["enabled"]:
            _source, url, _key = self.agent.resolve()
            if url is not None:
                try:
                    payload = await self.agent.call("/v1/metrics")
                    self.last_error = None
                except AgentError as exc:
                    self.last_error = exc.code
        else:
            self.alerts.reset()
        if isinstance(payload, dict):
            cpu_count = await self._cpu_count_for(payload, now)
            rows = self.ingest(payload, now, cpu_count)
        else:
            rows = self.aggregator.flush_due(now)
        await self.write_rows(rows)
        await self.maintain(now)

    async def maintain(self, now: float) -> None:
        """Once per wall-clock hour: roll up complete hours and apply retention."""
        hour = int(now // 3600)
        if self._maintained_hour is not None and hour <= self._maintained_hour:
            return
        self._maintained_hour = hour
        try:
            await asyncio.to_thread(store.rollup_pending, self.database, now)
            await asyncio.to_thread(
                store.prune,
                self.database,
                now,
                int(self.settings["minute_retention_days"]),
                int(self.settings["hour_retention_days"]),
            )
        except Exception:
            LOGGER.exception("monitoring rollup/retention failed")

    def _emit(self, metric: str, kind: str, value: float, info: dict[str, Any]) -> None:
        high = kind == "high"
        threshold = info.get("threshold")
        self.ctx.events.publish(
            Event(
                type=f"metrics.{metric}_{kind}",
                severity="warning" if high else "info",
                title=ALERT_TITLES[(metric, kind)],
                message=(
                    f"{metric} {value:.1f}% >= {threshold}% for "
                    f"{info.get('duration_minutes')} min"
                    if high
                    else f"{metric} {value:.1f}% < {threshold}%"
                ),
                module=MODULE_NAME,
                # Separate keys: a recovery must not be swallowed by the high alert's dedupe.
                dedupe_key=f"metrics.{metric}_{kind}",
                details={"metric": metric, **info},
            )
        )

    # ----- queries -----------------------------------------------------------
    def _range(self, range_key: str) -> tuple[str, Any, float]:
        seconds = RANGES[range_key]
        resolution = pick_resolution(seconds, int(self.settings["minute_retention_days"]))
        model = MetricMinute if resolution == "minute" else MetricHour
        return resolution, model, self.clock() - seconds

    def host_series(self, range_key: str) -> dict[str, Any]:
        resolution, model, since = self._range(range_key)
        rows = store.series(self.database, model, "host", since)
        points = [{"ts": row["ts"], **{k: row[k] for k in HOST_POINT_FIELDS}} for row in rows]
        return {
            "resolution": resolution,
            "points": downsample(points),
            "latest": self.latest_host(rows),
        }

    def latest_host(self, rows: list[dict[str, Any]] | None = None) -> dict[str, Any] | None:
        """Newest absolute host totals: the last poll, else the newest stored minute.

        Stored minutes carry memory bytes (averaged) but no disk byte totals.
        """
        now = self.clock()
        if self.last_host is not None and now - self.last_host["ts"] <= LATEST_LOOKBACK_SECONDS:
            return dict(self.last_host)
        newest = rows[-1] if rows else None
        if newest is None or now - float(newest["ts"]) > LATEST_LOOKBACK_SECONDS:
            return None
        return {
            "ts": int(newest["ts"]),
            "source": "minute",
            "cpu_percent": newest.get("cpu_percent"),
            "load1": newest.get("load1"),
            "mem_total_bytes": newest.get("mem_limit_bytes"),
            "mem_used_bytes": newest.get("mem_bytes"),
            "mem_percent": newest.get("mem_percent"),
            "disk_path": None,
            "disk_total_bytes": None,
            "disk_used_bytes": None,
            "disk_percent": newest.get("disk_percent"),
        }

    def container_series(self, range_key: str) -> dict[str, Any]:
        resolution, model, since = self._range(range_key)
        rows = store.series(self.database, model, "container", since)
        latest = {
            row["scope"]: row
            for row in store.latest_containers(
                self.database, self.clock() - LATEST_LOOKBACK_SECONDS
            )
        }
        groups: dict[str, list[dict[str, Any]]] = {}
        for row in rows:
            groups.setdefault(row["scope"], []).append(row)
        items: list[dict[str, Any]] = []
        for name, group in groups.items():
            newest = latest.get(name) or group[-1]
            items.append(
                {
                    "name": name,
                    "protected": bool(newest["protected"]),
                    "latest": {
                        "cpu_percent": newest["cpu_percent"],
                        "mem_bytes": newest["mem_bytes"],
                        "mem_limit_bytes": newest["mem_limit_bytes"],
                    },
                    "points": downsample(
                        [
                            {
                                "ts": row["ts"],
                                "cpu_percent": row["cpu_percent"],
                                "mem_bytes": row["mem_bytes"],
                            }
                            for row in group
                        ]
                    ),
                }
            )
        items.sort(key=lambda item: (-(item["latest"]["cpu_percent"] or 0.0), item["name"]))
        return {"resolution": resolution, "items": items[:MAX_CONTAINER_SERIES]}

    def top(self, by: str, limit: int) -> dict[str, Any]:
        rows = store.latest_containers(self.database, self.clock() - LATEST_LOOKBACK_SECONDS)
        key = "cpu_percent" if by == "cpu" else "mem_bytes"
        rows.sort(key=lambda row: (-(row[key] if row[key] is not None else -1), row["scope"]))
        return {
            "items": [
                {
                    "name": row["scope"],
                    "cpu_percent": row["cpu_percent"],
                    "mem_bytes": row["mem_bytes"],
                }
                for row in rows[:limit]
            ]
        }

    # ----- background ----------------------------------------------------------
    async def _loop(self) -> None:
        assert self._wake is not None
        while True:
            started = time.monotonic()
            try:
                await self.poll()
            except asyncio.CancelledError:
                raise
            except Exception:
                LOGGER.exception("monitoring poll failed")
            interval = float(self.settings["interval_seconds"])
            delay = max(1.0, interval - (time.monotonic() - started))
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(self._wake.wait(), timeout=delay)
            self._wake.clear()

    async def start(self) -> None:
        self._wake = asyncio.Event()
        self._task = asyncio.create_task(self._loop(), name="mrk-monitoring-collector")

    async def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
            self._task = None
        # Keep the partial minute rather than losing up to 59 seconds of samples.
        await self.write_rows(self.aggregator.flush())


def build_router(ctx: ModuleContext, service: MonitoringService) -> APIRouter:
    router = APIRouter(prefix="/api/v1/metrics", tags=["monitoring"])

    def bad_range() -> JSONResponse:
        return ctx.error_payload(
            "invalid_range", f"range must be one of {', '.join(RANGES)}", 422
        )

    @router.get("/host", response_model=None)
    async def host_metrics(
        request: Request, range_key: str = Query(default="1h", alias="range")
    ) -> dict[str, Any] | JSONResponse:
        ctx.require_principal(request, "metrics:read")
        if range_key not in RANGES:
            return bad_range()
        return await asyncio.to_thread(service.host_series, range_key)

    @router.get("/containers", response_model=None)
    async def container_metrics(
        request: Request, range_key: str = Query(default="1h", alias="range")
    ) -> dict[str, Any] | JSONResponse:
        ctx.require_principal(request, "metrics:read")
        if range_key not in RANGES:
            return bad_range()
        return await asyncio.to_thread(service.container_series, range_key)

    @router.get("/top", response_model=None)
    async def top_containers(
        request: Request, by: str = "cpu", limit: int = Query(default=5, ge=1, le=50)
    ) -> dict[str, Any] | JSONResponse:
        ctx.require_principal(request, "metrics:read")
        if by not in ("cpu", "mem"):
            return ctx.error_payload("invalid_by", "by must be cpu or mem", 422)
        return await asyncio.to_thread(service.top, by, limit)

    @router.get("/settings")
    async def get_settings(request: Request) -> dict[str, Any]:
        ctx.require_principal(request, "metrics:read")
        return service.settings

    @router.put("/settings", response_model=None)
    async def put_settings(request: Request) -> dict[str, Any] | JSONResponse:
        principal = ctx.require_principal(request, "agent:write")
        ctx.require_csrf(request, principal)
        try:
            payload = json.loads(await request.body() or b"{}")
        except (ValueError, UnicodeDecodeError):
            return ctx.error_payload("invalid_json", "request body must be JSON", 422)
        try:
            value = await asyncio.to_thread(service.save_settings, payload)
        except SettingsError as exc:
            return ctx.error_payload(exc.code, exc.message, 422)
        await asyncio.to_thread(
            ctx.audit, principal.user_id, "monitoring.settings.update", "monitoring", "settings"
        )
        return value

    return router


def register(ctx: ModuleContext) -> None:
    global ACTIVE_SERVICE
    service = MonitoringService(ctx)
    ACTIVE_SERVICE = service
    ctx.routers.append(build_router(ctx, service))
    ctx.start_hooks.append(service.start)
    ctx.stop_hooks.append(service.stop)

