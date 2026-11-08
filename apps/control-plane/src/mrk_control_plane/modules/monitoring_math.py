"""Pure helpers for the monitoring module: settings, rates, minute buckets, alerts.

Nothing here touches the network or the database, so it is unit-tested directly.
"""

from __future__ import annotations

import copy
import math
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any

# ----- settings --------------------------------------------------------------

DEFAULT_SETTINGS: dict[str, Any] = {
    "enabled": True,
    "interval_seconds": 15,
    "minute_retention_days": 7,
    "hour_retention_days": 90,
    "alerts": {
        "enabled": True,
        "cpu_percent": 90,
        "mem_percent": 90,
        "disk_percent": 85,
        "duration_minutes": 5,
    },
}

_TOP_RANGES: dict[str, tuple[int, int]] = {
    "interval_seconds": (5, 3600),
    "minute_retention_days": (1, 90),
    "hour_retention_days": (1, 3650),
}
_ALERT_RANGES: dict[str, tuple[int, int]] = {
    "cpu_percent": (1, 100),
    "mem_percent": (1, 100),
    "disk_percent": (1, 100),
    "duration_minutes": (1, 1440),
}


class SettingsError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def _number(value: Any, name: str, low: int, high: int) -> int | float:
    if isinstance(value, bool) or not isinstance(value, int | float) or not math.isfinite(value):
        raise SettingsError("invalid_settings", f"{name} must be a number")
    if not low <= value <= high:
        raise SettingsError("invalid_settings", f"{name} must be between {low} and {high}")
    return int(value) if float(value).is_integer() else float(value)


def validate_settings(payload: Any, base: dict[str, Any] | None = None) -> dict[str, Any]:
    """Merge a (partial) payload onto base and validate. Unknown keys are rejected."""
    if not isinstance(payload, dict):
        raise SettingsError("invalid_settings", "settings must be an object")
    result = copy.deepcopy(base or DEFAULT_SETTINGS)
    for key, value in payload.items():
        if key == "enabled":
            if not isinstance(value, bool):
                raise SettingsError("invalid_settings", "enabled must be a boolean")
            result["enabled"] = value
        elif key in _TOP_RANGES:
            low, high = _TOP_RANGES[key]
            number = _number(value, key, low, high)
            if not isinstance(number, int):
                raise SettingsError("invalid_settings", f"{key} must be an integer")
            result[key] = number
        elif key == "alerts":
            if not isinstance(value, dict):
                raise SettingsError("invalid_settings", "alerts must be an object")
            for alert_key, alert_value in value.items():
                if alert_key == "enabled":
                    if not isinstance(alert_value, bool):
                        raise SettingsError("invalid_settings", "alerts.enabled must be a boolean")
                    result["alerts"]["enabled"] = alert_value
                elif alert_key in _ALERT_RANGES:
                    low, high = _ALERT_RANGES[alert_key]
                    number = _number(alert_value, f"alerts.{alert_key}", low, high)
                    if alert_key == "duration_minutes" and not isinstance(number, int):
                        raise SettingsError(
                            "invalid_settings", "alerts.duration_minutes must be an integer"
                        )
                    result["alerts"][alert_key] = number
                else:
                    raise SettingsError("invalid_settings", f"unknown setting alerts.{alert_key}")
        else:
            raise SettingsError("invalid_settings", f"unknown setting {key}")
    if result["hour_retention_days"] < result["minute_retention_days"]:
        raise SettingsError(
            "invalid_settings", "hour_retention_days must be >= minute_retention_days"
        )
    return result


# ----- rates -----------------------------------------------------------------


class RateTracker:
    """Per-second rates from monotonically increasing counters.

    A counter that goes backwards (agent/container restart, wrap) or whose
    identity changes (same name, new container id) yields no rate for that sample
    and becomes the new baseline. Keys unseen for forget_after seconds are dropped.
    """

    def __init__(self, forget_after: float = 600.0) -> None:
        self.forget_after = forget_after
        self._last: dict[Any, tuple[float, float, Any]] = {}

    def rate(self, key: Any, value: Any, ts: float, ident: Any = None) -> float | None:
        if isinstance(value, bool) or not isinstance(value, int | float):
            self._last.pop(key, None)
            return None
        previous = self._last.get(key)
        self._last[key] = (float(value), ts, ident)
        if previous is None:
            return None
        last_value, last_ts, last_ident = previous
        elapsed = ts - last_ts
        if last_ident != ident or elapsed <= 0 or value < last_value:
            return None
        return (float(value) - last_value) / elapsed

    def forget_stale(self, now: float) -> None:
        for key in [k for k, (_v, ts, _i) in self._last.items() if now - ts > self.forget_after]:
            del self._last[key]

    def __len__(self) -> int:
        return len(self._last)


def percent(part: Any, whole: Any) -> float | None:
    if not isinstance(part, int | float) or not isinstance(whole, int | float) or whole <= 0:
        return None
    return round(min(max(float(part) / float(whole) * 100.0, 0.0), 100.0), 2)


def _num(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    return float(value) if math.isfinite(value) else None


def _int(value: Any) -> int | None:
    number = _num(value)
    return None if number is None else int(number)


@dataclass(slots=True)
class Sample:
    """One normalized point for one scope at one poll."""

    kind: str
    scope: str
    protected: bool = False
    cpu_percent: float | None = None
    mem_bytes: int | None = None
    mem_limit_bytes: int | None = None
    mem_percent: float | None = None
    disk_percent: float | None = None
    load1: float | None = None
    net_rx_bps: float | None = None
    net_tx_bps: float | None = None
    io_read_bps: float | None = None
    io_write_bps: float | None = None


MAX_CONTAINERS = 200


def normalize_metrics(
    payload: Any, ts: float, rates: RateTracker, cpu_count: int | None
) -> list[Sample]:
    """Turn one /v1/metrics payload into host + container samples."""
    if not isinstance(payload, dict):
        return []
    samples: list[Sample] = []
    host = payload.get("host")
    host_mem_total: int | None = None
    if isinstance(host, dict):
        host_mem_total = _int(host.get("mem_total_bytes"))
        mem_used = _int(host.get("mem_used_bytes"))
        disks = host.get("disks") if isinstance(host.get("disks"), list) else []
        disk_values = [
            value
            for value in (
                percent(disk.get("used_bytes"), disk.get("total_bytes"))
                for disk in disks
                if isinstance(disk, dict)
            )
            if value is not None
        ]
        cpu = _num(host.get("cpu_percent"))
        samples.append(
            Sample(
                kind="host",
                scope="host",
                cpu_percent=None if cpu is None else round(min(max(cpu, 0.0), 100.0), 2),
                mem_bytes=mem_used,
                mem_limit_bytes=host_mem_total,
                mem_percent=percent(mem_used, host_mem_total),
                disk_percent=max(disk_values) if disk_values else None,
                load1=_num(host.get("load1")),
                net_rx_bps=rates.rate(("host", "net_rx"), host.get("net_rx_bytes"), ts),
                net_tx_bps=rates.rate(("host", "net_tx"), host.get("net_tx_bytes"), ts),
            )
        )
    containers = payload.get("containers")
    for item in (containers if isinstance(containers, list) else [])[:MAX_CONTAINERS]:
        if not isinstance(item, dict) or not isinstance(item.get("name"), str):
            continue
        name = item["name"].lstrip("/")[:128]
        if not name:
            continue
        ident = item.get("id")
        usec_rate = rates.rate((name, "cpu"), item.get("cpu_usage_usec"), ts, ident)
        cpu_percent: float | None = None
        if usec_rate is not None and cpu_count:
            # usec of CPU per second of wall time / (1e6 * cores) -> share of the host.
            cpu_percent = round(min(max(usec_rate / 1e6 / cpu_count * 100.0, 0.0), 100.0), 2)
        mem = _int(item.get("mem_bytes"))
        limit = _int(item.get("mem_limit_bytes"))
        samples.append(
            Sample(
                kind="container",
                scope=name,
                protected=bool(item.get("protected")),
                cpu_percent=cpu_percent,
                mem_bytes=mem,
                mem_limit_bytes=limit,
                mem_percent=percent(mem, limit if limit else host_mem_total),
                io_read_bps=rates.rate((name, "io_read"), item.get("io_read_bytes"), ts, ident),
                io_write_bps=rates.rate((name, "io_write"), item.get("io_write_bytes"), ts, ident),
            )
        )
    rates.forget_stale(ts)
    return samples


# ----- minute buckets ----------------------------------------------------------

AVERAGED = (
    "cpu_percent",
    "mem_bytes",
    "mem_percent",
    "disk_percent",
    "load1",
    "net_rx_bps",
    "net_tx_bps",
    "io_read_bps",
    "io_write_bps",
)
METRIC_FIELDS = (*AVERAGED, "cpu_max_percent", "mem_limit_bytes")
_INTEGER_FIELDS = {"mem_bytes", "mem_limit_bytes"}


@dataclass(slots=True)
class _Accumulator:
    samples: int = 0
    protected: bool = False
    sums: dict[str, float] = field(default_factory=dict)
    counts: dict[str, int] = field(default_factory=dict)
    cpu_max: float | None = None
    mem_limit: int | None = None

    def add(self, sample: Sample) -> None:
        self.samples += 1
        self.protected = sample.protected
        for name in AVERAGED:
            value = getattr(sample, name)
            if value is None:
                continue
            self.sums[name] = self.sums.get(name, 0.0) + float(value)
            self.counts[name] = self.counts.get(name, 0) + 1
        if sample.cpu_percent is not None:
            self.cpu_max = max(self.cpu_max or 0.0, sample.cpu_percent)
        if sample.mem_limit_bytes is not None:
            self.mem_limit = sample.mem_limit_bytes

    def row(self, kind: str, scope: str, ts: int) -> dict[str, Any]:
        row: dict[str, Any] = {
            "kind": kind,
            "scope": scope,
            "ts": ts,
            "samples": self.samples,
            "protected": self.protected,
            "cpu_max_percent": self.cpu_max,
            "mem_limit_bytes": self.mem_limit,
        }
        for name in AVERAGED:
            count = self.counts.get(name)
            if not count:
                row[name] = None
            elif name in _INTEGER_FIELDS:
                row[name] = int(round(self.sums[name] / count))
            else:
                row[name] = round(self.sums[name] / count, 3)
        return row


class MinuteAggregator:
    """Accumulates samples for the current wall-clock minute.

    add() returns the finished rows of the previous minute (if the minute
    changed) so the caller can write exactly one batch per minute.
    """

    def __init__(self) -> None:
        self.minute: int | None = None
        self._buckets: dict[tuple[str, str], _Accumulator] = {}

    @staticmethod
    def minute_of(now: float) -> int:
        return int(now // 60) * 60

    def add(self, samples: Iterable[Sample], now: float) -> list[dict[str, Any]]:
        finished = self.flush_due(now)
        if self.minute is None:
            self.minute = self.minute_of(now)
        for sample in samples:
            key = (sample.kind, sample.scope)
            bucket = self._buckets.get(key)
            if bucket is None:
                if sample.kind == "container" and len(self._buckets) > MAX_CONTAINERS:
                    continue
                bucket = self._buckets[key] = _Accumulator()
            bucket.add(sample)
        return finished

    def flush_due(self, now: float) -> list[dict[str, Any]]:
        if self.minute is None or self.minute_of(now) <= self.minute:
            return []
        return self.flush()

    def flush(self) -> list[dict[str, Any]]:
        if self.minute is None:
            return []
        rows = [
            bucket.row(kind, scope, self.minute)
            for (kind, scope), bucket in self._buckets.items()
            if bucket.samples
        ]
        self.minute = None
        self._buckets = {}
        return rows


def rollup_rows(rows: Iterable[dict[str, Any]], hour_ts: int) -> list[dict[str, Any]]:
    """Sample-weighted hourly aggregate of minute rows, one per (kind, scope)."""
    groups: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for row in rows:
        groups.setdefault((row["kind"], row["scope"]), []).append(row)
    result: list[dict[str, Any]] = []
    for (kind, scope), items in groups.items():
        items.sort(key=lambda item: item["ts"])
        out: dict[str, Any] = {
            "kind": kind,
            "scope": scope,
            "ts": hour_ts,
            "samples": sum(int(item.get("samples") or 0) for item in items),
            "protected": bool(items[-1].get("protected")),
        }
        for name in AVERAGED:
            weighted = [
                (float(item[name]), max(int(item.get("samples") or 1), 1))
                for item in items
                if item.get(name) is not None
            ]
            if not weighted:
                out[name] = None
                continue
            value = sum(v * w for v, w in weighted) / sum(w for _v, w in weighted)
            out[name] = int(round(value)) if name in _INTEGER_FIELDS else round(value, 3)
        peaks = [float(item["cpu_max_percent"]) for item in items if item.get("cpu_max_percent")
                 is not None]
        out["cpu_max_percent"] = max(peaks) if peaks else None
        limits = [item["mem_limit_bytes"] for item in items if item.get("mem_limit_bytes")
                  is not None]
        out["mem_limit_bytes"] = int(limits[-1]) if limits else None
        result.append(out)
    return result


# ----- queries -----------------------------------------------------------------

RANGES: dict[str, int] = {"1h": 3600, "6h": 6 * 3600, "24h": 86400, "7d": 7 * 86400,
                          "30d": 30 * 86400}
MAX_POINTS = 500


def pick_resolution(range_seconds: int, minute_retention_days: int) -> str:
    if range_seconds <= 86400 and range_seconds <= minute_retention_days * 86400:
        return "minute"
    return "hour"


def downsample(
    points: list[dict[str, Any]], max_points: int = MAX_POINTS
) -> list[dict[str, Any]]:
    """Average consecutive groups so at most max_points remain (ts = group start)."""
    if len(points) <= max_points:
        return points
    size = math.ceil(len(points) / max_points)
    result: list[dict[str, Any]] = []
    for start in range(0, len(points), size):
        group = points[start : start + size]
        merged: dict[str, Any] = {"ts": group[0]["ts"]}
        for key in group[0]:
            if key == "ts":
                continue
            values = [item[key] for item in group if isinstance(item.get(key), int | float)
                      and not isinstance(item.get(key), bool)]
            if not values:
                merged[key] = group[-1].get(key)
                continue
            mean = sum(values) / len(values)
            merged[key] = int(round(mean)) if all(isinstance(v, int) for v in values) else round(
                mean, 3
            )
        result.append(merged)
    return result


# ----- alerts --------------------------------------------------------------------

ALERT_METRICS = ("cpu", "mem", "disk")
RECOVERY_SECONDS = 60.0


@dataclass(slots=True)
class _AlertState:
    above_since: float | None = None
    below_since: float | None = None
    firing: bool = False


class AlertTracker:
    """Sustained-threshold alerts for host cpu/mem/disk.

    A metric fires once after staying >= threshold for duration_minutes, and
    recovers once after staying below it for RECOVERY_SECONDS. Nothing else is
    emitted in between, so a flapping or constantly high value never spams.
    """

    def __init__(self, emit: Callable[[str, str, float, dict[str, Any]], None]) -> None:
        self.emit = emit
        self.states: dict[str, _AlertState] = {name: _AlertState() for name in ALERT_METRICS}

    def reset(self) -> None:
        self.states = {name: _AlertState() for name in ALERT_METRICS}

    def observe(self, sample: Sample | None, settings: dict[str, Any], now: float) -> None:
        alerts = settings.get("alerts") or {}
        if not alerts.get("enabled", True):
            self.reset()
            return
        if sample is None:
            return
        duration = float(alerts.get("duration_minutes", 5)) * 60.0
        values = {
            "cpu": sample.cpu_percent,
            "mem": sample.mem_percent,
            "disk": sample.disk_percent,
        }
        for name in ALERT_METRICS:
            value = values[name]
            if value is None:
                continue
            threshold = float(alerts.get(f"{name}_percent", 100))
            state = self.states[name]
            info = {"value": round(float(value), 2), "threshold": threshold,
                    "duration_minutes": duration / 60.0}
            if value >= threshold:
                state.below_since = None
                if state.above_since is None:
                    state.above_since = now
                if not state.firing and now - state.above_since >= duration:
                    state.firing = True
                    self.emit(name, "high", float(value), info)
            else:
                state.above_since = None
                if not state.firing:
                    state.below_since = None
                    continue
                if state.below_since is None:
                    state.below_since = now
                if now - state.below_since >= RECOVERY_SECONDS:
                    state.firing = False
                    state.below_since = None
                    self.emit(name, "recovered", float(value), info)
