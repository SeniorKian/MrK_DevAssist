"""Gate 17 resource monitoring: rates, minute batching, rollup, retention, alerts, API."""

from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from mrk_control_plane.config import Settings
from mrk_control_plane.database import Database
from mrk_control_plane.main import create_app
from mrk_control_plane.models import MetricHour, MetricMinute
from mrk_control_plane.modules import monitoring, monitoring_store
from mrk_control_plane.modules.host_agent import AgentError
from mrk_control_plane.modules.monitoring_math import (
    DEFAULT_SETTINGS,
    RECOVERY_SECONDS,
    AlertTracker,
    MinuteAggregator,
    RateTracker,
    Sample,
    SettingsError,
    downsample,
    normalize_metrics,
    pick_resolution,
    rollup_rows,
    validate_settings,
)
from sqlalchemy import func, inspect, select, text

from .helpers import login_owner

PASSWORD = "a-long-role-password-123"  # noqa: S105 - test-only fixture
T0 = 1_800_000_000.0 - (1_800_000_000 % 3600)  # an hour boundary


def metrics_payload(ts: float, step: int, *, cpu_usec: int | None = None) -> dict[str, Any]:
    return {
        "ts": ts,
        "host": {
            "cpu_percent": 40.0 + step,
            "load1": 0.5,
            "mem_total_bytes": 1000,
            "mem_used_bytes": 250,
            "disks": [
                {"path": "/", "total_bytes": 100, "used_bytes": 40},
                {"path": "/data", "total_bytes": 100, "used_bytes": 70},
            ],
            "net_rx_bytes": 1000 * step,
            "net_tx_bytes": 500 * step,
        },
        "containers": [
            {
                "id": "c1",
                "name": "app-web",
                "protected": False,
                "cpu_usage_usec": cpu_usec if cpu_usec is not None else step * 15_000_000,
                "mem_bytes": 100 + step,
                "mem_limit_bytes": 400,
                "io_read_bytes": 300 * step,
                "io_write_bytes": 0,
            },
            {
                "id": "c2",
                "name": "dokploy-postgres",
                "protected": True,
                "cpu_usage_usec": step * 1_500_000,
                "mem_bytes": 800,
                "mem_limit_bytes": None,
                "io_read_bytes": 0,
                "io_write_bytes": 0,
            },
        ],
    }


# ----- rates / normalization -------------------------------------------------------


def test_rate_tracker_deltas_resets_and_identity() -> None:
    rates = RateTracker(forget_after=100)
    assert rates.rate("k", 100, 0.0) is None  # first sample is only a baseline
    assert rates.rate("k", 400, 10.0) == 30.0
    assert rates.rate("k", 50, 20.0) is None  # counter reset -> new baseline
    assert rates.rate("k", 150, 30.0) == 10.0
    assert rates.rate("k", 150, 30.0) is None  # no time elapsed
    assert rates.rate("c", 10, 0.0, ident="a") is None
    assert rates.rate("c", 20, 10.0, ident="b") is None  # same name, new container
    assert rates.rate("c", 30, 20.0, ident="b") == 1.0
    assert rates.rate("k", None, 40.0) is None and rates.rate("k", 10, 50.0) is None
    rates.forget_stale(500.0)
    assert len(rates) == 0


def test_normalize_host_and_container_rates() -> None:
    rates = RateTracker()
    first = normalize_metrics(metrics_payload(T0, 1), T0, rates, cpu_count=4)
    host, web, db = first
    assert host.kind == "host" and host.mem_percent == 25.0 and host.disk_percent == 70.0
    assert host.net_rx_bps is None and web.cpu_percent is None  # baselines only
    assert web.mem_percent == 25.25 and db.mem_percent == 80.0  # no limit -> host total
    assert db.protected is True

    second = normalize_metrics(metrics_payload(T0 + 15, 2), T0 + 15, rates, cpu_count=4)
    host, web, db = second
    assert host.net_rx_bps == pytest.approx(1000 / 15) and host.net_tx_bps == pytest.approx(
        500 / 15
    )
    # 15 s of CPU in 15 s wall time on a 4-core host = one full core = 25 %.
    assert web.cpu_percent == 25.0
    assert db.cpu_percent == 2.5
    assert web.io_read_bps == pytest.approx(20.0)

    # Container restart: the usage counter goes back to a small number.
    third = normalize_metrics(metrics_payload(T0 + 30, 3, cpu_usec=10), T0 + 30, rates, 4)
    assert third[1].cpu_percent is None
    fourth = normalize_metrics(
        metrics_payload(T0 + 45, 4, cpu_usec=10 + 30_000_000), T0 + 45, rates, 4
    )
    assert fourth[1].cpu_percent == 50.0
    # Unknown cpu_count -> no container cpu, everything else still works.
    unknown = normalize_metrics(metrics_payload(T0 + 60, 5), T0 + 60, rates, None)
    assert unknown[1].cpu_percent is None and unknown[1].mem_bytes == 105
    assert normalize_metrics({"host": None, "containers": None}, T0, rates, 4) == []
    assert normalize_metrics("bad", T0, rates, 4) == []


# ----- minute buckets / rollup ---------------------------------------------------------


def test_minute_aggregator_averages_and_flushes_once_per_minute() -> None:
    aggregator = MinuteAggregator()
    assert aggregator.add([Sample("host", "host", cpu_percent=10.0, mem_bytes=100)], T0) == []
    assert aggregator.add([Sample("host", "host", cpu_percent=30.0, mem_bytes=201)], T0 + 30) == []
    assert aggregator.flush_due(T0 + 59) == []
    rows = aggregator.add([Sample("host", "host", cpu_percent=50.0)], T0 + 61)
    assert len(rows) == 1
    row = rows[0]
    assert row["ts"] == T0 and row["samples"] == 2 and row["cpu_percent"] == 20.0
    assert row["cpu_max_percent"] == 30.0 and row["mem_bytes"] == 150
    rows = aggregator.flush_due(T0 + 125)
    assert rows[0]["ts"] == T0 + 60 and rows[0]["mem_bytes"] is None
    assert aggregator.flush() == []


def test_rollup_rows_are_sample_weighted() -> None:
    rows = [
        {"kind": "host", "scope": "host", "ts": T0, "samples": 3, "protected": False,
         "cpu_percent": 10.0, "cpu_max_percent": 20.0, "mem_bytes": 100, "mem_limit_bytes": 9},
        {"kind": "host", "scope": "host", "ts": T0 + 60, "samples": 1, "protected": False,
         "cpu_percent": 50.0, "cpu_max_percent": 90.0, "mem_bytes": 300, "mem_limit_bytes": 10},
    ]
    (hour,) = rollup_rows(rows, int(T0))
    assert hour["cpu_percent"] == 20.0 and hour["cpu_max_percent"] == 90.0
    assert hour["mem_bytes"] == 150 and hour["mem_limit_bytes"] == 10 and hour["samples"] == 4
    assert hour["net_rx_bps"] is None


@pytest.fixture
def database(tmp_path: Path) -> Database:
    db = Database(tmp_path)
    db.initialize()
    return db


def minute_row(ts: float, scope: str = "host", kind: str = "host", **values: Any) -> dict:
    row = {"kind": kind, "scope": scope, "ts": int(ts), "samples": 4, "protected": False}
    row.update(values)
    return row


def test_store_rollup_is_idempotent_and_retention_prunes(database: Database) -> None:
    rows = [minute_row(T0 + i * 60, cpu_percent=float(i)) for i in range(60)]
    rows += [minute_row(T0 + 3600 + i * 60, cpu_percent=100.0) for i in range(10)]
    rows += [minute_row(T0, "app", "container", cpu_percent=4.0, mem_bytes=10)]
    assert monitoring_store.insert_rows(database, MetricMinute, rows) == 71

    # Only complete hours roll up; the current hour (T0+3600..) is left alone.
    assert monitoring_store.rollup_pending(database, T0 + 3600 + 900) == [int(T0)]
    assert monitoring_store.rollup_pending(database, T0 + 3600 + 900) == []
    assert monitoring_store.rollup_hour(database, int(T0)) == 2  # rebuild is idempotent
    hours = monitoring_store.series(database, MetricHour, "host", 0)
    assert len(hours) == 1 and hours[0]["cpu_percent"] == 29.5 and hours[0]["samples"] == 240
    assert monitoring_store.series(database, MetricHour, "container", 0)[0]["mem_bytes"] == 10
    assert monitoring_store.rollup_pending(database, T0 + 7200 + 1) == [int(T0 + 3600)]

    now = T0 + 3 * 86400
    deleted = monitoring_store.prune(database, now, minute_retention_days=2,
                                     hour_retention_days=2)
    assert deleted == (71, 3)
    monitoring_store.insert_rows(database, MetricMinute, [minute_row(now - 60)])
    assert monitoring_store.prune(database, now, 2, 90) == (0, 0)


def test_range_resolution_and_downsampling() -> None:
    assert pick_resolution(3600, 7) == "minute"
    assert pick_resolution(86400, 7) == "minute"
    assert pick_resolution(7 * 86400, 7) == "hour"
    assert pick_resolution(86400, 1) == "minute"
    points = [{"ts": i * 60, "cpu_percent": float(i), "mem_bytes": i, "x": None}
              for i in range(1440)]
    reduced = downsample(points)
    assert len(reduced) <= 500 and reduced[0]["ts"] == 0
    assert reduced[0]["cpu_percent"] == 1.0 and reduced[0]["mem_bytes"] == 1
    assert reduced[0]["x"] is None
    assert downsample(points[:10]) == points[:10]
    assert len(downsample(points, 7)) <= 7


# ----- alerts ---------------------------------------------------------------------------


def test_alert_state_machine_sustained_and_no_spam() -> None:
    emitted: list[tuple[str, str]] = []
    tracker = AlertTracker(lambda metric, kind, value, info: emitted.append((metric, kind)))
    settings = validate_settings({"alerts": {"cpu_percent": 90, "duration_minutes": 2}})

    def at(seconds: float, cpu: float | None = None, disk: float | None = None) -> None:
        tracker.observe(Sample("host", "host", cpu_percent=cpu, disk_percent=disk), settings,
                        T0 + seconds)

    at(0, cpu=95)
    at(60, cpu=95)
    assert emitted == []
    at(90, cpu=50)  # dip resets the sustained window
    at(100, cpu=95)
    at(200, cpu=99)
    assert emitted == []
    at(220, cpu=99)
    assert emitted == [("cpu", "high")]
    for second in range(230, 2000, 15):
        at(second, cpu=99)
    at(2000, cpu=None)  # missing values change nothing
    assert emitted == [("cpu", "high")]  # never spams while it stays high
    at(2010, cpu=10)
    at(2010 + RECOVERY_SECONDS / 2, cpu=95)  # brief dip is not a recovery
    at(2050, cpu=10)
    assert emitted == [("cpu", "high")]
    at(2050 + RECOVERY_SECONDS, cpu=10)
    assert emitted == [("cpu", "high"), ("cpu", "recovered")]
    at(3000, cpu=10)
    assert emitted == [("cpu", "high"), ("cpu", "recovered")]

    # Disk has its own state; disabling alerts resets silently.
    at(4000, disk=99)
    at(4200, disk=99)
    assert emitted[-1] == ("disk", "high")
    tracker.observe(Sample("host", "host", disk_percent=10), {"alerts": {"enabled": False}},
                    T0 + 4300)
    at(4400, disk=10)
    at(4500, disk=10)
    assert emitted[-1] == ("disk", "high")


# ----- settings -------------------------------------------------------------------------


def test_settings_validation() -> None:
    assert validate_settings({}) == DEFAULT_SETTINGS
    merged = validate_settings({"interval_seconds": 30, "alerts": {"disk_percent": 80.5}})
    assert merged["interval_seconds"] == 30 and merged["alerts"]["disk_percent"] == 80.5
    assert merged["alerts"]["cpu_percent"] == 90
    for bad in (
        [],
        {"unknown": 1},
        {"enabled": "yes"},
        {"interval_seconds": 1},
        {"interval_seconds": 15.5},
        {"interval_seconds": True},
        {"minute_retention_days": 0},
        {"hour_retention_days": 3, "minute_retention_days": 7},
        {"alerts": []},
        {"alerts": {"cpu_percent": 0}},
        {"alerts": {"cpu_percent": 101}},
        {"alerts": {"duration_minutes": 1.5}},
        {"alerts": {"nope": 1}},
        {"alerts": {"enabled": 1}},
        {"interval_seconds": float("nan")},
    ):
        with pytest.raises(SettingsError):
            validate_settings(bad)


# ----- collector service ------------------------------------------------------------------


class FakeAgent:
    def __init__(self) -> None:
        self.payloads: list[Any] = []
        self.configured = True
        self.calls: list[str] = []

    def resolve(self):
        return ("panel", "http://agent:7070", b"k") if self.configured else (None, None, None)

    async def call(self, path: str) -> Any:
        self.calls.append(path)
        if path == "/v1/info":
            return {"host": {"cpu_count": 2}}
        if not self.payloads:
            raise AgentError("agent_unreachable", 502, "down")
        return self.payloads.pop(0)


def make_service(tmp_path: Path, database: Database, clock: list[float]):
    events: list[Any] = []
    ctx = SimpleNamespace(
        database=database,
        data_dir=tmp_path,
        events=SimpleNamespace(publish=events.append),
    )
    agent = FakeAgent()
    service = monitoring.MonitoringService(ctx, agent=agent, clock=lambda: clock[0])
    return service, agent, events


def test_collector_writes_one_batch_per_minute(
    tmp_path: Path, database: Database, monkeypatch
) -> None:
    clock = [T0 + 5]
    service, agent, _events = make_service(tmp_path, database, clock)
    inserts: list[int] = []
    original = monitoring_store.insert_rows

    def counting(db, model, rows):
        inserts.append(len(rows))
        return original(db, model, rows)

    monkeypatch.setattr(monitoring_store, "insert_rows", counting)

    async def scenario() -> None:
        for step in range(12):  # 3 minutes at a 15 s interval
            agent.payloads.append(metrics_payload(clock[0], step + 1))
            await service.poll()
            clock[0] += 15
        # Agent goes away: the pending minute is still flushed on the next tick.
        clock[0] += 60
        await service.poll()

    asyncio.run(scenario())
    assert inserts == [3, 3, 3]  # one insert per minute, host + two containers each
    with database.session() as db:
        assert db.scalar(select(func.count()).select_from(MetricMinute)) == 9
    # cpu_count came from /v1/info once (the payload had none) and was reused.
    assert agent.calls.count("/v1/info") == 1
    top = service.top("cpu", 5)["items"]
    assert [item["name"] for item in top] == ["app-web", "dokploy-postgres"]
    assert top[0]["cpu_percent"] == 50.0  # 1 core of 2
    by_mem = service.top("mem", 1)["items"]
    assert by_mem == [{"name": "dokploy-postgres", "cpu_percent": 5.0, "mem_bytes": 800}]
    assert service.last_error == "agent_unreachable"

    host = service.host_series("1h")
    assert host["resolution"] == "minute" and len(host["points"]) == 3
    assert set(host["points"][0]) == {"ts", "cpu_percent", "mem_percent", "disk_percent",
                                      "load1", "net_rx_bps", "net_tx_bps"}
    containers = service.container_series("1h")
    assert containers["items"][0]["name"] == "app-web"
    assert containers["items"][0]["latest"]["mem_limit_bytes"] == 400
    assert len(containers["items"][0]["points"]) == 3
    assert containers["items"][1]["protected"] is True


def test_collector_disabled_unconfigured_and_stop_flush(
    tmp_path: Path, database: Database
) -> None:
    clock = [T0 + 5]
    service, agent, _events = make_service(tmp_path, database, clock)

    async def scenario() -> None:
        agent.configured = False
        await service.poll()
        assert agent.calls == []
        agent.configured = True
        service.save_settings({"enabled": False})
        await service.poll()
        assert agent.calls == []
        service.save_settings({"enabled": True})
        agent.payloads.append(metrics_payload(clock[0], 1))
        await service.poll()
        await service.stop()  # partial minute is kept

    asyncio.run(scenario())
    with database.session() as db:
        assert db.scalar(select(func.count()).select_from(MetricMinute)) == 3
    stored = json.loads((tmp_path / "control-plane" / "monitoring.json").read_text())
    assert stored["enabled"] is True
    # A fresh service reads the persisted file; a corrupt file falls back to defaults.
    reloaded, _a, _e = make_service(tmp_path, database, clock)
    assert reloaded.settings == stored
    (tmp_path / "control-plane" / "monitoring.json").write_text("{bad")
    assert make_service(tmp_path, database, clock)[0].settings == DEFAULT_SETTINGS


def test_collector_publishes_alert_events(tmp_path: Path, database: Database) -> None:
    clock = [T0]
    service, agent, events = make_service(tmp_path, database, clock)
    service.save_settings({"alerts": {"mem_percent": 20, "duration_minutes": 1}})

    async def scenario() -> None:
        for _ in range(6):
            agent.payloads.append(metrics_payload(clock[0], 1))
            await service.poll()
            clock[0] += 15
        low = metrics_payload(clock[0], 1)
        low["host"]["mem_used_bytes"] = 10
        for _ in range(6):
            agent.payloads.append(dict(low, ts=clock[0]))
            await service.poll()
            clock[0] += 15

    asyncio.run(scenario())
    assert [event.type for event in events] == ["metrics.mem_high", "metrics.mem_recovered"]
    high, recovered = events
    assert high.severity == "warning" and recovered.severity == "info"
    assert high.dedupe_key == "metrics.mem_high"
    assert recovered.dedupe_key == "metrics.mem_recovered"
    assert high.module == "monitoring" and high.details["threshold"] == 20


def test_range_queries_pick_resolution_and_downsample(
    tmp_path: Path, database: Database
) -> None:
    now = T0 + 86400
    clock = [now]
    service, _agent, _events = make_service(tmp_path, database, clock)
    rows = [minute_row(now - 86400 + i * 60, cpu_percent=1.0) for i in range(1440)]
    monitoring_store.insert_rows(database, MetricMinute, rows)
    monitoring_store.insert_rows(
        database, MetricHour, [minute_row(now - h * 3600, cpu_percent=2.0) for h in range(200)]
    )
    day = service.host_series("24h")
    assert day["resolution"] == "minute" and 400 < len(day["points"]) <= 500
    week = service.host_series("7d")
    assert week["resolution"] == "hour" and len(week["points"]) == 169
    assert all(point["cpu_percent"] == 2.0 for point in week["points"])
    month = service.host_series("30d")
    assert month["resolution"] == "hour" and len(month["points"]) == 200


# ----- API ----------------------------------------------------------------------------------


def role_client(owner: TestClient, headers: dict[str, str], role: str):
    created = owner.post(
        "/api/v1/users",
        headers=headers,
        json={"username": f"{role}1", "password": PASSWORD, "role": role},
    )
    assert created.status_code == 201, created.text
    client = TestClient(owner.app)
    login = client.post("/api/v1/auth/login", json={"username": f"{role}1", "password": PASSWORD})
    assert login.status_code == 200
    return client, {"X-CSRF-Token": str(login.json()["csrf_token"])}


def test_metrics_api_rbac_csrf_and_payloads(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("MRK_AGENT_URL", raising=False)
    monkeypatch.delenv("MRK_AGENT_KEY_FILE", raising=False)
    app = create_app(Settings.for_test(tmp_path / "cp"))
    with TestClient(app) as owner:
        headers = {"X-CSRF-Token": str(login_owner(owner)["csrf_token"])}
        service = monitoring.ACTIVE_SERVICE
        assert service is not None
        now = time.time()
        minute = int(now // 60) * 60 - 60
        monitoring_store.insert_rows(
            service.database,
            MetricMinute,
            [
                minute_row(minute, cpu_percent=12.0, mem_percent=30.0, disk_percent=40.0),
                minute_row(minute, "web", "container", cpu_percent=7.0, mem_bytes=500,
                           mem_limit_bytes=1000),
                minute_row(minute, "db", "container", cpu_percent=1.0, mem_bytes=900,
                           protected=True),
            ],
        )
        roles = {"owner": (owner, headers)}
        for role in ("admin", "operator", "developer", "viewer"):
            roles[role] = role_client(owner, headers, role)
        reads = ["/api/v1/metrics/host?range=1h", "/api/v1/metrics/containers?range=6h",
                 "/api/v1/metrics/top?by=mem&limit=1", "/api/v1/metrics/settings"]
        for role, (client, role_headers) in roles.items():
            for path in reads:
                assert client.get(path).status_code == 200, (role, path)
            put = client.put("/api/v1/metrics/settings", headers=role_headers,
                             json={"interval_seconds": 20})
            assert put.status_code == (200 if role in ("owner", "admin") else 403), role
        anonymous = TestClient(app)
        for path in reads:
            assert anonymous.get(path).status_code == 401
        assert owner.put("/api/v1/metrics/settings", json={}).status_code == 403  # no CSRF

        host = owner.get("/api/v1/metrics/host").json()
        assert host["resolution"] == "minute"
        assert host["points"][0]["cpu_percent"] == 12.0
        containers = owner.get("/api/v1/metrics/containers").json()["items"]
        assert [item["name"] for item in containers] == ["web", "db"]
        assert containers[0]["latest"] == {"cpu_percent": 7.0, "mem_bytes": 500,
                                           "mem_limit_bytes": 1000}
        assert containers[1]["protected"] is True
        assert owner.get("/api/v1/metrics/top?by=mem&limit=1").json() == {
            "items": [{"name": "db", "cpu_percent": 1.0, "mem_bytes": 900}]
        }
        assert owner.get("/api/v1/metrics/host?range=2h").status_code == 422
        assert owner.get("/api/v1/metrics/top?by=disk").status_code == 422
        assert owner.get("/api/v1/metrics/top?limit=0").status_code == 422

        bad = owner.put("/api/v1/metrics/settings", headers=headers,
                        json={"alerts": {"cpu_percent": 500}})
        assert bad.status_code == 422 and bad.json()["error"]["code"] == "invalid_settings"
        raw = owner.put("/api/v1/metrics/settings", headers=headers, content=b"{nope")
        assert raw.status_code == 422
        saved = owner.put("/api/v1/metrics/settings", headers=headers,
                          json={"alerts": {"duration_minutes": 10}}).json()
        assert saved["interval_seconds"] == 20 and saved["alerts"]["duration_minutes"] == 10
        assert owner.get("/api/v1/metrics/settings").json() == saved
        actions = [item["action"] for item in owner.get("/api/v1/audit-events").json()["items"]]
        assert "monitoring.settings.update" in actions


# ----- migration ---------------------------------------------------------------------------


def test_migration_creates_metric_tables_on_fresh_sqlite(tmp_path: Path) -> None:
    database = Database(tmp_path)
    database.initialize()
    with database.engine.connect() as connection:
        inspector = inspect(connection)
        tables = set(inspector.get_table_names())
        assert {"metric_minutes", "metric_hours"} <= tables
        for table in ("metric_minutes", "metric_hours"):
            indexes = {index["name"]: index["column_names"] for index in
                       inspector.get_indexes(table)}
            assert indexes[f"{table}_scope_ts_idx"] == ["scope", "ts"]
            assert indexes[f"{table}_ts_idx"] == ["ts"]
            columns = {column["name"] for column in inspector.get_columns(table)}
            assert {"scope", "ts", "cpu_percent", "mem_bytes", "mem_limit_bytes", "mem_percent",
                    "disk_percent", "load1", "net_rx_bps", "net_tx_bps", "io_read_bps",
                    "io_write_bps"} <= columns

    config = Config()
    config.set_main_option(
        "script_location",
        (Path(monitoring.__file__).parents[1] / "migrations").as_posix(),
    )
    config.set_main_option("sqlalchemy.url", database.url)
    with database.engine.begin() as connection:
        config.attributes["connection"] = connection
        command.downgrade(config, "20261108_0004")
    with database.engine.connect() as connection:
        assert "metric_minutes" not in inspect(connection).get_table_names()
        version = connection.execute(text("SELECT version_num FROM alembic_version")).scalar()
        assert version == "20261108_0004"
    database.initialize()
    with database.engine.connect() as connection:
        assert "metric_hours" in inspect(connection).get_table_names()
