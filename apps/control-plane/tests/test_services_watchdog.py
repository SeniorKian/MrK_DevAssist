"""Crash recovery for npm/PyPI/S3 without restarting the container (services watchdog)."""

from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from mrk_control_plane import process_control
from mrk_control_plane.modules import services_watchdog
from mrk_control_plane.modules.services_catalog import write_stopped
from mrk_control_plane.modules.services_watchdog import ServiceWatchdog, retry_delay


class FakeSupervisor:
    def __init__(self) -> None:
        self.states: dict[str, str] = {
            "verdaccio": "RUNNING",
            "devpi": "RUNNING",
            "pypi-router": "RUNNING",
            "s3-engine": "RUNNING",
        }
        self.actions: list[tuple[str, str]] = []
        self.start_works = False

    def status(self, names: list[str]) -> dict[str, dict[str, str]]:
        return {
            name: {"state": self.states[name], "description": "Exited too quickly"}
            for name in names
            if name in self.states
        }

    def action(self, name: str, action: str) -> None:
        self.actions.append((name, action))
        if self.start_works:
            self.states[name] = "RUNNING"


class Clock:
    def __init__(self) -> None:
        self.now = 1_000_000.0

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def harness(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> SimpleNamespace:
    supervisor = FakeSupervisor()
    monkeypatch.setattr(process_control, "supervisor_available", lambda: True)
    monkeypatch.setattr(process_control, "program_status", supervisor.status)
    monkeypatch.setattr(process_control, "program_action", supervisor.action)
    events: list[Any] = []
    ctx = SimpleNamespace(
        data_dir=tmp_path, events=SimpleNamespace(publish=lambda event: events.append(event))
    )
    settings = {
        "auto_restart": True,
        "restart_base_delay_seconds": 30,
        "restart_max_delay_seconds": 900,
    }
    clock = Clock()
    watchdog = ServiceWatchdog(ctx, lambda: settings, clock=clock)
    return SimpleNamespace(
        supervisor=supervisor, events=events, settings=settings, clock=clock,
        watchdog=watchdog, data_dir=tmp_path,
    )


def run(coro: Any) -> Any:
    return asyncio.run(coro)


def test_retry_delay_grows_and_is_capped() -> None:
    assert [retry_delay(n, 30, 900) for n in range(7)] == [30, 60, 120, 240, 480, 900, 900]


def test_crash_is_retried_with_backoff_and_notified_once(harness: SimpleNamespace) -> None:
    h = harness
    h.supervisor.states["verdaccio"] = "FATAL"
    run(h.watchdog.check())
    record = h.watchdog.record("npm")
    assert record is not None and record.attempts == 0
    assert record.last_error == "verdaccio: Exited too quickly"
    assert [e.type for e in h.events] == ["service.crashed"]
    assert h.watchdog.handles("npm")
    assert h.supervisor.actions == []  # waits the first delay

    h.clock.now += 31
    run(h.watchdog.check())
    assert h.supervisor.actions == [("verdaccio", "start")]
    assert record.attempts == 1
    assert record.next_retry_at == pytest.approx(h.clock.now + 60)

    h.clock.now += 30  # not yet: second wait is 60s
    run(h.watchdog.check())
    assert len(h.supervisor.actions) == 1
    h.clock.now += 31
    run(h.watchdog.check())
    assert len(h.supervisor.actions) == 2
    assert [e.type for e in h.events] == ["service.crashed"]  # no spam

    h.supervisor.states["verdaccio"] = "RUNNING"
    run(h.watchdog.check())
    assert h.watchdog.record("npm") is None
    assert not h.watchdog.handles("npm")
    assert [e.type for e in h.events] == ["service.crashed", "service.recovered"]


def test_flapping_service_keeps_its_backoff_until_stable(harness: SimpleNamespace) -> None:
    h = harness
    h.supervisor.states["devpi"] = "FATAL"
    run(h.watchdog.check())
    h.clock.now += 31
    h.supervisor.start_works = True
    run(h.watchdog.check())
    run(h.watchdog.check())  # running again
    assert h.watchdog.record("pypi") is None
    assert ("devpi", "start") in h.supervisor.actions
    # Crashes again quickly: the attempt count carries over (no tight loop).
    h.supervisor.states["devpi"] = "FATAL"
    run(h.watchdog.check())
    record = h.watchdog.record("pypi")
    assert record is not None and record.attempts == 1
    assert record.next_retry_at == pytest.approx(h.clock.now + 60)


def test_stopped_on_purpose_and_auto_restart_off_are_respected(harness: SimpleNamespace) -> None:
    h = harness
    write_stopped(h.data_dir, {"s3"})
    h.supervisor.states["s3-engine"] = "FATAL"
    run(h.watchdog.check())
    assert h.watchdog.record("s3") is None and h.events == []

    h.settings["auto_restart"] = False
    h.supervisor.states["verdaccio"] = "FATAL"
    run(h.watchdog.check())
    h.clock.now += 10_000
    run(h.watchdog.check())
    assert h.supervisor.actions == []
    assert h.watchdog.record("npm") is not None
    assert not h.watchdog.handles("npm")  # readiness reports it again
    assert h.events[0].details["auto_restart"] is False


def test_manual_action_resets_schedule(harness: SimpleNamespace) -> None:
    h = harness
    h.supervisor.states["verdaccio"] = "FATAL"
    run(h.watchdog.check())
    h.watchdog.reset("npm")
    assert h.watchdog.record("npm") is None
    h.watchdog.busy.add("npm")
    run(h.watchdog.check())
    assert h.watchdog.record("npm") is None  # skipped while an operator action runs


def test_watchdog_constants_are_sane() -> None:
    assert services_watchdog.WATCHED_SERVICES == ("npm", "pypi", "s3")
    assert services_watchdog.TICK_SECONDS <= 30
