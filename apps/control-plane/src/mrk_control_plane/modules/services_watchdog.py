"""Crash recovery for non-essential services (npm, PyPI, S3).

Supervisor restarts a crashed program a few times on its own. When it gives up
(state FATAL), the supervisor listener stops the whole container only for the
essential programs (database, panel). For the others this watchdog takes over:
it keeps the container (and the panel) up, retries with a growing delay
(base, 2x base, 4x base ... up to a cap), shows the service as "crashed" with
the next retry time, and sends one notification when it crashes and one when
it works again. Services the operator stopped on purpose are never touched.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from .. import process_control
from ..module_context import Event
from .services_catalog import SERVICE_INDEX, read_stopped

LOGGER = logging.getLogger(__name__)
WATCHED_SERVICES = ("npm", "pypi", "s3")
TICK_SECONDS = 15.0
# A service that stays up this long after a recovery starts again from the base delay.
STABLE_SECONDS = 300.0


@dataclass
class CrashRecord:
    since: float
    attempts: int = 0
    next_retry_at: float = 0.0
    last_attempt_at: float | None = None
    programs: list[str] = field(default_factory=list)
    last_error: str | None = None
    recovered_at: float | None = None

    def public(self) -> dict[str, Any]:
        return {
            "since": int(self.since),
            "attempts": self.attempts,
            "next_retry_at": int(self.next_retry_at) if self.next_retry_at else None,
            "last_attempt_at": int(self.last_attempt_at) if self.last_attempt_at else None,
            "programs": list(self.programs),
            "last_error": self.last_error,
        }


def retry_delay(attempts: int, base: float, cap: float) -> float:
    """Delay before attempt number ``attempts + 1``: base, 2*base, 4*base ... <= cap."""
    return float(min(cap, base * (2 ** min(attempts, 20))))


class ServiceWatchdog:
    def __init__(
        self,
        ctx: Any,
        get_settings: Callable[[], dict[str, Any]],
        *,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.ctx = ctx
        self.get_settings = get_settings
        self.clock = clock
        self.crashed: dict[str, CrashRecord] = {}
        # Services that recovered recently: keep their attempt count until stable.
        self.recovering: dict[str, CrashRecord] = {}
        self.busy: set[str] = set()
        self._task: asyncio.Task[None] | None = None

    # ------------------------------------------------------------------ queries
    def record(self, service_id: str) -> CrashRecord | None:
        return self.crashed.get(service_id)

    def handles(self, service_id: str) -> bool:
        """True while the watchdog is recovering this service (readiness ignores it)."""
        return service_id in self.crashed and bool(self.get_settings().get("auto_restart", True))

    def reset(self, service_id: str) -> None:
        """Called after a manual start/stop/restart: the operator took over."""
        self.crashed.pop(service_id, None)
        self.recovering.pop(service_id, None)

    # ------------------------------------------------------------------ one pass
    async def check(self) -> None:
        settings = self.get_settings()
        if not process_control.supervisor_available():
            return
        programs = sorted({p for sid in WATCHED_SERVICES for p in SERVICE_INDEX[sid].programs})
        status = await asyncio.to_thread(process_control.program_status, programs)
        if status is None:
            return
        stopped = await asyncio.to_thread(read_stopped, self.ctx.data_dir)
        now = self.clock()
        for service_id in WATCHED_SERVICES:
            if service_id in self.busy:
                continue
            service = SERVICE_INDEX[service_id]
            states = {name: status.get(name, {}) for name in service.programs}
            fatal = [name for name, item in states.items() if item.get("state") == "FATAL"]
            if service_id in stopped:
                self.reset(service_id)
                continue
            if fatal:
                await self._on_fatal(service_id, fatal, states, settings, now)
            elif all(item.get("state") == "RUNNING" for item in states.values()):
                self._on_running(service_id, now)

    async def _on_fatal(
        self,
        service_id: str,
        fatal: list[str],
        states: dict[str, dict[str, str]],
        settings: dict[str, Any],
        now: float,
    ) -> None:
        record = self.crashed.get(service_id)
        if record is None:
            previous = self.recovering.pop(service_id, None)
            record = CrashRecord(since=now, attempts=previous.attempts if previous else 0)
            self.crashed[service_id] = record
            record.programs = fatal
            record.last_error = _describe(states, fatal)
            record.next_retry_at = now + retry_delay(
                record.attempts,
                float(settings.get("restart_base_delay_seconds", 30)),
                float(settings.get("restart_max_delay_seconds", 900)),
            )
            self._publish_crashed(service_id, record, settings)
        else:
            record.programs = fatal
            record.last_error = _describe(states, fatal)
        if not settings.get("auto_restart", True) or now < record.next_retry_at:
            return
        self.busy.add(service_id)
        try:
            record.attempts += 1
            record.last_attempt_at = now
            LOGGER.warning(
                "restarting crashed service %s (attempt %s)", service_id, record.attempts
            )
            for program in _start_order(service_id):
                try:
                    # "start" works from FATAL and tolerates programs already running.
                    await asyncio.to_thread(process_control.program_action, program, "start")
                except process_control.SupervisorError as exc:
                    record.last_error = exc.code
                    break
        finally:
            self.busy.discard(service_id)
            record.next_retry_at = self.clock() + retry_delay(
                record.attempts,
                float(settings.get("restart_base_delay_seconds", 30)),
                float(settings.get("restart_max_delay_seconds", 900)),
            )

    def _on_running(self, service_id: str, now: float) -> None:
        record = self.crashed.pop(service_id, None)
        if record is not None:
            record.recovered_at = now
            self.recovering[service_id] = record
            self.ctx.events.publish(
                Event(
                    type="service.recovered",
                    severity="info",
                    title=f"{service_id} works again",
                    message=f"recovered after {record.attempts} automatic restart(s)",
                    module="services",
                    dedupe_key=f"service.crashed:{service_id}",
                    details={"service_id": service_id, "attempts": record.attempts},
                )
            )
            return
        earlier = self.recovering.get(service_id)
        if earlier is not None and earlier.recovered_at is not None:
            if now - earlier.recovered_at >= STABLE_SECONDS:
                self.recovering.pop(service_id, None)

    def _publish_crashed(
        self, service_id: str, record: CrashRecord, settings: dict[str, Any]
    ) -> None:
        auto = bool(settings.get("auto_restart", True))
        self.ctx.events.publish(
            Event(
                type="service.crashed",
                severity="error",
                title=f"{service_id} stopped working",
                message=(
                    "Pishkar keeps the panel up and retries automatically"
                    if auto
                    else "automatic restart is off; restart it from My services"
                ),
                module="services",
                dedupe_key=f"service.crashed:{service_id}",
                details={
                    "service_id": service_id,
                    "programs": record.programs,
                    "auto_restart": auto,
                    "next_retry_at": int(record.next_retry_at) if auto else None,
                },
            )
        )

    # ------------------------------------------------------------------ lifecycle
    async def _loop(self) -> None:
        while True:
            try:
                await self.check()
            except asyncio.CancelledError:
                raise
            except Exception:
                LOGGER.exception("service watchdog pass failed")
            await asyncio.sleep(TICK_SECONDS)

    def start(self) -> None:
        if self._task is None:
            self._task = asyncio.create_task(self._loop(), name="mrk-service-watchdog")

    async def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None


def _start_order(service_id: str) -> list[str]:
    if service_id == "pypi":
        return ["devpi", "pypi-router"]
    return list(SERVICE_INDEX[service_id].programs)


def _describe(states: dict[str, dict[str, str]], fatal: list[str]) -> str | None:
    for name in fatal:
        description = (states.get(name) or {}).get("description")
        if description:
            return f"{name}: {description}"[:200]
    return None
