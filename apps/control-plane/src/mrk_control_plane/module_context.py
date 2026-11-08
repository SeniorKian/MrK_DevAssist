"""Shared contract for feature modules (notifications, host agent, future ones).

Each module lives in ``mrk_control_plane/modules/<name>.py`` and exposes
``register(ctx: ModuleContext) -> None``. It may add an APIRouter, background
start/stop hooks and event subscribers, without editing main.py. main.py builds
one ModuleContext, calls every registered module, mounts the routers and runs
the hooks inside the app lifespan.
"""

from __future__ import annotations

import asyncio
import logging
import threading
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from .auth import AuthStore, Principal
from .config import Settings
from .database import Database
from .netresolve import NetworkSettingsStore
from .secret_store import SecretStore

LOGGER = logging.getLogger(__name__)

SEVERITIES = ("info", "warning", "error", "critical")


@dataclass(frozen=True, slots=True)
class Event:
    """A platform event other modules can react to (e.g. send a notification).

    type: dotted name such as ``backup.failed`` or ``agent.offline``.
    severity: one of SEVERITIES.
    dedupe_key: events with the same key inside a module's dedupe window are merged.
    """

    type: str
    severity: str
    title: str
    message: str = ""
    module: str = "core"
    dedupe_key: str | None = None
    details: dict[str, Any] = field(default_factory=dict)
    occurred_at: float = field(default_factory=time.time)


EventHandler = Callable[[Event], Awaitable[None]]


class EventBus:
    """In-process publish/subscribe. publish() is safe from threads and coroutines."""

    def __init__(self) -> None:
        self._handlers: list[EventHandler] = []
        self._loop: asyncio.AbstractEventLoop | None = None
        self._lock = threading.Lock()

    def bind(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop

    def subscribe(self, handler: EventHandler) -> None:
        with self._lock:
            self._handlers.append(handler)

    def publish(self, event: Event) -> None:
        if event.severity not in SEVERITIES:
            raise ValueError(f"unknown severity: {event.severity}")
        loop = self._loop
        if loop is None or loop.is_closed():
            LOGGER.debug("event dropped before startup", extra={"event_type": event.type})
            return
        with self._lock:
            handlers = list(self._handlers)
        for handler in handlers:
            try:
                running = asyncio.get_running_loop()
            except RuntimeError:
                running = None
            if running is loop:
                loop.create_task(self._safe(handler, event))
            else:
                asyncio.run_coroutine_threadsafe(self._safe(handler, event), loop)

    @staticmethod
    async def _safe(handler: EventHandler, event: Event) -> None:
        try:
            await handler(event)
        except Exception:
            LOGGER.exception("event handler failed", extra={"event_type": event.type})


@dataclass(slots=True)
class ModuleContext:
    settings: Settings
    data_dir: Path
    database: Database
    auth_store: AuthStore
    secret_store: SecretStore
    network_settings: NetworkSettingsStore
    events: EventBus
    require_principal: Callable[[Request, str | None], Principal]
    require_csrf: Callable[[Request, Principal], None]
    error_payload: Callable[[str, str, int], JSONResponse]
    routers: list[APIRouter] = field(default_factory=list)
    start_hooks: list[Callable[[], Awaitable[None]]] = field(default_factory=list)
    stop_hooks: list[Callable[[], Awaitable[None]]] = field(default_factory=list)

    def audit(
        self,
        actor_user_id: int | None,
        action: str,
        object_type: str,
        object_id: str | None,
        result: str = "success",
    ) -> None:
        self.auth_store.record_audit(
            actor_user_id,
            action,
            object_type,
            None if object_id is None else object_id[:255],
            result,
        )
