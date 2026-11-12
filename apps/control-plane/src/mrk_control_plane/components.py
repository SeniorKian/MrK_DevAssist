"""Health probes shared by readiness, ``/api/v1/system/status``, ``/metrics`` and Home.

One place decides what a component's state is, so the status page, the metric and
the Home attention list never disagree:

* ``component_health`` gives the real state of every enabled component (a probe
  of up to ``HEALTH_TIMEOUT_SECONDS``), honouring "stopped on purpose" and the
  watchdog's recovery, and says whether it runs in its own container.
* ``*_blocks_readiness`` answer the narrower readiness question: a registry in its
  own container never gates the panel's container health (Swarm would restart the
  panel for something it cannot fix), but it is still reported as unavailable.

``Reachability`` is the hysteresis every "is X reachable" flag uses: one slow or
failed probe never flips a component to unreachable or publishes a notification.
"""

from __future__ import annotations

import asyncio
import http.client
import json
import socket
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

HEALTH_TIMEOUT_SECONDS = 3.0
READINESS_TIMEOUT_SECONDS = 1.0
NETWORK_FIX = (
    "the panel and the service must share network mrk-net (or the same Dokploy "
    "network); check the service name/alias"
)

# Texts of name-resolution failures across libc flavours (glibc, musl, Windows, macOS).
_NAME_MARKERS = (
    "name or service not known",
    "temporary failure in name resolution",
    "nodename nor servname",
    "getaddrinfo failed",
    "no address associated with hostname",
    "name does not resolve",
    "name resolution",
    "failed to resolve",
)


def is_name_resolution_error(exc: BaseException | None) -> bool:
    """True when ``exc`` (or anything it wraps) is a DNS/name lookup failure."""
    seen: set[int] = set()
    current = exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        if isinstance(current, socket.gaierror):
            return True
        text = str(current).lower()
        if any(marker in text for marker in _NAME_MARKERS):
            return True
        current = current.__cause__ or current.__context__
    return False


@dataclass(frozen=True)
class Probe:
    ok: bool
    # None | name_unresolved | timeout | refused | unreachable | http_status
    reason: str | None = None


def probe_http_component(
    host: str, port: int, path: str, timeout: float = HEALTH_TIMEOUT_SECONDS
) -> Probe:
    connection = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        connection.request("GET", path, headers={"Accept": "application/json"})
        response = connection.getresponse()
        response.read(4096)
        if 200 <= response.status < 300:
            return Probe(True)
        return Probe(False, "http_status")
    except socket.gaierror:
        return Probe(False, "name_unresolved")
    except TimeoutError:
        return Probe(False, "timeout")
    except ConnectionRefusedError:
        return Probe(False, "refused")
    except OSError as exc:
        return Probe(False, "name_unresolved" if is_name_resolution_error(exc) else "unreachable")
    finally:
        connection.close()


def check_http_component(host: str, port: int, path: str, timeout: float = 1.0) -> bool:
    return probe_http_component(host, port, path, timeout).ok


def fetch_json_component(
    host: str, port: int, path: str, timeout: float = 1.0
) -> dict[str, Any] | None:
    connection = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        connection.request("GET", path, headers={"Accept": "application/json"})
        response = connection.getresponse()
        body = response.read(65537)
        if not 200 <= response.status < 300 or len(body) > 65536:
            return None
        parsed = json.loads(body)
        return parsed if isinstance(parsed, dict) else None
    except (OSError, json.JSONDecodeError):
        return None
    finally:
        connection.close()


# ----------------------------------------------------------------------------- hysteresis


class Reachability:
    """Consecutive-failure hysteresis for a reachable/unreachable flag.

    ``reachable`` turns False only after ``failures_needed`` failures in a row that
    span at least ``min_seconds`` (``immediate=True`` skips both, for errors that a
    retry cannot fix, like a rejected key). One success turns it True again.
    ``record`` returns ``"online"``/``"offline"`` on a transition, else None.
    """

    def __init__(self, failures_needed: int = 3, min_seconds: float = 0.0,
                 clock: Callable[[], float] = time.time) -> None:
        self.failures_needed = max(1, failures_needed)
        self.min_seconds = max(0.0, min_seconds)
        self.clock = clock
        self.reachable: bool | None = None
        self.failures = 0
        self.first_failure_at: float | None = None
        self.last_ok_at: float | None = None

    def reset(self) -> None:
        self.reachable = None
        self.failures = 0
        self.first_failure_at = None
        self.last_ok_at = None

    def record(self, ok: bool, *, immediate: bool = False) -> str | None:
        now = self.clock()
        if ok:
            previous = self.reachable
            self.reachable = True
            self.failures = 0
            self.first_failure_at = None
            self.last_ok_at = now
            return "online" if previous is False else None
        self.failures += 1
        if self.first_failure_at is None:
            self.first_failure_at = now
        if self.reachable is False:
            return None
        if immediate or (
            self.failures >= self.failures_needed
            and now - self.first_failure_at >= self.min_seconds
        ):
            self.reachable = False
            return "offline"
        return None


# ----------------------------------------------------------------------------- components

REGISTRY_PROBES = {
    "npm": ("npm_enabled", "npm_health_host", "npm_health_port", "/-/ping"),
    "pypi": ("pypi_enabled", "pypi_health_host", "pypi_health_port", "/+status"),
}


@dataclass(frozen=True)
class ComponentHealth:
    # ready | unavailable | offline | stopped | restarting | not_configured
    state: str
    remote: bool = False
    code: str | None = None

    @property
    def blocks_readiness(self) -> bool:
        return self.state == "unavailable" and not self.remote

    def as_dict(self) -> dict[str, Any]:
        return {"state": self.state, "remote": self.remote, "code": self.code}


def held_back(settings: Any, service_id: str) -> str | None:
    """``stopped`` when the operator stopped it, ``restarting`` while the watchdog
    recovers it, else None. Either way it must not count as a failure."""
    from .modules import services as services_module
    from .modules.services_catalog import read_stopped

    if service_id in read_stopped(settings.data_dir):  # unreadable file = none stopped
        return "stopped"
    watched = services_module.ACTIVE_SERVICE
    try:
        if watched is not None and watched.watchdog.handles(service_id):
            return "restarting"
    except Exception:  # noqa: BLE001 - the watchdog's settings may be unreadable
        return None
    return None


def _is_remote(service_id: str, settings: Any) -> bool:
    from . import remote_services

    try:
        return remote_services.is_remote(service_id, Path(settings.data_dir))
    except Exception:  # noqa: BLE001
        return False


def _registry_code(service_id: str, probe: Probe) -> str:
    if probe.reason == "name_unresolved":
        return "registry_name_unresolved"
    if probe.reason == "timeout":
        return "registry_timeout"
    return "registry_unreachable"


async def registry_health(
    settings: Any, service_id: str, *, timeout: float = HEALTH_TIMEOUT_SECONDS
) -> ComponentHealth:
    enabled, host_field, port_field, path = REGISTRY_PROBES[service_id]
    if not getattr(settings, enabled, False):
        return ComponentHealth("not_configured")
    remote = await asyncio.to_thread(_is_remote, service_id, settings)
    held = await asyncio.to_thread(held_back, settings, service_id)
    if held is not None:
        return ComponentHealth(held, remote)
    if service_id == "pypi" and not remote:
        marker = getattr(settings, "pypi_bootstrap_state_file", None)
        if marker is not None and not marker.is_file():
            return ComponentHealth("unavailable", remote, "registry_bootstrapping")
    probe = await asyncio.to_thread(
        probe_http_component, getattr(settings, host_field), getattr(settings, port_field),
        path, timeout,
    )
    if probe.ok:
        return ComponentHealth("ready", remote)
    return ComponentHealth("unavailable", remote, _registry_code(service_id, probe))


async def registry_blocks_readiness(
    settings: Any, service_id: str, *, timeout: float = READINESS_TIMEOUT_SECONDS
) -> bool:
    """Readiness only: never probes a registry in its own container."""
    enabled = REGISTRY_PROBES[service_id][0]
    if not getattr(settings, enabled, False):
        return False
    if await asyncio.to_thread(_is_remote, service_id, settings):
        return False
    if await asyncio.to_thread(held_back, settings, service_id) is not None:
        return False
    return (await registry_health(settings, service_id, timeout=timeout)).blocks_readiness


async def router_status(
    settings: Any, *, timeout: float = HEALTH_TIMEOUT_SECONDS
) -> dict[str, Any] | None:
    if not getattr(settings, "pypi_enabled", False):
        return None
    return await asyncio.to_thread(
        fetch_json_component, settings.pypi_router_health_host,
        settings.pypi_router_health_port, "/status", timeout,
    )


async def router_health(
    settings: Any, *, timeout: float = HEALTH_TIMEOUT_SECONDS
) -> tuple[ComponentHealth, dict[str, Any] | None]:
    if not getattr(settings, "pypi_enabled", False):
        return ComponentHealth("not_configured"), None
    held = await asyncio.to_thread(held_back, settings, "pypi")
    status = await router_status(settings, timeout=timeout)
    if status is not None:
        return ComponentHealth("offline" if status.get("offline") is True else "ready"), status
    if held is not None:
        # The router serves PyPI only; with PyPI stopped its silence is not a failure.
        return ComponentHealth(held), None
    return ComponentHealth("unavailable", code="router_unreachable"), None


async def router_blocks_readiness(
    settings: Any, *, timeout: float = READINESS_TIMEOUT_SECONDS
) -> bool:
    if not getattr(settings, "pypi_enabled", False):
        return False
    if await asyncio.to_thread(held_back, settings, "pypi") is not None:
        return False
    probe = await asyncio.to_thread(
        probe_http_component, settings.pypi_router_health_host,
        settings.pypi_router_health_port, "/health", timeout,
    )
    return not probe.ok


async def database_health_state(engine: Any, *, timeout: float = HEALTH_TIMEOUT_SECONDS
                                ) -> ComponentHealth:
    from .database import database_health

    try:
        ready = await asyncio.wait_for(asyncio.to_thread(database_health, engine), timeout)
    except TimeoutError:
        # PGlite has a single connection; a long backup or scan holds it. Busy, not down.
        ready = True
    return ComponentHealth("ready") if ready else ComponentHealth(
        "unavailable", code="database_unreachable")


async def component_health(
    settings: Any, engine: Any, *, timeout: float = HEALTH_TIMEOUT_SECONDS
) -> tuple[dict[str, ComponentHealth], dict[str, Any] | None]:
    """Every component's state (all probes in parallel) plus the raw router status."""
    npm, pypi, (router, router_raw), database = await asyncio.gather(
        registry_health(settings, "npm", timeout=timeout),
        registry_health(settings, "pypi", timeout=timeout),
        router_health(settings, timeout=timeout),
        database_health_state(engine, timeout=timeout),
    )
    return {
        "database": database,
        "npm_registry": npm,
        "pypi_registry": pypi,
        "pypi_upstream_router": router,
    }, router_raw
