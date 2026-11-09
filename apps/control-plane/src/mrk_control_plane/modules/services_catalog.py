"""The fixed list of MRK services and how their state and usage are read (docs/35 §3).

Process state comes from supervisord (allowlisted programs only, see
``process_control``). Without the supervisor socket (development, tests) the
state is derived from the local health endpoints, and nothing is controllable.
Usage numbers are cheap approximations, cached per service.
"""

from __future__ import annotations

import asyncio
import json
import os
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

USAGE_TTL_SECONDS = 60.0
WALK_BUDGET_SECONDS = 3.0
WALK_MAX_ENTRIES = 400_000
STOPPED_FILE = "stopped-services.json"
DOH_DEFAULT_PORT = 8053  # panel default for plain DoH behind Traefik (docs/40 §2.3)


@dataclass(frozen=True, slots=True)
class ServiceDef:
    id: str
    name_fa: str
    name_en: str
    description_fa: str
    description_en: str
    internal_port: int | None
    programs: tuple[str, ...]
    actions: tuple[str, ...]
    data_dirs: tuple[str, ...]
    manage_route: str
    domains: bool  # may have public domains


SERVICES: tuple[ServiceDef, ...] = (
    ServiceDef(
        "panel",
        "پنل مدیریت",
        "Admin panel",
        "همین صفحه‌ها: مدیریت کاربران، تنظیمات و همه سرویس‌ها.",
        "These pages: people, settings and every service.",
        8080,
        ("control-plane",),
        (),
        ("control-plane", "database"),
        "#/settings",
        True,
    ),
    ServiceDef(
        "npm",
        "مخزن npm",
        "npm registry",
        "بسته‌های npm را برای پروژه‌ها نگه می‌دارد و از اینترنت می‌آورد.",
        "Caches npm packages for your projects and fetches them from the internet.",
        4873,
        ("verdaccio",),
        ("start", "stop", "restart"),
        ("npm",),
        "#/packages/sources",
        True,
    ),
    ServiceDef(
        "pypi",
        "مخزن PyPI",
        "PyPI registry",
        "بسته‌های پایتون را برای پروژه‌ها نگه می‌دارد و از اینترنت می‌آورد.",
        "Caches Python packages for your projects and fetches them from the internet.",
        3141,
        ("devpi", "pypi-router"),
        ("start", "stop", "restart"),
        ("pypi",),
        "#/packages/sources",
        True,
    ),
    ServiceDef(
        "s3",
        "فضای فایل (S3)",
        "File storage (S3)",
        "فضای فایل سازگار با S3 برای برنامه‌ها و پشتیبان‌ها.",
        "S3-compatible file storage for apps and backups.",
        9000,
        ("s3-engine",),
        ("start", "stop", "restart"),
        ("modules/s3",),
        "#/files/storage",
        True,
    ),
    ServiceDef(
        "agent",
        "دستیار سرور (Agent)",
        "Server agent",
        "کانتینر جدا که وضعیت سرور و Docker را به پنل می‌دهد.",
        "A separate container that reports the server and Docker to the panel.",
        None,
        (),
        (),
        (),
        "#/server/overview",
        False,
    ),
    ServiceDef(
        "firewall",
        "فایروال",
        "Firewall",
        "کانتینر جدا که ورودی‌های سرور را محدود می‌کند.",
        "A separate container that filters traffic into the server.",
        None,
        (),
        (),
        (),
        "#/security/firewall",
        False,
    ),
    ServiceDef(
        "dns",
        "سرور DNS",
        "DNS server",
        "کانتینر جدا که نام‌ها را برای سرور و کانتینرها پاسخ می‌دهد (پورت 53).",
        "A separate container that answers names for the server and containers (port 53).",
        53,
        (),
        (),
        (),
        "#/dns/status",
        False,
    ),
    # docs/40 §5: plain-HTTP DoH of the DNS engine behind Traefik (the public
    # certificate comes from Traefik). Listed only while ``encrypted.doh`` is on
    # with ``tls:false`` (or while it still has domains); the port is the engine's
    # DoH listener (default below).
    ServiceDef(
        "dns-doh",
        "DNS رمزدار (DoH)",
        "Encrypted DNS (DoH)",
        "نشانی https برای DNS رمزدار گوشی‌ها و مرورگرها؛ گواهی را Traefik می‌دهد.",
        "An https address for encrypted DNS on phones and browsers; Traefik provides "
        "the certificate.",
        DOH_DEFAULT_PORT,
        (),
        (),
        (),
        "#/dns/encrypted",
        True,
    ),
)
# Services whose card appears only while the feature is on (see services_view).
CONDITIONAL_SERVICES: tuple[str, ...] = ("dns-doh",)
SERVICE_INDEX: dict[str, ServiceDef] = {item.id: item for item in SERVICES}
DOMAIN_SERVICES: tuple[str, ...] = tuple(item.id for item in SERVICES if item.domains)


# ----------------------------------------------------------------------------- stopped list


def stopped_path(data_dir: Path) -> Path:
    return data_dir / "control-plane" / STOPPED_FILE


def read_stopped(data_dir: Path) -> set[str]:
    """Services the operator stopped on purpose (readiness ignores them)."""
    try:
        payload = json.loads(stopped_path(data_dir).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return set()
    items = payload.get("services") if isinstance(payload, dict) else None
    return {item for item in items or [] if item in SERVICE_INDEX}


def write_stopped(data_dir: Path, services: set[str]) -> None:
    path = stopped_path(data_dir)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(
        json.dumps({"services": sorted(services), "updated_at": int(time.time())}) + "\n",
        encoding="utf-8",
    )
    os.replace(temporary, path)


# ----------------------------------------------------------------------------- state


def state_from_programs(
    service: ServiceDef, status: dict[str, dict[str, str]] | None
) -> tuple[str, str | None]:
    """Map supervisor states of a service's programs to the contract state."""
    if status is None:
        return "unknown", "supervisor_unavailable"
    states = [status.get(name, {}).get("state", "UNKNOWN") for name in service.programs]
    if all(state == "RUNNING" for state in states):
        return "running", None
    if any(state in {"STARTING", "BACKOFF"} for state in states) and not any(
        state == "FATAL" for state in states
    ):
        return "starting", None
    if all(state in {"STOPPED", "EXITED", "STOPPING"} for state in states):
        return "stopped", None
    if any(state == "FATAL" for state in states):
        return ("stopped" if len(states) == 1 else "degraded"), "program_failed"
    return "degraded", "partially_running"


# ----------------------------------------------------------------------------- usage


class UsageCache:
    """Disk bytes, newest file time and an item count per service, refreshed lazily."""

    def __init__(
        self,
        data_dir: Path,
        counters: dict[str, Callable[[], Any]] | None = None,
        ttl: float = USAGE_TTL_SECONDS,
    ) -> None:
        self.data_dir = data_dir
        self.ttl = ttl
        self.counters = counters or {}
        self._values: dict[str, tuple[float, dict[str, Any]]] = {}
        self._running: set[str] = set()
        self._lock = threading.Lock()

    def _walk(self, roots: list[Path]) -> tuple[int, float | None, bool]:
        total = 0
        newest: float | None = None
        seen = 0
        deadline = time.monotonic() + WALK_BUDGET_SECONDS
        stack = [root for root in roots if root.is_dir()]
        partial = False
        while stack:
            current = stack.pop()
            try:
                with os.scandir(current) as entries:
                    for entry in entries:
                        seen += 1
                        if seen > WALK_MAX_ENTRIES or time.monotonic() > deadline:
                            partial = True
                            stack.clear()
                            break
                        try:
                            if entry.is_symlink():
                                continue
                            if entry.is_dir(follow_symlinks=False):
                                stack.append(Path(entry.path))
                                continue
                            info = entry.stat(follow_symlinks=False)
                        except OSError:
                            continue
                        total += info.st_size
                        if newest is None or info.st_mtime > newest:
                            newest = info.st_mtime
            except OSError:
                continue
        return total, newest, partial

    def compute(self, service: ServiceDef) -> dict[str, Any]:
        roots = [self.data_dir / relative for relative in service.data_dirs]
        disk, newest, partial = self._walk(roots) if roots else (None, None, False)
        usage: dict[str, Any] = {
            "disk_bytes": disk,
            "disk_partial": partial,
            "items": None,
            "items_kind": None,
            "last_activity_at": int(newest) if newest else None,
            "requests_24h": None,
        }
        counter = self.counters.get(service.id)
        if counter is not None:
            try:
                extra = counter()
            except Exception:  # noqa: BLE001 - a count is optional
                extra = None
            if isinstance(extra, dict):
                usage.update(extra)
        return usage

    def get(self, service: ServiceDef) -> dict[str, Any] | None:
        with self._lock:
            cached = self._values.get(service.id)
        if cached is not None and time.monotonic() - cached[0] < self.ttl:
            return cached[1]
        return cached[1] if cached else None

    def stale(self, service: ServiceDef) -> bool:
        with self._lock:
            cached = self._values.get(service.id)
            running = service.id in self._running
        return not running and (cached is None or time.monotonic() - cached[0] >= self.ttl)

    def refresh(self, service: ServiceDef) -> dict[str, Any]:
        with self._lock:
            self._running.add(service.id)
        try:
            value = self.compute(service)
        finally:
            with self._lock:
                self._running.discard(service.id)
        with self._lock:
            self._values[service.id] = (time.monotonic(), value)
        return value

    async def read(self, service: ServiceDef, wait: float = 1.5) -> dict[str, Any] | None:
        """Cached usage; refresh in the background when stale (first call waits briefly)."""
        if self.stale(service):
            task = asyncio.ensure_future(asyncio.to_thread(self.refresh, service))
            if self.get(service) is None:
                try:
                    return await asyncio.wait_for(asyncio.shield(task), wait)
                except TimeoutError:
                    return None
        return self.get(service)
