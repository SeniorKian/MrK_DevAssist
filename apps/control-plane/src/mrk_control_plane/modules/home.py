"""Home summary: "only what needs you" (docs/33 §1.2, Phase 2 BE3).

``GET /api/v1/home`` (alias ``/api/v1/home/summary``) returns, for any signed-in
person, the attention items they are allowed to see, quick actions and the
getting-started checklist. Every item carries a stable ``title_key`` (= its rule
id) and ``params``; the panel turns them into plain Persian, so no English text
or error code reaches Simple mode.

Facts are gathered once per 15 s for everybody (one source at a time may fail or
time out without failing the response), then filtered per person by
permission. Module state is read through each module's own service object or
its tables; nothing here makes outbound calls of its own except the local
registry health checks the system status page already makes.
"""

from __future__ import annotations

import asyncio
import logging
import shutil
import time
from collections.abc import Awaitable, Callable
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import func, select

from ..auth import Principal
from ..components import check_http_component, fetch_json_component
from ..database import database_health
from ..models import (
    AuditEvent,
    MetricMinute,
    NotificationChannel,
    S3Bucket,
    ServerBackupJob,
    ServerBackupRun,
    SystemSetting,
    Task,
    UpstreamHealthCheck,
    User,
)
from ..module_context import ModuleContext

LOGGER = logging.getLogger(__name__)

CACHE_SECONDS = 15.0
SOURCE_TIMEOUT_SECONDS = 3.0
DEFAULT_DISK_THRESHOLD = 85.0
DISK_CRITICAL_PERCENT = 95.0
FIREWALL_DRY_RUN_DAYS = 7
HOST_SAMPLE_MAX_AGE = 15 * 60
SEVERITY_ORDER = {"critical": 0, "error": 1, "warning": 2, "info": 3}
PREFS_KEY = "home.prefs.{user_id}"

# Rule id -> (who may see it, default action). The id doubles as title_key.
ATTENTION_RULES: dict[str, dict[str, Any]] = {
    "component_unavailable": {"any_of": ["system:read"],
                              "action": {"kind": "navigate", "route": "#/packages/sources"}},
    "disk_almost_full": {"any_of": ["system:read", "metrics:read"],
                         "action": {"kind": "navigate", "route": "#/files/maintenance"}},
    "upstreams_all_failing": {"any_of": ["upstream:read"],
                              "action": {"kind": "retry", "route": "#/packages/sources"}},
    "ecosystem_offline": {"any_of": ["upstream:read"],
                          "action": {"kind": "navigate", "route": "#/packages/sources"}},
    "agent_not_paired": {"any_of": ["agent:write"],
                         "action": {"kind": "wizard", "route": "#/server/overview?connect=agent"}},
    "agent_unreachable": {"any_of": ["agent:read"],
                          "action": {"kind": "navigate", "route": "#/server/overview"}},
    "backup_failed": {"any_of": ["backup:server:read"],
                      "action": {"kind": "run", "route": "#/files/app-backups"}},
    "backup_overdue": {"any_of": ["backup:server:read"],
                       "action": {"kind": "run", "route": "#/files/app-backups"}},
    "no_backup_jobs": {"any_of": ["backup:server:write"],
                       "action": {"kind": "create", "route": "#/files/app-backups?new=1"}},
    "updates_available": {"any_of": ["updates:read"],
                          "action": {"kind": "navigate", "route": "#/server/updates"}},
    "vulnerabilities_found": {"any_of": ["vuln:read"],
                              "action": {"kind": "navigate", "route": "#/security/vuln"}},
    "firewall_dry_run": {"any_of": ["firewall:read"],
                         "action": {"kind": "navigate", "route": "#/security/firewall"}},
    "no_notification_channel": {"any_of": ["notification:write"],
                                "action": {"kind": "create",
                                           "route": "#/alerts/channels?new=1"}},
    "jobs_failed": {"any_of": ["task:read"],
                    "action": {"kind": "navigate", "route": "#/alerts/jobs?state=failed"}},
    "s3_public_endpoint_missing": {"any_of": ["s3:admin"],
                                   "action": {"kind": "navigate",
                                              "route": "#/files/storage?settings=1"}},
}

QUICK_ACTIONS: tuple[dict[str, Any], ...] = (
    {"id": "connect_project", "route": "#/packages/connect", "any_of": ["system:read"]},
    {"id": "search_package", "route": "#/packages/search", "any_of": ["cache:read"]},
    {"id": "backup_now", "route": "#/files/app-backups", "any_of": ["backup:server:write"]},
    {"id": "invite_teammate", "route": "#/access/people?invite=1", "any_of": ["user:write"]},
    {"id": "check_updates", "route": "#/server/updates?check=1", "any_of": ["updates:write"]},
    {"id": "view_server_usage", "route": "#/server/usage", "any_of": ["metrics:read"]},
)

CHECKLIST_STEPS: tuple[dict[str, Any], ...] = (
    {"id": "owner_account", "route": "#/access/people", "any_of": [], "optional": False},
    {"id": "connect_project", "route": "#/packages/connect", "any_of": [], "optional": False},
    {"id": "add_notification_channel", "route": "#/alerts/channels?new=1",
     "any_of": ["notification:write"], "optional": False},
    {"id": "connect_agent", "route": "#/server/overview?connect=agent",
     "any_of": ["agent:write"], "optional": False},
    {"id": "create_backup", "route": "#/files/app-backups?new=1",
     "any_of": ["backup:server:write"], "optional": False},
    {"id": "invite_teammate", "route": "#/access/people?invite=1",
     "any_of": ["user:write"], "optional": False},
    {"id": "set_public_address", "route": "#/files/storage?settings=1",
     "any_of": ["s3:admin"], "optional": True},
)
CHECKLIST_IDS = frozenset(step["id"] for step in CHECKLIST_STEPS)


def _allowed(principal: Principal, any_of: list[str]) -> bool:
    return not any_of or any(principal.allows(item) for item in any_of)


def _item(rule: str, severity: str, params: dict[str, Any], subject: str | None = None,
          any_of: list[str] | None = None) -> dict[str, Any]:
    spec = ATTENTION_RULES[rule]
    return {
        "id": f"{rule}:{subject}" if subject else rule,
        "rule": rule,
        "severity": severity,
        "title_key": rule,
        "params": params,
        "action": dict(spec["action"]),
        "_any_of": list(any_of if any_of is not None else spec["any_of"]),
    }


# ----------------------------------------------------------------------------- rules


def evaluate(facts: dict[str, Any], now: float) -> list[dict[str, Any]]:
    """Apply the 13 trigger rules of docs/33 §1.2 to the gathered facts.

    Pure function: a missing source (``None``) simply produces no items.
    """
    items: list[dict[str, Any]] = []

    core = facts.get("core")
    if core:
        # 1. a component unavailable
        for component, state in sorted((core.get("components") or {}).items()):
            if state == "unavailable":
                items.append(_item("component_unavailable", "critical",
                                   {"component": component}, component))

    # 2. disk at or above the alert threshold (data volume or host)
    monitoring = facts.get("monitoring") or {}
    threshold = float(monitoring.get("disk_threshold") or DEFAULT_DISK_THRESHOLD)
    candidates: list[tuple[float, str, str]] = []
    storage_percent = (core or {}).get("storage_used_percent")
    if isinstance(storage_percent, int | float) and storage_percent >= threshold:
        candidates.append((float(storage_percent), "storage", "system:read"))
    host_percent = monitoring.get("host_disk_percent")
    if isinstance(host_percent, int | float) and host_percent >= threshold:
        candidates.append((float(host_percent), "host", "metrics:read"))
    if candidates:
        percent, source, _permission = max(candidates)
        items.append(_item(
            "disk_almost_full",
            "critical" if percent >= DISK_CRITICAL_PERCENT else "warning",
            {"percent": round(percent), "threshold": round(threshold), "source": source},
            any_of=sorted({item[2] for item in candidates}),
        ))

    upstreams = facts.get("upstreams")
    if upstreams:
        for ecosystem in sorted(upstreams.get("ecosystems") or {}):
            state = upstreams["ecosystems"][ecosystem]
            if state.get("offline"):
                # 4. offline mode on
                items.append(_item("ecosystem_offline", "warning",
                                   {"ecosystem": ecosystem}, ecosystem))
            elif state.get("enabled_count", 0) == 0 or state.get("usable_count", 0) == 0:
                # 3. every upstream of the ecosystem failing or blocked
                items.append(_item("upstreams_all_failing", "error", {
                    "ecosystem": ecosystem,
                    "blocked": state.get("blocked_count", 0),
                    "failing": state.get("failing_count", 0),
                }, ecosystem))

    # 5. agent not paired / unreachable
    agent = facts.get("agent")
    if agent is not None:
        if not agent.get("configured"):
            items.append(_item("agent_not_paired", "info", {}))
        elif agent.get("reachable") is False:
            items.append(_item("agent_unreachable", "error",
                               {"since": agent.get("last_checked_at")}))

    backups = facts.get("backups")
    if backups is not None:
        jobs = backups.get("jobs") or []
        # 7. no backup job at all
        if not jobs:
            items.append(_item("no_backup_jobs", "warning", {}))
        for job in jobs:
            if not job.get("enabled"):
                continue
            base = {"job_id": job["id"], "job_name": job["name"],
                    "last_success_at": job.get("last_success_at")}
            # 6. last run failed, or no success in 2x the schedule
            if job.get("last_state") == "failed":
                items.append(_item("backup_failed", "error",
                                   {**base, "failed_at": job.get("last_run_at"),
                                    "error_code": job.get("last_error_code")}, job["id"]))
                continue
            interval = job.get("interval_seconds")
            if not interval:
                continue
            reference = job.get("last_success_at") or job.get("created_at") or now
            if now - float(reference) > 2 * float(interval):
                items.append(_item("backup_overdue", "error",
                                   {**base, "interval_seconds": int(interval)}, job["id"]))

    # 8. image updates available
    updates = facts.get("updates")
    if updates and int(updates.get("available") or 0) > 0:
        items.append(_item("updates_available", "info", {"count": int(updates["available"])}))

    # 9. critical/high vulnerabilities
    vuln = facts.get("vuln")
    if vuln:
        critical, high = int(vuln.get("critical") or 0), int(vuln.get("high") or 0)
        if critical or high:
            items.append(_item("vulnerabilities_found", "critical" if critical else "error",
                               {"count": critical + high, "critical": critical,
                                "high": high}))

    # 10. firewall in dry-run for more than 7 days
    firewall = facts.get("firewall")
    if firewall and firewall.get("configured") and firewall.get("mode") == "dry_run":
        since = firewall.get("since")
        if isinstance(since, int | float) and now - since > FIREWALL_DRY_RUN_DAYS * 86400:
            items.append(_item("firewall_dry_run", "warning",
                               {"days": int((now - since) // 86400), "since": int(since)}))

    # 11. no notification channel
    notifications = facts.get("notifications")
    if notifications is not None and int(notifications.get("channels") or 0) == 0:
        items.append(_item("no_notification_channel", "warning", {}))

    # 12. failed jobs in the last 24 h
    tasks = facts.get("tasks")
    if tasks and int(tasks.get("failed_24h") or 0) > 0:
        items.append(_item("jobs_failed", "warning", {"count": int(tasks["failed_24h"])}))

    # 13. S3 public endpoint missing while buckets exist
    s3 = facts.get("s3")
    if s3 and int(s3.get("buckets") or 0) > 0 and not s3.get("public_endpoint"):
        items.append(_item("s3_public_endpoint_missing", "info",
                           {"buckets": int(s3["buckets"])}))

    items.sort(key=lambda item: (SEVERITY_ORDER[item["severity"]], item["id"]))
    return items


def checklist_done(facts: dict[str, Any]) -> dict[str, bool | None]:
    """Detected completion per step; None when the source could not be read."""

    def get(source: str, key: str) -> Any:
        value = facts.get(source)
        return None if value is None else value.get(key)

    packages = get("people", "cached_packages")
    channels = get("notifications", "channels")
    jobs = get("backups", "jobs")
    users = get("people", "users")
    return {
        "owner_account": True,
        "connect_project": None if packages is None else packages > 0,
        "add_notification_channel": None if channels is None else channels > 0,
        "connect_agent": None if facts.get("agent") is None else bool(
            facts["agent"].get("configured")),
        "create_backup": None if jobs is None else bool(jobs),
        "invite_teammate": None if users is None else users > 1,
        "set_public_address": None if facts.get("s3") is None else bool(
            facts["s3"].get("public_endpoint")),
    }


def build_summary(
    facts: dict[str, Any], principal: Principal, prefs: dict[str, Any], now: float
) -> dict[str, Any]:
    attention = []
    for item in evaluate(facts, now):
        if _allowed(principal, item["_any_of"]):
            attention.append({key: value for key, value in item.items() if key != "_any_of"})
    quick_actions = [
        {"id": action["id"], "route": action["route"]}
        for action in QUICK_ACTIONS
        if _allowed(principal, action["any_of"])
    ]
    detected = checklist_done(facts)
    manual = prefs.get("done") if isinstance(prefs.get("done"), dict) else {}
    checklist = []
    for step in CHECKLIST_STEPS:
        if not _allowed(principal, step["any_of"]):
            continue
        auto = detected.get(step["id"])
        done = bool(auto) or bool(manual.get(step["id"]))
        checklist.append({"id": step["id"], "done": done, "route": step["route"],
                          "optional": step["optional"], "detected": auto})
    worst = attention[0]["severity"] if attention else None
    level = "ok" if worst is None else "problem" if worst in {"critical", "error"} \
        else "attention"
    required = [step for step in checklist if not step["optional"]]
    return {
        "verdict": {"level": level, "count": len(attention)},
        "attention": attention,
        "quick_actions": quick_actions,
        "checklist": checklist,
        "checklist_progress": {
            "done": sum(1 for step in required if step["done"]),
            "total": len(required),
        },
        "checklist_dismissed": bool(prefs.get("dismissed")),
        "generated_at": int(facts.get("_generated_at") or now),
        "sources": dict(facts.get("_sources") or {}),
    }


# ----------------------------------------------------------------------------- facts


def find_service(ctx: ModuleContext, class_name: str) -> Any | None:
    """The live service object a module registered (via its bound start/stop hooks).

    Modules keep their services private; their hooks are bound methods, so the
    owner object is reachable without changing any module.
    """
    for hook in (*ctx.start_hooks, *ctx.stop_hooks):
        owner = getattr(hook, "__self__", None)
        if owner is not None and type(owner).__name__ == class_name:
            return owner
    return None


class HomeService:
    def __init__(self, ctx: ModuleContext, clock: Callable[[], float] = time.time) -> None:
        self.ctx = ctx
        self.clock = clock
        self._cache: tuple[float, dict[str, Any]] | None = None
        self._lock = asyncio.Lock()
        self.collectors: dict[str, Callable[[], Awaitable[dict[str, Any] | None]]] = {
            "core": self._core,
            "upstreams": self._upstreams,
            "tasks": self._tasks,
            "monitoring": self._monitoring,
            "agent": self._agent,
            "backups": self._backups,
            "updates": self._updates,
            "vuln": self._vuln,
            "firewall": self._firewall,
            "notifications": self._notifications,
            "s3": self._s3,
            "people": self._people,
        }

    def invalidate(self) -> None:
        self._cache = None

    async def facts(self) -> dict[str, Any]:
        cached = self._cache
        if cached is not None and time.monotonic() - cached[0] < CACHE_SECONDS:
            return cached[1]
        async with self._lock:
            cached = self._cache
            if cached is not None and time.monotonic() - cached[0] < CACHE_SECONDS:
                return cached[1]
            names = list(self.collectors)
            results = await asyncio.gather(
                *(self._run(name) for name in names), return_exceptions=False
            )
            facts: dict[str, Any] = {"_sources": {}, "_generated_at": int(self.clock())}
            for name, (status, value) in zip(names, results, strict=True):
                facts["_sources"][name] = status
                facts[name] = value
            self._cache = (time.monotonic(), facts)
            return facts

    async def _run(self, name: str) -> tuple[str, dict[str, Any] | None]:
        try:
            value = await asyncio.wait_for(self.collectors[name](), SOURCE_TIMEOUT_SECONDS)
        except TimeoutError:
            LOGGER.warning("home source timed out", extra={"source": name})
            return "timeout", None
        except Exception:
            LOGGER.exception("home source failed", extra={"source": name})
            return "error", None
        return ("ok" if value is not None else "unavailable"), value

    # -- core ------------------------------------------------------------------------
    async def _core(self) -> dict[str, Any]:
        settings = self.ctx.settings
        components: dict[str, str] = {}

        async def http_ok(host: str, port: int, path: str) -> bool:
            return await asyncio.to_thread(check_http_component, host, port, path)

        if getattr(settings, "npm_enabled", False):
            ready = await http_ok(settings.npm_health_host, settings.npm_health_port, "/-/ping")
            components["npm_registry"] = "ready" if ready else "unavailable"
        if getattr(settings, "pypi_enabled", False):
            state_file = getattr(settings, "pypi_bootstrap_state_file", None)
            ready = (state_file is None or state_file.is_file()) and await http_ok(
                settings.pypi_health_host, settings.pypi_health_port, "/+status"
            )
            components["pypi_registry"] = "ready" if ready else "unavailable"
            router = await asyncio.to_thread(
                fetch_json_component, settings.pypi_router_health_host,
                settings.pypi_router_health_port, "/status",
            )
            components["pypi_upstream_router"] = "ready" if router is not None \
                else "unavailable"
        try:
            database_ready = await asyncio.wait_for(
                asyncio.to_thread(database_health, self.ctx.database.engine), timeout=2
            )
        except TimeoutError:
            database_ready = True  # busy, not down (same rule as /system/status)
        components["database"] = "ready" if database_ready else "unavailable"
        total, used, _free = await asyncio.to_thread(shutil.disk_usage, self.ctx.data_dir)
        return {
            "components": components,
            "storage_used_percent": round(used / total * 100, 1) if total else None,
        }

    async def _upstreams(self) -> dict[str, Any]:
        from ..upstream_store import UpstreamStore

        settings = self.ctx.settings
        store = UpstreamStore(self.ctx.data_dir)  # file-backed; cheap to open
        items = await asyncio.to_thread(store.raw_list)
        router = None
        if getattr(settings, "pypi_enabled", False):
            router = await asyncio.to_thread(
                fetch_json_component, settings.pypi_router_health_host,
                settings.pypi_router_health_port, "/status",
            )
        open_circuits = {
            str(entry.get("name"))
            for entry in (router or {}).get("upstreams", [])
            if isinstance(entry, dict) and entry.get("state") == "open"
        }

        def latest_checks() -> dict[str, bool]:
            with self.ctx.database.session() as db:
                newest = (
                    select(UpstreamHealthCheck.upstream_id,
                           func.max(UpstreamHealthCheck.id).label("last_id"))
                    .group_by(UpstreamHealthCheck.upstream_id).subquery()
                )
                rows = db.execute(
                    select(UpstreamHealthCheck.upstream_id, UpstreamHealthCheck.ok)
                    .join(newest, UpstreamHealthCheck.id == newest.c.last_id)
                ).all()
                return {str(upstream_id): bool(ok) for upstream_id, ok in rows}

        checks = await asyncio.to_thread(latest_checks)
        now = self.clock()
        ecosystems: dict[str, dict[str, Any]] = {}
        for ecosystem in ("npm", "pypi"):
            if not getattr(settings, f"{ecosystem}_enabled", False):
                continue
            enabled = [item for item in items
                       if item.get("ecosystem") == ecosystem and item.get("enabled")]
            blocked = [item for item in enabled if item.get("blocked_until") is not None
                       and int(str(item["blocked_until"])) > now]
            failing = [
                item for item in enabled
                if item not in blocked and (
                    checks.get(str(item["id"])) is False
                    or (ecosystem == "pypi" and str(item.get("name")) in open_circuits)
                )
            ]
            ecosystems[ecosystem] = {
                "offline": await asyncio.to_thread(store.offline, ecosystem),
                "enabled_count": len(enabled),
                "blocked_count": len(blocked),
                "failing_count": len(failing),
                "usable_count": len(enabled) - len(blocked) - len(failing),
            }
        return {"ecosystems": ecosystems}

    async def _tasks(self) -> dict[str, Any]:
        since = int(self.clock()) - 86400

        def count() -> int:
            with self.ctx.database.session() as db:
                return int(db.scalar(
                    select(func.count()).select_from(Task).where(
                        Task.state == "failed", Task.finished_at >= since
                    )
                ) or 0)

        return {"failed_24h": await asyncio.to_thread(count)}

    async def _monitoring(self) -> dict[str, Any]:
        service = find_service(self.ctx, "MonitoringService")
        threshold = DEFAULT_DISK_THRESHOLD
        if service is not None:
            alerts = (getattr(service, "settings", None) or {}).get("alerts") or {}
            if isinstance(alerts.get("disk_percent"), int | float):
                threshold = float(alerts["disk_percent"])
        cutoff = int(self.clock()) - HOST_SAMPLE_MAX_AGE

        def latest() -> float | None:
            with self.ctx.database.session() as db:
                return db.scalar(
                    select(MetricMinute.disk_percent)
                    .where(MetricMinute.kind == "host", MetricMinute.ts >= cutoff,
                           MetricMinute.disk_percent.is_not(None))
                    .order_by(MetricMinute.ts.desc()).limit(1)
                )

        return {"disk_threshold": threshold, "host_disk_percent": await asyncio.to_thread(latest)}

    async def _agent(self) -> dict[str, Any] | None:
        service = find_service(self.ctx, "HostAgentService")
        if service is None:
            return None
        # refresh=False: never probe from here; the module's own loop keeps it fresh.
        status = await service.status(refresh=False)
        return {
            "configured": bool(status.get("configured")),
            "reachable": status.get("reachable"),
            "last_checked_at": status.get("last_checked_at"),
        }

    async def _backups(self) -> dict[str, Any] | None:
        service = find_service(self.ctx, "ServerBackupService")
        timezone = None
        if service is not None:
            try:
                timezone = (await asyncio.to_thread(service.settings)).get("timezone")
            except Exception:  # noqa: BLE001 - the default zone is good enough here
                timezone = None
        from .server_backups_cron import DEFAULT_TIMEZONE, CronError, parse_cron

        now = self.clock()

        def read() -> list[dict[str, Any]]:
            jobs: list[dict[str, Any]] = []
            with self.ctx.database.session() as db:
                for job in db.scalars(select(ServerBackupJob).order_by(ServerBackupJob.name)):
                    last = db.scalar(
                        select(ServerBackupRun).where(ServerBackupRun.job_id == job.id)
                        .where(ServerBackupRun.state != "running")
                        .order_by(ServerBackupRun.started_at.desc()).limit(1)
                    )
                    success = db.scalar(
                        select(func.max(ServerBackupRun.finished_at)).where(
                            ServerBackupRun.job_id == job.id,
                            ServerBackupRun.state == "succeeded",
                        )
                    )
                    interval = None
                    try:
                        schedule = parse_cron(job.schedule)
                        zone = timezone or DEFAULT_TIMEZONE
                        first = schedule.next_after(now, zone)
                        interval = schedule.next_after(first, zone) - first
                    except (CronError, ValueError):
                        interval = None
                    jobs.append({
                        "id": job.id,
                        "name": job.name,
                        "enabled": bool(job.enabled),
                        "created_at": job.created_at,
                        "interval_seconds": interval,
                        "last_state": last.state if last is not None else None,
                        "last_run_at": (last.finished_at or last.started_at)
                        if last is not None else None,
                        "last_error_code": last.error_code if last is not None else None,
                        "last_success_at": success,
                    })
            return jobs

        return {"jobs": await asyncio.to_thread(read)}

    async def _updates(self) -> dict[str, Any] | None:
        service = find_service(self.ctx, "UpdatesService")
        if service is None:
            return None
        view = await asyncio.to_thread(service.images_view)
        return {"available": int(view.get("summary", {}).get("update_available") or 0)}

    async def _vuln(self) -> dict[str, Any] | None:
        service = find_service(self.ctx, "VulnService")
        if service is None:
            return None
        summary = await asyncio.to_thread(service.summary_view)
        counts = summary.get("counts") or {}
        return {"critical": int(counts.get("critical") or 0),
                "high": int(counts.get("high") or 0)}

    async def _firewall(self) -> dict[str, Any] | None:
        service = find_service(self.ctx, "FirewallService")
        if service is None:
            return None
        configured = await asyncio.to_thread(service.configured)
        settings = await asyncio.to_thread(service.settings)

        def since() -> int | None:
            # The mode has been what it is since the last mode change or pairing.
            with self.ctx.database.session() as db:
                return db.scalar(
                    select(func.max(AuditEvent.occurred_at)).where(
                        AuditEvent.action.in_(("firewall.mode.change",
                                               "firewall.config.update")),
                        AuditEvent.result == "success",
                    )
                )

        return {"configured": bool(configured), "mode": settings.get("mode"),
                "since": await asyncio.to_thread(since)}

    async def _notifications(self) -> dict[str, Any]:
        def count() -> int:
            with self.ctx.database.session() as db:
                return int(db.scalar(
                    select(func.count()).select_from(NotificationChannel)
                    .where(NotificationChannel.enabled.is_(True))
                ) or 0)

        return {"channels": await asyncio.to_thread(count)}

    async def _s3(self) -> dict[str, Any]:
        from .s3_store import SETTINGS_KEY

        def read() -> dict[str, Any]:
            with self.ctx.database.session() as db:
                buckets = int(db.scalar(select(func.count()).select_from(S3Bucket)) or 0)
                row = db.get(SystemSetting, SETTINGS_KEY)
                stored = row.value if row is not None and isinstance(row.value, dict) else {}
            return {"buckets": buckets, "public_endpoint": bool(stored.get("public_endpoint"))}

        return await asyncio.to_thread(read)

    async def _people(self) -> dict[str, Any]:
        def users() -> int:
            with self.ctx.database.session() as db:
                return int(db.scalar(select(func.count()).select_from(User)) or 0)

        def packages() -> int:
            # "Has any project used the mirror yet?": one cached file is enough, so
            # peek at the storage folders instead of scanning the whole catalogue.
            found = 0
            for folder in (self.ctx.data_dir / "pypi" / "server" / "+files",
                           self.ctx.data_dir / "npm" / "storage"):
                try:
                    found += next(folder.iterdir(), None) is not None
                except OSError:
                    continue
            return found

        return {"users": await asyncio.to_thread(users),
                "cached_packages": await asyncio.to_thread(packages)}

    # -- per-user checklist prefs ------------------------------------------------------
    def prefs(self, user_id: int) -> dict[str, Any]:
        with self.ctx.database.session() as db:
            row = db.get(SystemSetting, PREFS_KEY.format(user_id=user_id))
            return dict(row.value) if row is not None and isinstance(row.value, dict) else {}

    def save_prefs(self, user_id: int, dismissed: bool | None,
                   steps: dict[str, bool] | None) -> dict[str, Any]:
        key = PREFS_KEY.format(user_id=user_id)
        now = int(self.clock())
        with self.ctx.database.session() as db, db.begin():
            row = db.get(SystemSetting, key)
            value = dict(row.value) if row is not None and isinstance(row.value, dict) else {}
            if dismissed is not None:
                value["dismissed"] = dismissed
            if steps:
                done = dict(value.get("done") or {})
                done.update({name: bool(flag) for name, flag in steps.items()})
                value["done"] = done
            if row is None:
                db.add(SystemSetting(key=key, value=value, updated_at=now,
                                     updated_by_user_id=user_id))
            else:
                row.value = value
                row.updated_at = now
                row.updated_by_user_id = user_id
            return value


class ChecklistUpdate(BaseModel):
    dismissed: bool | None = None
    steps: dict[str, bool] | None = Field(default=None, max_length=16)


LAST_SERVICE: HomeService | None = None  # the most recently registered app's service


def register(ctx: ModuleContext) -> None:
    global LAST_SERVICE
    service = HomeService(ctx)
    LAST_SERVICE = service
    router = APIRouter(prefix="/api/v1/home", tags=["home"])

    async def summary(request: Request) -> dict[str, Any]:
        principal = ctx.require_principal(request, None)
        prefs = await asyncio.to_thread(service.prefs, principal.user_id)
        if principal.must_change_password:
            return {"verdict": {"level": "ok", "count": 0}, "attention": [],
                    "quick_actions": [], "checklist": [],
                    "checklist_progress": {"done": 0, "total": 0},
                    "checklist_dismissed": bool(prefs.get("dismissed")),
                    "must_change_password": True, "generated_at": int(service.clock()),
                    "sources": {}}
        facts = await service.facts()
        result = build_summary(facts, principal, prefs, service.clock())
        if not principal.allows("system:read"):
            result.pop("sources", None)
        return result

    router.add_api_route("", summary, methods=["GET"])
    router.add_api_route("/summary", summary, methods=["GET"])

    @router.get("/rules")
    async def rules(request: Request) -> dict[str, Any]:
        """The stable ids the panel maps to plain text (for i18n completeness checks)."""
        ctx.require_principal(request, None)
        return {
            "attention": sorted(ATTENTION_RULES),
            "quick_actions": [item["id"] for item in QUICK_ACTIONS],
            "checklist": [item["id"] for item in CHECKLIST_STEPS],
        }

    @router.patch("/checklist", response_model=None)
    async def update_checklist(
        request: Request, body: ChecklistUpdate
    ) -> dict[str, Any] | JSONResponse:
        principal = ctx.require_principal(request, None)
        ctx.require_csrf(request, principal)
        unknown = sorted(set(body.steps or {}) - CHECKLIST_IDS)
        if unknown:
            return ctx.error_payload(  # type: ignore[call-arg]
                "invalid_checklist_step", "unknown checklist step", 422,
                fields=[{"field": f"steps.{name}", "reason_code": "unknown_step"}
                        for name in unknown],
            )
        value = await asyncio.to_thread(service.save_prefs, principal.user_id,
                                        body.dismissed, body.steps)
        return {"dismissed": bool(value.get("dismissed")), "done": value.get("done") or {}}

    ctx.routers.append(router)
