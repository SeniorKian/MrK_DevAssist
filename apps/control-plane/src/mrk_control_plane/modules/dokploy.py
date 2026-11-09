"""Dokploy integration module (Gate 17, S1).

MRK talks to Dokploy only through Dokploy's official API (docs/28 §1, §9):
rate limited (default 2 req/s, concurrency 2), list/detail cached for 15s and
invalidated after actions, destructive actions confirmed and audited.

Configuration comes from the panel (``data_dir/control-plane/dokploy.json`` +
SecretStore for the API key) or, when both MRK_DOKPLOY_URL and
MRK_DOKPLOY_API_KEY_FILE are set, from the environment (env wins, read-only).
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import secrets
import time
from collections import OrderedDict
from pathlib import Path
from typing import Any
from urllib.parse import quote

from fastapi import APIRouter, Request
from pydantic import BaseModel, ConfigDict, Field

from ..logging_config import redact_text
from ..module_context import Event, ModuleContext
from . import dokploy_normalize as norm
from .dokploy_client import (
    Connection,
    DokployClient,
    DokployError,
    TTLCache,
    validate_api_key,
    validate_dokploy_url,
)

LOGGER = logging.getLogger(__name__)
MODULE_NAME = "dokploy"
CONFIG_FILE = "dokploy.json"
REACHABILITY_DEDUPE_KEY = "dokploy.reachability"
SERVICE_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
ACTIONS = ("deploy", "redeploy", "start", "stop")
DOMAIN_TTL_SECONDS = 300.0
DOMAIN_FETCH_BUDGET = 6
MAX_SEEN_FAILURES = 2000
MAX_LOG_LINES = 5000
# project.one calls spent per (cached) appName index build.
APP_INDEX_PROJECT_BUDGET = 25


def _env_number(name: str, default: float, low: float, high: float) -> float:
    raw = os.getenv(name, "").strip()
    if not raw:
        return default
    try:
        value = float(raw)
    except ValueError:
        LOGGER.warning("ignoring invalid %s", name)
        return default
    return min(max(value, low), high)


def _env_flag(name: str) -> bool:
    return os.getenv(name, "").strip().lower() in {"1", "true", "yes", "on"}


# (key, env var, default, low, high). Panel values override env defaults.
TUNABLES: tuple[tuple[str, str, float, float, float], ...] = (
    ("rate_limit_per_second", "MRK_DOKPLOY_RATE_LIMIT_PER_SECOND", 2.0, 0.1, 20.0),
    ("poll_interval_seconds", "MRK_DOKPLOY_POLL_SECONDS", 60.0, 0.0, 3600.0),
    ("cache_seconds", "MRK_DOKPLOY_CACHE_SECONDS", 15.0, 0.0, 600.0),
)


class DokployConfigRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    url: str = Field(min_length=8, max_length=2048)
    api_key: str | None = Field(default=None, min_length=16, max_length=512)
    rate_limit_per_second: float | None = Field(default=None, ge=0.1, le=20)
    poll_interval_seconds: int | None = Field(default=None, ge=0, le=3600)
    cache_seconds: int | None = Field(default=None, ge=0, le=600)


class DokployTestRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    url: str | None = Field(default=None, min_length=8, max_length=2048)
    api_key: str | None = Field(default=None, min_length=16, max_length=512)


class ConfirmationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    confirmation: str | None = Field(default=None, max_length=255)


class DokployService:
    def __init__(self, ctx: ModuleContext) -> None:
        self.ctx = ctx
        self.config_path = ctx.data_dir / "control-plane" / CONFIG_FILE
        self.allow_loopback = _env_flag("MRK_DOKPLOY_ALLOW_LOOPBACK")
        self.client = DokployClient(
            rate_per_second=self.tunable("rate_limit_per_second"),
            concurrency=int(_env_number("MRK_DOKPLOY_CONCURRENCY", 2, 1, 8)),
            timeout_seconds=_env_number("MRK_DOKPLOY_TIMEOUT_SECONDS", 15.0, 1.0, 120.0),
            max_wait_seconds=_env_number("MRK_DOKPLOY_MAX_QUEUE_SECONDS", 10.0, 0.0, 60.0),
        )
        self.cache = TTLCache()
        self.domains: dict[tuple[str, str], tuple[float, list[str]]] = {}
        self.features: dict[str, bool] = {}
        self.reachable: bool | None = None
        self.last_checked_at: float | None = None
        self.last_error: str | None = None
        self.version: str | None = None
        self.seen_failures: OrderedDict[str, None] = OrderedDict()
        self.failures_seeded = False
        self.status_failed: set[tuple[str, str]] = set()
        self.started_at = time.time()
        self._task: asyncio.Task[None] | None = None

    # ----- configuration -------------------------------------------------
    def env_managed(self) -> bool:
        return bool(
            os.getenv("MRK_DOKPLOY_URL", "").strip()
            and os.getenv("MRK_DOKPLOY_API_KEY_FILE", "").strip()
        )

    def _panel_file(self) -> dict[str, Any] | None:
        try:
            if not self.config_path.exists():
                return None
            payload = json.loads(self.config_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            LOGGER.warning("dokploy config file is unreadable; treating as unconfigured")
            return None
        return payload if isinstance(payload, dict) else None

    def tunable(self, key: str) -> float:
        spec = next(item for item in TUNABLES if item[0] == key)
        _key, env_name, default, low, high = spec
        value = _env_number(env_name, default, low, high)
        if not self.env_managed():
            stored = self._panel_file() or {}
            candidate = stored.get(key)
            if isinstance(candidate, int | float) and not isinstance(candidate, bool):
                value = min(max(float(candidate), low), high)
        return value

    def resolve(self) -> tuple[str | None, str | None, str | None]:
        """Return (source, url, api_key). Invalid config resolves to a missing key."""
        if self.env_managed():
            url_text = os.getenv("MRK_DOKPLOY_URL", "").strip()
            try:
                url = validate_dokploy_url(url_text, allow_loopback=self.allow_loopback)
                key = validate_api_key(
                    Path(os.getenv("MRK_DOKPLOY_API_KEY_FILE", "").strip()).read_text(
                        encoding="utf-8"
                    )
                )
            except (OSError, ValueError, UnicodeDecodeError) as exc:
                self.last_error = f"environment configuration invalid: {type(exc).__name__}"
                return "env", None, None
            return "env", url, key
        stored = self._panel_file()
        if not stored or not isinstance(stored.get("url"), str):
            return None, None, None
        key: str | None = None
        reference = stored.get("secret_ref")
        if isinstance(reference, str):
            try:
                key = self.ctx.secret_store.get(reference)["api_key"]
            except (KeyError, ValueError):
                key = None
        return "panel", stored["url"], key

    def connection(self) -> Connection:
        source, url, key = self.resolve()
        if source is None:
            raise DokployError("dokploy_not_configured", 409, "Dokploy is not configured")
        if url is None or key is None:
            raise DokployError(
                "dokploy_auth_failed", 502, "The Dokploy URL or API key is unavailable"
            )
        self.client.set_rate(self.tunable("rate_limit_per_second"))
        return Connection(url=url, api_key=key)

    def _write_panel(self, payload: dict[str, Any]) -> None:
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.config_path.with_name(f".{CONFIG_FILE}.{secrets.token_hex(4)}.tmp")
        temporary.write_text(json.dumps(payload) + "\n", encoding="utf-8")
        temporary.chmod(0o600)
        os.replace(temporary, self.config_path)

    def save(self, body: DokployConfigRequest) -> None:
        url = validate_dokploy_url(body.url, allow_loopback=self.allow_loopback)
        stored = self._panel_file() or {}
        reference = stored.get("secret_ref") if isinstance(stored.get("secret_ref"), str) else None
        if body.api_key is not None:
            key = validate_api_key(body.api_key)
            reference, _ = self.ctx.secret_store.replace(reference, {"api_key": key})
        elif reference is None or stored.get("url") != url:
            # Never forward a stored key to a different panel URL without re-entry.
            raise DokployError("dokploy_api_key_required", 422, "A Dokploy API key is required")
        else:
            try:
                self.ctx.secret_store.get(reference)
            except (KeyError, ValueError) as exc:
                raise DokployError(
                    "dokploy_api_key_required", 422, "A Dokploy API key is required"
                ) from exc
        payload: dict[str, Any] = {
            "url": url,
            "secret_ref": reference,
            "updated_at": int(time.time()),
        }
        for key_name, *_rest in TUNABLES:
            value = getattr(body, key_name)
            if value is None:
                value = stored.get(key_name)
            if value is not None:
                payload[key_name] = value
        self._write_panel(payload)
        self.reset()

    def disconnect(self) -> None:
        stored = self._panel_file() or {}
        reference = stored.get("secret_ref")
        if isinstance(reference, str):
            self.ctx.secret_store.delete(reference)
        self.config_path.unlink(missing_ok=True)
        self.reset()

    def reset(self) -> None:
        self.cache.clear()
        self.domains.clear()
        self.features.clear()
        self.reachable = None
        self.last_checked_at = None
        self.last_error = None
        self.version = None
        self.seen_failures.clear()
        self.failures_seeded = False
        self.status_failed.clear()

    def config_view(self) -> dict[str, Any]:
        source, url, key = self.resolve()
        configured = source is not None and url is not None
        return {
            "configured": configured,
            "url": url,
            # Base of the Dokploy web panel (same as url: a trailing /api is
            # stripped on save); the UI builds "open in Dokploy" links from it.
            "panel_url": url if configured else None,
            "source": source,
            "last_error": self.last_error if source is not None else None,
            "api_key_configured": key is not None,
            "reachable": self.reachable if configured else None,
            "last_checked_at": self.last_checked_at,
            "version": self.version,
            "rate_limit_per_second": self.tunable("rate_limit_per_second"),
            "poll_interval_seconds": int(self.tunable("poll_interval_seconds")),
            "cache_seconds": int(self.tunable("cache_seconds")),
        }

    # ----- calls ---------------------------------------------------------
    async def call(self, procedure: str, **kwargs: Any) -> Any:
        connection = self.connection()
        try:
            result = await self.client.call(connection, procedure, **kwargs)
        except DokployError as exc:
            if exc.code in {"dokploy_unreachable", "dokploy_auth_failed"}:
                self._mark(False, exc.message, exc.code)
            raise
        self._mark(True)
        return result

    def _mark(self, ok: bool, message: str | None = None, code: str | None = None) -> None:
        previous = self.reachable
        self.reachable = ok
        self.last_checked_at = time.time()
        self.last_error = None if ok else message
        if ok and previous is False:
            self.ctx.events.publish(
                Event(
                    type="dokploy.reachable",
                    severity="info",
                    title="Dokploy is reachable again",
                    module=MODULE_NAME,
                    dedupe_key=REACHABILITY_DEDUPE_KEY,
                )
            )
        elif not ok and previous is not False:
            self.ctx.events.publish(
                Event(
                    type="dokploy.unreachable",
                    severity="error",
                    title="Dokploy is unreachable",
                    message=message or "",
                    module=MODULE_NAME,
                    dedupe_key=REACHABILITY_DEDUPE_KEY,
                    details={"error_code": code},
                )
            )

    async def _cached(self, key: str, loader: Any) -> Any:
        hit = self.cache.get(key)
        if hit is not None:
            return hit
        # Single flight: concurrent callers for the same key wait for one load
        # instead of each walking Dokploy (protects Dokploy from bursts).
        locks = self.__dict__.setdefault("_cache_locks", {})
        lock = locks.setdefault(key, asyncio.Lock())
        async with lock:
            hit = self.cache.get(key)
            if hit is not None:
                return hit
            value = await loader()
            self.cache.set(key, value, self.tunable("cache_seconds"))
            return value

    async def _optional(self, feature: str, procedure: str, **kwargs: Any) -> Any | None:
        """Call a procedure newer Dokploy releases have; None if this one lacks it."""
        if self.features.get(feature) is False:
            return None
        try:
            result = await self.call(procedure, **kwargs)
        except DokployError as exc:
            if exc.procedure_missing:
                self.features[feature] = False
                return None
            raise
        self.features[feature] = True
        return result

    async def test(self, url: str | None = None, api_key: str | None = None) -> dict[str, Any]:
        """Check URL + key with settings.getDokployVersion (falls back to project.all)."""
        candidate = url is not None or api_key is not None
        started = time.perf_counter()
        try:
            if candidate:
                _source, current_url, current_key = self.resolve()
                target_url = (
                    validate_dokploy_url(url, allow_loopback=self.allow_loopback)
                    if url is not None
                    else current_url
                )
                if api_key is None and target_url != current_url:
                    raise DokployError(
                        "dokploy_api_key_required",
                        422,
                        "An API key is required to test a different Dokploy URL",
                    )
                target_key = validate_api_key(api_key) if api_key is not None else current_key
                if target_url is None or target_key is None:
                    raise DokployError(
                        "dokploy_not_configured", 409, "A Dokploy URL and API key are required"
                    )
                connection = Connection(url=target_url, api_key=target_key)
                version = await self._version(connection)
            else:
                version = await self._version(self.connection(), track=True)
        except DokployError as exc:
            if exc.code in {"dokploy_not_configured", "dokploy_api_key_required"}:
                raise
            latency = round((time.perf_counter() - started) * 1000, 1)
            return {"ok": False, "latency_ms": latency, "error_code": exc.code}
        latency = round((time.perf_counter() - started) * 1000, 1)
        if not candidate:
            self.version = version
        result: dict[str, Any] = {"ok": True, "latency_ms": latency}
        if version:
            result["version"] = version
        return result

    async def _version(self, connection: Connection, track: bool = False) -> str | None:
        async def run(procedure: str) -> Any:
            if track:
                return await self.call(procedure)
            return await self.client.call(connection, procedure)

        try:
            value = await run("settings.getDokployVersion")
        except DokployError as exc:
            if not exc.procedure_missing:
                raise
            await run("project.all")
            return None
        return value[:64] if isinstance(value, str) else None

    # ----- domains (slow-changing, fetched within a small budget) -------
    def _fresh_domains(self, key: tuple[str, str]) -> list[str] | None:
        item = self.domains.get(key)
        if item is None or time.monotonic() - item[0] > DOMAIN_TTL_SECONDS:
            return None
        return item[1]

    async def _fill_domains(self, keys: list[tuple[str, str]], budget: int) -> bool:
        """Fetch domains for up to ``budget`` services; True if all are now known."""
        missing = [key for key in keys if self._fresh_domains(key) is None]
        for key in missing[:budget]:
            service_type, service_id = key
            procedure, param = (
                ("domain.byApplicationId", "applicationId")
                if service_type == "application"
                else ("domain.byComposeId", "composeId")
            )
            try:
                payload = await self.call(procedure, params={param: service_id})
            except DokployError as exc:
                if exc.code == "dokploy_rate_limited":
                    return False
                if exc.code in {"dokploy_unreachable", "dokploy_auth_failed"}:
                    raise
                payload = []
            self.domains[key] = (time.monotonic(), norm.domain_strings(payload))
        return len(missing) <= budget

    # ----- projects / services --------------------------------------------
    async def recent_deployments(self) -> list[dict[str, Any]] | None:
        async def load() -> Any:
            payload = await self._optional("allCentralized", "deployment.allCentralized")
            return {"items": payload if isinstance(payload, list) else None}

        result = await self._cached("deployments:recent", load)
        return result["items"]

    async def _projects_raw(self) -> list[dict[str, Any]]:
        async def load() -> Any:
            payload = await self.call("project.all")
            return {"items": payload if isinstance(payload, list) else []}

        return (await self._cached("projects:all", load))["items"]

    def panel_url(self) -> str | None:
        source, url, _key = self.resolve()
        return url if source is not None else None

    @staticmethod
    def service_url(panel_url: str, ref: dict[str, Any]) -> str:
        """Deep link to a service page in the Dokploy panel (best effort)."""
        path = f"/dashboard/project/{quote(str(ref['project_id']), safe='')}"
        if ref.get("environment_id"):
            path += f"/environment/{quote(str(ref['environment_id']), safe='')}"
        path += f"/services/{ref['type']}/{quote(str(ref['id']), safe='')}"
        return panel_url.rstrip("/") + path

    async def app_index(self) -> dict[str, dict[str, Any]]:
        """Map Dokploy ``appName`` -> {type, id, name, project_id, environment_id}.

        project.all does not always carry ``appName``; project.one is asked for
        those projects (bounded). Only these whitelisted ids leave this method.
        """

        async def load() -> Any:
            raw = await self._projects_raw()
            index: dict[str, dict[str, Any]] = {}
            incomplete = [
                project for project in raw if not norm.app_name_index(project, index)
            ]
            for project in incomplete[:APP_INDEX_PROJECT_BUDGET]:
                project_id = project.get("projectId")
                try:
                    one = await self.call("project.one", params={"projectId": project_id})
                except DokployError as exc:
                    if exc.code in {"dokploy_unreachable", "dokploy_auth_failed"}:
                        raise
                    continue
                if isinstance(one, dict):
                    norm.app_name_index({**one, "projectId": project_id}, index)
            return {"items": index}

        return (await self._cached("projects:app-index", load))["items"]

    async def projects(self) -> dict[str, Any]:
        async def build() -> Any:
            raw = await self._projects_raw()
            details: dict[str, dict[str, Any]] = {}
            for project in raw:
                project_id = project.get("projectId") if isinstance(project, dict) else None
                if isinstance(project_id, str) and norm.services_missing_names(project):
                    try:
                        one = await self.call("project.one", params={"projectId": project_id})
                    except DokployError as exc:
                        if exc.code in {"dokploy_unreachable", "dokploy_auth_failed"}:
                            raise
                        continue
                    if isinstance(one, dict):
                        details[project_id] = one
            try:
                recent = await self.recent_deployments()
            except DokployError as exc:
                if exc.code == "dokploy_unreachable":
                    raise
                recent = None
            tree = norm.project_tree(raw, details=details, latest=norm.latest_by_service(recent))
            keys = [
                (service["type"], service["id"])
                for project in tree
                for service in project["services"]
                if service["type"] in norm.DEPLOYABLE_TYPES
            ]
            complete = await self._fill_domains(keys, DOMAIN_FETCH_BUDGET)
            for project in tree:
                for service in project["services"]:
                    known = self._fresh_domains((service["type"], service["id"]))
                    service["domains"] = list(known or [])
            return {"items": tree, "partial": not complete}

        return await self._cached("projects:tree", build)

    @staticmethod
    def check_ref(service_type: str, service_id: str) -> None:
        if service_type not in norm.SERVICE_TYPES:
            raise DokployError("invalid_service_type", 422, "Unknown Dokploy service type")
        if not SERVICE_ID_RE.fullmatch(service_id):
            raise DokployError("invalid_service_id", 422, "Invalid Dokploy service id")

    async def service(self, service_type: str, service_id: str) -> dict[str, Any]:
        self.check_ref(service_type, service_id)
        router, id_field, _status = norm.SERVICE_TYPES[service_type]

        async def load() -> Any:
            try:
                payload = await self.call(f"{router}.one", params={id_field: service_id})
            except DokployError as exc:
                if exc.code == "dokploy_not_found":
                    raise DokployError(
                        "dokploy_service_not_found", 404, "Dokploy service not found"
                    ) from None
                raise
            if not isinstance(payload, dict):
                raise DokployError("dokploy_service_not_found", 404, "Dokploy service not found")
            detail = norm.service_detail(service_type, service_id, payload)
            if service_type in norm.DEPLOYABLE_TYPES:
                self.domains[(service_type, service_id)] = (time.monotonic(), detail["domains"])
            return detail

        return await self._cached(f"service:{service_type}:{service_id}", load)

    async def action(self, service_type: str, service_id: str, action: str) -> None:
        self.check_ref(service_type, service_id)
        if action not in ACTIONS:
            raise DokployError("invalid_action", 422, "Unknown Dokploy action")
        router, id_field, _status = norm.SERVICE_TYPES[service_type]
        body: dict[str, Any] = {id_field: service_id}
        procedure = f"{router}.{action}"
        if service_type in norm.DEPLOYABLE_TYPES and action in {"deploy", "redeploy"}:
            body["title"] = "Manual deployment from Pishkar" if action == "deploy" else (
                "Redeploy from Pishkar"
            )
        elif service_type in norm.DATABASE_TYPES and action == "redeploy":
            # Databases have no redeploy; Dokploy's "reload" restarts the service
            # (stop + start). "rebuild" would recreate data and is never used.
            detail = await self.service(service_type, service_id)
            if not detail.get("app_name"):
                raise DokployError("dokploy_rejected", 409, "Dokploy service has no app name")
            procedure = f"{router}.reload"
            body["appName"] = detail["app_name"]
        try:
            await self.call(procedure, body=body, mutation=True, parse=False)
        except DokployError as exc:
            if exc.code == "dokploy_not_found":
                raise DokployError(
                    "dokploy_service_not_found", 404, "Dokploy service not found"
                ) from None
            raise
        finally:
            self.cache.clear()

    async def deployment_log(self, deployment_id: str, tail: int) -> dict[str, Any]:
        if not SERVICE_ID_RE.fullmatch(deployment_id):
            raise DokployError("invalid_deployment_id", 422, "Invalid Dokploy deployment id")
        if self.features.get("readLogs") is False:
            return {"available": False, "lines": [], "truncated": False}
        try:
            text = await self.call(
                "deployment.readLogs", params={"deploymentId": deployment_id, "tail": tail}
            )
        except DokployError as exc:
            if exc.procedure_missing:
                self.features["readLogs"] = False
                return {"available": False, "lines": [], "truncated": False}
            if exc.code == "dokploy_not_found":
                raise DokployError(
                    "dokploy_deployment_not_found", 404, "Dokploy deployment not found"
                ) from None
            raise
        self.features["readLogs"] = True
        lines = text.splitlines() if isinstance(text, str) else []
        truncated = len(lines) > MAX_LOG_LINES
        lines = [redact_text(line[:4000]) for line in lines[-MAX_LOG_LINES:]]
        return {"available": True, "lines": lines, "truncated": truncated}

    # ----- background poll -------------------------------------------------
    def _remember_failure(self, deployment_id: str) -> bool:
        if deployment_id in self.seen_failures:
            return False
        self.seen_failures[deployment_id] = None
        while len(self.seen_failures) > MAX_SEEN_FAILURES:
            self.seen_failures.popitem(last=False)
        return True

    def _publish_failure(self, item: dict[str, Any]) -> None:
        service_type = "application" if item.get("applicationId") else "compose"
        service = item.get(service_type) if isinstance(item.get(service_type), dict) else {}
        service_id = item.get("applicationId") or item.get("composeId")
        name = service.get("name") or service_id or "unknown service"
        project = None
        environment = service.get("environment")
        if isinstance(environment, dict) and isinstance(environment.get("project"), dict):
            project = environment["project"].get("name")
        summary = norm.deployment(item)
        self.ctx.events.publish(
            Event(
                type="dokploy.deploy_failed",
                severity="error",
                title=f"Dokploy deployment failed: {str(name)[:120]}",
                message=summary["error_message"] or summary["title"] or "",
                module=MODULE_NAME,
                dedupe_key=f"dokploy.deploy_failed:{summary['id']}",
                details={
                    "deployment_id": summary["id"],
                    "service_type": service_type,
                    "service_id": service_id,
                    "service_name": str(name)[:255],
                    "project": project,
                    "created_at": summary["created_at"],
                },
            )
        )

    async def poll_once(self, interval: float) -> None:
        recent = await self.recent_deployments()
        if recent is None:
            await self._poll_statuses()
            return
        horizon = time.time() - max(interval * 2, 120.0)
        for item in sorted(recent, key=lambda d: norm.parse_time(d.get("createdAt")) or 0):
            if not isinstance(item, dict) or item.get("status") != "error":
                continue
            deployment_id = item.get("deploymentId")
            if not isinstance(deployment_id, str) or not self._remember_failure(deployment_id):
                continue
            stamp = norm.parse_time(item.get("finishedAt")) or norm.parse_time(
                item.get("createdAt")
            )
            if self.failures_seeded or (stamp is not None and stamp >= horizon):
                self._publish_failure(item)
        self.failures_seeded = True

    async def _poll_statuses(self) -> None:
        """Older Dokploy (no deployment.allCentralized): watch service status instead."""
        tree = norm.project_tree(await self._projects_raw())
        current: set[tuple[str, str]] = set()
        for project in tree:
            for service in project["services"]:
                if service["type"] in norm.DEPLOYABLE_TYPES and service["status"] == "error":
                    key = (service["type"], service["id"])
                    current.add(key)
                    if key not in self.status_failed and self.failures_seeded:
                        self.ctx.events.publish(
                            Event(
                                type="dokploy.deploy_failed",
                                severity="error",
                                title=f"Dokploy deployment failed: {service['name']}",
                                module=MODULE_NAME,
                                dedupe_key=f"dokploy.deploy_failed:{key[0]}:{key[1]}",
                                details={
                                    "service_type": key[0],
                                    "service_id": key[1],
                                    "service_name": service["name"],
                                    "project": project["name"],
                                },
                            )
                        )
        self.status_failed = current
        self.failures_seeded = True

    async def _loop(self) -> None:
        while True:
            interval = self.tunable("poll_interval_seconds")
            if interval > 0:
                try:
                    source, url, _key = self.resolve()
                    if source is not None and url is not None:
                        await self.poll_once(interval)
                except asyncio.CancelledError:
                    raise
                except DokployError as exc:
                    LOGGER.info("dokploy poll failed", extra={"error_code": exc.code})
                except Exception:
                    LOGGER.exception("dokploy poll failed")
            await asyncio.sleep(max(interval, 15.0) if interval > 0 else 60.0)

    async def start(self) -> None:
        self._task = asyncio.create_task(self._loop(), name="mrk-dokploy-poll")

    async def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None


ACTIVE_SERVICE: DokployService | None = None


def register(ctx: ModuleContext) -> None:
    global ACTIVE_SERVICE
    service = DokployService(ctx)
    ACTIVE_SERVICE = service
    router = APIRouter(prefix="/api/v1/dokploy", tags=["dokploy"])

    def failure(exc: DokployError):
        return ctx.error_payload(exc.code, exc.message, exc.status_code)

    async def audit(principal: Any, action: str, object_id: str, result: str = "success") -> None:
        await asyncio.to_thread(
            ctx.audit, principal.user_id, action, "dokploy", object_id, result
        )

    def env_locked():
        return ctx.error_payload(
            "dokploy_managed_by_environment",
            "Dokploy is configured by environment variables",
            409,
        )

    @router.get("/config")
    async def get_config(request: Request):
        ctx.require_principal(request, "dokploy:read")
        return service.config_view()

    @router.put("/config")
    async def put_config(request: Request, body: DokployConfigRequest):
        principal = ctx.require_principal(request, "dokploy:write")
        ctx.require_csrf(request, principal)
        if service.env_managed():
            return env_locked()
        try:
            await asyncio.to_thread(service.save, body)
        except DokployError as exc:
            await audit(principal, "dokploy.config.update", "dokploy", "failure")
            return failure(exc)
        except ValueError as exc:
            message = str(exc)
            code = "invalid_dokploy_api_key" if "key" in message else "invalid_dokploy_url"
            return ctx.error_payload(code, message, 422)
        await audit(principal, "dokploy.config.update", "dokploy")
        return service.config_view()

    @router.delete("/config")
    async def delete_config(request: Request, body: ConfirmationRequest):
        principal = ctx.require_principal(request, "dokploy:write")
        ctx.require_csrf(request, principal)
        if body.confirmation != "DISCONNECT":
            return ctx.error_payload(
                "confirmation_required", 'Type "DISCONNECT" to confirm', 422
            )
        if service.env_managed():
            return env_locked()
        await asyncio.to_thread(service.disconnect)
        await audit(principal, "dokploy.disconnect", "dokploy")
        return service.config_view()

    @router.post("/test")
    async def test_connection(request: Request):
        principal = ctx.require_principal(request, "dokploy:write")
        ctx.require_csrf(request, principal)
        raw = await request.body()
        try:
            body = DokployTestRequest.model_validate_json(raw) if raw.strip() else None
        except ValueError:
            return ctx.error_payload("validation_error", "Invalid request body", 422)
        try:
            result = await service.test(
                body.url if body else None, body.api_key if body else None
            )
        except DokployError as exc:
            return failure(exc)
        except ValueError as exc:
            message = str(exc)
            code = "invalid_dokploy_api_key" if "key" in message else "invalid_dokploy_url"
            return ctx.error_payload(code, message, 422)
        await audit(
            principal, "dokploy.test", "dokploy", "success" if result["ok"] else "failure"
        )
        return result

    @router.get("/projects")
    async def list_projects(request: Request):
        ctx.require_principal(request, "dokploy:read")
        try:
            return await service.projects()
        except DokployError as exc:
            return failure(exc)

    @router.get("/services/{service_type}/{service_id}")
    async def get_service(service_type: str, service_id: str, request: Request):
        ctx.require_principal(request, "dokploy:read")
        try:
            return await service.service(service_type, service_id)
        except DokployError as exc:
            return failure(exc)

    @router.post("/services/{service_type}/{service_id}/{action}")
    async def service_action(service_type: str, service_id: str, action: str, request: Request):
        principal = ctx.require_principal(request, "dokploy:deploy")
        ctx.require_csrf(request, principal)
        object_id = f"{service_type}:{service_id}"[:255]
        raw = await request.body()
        try:
            body = ConfirmationRequest.model_validate_json(raw) if raw.strip() else None
        except ValueError:
            return ctx.error_payload("validation_error", "Invalid request body", 422)
        try:
            service.check_ref(service_type, service_id)
            if action not in ACTIONS:
                raise DokployError("invalid_action", 422, "Unknown Dokploy action")
            if action == "stop":
                detail = await service.service(service_type, service_id)
                if body is None or body.confirmation != detail["name"]:
                    await audit(principal, "dokploy.service.stop", object_id, "failure")
                    return ctx.error_payload(
                        "confirmation_required",
                        "Type the service name to confirm stopping it",
                        422,
                    )
            await service.action(service_type, service_id, action)
        except DokployError as exc:
            if exc.status_code != 422:
                await audit(principal, f"dokploy.service.{action}", object_id, "failure")
            return failure(exc)
        await audit(principal, f"dokploy.service.{action}", object_id)
        return {"ok": True}

    @router.get("/deployments/{deployment_id}/log")
    async def deployment_log(deployment_id: str, request: Request, tail: int = 500):
        principal = ctx.require_principal(request, "dokploy:read")
        try:
            result = await service.deployment_log(deployment_id, min(max(tail, 1), 10000))
        except DokployError as exc:
            return failure(exc)
        if result["available"]:
            await audit(principal, "dokploy.deployment.log.view", deployment_id)
        return result

    ctx.routers.append(router)
    ctx.start_hooks.append(service.start)
    ctx.stop_hooks.append(service.stop)
