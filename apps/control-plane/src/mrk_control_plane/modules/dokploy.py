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
import contextvars
import importlib
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
# Deployment failures already announced, so a restart does not announce them again.
STATE_FILE = "dokploy-state.json"
REACHABILITY_DEDUPE_KEY = "dokploy.reachability"
SERVICE_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
ACTIONS = ("deploy", "redeploy", "start", "stop")
DOMAIN_TTL_SECONDS = 300.0
DOMAIN_FETCH_BUDGET = 6
MAX_SEEN_FAILURES = 2000
MAX_LOG_LINES = 5000
# project.one calls spent per (cached) appName index build; the rest wait for the next
# build (project.one answers are cached for PROJECT_ONE_TTL_SECONDS meanwhile).
APP_INDEX_PROJECT_BUDGET = 8
PROJECT_ONE_TTL_SECONDS = 180.0
# Consecutive connection failures before Dokploy counts as unreachable (and is announced).
UNREACHABLE_AFTER = 2
# Procedures that check the connection itself: an auth failure here means the key is bad.
PROBE_PROCEDURES = frozenset({"settings.getDokployVersion", "project.all"})
# Docker labels naming a Dokploy appName, most specific first: a Compose of composeType
# "stack" runs as `docker stack deploy <appName>`, a plain Compose as project <appName>,
# an Application as swarm service <appName>.
APP_NAME_LABELS = (
    "com.docker.stack.namespace",
    "com.docker.compose.project",
    "com.docker.swarm.service.name",
)

# Set while the poller runs, so its calls yield the request budget to page loads.
_BACKGROUND: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "mrk_dokploy_background", default=False
)


def app_name_candidates(labels: Any) -> list[str]:
    """The Dokploy appNames a container's labels may carry, in the order to try them."""
    if not isinstance(labels, dict):
        return []
    names: list[str] = []
    for key in APP_NAME_LABELS:
        value = labels.get(key)
        if isinstance(value, str) and value and value not in names:
            names.append(value)
    swarm = labels.get("com.docker.swarm.service.name")
    if isinstance(swarm, str) and "_" in swarm:
        # A stack service is "<namespace>_<service>" (older agents lack the namespace label).
        prefix = swarm.rsplit("_", 1)[0]
        if prefix and prefix not in names:
            names.append(prefix)
    return names


def ref_for_labels(labels: Any, index: dict[str, dict[str, Any]]) -> dict[str, Any] | None:
    """The Dokploy service ref (from :meth:`DokployService.app_index`) for these labels."""
    for name in app_name_candidates(labels):
        ref = index.get(name)
        if ref is not None:
            return ref
    return None


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


def _fatal(exc: DokployError) -> bool:
    """Whether a failure inside a multi-call load must abort it (vs. skip one item)."""
    return exc.connection_failure or exc.code == "dokploy_auth_failed"


class DokployConfigRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    url: str = Field(min_length=8, max_length=2048)
    api_key: str | None = Field(default=None, min_length=16, max_length=512)
    # The address people open Dokploy at, when ``url`` is an internal one
    # (http://dokploy:3000). Used only for "open in Dokploy" links; "" clears it.
    public_url: str | None = Field(default=None, max_length=2048)
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
        self.last_error_code: str | None = None
        self.failure_streak = 0
        self.down_announced = False
        self.version: str | None = None
        self.state_path = ctx.data_dir / "control-plane" / STATE_FILE
        self.seen_failures: OrderedDict[str, None] = OrderedDict()
        self.failures_seeded = False
        self.status_failed: set[tuple[str, str]] = set()
        self.status_seeded = False
        self._state_dirty = False
        self._load_state()
        self.started_at = time.time()
        self._task: asyncio.Task[None] | None = None

    # ----- announced failures (survive restarts) ---------------------------
    def _load_state(self) -> None:
        try:
            if not self.state_path.exists():
                return
            payload = json.loads(self.state_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            LOGGER.warning("dokploy state file is unreadable; starting fresh")
            return
        if not isinstance(payload, dict):
            return
        seen = payload.get("seen_failures")
        for item in seen[-MAX_SEEN_FAILURES:] if isinstance(seen, list) else []:
            if isinstance(item, str) and item:
                self.seen_failures[item[:128]] = None
        failed = payload.get("status_failed")
        for item in failed if isinstance(failed, list) else []:
            if (isinstance(item, list) and len(item) == 2
                    and all(isinstance(part, str) for part in item)):
                self.status_failed.add((item[0][:32], item[1][:64]))
        # A saved state means the "what failed before" baseline is already known.
        self.failures_seeded = bool(payload.get("seeded"))
        self.status_seeded = bool(payload.get("status_seeded"))

    def _save_state(self) -> None:
        payload = {
            "seeded": self.failures_seeded,
            "status_seeded": self.status_seeded,
            "seen_failures": list(self.seen_failures),
            "status_failed": sorted([list(item) for item in self.status_failed]),
        }
        try:
            self.state_path.parent.mkdir(parents=True, exist_ok=True)
            temporary = self.state_path.with_name(f".{STATE_FILE}.{secrets.token_hex(4)}.tmp")
            temporary.write_text(json.dumps(payload) + "\n", encoding="utf-8")
            temporary.chmod(0o600)
            os.replace(temporary, self.state_path)
        except OSError:
            LOGGER.warning("dokploy state file could not be written")

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
        if body.public_url is None:
            if isinstance(stored.get("public_url"), str):
                payload["public_url"] = stored["public_url"]
        elif body.public_url.strip():
            payload["public_url"] = self._validate_public_url(body.public_url)
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
        # Another Dokploy may be connected next: its deployment ids start a new history.
        self.seen_failures.clear()
        self.status_failed.clear()
        self.failures_seeded = False
        self.status_seeded = False
        try:
            self.state_path.unlink(missing_ok=True)
        except OSError:
            LOGGER.warning("dokploy state file could not be removed")

    def reset(self) -> None:
        """Forget cached answers and connection health (config saved, reset or replaced).

        Announced deployment failures are kept: the same Dokploy keeps its deployment ids,
        and announcing them again after re-saving the settings would only be noise.
        """
        self.cache.clear()
        self.domains.clear()
        self.features.clear()
        self.reachable = None
        self.last_checked_at = None
        self.last_error = None
        self.last_error_code = None
        self.failure_streak = 0
        self.down_announced = False
        self.version = None
        self._invalidate_routing()

    @staticmethod
    def _invalidate_routing() -> None:
        """Let domain routing re-detect "inside Dokploy" after the connection changed."""
        try:
            services = importlib.import_module(f"{__package__}.services")
            active = getattr(services, "ACTIVE_SERVICE", None)
            changed = getattr(active, "on_dokploy_changed", None)
            if callable(changed):
                changed()  # forgets the detection and reads Dokploy's domains back soon
                return
            routing = getattr(active, "routing", None)
            invalidate = getattr(routing, "invalidate", None)
            if callable(invalidate):
                invalidate()
        except Exception:  # noqa: BLE001 - a stale detection is refreshed on its own later
            LOGGER.info("domain routing invalidation skipped", exc_info=True)

    def _validate_public_url(self, value: str) -> str:
        # Only a link for the browser, so loopback is fine here; credentials, queries and
        # metadata addresses are still refused.
        try:
            return validate_dokploy_url(value, allow_loopback=True)
        except ValueError as exc:
            raise ValueError(f"Public {exc}") from None

    def public_url(self) -> str | None:
        """The address people open Dokploy at (for links), if one is set."""
        # Panel-saved only for now; an env-managed setup links to its API URL.
        stored = None if self.env_managed() else (self._panel_file() or {}).get("public_url")
        raw = stored.strip() if isinstance(stored, str) else ""
        if not raw:
            return None
        try:
            return self._validate_public_url(raw)
        except ValueError:
            LOGGER.warning("ignoring an invalid public Dokploy URL")
            return None

    def status_view(self) -> dict[str, Any]:
        """Connection health as of the latest call (sent with every /projects answer)."""
        return {
            "reachable": self.reachable,
            "last_error": self.last_error,
            "last_error_code": self.last_error_code,
            "last_checked_at": self.last_checked_at,
        }

    def config_view(self) -> dict[str, Any]:
        source, url, key = self.resolve()
        configured = source is not None and url is not None
        public = self.public_url() if configured else None
        return {
            "configured": configured,
            "url": url,
            "public_url": public,
            # Base of the Dokploy web panel for "open in Dokploy" links: the public
            # address when one is set, else the API address (a trailing /api is
            # stripped on save).
            "panel_url": (public or url) if configured else None,
            "source": source,
            "last_error": self.last_error if source is not None else None,
            "last_error_code": self.last_error_code if source is not None else None,
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
        probe = bool(kwargs.pop("probe", False)) or procedure in PROBE_PROCEDURES
        kwargs.setdefault("background", _BACKGROUND.get())
        try:
            result = await self.client.call(connection, procedure, probe=probe, **kwargs)
        except DokployError as exc:
            self._record_failure(exc, probe)
            raise
        self._mark(True)
        return result

    def _record_failure(self, exc: DokployError, probe: bool) -> None:
        """Decide what one failed call says about the connection as a whole."""
        if exc.connection_failure or (
            probe and exc.code in {"dokploy_auth_failed", "dokploy_forbidden"}
        ):
            self._mark(False, exc.message, exc.code)
        elif exc.upstream_status is not None and exc.code not in {
            "dokploy_auth_failed", "dokploy_forbidden"
        }:
            # Dokploy answered (404, 400, 500 ...): the connection itself works.
            self._mark(True)
        # Otherwise (MRK's own rate limit, a refused item): nothing new is known.

    def _mark(self, ok: bool, message: str | None = None, code: str | None = None) -> None:
        self.last_checked_at = time.time()
        if ok:
            previous = self.reachable
            self.failure_streak = 0
            self.reachable = True
            self.last_error = None
            self.last_error_code = None
            if previous is not True:
                self._invalidate_routing()
            if self.down_announced:
                self.down_announced = False
                self.ctx.events.publish(
                    Event(
                        type="dokploy.reachable",
                        severity="info",
                        title="Dokploy is reachable again",
                        module=MODULE_NAME,
                        dedupe_key=REACHABILITY_DEDUPE_KEY,
                    )
                )
            return
        self.failure_streak += 1
        self.last_error = message
        self.last_error_code = code
        if self.failure_streak < UNREACHABLE_AFTER:
            return  # one blip (a restart, a slow answer) is not an outage
        self.reachable = False
        if not self.down_announced:
            self.down_announced = True
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
            return {
                "ok": False,
                "latency_ms": latency,
                "error_code": exc.code,
                # Dokploy's own reason (redacted), shown under "technical details".
                "message": exc.message,
            }
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
                return await self.call(procedure, probe=True)
            return await self.client.call(connection, procedure, probe=True)

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
                if _fatal(exc):
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
        """Base for "open in Dokploy" links: the public address if set, else the API one."""
        source, url, _key = self.resolve()
        if source is None or url is None:
            return None
        return self.public_url() or url

    @staticmethod
    def project_url(panel_url: str, project_id: str, environment_id: str | None) -> str:
        """Deep link to a project; Dokploy >= 0.25 routes projects by environment."""
        path = f"/dashboard/project/{quote(str(project_id), safe='')}"
        if environment_id:
            path += f"/environment/{quote(str(environment_id), safe='')}"
        return panel_url.rstrip("/") + path

    @staticmethod
    def service_url(panel_url: str, ref: dict[str, Any]) -> str:
        """Deep link to a service page in the Dokploy panel.

        Dokploy >= 0.25: ``/dashboard/project/<pid>/environment/<eid>/services/<type>/<id>``;
        older releases have no environment segment.
        """
        base = DokployService.project_url(
            panel_url, str(ref["project_id"]), ref.get("environment_id")
        )
        return f"{base}/services/{ref['type']}/{quote(str(ref['id']), safe='')}"

    async def project_detail(self, project_id: str) -> dict[str, Any] | None:
        """project.one reduced to names/appNames/statuses, cached per project.

        The full answer carries project/environment variables; only the whitelisted
        service fields are kept (and cached) here. None when Dokploy refused this one.
        """
        if not SERVICE_ID_RE.fullmatch(project_id):
            return None
        key = f"project-one:{project_id}"
        hit = self.cache.get(key)
        if hit is not None:
            return hit["item"]
        try:
            one = await self.call("project.one", params={"projectId": project_id})
        except DokployError as exc:
            if _fatal(exc):
                raise
            if exc.code != "dokploy_rate_limited":
                # Refused for this key: do not ask again on every page load.
                self.cache.set(key, {"item": None}, 60.0)
            return None
        item = norm.project_outline({**one, "projectId": project_id}) if isinstance(
            one, dict
        ) else None
        del one
        self.cache.set(key, {"item": item}, PROJECT_ONE_TTL_SECONDS)
        return item

    async def app_index(self) -> dict[str, dict[str, Any]]:
        """Map Dokploy ``appName`` -> {type, id, name, project_id, environment_id}.

        project.all does not always carry ``appName``; project.one is asked for
        those projects (bounded, cached). Only these whitelisted ids leave this method.
        """

        async def load() -> Any:
            raw = await self._projects_raw()
            index: dict[str, dict[str, Any]] = {}
            incomplete = [
                project for project in raw if not norm.app_name_index(project, index)
            ]
            for project in incomplete[:APP_INDEX_PROJECT_BUDGET]:
                project_id = project.get("projectId")
                if not isinstance(project_id, str):
                    continue
                one = await self.project_detail(project_id)
                if one is not None:
                    norm.app_name_index(one, index)
            return {"items": index}

        return (await self._cached("projects:app-index", load))["items"]

    def ref_for_labels(
        self, labels: Any, index: dict[str, dict[str, Any]]
    ) -> dict[str, Any] | None:
        """The service a container belongs to, from its Docker labels (see APP_NAME_LABELS)."""
        return ref_for_labels(labels, index)

    async def projects(self) -> dict[str, Any]:
        async def build() -> Any:
            raw = await self._projects_raw()
            details: dict[str, dict[str, Any]] = {}
            for project in raw:
                project_id = project.get("projectId") if isinstance(project, dict) else None
                if isinstance(project_id, str) and norm.services_missing_names(project):
                    one = await self.project_detail(project_id)
                    if one is not None:
                        details[project_id] = one
            try:
                recent = await self.recent_deployments()
            except DokployError as exc:
                if _fatal(exc):
                    raise
                recent = None
            tree = norm.project_tree(raw, details=details, latest=norm.latest_by_service(recent))
            panel = self.panel_url()
            for project in tree:
                environment_id = project.get("default_environment_id")
                project["url"] = (
                    self.project_url(panel, project["id"], environment_id) if panel else None
                )
                for service in project["services"]:
                    service["url"] = self.service_url(panel, {
                        "project_id": project["id"],
                        "environment_id": service.get("environment_id"),
                        "type": service["type"],
                        "id": service["id"],
                    }) if panel else None
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
                    # Removed in Dokploy: the cached list still shows it, so drop that too.
                    for key in ("projects:tree", "projects:all", "projects:app-index"):
                        self.cache.pop(key)
                    raise DokployError(
                        "dokploy_service_not_found", 404,
                        "Dokploy service not found; it may have been removed. Refresh the list",
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
            body["title"] = "Manual deployment from DevAssist" if action == "deploy" else (
                "Redeploy from DevAssist"
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
                    "dokploy_service_not_found", 404,
                    "Dokploy service not found; it may have been removed. Refresh the list",
                ) from None
            raise
        finally:
            self.cache.clear()

    # ----- env of a service (docs/48, layer C) -------------------------------
    async def build_env_source(self, service_type: str, service_id: str) -> dict[str, Any]:
        """The fields layer C reads, straight from ``<router>.one`` (never cached).

        Only these keys leave this method; the rest of the answer (secrets of other
        kinds, mounts, ...) is dropped here.
        """
        if service_type not in norm.DEPLOYABLE_TYPES:
            raise DokployError("invalid_service_type", 422, "Only applications and compose")
        self.check_ref(service_type, service_id)
        router, id_field, _status = norm.SERVICE_TYPES[service_type]
        try:
            payload = await self.call(f"{router}.one", params={id_field: service_id})
        except DokployError as exc:
            if exc.code == "dokploy_not_found":
                raise DokployError(
                    "dokploy_service_not_found", 404,
                    "Dokploy service not found; it may have been removed. Refresh the list",
                ) from None
            raise
        if not isinstance(payload, dict):
            raise DokployError("dokploy_service_not_found", 404, "Dokploy service not found")
        keep = ("env", "buildArgs", "buildSecrets", "createEnvFile", "buildType",
                "sourceType", "composeType", "appName", "name")
        return {key: payload[key] for key in keep if key in payload}

    async def save_build_env(
        self, service_type: str, service_id: str, env: str, source: dict[str, Any]
    ) -> None:
        """Write a new env text; every other field of saveEnvironment keeps its value."""
        if service_type not in norm.DEPLOYABLE_TYPES:
            raise DokployError("invalid_service_type", 422, "Only applications and compose")
        self.check_ref(service_type, service_id)
        if service_type == "application":
            body: dict[str, Any] = {"applicationId": service_id, "env": env}
            # saveEnvironment wants these too; resend what Dokploy holds now.
            for key in ("buildArgs", "buildSecrets", "createEnvFile"):
                if key in source:
                    body[key] = source[key]
            procedure = "application.saveEnvironment"
        else:
            body = {"composeId": service_id, "env": env}
            procedure = "compose.update"
        try:
            await self.call(procedure, body=body, mutation=True, parse=False)
        finally:
            self.cache.pop(f"service:{service_type}:{service_id}")

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
        self._state_dirty = True
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
        if self._state_dirty or not self.failures_seeded:
            self.failures_seeded = True
            self._state_dirty = False
            await asyncio.to_thread(self._save_state)

    async def _poll_statuses(self) -> None:
        """Older Dokploy (no deployment.allCentralized): watch service status instead."""
        tree = norm.project_tree(await self._projects_raw())
        current: set[tuple[str, str]] = set()
        for project in tree:
            for service in project["services"]:
                if service["type"] in norm.DEPLOYABLE_TYPES and service["status"] == "error":
                    key = (service["type"], service["id"])
                    current.add(key)
                    if key not in self.status_failed and self.status_seeded:
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
        changed = current != self.status_failed or not self.status_seeded
        self.status_failed = current
        self.status_seeded = True
        if changed:
            await asyncio.to_thread(self._save_state)

    async def _loop(self) -> None:
        _BACKGROUND.set(True)  # this task's calls never queue ahead of page loads
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
            code = (
                "invalid_dokploy_public_url" if message.startswith("Public")
                else "invalid_dokploy_api_key" if "key" in message
                else "invalid_dokploy_url"
            )
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
            result = await service.projects()
        except DokployError as exc:
            return failure(exc)
        # Health as of this very load, so the page never shows the previous poll's warning.
        return {**result, **service.status_view()}

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
