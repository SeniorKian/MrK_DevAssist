from __future__ import annotations

import asyncio
import csv
import functools
import io
import json
import logging
import os
import shutil
import time
import zipfile
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager, suppress
from pathlib import Path
from typing import Any, Literal

import uvicorn
from fastapi import FastAPI, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from starlette.exceptions import HTTPException as StarletteHTTPException

from . import __version__, components, remote_services
from .auth import (
    AuthStore,
    FieldError,
    PermissionEscalationError,
    Principal,
    RoleInUseError,
    password_policy,
    permission_catalog,
)
from .backup import BackupManager
from .catalog import PackageCatalog
from .config import Settings, apply_startup_overrides
from .database import Database
from .logging_config import configure_logging
from .middleware import (
    DynamicTrustedHostMiddleware,
    RequestSecurityMiddleware,
    TrustedHostsHolder,
    correlation_id_context,
)
from .module_context import Event, EventBus, ModuleContext
from .netresolve import NetworkSettingsStore, resolve_host, validate_config
from .outbound import (
    ALL_PROXY_TYPES,
    HTTP_PROXY_TYPES,
    OutboundError,
    OutboundProvider,
    check_reference,
    outbound_registry,
    resolve_route,
)
from .outbound_api import build_router as build_outbound_router
from .package_policy import pep503, valid_package_name
from .process_control import reload_verdaccio_best_effort
from .secret_store import SecretStore
from .tasks import (
    MAX_CLEANUP_CANDIDATES,
    TRASH_ID,
    RetryRejected,
    TaskManager,
    cleanup_confirmation,
)
from .tenancy import TenancyError
from .upstream_health import UpstreamHealthStore
from .upstream_probe import probe_upstream, reject_private_destination
from .upstream_store import UpstreamStore

LOGGER = logging.getLogger(__name__)
DATA_DIRECTORIES = (
    "control-plane",
    "npm/storage",
    "npm/config",
    "npm/auth",
    "pypi/server",
    "pypi/client",
    "logs",
    "backups",
    "tmp",
)
SESSION_COOKIE = "mrk_session"
CSRF_FAILED = "csrf_failed"
PASSWORD_CHANGE_REQUIRED = "password_change_required"  # noqa: S105 - an error code
ADMIN_AREA_LOCAL_ONLY = "admin_area_local_only"


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=254)
    password: str = Field(min_length=1, max_length=256)


class SetupOwnerRequest(BaseModel):
    display_name: str = Field(min_length=2, max_length=100)
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=1, max_length=256)
    password_confirmation: str = Field(min_length=1, max_length=256)


class InviteTokenRequest(BaseModel):
    token: str = Field(min_length=10, max_length=200)


class InviteSignupRequest(BaseModel):
    token: str = Field(min_length=10, max_length=200)
    display_name: str = Field(min_length=2, max_length=100)
    password: str = Field(min_length=1, max_length=256)
    password_confirmation: str = Field(min_length=1, max_length=256)


class RegistrationPolicyRequest(BaseModel):
    enabled: bool


class DnsSettingsRequest(BaseModel):
    mode: Literal["system", "custom"]
    servers: list[str] = Field(default_factory=list, max_length=6)
    timeout_seconds: float = Field(default=2.0, ge=0.2, le=10)
    prefer_ipv4: bool = True


class UpstreamPolicyRequest(BaseModel):
    allow_private_upstreams: bool


class DnsTestRequest(BaseModel):
    hostname: str = Field(min_length=1, max_length=253, pattern=r"^[A-Za-z0-9.-]+$")
    mode: Literal["system", "custom"] | None = None
    servers: list[str] | None = Field(default=None, max_length=6)


class CreateUserRequest(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=1, max_length=256)
    role: str = Field(min_length=1, max_length=32)
    display_name: str | None = Field(default=None, max_length=100)
    email: str | None = Field(default=None, max_length=254)
    must_change_password: bool = False


class InviteUserRequest(BaseModel):
    display_name: str = Field(min_length=1, max_length=100)
    email: str | None = Field(default=None, max_length=254)
    role: str = Field(default="viewer", min_length=1, max_length=32)
    username: str | None = Field(default=None, max_length=64)
    create_link: bool = True


class ResetPasswordRequest(BaseModel):
    create_link: bool = True


class RevokeSessionsRequest(BaseModel):
    include_tokens: bool = False


class AcceptInviteRequest(BaseModel):
    password: str = Field(min_length=1, max_length=256)
    password_confirmation: str | None = Field(default=None, max_length=256)


class ChangePasswordRequest(BaseModel):
    current_password: str = Field(min_length=1, max_length=256)
    new_password: str = Field(min_length=1, max_length=256)


class CreateRoleRequest(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    description: str | None = Field(default=None, max_length=500)
    permissions: list[str] = Field(max_length=64)


class UpdateRoleRequest(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=80)
    description: str | None = Field(default=None, max_length=500)
    permissions: list[str] | None = Field(default=None, max_length=64)


class UpdateUserRequest(BaseModel):
    role: str | None = None
    enabled: bool | None = None


class CreateTokenRequest(BaseModel):
    name: str = Field(min_length=3, max_length=80)
    scopes: list[str] = Field(min_length=1, max_length=32)
    expires_in_seconds: int = Field(ge=900, le=31536000)


class CreateUpstreamRequest(BaseModel):
    name: str = Field(min_length=2, max_length=80)
    ecosystem: str
    url: str = Field(min_length=8, max_length=2048)
    priority: int = Field(ge=1, le=10000)
    timeout_seconds: int = Field(default=30, ge=1, le=300)
    # None = direct, "default" = default proxy, otherwise a proxy profile id.
    proxy_id: str | None = Field(default=None, max_length=64)


class UpdateUpstreamRequest(BaseModel):
    name: str | None = Field(default=None, min_length=2, max_length=80)
    url: str | None = Field(default=None, min_length=8, max_length=2048)
    priority: int | None = Field(default=None, ge=1, le=10000)
    timeout_seconds: int | None = Field(default=None, ge=1, le=300)
    enabled: bool | None = None
    # Sent explicitly as null: switch back to a direct connection.
    proxy_id: str | None = Field(default=None, max_length=64)


def upstream_proxy_types(ecosystem: str) -> frozenset[str]:
    # Verdaccio (npm) supports only HTTP(S) proxies on uplinks.
    return HTTP_PROXY_TYPES if ecosystem == "npm" else ALL_PROXY_TYPES


def upstream_proxy_code(ecosystem: str) -> str:
    return "proxy_type_unsupported_for_npm" if ecosystem == "npm" else "proxy_type_unsupported"


class DeleteUpstreamRequest(BaseModel):
    confirmation: str = Field(min_length=2, max_length=80)


class BlockUpstreamRequest(BaseModel):
    reason: str = Field(min_length=3, max_length=256)
    duration_seconds: int | None = Field(default=None, ge=60, le=2592000)


class OfflineRequest(BaseModel):
    offline: bool


class TestUpstreamRequest(BaseModel):
    upstream_id: str | None = Field(default=None, min_length=1, max_length=64)
    url: str | None = Field(default=None, min_length=8, max_length=2048)
    timeout_seconds: int = Field(default=10, ge=1, le=30)
    # For an unsaved URL; a saved upstream (upstream_id) uses its own proxy_id.
    proxy_id: str | None = Field(default=None, max_length=64)


class ReplaceUpstreamCredentialRequest(BaseModel):
    credential_type: Literal["bearer", "basic"]
    token: str | None = Field(default=None, min_length=1, max_length=4096)
    username: str | None = Field(default=None, min_length=1, max_length=256)
    password: str | None = Field(default=None, min_length=1, max_length=4096)


class PackagePolicyRequest(BaseModel):
    pinned: bool | None = None
    quarantined: bool | None = None
    quarantine_reason: str | None = Field(default=None, max_length=256)


class CleanupCandidateRequest(BaseModel):
    ecosystem: Literal["npm", "pypi"]
    name: str = Field(min_length=1, max_length=214)


class LifecycleCleanupRequest(BaseModel):
    target_bytes: int | None = Field(default=None, ge=1, le=2**62)
    target_percent: int | None = Field(default=None, ge=20, le=90)
    candidates: list[CleanupCandidateRequest] | None = Field(
        default=None, min_length=1, max_length=500
    )
    confirmation: str = Field(min_length=1, max_length=64)


class PurgePackageRequest(BaseModel):
    confirmation: str = Field(min_length=8, max_length=300)


class PrefetchRequest(BaseModel):
    ecosystem: str
    content: str = Field(min_length=1, max_length=1_000_000)


class BackupSecretRequest(BaseModel):
    passphrase: str = Field(min_length=16, max_length=1024)


class RestorePlanRequest(BackupSecretRequest):
    confirmation: str = Field(min_length=8, max_length=256)


class BackupCreateRequest(BackupSecretRequest):
    profile: Literal["config", "full"] = "config"


class TaskRetryRequest(BaseModel):
    confirmation: str | None = Field(default=None, max_length=300)


class TrashDeleteRequest(BaseModel):
    confirmation: str = Field(min_length=8, max_length=64)


def _prepare_data_directories(root: Path) -> None:
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    for relative_path in DATA_DIRECTORIES:
        path = root / relative_path
        path.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            os.chmod(path, 0o700)
        except OSError:
            LOGGER.warning("unable to enforce directory mode", extra={"directory": relative_path})


def _error_payload(
    code: str,
    message: str,
    status_code: int,
    *,
    fields: list[dict[str, object]] | None = None,
    **extra: object,
) -> JSONResponse:
    """The one error envelope: {error: {code, message, request_id, ...}}.

    ``fields`` ([{field, reason_code, params?}]) lets the panel attach the
    message to the exact input (docs/33 §2.3); ``field``/``reason`` mirror the
    first entry for clients that read only one.
    """
    error: dict[str, object] = {
        "code": code,
        "message": message,
        "request_id": correlation_id_context.get(),
    }
    if fields:
        error["fields"] = fields
        error["field"] = fields[0].get("field")
        error["reason"] = fields[0].get("reason_code")
    error.update(extra)
    return JSONResponse(status_code=status_code, content={"error": error})


def _field_error(
    exc: FieldError, code: str | None = None, status_code: int | None = None, **extra: object
) -> JSONResponse:
    return _error_payload(
        code or exc.code,
        exc.message,
        status_code or exc.status_code,
        fields=exc.fields,
        **extra,
    )


_REASON_CODES = {
    "missing": "required",
    "string_too_short": "too_short",
    "string_too_long": "too_long",
    "too_short": "too_short",
    "too_long": "too_long",
    "greater_than_equal": "too_small",
    "greater_than": "too_small",
    "less_than_equal": "too_large",
    "less_than": "too_large",
    "string_pattern_mismatch": "invalid_format",
    "literal_error": "invalid_choice",
    "enum": "invalid_choice",
    "json_invalid": "invalid_json",
    "extra_forbidden": "unknown_field",
}


def _validation_fields(exc: RequestValidationError) -> list[dict[str, object]]:
    """Turn pydantic errors into [{field, reason_code, params?}] with stable codes."""
    result: list[dict[str, object]] = []
    for item in exc.errors():
        location = [str(part) for part in item.get("loc", ())]
        if location and location[0] in {"body", "query", "path", "header", "cookie"}:
            location = location[1:]
        kind = str(item.get("type", ""))
        reason = _REASON_CODES.get(kind)
        if reason is None:
            reason = (
                "invalid_type"
                if kind.endswith(("_type", "_parsing")) or kind.startswith("model_")
                else "invalid"
            )
        entry: dict[str, object] = {
            "field": ".".join(location) or "body",
            "reason_code": reason,
        }
        context = item.get("ctx")
        if isinstance(context, dict):
            params = {
                key: value
                for key, value in context.items()
                if key in {"min_length", "max_length", "ge", "gt", "le", "lt", "expected",
                           "pattern"}
                and isinstance(value, str | int | float | bool)
            }
            if params:
                entry["params"] = params
        result.append(entry)
    return result[:50]


def _csv_cell(value: object) -> str:
    text = "" if value is None else str(value)
    if text.startswith(("=", "+", "-", "@", "\t", "\r")):
        return f"'{text}"
    return text


def _account_error(exc: ValueError, fallback: str) -> JSONResponse:
    """Map account validation failures to a specific code the panel can explain."""
    if isinstance(exc, FieldError) and exc.fields:
        return _field_error(exc)
    text = str(exc)
    if text.startswith("password must"):
        return _error_payload("weak_password", text, 422)
    if "rate limited" in text:
        return _error_payload("rate_limited", "Too many attempts; try again later", 429)
    if "already initialized" in text:
        return _error_payload("already_initialized", "The owner account already exists", 409)
    if "email" in text:
        return _error_payload("invalid_email", "The email address is not valid", 422)
    if "display name" in text:
        return _error_payload("invalid_name", "The name must be 2 to 100 characters", 422)
    if "already exists" in text:
        return _error_payload("account_exists", "An account with this email already exists", 409)
    return _error_payload(fallback, "The request was rejected", 409)


def create_app(settings: Settings | None = None) -> FastAPI:
    if settings is None:
        # Panel startup overrides (settings registry) for readers using os.getenv.
        apply_startup_overrides()
    active_settings = settings or Settings.from_env()
    configure_logging(active_settings.log_level)
    # npm / PyPI connected from the add-service wizard (docs/44).
    remote_services.apply(active_settings)
    database = Database(active_settings.data_dir, active_settings.database_url)
    auth_store = AuthStore(
        active_settings.data_dir,
        active_settings.session_ttl_seconds,
        database=database,
        rate_limit_attempts=active_settings.login_rate_limit_attempts,
        rate_limit_window_seconds=active_settings.login_rate_limit_window_seconds,
        session_prune_age_seconds=active_settings.session_prune_age_seconds,
    )
    upstream_store = UpstreamStore(active_settings.data_dir)
    network_settings = NetworkSettingsStore(active_settings.data_dir)
    events = EventBus()
    module_state: dict[str, ModuleContext] = {}
    upstream_health = UpstreamHealthStore(database)
    secret_store = SecretStore(active_settings.data_dir)
    package_catalog = PackageCatalog(active_settings.data_dir)
    backup_manager = BackupManager(active_settings.data_dir, __version__, database=database)
    task_manager = TaskManager(
        active_settings.data_dir,
        package_catalog,
        database=database,
        backup_manager=backup_manager,
        audit=lambda *args: _task_audit(*args),
    )

    def _task_audit(
        actor_user_id: int | None,
        action: str,
        object_type: str,
        object_id: str | None,
        result: str = "success",
    ) -> None:
        auth_store.record_audit(actor_user_id, action, object_type, object_id, result)
        # Turn task outcomes into platform events for notifications.
        if not action.startswith("task.") or object_type != "task":
            return
        kind = action.removeprefix("task.")
        if result in {"failure", "failed"}:
            severity = "error"
            title = f"Task failed: {kind}"
        elif kind == "backup.create" and result == "succeeded":
            severity = "info"
            title = "Backup created"
        else:
            return
        events.publish(
            Event(
                type=f"{kind}.{'failed' if severity == 'error' else 'succeeded'}",
                severity=severity,
                title=title,
                message=f"task {object_id}",
                module="tasks",
                dedupe_key=f"{kind}:{result}",
                details={"task_id": object_id, "kind": kind},
            )
        )

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        _prepare_data_directories(active_settings.data_dir)
        from .restore import restore_in_progress

        if restore_in_progress(active_settings.data_dir):
            # Serving while `mrk-restore apply` swaps directories would corrupt data.
            raise RuntimeError("an offline restore is in progress; refusing to start")
        upstream_store.ensure_defaults(
            os.getenv("MRK_PYPI_PRIMARY_UPSTREAM", "https://pypi.org/simple/"),
            os.getenv(
                "MRK_PYPI_FALLBACK_UPSTREAM",
                "https://package-mirror.liara.ir/repository/pypi/simple/",
            ),
            os.getenv("MRK_NPM_PRIMARY_UPSTREAM", "https://registry.npmjs.org/"),
            os.getenv(
                "MRK_NPM_FALLBACK_UPSTREAM",
                "https://package-mirror.liara.ir/repository/npm/",
            ),
        )
        if not auth_store.has_users():
            LOGGER.warning("first-run owner registration is required")
        app.state.started_at = time.monotonic()
        events.bind(asyncio.get_running_loop())
        module_ctx = module_state.get("ctx")
        for hook in module_ctx.start_hooks if module_ctx else []:
            try:
                await hook()
            except Exception:
                LOGGER.exception("module start hook failed")
        app.state.ready = True
        heartbeat_path = active_settings.data_dir / "control-plane" / "runtime-heartbeat"

        async def heartbeat() -> None:
            while True:
                try:
                    temporary = heartbeat_path.with_suffix(".tmp")
                    temporary.write_text(f"{int(time.time())}\n", encoding="utf-8")
                    temporary.chmod(0o600)
                    temporary.replace(heartbeat_path)
                except OSError:
                    # A full disk must not kill the heartbeat for good; restore relies on it.
                    LOGGER.exception("cannot write the runtime heartbeat")
                await asyncio.sleep(5)

        async def npm_block_expiry() -> None:
            # Verdaccio reads its uplinks only at start, so a timed block would
            # otherwise last until the next restart. Reload when one expires.
            blocked: set[str] = set()
            while True:
                try:
                    now = int(time.time())
                    items = await asyncio.to_thread(upstream_store.raw_list)
                    timed = [
                        item
                        for item in items
                        if item.get("ecosystem") == "npm"
                        and item.get("blocked_until") is not None
                    ]
                    current = {
                        str(item["id"]) for item in timed if int(item["blocked_until"]) > now
                    }
                    expired = {
                        str(item["id"]) for item in timed if int(item["blocked_until"]) <= now
                    }
                    # Only a block that ran out needs a reload; an API unblock
                    # already reloaded, and a deleted upstream needs nothing.
                    if blocked & expired:
                        await asyncio.to_thread(reload_verdaccio_best_effort)
                    blocked = current
                except Exception:
                    LOGGER.exception("npm block expiry check failed")
                await asyncio.sleep(active_settings.npm_block_poll_seconds)

        async def retention() -> None:
            days = int(os.getenv("MRK_AUDIT_RETENTION_DAYS", "365"))
            vacuum_hours = float(os.getenv("MRK_DB_VACUUM_INTERVAL_HOURS", "24"))
            last_vacuum = time.monotonic()
            while True:
                try:
                    removed = await asyncio.to_thread(auth_store.prune, days)
                    LOGGER.info("retention cleanup finished", extra=removed)
                except Exception:
                    LOGGER.exception("retention cleanup failed")
                if vacuum_hours > 0 and time.monotonic() - last_vacuum >= vacuum_hours * 3600:
                    last_vacuum = time.monotonic()
                    try:
                        # PGlite is single-user, so autovacuum never runs on its own.
                        await asyncio.to_thread(database.maintenance)
                        LOGGER.info("database maintenance finished")
                    except Exception:
                        LOGGER.exception("database maintenance failed")
                await asyncio.sleep(min(6 * 3600, max(vacuum_hours, 0.25) * 3600))

        heartbeat_worker = asyncio.create_task(heartbeat(), name="mrk-heartbeat")
        retention_worker = asyncio.create_task(retention(), name="mrk-retention")
        block_worker = asyncio.create_task(npm_block_expiry(), name="mrk-npm-block-expiry")
        task_worker = asyncio.create_task(task_manager.run(), name="mrk-task-worker")
        LOGGER.info("control plane started")
        try:
            yield
        finally:
            app.state.ready = False
            module_ctx = module_state.get("ctx")
            for hook in reversed(module_ctx.stop_hooks if module_ctx else []):
                try:
                    await hook()
                except Exception:
                    LOGGER.exception("module stop hook failed")
            heartbeat_worker.cancel()
            block_worker.cancel()
            retention_worker.cancel()
            with suppress(asyncio.CancelledError):
                await retention_worker
            with suppress(asyncio.CancelledError):
                await heartbeat_worker
            with suppress(asyncio.CancelledError):
                await block_worker
            heartbeat_path.unlink(missing_ok=True)
            await task_manager.stop()
            await task_worker
            database.dispose()
            LOGGER.info("control plane stopped")

    app = FastAPI(
        title="DevAssist",
        version=__version__,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )
    app.state.settings = active_settings
    app.state.ready = False
    app.state.started_at = time.monotonic()
    app.state.auth_store = auth_store
    app.state.database = database

    app.add_middleware(RequestSecurityMiddleware)
    # Static MRK_TRUSTED_HOSTS plus the panel's domains (docs/35 §4), updated at runtime.
    trusted_hosts = TrustedHostsHolder(active_settings.trusted_hosts)
    app.state.trusted_hosts = trusted_hosts
    app.add_middleware(DynamicTrustedHostMiddleware, holder=trusted_hosts)
    if active_settings.cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=list(active_settings.cors_origins),
            allow_credentials=True,
            allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
            allow_headers=["Accept", "Content-Type", "X-CSRF-Token", "X-Request-ID"],
        )

    @app.exception_handler(StarletteHTTPException)
    async def http_error(_request: Request, exc: StarletteHTTPException) -> JSONResponse:
        if exc.status_code == 403:
            # The UI refreshes its token and retries only on csrf_failed; a
            # permission denial ("forbidden") must not be retried.
            if exc.detail == CSRF_FAILED:
                return _error_payload(CSRF_FAILED, "CSRF token is missing or invalid", 403)
            if exc.detail == PASSWORD_CHANGE_REQUIRED:
                return _error_payload(
                    PASSWORD_CHANGE_REQUIRED, "Choose a new password before continuing", 403
                )
            if exc.detail == ADMIN_AREA_LOCAL_ONLY:
                return _error_payload(
                    ADMIN_AREA_LOCAL_ONLY,
                    "Server management is only reachable from the local network", 403,
                )
            return _error_payload("forbidden", "Permission denied", 403)
        public_message = "Not found" if exc.status_code == 404 else "Request failed"
        return _error_payload("http_error", public_message, exc.status_code)

    @app.exception_handler(TenancyError)
    async def tenancy_error(_request: Request, exc: TenancyError) -> JSONResponse:
        extra = {key: value for key, value in exc.extra.items() if value is not None}
        return _error_payload(exc.code, exc.message, exc.status_code, fields=exc.fields, **extra)

    @app.exception_handler(RequestValidationError)
    async def validation_error(_request: Request, exc: RequestValidationError) -> JSONResponse:
        return _error_payload(
            "validation_error", "Request validation failed", 422,
            fields=_validation_fields(exc),
        )

    @app.exception_handler(Exception)
    async def unexpected_error(_request: Request, exc: Exception) -> JSONResponse:
        LOGGER.exception("unhandled request failure", exc_info=exc)
        return _error_payload("internal_error", "Internal server error", 500)

    @app.get("/health/live", include_in_schema=False)
    async def liveness() -> dict[str, str]:
        return {"status": "ok"}

    async def pypi_router_status() -> dict[str, object] | None:
        return await components.router_status(
            active_settings, timeout=components.READINESS_TIMEOUT_SECONDS
        )

    @app.get("/health/ready", include_in_schema=False, response_model=None)
    async def readiness(request: Request) -> JSONResponse | dict[str, str]:
        if not request.app.state.ready:
            return JSONResponse(status_code=503, content={"status": "not_ready"})
        # A registry stopped on purpose, recovering under the watchdog or running in
        # its own container never gates the panel (Swarm would restart the panel for
        # it); /system/status and /metrics still report its real state.
        if await components.registry_blocks_readiness(active_settings, "npm"):
            return JSONResponse(
                status_code=503,
                content={"status": "not_ready", "component": "npm_registry"},
            )
        if await components.registry_blocks_readiness(active_settings, "pypi"):
            return JSONResponse(
                status_code=503,
                content={"status": "not_ready", "component": "pypi_registry"},
            )
        if await components.router_blocks_readiness(active_settings):
            # Without the router every PyPI cache miss fails, even when upstreams are fine.
            return JSONResponse(
                status_code=503,
                content={"status": "not_ready", "component": "pypi_upstream_router"},
            )
        database_state = await components.database_health_state(database.engine)
        if database_state.state == "unavailable":
            return JSONResponse(
                status_code=503,
                content={"status": "not_ready", "component": "database"},
            )
        return {"status": "ready"}

    def require_principal(request: Request, permission: str | None = None) -> Principal:
        principal = auth_store.principal_for_token(request.cookies.get(SESSION_COOKIE))
        if principal is None:
            authorization = request.headers.get("authorization", "")
            if authorization.lower().startswith("bearer "):
                principal = auth_store.principal_for_api_token(authorization[7:].strip())
        if principal is None:
            raise StarletteHTTPException(status_code=401)
        if permission is not None and principal.must_change_password:
            # An invited account signs in with a one-time password and may only
            # read itself, change the password or sign out until it picks one.
            raise StarletteHTTPException(status_code=403, detail=PASSWORD_CHANGE_REQUIRED)
        if permission is not None and not principal.allows(permission):
            raise StarletteHTTPException(status_code=403)
        tenancy = getattr(app.state, "tenancy", None)
        if permission is not None and tenancy is not None and not tenancy.admin_area_allowed(
            request.client.host if request.client else None
        ):
            # docs/43 §2: tenancy.admin_area_local_only keeps server management local.
            raise StarletteHTTPException(status_code=403, detail=ADMIN_AREA_LOCAL_ONLY)
        return principal

    def require_csrf(request: Request, principal: Principal) -> None:
        if principal.token_id is not None:
            return
        if not auth_store.verify_csrf(principal, request.headers.get("x-csrf-token")):
            raise StarletteHTTPException(status_code=403, detail=CSRF_FAILED)

    async def reload_npm(actor_user_id: int) -> bool:
        """Best-effort Verdaccio reload after a change that is already saved.

        A failed reload used to raise after the write and before the audit
        record, so the client saw a 500 for a change that had been applied.
        """
        reloaded = await asyncio.to_thread(reload_verdaccio_best_effort)
        if not reloaded:
            await asyncio.to_thread(
                auth_store.record_audit,
                actor_user_id,
                "npm.reload",
                "service",
                "verdaccio",
                "failure",
            )
        return reloaded

    async def purge_quarantined_pypi(name: str, actor_user_id: int) -> str | None:
        """Queue a purge of a newly quarantined PyPI project from the devpi cache.

        Reuses the regular purge task with the confirmation it expects. The
        router already 404s the project, so this only removes cached copies;
        it is best effort (nothing cached, or the project is pinned: no purge).
        """
        preview: dict[str, object] | None = None
        for candidate in dict.fromkeys((name, pep503(name))):
            try:
                preview = await asyncio.to_thread(
                    package_catalog.purge_preview, "pypi", candidate
                )
                break
            except KeyError:
                continue
        if preview is None or preview.get("blocked_by_pin"):
            return None
        try:
            task_id = await asyncio.to_thread(
                task_manager.enqueue,
                "package.purge",
                {
                    "ecosystem": "pypi",
                    "name": str(preview["name"]),
                    "confirmation": str(preview["confirmation"]),
                },
                actor_user_id,
            )
        except Exception:
            LOGGER.exception("cannot queue the purge of a quarantined PyPI project")
            return None
        await asyncio.to_thread(
            auth_store.record_audit,
            actor_user_id,
            "package.quarantine.purge.enqueue",
            "task",
            task_id,
        )
        return task_id

    def set_session_cookie(response: JSONResponse, token: str) -> None:
        response.set_cookie(
            SESSION_COOKIE,
            token,
            max_age=active_settings.session_ttl_seconds,
            httponly=True,
            secure=active_settings.auth_cookie_secure,
            samesite="strict",
            path="/",
        )

    def principal_payload(principal: Principal) -> dict[str, object]:
        return {
            "id": principal.user_id,
            "username": principal.username,
            "display_name": principal.display_name,
            "email": principal.email,
            "role": principal.role,
            "permissions": sorted(principal.permissions),
            "must_change_password": principal.must_change_password,
        }

    @app.get("/api/v1/auth/setup-status", include_in_schema=False)
    async def setup_status() -> dict[str, object]:
        required = not await asyncio.to_thread(auth_store.has_users)
        return {"required": required, "password_policy": password_policy()}

    @app.get("/api/v1/auth/registration-status", include_in_schema=False)
    async def registration_status() -> dict[str, object]:
        tenancy = getattr(app.state, "tenancy", None)
        if tenancy is not None and await asyncio.to_thread(tenancy.enabled):
            # docs/43 §2: with «my space» on, tenancy.signup decides.
            mode = (await asyncio.to_thread(tenancy.get_settings))["signup"]
            return {"enabled": mode != "off", "mode": mode}
        return {
            "enabled": await asyncio.to_thread(
                auth_store.public_registration_enabled
            )
        }

    @app.post("/api/v1/auth/setup", include_in_schema=False, response_model=None)
    async def setup_owner(
        payload: SetupOwnerRequest, request: Request
    ) -> JSONResponse:
        if payload.password != payload.password_confirmation:
            return _error_payload(
                "password_mismatch", "Passwords do not match", 422,
                fields=[{"field": "password_confirmation", "reason_code": "mismatch"}],
            )
        try:
            identifier = await asyncio.to_thread(
                auth_store.setup_owner,
                payload.display_name,
                payload.email,
                payload.password,
                request.client.host if request.client else None,
                correlation_id_context.get(),
            )
        except ValueError as exc:
            return _account_error(exc, "setup_rejected")
        result = await asyncio.to_thread(
            auth_store.authenticate,
            identifier,
            payload.password,
            request.client.host if request.client else None,
            correlation_id_context.get(),
        )
        if result is None:
            return _error_payload("setup_failed", "First-run setup failed", 500)
        token, csrf, principal = result
        response = JSONResponse(
            {"user": principal_payload(principal), "csrf_token": csrf}, status_code=201
        )
        set_session_cookie(response, token)
        return response

    @app.post("/api/v1/auth/register", include_in_schema=False, response_model=None)
    async def register_user(
        payload: SetupOwnerRequest, request: Request
    ) -> JSONResponse:
        if payload.password != payload.password_confirmation:
            return _error_payload(
                "password_mismatch", "Passwords do not match", 422,
                fields=[{"field": "password_confirmation", "reason_code": "mismatch"}],
            )
        tenancy = getattr(app.state, "tenancy", None)
        mode = None
        if tenancy is not None and await asyncio.to_thread(tenancy.enabled):
            mode = (await asyncio.to_thread(tenancy.get_settings))["signup"]
        created: list[int] = []
        try:
            identifier = await asyncio.to_thread(
                functools.partial(
                    auth_store.register_public_user,
                    payload.display_name,
                    payload.email,
                    payload.password,
                    request.client.host if request.client else None,
                    correlation_id_context.get(),
                    **(
                        {}
                        if mode is None
                        else {
                            "allowed": mode != "off",
                            "role": "customer",
                            "enabled": mode == "open",
                            "created": created,
                        }
                    ),
                )
            )
        except ValueError as exc:
            return _account_error(exc, "registration_rejected")
        if mode == "approval":
            # docs/43 §2: the account waits, disabled, until an admin approves it.
            await asyncio.to_thread(tenancy.record_signup, created[0])
            return JSONResponse({"status": "pending_approval"}, status_code=202)
        if mode == "open":
            await asyncio.to_thread(tenancy.ensure_personal, created[0])
        result = await asyncio.to_thread(
            auth_store.authenticate,
            identifier,
            payload.password,
            request.client.host if request.client else None,
            correlation_id_context.get(),
        )
        if result is None:
            return _error_payload("registration_failed", "Registration failed", 500)
        token, csrf, principal = result
        response = JSONResponse(
            {"user": principal_payload(principal), "csrf_token": csrf},
            status_code=201,
        )
        set_session_cookie(response, token)
        return response

    # docs/43 §0.1: a workspace invite to an email without an account. The email always
    # comes from the invite; tenancy.invite_signup (default: as tenancy.signup) decides.
    async def invite_tenancy() -> Any:
        tenancy = getattr(app.state, "tenancy", None)
        if tenancy is None or not await asyncio.to_thread(tenancy.enabled):
            raise TenancyError("not_found", 404, "Not found")
        return tenancy

    @app.post("/api/v1/auth/workspace-invite", include_in_schema=False, response_model=None)
    async def workspace_invite_preview(payload: InviteTokenRequest) -> JSONResponse:
        tenancy = await invite_tenancy()
        preview = await asyncio.to_thread(tenancy.invite_preview, payload.token)
        return JSONResponse({**preview, "password_policy": password_policy()})

    @app.post("/api/v1/auth/workspace-invite/register", include_in_schema=False,
              response_model=None)
    async def register_from_invite(payload: InviteSignupRequest, request: Request
                                   ) -> JSONResponse:
        if payload.password != payload.password_confirmation:
            return _error_payload(
                "password_mismatch", "Passwords do not match", 422,
                fields=[{"field": "password_confirmation", "reason_code": "mismatch"}],
            )
        tenancy = await invite_tenancy()
        preview = await asyncio.to_thread(tenancy.check_invite_signup, payload.token)
        mode = preview["signup"]
        source_ip = request.client.host if request.client else None
        created: list[int] = []
        try:
            identifier = await asyncio.to_thread(
                functools.partial(
                    auth_store.register_public_user, payload.display_name, preview["email"],
                    payload.password, source_ip, correlation_id_context.get(),
                    allowed=True, role="customer", enabled=mode == "open", created=created,
                )
            )
        except ValueError as exc:
            return _account_error(exc, "registration_rejected")
        user_id = created[0]
        joined: dict[str, Any] = {}
        invite_error: str | None = None
        try:
            joined = await asyncio.to_thread(tenancy.accept_invite_as_new_user, user_id,
                                             payload.token)
        except TenancyError as exc:  # e.g. the team filled up meanwhile: keep the account
            invite_error = exc.code
        if mode == "approval":
            await asyncio.to_thread(tenancy.record_signup, user_id)
            return JSONResponse({"status": "pending_approval", "invite_error": invite_error,
                                 **joined}, status_code=202)
        await asyncio.to_thread(tenancy.ensure_personal, user_id)
        result = await asyncio.to_thread(
            auth_store.authenticate, identifier, payload.password, source_ip,
            correlation_id_context.get(),
        )
        if result is None:
            return _error_payload("registration_failed", "Registration failed", 500)
        token, csrf, principal = result
        response = JSONResponse(
            {"user": principal_payload(principal), "csrf_token": csrf,
             "invite_error": invite_error, **joined},
            status_code=201,
        )
        set_session_cookie(response, token)
        return response

    @app.post("/api/v1/auth/login", include_in_schema=False)
    async def login(payload: LoginRequest, request: Request) -> JSONResponse:
        result = await asyncio.to_thread(
            auth_store.authenticate,
            payload.username,
            payload.password,
            request.client.host if request.client else None,
            correlation_id_context.get(),
        )
        if result is None:
            return _error_payload("invalid_credentials", "Invalid credentials", 401)
        token, csrf, principal = result
        response = JSONResponse(
            {
                "user": principal_payload(principal),
                "csrf_token": csrf,
                "must_change_password": principal.must_change_password,
            }
        )
        set_session_cookie(response, token)
        return response

    @app.post("/api/v1/auth/change-password", include_in_schema=False, response_model=None)
    async def change_password(
        payload: ChangePasswordRequest, request: Request
    ) -> JSONResponse:
        principal = require_principal(request)
        if principal.session_id is None:
            # App keys cannot change the password of the person who made them.
            raise StarletteHTTPException(status_code=403)
        require_csrf(request, principal)
        try:
            updated = await asyncio.to_thread(
                auth_store.change_password,
                principal,
                payload.current_password,
                payload.new_password,
                request.client.host if request.client else None,
                correlation_id_context.get(),
            )
        except FieldError as exc:
            return _field_error(exc)
        return JSONResponse({"status": "changed", "user": principal_payload(updated)})

    @app.get("/api/v1/auth/invite/{token}", include_in_schema=False, response_model=None)
    async def invite_details(token: str, request: Request) -> JSONResponse:
        try:
            details = await asyncio.to_thread(
                auth_store.get_invite, token, request.client.host if request.client else None
            )
        except FieldError as exc:
            return _field_error(exc)
        return JSONResponse(details)

    @app.post(
        "/api/v1/auth/invite/{token}/accept", include_in_schema=False, response_model=None
    )
    async def accept_invite(
        token: str, payload: AcceptInviteRequest, request: Request
    ) -> JSONResponse:
        if (
            payload.password_confirmation is not None
            and payload.password != payload.password_confirmation
        ):
            return _error_payload(
                "password_mismatch", "Passwords do not match", 422,
                fields=[{"field": "password_confirmation", "reason_code": "mismatch"}],
            )
        try:
            session_token, csrf, principal = await asyncio.to_thread(
                auth_store.accept_invite,
                token,
                payload.password,
                request.client.host if request.client else None,
                correlation_id_context.get(),
            )
        except FieldError as exc:
            return _field_error(exc)
        response = JSONResponse(
            {
                "user": principal_payload(principal),
                "csrf_token": csrf,
                "must_change_password": False,
            }
        )
        set_session_cookie(response, session_token)
        return response

    @app.get("/api/v1/auth/capabilities", include_in_schema=False)
    async def auth_capabilities() -> dict[str, object]:
        return {
            "local": {"enabled": True},
            "oidc": {"enabled": False, "status": "not_configured"},
            "mfa": {"enabled": False, "status": "planned"},
        }

    @app.get("/api/v1/auth/me", include_in_schema=False)
    async def auth_me(request: Request) -> dict[str, object]:
        principal = require_principal(request)
        csrf = (
            await asyncio.to_thread(
                auth_store.issue_csrf, principal, str(request.cookies.get(SESSION_COOKIE))
            )
            if principal.session_id is not None
            else None
        )
        return {
            "user": principal_payload(principal),
            "csrf_token": csrf,
        }

    @app.post("/api/v1/auth/refresh", include_in_schema=False)
    async def refresh(request: Request) -> JSONResponse:
        principal = require_principal(request)
        if principal.session_id is None:
            raise StarletteHTTPException(status_code=400)
        require_csrf(request, principal)
        token, csrf = await asyncio.to_thread(auth_store.rotate_session, principal)
        response = JSONResponse({"csrf_token": csrf})
        set_session_cookie(response, token)
        return response

    @app.post("/api/v1/auth/logout", include_in_schema=False)
    async def logout(request: Request) -> JSONResponse:
        principal = require_principal(request)
        if principal.session_id is None:
            raise StarletteHTTPException(status_code=400)
        require_csrf(request, principal)
        await asyncio.to_thread(
            auth_store.revoke_session,
            principal.session_id,
            principal.user_id,
            correlation_id_context.get(),
        )
        response = JSONResponse({"status": "logged_out"})
        response.delete_cookie(SESSION_COOKIE, path="/")
        return response

    @app.get("/api/v1/system/status", include_in_schema=False)
    async def system_status(request: Request) -> dict[str, object]:
        require_principal(request, "system:read")
        # The same states Home and /metrics use: a registry in its own container is
        # "unavailable" here when it is down, even though it never gates readiness.
        health, _router_raw = await components.component_health(
            active_settings, database.engine
        )
        total_bytes, used_bytes, free_bytes = await asyncio.to_thread(
            shutil.disk_usage, active_settings.data_dir
        )
        return {
            "status": "operational",
            "version": __version__,
            "environment": active_settings.environment,
            "database": {
                "dialect": database.dialect,
                "mode": database.mode,
            },
            "uptime_seconds": max(0, int(time.monotonic() - app.state.started_at)),
            "build": {
                "commit": active_settings.build_commit,
                "built_at": active_settings.build_date,
                "ui_version": __version__,
            },
            "storage": {
                "total_bytes": total_bytes,
                "used_bytes": used_bytes,
                "free_bytes": free_bytes,
                "used_percent": round((used_bytes / total_bytes) * 100, 1)
                if total_bytes
                else 0.0,
            },
            "components": {
                "control_plane": "ready",
                **{name: item.state for name, item in health.items()},
            },
            "component_details": {
                name: item.as_dict() for name, item in health.items()
            },
        }

    @app.get("/api/v1/upstreams", include_in_schema=False)
    async def upstreams(request: Request) -> dict[str, object]:
        require_principal(request, "upstream:read")
        router_status = await pypi_router_status()
        return {
            "items": await asyncio.to_thread(upstream_store.list),
            "runtime": router_status or {},
            "offline": {
                ecosystem: upstream_store.offline(ecosystem)
                for ecosystem in ("npm", "pypi")
            },
        }

    @app.post(
        "/api/v1/upstreams",
        include_in_schema=False,
        status_code=201,
        response_model=None,
    )
    async def create_upstream(
        payload: CreateUpstreamRequest, request: Request
    ) -> JSONResponse | dict[str, object]:
        principal = require_principal(request, "upstream:write")
        require_csrf(request, principal)
        allow_private = network_settings.allow_private_upstreams()
        try:
            proxy_id = check_reference(
                network_settings,
                payload.proxy_id,
                upstream_proxy_types(payload.ecosystem),
                upstream_proxy_code(payload.ecosystem),
            )
        except OutboundError as exc:
            return _error_payload(exc.code, exc.message, 422)
        try:
            if payload.ecosystem == "npm":
                await reject_private_destination(
                    payload.url,
                    network_settings.dns(),
                    allow_private=allow_private,
                    proxied=proxy_id is not None,
                )
            item = await asyncio.to_thread(
                upstream_store.create,
                payload.name,
                payload.ecosystem,
                payload.url,
                payload.priority,
                payload.timeout_seconds,
                allow_private,
                proxy_id,
            )
        except ValueError as exc:
            return _error_payload("invalid_upstream", str(exc), 409)
        if item["ecosystem"] == "npm":
            await reload_npm(principal.user_id)
        await asyncio.to_thread(
            auth_store.record_audit,
            principal.user_id,
            "upstream.create",
            "upstream",
            str(item["id"]),
            "success",
            request.client.host if request.client else None,
            correlation_id_context.get(),
        )
        return upstream_store.public(item)

    @app.post(
        "/api/v1/upstreams/test", include_in_schema=False, response_model=None
    )
    async def test_upstream(
        payload: TestUpstreamRequest, request: Request
    ) -> JSONResponse | dict[str, object]:
        principal = require_principal(request, "upstream:write")
        require_csrf(request, principal)
        item: dict[str, object] | None = None
        probe_proxy_ref: str | None = None
        try:
            if payload.upstream_id is not None:
                item = await asyncio.to_thread(upstream_store.get, payload.upstream_id)
                probe_url = str(item["url"])
                probe_timeout = min(int(item["timeout_seconds"]), 30)
                probe_proxy_ref = str(item["proxy_id"]) if item.get("proxy_id") else None
                authorization = None
                if item.get("credential_ref") and item.get("credential_type"):
                    authorization = await asyncio.to_thread(
                        secret_store.authorization_header,
                        str(item["credential_ref"]),
                        str(item["credential_type"]),
                    )
            elif payload.url is not None:
                probe_url = payload.url
                probe_timeout = payload.timeout_seconds
                probe_proxy_ref = payload.proxy_id or None
                authorization = None
            else:
                return _error_payload(
                    "invalid_upstream", "upstream_id or url is required", 422
                )
            proxy_kwargs: dict[str, object] = {}
            if probe_proxy_ref is not None:
                route = await asyncio.to_thread(
                    resolve_route, network_settings, secret_store, probe_proxy_ref
                )
                if route is not None:
                    proxy_kwargs["proxy"] = route
            result = await probe_upstream(
                probe_url,
                probe_timeout,
                authorization,
                dns=network_settings.dns(),
                allow_private=network_settings.allow_private_upstreams(),
                **proxy_kwargs,
            )
        except KeyError:
            raise StarletteHTTPException(status_code=404) from None
        except OutboundError as exc:
            return _error_payload(exc.code, exc.message, 409)
        except ValueError as exc:
            return _error_payload("invalid_upstream", str(exc), 409)
        if item is not None:
            await asyncio.to_thread(
                upstream_health.record,
                str(item["id"]),
                str(item["ecosystem"]),
                str(item["name"]),
                result,
                principal.user_id,
            )
        await asyncio.to_thread(
            auth_store.record_audit,
            principal.user_id,
            "upstream.test",
            "upstream",
            None,
            "success" if result["ok"] else "failure",
        )
        return result

    @app.put(
        "/api/v1/upstreams/{upstream_id}/credential",
        include_in_schema=False,
        response_model=None,
    )
    async def replace_upstream_credential(
        upstream_id: str,
        payload: ReplaceUpstreamCredentialRequest,
        request: Request,
    ) -> JSONResponse | dict[str, object]:
        principal = require_principal(request, "upstream:write")
        require_csrf(request, principal)
        try:
            item = await asyncio.to_thread(upstream_store.get, upstream_id)
        except KeyError:
            raise StarletteHTTPException(status_code=404) from None
        if payload.credential_type == "bearer":
            if (
                payload.token is None
                or payload.username is not None
                or payload.password is not None
            ):
                return _error_payload(
                    "invalid_credential", "bearer credentials require only token", 422
                )
            secret_value = {"token": payload.token}
        else:
            if payload.username is None or payload.password is None or payload.token is not None:
                return _error_payload(
                    "invalid_credential",
                    "basic credentials require username and password",
                    422,
                )
            if item["ecosystem"] == "npm":
                return _error_payload(
                    "invalid_credential", "npm uplinks support bearer credentials only", 422
                )
            secret_value = {"username": payload.username, "password": payload.password}
        reference, updated_at = await asyncio.to_thread(
            secret_store.replace,
            str(item["credential_ref"]) if item.get("credential_ref") else None,
            secret_value,
        )
        await asyncio.to_thread(
            upstream_store.update,
            upstream_id,
            {
                "credential_ref": reference,
                "credential_type": payload.credential_type,
                "credential_updated_at": updated_at,
            },
        )
        if item["ecosystem"] == "npm":
            await reload_npm(principal.user_id)
        await asyncio.to_thread(
            auth_store.record_audit,
            principal.user_id,
            "upstream.credential.replace",
            "upstream",
            upstream_id,
            "success",
            request.client.host if request.client else None,
            correlation_id_context.get(),
        )
        return {
            "configured": True,
            "credential_type": payload.credential_type,
            "updated_at": updated_at,
        }

    @app.delete(
        "/api/v1/upstreams/{upstream_id}/credential", include_in_schema=False
    )
    async def remove_upstream_credential(
        upstream_id: str, request: Request
    ) -> dict[str, object]:
        principal = require_principal(request, "upstream:write")
        require_csrf(request, principal)
        try:
            item = await asyncio.to_thread(upstream_store.get, upstream_id)
        except KeyError:
            raise StarletteHTTPException(status_code=404) from None
        await asyncio.to_thread(
            upstream_store.update,
            upstream_id,
            {
                "credential_ref": None,
                "credential_type": None,
                "credential_updated_at": None,
            },
        )
        if item.get("credential_ref"):
            await asyncio.to_thread(secret_store.delete, str(item["credential_ref"]))
        if item["ecosystem"] == "npm":
            await reload_npm(principal.user_id)
        await asyncio.to_thread(
            auth_store.record_audit,
            principal.user_id,
            "upstream.credential.remove",
            "upstream",
            upstream_id,
            "success",
            request.client.host if request.client else None,
            correlation_id_context.get(),
        )
        return {"configured": False}

    @app.get(
        "/api/v1/upstreams/{upstream_id}/health",
        include_in_schema=False,
    )
    async def upstream_health_timeline(
        upstream_id: str,
        request: Request,
        limit: int = Query(default=100, ge=1, le=500),
    ) -> dict[str, object]:
        require_principal(request, "upstream:read")
        try:
            await asyncio.to_thread(upstream_store.get, upstream_id)
        except KeyError:
            raise StarletteHTTPException(status_code=404) from None
        return {
            "items": await asyncio.to_thread(upstream_health.list, upstream_id, limit)
        }

    @app.patch(
        "/api/v1/upstreams/{upstream_id}",
        include_in_schema=False,
        response_model=None,
    )
    async def update_upstream(
        upstream_id: str, payload: UpdateUpstreamRequest, request: Request
    ) -> JSONResponse | dict[str, object]:
        principal = require_principal(request, "upstream:write")
        require_csrf(request, principal)
        changes = payload.model_dump(exclude_none=True)
        if "proxy_id" in payload.model_fields_set:
            changes["proxy_id"] = payload.proxy_id or None
        try:
            if "proxy_id" in changes:
                current = await asyncio.to_thread(upstream_store.get, upstream_id)
                ecosystem = str(current["ecosystem"])
                try:
                    changes["proxy_id"] = check_reference(
                        network_settings,
                        changes["proxy_id"],
                        upstream_proxy_types(ecosystem),
                        upstream_proxy_code(ecosystem),
                    )
                except OutboundError as exc:
                    return _error_payload(exc.code, exc.message, 422)
            if "url" in changes:
                current = await asyncio.to_thread(upstream_store.get, upstream_id)
                if current["ecosystem"] == "npm":
                    proxied = (
                        changes["proxy_id"] if "proxy_id" in changes else current.get("proxy_id")
                    )
                    await reject_private_destination(
                        str(changes["url"]),
                        network_settings.dns(),
                        allow_private=network_settings.allow_private_upstreams(),
                        proxied=bool(proxied),
                    )
            item = await asyncio.to_thread(
                upstream_store.update,
                upstream_id,
                changes,
                network_settings.allow_private_upstreams(),
            )
        except KeyError:
            raise StarletteHTTPException(status_code=404) from None
        except ValueError as exc:
            return _error_payload("invalid_upstream", str(exc), 409)
        if item["ecosystem"] == "npm":
            await reload_npm(principal.user_id)
        await asyncio.to_thread(
            auth_store.record_audit,
            principal.user_id,
            "upstream.update",
            "upstream",
            upstream_id,
        )
        return upstream_store.public(item)

    @app.delete(
        "/api/v1/upstreams/{upstream_id}",
        include_in_schema=False,
        response_model=None,
    )
    async def delete_upstream(
        upstream_id: str,
        payload: DeleteUpstreamRequest,
        request: Request,
    ) -> JSONResponse | Response:
        principal = require_principal(request, "upstream:write")
        require_csrf(request, principal)
        try:
            current = await asyncio.to_thread(upstream_store.get, upstream_id)
            if payload.confirmation != current["name"]:
                return _error_payload(
                    "confirmation_mismatch", "type the exact upstream name", 409
                )
            item = await asyncio.to_thread(upstream_store.delete, upstream_id)
        except KeyError:
            raise StarletteHTTPException(status_code=404) from None
        except ValueError as exc:
            return _error_payload("unsafe_upstream_delete", str(exc), 409)
        if item.get("credential_ref"):
            await asyncio.to_thread(secret_store.delete, str(item["credential_ref"]))
        if item["ecosystem"] == "npm":
            await reload_npm(principal.user_id)
        await asyncio.to_thread(
            auth_store.record_audit,
            principal.user_id,
            "upstream.delete",
            "upstream",
            upstream_id,
            "success",
            request.client.host if request.client else None,
            correlation_id_context.get(),
        )
        return Response(status_code=204)

    @app.post(
        "/api/v1/upstreams/{upstream_id}/block",
        include_in_schema=False,
        response_model=None,
    )
    async def block_upstream(
        upstream_id: str, payload: BlockUpstreamRequest, request: Request
    ) -> JSONResponse | dict[str, object]:
        principal = require_principal(request, "upstream:operate")
        require_csrf(request, principal)
        blocked_until = (
            int(time.time()) + payload.duration_seconds
            if payload.duration_seconds is not None
            else 2147483647
        )
        try:
            item = await asyncio.to_thread(
                upstream_store.update,
                upstream_id,
                {"blocked_until": blocked_until, "blocked_reason": payload.reason},
            )
        except KeyError:
            raise StarletteHTTPException(status_code=404) from None
        except ValueError as exc:
            return _error_payload("invalid_upstream", str(exc), 409)
        if item["ecosystem"] == "npm":
            await reload_npm(principal.user_id)
        await asyncio.to_thread(
            auth_store.record_audit,
            principal.user_id,
            "upstream.block",
            "upstream",
            upstream_id,
        )
        return upstream_store.public(item)

    @app.post("/api/v1/upstreams/{upstream_id}/unblock", include_in_schema=False)
    async def unblock_upstream(upstream_id: str, request: Request) -> dict[str, object]:
        principal = require_principal(request, "upstream:operate")
        require_csrf(request, principal)
        try:
            item = await asyncio.to_thread(
                upstream_store.update,
                upstream_id,
                {"blocked_until": None, "blocked_reason": None},
            )
        except KeyError:
            raise StarletteHTTPException(status_code=404) from None
        if item["ecosystem"] == "npm":
            await reload_npm(principal.user_id)
        await asyncio.to_thread(
            auth_store.record_audit,
            principal.user_id,
            "upstream.unblock",
            "upstream",
            upstream_id,
        )
        return upstream_store.public(item)

    @app.put(
        "/api/v1/ecosystems/{ecosystem}/offline",
        include_in_schema=False,
        response_model=None,
    )
    async def set_offline(
        ecosystem: str, payload: OfflineRequest, request: Request
    ) -> JSONResponse | dict[str, object]:
        principal = require_principal(request, "upstream:operate")
        require_csrf(request, principal)
        try:
            await asyncio.to_thread(
                upstream_store.set_offline, ecosystem, payload.offline
            )
        except ValueError as exc:
            return _error_payload("invalid_ecosystem", str(exc), 404)
        if ecosystem == "npm":
            await reload_npm(principal.user_id)
        await asyncio.to_thread(
            auth_store.record_audit,
            principal.user_id,
            "ecosystem.offline" if payload.offline else "ecosystem.online",
            "ecosystem",
            ecosystem,
        )
        return {"ecosystem": ecosystem, "offline": payload.offline}

    # ---- roles & permission catalogue (docs/33 §5) ----

    def escalation_error(exc: PermissionEscalationError) -> JSONResponse:
        return _error_payload(
            "permission_escalation", exc.message, 403, permissions=exc.permissions,
            fields=[{"field": "permissions" if exc.permissions else "role",
                     "reason_code": "exceeds_own_permissions",
                     "params": {"permissions": exc.permissions}}],
        )

    def require_owner(request: Request) -> Principal:
        principal = require_principal(request, "user:write")
        if "*" not in principal.permissions:
            raise StarletteHTTPException(status_code=403)
        require_csrf(request, principal)
        return principal

    @app.get("/api/v1/permissions", include_in_schema=False)
    async def permissions_catalog(request: Request) -> dict[str, object]:
        # Any signed-in person: the token wizard and "see all permissions" use it.
        require_principal(request)
        return permission_catalog()

    @app.get("/api/v1/roles", include_in_schema=False)
    async def roles(request: Request) -> dict[str, object]:
        require_principal(request, "user:read")
        return {"items": await asyncio.to_thread(auth_store.list_roles)}

    @app.get("/api/v1/roles/{role_id}", include_in_schema=False, response_model=None)
    async def role_detail(role_id: str, request: Request) -> dict[str, object]:
        require_principal(request, "user:read")
        role = await asyncio.to_thread(auth_store.get_role, role_id)
        if role is None:
            raise StarletteHTTPException(status_code=404)
        return role

    @app.post("/api/v1/roles", include_in_schema=False, status_code=201, response_model=None)
    async def create_role(
        payload: CreateRoleRequest, request: Request
    ) -> dict[str, object] | JSONResponse:
        principal = require_owner(request)
        try:
            return await asyncio.to_thread(
                auth_store.create_custom_role,
                payload.name,
                payload.description,
                payload.permissions,
                principal,
            )
        except FieldError as exc:
            return _field_error(exc)
        except PermissionEscalationError as exc:
            return escalation_error(exc)

    @app.patch("/api/v1/roles/{role_id}", include_in_schema=False, response_model=None)
    async def update_role(
        role_id: str, payload: UpdateRoleRequest, request: Request
    ) -> dict[str, object] | JSONResponse:
        principal = require_owner(request)
        try:
            role = await asyncio.to_thread(
                auth_store.update_custom_role,
                role_id,
                principal,
                payload.name,
                payload.description,
                payload.permissions,
            )
        except FieldError as exc:
            return _field_error(exc)
        except PermissionEscalationError as exc:
            return escalation_error(exc)
        if role is None:
            raise StarletteHTTPException(status_code=404)
        return role

    @app.delete("/api/v1/roles/{role_id}", include_in_schema=False, response_model=None)
    async def delete_role(role_id: str, request: Request) -> dict[str, str] | JSONResponse:
        principal = require_owner(request)
        try:
            deleted = await asyncio.to_thread(
                auth_store.delete_custom_role, role_id, principal
            )
        except FieldError as exc:
            return _field_error(exc)
        except RoleInUseError as exc:
            return _error_payload(
                "role_in_use",
                "Move these people to another role first",
                409,
                users=exc.users,
                fields=[{"field": "role", "reason_code": "in_use",
                         "params": {"users": len(exc.users)}}],
            )
        if not deleted:
            raise StarletteHTTPException(status_code=404)
        return {"status": "deleted"}

    @app.get("/api/v1/settings/registration", include_in_schema=False)
    async def registration_policy(request: Request) -> dict[str, object]:
        require_principal(request, "user:read")
        return {
            "enabled": await asyncio.to_thread(
                auth_store.public_registration_enabled
            ),
            "default_role": "viewer",
        }

    @app.patch("/api/v1/settings/registration", include_in_schema=False)
    async def update_registration_policy(
        payload: RegistrationPolicyRequest, request: Request
    ) -> dict[str, object]:
        principal = require_principal(request, "user:write")
        require_csrf(request, principal)
        enabled = await asyncio.to_thread(
            auth_store.set_public_registration,
            payload.enabled,
            principal.user_id,
        )
        return {"enabled": enabled, "default_role": "viewer"}

    # ---- outbound proxies (outbound.py / outbound_api.py) ----

    outbound_services = outbound_registry(active_settings.data_dir)

    def upstream_outbound_entries() -> list[dict[str, object]]:
        return [
            {
                "id": item["id"],
                "name": item["name"],
                "group": item["ecosystem"],
                "proxy_id": item.get("proxy_id"),
            }
            for item in upstream_store.list()
        ]

    def set_upstream_proxy(upstream_id: str, proxy_id: str | None) -> None:
        upstream_store.update(upstream_id, {"proxy_id": proxy_id})

    async def upstream_proxy_changed(entries: list[dict[str, object]]) -> None:
        # The PyPI router re-reads its files per request; Verdaccio needs a reload.
        if any(entry.get("group") == "npm" for entry in entries):
            reloaded = await asyncio.to_thread(reload_verdaccio_best_effort)
            if not reloaded:
                LOGGER.warning("Verdaccio reload after a proxy change failed")

    outbound_services.register(
        OutboundProvider(
            kind="upstream",
            list_entries=upstream_outbound_entries,
            supported_types=lambda entry: upstream_proxy_types(str(entry.get("group"))),
            unsupported_code="proxy_type_unsupported_for_npm",
            set_proxy=set_upstream_proxy,
            read_permission="upstream:read",
            write_permission="upstream:write",
            on_change=upstream_proxy_changed,
        )
    )
    app.include_router(
        build_outbound_router(
            network=network_settings,
            secret_store=secret_store,
            registry=outbound_services,
            require_principal=require_principal,
            require_csrf=require_csrf,
            error_payload=_error_payload,
            record_audit=auth_store.record_audit,
        )
    )

    @app.get("/api/v1/settings/network", include_in_schema=False)
    async def network_policy(request: Request) -> dict[str, object]:
        require_principal(request, "upstream:read")
        return {
            "dns": network_settings.dns().public(),
            "upstream_policy": {
                "allow_private_upstreams": network_settings.allow_private_upstreams()
            },
        }

    @app.get("/api/v1/settings/network/upstream-policy", include_in_schema=False)
    async def upstream_policy(request: Request) -> dict[str, object]:
        require_principal(request, "upstream:write")
        return {"allow_private_upstreams": network_settings.allow_private_upstreams()}

    @app.put("/api/v1/settings/network/upstream-policy", include_in_schema=False)
    async def update_upstream_policy(
        payload: UpstreamPolicyRequest, request: Request
    ) -> dict[str, object]:
        # Opt-in for internal mirrors (RFC1918/ULA/CGNAT, LAN names). Loopback,
        # link-local and metadata addresses stay forbidden regardless.
        principal = require_principal(request, "upstream:write")
        require_csrf(request, principal)
        allowed = await asyncio.to_thread(
            network_settings.save_upstream_policy, payload.allow_private_upstreams
        )
        await asyncio.to_thread(
            auth_store.record_audit,
            principal.user_id,
            "settings.network.upstream_policy",
            "settings",
            f"allow_private_upstreams={str(allowed).lower()}",
            "success",
            request.client.host if request.client else None,
            correlation_id_context.get(),
        )
        return {"allow_private_upstreams": allowed}

    @app.put("/api/v1/settings/network/dns", include_in_schema=False, response_model=None)
    async def update_dns_policy(
        payload: DnsSettingsRequest, request: Request
    ) -> JSONResponse | dict[str, object]:
        # Applies on the next upstream request in every process; no restart needed.
        principal = require_principal(request, "upstream:write")
        require_csrf(request, principal)
        try:
            config = validate_config(payload.model_dump())
        except ValueError as exc:
            return _error_payload("invalid_dns_settings", str(exc), 422)
        await asyncio.to_thread(network_settings.save_dns, config)
        await asyncio.to_thread(
            auth_store.record_audit,
            principal.user_id,
            "settings.network.dns",
            "settings",
            config.mode,
        )
        return {"dns": config.public()}

    @app.post("/api/v1/settings/network/dns-test", include_in_schema=False, response_model=None)
    async def test_dns_policy(
        payload: DnsTestRequest, request: Request
    ) -> JSONResponse | dict[str, object]:
        """Resolve a name with the saved settings, or with unsaved ones to try first."""
        principal = require_principal(request, "upstream:write")
        require_csrf(request, principal)
        current = network_settings.dns()
        try:
            config = (
                validate_config(
                    {
                        "mode": payload.mode or current.mode,
                        "servers": payload.servers
                        if payload.servers is not None
                        else [item.label() for item in current.servers],
                        "timeout_seconds": current.timeout_seconds,
                        "prefer_ipv4": current.prefer_ipv4,
                    }
                )
                if payload.mode or payload.servers is not None
                else current
            )
        except ValueError as exc:
            return _error_payload("invalid_dns_settings", str(exc), 422)
        started = time.perf_counter()
        try:
            addresses = await asyncio.wait_for(
                asyncio.to_thread(resolve_host, payload.hostname, 443, config),
                timeout=config.timeout_seconds * 4 + 1,
            )
            ok = bool(addresses)
        except (OSError, ValueError, TimeoutError):
            addresses, ok = [], False
        return {
            "ok": ok,
            "mode": config.mode,
            "addresses": addresses[:16],
            "latency_ms": round((time.perf_counter() - started) * 1000, 1),
        }

    @app.get("/api/v1/users", include_in_schema=False)
    async def users(request: Request) -> dict[str, object]:
        require_principal(request, "user:read")
        return {"items": await asyncio.to_thread(auth_store.list_users)}

    @app.post("/api/v1/users", include_in_schema=False, status_code=201)
    async def create_user(payload: CreateUserRequest, request: Request) -> dict[str, object]:
        principal = require_principal(request, "user:write")
        require_csrf(request, principal)
        if payload.role == "owner" and principal.role != "owner":
            raise StarletteHTTPException(status_code=403)
        try:
            user_id = await asyncio.to_thread(
                auth_store.create_user,
                payload.username,
                payload.password,
                payload.role,
                principal.user_id,
                payload.display_name,
                payload.email,
                principal.permissions,
                payload.must_change_password,
            )
        except PermissionEscalationError as exc:
            return escalation_error(exc)
        except FieldError as exc:
            # The historical code/status stay; "fields" names the input.
            return _field_error(exc, "invalid_user", 409)
        except ValueError as exc:
            return _error_payload("invalid_user", str(exc), 409)
        return {"id": user_id}

    @app.post("/api/v1/users/invite", include_in_schema=False, status_code=201,
              response_model=None)
    async def invite_user(
        payload: InviteUserRequest, request: Request
    ) -> dict[str, object] | JSONResponse:
        principal = require_principal(request, "user:write")
        require_csrf(request, principal)
        if payload.role == "owner" and principal.role != "owner":
            raise StarletteHTTPException(status_code=403)
        try:
            # The one-time password and link token are in this response only.
            return await asyncio.to_thread(
                auth_store.invite_user,
                payload.display_name,
                payload.email,
                payload.role,
                principal,
                payload.username,
                payload.create_link,
                request.client.host if request.client else None,
                correlation_id_context.get(),
            )
        except PermissionEscalationError as exc:
            return escalation_error(exc)
        except FieldError as exc:
            return _field_error(exc)

    @app.patch("/api/v1/users/{user_id}", include_in_schema=False)
    async def update_user(
        user_id: int, payload: UpdateUserRequest, request: Request
    ) -> dict[str, str]:
        principal = require_principal(request, "user:write")
        require_csrf(request, principal)
        if payload.role == "owner" and principal.role != "owner":
            raise StarletteHTTPException(status_code=403)
        users_before = await asyncio.to_thread(auth_store.list_users)
        target = next((item for item in users_before if item["id"] == user_id), None)
        if target is None:
            raise StarletteHTTPException(status_code=404)
        if target["role"] == "owner" and principal.role != "owner":
            raise StarletteHTTPException(status_code=403)
        try:
            await asyncio.to_thread(
                auth_store.update_user,
                user_id,
                payload.role,
                payload.enabled,
                principal.user_id,
                principal.permissions,
            )
        except PermissionEscalationError as exc:
            return escalation_error(exc)
        except FieldError as exc:
            if exc.status_code == 404:
                raise StarletteHTTPException(status_code=404) from None
            return _field_error(exc, "invalid_user_update", 409)
        except ValueError as exc:
            return _error_payload("invalid_user_update", str(exc), 409)
        return {"status": "updated"}

    def _lifecycle_error(exc: Exception) -> JSONResponse:
        if isinstance(exc, PermissionEscalationError):
            return escalation_error(exc)
        assert isinstance(exc, FieldError)
        if exc.status_code == 404:
            raise StarletteHTTPException(status_code=404) from None
        return _field_error(exc)

    @app.delete("/api/v1/users/{user_id}", include_in_schema=False, response_model=None)
    async def delete_user(user_id: int, request: Request) -> dict[str, str] | JSONResponse:
        principal = require_principal(request, "user:write")
        require_csrf(request, principal)
        try:
            await asyncio.to_thread(
                auth_store.delete_user, user_id, principal,
                request.client.host if request.client else None,
                correlation_id_context.get(),
            )
        except (PermissionEscalationError, FieldError) as exc:
            return _lifecycle_error(exc)
        return {"status": "deleted"}

    @app.post("/api/v1/users/{user_id}/password-reset", include_in_schema=False,
              response_model=None)
    async def reset_user_password(
        user_id: int, request: Request, payload: ResetPasswordRequest | None = None
    ) -> dict[str, object] | JSONResponse:
        principal = require_principal(request, "user:write")
        require_csrf(request, principal)
        try:
            # The one-time password and link token are in this response only.
            return await asyncio.to_thread(
                auth_store.reset_user_password, user_id, principal,
                payload.create_link if payload is not None else True,
                request.client.host if request.client else None,
                correlation_id_context.get(),
            )
        except (PermissionEscalationError, FieldError) as exc:
            return _lifecycle_error(exc)

    @app.post("/api/v1/users/{user_id}/sessions/revoke", include_in_schema=False,
              response_model=None)
    async def revoke_user_sessions(
        user_id: int, request: Request, payload: RevokeSessionsRequest | None = None
    ) -> dict[str, object] | JSONResponse:
        principal = require_principal(request, "user:write")
        require_csrf(request, principal)
        try:
            counts = await asyncio.to_thread(
                auth_store.revoke_user_sessions, user_id, principal,
                payload.include_tokens if payload is not None else False,
                request.client.host if request.client else None,
                correlation_id_context.get(),
            )
        except (PermissionEscalationError, FieldError) as exc:
            return _lifecycle_error(exc)
        return {"status": "revoked", **counts}

    @app.get("/api/v1/tokens", include_in_schema=False)
    async def api_tokens(request: Request) -> dict[str, object]:
        principal = require_principal(request, "token:read")
        return {
            "items": await asyncio.to_thread(
                auth_store.list_api_tokens, principal.user_id
            )
        }

    @app.post("/api/v1/tokens", include_in_schema=False, status_code=201)
    async def create_api_token(
        payload: CreateTokenRequest, request: Request
    ) -> dict[str, object]:
        principal = require_principal(request, "token:write")
        require_csrf(request, principal)
        if principal.token_id is not None:
            # Scopes were only checked against the role, so a narrow, short-lived
            # token could mint a 365-day token with every role permission.
            raise StarletteHTTPException(status_code=403)
        try:
            token_id, token = await asyncio.to_thread(
                auth_store.create_api_token,
                principal.user_id,
                payload.name,
                payload.scopes,
                payload.expires_in_seconds,
            )
        except FieldError as exc:
            return _field_error(exc, "invalid_token", 409)
        except ValueError as exc:
            return _error_payload("invalid_token", str(exc), 409)
        return {"id": token_id, "token": token}

    @app.delete("/api/v1/tokens/{token_id}", include_in_schema=False)
    async def revoke_api_token(token_id: int, request: Request) -> dict[str, str]:
        principal = require_principal(request, "token:write")
        require_csrf(request, principal)
        revoked = await asyncio.to_thread(
            auth_store.revoke_api_token, token_id, principal.user_id
        )
        if not revoked:
            raise StarletteHTTPException(status_code=404)
        return {"status": "revoked"}

    @app.get("/api/v1/audit-events", include_in_schema=False)
    async def audit_events(
        request: Request,
        limit: int = 100,
        before_id: int | None = Query(default=None, ge=1),
        actor_user_id: int | None = Query(default=None, ge=0),
        action: str | None = Query(default=None, max_length=400),
        result: str | None = Query(default=None, max_length=32),
        since: int | None = Query(default=None, ge=0),
        until: int | None = Query(default=None, ge=0),
    ) -> dict[str, object]:
        require_principal(request, "audit:read")
        size = min(max(limit, 1), 500)
        items = await asyncio.to_thread(
            functools.partial(
                auth_store.list_audit, size, before_id=before_id,
                actor_user_id=actor_user_id, action_prefix=action, result=result,
                since=since, until=until,
            )
        )
        # Keyset cursor: pass it back as before_id for the next (older) page.
        next_before_id = items[-1]["id"] if len(items) == size else None
        return {"items": items, "next_before_id": next_before_id}

    @app.get("/api/v1/audit-events/export.csv", include_in_schema=False)
    async def export_audit_events(
        request: Request,
        actor_user_id: int | None = Query(default=None, ge=0),
        action: str | None = Query(default=None, max_length=400),
        result: str | None = Query(default=None, max_length=32),
        since: int | None = Query(default=None, ge=0),
        until: int | None = Query(default=None, ge=0),
    ) -> Response:
        principal = require_principal(request, "audit:read")
        fields = [
            "id",
            "actor_user_id",
            "action",
            "object_type",
            "object_id",
            "result",
            "source_ip",
            "request_id",
            "occurred_at",
        ]
        # Recorded before streaming so the export itself is in the file, and the
        # snapshot is bounded: rows written while streaming are not chased.
        await asyncio.to_thread(
            auth_store.record_audit,
            principal.user_id,
            "audit.export",
            "audit",
            "csv",
        )
        batch_size = 500

        async def rows_csv() -> AsyncIterator[str]:
            output = io.StringIO(newline="")
            writer = csv.DictWriter(output, fieldnames=fields, extrasaction="ignore")
            writer.writeheader()
            yield "\ufeff" + output.getvalue()
            cursor: int | None = None
            while True:
                rows = await asyncio.to_thread(
                    functools.partial(
                        auth_store.list_audit, batch_size, before_id=cursor,
                        actor_user_id=actor_user_id, action_prefix=action, result=result,
                        since=since, until=until,
                    )
                )
                if not rows:
                    return
                output.seek(0)
                output.truncate(0)
                for row in rows:
                    writer.writerow({key: _csv_cell(row.get(key)) for key in fields})
                yield output.getvalue()
                if len(rows) < batch_size:
                    return
                cursor = int(rows[-1]["id"])  # type: ignore[call-overload]

        return StreamingResponse(
            rows_csv(),
            media_type="text/csv; charset=utf-8",
            headers={"Content-Disposition": 'attachment; filename="mrk-audit.csv"'},
        )

    @app.get("/metrics", include_in_schema=False)
    async def prometheus_metrics(request: Request) -> PlainTextResponse:
        require_principal(request, "system:read")
        total_bytes, used_bytes, free_bytes = await asyncio.to_thread(
            shutil.disk_usage, active_settings.data_dir
        )
        task_stats = await asyncio.to_thread(task_manager.stats)
        upstream_items = await asyncio.to_thread(upstream_store.list)
        health, _router_raw = await components.component_health(
            active_settings, database.engine
        )
        component_ready = {
            "control_plane": 1,
            "npm_registry": int(health["npm_registry"].state == "ready"),
            "pypi_registry": int(health["pypi_registry"].state == "ready"),
            "pypi_upstream_router": int(
                health["pypi_upstream_router"].state in {"ready", "offline"}
            ),
            "database": int(health["database"].state == "ready"),
        }
        lines = [
            "# HELP mrk_uptime_seconds Control plane uptime in seconds.",
            "# TYPE mrk_uptime_seconds gauge",
            f"mrk_uptime_seconds {max(0, int(time.monotonic() - app.state.started_at))}",
            "# HELP mrk_storage_bytes Storage capacity by state.",
            "# TYPE mrk_storage_bytes gauge",
            f'mrk_storage_bytes{{state="total"}} {total_bytes}',
            f'mrk_storage_bytes{{state="used"}} {used_bytes}',
            f'mrk_storage_bytes{{state="free"}} {free_bytes}',
            "# HELP mrk_component_ready Whether a component is ready.",
            "# TYPE mrk_component_ready gauge",
        ]
        lines.extend(
            f'mrk_component_ready{{component="{name}"}} {value}'
            for name, value in component_ready.items()
        )
        lines.extend(
            [
                "# HELP mrk_tasks_total Tasks by lifecycle state.",
                "# TYPE mrk_tasks_total gauge",
            ]
        )
        lines.extend(
            f'mrk_tasks_total{{state="{state}"}} {count}'
            for state, count in task_stats.items()
        )
        for ecosystem in ("npm", "pypi"):
            enabled = sum(
                1
                for item in upstream_items
                if item.get("ecosystem") == ecosystem and item.get("enabled") is True
            )
            lines.append(
                f'mrk_upstreams_enabled{{ecosystem="{ecosystem}"}} {enabled}'
            )
            lines.append(
                f'mrk_offline_mode{{ecosystem="{ecosystem}"}} '
                f'{int(upstream_store.offline(ecosystem))}'
            )
        return PlainTextResponse(
            "\n".join(lines) + "\n",
            media_type="text/plain; version=0.0.4; charset=utf-8",
        )

    @app.get("/api/v1/support-bundle", include_in_schema=False)
    async def support_bundle(request: Request) -> Response:
        principal = require_principal(request, "audit:read")
        status = await system_status(request)
        upstream_items = await asyncio.to_thread(upstream_store.list)
        tasks = await asyncio.to_thread(task_manager.list, 200)
        audit = await asyncio.to_thread(auth_store.list_audit, 500)
        packages = await asyncio.to_thread(package_catalog.search, "", None, 500)
        payloads = {
            "manifest.json": {
                "format": 1,
                "generated_at": int(time.time()),
                "version": __version__,
                "contains_secrets": False,
                "notice": "Raw logs and credential material are intentionally excluded.",
            },
            "system.json": status,
            "upstreams.json": {"items": upstream_items},
            "tasks.json": {"items": tasks},
            "audit.json": {"items": audit},
            "packages.json": {"items": packages},
        }
        buffer = io.BytesIO()
        with zipfile.ZipFile(
            buffer, mode="w", compression=zipfile.ZIP_DEFLATED, compresslevel=6
        ) as archive:
            for name, payload in payloads.items():
                archive.writestr(
                    name,
                    json.dumps(payload, ensure_ascii=False, indent=2, default=str),
                )
        await asyncio.to_thread(
            auth_store.record_audit,
            principal.user_id,
            "support.bundle.export",
            "support_bundle",
            None,
        )
        return Response(
            content=buffer.getvalue(),
            media_type="application/zip",
            headers={
                "Content-Disposition": 'attachment; filename="mrk-support-bundle.zip"'
            },
        )

    @app.get("/api/v1/packages", include_in_schema=False)
    async def packages(
        request: Request,
        q: str = Query(default="", max_length=200),
        ecosystem: str | None = Query(default=None),
        limit: int = Query(default=100, ge=1, le=500),
    ) -> dict[str, object]:
        require_principal(request, "cache:read")
        if ecosystem is not None and ecosystem not in {"npm", "pypi"}:
            return {"items": [], "count": 0}
        items = await asyncio.to_thread(package_catalog.search, q, ecosystem, limit)
        return {"items": items, "count": len(items)}

    @app.put(
        "/api/v1/packages/{ecosystem}/{name:path}/policy",
        include_in_schema=False,
        response_model=None,
    )
    async def set_package_policy(
        ecosystem: str,
        name: str,
        payload: PackagePolicyRequest,
        request: Request,
    ) -> JSONResponse | dict[str, object]:
        principal = require_principal(request, "cache:write")
        require_csrf(request, principal)
        if payload.quarantined and not payload.quarantine_reason:
            return _error_payload(
                "quarantine_reason_required", "A quarantine reason is required", 409
            )
        if not valid_package_name(ecosystem, name):
            # The name ends up in the Verdaccio config and the audit log.
            return _error_payload("invalid_package", "Invalid package name", 409)
        try:
            policy = await asyncio.to_thread(
                package_catalog.set_policy,
                ecosystem,
                name,
                payload.pinned,
                payload.quarantined,
                payload.quarantine_reason,
            )
        except ValueError as exc:
            return _error_payload("invalid_package", str(exc), 409)
        await asyncio.to_thread(
            auth_store.record_audit,
            principal.user_id,
            "package.policy",
            "package",
            f"{ecosystem}:{name}",
        )
        if payload.quarantined is not None:
            # Quarantine is enforced on the serving path: Verdaccio denies the
            # name after a reload, and the PyPI router 404s it immediately.
            if ecosystem == "npm":
                await reload_npm(principal.user_id)
            elif payload.quarantined:
                await purge_quarantined_pypi(name, principal.user_id)
        return policy

    async def audit_op(
        principal: Principal,
        action: str,
        object_type: str,
        object_id: str | None,
        result: str = "success",
    ) -> None:
        await asyncio.to_thread(
            auth_store.record_audit,
            principal.user_id,
            action,
            object_type,
            None if object_id is None else object_id[:255],
            result,
        )

    @app.get("/api/v1/packages/trash", include_in_schema=False)
    async def package_trash(request: Request) -> dict[str, object]:
        require_principal(request, "cache:read")
        return {"items": await asyncio.to_thread(task_manager.list_trash)}

    @app.post(
        "/api/v1/packages/trash/{trash_id}/restore",
        include_in_schema=False,
        response_model=None,
    )
    async def restore_package_trash(
        trash_id: str, request: Request
    ) -> JSONResponse | dict[str, object]:
        principal = require_principal(request, "cache:write")
        require_csrf(request, principal)
        if not TRASH_ID.match(trash_id):
            raise StarletteHTTPException(status_code=404)
        await audit_op(principal, "package.trash.restore", "trash", trash_id, "attempt")
        try:
            restored = await asyncio.to_thread(task_manager.restore_trash, trash_id)
        except KeyError:
            await audit_op(principal, "package.trash.restore", "trash", trash_id, "failure")
            raise StarletteHTTPException(status_code=404) from None
        except (FileExistsError, FileNotFoundError, OSError) as exc:
            await audit_op(principal, "package.trash.restore", "trash", trash_id, "failure")
            return _error_payload("trash_restore_conflict", str(exc), 409)
        await audit_op(principal, "package.trash.restore", "trash", trash_id)
        return {**restored, "status": "restored"}

    @app.delete(
        "/api/v1/packages/trash/{trash_id}",
        include_in_schema=False,
        response_model=None,
    )
    async def delete_package_trash(
        trash_id: str, payload: TrashDeleteRequest, request: Request
    ) -> JSONResponse | dict[str, object]:
        principal = require_principal(request, "cache:write")
        require_csrf(request, principal)
        if not TRASH_ID.match(trash_id):
            raise StarletteHTTPException(status_code=404)
        if payload.confirmation.strip() != f"DELETE {trash_id}":
            return _error_payload(
                "confirmation_mismatch", f"Type DELETE {trash_id} to confirm", 400
            )
        await audit_op(principal, "package.trash.delete", "trash", trash_id, "attempt")
        try:
            deleted = await asyncio.to_thread(task_manager.delete_trash, trash_id)
        except KeyError:
            await audit_op(principal, "package.trash.delete", "trash", trash_id, "failure")
            raise StarletteHTTPException(status_code=404) from None
        except OSError as exc:
            await audit_op(principal, "package.trash.delete", "trash", trash_id, "failure")
            return _error_payload("trash_delete_failed", str(exc), 409)
        await audit_op(principal, "package.trash.delete", "trash", trash_id)
        return {**deleted, "status": "deleted"}

    @app.post(
        "/api/v1/packages/{ecosystem}/{name:path}/purge-preview",
        include_in_schema=False,
        response_model=None,
    )
    async def package_purge_preview(
        ecosystem: str, name: str, request: Request
    ) -> JSONResponse | dict[str, object]:
        principal = require_principal(request, "cache:write")
        require_csrf(request, principal)
        try:
            return await asyncio.to_thread(
                package_catalog.purge_preview, ecosystem, name
            )
        except KeyError:
            raise StarletteHTTPException(status_code=404) from None

    @app.post(
        "/api/v1/packages/{ecosystem}/{name:path}/purge",
        include_in_schema=False,
        status_code=202,
        response_model=None,
    )
    async def purge_package(
        ecosystem: str,
        name: str,
        payload: PurgePackageRequest,
        request: Request,
    ) -> JSONResponse | dict[str, str]:
        principal = require_principal(request, "task:write")
        require_csrf(request, principal)
        try:
            preview = await asyncio.to_thread(
                package_catalog.purge_preview, ecosystem, name
            )
        except KeyError:
            raise StarletteHTTPException(status_code=404) from None
        object_id = f"{ecosystem}:{preview['name']}"
        if payload.confirmation.strip() != preview["confirmation"]:
            await audit_op(principal, "package.purge", "package", object_id, "failure")
            return _error_payload(
                "confirmation_mismatch", "Purge confirmation does not match", 409
            )
        if preview["blocked_by_pin"]:
            await audit_op(principal, "package.purge", "package", object_id, "failure")
            return _error_payload("package_pinned", "Package is pinned", 409)
        await audit_op(principal, "package.purge", "package", object_id, "attempt")
        task_id = await asyncio.to_thread(
            task_manager.enqueue,
            "package.purge",
            {
                "ecosystem": ecosystem,
                "name": str(preview["name"]),
                "confirmation": str(preview["confirmation"]),
            },
            principal.user_id,
        )
        await audit_op(principal, "package.purge.enqueue", "task", task_id)
        return {"task_id": task_id, "state": "pending"}

    @app.post(
        "/api/v1/packages/{ecosystem}/{name:path}/revalidate",
        include_in_schema=False,
        status_code=202,
        response_model=None,
    )
    async def revalidate_package(
        ecosystem: str, name: str, request: Request
    ) -> JSONResponse | dict[str, str]:
        principal = require_principal(request, "task:write")
        require_csrf(request, principal)
        if ecosystem not in {"npm", "pypi"} or not valid_package_name(ecosystem, name):
            raise StarletteHTTPException(status_code=404)
        object_id = f"{ecosystem}:{name}"
        if await asyncio.to_thread(package_catalog.is_quarantined, ecosystem, name):
            await audit_op(principal, "package.revalidate", "package", object_id, "failure")
            return _error_payload("package_quarantined", "Package is quarantined", 409)
        # Revalidate deletes the cached copy before re-fetching it.
        await audit_op(principal, "package.revalidate", "package", object_id, "attempt")
        task_id = await asyncio.to_thread(
            task_manager.enqueue,
            "package.revalidate",
            {"ecosystem": ecosystem, "name": name},
            principal.user_id,
        )
        await audit_op(principal, "package.revalidate.enqueue", "task", task_id)
        return {"task_id": task_id, "state": "pending"}

    @app.post(
        "/api/v1/packages/prefetch",
        include_in_schema=False,
        status_code=202,
        response_model=None,
    )
    async def prefetch_packages(
        payload: PrefetchRequest, request: Request
    ) -> JSONResponse | dict[str, str]:
        principal = require_principal(request, "task:write")
        require_csrf(request, principal)
        if payload.ecosystem not in {"npm", "pypi"}:
            return _error_payload("invalid_ecosystem", "Unsupported ecosystem", 409)
        task_id = await asyncio.to_thread(
            task_manager.enqueue,
            "package.prefetch",
            {"ecosystem": payload.ecosystem, "content": payload.content},
            principal.user_id,
        )
        await audit_op(principal, "package.prefetch.enqueue", "task", task_id)
        return {"task_id": task_id, "state": "pending"}

    @app.get("/api/v1/tasks", include_in_schema=False)
    async def tasks(request: Request, limit: int = 100) -> dict[str, object]:
        require_principal(request, "task:read")
        return {"items": await asyncio.to_thread(task_manager.list, limit)}

    @app.post("/api/v1/tasks/{task_id}/cancel", include_in_schema=False)
    async def cancel_task(task_id: str, request: Request) -> dict[str, str]:
        principal = require_principal(request, "task:write")
        require_csrf(request, principal)
        if len(task_id) > 48 or not await asyncio.to_thread(task_manager.cancel, task_id):
            raise StarletteHTTPException(status_code=409)
        await audit_op(principal, "task.cancel", "task", task_id)
        return {"status": "cancel_requested"}

    @app.post(
        "/api/v1/tasks/{task_id}/retry",
        include_in_schema=False,
        status_code=202,
        response_model=None,
    )
    async def retry_task(
        task_id: str, request: Request, payload: TaskRetryRequest | None = None
    ) -> JSONResponse | dict[str, str]:
        principal = require_principal(request, "task:write")
        require_csrf(request, principal)
        if len(task_id) > 48:
            raise StarletteHTTPException(status_code=409)
        await audit_op(principal, "task.retry", "task", task_id, "attempt")
        try:
            retry_id = await asyncio.to_thread(
                task_manager.retry,
                task_id,
                principal.user_id,
                payload.confirmation if payload is not None else None,
            )
        except RetryRejected as exc:
            await audit_op(principal, "task.retry", "task", task_id, "failure")
            return _error_payload(exc.code, str(exc), exc.status_code)
        await audit_op(principal, "task.retry", "task", retry_id)
        return {"task_id": retry_id, "state": "pending"}

    async def cleanup_candidates(
        required: int,
    ) -> tuple[list[dict[str, object]], int]:
        """Oldest unpinned, unquarantined packages until ``required`` bytes add up."""
        if required <= 0:
            return [], 0
        packages = await asyncio.to_thread(package_catalog.all_packages)
        eligible = sorted(
            (
                package
                for package in packages
                if not package.get("pinned") and not package.get("quarantined")
            ),
            key=lambda package: float(package.get("latest_mtime", 0)),
        )
        candidates: list[dict[str, object]] = []
        reclaimable = 0
        for package in eligible:
            if reclaimable >= required:
                break
            size = int(package.get("size_bytes", 0))
            candidates.append(
                {
                    "ecosystem": package["ecosystem"],
                    "name": package["name"],
                    "size_bytes": size,
                    "latest_mtime": package["latest_mtime"],
                    # npm purges go to trash (same disk) until it expires.
                    "frees_space_immediately": package["ecosystem"] == "pypi",
                }
            )
            reclaimable += size
        return candidates, reclaimable

    async def required_reclaim(target_percent: int) -> tuple[int, int, int, int]:
        total_bytes, used_bytes, free_bytes = await asyncio.to_thread(
            shutil.disk_usage, active_settings.data_dir
        )
        target_used = int(total_bytes * (target_percent / 100))
        return total_bytes, used_bytes, free_bytes, max(0, used_bytes - target_used)

    @app.get("/api/v1/lifecycle/cleanup-preview", include_in_schema=False)
    async def cleanup_preview(
        request: Request,
        target_percent: int = Query(default=75, ge=20, le=90),
    ) -> dict[str, object]:
        require_principal(request, "cache:read")
        total_bytes, used_bytes, free_bytes, required = await required_reclaim(
            target_percent
        )
        candidates, reclaimable = await cleanup_candidates(required)
        trash = await asyncio.to_thread(task_manager.list_trash)
        return {
            "target_percent": target_percent,
            "current_percent": round((used_bytes / total_bytes) * 100, 1)
            if total_bytes
            else 0.0,
            "total_bytes": total_bytes,
            "used_bytes": used_bytes,
            "free_bytes": free_bytes,
            "required_reclaim_bytes": required,
            "candidate_reclaim_bytes": reclaimable,
            "candidates": candidates[:500],
            "truncated": len(candidates) > 500,
            "trash_bytes": sum(int(item.get("size_bytes") or 0) for item in trash),
            "dry_run": True,
            # POST /api/v1/lifecycle/cleanup {target_percent, confirmation} purges these.
            "confirmation": cleanup_confirmation(min(len(candidates), MAX_CLEANUP_CANDIDATES)),
        }

    @app.post(
        "/api/v1/lifecycle/cleanup",
        include_in_schema=False,
        status_code=202,
        response_model=None,
    )
    async def start_cleanup(
        payload: LifecycleCleanupRequest, request: Request
    ) -> JSONResponse | dict[str, object]:
        """Enqueue ONE ``lifecycle.cleanup`` task that purges the candidates server-side.

        Candidates come from ``candidates`` (explicit), ``target_bytes`` (oldest
        first until that many bytes) or ``target_percent`` (same as the preview).
        Pinned / quarantined / uncached packages are dropped here and re-checked
        by the worker before each purge.
        """
        principal = require_principal(request, "task:write")
        require_csrf(request, principal)
        modes = [
            payload.candidates is not None,
            payload.target_bytes is not None,
            payload.target_percent is not None,
        ]
        if sum(modes) != 1:
            return _error_payload(
                "cleanup_target_required",
                "Give exactly one of candidates, target_bytes or target_percent",
                422,
            )
        selected: list[dict[str, object]] = []
        skipped: list[dict[str, object]] = []
        if payload.candidates is not None:
            seen: set[str] = set()
            for item in payload.candidates:
                try:
                    preview = await asyncio.to_thread(
                        package_catalog.purge_preview, item.ecosystem, item.name
                    )
                except KeyError:
                    skipped.append(
                        {"ecosystem": item.ecosystem, "name": item.name, "reason": "not_cached"}
                    )
                    continue
                name = str(preview["name"])
                key = f"{item.ecosystem}:{name}"
                if key in seen:
                    continue
                seen.add(key)
                if preview["blocked_by_pin"] or preview.get("quarantined"):
                    skipped.append(
                        {
                            "ecosystem": item.ecosystem,
                            "name": name,
                            "reason": "package_pinned"
                            if preview["blocked_by_pin"]
                            else "package_quarantined",
                        }
                    )
                    continue
                selected.append(
                    {
                        "ecosystem": item.ecosystem,
                        "name": name,
                        "size_bytes": preview.get("size_bytes", 0),
                    }
                )
        else:
            if payload.target_bytes is not None:
                required = payload.target_bytes
            else:
                _total, _used, _free, required = await required_reclaim(
                    int(payload.target_percent or 75)
                )
            candidates, _reclaimable = await cleanup_candidates(required)
            selected = [
                {
                    "ecosystem": item["ecosystem"],
                    "name": item["name"],
                    "size_bytes": item["size_bytes"],
                }
                for item in candidates[:MAX_CLEANUP_CANDIDATES]
            ]
        if not selected:
            return _error_payload(
                "nothing_to_clean", "No package can be cleaned up", 409, skipped=skipped
            )
        expected = cleanup_confirmation(len(selected))
        if payload.confirmation.strip() != expected:
            await audit_op(principal, "lifecycle.cleanup", "lifecycle", "cleanup", "failure")
            return _error_payload(
                "confirmation_mismatch",
                f"Type {expected} to confirm",
                409,
                expected_confirmation=expected,
                candidate_count=len(selected),
            )
        await audit_op(principal, "lifecycle.cleanup", "lifecycle", "cleanup", "attempt")
        task_id = await asyncio.to_thread(
            task_manager.enqueue,
            "lifecycle.cleanup",
            {
                "candidates": [
                    {"ecosystem": item["ecosystem"], "name": item["name"]} for item in selected
                ],
                "target_bytes": payload.target_bytes,
                "target_percent": payload.target_percent,
            },
            principal.user_id,
        )
        await audit_op(principal, "lifecycle.cleanup.enqueue", "task", task_id)
        return {
            "task_id": task_id,
            "state": "pending",
            "kind": "lifecycle.cleanup",
            "candidate_count": len(selected),
            "candidate_reclaim_bytes": sum(
                int(item.get("size_bytes") or 0) for item in selected  # type: ignore[call-overload]
            ),
            "skipped": skipped,
        }

    @app.post("/api/v1/lifecycle/integrity-scan", include_in_schema=False, status_code=202)
    async def enqueue_integrity_scan(
        request: Request,
        full: bool = Query(default=False),
    ) -> dict[str, str]:
        principal = require_principal(request, "task:write")
        require_csrf(request, principal)
        task_id = await asyncio.to_thread(
            task_manager.enqueue, "integrity.scan", {"full": full}, principal.user_id
        )
        await audit_op(principal, "integrity.scan.enqueue", "task", task_id)
        return {"task_id": task_id, "state": "pending"}

    @app.get("/api/v1/backups", include_in_schema=False)
    async def backups(request: Request) -> dict[str, object]:
        require_principal(request, "backup:read")
        return {"items": await asyncio.to_thread(backup_manager.list)}

    @app.post(
        "/api/v1/backups",
        include_in_schema=False,
        status_code=202,
        response_model=None,
    )
    async def create_backup(
        payload: BackupCreateRequest, request: Request
    ) -> JSONResponse | dict[str, object]:
        principal = require_principal(request, "backup:write")
        require_csrf(request, principal)
        await audit_op(principal, "backup.create", "backup", payload.profile, "attempt")
        try:
            task_id = await asyncio.to_thread(
                task_manager.enqueue_backup,
                payload.profile,
                payload.passphrase,
                principal.user_id,
            )
        except ValueError as exc:
            await audit_op(principal, "backup.create", "backup", payload.profile, "failure")
            return _error_payload("backup_rejected", str(exc), 409)
        await audit_op(principal, "backup.create.enqueue", "task", task_id)
        return {"task_id": task_id, "state": "pending", "profile": payload.profile}

    @app.get(
        "/api/v1/backups/{backup_ref}/download",
        include_in_schema=False,
        response_model=None,
    )
    async def download_backup(
        backup_ref: str, request: Request
    ) -> StreamingResponse | JSONResponse:
        """Stream one encrypted MRKBKP archive (by filename or backup_id).

        backup:write, not backup:read: the file is the whole appliance's state.
        It is already encrypted and is served byte-for-byte, never decrypted.
        """
        principal = require_principal(request, "backup:write")
        object_id = backup_ref[:128]
        try:
            path, filename, size = await asyncio.to_thread(
                backup_manager.resolve_download, backup_ref
            )
            # Opened before responding so a concurrent prune cannot cut the stream.
            handle = await asyncio.to_thread(path.open, "rb")
        except FileNotFoundError:
            await audit_op(principal, "backup.download", "backup", object_id, "failure")
            return _error_payload("backup_not_found", "Backup was not found", 404)
        except (OSError, ValueError):
            await audit_op(principal, "backup.download", "backup", object_id, "failure")
            return _error_payload("backup_download_rejected", "Invalid backup", 409)
        await audit_op(principal, "backup.download", "backup", filename)
        safe_name = "".join(
            char if char.isalnum() or char in "._-" else "_" for char in filename
        )

        async def body() -> AsyncIterator[bytes]:
            try:
                while True:
                    chunk = await asyncio.to_thread(handle.read, 1024 * 1024)
                    if not chunk:
                        break
                    yield chunk
            finally:
                await asyncio.to_thread(handle.close)

        return StreamingResponse(
            body(),
            media_type="application/octet-stream",
            headers={
                "Content-Disposition": f'attachment; filename="{safe_name}"',
                "Content-Length": str(size),
            },
        )

    @app.post(
        "/api/v1/backups/{filename}/validate",
        include_in_schema=False,
        response_model=None,
    )
    async def validate_backup(
        filename: str, payload: BackupSecretRequest, request: Request
    ) -> JSONResponse | dict[str, object]:
        principal = require_principal(request, "backup:write")
        require_csrf(request, principal)
        if len(filename) > 128:
            return _error_payload("backup_validation_failed", "Invalid backup filename", 409)
        try:
            result = await asyncio.to_thread(
                backup_manager.validate, filename, payload.passphrase
            )
        except (OSError, ValueError, KeyError):
            await asyncio.to_thread(
                auth_store.record_audit,
                principal.user_id,
                "backup.validate",
                "backup",
                filename,
                "failure",
            )
            return _error_payload(
                "backup_validation_failed", "Backup could not be validated", 409
            )
        await asyncio.to_thread(
            auth_store.record_audit,
            principal.user_id,
            "backup.validate",
            "backup",
            filename,
        )
        return result

    @app.post(
        "/api/v1/backups/{filename}/restore-plan",
        include_in_schema=False,
        response_model=None,
    )
    async def create_restore_plan(
        filename: str, payload: RestorePlanRequest, request: Request
    ) -> JSONResponse | dict[str, object]:
        principal = require_principal(request, "backup:write")
        require_csrf(request, principal)
        if len(filename) > 128:
            return _error_payload("restore_plan_rejected", "Invalid backup filename", 409)
        try:
            plan = await asyncio.to_thread(
                backup_manager.create_restore_plan,
                filename,
                payload.passphrase,
                payload.confirmation,
                principal.user_id,
            )
        except (OSError, ValueError, KeyError):
            await asyncio.to_thread(
                auth_store.record_audit,
                principal.user_id,
                "backup.restore.plan",
                "backup",
                filename,
                "failure",
            )
            return _error_payload(
                "restore_plan_rejected", "Restore plan could not be created", 409
            )
        await asyncio.to_thread(
            auth_store.record_audit,
            principal.user_id,
            "backup.restore.plan",
            "backup",
            filename,
        )
        return {
            **plan,
            "requires_offline_apply": True,
            "passphrase_persisted": False,
            "apply_command": (
                "mrk-restore apply --plan "
                f"{plan['plan_id']} --passphrase-file /run/secrets/mrk_restore "
                f"--confirmation \"{plan['apply_confirmation']}\" "
                "--offline-confirm I_HAVE_STOPPED_MRK"
            ),
        }

    from .modules import register_all

    module_ctx = ModuleContext(
        settings=active_settings,
        data_dir=active_settings.data_dir,
        database=database,
        auth_store=auth_store,
        secret_store=secret_store,
        network_settings=network_settings,
        events=events,
        require_principal=require_principal,
        require_csrf=require_csrf,
        error_payload=_error_payload,
        trusted_hosts=trusted_hosts,
    )
    app.state.modules = register_all(module_ctx)
    from .modules import tenancy as tenancy_module

    app.state.tenancy = tenancy_module.ACTIVE_SERVICE
    app.state.events = events
    module_state["ctx"] = module_ctx
    for router in module_ctx.routers:
        app.include_router(router)

    # ---- settings registry (settings_registry*.py, docs/27 §1.6) ----
    from .settings_registry_api import build_registry_router, collect_module_services

    app.include_router(
        build_registry_router(
            data_dir=active_settings.data_dir,
            services=collect_module_services(),
            network=network_settings,
            auth_store=auth_store,
            require_principal=require_principal,
            require_csrf=require_csrf,
            error_payload=_error_payload,
            client_context=lambda request: (
                request.client.host if request.client else None,
                correlation_id_context.get(),
            ),
        )
    )
    # ---- end settings registry ----

    if active_settings.admin_ui_dir and active_settings.admin_ui_dir.is_dir():
        app.mount(
            "/",
            StaticFiles(directory=active_settings.admin_ui_dir, html=True),
            name="admin-ui",
        )

    return app


app = create_app()


def run() -> None:
    settings = Settings.from_env()
    # Behind a reverse proxy, client IPs (login throttling, audit) are only
    # trustworthy when forwarded headers come from a known proxy address.
    uvicorn.run(
        "mrk_control_plane.main:app",
        host=settings.host,
        port=settings.port,
        log_config=None,
        access_log=True,
        proxy_headers=True,
        forwarded_allow_ips=os.getenv("MRK_TRUSTED_PROXIES", "127.0.0.1"),
    )
