from __future__ import annotations

import asyncio
import csv
import io
import json
import logging
import os
import shutil
import sqlite3
import time
import zipfile
from contextlib import asynccontextmanager, suppress
from pathlib import Path
from typing import Literal

import uvicorn
from fastapi import FastAPI, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.trustedhost import TrustedHostMiddleware

from . import __version__
from .auth import ROLE_PERMISSIONS, AuthStore, Principal
from .backup import BackupManager
from .catalog import PackageCatalog
from .components import check_http_component, fetch_json_component
from .config import Settings
from .database import Database, database_health
from .logging_config import configure_logging
from .middleware import RequestSecurityMiddleware, correlation_id_context
from .process_control import restart_verdaccio_if_managed
from .secret_store import SecretStore
from .tasks import TaskManager
from .upstream_health import UpstreamHealthStore
from .upstream_probe import probe_upstream
from .upstream_store import UpstreamStore

LOGGER = logging.getLogger(__name__)
DATA_DIRECTORIES = (
    "control-plane",
    "database/pglite",
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


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


class SetupOwnerRequest(BaseModel):
    display_name: str = Field(min_length=2, max_length=100)
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=14, max_length=256)
    password_confirmation: str = Field(min_length=14, max_length=256)


class RegistrationPolicyRequest(BaseModel):
    enabled: bool


class CreateUserRequest(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=14, max_length=256)
    role: str


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


class UpdateUpstreamRequest(BaseModel):
    name: str | None = Field(default=None, min_length=2, max_length=80)
    url: str | None = Field(default=None, min_length=8, max_length=2048)
    priority: int | None = Field(default=None, ge=1, le=10000)
    timeout_seconds: int | None = Field(default=None, ge=1, le=300)
    enabled: bool | None = None


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


class ReplaceUpstreamCredentialRequest(BaseModel):
    credential_type: Literal["bearer", "basic"]
    token: str | None = Field(default=None, min_length=1, max_length=4096)
    username: str | None = Field(default=None, min_length=1, max_length=256)
    password: str | None = Field(default=None, min_length=1, max_length=4096)


class PackagePolicyRequest(BaseModel):
    pinned: bool | None = None
    quarantined: bool | None = None
    quarantine_reason: str | None = Field(default=None, max_length=256)


class PurgePackageRequest(BaseModel):
    confirmation: str = Field(min_length=8, max_length=300)


class PrefetchRequest(BaseModel):
    ecosystem: str
    content: str = Field(min_length=1, max_length=1_000_000)


class BackupSecretRequest(BaseModel):
    passphrase: str = Field(min_length=16, max_length=1024)


class RestorePlanRequest(BackupSecretRequest):
    confirmation: str = Field(min_length=8, max_length=256)


def _prepare_data_directories(root: Path) -> None:
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    for relative_path in DATA_DIRECTORIES:
        path = root / relative_path
        path.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            os.chmod(path, 0o700)
        except OSError:
            LOGGER.warning("unable to enforce directory mode", extra={"directory": relative_path})


def _error_payload(code: str, message: str, status_code: int) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={
            "error": {
                "code": code,
                "message": message,
                "request_id": correlation_id_context.get(),
            }
        },
    )


def _csv_cell(value: object) -> str:
    text = "" if value is None else str(value)
    if text.startswith(("=", "+", "-", "@")):
        return f"'{text}"
    return text


def create_app(settings: Settings | None = None) -> FastAPI:
    active_settings = settings or Settings.from_env()
    configure_logging(active_settings.log_level)
    database = Database(active_settings.data_dir, active_settings.database_url)
    auth_store = AuthStore(
        active_settings.data_dir,
        active_settings.session_ttl_seconds,
        database=database,
    )
    upstream_store = UpstreamStore(active_settings.data_dir)
    upstream_health = UpstreamHealthStore(database)
    secret_store = SecretStore(active_settings.data_dir)
    package_catalog = PackageCatalog(active_settings.data_dir)
    task_manager = TaskManager(active_settings.data_dir, package_catalog, database=database)
    backup_manager = BackupManager(active_settings.data_dir, __version__, database=database)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        _prepare_data_directories(active_settings.data_dir)
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
        app.state.ready = True
        heartbeat_path = active_settings.data_dir / "control-plane" / "runtime-heartbeat"

        async def heartbeat() -> None:
            while True:
                temporary = heartbeat_path.with_suffix(".tmp")
                temporary.write_text(f"{int(time.time())}\n", encoding="utf-8")
                temporary.chmod(0o600)
                temporary.replace(heartbeat_path)
                await asyncio.sleep(5)

        heartbeat_worker = asyncio.create_task(heartbeat(), name="mrk-heartbeat")
        task_worker = asyncio.create_task(task_manager.run(), name="mrk-task-worker")
        LOGGER.info("control plane started")
        try:
            yield
        finally:
            app.state.ready = False
            heartbeat_worker.cancel()
            with suppress(asyncio.CancelledError):
                await heartbeat_worker
            heartbeat_path.unlink(missing_ok=True)
            await task_manager.stop()
            await task_worker
            database.dispose()
            LOGGER.info("control plane stopped")

    app = FastAPI(
        title="MRK Package Mirror",
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
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=list(active_settings.trusted_hosts))
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
        public_message = "Not found" if exc.status_code == 404 else "Request failed"
        return _error_payload("http_error", public_message, exc.status_code)

    @app.exception_handler(RequestValidationError)
    async def validation_error(_request: Request, _exc: RequestValidationError) -> JSONResponse:
        return _error_payload("validation_error", "Request validation failed", 422)

    @app.exception_handler(Exception)
    async def unexpected_error(_request: Request, exc: Exception) -> JSONResponse:
        LOGGER.exception("unhandled request failure", exc_info=exc)
        return _error_payload("internal_error", "Internal server error", 500)

    @app.get("/health/live", include_in_schema=False)
    async def liveness() -> dict[str, str]:
        return {"status": "ok"}

    async def npm_is_ready() -> bool:
        if not active_settings.npm_enabled:
            return True
        return await asyncio.to_thread(
            check_http_component,
            active_settings.npm_health_host,
            active_settings.npm_health_port,
            "/-/ping",
        )

    async def pypi_is_ready() -> bool:
        if not active_settings.pypi_enabled:
            return True
        if (
            active_settings.pypi_bootstrap_state_file is not None
            and not active_settings.pypi_bootstrap_state_file.is_file()
        ):
            return False
        return await asyncio.to_thread(
            check_http_component,
            active_settings.pypi_health_host,
            active_settings.pypi_health_port,
            "/+status",
        )

    async def pypi_router_status() -> dict[str, object] | None:
        if not active_settings.pypi_enabled:
            return None
        return await asyncio.to_thread(
            fetch_json_component,
            active_settings.pypi_router_health_host,
            active_settings.pypi_router_health_port,
            "/status",
        )

    @app.get("/health/ready", include_in_schema=False, response_model=None)
    async def readiness(request: Request) -> JSONResponse | dict[str, str]:
        if not request.app.state.ready:
            return JSONResponse(status_code=503, content={"status": "not_ready"})
        if not await npm_is_ready():
            return JSONResponse(
                status_code=503,
                content={"status": "not_ready", "component": "npm_registry"},
            )
        if not await pypi_is_ready():
            return JSONResponse(
                status_code=503,
                content={"status": "not_ready", "component": "pypi_registry"},
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
        if permission is not None and not principal.allows(permission):
            raise StarletteHTTPException(status_code=403)
        return principal

    def require_csrf(request: Request, principal: Principal) -> None:
        if principal.token_id is not None:
            return
        if not auth_store.verify_csrf(principal, request.headers.get("x-csrf-token")):
            raise StarletteHTTPException(status_code=403)

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
        }

    @app.get("/api/v1/auth/setup-status", include_in_schema=False)
    async def setup_status() -> dict[str, object]:
        required = not await asyncio.to_thread(auth_store.has_users)
        return {"required": required}

    @app.get("/api/v1/auth/registration-status", include_in_schema=False)
    async def registration_status() -> dict[str, bool]:
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
            return _error_payload("password_mismatch", "Passwords do not match", 422)
        try:
            identifier = await asyncio.to_thread(
                auth_store.setup_owner,
                payload.display_name,
                payload.email,
                payload.password,
                request.client.host if request.client else None,
                correlation_id_context.get(),
            )
        except (ValueError, sqlite3.IntegrityError):
            return _error_payload("setup_rejected", "First-run setup was rejected", 409)
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
            return _error_payload("password_mismatch", "Passwords do not match", 422)
        try:
            identifier = await asyncio.to_thread(
                auth_store.register_public_user,
                payload.display_name,
                payload.email,
                payload.password,
                request.client.host if request.client else None,
                correlation_id_context.get(),
            )
        except ValueError:
            return _error_payload(
                "registration_rejected", "Registration is unavailable", 409
            )
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
            }
        )
        set_session_cookie(response, token)
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
        csrf = await asyncio.to_thread(auth_store.issue_csrf, principal)
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
        npm_status = "not_configured"
        if active_settings.npm_enabled:
            npm_status = "ready" if await npm_is_ready() else "unavailable"
        pypi_status = "not_configured"
        if active_settings.pypi_enabled:
            pypi_status = "ready" if await pypi_is_ready() else "unavailable"
        router_status = await pypi_router_status()
        database_ready = await asyncio.to_thread(database_health, database.engine)
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
                "database": "ready" if database_ready else "unavailable",
                "npm_registry": npm_status,
                "pypi_registry": pypi_status,
                "pypi_upstream_router": (
                    "offline"
                    if router_status and router_status.get("offline") is True
                    else "ready"
                    if router_status is not None
                    else "not_configured"
                    if not active_settings.pypi_enabled
                    else "unavailable"
                ),
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
        try:
            item = await asyncio.to_thread(
                upstream_store.create,
                payload.name,
                payload.ecosystem,
                payload.url,
                payload.priority,
                payload.timeout_seconds,
            )
        except ValueError as exc:
            return _error_payload("invalid_upstream", str(exc), 409)
        if item["ecosystem"] == "npm":
            await asyncio.to_thread(restart_verdaccio_if_managed)
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
        try:
            if payload.upstream_id is not None:
                item = await asyncio.to_thread(upstream_store.get, payload.upstream_id)
                probe_url = str(item["url"])
                probe_timeout = min(int(item["timeout_seconds"]), 30)
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
                authorization = None
            else:
                return _error_payload(
                    "invalid_upstream", "upstream_id or url is required", 422
                )
            result = await probe_upstream(probe_url, probe_timeout, authorization)
        except KeyError:
            raise StarletteHTTPException(status_code=404) from None
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
            await asyncio.to_thread(restart_verdaccio_if_managed)
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
            await asyncio.to_thread(restart_verdaccio_if_managed)
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
        try:
            item = await asyncio.to_thread(upstream_store.update, upstream_id, changes)
        except KeyError:
            raise StarletteHTTPException(status_code=404) from None
        except ValueError as exc:
            return _error_payload("invalid_upstream", str(exc), 409)
        if item["ecosystem"] == "npm":
            await asyncio.to_thread(restart_verdaccio_if_managed)
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
            await asyncio.to_thread(restart_verdaccio_if_managed)
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
        if item["ecosystem"] == "npm":
            await asyncio.to_thread(restart_verdaccio_if_managed)
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
            await asyncio.to_thread(restart_verdaccio_if_managed)
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
            await asyncio.to_thread(restart_verdaccio_if_managed)
        await asyncio.to_thread(
            auth_store.record_audit,
            principal.user_id,
            "ecosystem.offline" if payload.offline else "ecosystem.online",
            "ecosystem",
            ecosystem,
        )
        return {"ecosystem": ecosystem, "offline": payload.offline}

    @app.get("/api/v1/roles", include_in_schema=False)
    async def roles(request: Request) -> dict[str, object]:
        require_principal(request, "user:read")
        return {
            "items": [
                {"name": name, "permissions": sorted(permissions)}
                for name, permissions in ROLE_PERMISSIONS.items()
            ]
        }

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
            )
        except (ValueError, sqlite3.IntegrityError) as exc:
            return _error_payload("invalid_user", str(exc), 409)
        return {"id": user_id}

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
            )
        except ValueError as exc:
            return _error_payload("invalid_user_update", str(exc), 409)
        return {"status": "updated"}

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
        try:
            token_id, token = await asyncio.to_thread(
                auth_store.create_api_token,
                principal.user_id,
                payload.name,
                payload.scopes,
                payload.expires_in_seconds,
            )
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
    async def audit_events(request: Request, limit: int = 100) -> dict[str, object]:
        require_principal(request, "audit:read")
        return {"items": await asyncio.to_thread(auth_store.list_audit, limit)}

    @app.get("/api/v1/audit-events/export.csv", include_in_schema=False)
    async def export_audit_events(request: Request) -> Response:
        principal = require_principal(request, "audit:read")
        rows = await asyncio.to_thread(auth_store.list_audit, 500)
        output = io.StringIO(newline="")
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
        writer = csv.DictWriter(output, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({key: _csv_cell(row.get(key)) for key in fields})
        await asyncio.to_thread(
            auth_store.record_audit,
            principal.user_id,
            "audit.export",
            "audit",
            "csv",
        )
        return Response(
            content="\ufeff" + output.getvalue(),
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
        component_ready = {
            "control_plane": 1,
            "npm_registry": int(
                active_settings.npm_enabled and await npm_is_ready()
            ),
            "pypi_registry": int(
                active_settings.pypi_enabled and await pypi_is_ready()
            ),
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
        return policy

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
    )
    async def purge_package(
        ecosystem: str,
        name: str,
        payload: PurgePackageRequest,
        request: Request,
    ) -> dict[str, str]:
        principal = require_principal(request, "task:write")
        require_csrf(request, principal)
        task_id = await asyncio.to_thread(
            task_manager.enqueue,
            "package.purge",
            {
                "ecosystem": ecosystem,
                "name": name,
                "confirmation": payload.confirmation,
            },
            principal.user_id,
        )
        await asyncio.to_thread(
            auth_store.record_audit,
            principal.user_id,
            "package.purge.enqueue",
            "task",
            task_id,
        )
        return {"task_id": task_id, "state": "pending"}

    @app.post(
        "/api/v1/packages/{ecosystem}/{name:path}/revalidate",
        include_in_schema=False,
        status_code=202,
    )
    async def revalidate_package(
        ecosystem: str, name: str, request: Request
    ) -> dict[str, str]:
        principal = require_principal(request, "task:write")
        require_csrf(request, principal)
        task_id = await asyncio.to_thread(
            task_manager.enqueue,
            "package.revalidate",
            {"ecosystem": ecosystem, "name": name},
            principal.user_id,
        )
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
        return {"task_id": task_id, "state": "pending"}

    @app.get("/api/v1/tasks", include_in_schema=False)
    async def tasks(request: Request, limit: int = 100) -> dict[str, object]:
        require_principal(request, "task:read")
        return {"items": await asyncio.to_thread(task_manager.list, limit)}

    @app.post("/api/v1/tasks/{task_id}/cancel", include_in_schema=False)
    async def cancel_task(task_id: str, request: Request) -> dict[str, str]:
        principal = require_principal(request, "task:write")
        require_csrf(request, principal)
        if not await asyncio.to_thread(task_manager.cancel, task_id):
            raise StarletteHTTPException(status_code=409)
        await asyncio.to_thread(
            auth_store.record_audit,
            principal.user_id,
            "task.cancel",
            "task",
            task_id,
        )
        return {"status": "cancel_requested"}

    @app.post("/api/v1/tasks/{task_id}/retry", include_in_schema=False, status_code=202)
    async def retry_task(task_id: str, request: Request) -> dict[str, str]:
        principal = require_principal(request, "task:write")
        require_csrf(request, principal)
        original = await asyncio.to_thread(task_manager.get_retry_payload, task_id)
        if original is None:
            raise StarletteHTTPException(status_code=409)
        kind, payload, _actor = original
        retry_id = await asyncio.to_thread(
            task_manager.enqueue, kind, payload, principal.user_id, task_id
        )
        return {"task_id": retry_id, "state": "pending"}

    @app.get("/api/v1/lifecycle/cleanup-preview", include_in_schema=False)
    async def cleanup_preview(
        request: Request,
        target_percent: int = Query(default=75, ge=20, le=90),
    ) -> dict[str, object]:
        require_principal(request, "cache:read")
        total_bytes, used_bytes, free_bytes = await asyncio.to_thread(
            shutil.disk_usage, active_settings.data_dir
        )
        target_used = int(total_bytes * (target_percent / 100))
        required = max(0, used_bytes - target_used)
        packages = await asyncio.to_thread(package_catalog.search, "", None, 500)
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
            if reclaimable >= required and required > 0:
                break
            size = int(package.get("size_bytes", 0))
            candidates.append(
                {
                    "ecosystem": package["ecosystem"],
                    "name": package["name"],
                    "size_bytes": size,
                    "latest_mtime": package["latest_mtime"],
                }
            )
            reclaimable += size
        if required == 0:
            candidates = []
            reclaimable = 0
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
            "candidates": candidates,
            "truncated": len(packages) >= 500,
            "dry_run": True,
        }

    @app.post("/api/v1/lifecycle/integrity-scan", include_in_schema=False, status_code=202)
    async def enqueue_integrity_scan(
        request: Request,
    ) -> dict[str, str]:
        principal = require_principal(request, "task:write")
        require_csrf(request, principal)
        task_id = await asyncio.to_thread(
            task_manager.enqueue, "integrity.scan", {}, principal.user_id
        )
        await asyncio.to_thread(
            auth_store.record_audit,
            principal.user_id,
            "integrity.scan.enqueue",
            "task",
            task_id,
        )
        return {"task_id": task_id, "state": "pending"}

    @app.get("/api/v1/backups", include_in_schema=False)
    async def backups(request: Request) -> dict[str, object]:
        require_principal(request, "backup:read")
        return {"items": await asyncio.to_thread(backup_manager.list)}

    @app.post("/api/v1/backups", include_in_schema=False, status_code=201)
    async def create_backup(
        payload: BackupSecretRequest, request: Request
    ) -> dict[str, object]:
        principal = require_principal(request, "backup:write")
        require_csrf(request, principal)
        result = await asyncio.to_thread(backup_manager.create, payload.passphrase)
        await asyncio.to_thread(
            auth_store.record_audit,
            principal.user_id,
            "backup.create",
            "backup",
            str(result["backup_id"]),
        )
        return result

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
        try:
            result = await asyncio.to_thread(
                backup_manager.validate, filename, payload.passphrase
            )
        except (FileNotFoundError, ValueError):
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
        try:
            plan = await asyncio.to_thread(
                backup_manager.create_restore_plan,
                filename,
                payload.passphrase,
                payload.confirmation,
                principal.user_id,
            )
        except (FileNotFoundError, ValueError):
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
    uvicorn.run(
        "mrk_control_plane.main:app",
        host=settings.host,
        port=settings.port,
        log_config=None,
        access_log=True,
    )
