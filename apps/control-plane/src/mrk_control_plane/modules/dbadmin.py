"""Native database management module (Gate 19 S9, docs/32 §5) — ``/api/v1/dbadmin``.

A small, safe, built-in Adminer: saved connections (password write-only in the
SecretStore), discovery suggestions from Dokploy and the Host Agent, schema and
table browsing, a query editor and CSV export for PostgreSQL, MySQL/MariaDB,
MongoDB and Redis.

Safety model:

* **Read-only by default.** Write mode needs ``db:write``, ``"write": true`` and
  the typed confirmation ``WRITE <connection name>``; it is audited with the
  statement's SHA-256 (never its text or any data).
* **Destination policy.** Private/LAN and public hosts are allowed; loopback
  (this appliance, PGlite), link-local/cloud metadata, multicast and reserved
  addresses are rejected. The name is resolved once and the checked address is
  what the driver connects to.
* **Bounded work.** Connect and statement timeouts, at most 2 concurrent
  operations per connection, row/cell/response caps, and the control-plane
  database (PGlite) is never held open while a target database is in use.
"""

from __future__ import annotations

import asyncio
import contextlib
import csv
import io
import json
import logging
import os
import re
import secrets
import time
from collections.abc import AsyncIterator, Callable, Iterator
from typing import Any

from fastapi import APIRouter, Query, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select

from ..models import DbAdminConnection
from ..module_context import ModuleContext
from . import dbadmin_engines as engines
from . import dbadmin_policy as policy
from . import dbadmin_sql as sqltext

LOGGER = logging.getLogger(__name__)
MODULE_NAME = "dbadmin"
READ = "db:read"
WRITE = "db:write"
SETTINGS_FILE = "dbadmin.json"
QUEUE_WAIT_SECONDS = 10.0
DOKPLOY_NETWORK = "dokploy-network"
DISCOVER_TIMEOUT_SECONDS = 10.0
DOKPLOY_KEYS = {"postgres": "postgres", "mysql": "mysql", "mariadb": "mariadb",
                "mongo": "mongo", "redis": "redis"}
_ID = re.compile(r"^[0-9a-f]{16}$")

ACTIVE_SERVICE: DbAdminService | None = None


class ApiError(Exception):
    def __init__(self, code: str, message: str, status_code: int = 422) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code


# --- request bodies -------------------------------------------------------------------


class ConnectionCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=80)
    engine: str
    host: str = Field(min_length=1, max_length=255)
    port: int | None = None
    database: str | None = Field(default=None, max_length=128)
    username: str | None = Field(default=None, max_length=128)
    password: str | None = Field(default=None, max_length=1024)
    tls_mode: str = "disable"
    options: dict[str, Any] = Field(default_factory=dict)


class ConnectionPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str | None = Field(default=None, min_length=1, max_length=80)
    engine: str | None = None
    host: str | None = Field(default=None, min_length=1, max_length=255)
    port: int | None = None
    database: str | None = Field(default=None, max_length=128)
    username: str | None = Field(default=None, max_length=128)
    password: str | None = Field(default=None, max_length=1024)
    clear_password: bool = False
    tls_mode: str | None = None
    options: dict[str, Any] | None = None


class ConfirmBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    confirmation: str = Field(min_length=1, max_length=120)


class RedisCommand(BaseModel):
    model_config = ConfigDict(extra="forbid")

    command: str = Field(min_length=1, max_length=32)
    args: list[Any] = Field(default_factory=list)


class QueryBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    text: str | None = Field(default=None, max_length=1_000_000)
    mongo: dict[str, Any] | None = None
    redis: RedisCommand | None = None
    database: str | None = Field(default=None, max_length=128)
    write: bool = False
    dry_run: bool = False
    confirmation: str | None = Field(default=None, max_length=120)


class ExportTable(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=255)
    schema_: str | None = Field(default=None, alias="schema", max_length=128)
    filter: str | list[Any] | dict[str, Any] | None = None
    sort: str | None = Field(default=None, max_length=1000)


class ExportBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    table: ExportTable | None = None
    text: str | None = Field(default=None, max_length=1_000_000)
    mongo: dict[str, Any] | None = None
    max_rows: int | None = Field(default=None, ge=1)
    excel_safe: bool = True


class SettingsBody(BaseModel):
    model_config = ConfigDict(extra="allow")


# --- helpers ----------------------------------------------------------------------------


def write_confirmation(name: str) -> str:
    return f"WRITE {name}"


def network_guide() -> dict[str, Any]:
    snippet = (
        "services:\n"
        "  mrk-mirror:\n"
        "    networks:\n"
        "      - default\n"
        "      - mrk-agent\n"
        f"      - {DOKPLOY_NETWORK}\n"
        "\n"
        "networks:\n"
        f"  {DOKPLOY_NETWORK}:\n"
        "    external: true\n"
    )
    return {
        "network": DOKPLOY_NETWORK,
        "summary": (
            "Databases created in Dokploy listen only on the Docker network "
            f"'{DOKPLOY_NETWORK}'. The MRK container must join that network to reach them; "
            "then use the Dokploy app name (for example my-db-x1y2z3) as host and the "
            "database's internal port."
        ),
        "compose_snippet": snippet,
        "docker_command": f"docker network connect {DOKPLOY_NETWORK} <mrk-container-name>",
        "default_ports": dict(policy.DEFAULT_PORTS),
        "notes": [
            "Add the network to the Pishkar service in your compose file and redeploy, or run "
            "the docker command once (it is lost when the container is recreated).",
            f"'{DOKPLOY_NETWORK}' is created by Dokploy; mark it 'external: true' so compose "
            "never creates or deletes it.",
            "Pishkar does not change Dokploy or its network; joining only lets Pishkar open "
            "connections to the databases you configure.",
            "Prefer a dedicated read-only database user for browsing; write mode is "
            "available to owner/admin with a typed confirmation.",
            "Loopback, link-local and cloud metadata addresses are refused.",
        ],
    }


def _public(row: DbAdminConnection) -> dict[str, Any]:
    return {
        "id": row.id,
        "name": row.name,
        "engine": row.engine,
        "host": row.host,
        "port": row.port,
        "database": row.database,
        "username": row.username,
        "tls_mode": row.tls_mode,
        "options": dict(row.options or {}),
        "password_configured": row.secret_ref is not None,
        "write_confirmation": write_confirmation(row.name),
        "env_hints": policy.ENV_HINTS.get(row.engine, []),
        "last_tested_at": row.last_tested_at,
        "last_test_ok": row.last_test_ok,
        "created_at": row.created_at,
        "updated_at": row.updated_at,
    }


def _filter_text(value: Any) -> str | None:
    if value is None or isinstance(value, str):
        return value
    return json.dumps(value)


# --- service ------------------------------------------------------------------------------


class DbAdminService:
    def __init__(self, ctx: ModuleContext) -> None:
        self.ctx = ctx
        self.settings_path = ctx.data_dir / "control-plane" / SETTINGS_FILE
        self._semaphores: dict[str, asyncio.Semaphore] = {}
        # Tests only: lets integration tests reach throwaway containers on 127.0.0.1.
        self.allow_loopback = False

    # -- settings ------------------------------------------------------------------
    def settings(self) -> dict[str, int]:
        try:
            payload = json.loads(self.settings_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            payload = {}
        return policy.validate_settings(payload, strict=False)

    def save_settings(self, raw: dict[str, Any]) -> dict[str, int]:
        merged = {**self.settings(), **raw}
        validated = policy.validate_settings(merged, strict=True)
        self.settings_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.settings_path.with_name(f".{SETTINGS_FILE}.{secrets.token_hex(4)}.tmp")
        temporary.write_text(json.dumps(validated) + "\n", encoding="utf-8")
        os.replace(temporary, self.settings_path)
        return validated

    def limits(self) -> engines.Limits:
        current = self.settings()
        return engines.Limits(
            max_rows=current["max_rows"],
            max_cell_bytes=current["max_cell_bytes"],
            max_response_bytes=current["max_response_bytes"],
        )

    # -- connections -----------------------------------------------------------------
    def list_connections(self) -> list[dict[str, Any]]:
        with self.ctx.database.session() as db:
            rows = db.scalars(select(DbAdminConnection).order_by(DbAdminConnection.name)).all()
            return [_public(row) for row in rows]

    def get_connection(self, connection_id: str) -> dict[str, Any]:
        with self.ctx.database.session() as db:
            row = db.get(DbAdminConnection, connection_id)
            if row is None:
                raise ApiError("not_found", "connection not found", 404)
            return _public(row)

    @staticmethod
    def _validated(engine: str, raw: dict[str, Any]) -> dict[str, Any]:
        engine = policy.validate_engine(engine)
        port = raw.get("port")
        return {
            "engine": engine,
            "host": policy.validate_host(raw.get("host")),
            "port": policy.validate_port(policy.DEFAULT_PORTS[engine] if port is None else port),
            "database": policy.validate_database(engine, raw.get("database")),
            "username": policy.validate_username(raw.get("username")),
            "tls_mode": policy.validate_tls(raw.get("tls_mode")),
            "options": policy.validate_options(engine, raw.get("options")),
        }

    def create_connection(self, body: ConnectionCreate, user_id: int | None) -> dict[str, Any]:
        name = policy.validate_name(body.name)
        fields = self._validated(body.engine, body.model_dump())
        password = None if body.password in (None, "") else policy.validate_password(body.password)
        reference = None
        if password is not None:
            reference, _ = self.ctx.secret_store.replace(None, {"password": password})
        now = int(time.time())
        try:
            with self.ctx.database.session() as db, db.begin():
                if db.scalar(select(DbAdminConnection).where(DbAdminConnection.name == name)):
                    raise ApiError("name_taken", "a connection with this name exists", 409)
                row = DbAdminConnection(
                    id=secrets.token_hex(8), name=name, secret_ref=reference,
                    created_by_user_id=user_id, created_at=now, updated_at=now, **fields,
                )
                db.add(row)
                db.flush()
                return _public(row)
        except BaseException:
            if reference is not None:
                self.ctx.secret_store.delete(reference)
            raise

    def update_connection(self, connection_id: str, body: ConnectionPatch) -> dict[str, Any]:
        sent = body.model_dump(exclude_unset=True)
        stale_reference: str | None = None
        with self.ctx.database.session() as db, db.begin():
            row = db.get(DbAdminConnection, connection_id)
            if row is None:
                raise ApiError("not_found", "connection not found", 404)
            current = {
                "engine": row.engine, "host": row.host, "port": row.port,
                "database": row.database, "username": row.username, "tls_mode": row.tls_mode,
                "options": dict(row.options or {}),
            }
            merged = {**current, **{k: v for k, v in sent.items() if k in current}}
            if "engine" in sent and sent["engine"] != row.engine and "port" not in sent:
                merged["port"] = None  # new engine: default port
            fields = self._validated(merged["engine"], merged)
            new_password = sent.get("password")
            if new_password == "":
                new_password = None
            # Never send a stored password to a different endpoint or over weaker TLS
            # unless the caller types it again.
            moved = any(fields[key] != current[key] for key in ("engine", "host", "port")) or (
                policy.TLS_MODES.index(fields["tls_mode"])
                < policy.TLS_MODES.index(current["tls_mode"])
            )
            if moved and row.secret_ref is not None and new_password is None and not (
                body.clear_password
            ):
                raise ApiError(
                    "password_required",
                    "re-enter the password when changing engine, host, port or lowering TLS",
                )
            if body.name is not None:
                name = policy.validate_name(body.name)
                if db.scalar(select(DbAdminConnection).where(
                    DbAdminConnection.name == name, DbAdminConnection.id != row.id
                )):
                    raise ApiError("name_taken", "a connection with this name exists", 409)
                row.name = name
            if new_password is not None:
                password = policy.validate_password(new_password)
                row.secret_ref, _ = self.ctx.secret_store.replace(
                    row.secret_ref, {"password": password}
                )
            elif body.clear_password and row.secret_ref is not None:
                stale_reference = row.secret_ref
                row.secret_ref = None
            for key, value in fields.items():
                setattr(row, key, value)
            row.updated_at = int(time.time())
            if moved:
                row.last_tested_at = None
                row.last_test_ok = None
            result = _public(row)
        if stale_reference is not None:
            self.ctx.secret_store.delete(stale_reference)
        return result

    def delete_connection(self, connection_id: str, confirmation: str) -> str:
        with self.ctx.database.session() as db, db.begin():
            row = db.get(DbAdminConnection, connection_id)
            if row is None:
                raise ApiError("not_found", "connection not found", 404)
            if confirmation != row.name:
                raise ApiError("confirmation_required", "type the connection name to delete it")
            reference = row.secret_ref
            name = row.name
            db.delete(row)
        if reference is not None:
            self.ctx.secret_store.delete(reference)
        self._semaphores.pop(connection_id, None)
        return name

    def spec(self, connection_id: str) -> engines.ConnSpec:
        """Load everything needed for I/O, then release the control-plane database."""
        if not _ID.fullmatch(connection_id):
            raise ApiError("not_found", "connection not found", 404)
        with self.ctx.database.session() as db:
            row = db.get(DbAdminConnection, connection_id)
            if row is None:
                raise ApiError("not_found", "connection not found", 404)
            spec = engines.ConnSpec(
                id=row.id, name=row.name, engine=row.engine, host=row.host, port=row.port,
                database=row.database, username=row.username, tls_mode=row.tls_mode,
                options=dict(row.options or {}),
            )
            reference = row.secret_ref
        if reference is not None:
            try:
                spec.password = self.ctx.secret_store.get(reference)["password"]
            except (KeyError, ValueError):
                raise ApiError("secret_unavailable", "the stored password is unreadable", 409)\
                    from None
        current = self.settings()
        spec.connect_timeout = current["connect_timeout_seconds"]
        spec.statement_timeout_ms = current["statement_timeout_ms"]
        return spec

    def record_test(self, connection_id: str, ok: bool) -> None:
        with self.ctx.database.session() as db, db.begin():
            row = db.get(DbAdminConnection, connection_id)
            if row is not None:
                row.last_tested_at = int(time.time())
                row.last_test_ok = ok

    # -- I/O -----------------------------------------------------------------------------
    async def resolve(self, spec: engines.ConnSpec) -> engines.ConnSpec:
        try:
            spec.address = await asyncio.wait_for(
                asyncio.to_thread(
                    policy.resolve_destination, spec.host, spec.port,
                    allow_loopback=self.allow_loopback,
                ),
                timeout=max(spec.connect_timeout, 3),
            )
        except TimeoutError:
            raise ApiError("db_unresolvable", f"host {spec.host} could not be resolved",
                           502) from None
        return spec

    def _semaphore(self, connection_id: str) -> asyncio.Semaphore:
        semaphore = self._semaphores.get(connection_id)
        if semaphore is None:
            semaphore = asyncio.Semaphore(self.settings()["concurrency_per_connection"])
            self._semaphores[connection_id] = semaphore
        return semaphore

    async def run(self, spec: engines.ConnSpec, fn: Callable[[], Any],
                  hard_timeout: float | None = None) -> Any:
        """Run blocking driver work with the per-connection limit and a hard deadline."""
        semaphore = self._semaphore(spec.id)
        try:
            await asyncio.wait_for(semaphore.acquire(), QUEUE_WAIT_SECONDS)
        except TimeoutError:
            raise ApiError("connection_busy", "two operations are already running on this "
                           "connection; try again shortly", 429) from None
        future = asyncio.get_running_loop().run_in_executor(None, fn)

        def _release(done: asyncio.Future[Any]) -> None:
            semaphore.release()
            if not done.cancelled():
                done.exception()  # mark retrieved

        future.add_done_callback(_release)
        deadline = hard_timeout or (spec.connect_timeout + spec.statement_timeout_ms / 1000 + 10)
        try:
            return await asyncio.wait_for(asyncio.shield(future), deadline)
        except TimeoutError:
            raise ApiError("db_timeout", "the database did not answer in time", 504) from None

    async def prepared(self, connection_id: str) -> tuple[engines.ConnSpec, Any]:
        spec = await asyncio.to_thread(self.spec, connection_id)
        await self.resolve(spec)
        return spec, engines.adapter_for(spec, await asyncio.to_thread(self.limits))

    # -- discovery -----------------------------------------------------------------------
    async def discover(self) -> dict[str, Any]:
        existing = await asyncio.to_thread(self.list_connections)
        known = {(item["host"], item["port"]) for item in existing}
        dokploy, agent = await asyncio.gather(self._discover_dokploy(), self._discover_agent())
        for group in (dokploy, agent):
            for item in group["items"]:
                item["configured"] = (item.get("host"), item.get("port")) in known
        return {"dokploy": dokploy, "agent": agent, "network": network_guide()["summary"]}

    async def _discover_dokploy(self) -> dict[str, Any]:
        from . import dokploy

        service = dokploy.ACTIVE_SERVICE
        if service is None:
            return {"available": False, "error_code": "dokploy_unavailable", "items": []}
        try:
            raw = await asyncio.wait_for(service.call("project.all"), DISCOVER_TIMEOUT_SECONDS)
        except TimeoutError:
            return {"available": False, "error_code": "dokploy_timeout", "items": []}
        except Exception as exc:  # noqa: BLE001 - reported as a code
            return {"available": False, "error_code": getattr(exc, "code", "dokploy_error"),
                    "items": []}
        return {"available": True, "items": dokploy_suggestions(raw)}

    async def _discover_agent(self) -> dict[str, Any]:
        from .host_agent import HostAgentService

        try:
            payload = await asyncio.wait_for(
                HostAgentService(self.ctx).call("/v1/backup/sources"), DISCOVER_TIMEOUT_SECONDS
            )
        except TimeoutError:
            return {"available": False, "error_code": "agent_timeout", "items": []}
        except Exception as exc:  # noqa: BLE001 - reported as a code
            return {"available": False, "error_code": getattr(exc, "code", "agent_unavailable"),
                    "items": []}
        return {"available": True, "items": agent_suggestions(payload)}


def dokploy_suggestions(raw: Any) -> list[dict[str, Any]]:
    """Whitelist only non-secret fields from Dokploy ``project.all`` (never passwords)."""
    items: list[dict[str, Any]] = []
    for project in raw if isinstance(raw, list) else []:
        if not isinstance(project, dict):
            continue
        environments = project.get("environments")
        envs = environments if isinstance(environments, list) else [project]
        for env in envs:
            if not isinstance(env, dict):
                continue
            env_name = env.get("name") if env is not project else None
            for engine, key in DOKPLOY_KEYS.items():
                for db in env.get(key) or []:
                    if not isinstance(db, dict):
                        continue
                    app_name = db.get("appName")
                    host = app_name if isinstance(app_name, str) and app_name else None
                    database = db.get("databaseName") if engine not in {"redis"} else None
                    username = db.get("databaseUser") if engine != "redis" else None
                    items.append({
                        "source": "dokploy",
                        "engine": engine,
                        "name": str(db.get("name") or app_name or engine)[:80],
                        "project": str(project.get("name") or "")[:255] or None,
                        "environment": str(env_name)[:255] if env_name else None,
                        "host": host,
                        "port": policy.DEFAULT_PORTS[engine],
                        "database": database if isinstance(database, str) else None,
                        "username": username if isinstance(username, str) else None,
                        "status": str(db.get("applicationStatus") or "unknown")[:32],
                        "password_hint": "Copy the password from Dokploy → the database → "
                        "General → Internal Credentials.",
                        "env_hints": policy.ENV_HINTS[engine],
                        "network": DOKPLOY_NETWORK,
                    })
    return items


def agent_suggestions(payload: Any) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    databases = payload.get("databases") if isinstance(payload, dict) else None
    for item in databases if isinstance(databases, list) else []:
        if not isinstance(item, dict) or item.get("engine") not in policy.ENGINES:
            continue
        engine = item["engine"]
        name = str(item.get("name") or "")[:255]
        items.append({
            "source": "agent",
            "engine": engine,
            "name": name or str(item.get("container_id", ""))[:12],
            "container": name or None,
            "image": str(item.get("image") or "")[:256] or None,
            "state": str(item.get("state") or "")[:32] or None,
            "protected": bool(item.get("protected")),
            "host": name or None,
            "port": policy.DEFAULT_PORTS[engine],
            "password_hint": "Credentials are not read automatically. Look for these "
            "variables in the container's environment.",
            "env_hints": policy.ENV_HINTS[engine],
        })
    return items


# --- CSV streaming ---------------------------------------------------------------------


def csv_chunks(rows: Iterator[list[Any]], *, excel_safe: bool, max_bytes: int,
               chunk_bytes: int = 65536) -> Iterator[bytes]:
    """Encode rows as CSV, yielding ~64 KiB chunks; stops at ``max_bytes``."""
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\r\n")
    total = 0
    for row in rows:
        writer.writerow([policy.csv_cell(value, excel_safe=excel_safe) for value in row])
        if buffer.tell() >= chunk_bytes:
            data = buffer.getvalue().encode("utf-8")
            buffer.seek(0)
            buffer.truncate()
            if total + len(data) > max_bytes:
                return
            total += len(data)
            yield data
    data = buffer.getvalue().encode("utf-8")
    if data and total + len(data) <= max_bytes:
        yield data


# --- routes -------------------------------------------------------------------------------


def register(ctx: ModuleContext) -> None:
    global ACTIVE_SERVICE
    service = DbAdminService(ctx)
    ACTIVE_SERVICE = service
    router = APIRouter(prefix="/api/v1/dbadmin", tags=["dbadmin"])

    def failure(exc: Exception):
        if isinstance(exc, ApiError | policy.PolicyError | engines.EngineError | sqltext.SqlError):
            status = getattr(exc, "status_code", 422)
            return ctx.error_payload(exc.code, exc.message, status)
        raise exc

    async def audit(principal: Any, action: str, object_id: str | None,
                    result: str = "success") -> None:
        await asyncio.to_thread(ctx.audit, principal.user_id, action, "dbadmin_connection",
                                object_id, result)

    def mutating(request: Request, permission: str) -> Any:
        principal = ctx.require_principal(request, permission)
        ctx.require_csrf(request, principal)
        return principal

    # settings
    @router.get("/settings")
    async def get_settings(request: Request):
        ctx.require_principal(request, READ)
        return await asyncio.to_thread(service.settings)

    @router.put("/settings")
    async def put_settings(request: Request, body: SettingsBody):
        principal = mutating(request, WRITE)
        try:
            result = await asyncio.to_thread(service.save_settings, body.model_dump())
        except policy.PolicyError as exc:
            return failure(exc)
        await audit(principal, "dbadmin.settings.update", "settings")
        return result

    @router.get("/network-guide")
    async def get_network_guide(request: Request):
        ctx.require_principal(request, READ)
        return network_guide()

    @router.get("/discover")
    async def discover(request: Request):
        ctx.require_principal(request, READ)
        return await service.discover()

    # connections
    @router.get("/connections")
    async def connections(request: Request):
        ctx.require_principal(request, READ)
        return {"items": await asyncio.to_thread(service.list_connections)}

    @router.get("/connections/{connection_id}")
    async def connection(connection_id: str, request: Request):
        ctx.require_principal(request, READ)
        try:
            return await asyncio.to_thread(service.get_connection, connection_id)
        except ApiError as exc:
            return failure(exc)

    @router.post("/connections", status_code=201)
    async def create_connection(request: Request, body: ConnectionCreate):
        principal = mutating(request, WRITE)
        try:
            item = await asyncio.to_thread(service.create_connection, body, principal.user_id)
        except (ApiError, policy.PolicyError) as exc:
            await audit(principal, "dbadmin.connection.create", None, "failure")
            return failure(exc)
        await audit(principal, "dbadmin.connection.create", item["id"])
        return item

    @router.patch("/connections/{connection_id}")
    async def update_connection(connection_id: str, request: Request, body: ConnectionPatch):
        principal = mutating(request, WRITE)
        try:
            item = await asyncio.to_thread(service.update_connection, connection_id, body)
        except (ApiError, policy.PolicyError) as exc:
            return failure(exc)
        await audit(principal, "dbadmin.connection.update", connection_id)
        return item

    @router.delete("/connections/{connection_id}")
    async def delete_connection(connection_id: str, request: Request, body: ConfirmBody):
        principal = mutating(request, WRITE)
        try:
            await asyncio.to_thread(service.delete_connection, connection_id, body.confirmation)
        except ApiError as exc:
            return failure(exc)
        await audit(principal, "dbadmin.connection.delete", connection_id)
        return {"deleted": True}

    @router.post("/connections/{connection_id}/test")
    async def test_connection(connection_id: str, request: Request):
        principal = mutating(request, READ)
        try:
            spec, adapter = await service.prepared(connection_id)
            result = await service.run(spec, adapter.test)
        except (ApiError, policy.PolicyError, engines.EngineError) as exc:
            if not isinstance(exc, ApiError) or exc.code != "not_found":
                await asyncio.to_thread(service.record_test, connection_id, False)
            await audit(principal, "dbadmin.connection.test", connection_id, "failure")
            return failure(exc)
        await asyncio.to_thread(service.record_test, connection_id, True)
        await audit(principal, "dbadmin.connection.test", connection_id)
        return result

    # browse
    @router.get("/connections/{connection_id}/schema")
    async def schema(connection_id: str, request: Request):
        principal = ctx.require_principal(request, READ)
        try:
            spec, adapter = await service.prepared(connection_id)
            result = await service.run(spec, adapter.schema)
        except (ApiError, policy.PolicyError, engines.EngineError) as exc:
            return failure(exc)
        await audit(principal, "dbadmin.schema.read", connection_id)
        return result

    @router.get("/connections/{connection_id}/tables/{name}")
    async def table(
        connection_id: str,
        name: str,
        request: Request,
        schema: str | None = Query(default=None, max_length=128),
        page: int = Query(default=1, ge=1, le=1_000_000),
        limit: int = Query(default=50, ge=1, le=500),
        sort: str | None = Query(default=None, max_length=1000),
        filter: str | None = Query(default=None, max_length=20000),  # noqa: A002
    ):
        principal = ctx.require_principal(request, READ)
        if len(name) > 255:
            return ctx.error_payload("invalid_table", "table name is too long", 422)
        try:
            spec, adapter = await service.prepared(connection_id)
            result = await service.run(
                spec, lambda: adapter.table(schema, name, page, limit, sort, filter)
            )
        except (ApiError, policy.PolicyError, engines.EngineError) as exc:
            return failure(exc)
        await audit(principal, "dbadmin.table.read",
                    f"{connection_id}:{sqltext.statement_hash(f'{schema}.{name}')[:16]}")
        return result

    @router.post("/connections/{connection_id}/query")
    async def query(connection_id: str, request: Request, body: QueryBody):
        principal = mutating(request, READ)
        if body.dry_run and not body.write:
            return ctx.error_payload("write_required", "dry_run is part of write mode", 422)
        if body.write and not principal.allows(WRITE):
            await audit(principal, "dbadmin.query.write", connection_id, "denied")
            return ctx.error_payload("forbidden", "write mode needs db:write", 403)
        try:
            spec = await asyncio.to_thread(service.spec, connection_id)
            engine_request, digest = build_query(spec, body)
            if body.write and body.confirmation != write_confirmation(spec.name):
                raise ApiError("confirmation_required",
                               f"type {write_confirmation(spec.name)!r} to run in write mode")
        except (ApiError, policy.PolicyError, sqltext.SqlError) as exc:
            return failure(exc)
        action = "dbadmin.query.read"
        if body.write:
            action = "dbadmin.query.dry_run" if body.dry_run else "dbadmin.query.write"
        object_id = f"{connection_id}:{digest}"
        try:
            await service.resolve(spec)
            adapter = engines.adapter_for(spec, await asyncio.to_thread(service.limits))
            result = await service.run(spec, lambda: adapter.query(engine_request))
        except (ApiError, policy.PolicyError, engines.EngineError, sqltext.SqlError) as exc:
            await audit(principal, action, object_id, "failure")
            return failure(exc)
        await audit(principal, action, object_id)
        result["statement_sha256"] = digest
        return result

    @router.post("/connections/{connection_id}/export")
    async def export(connection_id: str, request: Request, body: ExportBody):
        principal = mutating(request, READ)
        chosen = [item for item in (body.table, body.text, body.mongo) if item is not None]
        if len(chosen) != 1:
            return ctx.error_payload("export_invalid", "pass exactly one of table, text, mongo",
                                     422)
        try:
            spec = await asyncio.to_thread(service.spec, connection_id)
            current = await asyncio.to_thread(service.settings)
            max_rows = min(body.max_rows or current["export_max_rows"],
                           current["export_max_rows"])
            rows_factory, digest = build_export(spec, body, max_rows,
                                                current["export_statement_timeout_ms"])
            await service.resolve(spec)
            adapter = engines.adapter_for(spec, await asyncio.to_thread(service.limits))
        except (ApiError, policy.PolicyError, engines.EngineError, sqltext.SqlError) as exc:
            return failure(exc)
        object_id = f"{connection_id}:{digest}"
        semaphore = service._semaphore(spec.id)
        try:
            await asyncio.wait_for(semaphore.acquire(), QUEUE_WAIT_SECONDS)
        except TimeoutError:
            return ctx.error_payload("connection_busy", "the connection is busy", 429)
        chunks = csv_chunks(rows_factory(adapter), excel_safe=body.excel_safe,
                            max_bytes=current["export_max_bytes"])
        sentinel = object()
        timeout = spec.connect_timeout + current["export_statement_timeout_ms"] / 1000 + 10
        try:
            first = await asyncio.wait_for(
                asyncio.to_thread(next, chunks, sentinel), timeout
            )
        except BaseException as exc:
            semaphore.release()
            with contextlib.suppress(Exception):
                chunks.close()
            await audit(principal, "dbadmin.export", object_id, "failure")
            if isinstance(exc, TimeoutError):
                return ctx.error_payload("db_timeout", "the database did not answer in time", 504)
            if isinstance(exc, ApiError | policy.PolicyError | engines.EngineError
                          | sqltext.SqlError):
                return failure(exc)
            raise
        await audit(principal, "dbadmin.export", object_id)

        async def body_iter() -> AsyncIterator[bytes]:
            try:
                if first is not sentinel:
                    yield first  # type: ignore[misc]
                while True:
                    try:
                        chunk = await asyncio.wait_for(
                            asyncio.to_thread(next, chunks, sentinel), timeout
                        )
                    except Exception:  # noqa: BLE001 - the stream is already open
                        LOGGER.warning("dbadmin export stopped early",
                                       extra={"connection_id": connection_id})
                        return
                    if chunk is sentinel:
                        return
                    yield chunk  # type: ignore[misc]
            finally:
                with contextlib.suppress(Exception):
                    await asyncio.to_thread(chunks.close)
                semaphore.release()

        safe = re.sub(r"[^A-Za-z0-9_.-]+", "-", spec.name).strip("-") or "export"
        headers = {"Content-Disposition": f'attachment; filename="{safe}-export.csv"',
                   "Cache-Control": "no-store"}
        return StreamingResponse(body_iter(), media_type="text/csv; charset=utf-8",
                                 headers=headers)

    ctx.routers.append(router)


def build_query(spec: engines.ConnSpec, body: QueryBody) -> tuple[engines.QueryRequest, str]:
    """Validate a query body for the connection's engine; return it and its SHA-256."""
    engine = spec.engine
    request = engines.QueryRequest(write=body.write, dry_run=body.dry_run)
    if engine in {"postgres", "mysql", "mariadb"}:
        if body.text is None or body.mongo is not None or body.redis is not None:
            raise ApiError("query_invalid", "SQL connections take 'text'")
        statement = sqltext.single_statement(body.text, sqltext.dialect_for(engine))
        if not body.write:
            sqltext.check_read_only(statement, sqltext.dialect_for(engine))
        if body.database is not None:
            if engine == "postgres":
                raise ApiError("query_invalid", "PostgreSQL connections have one database")
            request.database = policy.validate_database(engine, body.database)
        request.text = body.text
        return request, sqltext.statement_hash(body.text)
    if engine == "mongo":
        if body.mongo is None or body.text is not None or body.redis is not None:
            raise ApiError("query_invalid", "MongoDB connections take 'mongo'")
        request.mongo = policy.validate_mongo(body.mongo, write=body.write)
        request.database = policy.validate_database(engine, body.database)
        canonical = json.dumps(body.mongo, sort_keys=True, separators=(",", ":"), default=str)
        return request, sqltext.statement_hash(canonical)
    if body.redis is None or body.text is not None or body.mongo is not None:
        raise ApiError("query_invalid", "Redis connections take 'redis'")
    request.redis = policy.validate_redis(body.redis.command, body.redis.args, write=body.write)
    canonical = json.dumps([request.redis[0], *request.redis[1]], separators=(",", ":"))
    return request, sqltext.statement_hash(canonical)


def build_export(spec: engines.ConnSpec, body: ExportBody, max_rows: int, timeout_ms: int
                 ) -> tuple[Callable[[Any], Iterator[list[Any]]], str]:
    engine = spec.engine
    if engine == "redis":
        raise ApiError("export_unsupported", "Redis data cannot be exported as CSV")
    if body.table is not None:
        table = {"name": body.table.name, "schema": body.table.schema_,
                 "filter": _filter_text(body.table.filter), "sort": body.table.sort}
        digest = sqltext.statement_hash(json.dumps(table, sort_keys=True))
        if engine == "mongo":
            return (lambda adapter: adapter.export(None, table, max_rows, timeout_ms)), digest
        return (lambda adapter: adapter.export(None, table, max_rows, timeout_ms)), digest
    if engine == "mongo":
        if body.mongo is None:
            raise ApiError("export_invalid", "MongoDB exports take 'table' or 'mongo'")
        mongo = policy.validate_mongo(body.mongo, write=False)
        if mongo.op not in {"find", "aggregate"}:
            raise ApiError("export_unsupported", "only find/aggregate can be exported")
        digest = sqltext.statement_hash(json.dumps(body.mongo, sort_keys=True, default=str))
        return (lambda adapter: adapter.export(mongo, None, max_rows, timeout_ms)), digest
    if body.text is None:
        raise ApiError("export_invalid", "SQL exports take 'table' or 'text'")
    statement = sqltext.single_statement(body.text, sqltext.dialect_for(engine))
    sqltext.check_read_only(statement, sqltext.dialect_for(engine))
    text = body.text
    return (lambda adapter: adapter.export(text, None, max_rows, timeout_ms)), \
        sqltext.statement_hash(text)
