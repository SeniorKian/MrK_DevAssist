"""Server & database backups module (Gate 18 S6, docs/31 §4) — ``/api/v1/server-backups``.

Sources are read through the Host Agent (volume tar, fixed-template DB dumps),
encrypted with MRKBKP2 using a per-job random passphrase from the SecretStore,
and streamed to a local directory, an external S3 service or our own S3
engine. A 30-second scheduler runs enabled jobs from their 5-field cron
schedule in the configured time zone; retention runs after every success.
Restore is manual for now (download + ``mrk-backup-decrypt``; docs/27).
"""

from __future__ import annotations

import asyncio
import contextlib
import itertools
import json
import logging
import os
import re
import secrets
import time
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Query, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import delete, select

from .. import outbound
from ..agent.backup import DATABASE_NAME, VOLUME_NAME
from ..models import ServerBackupDestination, ServerBackupJob, ServerBackupRun
from ..module_context import Event, ModuleContext
from . import server_backups_dest as dest
from .host_agent import AgentError, HostAgentService
from .server_backups_cron import DEFAULT_TIMEZONE, CronError, load_timezone, parse_cron
from .server_backups_crypto import new_passphrase
from .server_backups_pipeline import PipelineError, run_backup
from .server_backups_s3 import S3Error

LOGGER = logging.getLogger(__name__)
MODULE_NAME = "server_backups"
READ = "backup:server:read"
WRITE = "backup:server:write"
SETTINGS_FILE = "server-backups.json"
SCHEDULER_INTERVAL_SECONDS = 30.0
SOURCE_KINDS = ("volume", "postgres", "mysql", "mariadb", "mongo", "redis")
_CONTAINER_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_NAME = re.compile(r"^[^\x00-\x1f\x7f]{1,80}$")
PROTECTED_NOTE = (
    "This container belongs to Dokploy. A dump is read-only and allowed, but prefer "
    "Dokploy's own database backups for Dokploy-managed databases."
)
DECRYPT_COMMAND = (
    "python -m mrk_control_plane.modules.server_backups_crypto ARTIFACT.mrkbak "
    "-o OUTPUT --passphrase-file KEY.txt [--decompress]"
)

ACTIVE_SERVICE: ServerBackupService | None = None


class BackupApiError(Exception):
    def __init__(self, code: str, message: str, status_code: int = 422) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code


# --- request bodies -------------------------------------------------------------------


class DestinationCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=80)
    kind: str
    config: dict[str, Any] = Field(default_factory=dict)
    secret: dict[str, Any] | None = None


class DestinationPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str | None = Field(default=None, min_length=1, max_length=80)
    config: dict[str, Any] | None = None
    secret: dict[str, Any] | None = None


class ConfirmBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    confirmation: str = Field(min_length=1, max_length=80)
    delete_artifacts: bool = False


class JobCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=80)
    source: dict[str, Any]
    destination_id: str = Field(min_length=1, max_length=32)
    schedule: str = Field(min_length=9, max_length=120)
    retention: dict[str, Any] = Field(default_factory=dict)
    enabled: bool = True


class JobPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str | None = Field(default=None, min_length=1, max_length=80)
    source: dict[str, Any] | None = None
    destination_id: str | None = Field(default=None, min_length=1, max_length=32)
    schedule: str | None = Field(default=None, min_length=9, max_length=120)
    retention: dict[str, Any] | None = None
    enabled: bool | None = None


class SettingsBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    timezone: str = Field(min_length=1, max_length=64)


# --- pure helpers ------------------------------------------------------------------------


def validate_name(value: str) -> str:
    text = value.strip()
    if not _NAME.fullmatch(text):
        raise BackupApiError("invalid_name", "name must be 1-80 printable characters")
    return text


def validate_source(raw: object) -> dict[str, Any]:
    if not isinstance(raw, dict) or set(raw) - {"kind", "volume", "container", "database"}:
        raise BackupApiError("invalid_source", "source has unknown fields")
    kind = raw.get("kind")
    if kind not in SOURCE_KINDS:
        raise BackupApiError("invalid_source", "unknown source kind")
    if kind == "volume":
        volume = raw.get("volume")
        if not isinstance(volume, str) or not VOLUME_NAME.fullmatch(volume) or ".." in volume:
            raise BackupApiError("invalid_volume", "volume name is invalid")
        return {"kind": kind, "volume": volume}
    container = raw.get("container")
    if not isinstance(container, str) or not _CONTAINER_REF.fullmatch(container) or (
        ".." in container
    ):
        raise BackupApiError("invalid_container", "container name or id is invalid")
    database = raw.get("database")
    if database in ("", None):
        database = None
    elif kind == "redis":
        raise BackupApiError("invalid_database", "redis backups take no database name")
    elif not isinstance(database, str) or not DATABASE_NAME.fullmatch(database):
        raise BackupApiError("invalid_database", "database name is invalid")
    return {"kind": kind, "container": container, "database": database}


def validate_retention(raw: object) -> dict[str, int | None]:
    if not isinstance(raw, dict) or set(raw) - {"keep_last", "keep_days"}:
        raise BackupApiError("invalid_retention", "retention takes keep_last and keep_days")
    result: dict[str, int | None] = {}
    for key, high in (("keep_last", 1000), ("keep_days", 3650)):
        value = raw.get(key)
        if value is None or value == 0:
            result[key] = None
        elif isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= high:
            raise BackupApiError("invalid_retention", f"{key} must be between 1 and {high}")
        else:
            result[key] = value
    return result


_RUN_SEQUENCE = itertools.count()


def select_expired(
    runs: list[tuple[str, int]], keep_last: int | None, keep_days: int | None, now: float
) -> list[str]:
    """``runs``: successful (id, started_at), newest first. Returns ids to delete.

    A run is kept if it is among the newest ``keep_last`` *or* newer than
    ``keep_days``; with neither set everything is kept. The newest run is
    always kept.
    """
    if not keep_last and not keep_days:
        return []
    ordered = sorted(runs, key=lambda item: item[1], reverse=True)
    keep: set[str] = {ordered[0][0]} if ordered else set()
    if keep_last:
        keep.update(run_id for run_id, _ in ordered[:keep_last])
    if keep_days:
        cutoff = now - keep_days * 86400
        keep.update(run_id for run_id, started in ordered if started >= cutoff)
    return [run_id for run_id, _ in ordered if run_id not in keep]


def payload_name(source: dict[str, Any]) -> str:
    kind = source["kind"]
    database = source.get("database")
    if kind == "volume":
        return f"{source['volume']}.tar"
    if kind == "postgres":
        return f"{database or 'postgres'}.pgdump"
    if kind in {"mysql", "mariadb"}:
        return f"{database or 'all-databases'}.sql"
    if kind == "mongo":
        return f"{database or 'all'}.mongo.archive"
    return "dump.rdb"


def classify(exc: BaseException) -> str:
    if isinstance(exc, PipelineError | AgentError | dest.DestinationError | S3Error):
        return exc.code
    if isinstance(exc, outbound.OutboundError):
        return exc.code
    return outbound.error_code(exc)


# --- service -------------------------------------------------------------------------------


class ServerBackupService:
    def __init__(self, ctx: ModuleContext, agent: HostAgentService | None = None) -> None:
        self.ctx = ctx
        self.agent = agent or HostAgentService(ctx)
        self.settings_path = ctx.data_dir / "control-plane" / SETTINGS_FILE
        self._running: dict[str, str] = {}
        self._tasks: set[asyncio.Task[None]] = set()
        self._scheduler: asyncio.Task[None] | None = None
        try:
            concurrency = int(os.getenv("MRK_SERVER_BACKUP_CONCURRENCY", "2"))
        except ValueError:
            concurrency = 2
        self._semaphore = asyncio.Semaphore(min(max(concurrency, 1), 8))
        self._lock = asyncio.Lock()

    # -- settings --------------------------------------------------------------------
    def settings(self) -> dict[str, Any]:
        try:
            payload = json.loads(self.settings_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            payload = {}
        timezone = payload.get("timezone") if isinstance(payload, dict) else None
        try:
            load_timezone(timezone)  # type: ignore[arg-type]
        except CronError:
            timezone = DEFAULT_TIMEZONE
        return {"timezone": timezone}

    def save_settings(self, timezone: str) -> dict[str, Any]:
        try:
            load_timezone(timezone)
        except CronError as exc:
            raise BackupApiError("invalid_timezone", str(exc)) from None
        self.settings_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.settings_path.with_name(f".{SETTINGS_FILE}.{secrets.token_hex(4)}.tmp")
        temporary.write_text(json.dumps({"timezone": timezone}) + "\n", encoding="utf-8")
        os.replace(temporary, self.settings_path)
        self.reschedule_all()
        return self.settings()

    def next_run(self, schedule: str, after: float | None = None) -> int:
        cron = parse_cron(schedule)
        return int(cron.next_after(time.time() if after is None else after,
                                   self.settings()["timezone"]))

    # -- destinations ----------------------------------------------------------------
    @staticmethod
    def _destination_public(row: ServerBackupDestination, used_by: int) -> dict[str, Any]:
        return {
            "id": row.id,
            "name": row.name,
            "kind": row.kind,
            "config": dest.public_config(row.kind, row.config or {}),
            "secret_configured": row.secret_ref is not None,
            "used_by_jobs": used_by,
            "created_at": row.created_at,
            "updated_at": row.updated_at,
        }

    def list_destinations(self) -> list[dict[str, Any]]:
        with self.ctx.database.session() as db:
            rows = db.scalars(
                select(ServerBackupDestination).order_by(ServerBackupDestination.name)
            ).all()
            jobs = db.scalars(select(ServerBackupJob.destination_id)).all()
            return [self._destination_public(row, jobs.count(row.id)) for row in rows]

    def _mrk_key_ref(self, access_key_id: str) -> str | None:
        try:
            from ..models import S3AccessKey
        except ImportError:  # pragma: no cover - s3 module absent
            return None
        with self.ctx.database.session() as db:
            row = db.get(S3AccessKey, access_key_id)
            return row.secret_ref if row is not None and row.enabled else None

    def _store_secret(self, reference: str | None, akid: str, secret: str) -> str:
        reference, _ = self.ctx.secret_store.replace(
            reference, {"access_key_id": akid, "secret_access_key": secret}
        )
        return reference

    def create_destination(self, body: DestinationCreate) -> dict[str, Any]:
        name = validate_name(body.name)
        akid = body.config.get("access_key_id") if isinstance(body.config, dict) else None
        known = (
            body.kind == "mrk_s3"
            and isinstance(akid, str)
            and self._mrk_key_ref(akid) is not None
        )
        validated = dest.validate(
            body.kind, body.config, body.secret, data_dir=self.ctx.data_dir,
            network=self.ctx.network_settings, known_mrk_key=known,
        )
        now = int(time.time())
        reference = None
        if validated.secret is not None:
            reference = self._store_secret(None, validated.config["access_key_id"],
                                           validated.secret)
        try:
            with self.ctx.database.session() as db, db.begin():
                if db.scalar(select(ServerBackupDestination).where(
                    ServerBackupDestination.name == name
                )) is not None:
                    raise BackupApiError("name_taken", "a destination with this name exists", 409)
                row = ServerBackupDestination(
                    id=secrets.token_hex(8), name=name, kind=body.kind,
                    config=validated.config, secret_ref=reference, created_at=now,
                    updated_at=now,
                )
                db.add(row)
                db.flush()
                return self._destination_public(row, 0)
        except BaseException:
            if reference is not None:
                self.ctx.secret_store.delete(reference)
            raise

    def update_destination(self, destination_id: str, body: DestinationPatch) -> dict[str, Any]:
        with self.ctx.database.session() as db, db.begin():
            row = db.get(ServerBackupDestination, destination_id)
            if row is None:
                raise BackupApiError("not_found", "destination not found", 404)
            config = body.config if body.config is not None else {}
            merged_akid = {**(row.config or {}), **config}.get("access_key_id")
            known = (
                row.kind == "mrk_s3"
                and isinstance(merged_akid, str)
                and self._mrk_key_ref(merged_akid) is not None
            )
            validated = dest.validate(
                row.kind, config, body.secret, data_dir=self.ctx.data_dir,
                network=self.ctx.network_settings, previous=dict(row.config or {}),
                has_secret=row.secret_ref is not None, known_mrk_key=known,
            )
            if body.name is not None:
                name = validate_name(body.name)
                clash = db.scalar(select(ServerBackupDestination).where(
                    ServerBackupDestination.name == name, ServerBackupDestination.id != row.id
                ))
                if clash is not None:
                    raise BackupApiError("name_taken", "a destination with this name exists", 409)
                row.name = name
            if validated.secret is not None:
                row.secret_ref = self._store_secret(
                    row.secret_ref, validated.config["access_key_id"], validated.secret
                )
            elif validated.clear_secret and row.secret_ref is not None:
                self.ctx.secret_store.delete(row.secret_ref)
                row.secret_ref = None
            row.config = validated.config
            row.updated_at = int(time.time())
            used = len(db.scalars(select(ServerBackupJob.id).where(
                ServerBackupJob.destination_id == row.id
            )).all())
            return self._destination_public(row, used)

    def delete_destination(self, destination_id: str, confirmation: str) -> str:
        with self.ctx.database.session() as db, db.begin():
            row = db.get(ServerBackupDestination, destination_id)
            if row is None:
                raise BackupApiError("not_found", "destination not found", 404)
            if confirmation != row.name:
                raise BackupApiError("confirmation_required", "Type the destination name")
            if db.scalar(select(ServerBackupJob.id).where(
                ServerBackupJob.destination_id == row.id
            )) is not None:
                raise BackupApiError("destination_in_use", "jobs still use this destination", 409)
            reference = row.secret_ref
            name = row.name
            db.delete(row)
        if reference:
            self.ctx.secret_store.delete(reference)
        return name

    def destination_spec(self, destination_id: str) -> dest.DestinationSpec:
        with self.ctx.database.session() as db:
            row = db.get(ServerBackupDestination, destination_id)
            if row is None:
                raise BackupApiError("not_found", "destination not found", 404)
            spec = dest.DestinationSpec(row.id, row.kind, dict(row.config or {}), row.secret_ref)
        if spec.kind == "mrk_s3" and spec.secret_ref is None:
            spec.mrk_key_secret_ref = self._mrk_key_ref(spec.config.get("access_key_id", ""))
        return spec

    def handle(self, spec: dest.DestinationSpec) -> dest.DestinationHandle:
        return dest.DestinationHandle(
            spec, data_dir=self.ctx.data_dir, network=self.ctx.network_settings,
            secret_store=self.ctx.secret_store,
        )

    # -- jobs ----------------------------------------------------------------------------
    def _last_run(self, db: Any, job_id: str) -> dict[str, Any] | None:
        row = db.scalar(select(ServerBackupRun).where(ServerBackupRun.job_id == job_id)
                        .order_by(ServerBackupRun.started_at.desc()).limit(1))
        return self._run_public(row) if row is not None else None

    def _job_public(self, db: Any, row: ServerBackupJob) -> dict[str, Any]:
        return {
            "id": row.id,
            "name": row.name,
            "source": row.source,
            "destination_id": row.destination_id,
            "schedule": row.schedule,
            "retention": row.retention,
            "enabled": row.enabled,
            "running": row.id in self._running,
            "next_run_at": row.next_run_at if row.enabled else None,
            "last_run": self._last_run(db, row.id),
            "created_at": row.created_at,
            "updated_at": row.updated_at,
        }

    def list_jobs(self) -> list[dict[str, Any]]:
        with self.ctx.database.session() as db:
            rows = db.scalars(select(ServerBackupJob).order_by(ServerBackupJob.name)).all()
            return [self._job_public(db, row) for row in rows]

    def _schedule(self, value: str) -> str:
        try:
            return parse_cron(value).expression
        except CronError as exc:
            raise BackupApiError("invalid_schedule", str(exc)) from None

    def create_job(self, body: JobCreate) -> dict[str, Any]:
        name = validate_name(body.name)
        source = validate_source(body.source)
        retention = validate_retention(body.retention)
        schedule = self._schedule(body.schedule)
        now = int(time.time())
        key_ref, _ = self.ctx.secret_store.replace(None, {"passphrase": new_passphrase()})
        try:
            with self.ctx.database.session() as db, db.begin():
                if db.get(ServerBackupDestination, body.destination_id) is None:
                    raise BackupApiError("destination_not_found", "destination not found")
                if db.scalar(select(ServerBackupJob).where(ServerBackupJob.name == name)):
                    raise BackupApiError("name_taken", "a job with this name exists", 409)
                row = ServerBackupJob(
                    id=secrets.token_hex(8), name=name, source=source,
                    destination_id=body.destination_id, schedule=schedule, retention=retention,
                    enabled=body.enabled, key_ref=key_ref,
                    next_run_at=self.next_run(schedule) if body.enabled else None,
                    created_at=now, updated_at=now,
                )
                db.add(row)
                db.flush()
                return self._job_public(db, row)
        except BaseException:
            self.ctx.secret_store.delete(key_ref)
            raise

    def update_job(self, job_id: str, body: JobPatch) -> dict[str, Any]:
        with self.ctx.database.session() as db, db.begin():
            row = db.get(ServerBackupJob, job_id)
            if row is None:
                raise BackupApiError("not_found", "job not found", 404)
            if body.name is not None:
                name = validate_name(body.name)
                if db.scalar(select(ServerBackupJob).where(
                    ServerBackupJob.name == name, ServerBackupJob.id != row.id
                )):
                    raise BackupApiError("name_taken", "a job with this name exists", 409)
                row.name = name
            if body.source is not None:
                row.source = validate_source(body.source)
            if body.retention is not None:
                row.retention = validate_retention(body.retention)
            if body.destination_id is not None:
                if db.get(ServerBackupDestination, body.destination_id) is None:
                    raise BackupApiError("destination_not_found", "destination not found")
                row.destination_id = body.destination_id
            if body.schedule is not None:
                row.schedule = self._schedule(body.schedule)
            if body.enabled is not None:
                row.enabled = body.enabled
            row.next_run_at = self.next_run(row.schedule) if row.enabled else None
            row.updated_at = int(time.time())
            return self._job_public(db, row)

    def job_snapshot(self, job_id: str) -> dict[str, Any]:
        with self.ctx.database.session() as db:
            row = db.get(ServerBackupJob, job_id)
            if row is None:
                raise BackupApiError("not_found", "job not found", 404)
            return {
                "id": row.id, "name": row.name, "source": dict(row.source),
                "destination_id": row.destination_id, "retention": dict(row.retention or {}),
                "key_ref": row.key_ref, "schedule": row.schedule, "enabled": row.enabled,
            }

    def job_passphrase(self, job_id: str) -> dict[str, str]:
        job = self.job_snapshot(job_id)
        try:
            passphrase = self.ctx.secret_store.get(job["key_ref"])["passphrase"]
        except (KeyError, ValueError):
            raise BackupApiError("key_unavailable", "the job key is unavailable", 409) from None
        return {"passphrase": passphrase, "key_ref": job["key_ref"]}

    async def delete_job(self, job_id: str, confirmation: str, delete_artifacts: bool) -> str:
        job = await asyncio.to_thread(self.job_snapshot, job_id)
        if confirmation != job["name"]:
            raise BackupApiError("confirmation_required", "Type the job name")
        if job_id in self._running:
            raise BackupApiError("job_running", "the job is running", 409)
        if delete_artifacts:
            runs = await asyncio.to_thread(self._artifact_runs, job_id)
            for run_id, destination_id, key in runs:
                await self._delete_artifact(destination_id, key, run_id)
        def _delete() -> None:
            with self.ctx.database.session() as db, db.begin():
                db.execute(delete(ServerBackupRun).where(ServerBackupRun.job_id == job_id))
                db.execute(delete(ServerBackupJob).where(ServerBackupJob.id == job_id))
            # Without the key the artifacts are unrecoverable, so it is kept unless
            # they were deleted too (export it first from the panel).
            if delete_artifacts:
                self.ctx.secret_store.delete(job["key_ref"])

        await asyncio.to_thread(_delete)
        return job["name"]

    def _artifact_runs(self, job_id: str) -> list[tuple[str, str, str]]:
        with self.ctx.database.session() as db:
            rows = db.scalars(select(ServerBackupRun).where(
                ServerBackupRun.job_id == job_id, ServerBackupRun.state == "succeeded"
            )).all()
            return [(r.id, r.destination_id, r.object_key) for r in rows if r.object_key]

    def reschedule_all(self) -> None:
        with self.ctx.database.session() as db, db.begin():
            for row in db.scalars(select(ServerBackupJob)).all():
                row.next_run_at = self.next_run(row.schedule) if row.enabled else None

    # -- runs ------------------------------------------------------------------------------
    @staticmethod
    def _run_public(row: ServerBackupRun) -> dict[str, Any]:
        return {
            "id": row.id,
            "job_id": row.job_id,
            "destination_id": row.destination_id,
            "trigger": row.trigger,
            "state": row.state,
            "started_at": row.started_at,
            "finished_at": row.finished_at,
            "bytes": row.bytes,
            "source_bytes": row.source_bytes,
            "sha256": row.sha256,
            "object_key": row.object_key,
            "error_code": row.error_code,
            "details": row.details or {},
        }

    def list_runs(self, job_id: str | None, limit: int) -> list[dict[str, Any]]:
        with self.ctx.database.session() as db:
            query = select(ServerBackupRun).order_by(
                ServerBackupRun.started_at.desc(), ServerBackupRun.id.desc()
            )
            if job_id:
                query = query.where(ServerBackupRun.job_id == job_id)
            return [self._run_public(row) for row in db.scalars(query.limit(limit)).all()]

    def get_run(self, run_id: str) -> dict[str, Any]:
        with self.ctx.database.session() as db:
            row = db.get(ServerBackupRun, run_id)
            if row is None:
                raise BackupApiError("not_found", "run not found", 404)
            job = db.get(ServerBackupJob, row.job_id)
            return {**self._run_public(row), "job_name": job.name if job else row.job_id}

    def _insert_run(self, job: dict[str, Any], trigger: str) -> str:
        # Time-ordered id (ns timestamp + random) so equal-second runs still sort.
        # time_ns can repeat on coarse clocks (≈15ms on Windows); the per-process
        # sequence keeps ids strictly ordered so retention never keeps an older run.
        run_id = f"{time.time_ns():016x}{next(_RUN_SEQUENCE) % 0x10000:04x}{secrets.token_hex(2)}"
        with self.ctx.database.session() as db, db.begin():
            db.add(ServerBackupRun(
                id=run_id, job_id=job["id"], destination_id=job["destination_id"],
                trigger=trigger, state="running", started_at=int(time.time()), details={},
            ))
        return run_id

    def _finish_run(self, run_id: str, **values: Any) -> None:
        with self.ctx.database.session() as db, db.begin():
            row = db.get(ServerBackupRun, run_id)
            if row is None:
                return
            for key, value in values.items():
                setattr(row, key, value)
            row.finished_at = int(time.time())

    async def start_run(self, job_id: str, trigger: str = "manual") -> str:
        async with self._lock:
            if job_id in self._running:
                raise BackupApiError("job_running", "the job is already running", 409)
            job = await asyncio.to_thread(self.job_snapshot, job_id)
            run_id = await asyncio.to_thread(self._insert_run, job, trigger)
            self._running[job_id] = run_id
        task = asyncio.create_task(self._execute(job, run_id), name=f"mrk-server-backup-{run_id}")
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        return run_id

    async def _execute(self, job: dict[str, Any], run_id: str) -> None:
        try:
            async with self._semaphore:
                await self._execute_inner(job, run_id)
        finally:
            self._running.pop(job["id"], None)

    async def _execute_inner(self, job: dict[str, Any], run_id: str) -> None:
        try:
            spec = await asyncio.to_thread(self.destination_spec, job["destination_id"])
            passphrase = (await asyncio.to_thread(self.job_passphrase, job["id"]))["passphrase"]
            stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
            async with self.handle(spec) as handle:
                key = handle.object_key(f"{job['id']}/{stamp}-{run_id}.mrkbak")
                result = await run_backup(
                    agent=self.agent, destination=handle, source=job["source"],
                    object_key=key, passphrase=passphrase, key_ref=job["key_ref"],
                    job_id=job["id"], backup_id=f"srv-{stamp}-{run_id}",
                    payload_name=payload_name(job["source"]),
                )
        except asyncio.CancelledError:
            await asyncio.to_thread(self._finish_run, run_id, state="failed",
                                    error_code="cancelled")
            raise
        except Exception as exc:
            code = classify(exc) if not isinstance(exc, BackupApiError) else exc.code
            if code in {"send_failed"}:
                LOGGER.exception("server backup failed", extra={"job_id": job["id"]})
            else:
                LOGGER.warning("server backup failed",
                               extra={"job_id": job["id"], "error_code": code})
            await asyncio.to_thread(self._finish_run, run_id, state="failed", error_code=code)
            await asyncio.to_thread(self.ctx.audit, None, "server_backup.run",
                                    "server_backup_job", job["id"], "failure")
            self.ctx.events.publish(Event(
                type="server_backup.failed", severity="error",
                title=f"Server backup failed: {job['name']}",
                message=f"error_code={code}", module=MODULE_NAME,
                dedupe_key=f"server_backup:{job['id']}",
                details={"job_id": job["id"], "run_id": run_id, "error_code": code},
            ))
            return
        await asyncio.to_thread(
            self._finish_run, run_id, state="succeeded", bytes=result.bytes,
            source_bytes=result.source_bytes, sha256=result.sha256,
            object_key=result.object_key, details=result.details,
        )
        await asyncio.to_thread(self.ctx.audit, None, "server_backup.run",
                                "server_backup_job", job["id"], "success")
        self.ctx.events.publish(Event(
            type="server_backup.succeeded", severity="info",
            title=f"Server backup succeeded: {job['name']}", module=MODULE_NAME,
            dedupe_key=f"server_backup:{job['id']}",
            details={"job_id": job["id"], "run_id": run_id, "bytes": result.bytes},
        ))
        try:
            await self.apply_retention(job["id"])
        except Exception:
            LOGGER.exception("server backup retention failed", extra={"job_id": job["id"]})

    async def _delete_artifact(self, destination_id: str, key: str, run_id: str) -> bool:
        try:
            spec = await asyncio.to_thread(self.destination_spec, destination_id)
            async with self.handle(spec) as handle:
                await handle.delete(key)
        except Exception as exc:
            LOGGER.warning("could not delete backup artifact",
                           extra={"run_id": run_id, "error_code": classify(exc)})
            return False
        return True

    async def apply_retention(self, job_id: str, now: float | None = None) -> list[str]:
        job = await asyncio.to_thread(self.job_snapshot, job_id)
        retention = job["retention"]

        def _runs() -> list[tuple[str, int, str, str | None]]:
            with self.ctx.database.session() as db:
                rows = db.scalars(select(ServerBackupRun).where(
                    ServerBackupRun.job_id == job_id, ServerBackupRun.state == "succeeded"
                )).all()
                # Newest first; run ids are time-ordered, so ties within one second keep
                # creation order through the stable sort in select_expired.
                ordered = sorted(rows, key=lambda r: (r.started_at, r.id), reverse=True)
                return [(r.id, r.started_at, r.destination_id, r.object_key) for r in ordered]

        runs = await asyncio.to_thread(_runs)
        expired = select_expired(
            [(run_id, started) for run_id, started, _d, _k in runs],
            retention.get("keep_last"), retention.get("keep_days"),
            time.time() if now is None else now,
        )
        by_id = {run_id: (destination_id, key) for run_id, _s, destination_id, key in runs}
        deleted: list[str] = []
        for run_id in expired:
            destination_id, key = by_id[run_id]
            if key and not await self._delete_artifact(destination_id, key, run_id):
                continue

            def _drop(run_id: str = run_id) -> None:
                with self.ctx.database.session() as db, db.begin():
                    row = db.get(ServerBackupRun, run_id)
                    if row is not None:
                        db.delete(row)

            await asyncio.to_thread(_drop)
            deleted.append(run_id)
        return deleted

    # -- scheduler -----------------------------------------------------------------------
    async def tick(self, now: float | None = None) -> list[str]:
        current = time.time() if now is None else now

        def _due() -> list[str]:
            with self.ctx.database.session() as db, db.begin():
                rows = db.scalars(select(ServerBackupJob).where(
                    ServerBackupJob.enabled.is_(True),
                    ServerBackupJob.next_run_at.is_not(None),
                    ServerBackupJob.next_run_at <= int(current),
                )).all()
                due = []
                for row in rows:
                    row.next_run_at = self.next_run(row.schedule, current)
                    due.append(row.id)
                return due

        started: list[str] = []
        for job_id in await asyncio.to_thread(_due):
            if job_id in self._running:
                continue  # still running from the previous slot: skip this one
            try:
                started.append(await self.start_run(job_id, "schedule"))
            except BackupApiError:
                continue
        return started

    def recover(self) -> None:
        with self.ctx.database.session() as db, db.begin():
            for row in db.scalars(select(ServerBackupRun).where(
                ServerBackupRun.state == "running"
            )).all():
                row.state = "failed"
                row.error_code = "interrupted"
                row.finished_at = int(time.time())

    async def _loop(self) -> None:
        while True:
            try:
                await self.tick()
            except asyncio.CancelledError:
                raise
            except Exception:
                LOGGER.exception("server backup scheduler failed")
            await asyncio.sleep(SCHEDULER_INTERVAL_SECONDS)

    async def start(self) -> None:
        await asyncio.to_thread(self.recover)
        self._scheduler = asyncio.create_task(self._loop(), name="mrk-server-backup-scheduler")

    async def stop(self) -> None:
        tasks = [task for task in [self._scheduler, *self._tasks] if task is not None]
        for task in tasks:
            task.cancel()
        for task in tasks:
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task
        self._scheduler = None

    async def wait_idle(self) -> None:
        """Test helper: wait for running backups to finish."""
        while self._tasks:
            await asyncio.gather(*list(self._tasks), return_exceptions=True)

    # -- sources -----------------------------------------------------------------------
    async def sources(self) -> dict[str, Any]:
        payload = await self.agent.call("/v1/backup/sources")
        if not isinstance(payload, dict):
            raise AgentError("agent_unreachable", 502, "unexpected agent payload")
        databases = []
        for item in payload.get("databases") or []:
            if isinstance(item, dict):
                entry = dict(item)
                entry["note"] = PROTECTED_NOTE if entry.get("protected") else None
                databases.append(entry)
        volumes = [item for item in payload.get("volumes") or [] if isinstance(item, dict)]
        return {"volumes": volumes, "databases": databases}

    async def source_note(self, source: dict[str, Any]) -> str | None:
        """Best effort: warn when a job dumps a protected (Dokploy) container."""
        if source["kind"] == "volume":
            return None
        try:
            data = await asyncio.wait_for(self.sources(), 5.0)
        except Exception:
            return None
        for item in data["databases"]:
            if source["container"] in {item.get("name"), item.get("container_id")}:
                return item.get("note")
        return None


# --- outbound registry -------------------------------------------------------------------


def register_outbound(ctx: ModuleContext, service: ServerBackupService) -> None:
    def list_entries() -> list[dict[str, Any]]:
        return [
            {"id": item["id"], "name": item["name"], "group": "s3",
             "proxy_id": item["config"].get("proxy_id")}
            for item in service.list_destinations()
            if item["kind"] == "s3"
        ]

    def set_proxy(destination_id: str, proxy_id: str | None) -> None:
        with ctx.database.session() as db, db.begin():
            row = db.get(ServerBackupDestination, destination_id)
            if row is None or row.kind != "s3":
                raise KeyError(destination_id)
            reference = outbound.check_reference(
                ctx.network_settings, proxy_id, dest.S3_SUPPORTED_PROXY_TYPES,
                "proxy_type_unsupported",
            )
            row.config = {**(row.config or {}), "proxy_id": reference}
            row.updated_at = int(time.time())

    outbound.outbound_registry(ctx.data_dir).register(
        outbound.OutboundProvider(
            kind="server_backup_destination",
            list_entries=list_entries,
            supported_types=lambda _entry: dest.S3_SUPPORTED_PROXY_TYPES,
            set_proxy=set_proxy,
            read_permission=READ,
            write_permission=WRITE,
        )
    )


# --- routes ------------------------------------------------------------------------------


def register(ctx: ModuleContext) -> None:
    global ACTIVE_SERVICE
    service = ServerBackupService(ctx)
    ACTIVE_SERVICE = service
    router = APIRouter(prefix="/api/v1/server-backups", tags=["server-backups"])

    def failure(exc: Exception):
        if isinstance(exc, BackupApiError | dest.DestinationError | AgentError):
            return ctx.error_payload(exc.code, exc.message, exc.status_code)
        if isinstance(exc, PipelineError):
            return ctx.error_payload(exc.code, str(exc), 422)
        raise exc

    async def audit(principal: Any, action: str, object_type: str, object_id: str | None,
                    result: str = "success") -> None:
        await asyncio.to_thread(ctx.audit, principal.user_id, action, object_type, object_id,
                                result)

    def writer(request: Request) -> Any:
        principal = ctx.require_principal(request, WRITE)
        ctx.require_csrf(request, principal)
        return principal

    # settings
    @router.get("/settings")
    async def get_settings(request: Request):
        ctx.require_principal(request, READ)
        return await asyncio.to_thread(service.settings)

    @router.put("/settings")
    async def put_settings(request: Request, body: SettingsBody):
        principal = writer(request)
        try:
            result = await asyncio.to_thread(service.save_settings, body.timezone)
        except BackupApiError as exc:
            return failure(exc)
        await audit(principal, "server_backup.settings.update", "server_backup", "settings")
        return result

    # destinations
    @router.get("/destinations")
    async def destinations(request: Request):
        ctx.require_principal(request, READ)
        return {"items": await asyncio.to_thread(service.list_destinations)}

    @router.post("/destinations", status_code=201)
    async def create_destination(request: Request, body: DestinationCreate):
        principal = writer(request)
        try:
            item = await asyncio.to_thread(service.create_destination, body)
        except (BackupApiError, dest.DestinationError) as exc:
            return failure(exc)
        await audit(principal, "server_backup.destination.create", "server_backup_destination",
                    item["id"])
        return item

    @router.patch("/destinations/{destination_id}")
    async def update_destination(destination_id: str, request: Request, body: DestinationPatch):
        principal = writer(request)
        try:
            item = await asyncio.to_thread(service.update_destination, destination_id, body)
        except (BackupApiError, dest.DestinationError) as exc:
            return failure(exc)
        await audit(principal, "server_backup.destination.update", "server_backup_destination",
                    destination_id)
        return item

    @router.delete("/destinations/{destination_id}")
    async def delete_destination(destination_id: str, request: Request, body: ConfirmBody):
        principal = writer(request)
        try:
            await asyncio.to_thread(service.delete_destination, destination_id,
                                    body.confirmation)
        except BackupApiError as exc:
            return failure(exc)
        await audit(principal, "server_backup.destination.delete", "server_backup_destination",
                    destination_id)
        return {"deleted": True}

    @router.post("/destinations/{destination_id}/test")
    async def test_destination(destination_id: str, request: Request):
        principal = writer(request)
        try:
            spec = await asyncio.to_thread(service.destination_spec, destination_id)
        except BackupApiError as exc:
            return failure(exc)
        started = time.perf_counter()
        try:
            async with service.handle(spec) as handle:
                result = await handle.test()
        except Exception as exc:
            result = {"ok": False,
                      "latency_ms": round((time.perf_counter() - started) * 1000, 1),
                      "error_code": classify(exc)}
        await audit(principal, "server_backup.destination.test", "server_backup_destination",
                    destination_id, "success" if result["ok"] else "failure")
        return result

    # jobs
    @router.get("/jobs")
    async def jobs(request: Request):
        ctx.require_principal(request, READ)
        return {"items": await asyncio.to_thread(service.list_jobs)}

    @router.post("/jobs", status_code=201)
    async def create_job(request: Request, body: JobCreate):
        principal = writer(request)
        try:
            item = await asyncio.to_thread(service.create_job, body)
        except BackupApiError as exc:
            return failure(exc)
        item["note"] = await service.source_note(item["source"])
        await audit(principal, "server_backup.job.create", "server_backup_job", item["id"])
        return item

    @router.patch("/jobs/{job_id}")
    async def update_job(job_id: str, request: Request, body: JobPatch):
        principal = writer(request)
        try:
            item = await asyncio.to_thread(service.update_job, job_id, body)
        except BackupApiError as exc:
            return failure(exc)
        if body.source is not None:
            item["note"] = await service.source_note(item["source"])
        await audit(principal, "server_backup.job.update", "server_backup_job", job_id)
        return item

    @router.delete("/jobs/{job_id}")
    async def delete_job(job_id: str, request: Request, body: ConfirmBody):
        principal = writer(request)
        try:
            await service.delete_job(job_id, body.confirmation, body.delete_artifacts)
        except BackupApiError as exc:
            return failure(exc)
        await audit(principal, "server_backup.job.delete", "server_backup_job", job_id)
        return {"deleted": True}

    @router.post("/jobs/{job_id}/run", status_code=202)
    async def run_job(job_id: str, request: Request):
        principal = writer(request)
        try:
            run_id = await service.start_run(job_id, "manual")
        except BackupApiError as exc:
            return failure(exc)
        await audit(principal, "server_backup.job.run", "server_backup_job", job_id)
        return {"run_id": run_id}

    @router.post("/jobs/{job_id}/key")
    async def export_key(job_id: str, request: Request):
        principal = writer(request)
        try:
            key = await asyncio.to_thread(service.job_passphrase, job_id)
        except BackupApiError as exc:
            return failure(exc)
        await audit(principal, "server_backup.key.export", "server_backup_job", job_id)
        return {**key, "decrypt_command": DECRYPT_COMMAND}

    # runs
    @router.get("/runs")
    async def runs(
        request: Request,
        job_id: str | None = Query(default=None, max_length=32),
        limit: int = Query(default=50, ge=1, le=500),
    ):
        ctx.require_principal(request, READ)
        return {"items": await asyncio.to_thread(service.list_runs, job_id, limit)}

    @router.get("/runs/{run_id}/download")
    async def download(run_id: str, request: Request):
        principal = ctx.require_principal(request, READ)
        try:
            run = await asyncio.to_thread(service.get_run, run_id)
            if run["state"] != "succeeded" or not run["object_key"]:
                raise BackupApiError("artifact_unavailable", "this run has no artifact", 409)
            spec = await asyncio.to_thread(service.destination_spec, run["destination_id"])
        except BackupApiError as exc:
            return failure(exc)
        stack = contextlib.AsyncExitStack()
        try:
            handle = await stack.enter_async_context(service.handle(spec))
            chunks = handle.read(run["object_key"])
            stack.push_async_callback(chunks.aclose)
            first = await anext(chunks, b"")
        except Exception as exc:
            await stack.aclose()
            await audit(principal, "server_backup.run.download", "server_backup_run", run_id,
                        "failure")
            if isinstance(exc, dest.DestinationError | BackupApiError):
                return failure(exc)
            return ctx.error_payload(classify(exc), "the artifact could not be read", 502)
        await audit(principal, "server_backup.run.download", "server_backup_run", run_id)

        async def body() -> AsyncIterator[bytes]:
            try:
                if first:
                    yield first
                async for chunk in chunks:
                    yield chunk
            finally:
                await stack.aclose()

        safe = re.sub(r"[^A-Za-z0-9_.-]+", "-", str(run["job_name"])).strip("-") or "backup"
        filename = f"{safe}-{Path(run['object_key']).name}"
        headers = {"Content-Disposition": f'attachment; filename="{filename}"',
                   "Cache-Control": "no-store"}
        if run.get("bytes"):
            headers["Content-Length"] = str(run["bytes"])
        return StreamingResponse(body(), media_type=dest.ARTIFACT_CONTENT_TYPE, headers=headers)

    @router.get("/sources")
    async def sources(request: Request):
        ctx.require_principal(request, READ)
        try:
            return await service.sources()
        except AgentError as exc:
            return failure(exc)

    register_outbound(ctx, service)
    ctx.routers.append(router)
    ctx.start_hooks.append(service.start)
    ctx.stop_hooks.append(service.stop)
