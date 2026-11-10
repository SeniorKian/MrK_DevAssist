"""Restore and test-restore of server backup runs (docs/28 S6, docs/31 §4).

A restore never touches live data. The chosen run's artifact is read from its
destination, checked against the SHA-256 recorded at backup time, decrypted and
authenticated (MRKBKP2 trailer + payload manifest), and unpacked into a hidden
staging folder under ``<data>/modules/server-backups/restores``. Only a fully
successful restore is renamed to its final folder, which must not exist yet, so
an existing folder is never overwritten or deleted.

* **Volumes** are unpacked from their tar. Every member is checked: absolute
  names, ``..`` components, writes through a symlink, hard links and device
  nodes are refused (a traversal attempt fails the whole restore with
  ``unsafe_archive``); symlinks are recreated only when they stay inside the
  restore folder.
* **Databases** are restored as their dump file (``.pgdump``, ``.sql``,
  ``.mongo.archive``, ``.rdb``). Loading a dump back into a running database is
  left to the operator (``pg_restore``/``mysql``/``mongorestore``): the Host
  Agent has no write path into containers or volumes (its volume mount is
  read-only by design), so restoring "in place" is out of scope here.

A *test restore* runs the same pipeline into a throw-away folder, checks the
result (tar fully readable, dump magic for PostgreSQL/Redis) and deletes it. An
optional cron schedule tests the newest successful run of every enabled job and
publishes ``server_backup.verify_failed`` on failure.

Records live in a small JSON file (no schema change); the newest
``KEEP_RECORDS`` are kept.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import logging
import os
import re
import secrets
import shutil
import stat
import tarfile
import threading
import time
from pathlib import Path, PurePosixPath
from typing import Any

from ..backup import BackupError
from ..module_context import Event
from .server_backups_cron import CronError, parse_cron
from .server_backups_crypto import decrypt_stream

LOGGER = logging.getLogger(__name__)
RESTORE_ROOT = "modules/server-backups/restores"
STATE_FILE = "server-backup-restores.json"
VERIFY_FILE = "server-backup-verify.json"
KEEP_RECORDS = 50
COPY_CHUNK = 1024 * 1024
_SEGMENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,79}$")
_DUMP_MAGIC = {"postgres": b"PGDMP", "redis": b"REDIS"}


class RestoreError(Exception):
    def __init__(self, code: str, message: str = "", status_code: int = 422) -> None:
        super().__init__(message or code)
        self.code = code
        self.message = message or code
        self.status_code = status_code


# --- pure helpers ------------------------------------------------------------------------


def validate_target(value: object) -> str | None:
    """A relative folder under the restore root: 1-4 plain segments, no dots-only parts."""
    if value is None:
        return None
    if not isinstance(value, str):
        raise RestoreError("invalid_target", "target must be a string")
    text = value.strip().strip("/")
    if not text:
        return None
    segments = text.split("/")
    if len(segments) > 4 or not all(_SEGMENT.match(part) for part in segments):
        raise RestoreError(
            "invalid_target", "use 1-4 folder names of letters, digits, '.', '_' or '-'"
        )
    return "/".join(segments)


def slug(text: str) -> str:
    value = re.sub(r"[^A-Za-z0-9_.-]+", "-", text).strip("-.")[:48]
    return value if value and _SEGMENT.match(value) else "backup"


def safe_file_name(name: object) -> str:
    text = name if isinstance(name, str) else ""
    value = re.sub(r"[^A-Za-z0-9_.-]+", "-", PurePosixPath(text).name).strip("-.")[:120]
    return value if value and _SEGMENT.match(value[:80]) else "payload.bin"


def _member_parts(name: str) -> tuple[str, ...]:
    if not name or "\x00" in name or "\\" in name or name.startswith("/"):
        raise RestoreError("unsafe_archive", "the archive contains an unsafe path")
    parts = tuple(part for part in PurePosixPath(name).parts if part not in {"", "."})
    if ".." in parts or (parts and os.name == "nt" and ":" in parts[0]):
        raise RestoreError("unsafe_archive", "the archive contains an unsafe path")
    return parts


def _inside(root: str, path: str) -> bool:
    try:
        return os.path.commonpath([root, path]) == root
    except ValueError:
        return False


def _ensure_dir(root: Path, parts: tuple[str, ...]) -> Path:
    """Create ``root/parts`` component by component, refusing symlinks and files."""
    current = root
    for part in parts:
        current = current / part
        try:
            info = os.lstat(current)
        except FileNotFoundError:
            os.mkdir(current, 0o755)
            continue
        if not stat.S_ISDIR(info.st_mode):
            raise RestoreError("unsafe_archive", "the archive writes through a link or file")
    return current


def extract_tar(tar_path: Path, root: Path, should_stop: Any = None) -> dict[str, int]:
    """Unpack a volume tar into ``root`` (created empty). Fails closed on traversal."""
    root.mkdir(parents=True, exist_ok=True)
    root_real = os.path.realpath(root)
    stats = {"files": 0, "dirs": 0, "links": 0, "skipped": 0, "bytes": 0}
    try:
        archive = tarfile.open(tar_path, mode="r:")  # noqa: SIM115 - closed below
    except tarfile.TarError as exc:
        raise RestoreError("invalid_archive", "the backup is not a readable archive") from exc
    with archive:
        try:
            for member in archive:
                if should_stop is not None and should_stop():
                    raise RestoreError("cancelled", "the restore was stopped")
                parts = _member_parts(member.name)
                if not parts:  # the archive root itself ("./")
                    if not member.isdir():
                        raise RestoreError("unsafe_archive", "the archive contains an unsafe path")
                    continue
                target = root.joinpath(*parts)
                if not _inside(root_real, os.path.normpath(os.path.join(root_real, *parts))):
                    raise RestoreError("unsafe_archive", "the archive contains an unsafe path")
                if member.isdir():
                    _ensure_dir(root, parts)
                    stats["dirs"] += 1
                    continue
                parent = _ensure_dir(root, parts[:-1])
                if not _inside(root_real, os.path.realpath(parent)):
                    raise RestoreError("unsafe_archive", "the archive writes outside the folder")
                with contextlib.suppress(FileNotFoundError):
                    existing = os.lstat(target)
                    if not stat.S_ISREG(existing.st_mode):
                        raise RestoreError("unsafe_archive", "the archive replaces a link")
                    os.unlink(target)  # duplicate member: the later one wins, as with tar
                if member.isfile():
                    source = archive.extractfile(member)
                    if source is None:
                        raise RestoreError("invalid_archive", "unreadable archive member")
                    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
                    flags |= getattr(os, "O_NOFOLLOW", 0)
                    descriptor = os.open(target, flags, 0o600)
                    with os.fdopen(descriptor, "wb") as output, source:
                        while chunk := source.read(COPY_CHUNK):
                            output.write(chunk)
                            stats["bytes"] += len(chunk)
                    with contextlib.suppress(OSError):
                        os.chmod(target, member.mode & 0o777)
                        os.utime(target, (member.mtime, member.mtime))
                    stats["files"] += 1
                elif member.issym():
                    link = member.linkname
                    resolved = os.path.normpath(os.path.join(os.path.dirname(target), link))
                    if (not link or os.path.isabs(link) or "\\" in link
                            or not _inside(root_real, os.path.realpath(resolved))):
                        stats["skipped"] += 1
                        continue
                    try:
                        os.symlink(link, target)
                    except (OSError, NotImplementedError):
                        stats["skipped"] += 1
                        continue
                    stats["links"] += 1
                else:  # hard links, devices, FIFOs: never recreated
                    stats["skipped"] += 1
        except tarfile.TarError as exc:
            raise RestoreError("invalid_archive", "the backup archive is damaged") from exc
    return stats


def check_dump(path: Path, kind: str) -> None:
    size = path.stat().st_size
    if size == 0:
        raise RestoreError("empty_dump", "the database dump is empty")
    magic = _DUMP_MAGIC.get(kind)
    if magic:
        with path.open("rb") as handle:
            if handle.read(len(magic)) != magic:
                raise RestoreError("invalid_dump", "the dump is not in the expected format")


def _decrypt_file(artifact: Path, payload: Path, passphrase: str) -> dict[str, Any]:
    with artifact.open("rb") as source, payload.open("xb") as output:
        return decrypt_stream(source, output, passphrase, decompress=True)


# --- manager -------------------------------------------------------------------------------


class RestoreManager:
    """Runs restores/test restores as background tasks of the backup service."""

    def __init__(self, service: Any) -> None:
        self.service = service
        self.ctx = service.ctx
        self.root = Path(self.ctx.data_dir) / RESTORE_ROOT
        control = Path(self.ctx.data_dir) / "control-plane"
        self.state_path = control / STATE_FILE
        self.verify_path = control / VERIFY_FILE
        self._file_lock = threading.Lock()
        self._live: dict[str, dict[str, Any]] = {}
        self._busy_runs: set[str] = set()
        self._tasks: set[asyncio.Task[None]] = set()
        self._verify_next: int | None = None
        self._start_lock = asyncio.Lock()

    # -- persistence ---------------------------------------------------------------------
    def _read_json(self, path: Path, default: Any) -> Any:
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return default

    def _write_json(self, path: Path, payload: Any) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_name(f".{path.name}.{secrets.token_hex(4)}.tmp")
        temporary.write_text(json.dumps(payload) + "\n", encoding="utf-8")
        os.replace(temporary, path)

    def _records(self) -> list[dict[str, Any]]:
        data = self._read_json(self.state_path, [])
        return [item for item in data if isinstance(item, dict)] if isinstance(data, list) else []

    def _store(self, record: dict[str, Any]) -> None:
        with self._file_lock:
            records = [item for item in self._records() if item.get("id") != record["id"]]
            records.insert(0, dict(record))
            records.sort(key=lambda item: str(item.get("id", "")), reverse=True)
            self._write_json(self.state_path, records[:KEEP_RECORDS])

    def list(self, run_id: str | None = None, limit: int = 50) -> list[dict[str, Any]]:
        merged = {item["id"]: item for item in self._records() if "id" in item}
        merged.update({key: dict(value) for key, value in self._live.items()})
        items = sorted(merged.values(), key=lambda item: str(item["id"]), reverse=True)
        if run_id:
            items = [item for item in items if item.get("run_id") == run_id]
        return items[:limit]

    def get(self, restore_id: str) -> dict[str, Any]:
        if restore_id in self._live:
            return dict(self._live[restore_id])
        for item in self._records():
            if item.get("id") == restore_id:
                return item
        raise RestoreError("not_found", "restore not found", 404)

    def recover(self) -> None:
        """After a crash: mark unfinished records failed and drop staging folders."""
        with self._file_lock:
            records = self._records()
            changed = False
            for item in records:
                if item.get("state") == "running":
                    item.update(state="failed", error_code="interrupted",
                                finished_at=int(time.time()))
                    changed = True
            if changed:
                self._write_json(self.state_path, records)
        if self.root.is_dir():
            for entry in self.root.iterdir():
                if entry.name.startswith((".restore-", ".verify-")):
                    shutil.rmtree(entry, ignore_errors=True)

    # -- verify schedule -----------------------------------------------------------------
    def verify_settings(self) -> dict[str, Any]:
        data = self._read_json(self.verify_path, {})
        schedule = data.get("schedule") if isinstance(data, dict) else None
        if schedule is not None:
            try:
                parse_cron(schedule)
            except CronError:
                schedule = None
        return {"schedule": schedule,
                "next_run_at": self._next_verify(schedule) if schedule else None}

    def _next_verify(self, schedule: str, after: float | None = None) -> int:
        if self._verify_next is None or after is not None:
            self._verify_next = self.service.next_run(schedule, after)
        return self._verify_next

    def save_verify_settings(self, schedule: str | None) -> dict[str, Any]:
        value = schedule.strip() if isinstance(schedule, str) and schedule.strip() else None
        if value is not None:
            try:
                parse_cron(value)
            except CronError as exc:
                raise RestoreError("invalid_schedule", str(exc)) from None
        with self._file_lock:
            self._write_json(self.verify_path, {"schedule": value})
        self._verify_next = None
        return self.verify_settings()

    def _latest_runs(self) -> list[str]:
        from sqlalchemy import select

        from ..models import ServerBackupJob, ServerBackupRun

        with self.ctx.database.session() as db:
            jobs = db.scalars(select(ServerBackupJob.id).where(
                ServerBackupJob.enabled.is_(True))).all()
            latest = []
            for job_id in jobs:
                run = db.scalar(select(ServerBackupRun.id).where(
                    ServerBackupRun.job_id == job_id, ServerBackupRun.state == "succeeded",
                    ServerBackupRun.object_key.is_not(None),
                ).order_by(ServerBackupRun.started_at.desc(), ServerBackupRun.id.desc()).limit(1))
                if run:
                    latest.append(run)
            return latest

    async def tick(self, now: float) -> list[str]:
        settings = await asyncio.to_thread(self.verify_settings)
        schedule = settings["schedule"]
        if not schedule or (settings["next_run_at"] or 0) > now:
            return []
        await asyncio.to_thread(self._next_verify, schedule, now)
        started = []
        for run_id in await asyncio.to_thread(self._latest_runs):
            if run_id in self._busy_runs:
                continue
            try:
                started.append(await self.start(run_id, "verify", trigger="schedule"))
            except RestoreError:
                continue
            except Exception:  # noqa: BLE001 - one bad job must not stop the others
                LOGGER.warning("scheduled test restore could not start", extra={"run_id": run_id})
        return started

    # -- start ---------------------------------------------------------------------------
    async def start(self, run_id: str, mode: str, *, target: str | None = None,
                    confirmation: str | None = None, trigger: str = "manual",
                    actor: int | None = None) -> str:
        run = await asyncio.to_thread(self.service.get_run, run_id)
        if run["state"] != "succeeded" or not run["object_key"]:
            raise RestoreError("artifact_unavailable", "this run has no artifact", 409)
        job = await asyncio.to_thread(self.service.job_snapshot, run["job_id"])
        if mode == "restore" and (confirmation or "").strip() != job["name"]:
            raise RestoreError("confirmation_mismatch", "type the backup name to confirm")
        folder = None
        if mode == "restore":
            stamp = time.strftime("%Y%m%d-%H%M%S", time.localtime())
            folder = validate_target(target) or f"{slug(job['name'])}-{stamp}"
            if (self.root / folder).exists():
                raise RestoreError("target_exists", "that folder already exists", 409)
        async with self._start_lock:
            if run_id in self._busy_runs:
                raise RestoreError("restore_running", "this backup is already being restored", 409)
            self._busy_runs.add(run_id)
        restore_id = f"{time.time_ns():016x}{secrets.token_hex(3)}"
        record: dict[str, Any] = {
            "id": restore_id, "run_id": run_id, "job_id": job["id"], "job_name": job["name"],
            "mode": mode, "trigger": trigger, "state": "running", "phase": "download",
            "progress": 0, "started_at": int(time.time()), "finished_at": None,
            "target": folder, "path": str(self.root / folder) if folder else None,
            "error_code": None, "details": {},
        }
        self._live[restore_id] = record
        try:
            await asyncio.to_thread(self._store, record)
        except BaseException:
            self._live.pop(restore_id, None)
            self._busy_runs.discard(run_id)
            raise
        task = asyncio.create_task(self._execute(record, run, job, actor),
                                   name=f"mrk-server-restore-{restore_id}")
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        return restore_id

    # -- execution -----------------------------------------------------------------------
    async def _execute(self, record: dict[str, Any], run: dict[str, Any], job: dict[str, Any],
                       actor: int | None) -> None:
        action = "server_backup.restore" if record["mode"] == "restore" else "server_backup.verify"
        try:
            async with self.service._semaphore:  # noqa: SLF001 - shares the backup slots
                details = await self._run(record, run, job)
        except asyncio.CancelledError:
            record.update(state="failed", error_code="cancelled", finished_at=int(time.time()))
            await asyncio.to_thread(self._store, record)
            self._live.pop(record["id"], None)
            self._busy_runs.discard(run["id"])
            raise
        except Exception as exc:
            code = getattr(exc, "code", None) or getattr(exc, "error_code", None)
            if not isinstance(code, str):
                from .server_backups import classify

                code = classify(exc)
            LOGGER.warning("server restore failed",
                           extra={"run_id": run["id"], "error_code": code, "mode": record["mode"]})
            # Audit and notify before the final state is visible, so anyone who
            # sees "failed" also finds the audit entry and the notification.
            try:
                await asyncio.to_thread(self.ctx.audit, actor, action, "server_backup_run",
                                        run["id"], "failure")
                kind = "restore_failed" if record["mode"] == "restore" else "verify_failed"
                title = ("Server backup restore failed" if record["mode"] == "restore"
                         else "Server backup test restore failed")
                self.ctx.events.publish(Event(
                    type=f"server_backup.{kind}", severity="error",
                    title=f"{title}: {job['name']}", message=f"error_code={code}",
                    module="server_backups", dedupe_key=f"server_backup_{kind}:{job['id']}",
                    details={"job_id": job["id"], "run_id": run["id"],
                             "restore_id": record["id"], "error_code": code},
                ))
            finally:
                record.update(state="failed", error_code=code, finished_at=int(time.time()))
                await self._finish(record, run)
            return
        try:
            await asyncio.to_thread(self.ctx.audit, actor, action, "server_backup_run",
                                    run["id"], "success")
            if record["mode"] == "restore":
                self.ctx.events.publish(Event(
                    type="server_backup.restored", severity="info",
                    title=f"Server backup restored: {job['name']}", module="server_backups",
                    dedupe_key=f"server_backup_restore:{job['id']}",
                    details={"job_id": job["id"], "run_id": run["id"],
                             "restore_id": record["id"]},
                ))
        finally:
            record.update(state="succeeded", phase="done", progress=100, details=details,
                          finished_at=int(time.time()))
            await self._finish(record, run)

    async def _finish(self, record: dict[str, Any], run: dict[str, Any]) -> None:
        await asyncio.to_thread(self._store, record)
        self._live.pop(record["id"], None)
        self._busy_runs.discard(run["id"])

    async def _run(self, record: dict[str, Any], run: dict[str, Any],
                   job: dict[str, Any]) -> dict[str, Any]:
        passphrase = (await asyncio.to_thread(self.service.job_passphrase, job["id"]))["passphrase"]
        spec = await asyncio.to_thread(self.service.destination_spec, run["destination_id"])
        work = self.root / f".{record['mode']}-{record['id']}"
        await asyncio.to_thread(work.mkdir, parents=True, exist_ok=False)
        try:
            return await self._run_in(work, record, run, job, passphrase, spec)
        finally:
            await asyncio.to_thread(shutil.rmtree, work, True)

    async def _run_in(self, work: Path, record: dict[str, Any], run: dict[str, Any],
                      job: dict[str, Any], passphrase: str, spec: Any) -> dict[str, Any]:
        artifact_bytes = int(run.get("bytes") or 0)
        needed = artifact_bytes + 2 * int(run.get("source_bytes") or 0) + 16 * 1024 * 1024
        if (await asyncio.to_thread(shutil.disk_usage, work)).free < needed:
            raise RestoreError("insufficient_space", "not enough free disk space to restore")

        # 1. fetch + compare with the digest recorded at backup time
        artifact = work / "artifact.mrkbak"
        digest = hashlib.sha256()
        received = 0
        handle_file = await asyncio.to_thread(artifact.open, "xb")
        try:
            async with self.service.handle(spec) as handle:
                chunks = handle.read(run["object_key"])
                try:
                    async for chunk in chunks:
                        digest.update(chunk)
                        received += len(chunk)
                        await asyncio.to_thread(handle_file.write, chunk)
                        if artifact_bytes:
                            record["progress"] = min(60, received * 60 // artifact_bytes)
                finally:
                    await chunks.aclose()
        finally:
            await asyncio.to_thread(handle_file.close)
        if run.get("sha256") and digest.hexdigest() != run["sha256"]:
            raise RestoreError("checksum_mismatch", "the stored backup file has changed")

        # 2. decrypt + authenticate (+ gunzip)
        record.update(phase="decrypt", progress=60)
        payload = work / "payload"
        try:
            header = await asyncio.to_thread(_decrypt_file, artifact, payload, passphrase)
        except BackupError as exc:  # wrong key, tampered or cut file: one plain code
            record["details"] = {"decrypt_error": exc.error_code}
            raise RestoreError("artifact_damaged", f"{exc.error_code}: {exc}") from exc
        await asyncio.to_thread(artifact.unlink)
        if header.get("job_id") not in (None, job["id"]):
            raise RestoreError("artifact_mismatch", "the backup file belongs to another job")

        # 3. unpack / check into the staging folder
        record.update(phase="extract", progress=80)
        content = work / "files"
        kind = job["source"]["kind"]
        details: dict[str, Any] = {"kind": kind, "sha256": digest.hexdigest(),
                                   "payload_name": header.get("payload_name")}
        if kind == "volume":
            details.update(await asyncio.to_thread(extract_tar, payload, content))
            await asyncio.to_thread(payload.unlink)
        else:
            await asyncio.to_thread(check_dump, payload, kind)
            name = safe_file_name(header.get("payload_name"))
            await asyncio.to_thread(content.mkdir)
            size = (await asyncio.to_thread(payload.stat)).st_size
            await asyncio.to_thread(os.replace, payload, content / name)
            details.update({"files": 1, "bytes": size, "file": name})
        if record["mode"] == "verify":
            return details

        # 4. publish the staged folder under its final name (never over existing data)
        record.update(phase="finish", progress=95)
        final = self.root / record["target"]

        def _publish() -> None:
            final.parent.mkdir(parents=True, exist_ok=True)
            if final.exists() or final.is_symlink():
                raise RestoreError("target_exists", "that folder already exists", 409)
            os.replace(content, final)

        await asyncio.to_thread(_publish)
        return details

    async def stop(self) -> None:
        tasks = list(self._tasks)
        for task in tasks:
            task.cancel()
        for task in tasks:
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task

    async def wait_idle(self) -> None:
        while self._tasks:
            await asyncio.gather(*list(self._tasks), return_exceptions=True)
