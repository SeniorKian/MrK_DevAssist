from __future__ import annotations

import asyncio
import base64
import contextlib
import errno
import hashlib
import json
import logging
import os
import re
import secrets
import shutil
import sqlite3
import stat
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import quote, unquote, urljoin, urlsplit

import httpx
from sqlalchemy import func, select, update
from sqlalchemy.engine import make_url

from .backup import BackupCancelled
from .catalog import NPM_NAME, PYPI_NAME, PackageCatalog, normalize_pypi, valid_name
from .database import Database, database_health
from .models import Task
from .upstream_store import UpstreamStore

if TYPE_CHECKING:
    from .backup import BackupManager

LOGGER = logging.getLogger(__name__)
# Name, optional extras, optional "== version" (a trailing "*" makes it a prefix
# match, which we treat as metadata-only).
REQUIREMENT_NAME = re.compile(
    r"^([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)\s*"
    r"(?:\[[A-Za-z0-9._,\s-]*\])?\s*"
    r"(?:==\s*([A-Za-z0-9_.+!-]+)(\*)?)?"
)
PYPI_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+!_-]*$")
NPM_VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$")
HREF = re.compile(r"""(?i)href\s*=\s*["']([^"']+)["']""")
PEP440 = re.compile(
    r"^v?(?:(?P<epoch>[0-9]+)!)?(?P<release>[0-9]+(?:\.[0-9]+)*)"
    r"(?:[-_.]?(?P<pre_l>a|b|c|rc|alpha|beta|pre|preview)[-_.]?(?P<pre_n>[0-9]*))?"
    r"(?:-(?P<post_n1>[0-9]+)|[-_.]?(?P<post_l>post|rev|r)[-_.]?(?P<post_n2>[0-9]*))?"
    r"(?:[-_.]?(?P<dev_l>dev)[-_.]?(?P<dev_n>[0-9]*))?"
    r"(?:\+(?P<local>[a-z0-9]+(?:[-_.][a-z0-9]+)*))?$"
)
TRASH_ID = re.compile(r"^[a-f0-9]{24}$")
HEX = re.compile(r"^[0-9a-f]+$")
DEVPI_SIMPLE = "http://127.0.0.1:3141/root/pypi/+simple/"
DEVPI_ORIGIN = "http://127.0.0.1:3141"
VERDACCIO_ORIGIN = "http://127.0.0.1:4873"
MAX_FILES_PER_PYPI_SPEC = 40
MAX_ISSUES = 100
TASK_KINDS = frozenset(
    {
        "package.purge",
        "package.revalidate",
        "package.prefetch",
        "integrity.scan",
        "backup.create",
        "lifecycle.cleanup",
    }
)
# Once claimed these run to completion: stopping halfway would lose the result
# (e.g. the trash id of a purged package).
NON_CANCELLABLE_KINDS = frozenset({"package.purge", "package.revalidate"})
TRASH_EXPIRY_INTERVAL_SECONDS = 3600
MAX_CLEANUP_CANDIDATES = 500


def cleanup_confirmation(count: int) -> str:
    """The phrase a server-side clean-up of ``count`` packages must be confirmed with."""
    return f"CLEANUP {count} PACKAGES"

__all__ = [
    "NPM_NAME",
    "PYPI_NAME",
    "RetryRejected",
    "TaskError",
    "TaskManager",
    "canonical_version",
    "cleanup_confirmation",
    "distribution_version",
    "parse_prefetch_specs",
]


class TaskError(Exception):
    """A task failure with a stable, non-sensitive error code."""

    def __init__(self, code: str, message: str | None = None) -> None:
        super().__init__(message or code)
        self.code = code


class RetryRejected(Exception):
    def __init__(self, status_code: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code


class _Interrupted(Exception):
    """The worker is shutting down; the task must be re-queued or failed."""


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        return default


def _normalize_pypi(name: str) -> str:
    return normalize_pypi(name)


def canonical_version(value: str) -> tuple[object, ...] | str:
    """A PEP 440 comparison key (1.0 == 1.0.0, 1.0RC1 == 1.0rc1); raw lowercase otherwise."""
    lowered = value.strip().lower()
    match = PEP440.match(lowered)
    if match is None:
        return lowered
    release = [int(part) for part in match.group("release").split(".")]
    while len(release) > 1 and release[-1] == 0:
        release.pop()
    pre_letter = match.group("pre_l")
    pre: tuple[str, int] | None = None
    if pre_letter:
        letter = {"alpha": "a", "beta": "b", "c": "rc", "pre": "rc", "preview": "rc"}.get(
            pre_letter, pre_letter
        )
        pre = (letter, int(match.group("pre_n") or 0))
    post_number = match.group("post_n1") or match.group("post_n2")
    post = int(post_number or 0) if (match.group("post_n1") or match.group("post_l")) else None
    dev = int(match.group("dev_n") or 0) if match.group("dev_l") else None
    local = re.sub(r"[-_]", ".", match.group("local") or "")
    return (int(match.group("epoch") or 0), tuple(release), pre, post, dev, local)


def distribution_version(filename: str, project: str) -> str | None:
    """Version of a wheel/sdist filename if it belongs to project, else None."""
    lowered = filename.lower()
    if lowered.endswith(".whl"):
        parts = filename[:-4].split("-")
        if len(parts) < 5:
            return None
        name_part, version_part = parts[0], parts[1]
    else:
        for extension in (".tar.gz", ".tar.bz2", ".tar.xz", ".zip"):
            if lowered.endswith(extension):
                base = filename[: -len(extension)]
                break
        else:
            return None
        if "-" not in base:
            return None
        name_part, version_part = base.rsplit("-", 1)
    if _normalize_pypi(name_part) != _normalize_pypi(project):
        return None
    return version_part.lower()


def parse_prefetch_specs(ecosystem: str, content: str) -> list[tuple[str, str | None]]:
    """Return validated (name, version) pairs; anything unexpected is skipped."""
    specs: list[tuple[str, str | None]] = []
    if ecosystem == "pypi":
        for line in content.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith(("#", "-")):
                continue
            match = REQUIREMENT_NAME.match(stripped)
            if not match or not PYPI_NAME.match(match.group(1)):
                continue
            version = match.group(2)
            if match.group(3) or (version is not None and version.endswith(".")):
                version = None  # wildcard pins cannot select exact files
            if version is not None and not PYPI_VERSION.match(version):
                continue
            specs.append((match.group(1), version))
    elif ecosystem == "npm":
        payload_json = json.loads(content)
        if not isinstance(payload_json, dict):
            raise ValueError("lockfile must be a JSON object")
        packages = payload_json.get("packages", {})
        if not isinstance(packages, dict):
            raise ValueError("lockfile packages must be an object")
        for key, item in packages.items():
            if "node_modules/" not in key or not isinstance(item, dict):
                continue
            version = item.get("version")
            name = key.rsplit("node_modules/", 1)[1]
            if (
                not isinstance(version, str)
                or not NPM_NAME.match(name)
                or not NPM_VERSION.match(version)
            ):
                continue
            specs.append((name, version))
    else:
        raise ValueError("unknown ecosystem")
    return list(dict.fromkeys(specs))[:500]


class _Ticker:
    """True at most once per interval: throttles DB progress/cancel round trips."""

    def __init__(self, interval: float = 1.0) -> None:
        self.interval = interval
        self._last = 0.0

    def due(self) -> bool:
        now = time.monotonic()
        if now - self._last >= self.interval:
            self._last = now
            return True
        return False


class _Ledger:
    """Per-file digest cache so repeated integrity scans only re-hash changed files."""

    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.connection = sqlite3.connect(path)
        self.connection.execute(
            "CREATE TABLE IF NOT EXISTS files (path TEXT PRIMARY KEY, size INTEGER, "
            "mtime_ns INTEGER, digests TEXT, verified_at INTEGER)"
        )
        with contextlib.suppress(OSError):
            path.chmod(0o600)

    def count(self) -> int:
        return int(self.connection.execute("SELECT COUNT(*) FROM files").fetchone()[0])

    def get(self, path: str, size: int, mtime_ns: int, fresh_after: int) -> dict[str, str] | None:
        row = self.connection.execute(
            "SELECT size, mtime_ns, digests, verified_at FROM files WHERE path = ?", (path,)
        ).fetchone()
        if row is None or row[0] != size or row[1] != mtime_ns or row[3] < fresh_after:
            return None
        return dict(json.loads(row[2]))

    def put(self, path: str, size: int, mtime_ns: int, digests: dict[str, str]) -> None:
        self.connection.execute(
            "INSERT OR REPLACE INTO files VALUES (?, ?, ?, ?, ?)",
            (path, size, mtime_ns, json.dumps(digests), int(time.time())),
        )

    def prune(self, seen: set[str]) -> None:
        stale = [
            row[0]
            for row in self.connection.execute("SELECT path FROM files")
            if row[0] not in seen
        ]
        self.connection.executemany("DELETE FROM files WHERE path = ?", [(p,) for p in stale])

    def close(self) -> None:
        self.connection.commit()
        self.connection.close()


def _hash_file(path: str, algorithms: tuple[str, ...]) -> dict[str, str]:
    digests = {name: hashlib.new(name) for name in algorithms}
    with open(path, "rb") as artifact:  # noqa: PTH123 - os.walk yields str paths
        while chunk := artifact.read(1024 * 1024):
            for digest in digests.values():
                digest.update(chunk)
    return {name: digest.hexdigest() for name, digest in digests.items()}


def _npm_references(package_json: Path) -> dict[str, dict[str, str]]:
    """Tarball basename -> {"integrity": SRI, "shasum": sha1 hex} from Verdaccio metadata."""
    payload = json.loads(package_json.read_text(encoding="utf-8"))
    references: dict[str, dict[str, str]] = {}
    if not isinstance(payload, dict):
        raise ValueError("package metadata is not an object")
    versions = payload.get("versions", {})
    if isinstance(versions, dict):
        for item in versions.values():
            dist = item.get("dist") if isinstance(item, dict) else None
            if not isinstance(dist, dict) or not isinstance(dist.get("tarball"), str):
                continue
            basename = unquote(urlsplit(dist["tarball"]).path.rsplit("/", 1)[-1])
            entry: dict[str, str] = {}
            if isinstance(dist.get("integrity"), str):
                entry["integrity"] = dist["integrity"]
            if isinstance(dist.get("shasum"), str):
                entry["shasum"] = dist["shasum"].lower()
            if entry:
                references[basename] = entry
    attachments = payload.get("_attachments", {})
    if isinstance(attachments, dict):
        for filename, item in attachments.items():
            if isinstance(item, dict) and isinstance(item.get("shasum"), str):
                references.setdefault(str(filename), {"shasum": item["shasum"].lower()})
    return references


def _npm_matches(reference: dict[str, str], digests: dict[str, str]) -> bool | None:
    """True/False when a comparable reference exists, None when nothing can be compared."""
    integrity = reference.get("integrity")
    compared = False
    if integrity:
        for token in integrity.split():
            algorithm, _, value = token.partition("-")
            if algorithm not in {"sha512", "sha1"} or not value:
                continue
            compared = True
            expected = base64.b64encode(bytes.fromhex(digests[algorithm])).decode("ascii")
            if expected == value.split("?", 1)[0]:
                return True
    shasum = reference.get("shasum")
    if shasum:
        compared = True
        if shasum == digests["sha1"]:
            return True
    return False if compared else None


def _move_directory(source: Path, target: Path) -> None:
    """Move a directory: an atomic rename, or a copy when it crosses a mount point.

    The npm storage can be its own volume (a separate mount), and a rename
    between two mounts fails with EXDEV. The copy goes to a hidden sibling first and
    is renamed into place, so ``target`` never exists half-written; the source is
    removed only after that.
    """
    try:
        os.replace(source, target)
        return
    except OSError as exc:
        if exc.errno != errno.EXDEV:
            raise
    partial = target.with_name(f".{target.name}.partial")
    shutil.rmtree(partial, ignore_errors=True)
    try:
        shutil.copytree(source, partial, symlinks=True)
        os.replace(partial, target)
    except Exception:
        shutil.rmtree(partial, ignore_errors=True)
        raise
    shutil.rmtree(source)


class TaskManager:
    def __init__(
        self,
        data_dir: Path,
        catalog: PackageCatalog,
        database: Database | None = None,
        backup_manager: BackupManager | None = None,
        audit: Callable[..., None] | None = None,
    ) -> None:
        self.data_dir = data_dir
        self.catalog = catalog
        self.backup_manager = backup_manager
        self.audit = audit
        task_database = data_dir / "control-plane" / "tasks.sqlite3"
        self.db = database or Database(
            data_dir, f"sqlite:///{task_database.resolve().as_posix()}"
        )
        database_name = make_url(self.db.url).database
        self.database = (
            Path(database_name) if database_name and self.db.is_embedded_sqlite else None
        )
        self.tmp_dir = data_dir / "tmp" / "tasks"
        self.trash_dir = data_dir / "backups" / "purge-trash"
        self.ledger_path = data_dir / "control-plane" / "integrity-ledger.sqlite3"
        self.tmp_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.trash_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._stop = asyncio.Event()
        self._wake = asyncio.Event()
        self._abort = threading.Event()
        self._secrets: dict[str, str] = {}
        self._current: asyncio.Task[dict[str, object]] | None = None
        self._current_kind: str | None = None
        self._current_actor: int | None = None
        self._last_trash_expiry = 0.0
        self._initialize()

    # -- persistence ------------------------------------------------------
    def _initialize(self) -> None:
        self.db.initialize()
        now = int(time.time())
        with self.db.session() as db, db.begin():
            # A cancel requested before a restart must stay cancelled: _claim
            # skips cancel_requested rows, so re-queueing them would leave them
            # pending forever.
            db.execute(
                update(Task)
                .where(Task.state.in_(("running", "pending")), Task.cancel_requested.is_(True))
                .values(state="cancelled", finished_at=now)
            )
            # Backup passphrases only ever live in memory.
            db.execute(
                update(Task)
                .where(Task.state == "running", Task.kind == "backup.create")
                .values(state="failed", error_code="interrupted", progress=0, finished_at=now)
            )
            db.execute(
                update(Task)
                .where(Task.state == "pending", Task.kind == "backup.create")
                .values(state="failed", error_code="key_unavailable", finished_at=now)
            )
            db.execute(
                update(Task)
                .where(Task.state == "running")
                .values(state="pending", started_at=None, progress=0)
            )
        if self.database is not None:
            try:
                self.database.chmod(0o600)
            except OSError:
                pass

    def _audit(
        self,
        actor_user_id: int | None,
        action: str,
        object_type: str,
        object_id: str | None,
        result: str = "success",
    ) -> None:
        if self.audit is None:
            return
        try:
            self.audit(actor_user_id, action, object_type, object_id, result)
        except Exception:
            LOGGER.exception("cannot record task audit event", extra={"action": action})

    def enqueue(
        self,
        kind: str,
        payload: dict[str, object],
        actor_user_id: int,
        retry_of: str | None = None,
    ) -> str:
        if kind not in TASK_KINDS:
            raise ValueError("unsupported task kind")
        task_id = secrets.token_hex(12)
        self._insert(task_id, kind, payload, actor_user_id, retry_of)
        return task_id

    def enqueue_backup(self, profile: str, passphrase: str, actor_user_id: int) -> str:
        if profile not in {"config", "full"}:
            raise ValueError("unknown backup profile")
        if not 16 <= len(passphrase) <= 1024:
            raise ValueError("passphrase must be between 16 and 1024 characters")
        task_id = secrets.token_hex(12)
        # Stored before the row exists so the worker can never claim it without
        # the key; the passphrase is never persisted.
        self._secrets[task_id] = passphrase
        try:
            self._insert(task_id, "backup.create", {"profile": profile}, actor_user_id, None)
        except Exception:
            self._secrets.pop(task_id, None)
            raise
        return task_id

    def _insert(
        self,
        task_id: str,
        kind: str,
        payload: dict[str, object],
        actor_user_id: int,
        retry_of: str | None,
    ) -> None:
        now = int(time.time())
        with self.db.session() as db, db.begin():
            db.add(
                Task(
                    id=task_id,
                    kind=kind,
                    state="pending",
                    payload=payload,
                    actor_user_id=actor_user_id,
                    progress=0,
                    created_at=now,
                    retry_of=retry_of,
                    cancel_requested=False,
                )
            )
        self._wake.set()

    def list(self, limit: int = 100) -> list[dict[str, object]]:
        with self.db.session() as db:
            rows = db.scalars(
                select(Task)
                .order_by(Task.created_at.desc(), Task.id.desc())
                .limit(min(max(limit, 1), 500))
            ).all()
            return [
                {
                    "id": row.id,
                    "kind": row.kind,
                    "state": row.state,
                    "actor_user_id": row.actor_user_id,
                    "progress": row.progress,
                    "result": row.result,
                    "error_code": row.error_code,
                    "created_at": row.created_at,
                    "started_at": row.started_at,
                    "finished_at": row.finished_at,
                    "cancel_requested": row.cancel_requested,
                    "cancellable": row.state == "pending"
                    or (row.state == "running" and row.kind not in NON_CANCELLABLE_KINDS),
                    "retry_of": row.retry_of,
                }
                for row in rows
            ]

    def stats(self) -> dict[str, int]:
        counts = {
            "pending": 0,
            "running": 0,
            "succeeded": 0,
            "failed": 0,
            "cancelled": 0,
        }
        with self.db.session() as db:
            rows = db.execute(select(Task.state, func.count()).group_by(Task.state)).all()
        for state, count in rows:
            if state in counts:
                counts[state] = int(count)
        return counts

    def get_payload(self, task_id: str) -> tuple[str, dict[str, object], int] | None:
        with self.db.session() as db:
            row = db.get(Task, task_id)
        if row is None:
            return None
        return row.kind, dict(row.payload), int(row.actor_user_id)

    def get_retry_payload(
        self, task_id: str
    ) -> tuple[str, dict[str, object], int] | None:
        """Return a retryable task only after it has reached a terminal state."""
        with self.db.session() as db:
            row = db.scalar(
                select(Task).where(
                    Task.id == task_id, Task.state.in_(("failed", "cancelled"))
                )
            )
        if row is None:
            return None
        return row.kind, dict(row.payload), int(row.actor_user_id)

    def retry(
        self, task_id: str, actor_user_id: int, confirmation: str | None = None
    ) -> str:
        """Re-enqueue a terminal task; destructive retries need a fresh confirmation."""
        original = self.get_retry_payload(task_id)
        if original is None:
            raise RetryRejected(409, "task_not_retryable", "Task is not in a retryable state")
        kind, payload, _actor = original
        if kind == "backup.create":
            raise RetryRejected(
                409, "backup_retry_unsupported", "Start a new backup with a passphrase"
            )
        if kind == "package.purge":
            try:
                preview = self.catalog.purge_preview(
                    str(payload.get("ecosystem")), str(payload.get("name"))
                )
            except KeyError:
                raise RetryRejected(
                    409, "package_not_cached", "Package is no longer cached"
                ) from None
            expected = str(preview["confirmation"])
            if confirmation is None or not secrets.compare_digest(
                confirmation.strip(), expected
            ):
                raise RetryRejected(
                    400, "confirmation_required", f"Retry requires confirmation: {expected}"
                )
            payload = {**payload, "confirmation": expected}
        if kind == "lifecycle.cleanup":
            candidates = payload.get("candidates")
            expected = cleanup_confirmation(len(candidates) if isinstance(candidates, list) else 0)
            if confirmation is None or not secrets.compare_digest(
                confirmation.strip(), expected
            ):
                raise RetryRejected(
                    400, "confirmation_required", f"Retry requires confirmation: {expected}"
                )
        return self.enqueue(kind, payload, actor_user_id, task_id)

    def cancel(self, task_id: str) -> bool:
        with self.db.session() as db, db.begin():
            row = db.scalar(
                select(Task).where(
                    Task.id == task_id, Task.state.in_(("pending", "running"))
                )
            )
            if row is None:
                return False
            if row.state == "running" and row.kind in NON_CANCELLABLE_KINDS:
                return False
            row.cancel_requested = True
            if row.state == "pending":
                row.state = "cancelled"
                row.finished_at = int(time.time())
                self._secrets.pop(task_id, None)
            return True

    def _claim(self) -> tuple[str, str, dict[str, object], int] | None:
        with self.db.session() as db, db.begin():
            row = db.scalar(
                select(Task)
                .where(Task.state == "pending", Task.cancel_requested.is_(False))
                .order_by(Task.created_at, Task.id)
                .with_for_update(skip_locked=True)
                .limit(1)
            )
            if row is None:
                return None
            row.state = "running"
            row.started_at = int(time.time())
            row.progress = 1
            return row.id, row.kind, dict(row.payload), int(row.actor_user_id)

    def _cancel_requested(self, task_id: str) -> bool:
        with self.db.session() as db:
            row = db.scalar(select(Task.cancel_requested).where(Task.id == task_id))
        return row is None or bool(row)

    def _should_stop(self, task_id: str, ticker: _Ticker) -> bool:
        """Raise on shutdown; True when a cancel was requested (DB checked once per tick)."""
        if self._abort.is_set():
            raise _Interrupted()
        return ticker.due() and self._cancel_requested(task_id)

    def _progress(self, task_id: str, value: int) -> None:
        with self.db.session() as db, db.begin():
            db.execute(
                update(Task)
                .where(Task.id == task_id)
                .values(progress=min(max(value, 0), 100))
            )

    def _finish(
        self,
        task_id: str,
        state: str,
        result: dict[str, object] | None = None,
        error_code: str | None = None,
    ) -> None:
        with self.db.session() as db, db.begin():
            db.execute(
                update(Task)
                .where(Task.id == task_id, Task.state == "running")
                .values(
                    state=state,
                    progress=100 if state == "succeeded" else 0,
                    result=result,
                    error_code=error_code,
                    finished_at=int(time.time()),
                )
            )

    def _requeue_interrupted(self, task_id: str, kind: str) -> None:
        with self.db.session() as db, db.begin():
            row = db.get(Task, task_id)
            if row is None or row.state != "running":
                return
            if row.cancel_requested:
                row.state = "cancelled"
                row.finished_at = int(time.time())
            elif kind == "backup.create":
                row.state = "failed"
                row.error_code = "interrupted"
                row.finished_at = int(time.time())
            else:
                row.state = "pending"
                row.started_at = None
                row.progress = 0

    # -- worker -----------------------------------------------------------
    async def run(self) -> None:
        failures = 0
        while not self._stop.is_set():
            try:
                row = await asyncio.to_thread(self._claim)
            except Exception:
                # A database hiccup (PGlite restart, pool timeout) must not kill
                # the worker for good; back off and keep polling.
                failures += 1
                LOGGER.exception("task claim failed; retrying")
                await asyncio.sleep(min(2 ** min(failures, 5), 30))
                continue
            failures = 0
            if row is None:
                await self._maybe_expire_trash()
                self._wake.clear()
                try:
                    await asyncio.wait_for(self._wake.wait(), timeout=2)
                except TimeoutError:
                    pass
                continue
            task_id, kind, payload, actor = row
            self._current_kind = kind
            self._current_actor = actor
            execution = asyncio.create_task(self._execute(task_id, kind, payload))
            self._current = execution
            try:
                result = await execution
                state = (
                    "cancelled"
                    if await asyncio.to_thread(self._cancel_requested, task_id)
                    else "succeeded"
                )
                await asyncio.to_thread(self._finish, task_id, state, result)
                await asyncio.to_thread(self._audit, actor, f"task.{kind}", "task", task_id, state)
            except (_Interrupted, asyncio.CancelledError) as exc:
                await asyncio.to_thread(self._requeue_interrupted, task_id, kind)
                if isinstance(exc, asyncio.CancelledError) and not self._stop.is_set():
                    raise
            except Exception as exc:  # worker boundary: persist a safe error code
                LOGGER.exception("task failed", extra={"task_id": task_id})
                code = (
                    exc.code
                    if isinstance(exc, TaskError)
                    else str(getattr(exc, "error_code", "") or type(exc).__name__)
                )
                try:
                    await asyncio.to_thread(self._finish, task_id, "failed", None, code)
                except Exception:
                    LOGGER.exception("cannot record task failure", extra={"task_id": task_id})
                await asyncio.to_thread(
                    self._audit, actor, f"task.{kind}", "task", task_id, "failure"
                )
            finally:
                self._secrets.pop(task_id, None)
                self._current = None
                self._current_kind = None
                self._current_actor = None

    async def stop(self) -> None:
        self._stop.set()
        self._abort.set()
        self._wake.set()
        if self._current is not None and self._current_kind == "package.prefetch":
            self._current.cancel()

    async def _maybe_expire_trash(self) -> None:
        if time.monotonic() - self._last_trash_expiry < TRASH_EXPIRY_INTERVAL_SECONDS:
            return
        self._last_trash_expiry = time.monotonic()
        try:
            expired = await asyncio.to_thread(self.expire_trash)
        except Exception:
            LOGGER.exception("purge trash expiry failed")
            return
        for trash_id in expired:
            await asyncio.to_thread(
                self._audit, None, "package.trash.expire", "trash", trash_id
            )
        if self.backup_manager is not None:
            try:
                await asyncio.to_thread(self.backup_manager.cleanup_stale)
            except Exception:
                LOGGER.exception("backup temporary cleanup failed")

    async def _execute(
        self, task_id: str, kind: str, payload: dict[str, object]
    ) -> dict[str, object]:
        if kind == "package.purge":
            return await self._purge(task_id, payload)
        if kind == "package.revalidate":
            return await self._revalidate(task_id, payload)
        if kind == "package.prefetch":
            return await self._prefetch(task_id, payload)
        if kind == "integrity.scan":
            return await asyncio.to_thread(
                self._integrity_scan, task_id, bool(payload.get("full", False))
            )
        if kind == "backup.create":
            return await asyncio.to_thread(self._backup, task_id, payload)
        if kind == "lifecycle.cleanup":
            return await self._cleanup(task_id, payload, self._current_actor)
        raise ValueError("unsupported task kind")

    # -- server-side free-space clean-up ------------------------------------
    async def _cleanup(
        self, task_id: str, payload: dict[str, object], actor: int | None = None
    ) -> dict[str, object]:
        """Purge a clean-up preview's candidates one by one, in this one task.

        Every item is re-checked when its turn comes: a package pinned or
        quarantined after the preview is skipped, one no longer cached is
        skipped. npm purges go to the recycle bin (recoverable until expiry,
        so the space is freed only then); devpi purges free space at once.
        Cancelling stops between packages; already purged ones stay purged.
        """
        raw = payload.get("candidates")
        candidates = [
            item
            for item in (raw if isinstance(raw, list) else [])
            if isinstance(item, dict)
            and item.get("ecosystem") in {"npm", "pypi"}
            and isinstance(item.get("name"), str)
        ][:MAX_CLEANUP_CANDIDATES]
        target_bytes = payload.get("target_bytes")
        target = target_bytes if isinstance(target_bytes, int) and target_bytes > 0 else None
        purged: list[dict[str, object]] = []
        skipped: list[dict[str, object]] = []
        failed: list[dict[str, object]] = []
        reclaimed = trashed = freed_now = 0
        cancelled = False
        total = max(len(candidates), 1)
        for index, item in enumerate(candidates):
            if await asyncio.to_thread(self._should_stop, task_id, _Ticker(0)):
                cancelled = True
                break
            if target is not None and reclaimed >= target:
                skipped.extend(
                    {
                        "ecosystem": rest["ecosystem"],
                        "name": rest["name"],
                        "reason": "target_reached",
                    }
                    for rest in candidates[index:]
                )
                break
            ecosystem = str(item["ecosystem"])
            name = str(item["name"])
            try:
                preview = await asyncio.to_thread(self.catalog.purge_preview, ecosystem, name)
            except KeyError:
                skipped.append({"ecosystem": ecosystem, "name": name, "reason": "not_cached"})
                continue
            reason = (
                "package_pinned"
                if preview["blocked_by_pin"]
                else "package_quarantined"
                if preview.get("quarantined")
                else None
            )
            if reason is not None:
                skipped.append({"ecosystem": ecosystem, "name": name, "reason": reason})
                continue
            canonical = str(preview["name"])
            object_id = f"{ecosystem}:{canonical}"
            size_value = preview.get("size_bytes")
            size = size_value if isinstance(size_value, int) else 0
            try:
                if ecosystem == "pypi":
                    result = await self._purge_pypi(canonical)
                else:
                    result = await asyncio.to_thread(self._purge_npm, task_id, canonical)
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # one bad package must not stop the clean-up
                code = exc.code if isinstance(exc, TaskError) else type(exc).__name__
                LOGGER.warning(
                    "clean-up purge failed",
                    extra={"task_id": task_id, "ecosystem": ecosystem, "error_code": code},
                )
                failed.append({"ecosystem": ecosystem, "name": canonical, "error_code": code})
                await asyncio.to_thread(
                    self._audit, actor, "package.purge", "package", object_id, "failure"
                )
                continue
            finally:
                await asyncio.to_thread(
                    self._progress, task_id, 5 + int(((index + 1) / total) * 90)
                )
            self.catalog.invalidate()
            recoverable = bool(result.get("recoverable"))
            reclaimed += size
            if recoverable:
                trashed += size
            else:
                freed_now += size
            purged.append(
                {
                    "ecosystem": ecosystem,
                    "name": canonical,
                    "size_bytes": size,
                    "recoverable": recoverable,
                    "trash_id": result.get("trash_id"),
                }
            )
            await asyncio.to_thread(
                self._audit, actor, "package.purge", "package", object_id
            )
        if candidates and not purged and failed and not cancelled:
            raise TaskError("cleanup_failed")
        return {
            "requested": len(candidates),
            "target_bytes": target,
            "purged": purged,
            "skipped": skipped,
            "failed": failed,
            "purged_count": len(purged),
            "reclaimed_bytes": reclaimed,
            "trashed_bytes": trashed,
            "freed_immediately_bytes": freed_now,
            "cancelled": cancelled,
        }

    # -- backup -----------------------------------------------------------
    def _backup(self, task_id: str, payload: dict[str, object]) -> dict[str, object]:
        if self.backup_manager is None:
            raise TaskError("backup_unavailable")
        passphrase = self._secrets.pop(task_id, None)
        if passphrase is None:
            raise TaskError("key_unavailable")
        ticker = _Ticker()

        def should_stop() -> bool:
            return self._should_stop(task_id, ticker)

        try:
            created = self.backup_manager.create(
                passphrase, str(payload.get("profile", "config")), should_stop=should_stop
            )
        except BackupCancelled:
            return {"cancelled": True}
        pruned = self.backup_manager.prune()
        for filename in pruned:
            self._audit(None, "backup.prune", "backup", filename)
        return {**created, "pruned": pruned}

    # -- integrity --------------------------------------------------------
    def _integrity_scan(self, task_id: str, full: bool = False) -> dict[str, object]:
        ticker = _Ticker()
        issues: list[dict[str, str]] = []
        issue_counts: dict[str, int] = {}
        counters = {
            "files_scanned": 0,
            "bytes_scanned": 0,
            "bytes_hashed": 0,
            "verified": 0,
            "unverified": 0,
            "mismatched": 0,
            "ledger_hits": 0,
            "metadata_files": 0,
        }
        fresh_days = _env_int("MRK_INTEGRITY_FULL_RESCAN_DAYS", 30)
        fresh_after = 2**62 if full else int(time.time()) - max(fresh_days, 0) * 86400
        ledger = _Ledger(self.ledger_path)
        expected = max(ledger.count(), 1)
        seen: set[str] = set()
        cancelled = False

        def issue(path: str, code: str) -> None:
            issue_counts[code] = issue_counts.get(code, 0) + 1
            if len(issues) < MAX_ISSUES:
                issues.append({"path": path, "code": code})

        def digests_for(path: str, relative: str, algorithms: tuple[str, ...]) -> dict[str, str]:
            info = os.lstat(path)
            counters["files_scanned"] += 1
            counters["bytes_scanned"] += info.st_size
            seen.add(relative)
            cached = ledger.get(relative, info.st_size, info.st_mtime_ns, fresh_after)
            if cached is not None and all(name in cached for name in algorithms):
                counters["ledger_hits"] += 1
                return cached
            digests = _hash_file(path, algorithms)
            counters["bytes_hashed"] += info.st_size
            ledger.put(relative, info.st_size, info.st_mtime_ns, digests)
            return digests

        def tick() -> bool:
            if self._should_stop(task_id, ticker):
                return True
            if ticker.due():
                self._progress(task_id, int(min(counters["files_scanned"] / expected, 1) * 90))
            return False

        try:
            storage = self.data_dir / "npm" / "storage"
            for _name, directory in self.catalog._npm_package_dirs():  # noqa: SLF001
                if cancelled:
                    break
                references: dict[str, dict[str, str]] = {}
                metadata = directory / "package.json"
                if metadata.is_file() and not metadata.is_symlink():
                    counters["metadata_files"] += 1
                    try:
                        references = _npm_references(metadata)
                    except (OSError, UnicodeDecodeError, ValueError):
                        issue(self._relative(metadata), "metadata_unparseable")
                for entry in os.scandir(directory):
                    if tick():
                        cancelled = True
                        break
                    relative = self._relative(Path(entry.path))
                    if entry.is_symlink():
                        issue(relative, "symlink_rejected")
                        continue
                    if not entry.name.endswith(".tgz") or not entry.is_file(
                        follow_symlinks=False
                    ):
                        continue
                    try:
                        digests = digests_for(entry.path, relative, ("sha512", "sha1"))
                    except OSError:
                        issue(relative, "unreadable")
                        continue
                    reference = references.get(entry.name)
                    verdict = _npm_matches(reference, digests) if reference else None
                    self._count_verdict(verdict, relative, counters, issue)
            if storage.is_dir() and not cancelled:
                for entry in os.scandir(storage):
                    if entry.is_symlink():
                        issue(self._relative(Path(entry.path)), "symlink_rejected")

            pypi_root = self.data_dir / "pypi" / "server" / "+files"
            if pypi_root.is_dir() and not cancelled:
                for directory, dirnames, filenames in os.walk(pypi_root):
                    for name in list(dirnames):
                        if os.path.islink(os.path.join(directory, name)):
                            issue(self._relative(Path(directory, name)), "symlink_rejected")
                            dirnames.remove(name)
                    for filename in filenames:
                        if tick():
                            cancelled = True
                            break
                        path = os.path.join(directory, filename)
                        relative = self._relative(Path(path))
                        if os.path.islink(path):
                            issue(relative, "symlink_rejected")
                            continue
                        try:
                            digests = digests_for(path, relative, ("sha256", "md5"))
                        except OSError:
                            issue(relative, "unreadable")
                            continue
                        self._count_verdict(
                            self._devpi_matches(relative, digests), relative, counters, issue
                        )
                    if cancelled:
                        break
            if not cancelled:
                ledger.prune(seen)
        finally:
            ledger.close()

        database_results = self._database_checks()
        database_ok = all(value == "ok" for value in database_results.values())
        return {
            "healthy": not issue_counts and database_ok and not cancelled,
            "complete": not cancelled,
            "full": full,
            **counters,
            "issues": issues,
            "issue_counts": issue_counts,
            "issues_truncated": sum(issue_counts.values()) > len(issues),
            "databases": database_results,
        }

    def _relative(self, path: Path) -> str:
        return str(path.relative_to(self.data_dir)).replace("\\", "/")

    @staticmethod
    def _count_verdict(
        verdict: bool | None,
        relative: str,
        counters: dict[str, int],
        issue: Callable[[str, str], None],
    ) -> None:
        if verdict is True:
            counters["verified"] += 1
        elif verdict is False:
            counters["mismatched"] += 1
            issue(relative, "hash_mismatch")
        else:
            counters["unverified"] += 1

    @staticmethod
    def _devpi_matches(relative: str, digests: dict[str, str]) -> bool | None:
        # devpi stores mirrored files under +f/<hash[:3]>/<hash[3:16]>/<filename>,
        # where hash is the link's hash spec (sha256 by default, md5 on old mirrors).
        parts = relative.split("/")
        if len(parts) < 4 or parts[-4] != "+f":
            return None
        prefix = parts[-3] + parts[-2]
        if len(parts[-3]) != 3 or len(parts[-2]) != 13 or not HEX.match(prefix):
            return None
        return any(digest.startswith(prefix) for digest in digests.values())

    def _database_checks(self) -> dict[str, str]:
        database_results: dict[str, str] = {}
        sqlite_databases = {
            path
            for path in (
                self.data_dir / "control-plane" / "control-plane.sqlite3",
                self.database,
            )
            if path is not None
        }
        for database in sqlite_databases:
            if not database.is_file():
                continue
            try:
                uri = f"{database.resolve().as_uri()}?mode=ro"
                with contextlib.closing(sqlite3.connect(uri, uri=True)) as db:
                    result = str(db.execute("PRAGMA quick_check").fetchone()[0])
                database_results[database.name] = result
            except sqlite3.Error:
                database_results[database.name] = "unreadable"
        if not self.db.is_embedded_sqlite:
            database_results["postgresql"] = (
                "ok" if database_health(self.db.engine) else "unreadable"
            )
        return database_results

    # -- purge / trash ----------------------------------------------------
    async def _purge(
        self, task_id: str, payload: dict[str, object]
    ) -> dict[str, object]:
        ecosystem = str(payload["ecosystem"])
        name = str(payload["name"])
        if ecosystem not in {"npm", "pypi"}:
            raise ValueError("unknown ecosystem")
        preview = await asyncio.to_thread(self.catalog.purge_preview, ecosystem, name)
        if preview["blocked_by_pin"]:
            raise TaskError("package_pinned")
        if not payload.get("revalidate") and payload.get("confirmation") != preview["confirmation"]:
            raise TaskError("confirmation_mismatch")
        await asyncio.to_thread(self._progress, task_id, 20)
        canonical = str(preview["name"])
        if ecosystem == "pypi":
            result = await self._purge_pypi(canonical)
        else:
            result = await asyncio.to_thread(self._purge_npm, task_id, canonical)
        self.catalog.invalidate()
        await asyncio.to_thread(self._progress, task_id, 90)
        return {**result, "preview": preview}

    async def _purge_pypi(self, name: str) -> dict[str, object]:
        auth_file = self.data_dir / "pypi" / "client" / "auth.json"
        auth_data = json.loads(auth_file.read_text(encoding="utf-8"))["auth"]
        credentials = next(iter(auth_data.values()))[0]
        serialized = base64.b64encode(
            f"{credentials[0]}:{credentials[1]}".encode("ascii")
        ).decode("ascii")
        url = f"{DEVPI_ORIGIN}/root/pypi/{quote(name, safe='')}?force=1"
        async with httpx.AsyncClient(timeout=90, trust_env=False) as client:
            response = await client.delete(url, headers={"X-Devpi-Auth": serialized})
        if response.status_code not in {200, 404}:
            response.raise_for_status()
        return {"engine": "devpi", "status_code": response.status_code, "recoverable": False}

    def _npm_package_path(self, name: str) -> Path:
        """Lexical path of a cached npm package; refuses symlinks on every component."""
        if not valid_name("npm", name):
            raise FileNotFoundError("npm package cache was not found")
        storage = self.data_dir / "npm" / "storage"
        if os.path.islink(storage) or not storage.is_dir():
            raise FileNotFoundError("npm package cache was not found")
        current = storage
        for part in name.split("/"):
            current = current / part
            try:
                info = os.lstat(current)
            except FileNotFoundError:
                raise FileNotFoundError("npm package cache was not found") from None
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
                raise FileNotFoundError("npm package cache is not a plain directory")
        return current

    @staticmethod
    def _tree_size(path: Path) -> int:
        total = 0
        for directory, _dirnames, filenames in os.walk(path):
            for filename in filenames:
                with contextlib.suppress(OSError):
                    total += os.lstat(os.path.join(directory, filename)).st_size
        return total

    def _purge_npm(self, task_id: str, name: str) -> dict[str, object]:
        target = self._npm_package_path(name)
        trash_id = secrets.token_hex(12)
        entry = self.trash_dir / trash_id
        entry.mkdir(mode=0o700)
        now = int(time.time())
        retention_days = max(_env_int("MRK_PURGE_TRASH_RETENTION_DAYS", 7), 0)
        meta = {
            "format": 1,
            "trash_id": trash_id,
            "ecosystem": "npm",
            "name": name,
            "task_id": task_id,
            "trashed_at": now,
            "expires_at": now + retention_days * 86400,
            "size_bytes": self._tree_size(target),
        }
        try:
            self._write_json(entry / "meta.json", meta)
            _move_directory(target, entry / "payload")
        except Exception:
            shutil.rmtree(entry, ignore_errors=True)
            raise
        return {"engine": "verdaccio", "recoverable": True, "trash_id": trash_id}

    @staticmethod
    def _write_json(path: Path, payload: dict[str, object]) -> None:
        temporary = path.with_name(f".{path.name}.tmp")
        temporary.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
        temporary.chmod(0o600)
        temporary.replace(path)

    def _trash_meta(self, trash_id: str) -> tuple[Path, dict[str, Any]]:
        if not TRASH_ID.match(trash_id):
            raise KeyError(trash_id)
        entry = self.trash_dir / trash_id
        meta_path = entry / "meta.json"
        if entry.is_symlink() or not meta_path.is_file() or meta_path.is_symlink():
            raise KeyError(trash_id)
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        if not isinstance(meta, dict) or meta.get("trash_id") != trash_id:
            raise KeyError(trash_id)
        return entry, meta

    def list_trash(self) -> list[dict[str, object]]:
        items: list[dict[str, object]] = []
        if not self.trash_dir.is_dir():
            return items
        for entry in os.scandir(self.trash_dir):
            try:
                _path, meta = self._trash_meta(entry.name)
            except (KeyError, OSError, ValueError):
                continue
            items.append(
                {
                    key: meta.get(key)
                    for key in (
                        "trash_id",
                        "ecosystem",
                        "name",
                        "trashed_at",
                        "size_bytes",
                        "expires_at",
                    )
                }
            )
        items.sort(key=lambda item: int(item.get("trashed_at") or 0), reverse=True)
        return items

    def restore_trash(self, trash_id: str) -> dict[str, object]:
        entry, meta = self._trash_meta(trash_id)
        name = str(meta.get("name", ""))
        if meta.get("ecosystem") != "npm" or not valid_name("npm", name):
            raise KeyError(trash_id)
        payload = entry / "payload"
        if payload.is_symlink() or not payload.is_dir():
            raise KeyError(trash_id)
        storage = self.data_dir / "npm" / "storage"
        if os.path.islink(storage):
            raise FileNotFoundError("npm storage is not a plain directory")
        parts = name.split("/")
        parent = storage
        for part in parts[:-1]:
            parent = parent / part
            if os.path.islink(parent):
                raise FileNotFoundError("npm storage scope is a symlink")
            parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        target = parent / parts[-1]
        if os.path.lexists(target):
            raise FileExistsError("package is cached again; purge it before restoring")
        _move_directory(payload, target)
        shutil.rmtree(entry, ignore_errors=True)
        self.catalog.invalidate()
        return {k: meta.get(k) for k in ("trash_id", "ecosystem", "name", "size_bytes")}

    def delete_trash(self, trash_id: str) -> dict[str, object]:
        entry, meta = self._trash_meta(trash_id)
        # rmtree never follows symlinks inside the tree.
        shutil.rmtree(entry)
        return {k: meta.get(k) for k in ("trash_id", "ecosystem", "name", "size_bytes")}

    def expire_trash(self, now: int | None = None) -> list[str]:
        current = int(time.time()) if now is None else now
        expired: list[str] = []
        for item in self.list_trash():
            if int(item.get("expires_at") or 0) <= current:
                trash_id = str(item["trash_id"])
                try:
                    self.delete_trash(trash_id)
                except (KeyError, OSError):
                    LOGGER.exception("cannot expire purge trash entry")
                    continue
                expired.append(trash_id)
        return expired

    # -- revalidate -------------------------------------------------------
    async def _revalidate(
        self, task_id: str, payload: dict[str, object]
    ) -> dict[str, object]:
        ecosystem = str(payload["ecosystem"])
        name = str(payload["name"])
        # In offline mode the re-fetch cannot succeed, so a revalidate would
        # just destroy the cached copy.
        if await asyncio.to_thread(UpstreamStore(self.data_dir).offline, ecosystem):
            raise ValueError("revalidate is unavailable in offline mode")
        if await asyncio.to_thread(self.catalog.is_quarantined, ecosystem, name):
            raise TaskError("package_quarantined")
        timeout = httpx.Timeout(90, connect=5)
        async with httpx.AsyncClient(timeout=timeout, trust_env=False) as client:
            if ecosystem == "pypi":
                # devpi deletion is irreversible: prove the upstream answers first.
                router = os.getenv("MRK_PYPI_UPSTREAM_URL", "http://127.0.0.1:3142/simple/")
                probe_url = urljoin(router.rstrip("/") + "/", f"{quote(normalize_pypi(name))}/")
                try:
                    probe = await client.get(probe_url)
                except httpx.HTTPError:
                    raise TaskError("upstream_unavailable") from None
                if probe.status_code != 200:
                    raise TaskError("upstream_unavailable")
            purged = await self._purge(task_id, {**payload, "revalidate": True})
            if ecosystem == "pypi":
                url = f"{DEVPI_SIMPLE}{quote(str(purged['preview']['name']), safe='')}/"  # type: ignore[index]
            else:
                url = f"{VERDACCIO_ORIGIN}/{quote(name, safe='@')}"
            try:
                response = await client.get(url, headers={"Accept": "application/json"})
                response.raise_for_status()
            except httpx.HTTPError:
                trash_id = purged.get("trash_id")
                if trash_id:
                    # The re-fetch failed: put the previous cache back.
                    try:
                        await asyncio.to_thread(
                            self._restore_after_failed_revalidate, str(trash_id)
                        )
                    except Exception:
                        LOGGER.exception("cannot restore cache after failed revalidate")
                raise TaskError("refetch_failed") from None
        return {
            "revalidated": True,
            "status_code": response.status_code,
            "trash_id": purged.get("trash_id"),
        }

    def _restore_after_failed_revalidate(self, trash_id: str) -> None:
        entry, meta = self._trash_meta(trash_id)
        name = str(meta["name"])
        target = self.data_dir / "npm" / "storage" / Path(*name.split("/"))
        if os.path.lexists(target) and not os.path.islink(target):
            # Verdaccio may have created a partial directory during the failed fetch.
            shutil.rmtree(target, ignore_errors=True)
        self.restore_trash(trash_id)

    # -- prefetch ---------------------------------------------------------
    async def _prefetch(
        self, task_id: str, payload: dict[str, object]
    ) -> dict[str, object]:
        """Warm the local caches by requesting packages from devpi/Verdaccio.

        This talks HTTP to the local engines only. The image ships neither pip
        nor the npm CLI, and passing untrusted lockfile names to a CLI allowed
        argument injection and fetching from arbitrary remotes.
        """
        ecosystem = str(payload["ecosystem"])
        specs = parse_prefetch_specs(ecosystem, str(payload["content"]))
        completed = 0
        failed = 0
        skipped = 0
        cancelled = False
        ticker = _Ticker()
        timeout = httpx.Timeout(300, connect=5)
        async with httpx.AsyncClient(timeout=timeout, trust_env=False) as client:
            for index, (name, version) in enumerate(specs):
                if await asyncio.to_thread(self._should_stop, task_id, _Ticker(0)):
                    cancelled = True
                    break
                if await asyncio.to_thread(self.catalog.is_quarantined, ecosystem, name):
                    skipped += 1
                    continue
                try:
                    if ecosystem == "pypi":
                        await self._prefetch_pypi(client, task_id, ticker, name, version)
                    else:
                        await self._prefetch_npm(client, name, str(version))
                    completed += 1
                except asyncio.CancelledError:
                    raise
                except _CancelledSpec:
                    cancelled = True
                    break
                except (httpx.HTTPError, ValueError, KeyError, TypeError):
                    failed += 1
                    LOGGER.warning(
                        "prefetch item failed",
                        extra={"task_id": task_id, "ecosystem": ecosystem},
                    )
                await asyncio.to_thread(
                    self._progress, task_id, int(((index + 1) / max(len(specs), 1)) * 95)
                )
        if specs and completed == 0 and failed > 0 and not cancelled:
            raise TaskError("prefetch_failed")
        return {
            "requested": len(specs),
            "completed": completed,
            "failed": failed,
            "skipped_quarantined": skipped,
            "cancelled": cancelled,
        }

    @staticmethod
    async def _drain(client: httpx.AsyncClient, url: str) -> None:
        async with client.stream("GET", url) as response:
            response.raise_for_status()
            async for _chunk in response.aiter_bytes():
                pass

    async def _prefetch_pypi(
        self,
        client: httpx.AsyncClient,
        task_id: str,
        ticker: _Ticker,
        name: str,
        version: str | None,
    ) -> None:
        page_url = f"{DEVPI_SIMPLE}{quote(name, safe='')}/"
        page = await client.get(page_url)
        page.raise_for_status()
        if version is None:
            return  # project metadata is now cached; files need a pinned version
        wanted = canonical_version(version)
        fetched = 0
        for href in HREF.findall(page.text):
            absolute = urljoin(page_url, href)
            parts = urlsplit(absolute)
            filename = unquote(parts.path.rsplit("/", 1)[-1])
            found = distribution_version(filename, name)
            if found is None or canonical_version(found) != wanted:
                continue
            if await asyncio.to_thread(self._should_stop, task_id, ticker):
                raise _CancelledSpec()
            # Only ever fetch from the local devpi, whatever the page says.
            await self._drain(client, f"{DEVPI_ORIGIN}{parts.path}")
            fetched += 1
            if fetched >= MAX_FILES_PER_PYPI_SPEC:
                break
        if fetched == 0:
            raise ValueError("no files for the requested version")

    async def _prefetch_npm(self, client: httpx.AsyncClient, name: str, version: str) -> None:
        metadata = await client.get(
            f"{VERDACCIO_ORIGIN}/{quote(name, safe='@')}",
            headers={"Accept": "application/json"},
        )
        metadata.raise_for_status()
        tarball = metadata.json()["versions"][version]["dist"]["tarball"]
        path = urlsplit(str(tarball)).path
        if not path.startswith("/"):
            raise ValueError("invalid tarball path")
        await self._drain(client, f"{VERDACCIO_ORIGIN}{path}")


class _CancelledSpec(Exception):
    pass
