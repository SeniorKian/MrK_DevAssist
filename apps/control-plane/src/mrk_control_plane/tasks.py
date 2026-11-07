from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import re
import secrets
import shutil
import sqlite3
import time
from pathlib import Path
from urllib.parse import quote

import httpx
from sqlalchemy import func, select, update
from sqlalchemy.engine import make_url

from .catalog import PackageCatalog
from .database import Database, database_health
from .models import Task

LOGGER = logging.getLogger(__name__)
REQUIREMENT_NAME = re.compile(r"^([A-Za-z0-9_.-]+)(?:==([A-Za-z0-9_.+!-]+))?")


class TaskManager:
    def __init__(
        self,
        data_dir: Path,
        catalog: PackageCatalog,
        database: Database | None = None,
    ) -> None:
        self.data_dir = data_dir
        self.catalog = catalog
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
        self.tmp_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.trash_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._stop = asyncio.Event()
        self._wake = asyncio.Event()
        self._initialize()

    def _initialize(self) -> None:
        self.db.initialize()
        with self.db.session() as db, db.begin():
            db.execute(
                update(Task)
                .where(Task.state == "running")
                .values(state="pending", started_at=None)
            )
        if self.database is not None:
            try:
                self.database.chmod(0o600)
            except OSError:
                pass

    def enqueue(
        self,
        kind: str,
        payload: dict[str, object],
        actor_user_id: int,
        retry_of: str | None = None,
    ) -> str:
        if kind not in {
            "package.purge",
            "package.revalidate",
            "package.prefetch",
            "integrity.scan",
        }:
            raise ValueError("unsupported task kind")
        task_id = secrets.token_hex(12)
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
        return task_id

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

    def cancel(self, task_id: str) -> bool:
        with self.db.session() as db, db.begin():
            row = db.scalar(
                select(Task).where(
                    Task.id == task_id, Task.state.in_(("pending", "running"))
                )
            )
            if row is None:
                return False
            row.cancel_requested = True
            if row.state == "pending":
                row.state = "cancelled"
                row.finished_at = int(time.time())
            return True

    def _claim(self) -> tuple[str, str, dict[str, object]] | None:
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
            return row.id, row.kind, dict(row.payload)

    def _cancel_requested(self, task_id: str) -> bool:
        with self.db.session() as db:
            row = db.scalar(select(Task.cancel_requested).where(Task.id == task_id))
        return row is None or bool(row)

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
                .where(Task.id == task_id)
                .values(
                    state=state,
                    progress=100 if state == "succeeded" else 0,
                    result=result,
                    error_code=error_code,
                    finished_at=int(time.time()),
                )
            )

    async def run(self) -> None:
        while not self._stop.is_set():
            row = await asyncio.to_thread(self._claim)
            if row is None:
                self._wake.clear()
                try:
                    await asyncio.wait_for(self._wake.wait(), timeout=2)
                except TimeoutError:
                    pass
                continue
            task_id, kind, payload = row
            try:
                result = await self._execute(task_id, kind, payload)
                if await asyncio.to_thread(self._cancel_requested, task_id):
                    await asyncio.to_thread(self._finish, task_id, "cancelled")
                else:
                    await asyncio.to_thread(self._finish, task_id, "succeeded", result)
            except Exception as exc:  # worker boundary: persist a safe error code
                LOGGER.exception("task failed", extra={"task_id": task_id})
                await asyncio.to_thread(
                    self._finish, task_id, "failed", None, type(exc).__name__
                )

    async def stop(self) -> None:
        self._stop.set()
        self._wake.set()

    async def _execute(
        self, task_id: str, kind: str, payload: dict[str, object]
    ) -> dict[str, object]:
        if kind == "package.purge":
            return await self._purge(task_id, payload)
        if kind == "package.revalidate":
            await self._purge(task_id, {**payload, "revalidate": True})
            if payload["ecosystem"] == "pypi":
                url = (
                    "http://127.0.0.1:3141/root/pypi/+simple/"
                    f"{quote(str(payload['name']), safe='')}/"
                )
            else:
                url = f"http://127.0.0.1:4873/{quote(str(payload['name']), safe='@/')}"
            async with httpx.AsyncClient(timeout=90) as client:
                response = await client.get(url)
                response.raise_for_status()
            return {"revalidated": True, "status_code": response.status_code}
        if kind == "package.prefetch":
            return await self._prefetch(task_id, payload)
        if kind == "integrity.scan":
            return await asyncio.to_thread(self._integrity_scan, task_id)
        raise ValueError("unsupported task kind")

    def _integrity_scan(self, task_id: str) -> dict[str, object]:
        roots = (
            self.data_dir / "npm" / "storage",
            self.data_dir / "pypi" / "server" / "+files",
        )
        files = [
            path
            for root in roots
            if root.is_dir()
            for path in root.rglob("*")
            if path.is_file() or path.is_symlink()
        ]
        issues: list[dict[str, str]] = []
        total_bytes = 0
        hashed_files = 0
        for index, path in enumerate(files):
            if self._cancel_requested(task_id):
                break
            relative = str(path.relative_to(self.data_dir)).replace("\\", "/")
            try:
                if path.is_symlink():
                    issues.append({"path": relative, "code": "symlink_rejected"})
                    continue
                digest = hashlib.sha256()
                with path.open("rb") as artifact:
                    while chunk := artifact.read(1024 * 1024):
                        digest.update(chunk)
                total_bytes += path.stat().st_size
                hashed_files += 1
            except OSError:
                if len(issues) < 100:
                    issues.append({"path": relative, "code": "unreadable"})
            self._progress(task_id, int(((index + 1) / max(len(files), 1)) * 90))

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
                with sqlite3.connect(f"file:{database}?mode=ro", uri=True) as db:
                    result = str(db.execute("PRAGMA quick_check").fetchone()[0])
                database_results[database.name] = result
            except sqlite3.Error:
                database_results[database.name] = "unreadable"
        if not self.db.is_embedded_sqlite:
            database_results["postgresql"] = (
                "ok" if database_health(self.db.engine) else "unreadable"
            )
        database_ok = all(value == "ok" for value in database_results.values())
        return {
            "healthy": not issues and database_ok,
            "files_scanned": hashed_files,
            "bytes_scanned": total_bytes,
            "issues": issues,
            "issues_truncated": len(issues) >= 100,
            "databases": database_results,
        }

    async def _purge(
        self, task_id: str, payload: dict[str, object]
    ) -> dict[str, object]:
        ecosystem = str(payload["ecosystem"])
        name = str(payload["name"])
        preview = await asyncio.to_thread(self.catalog.purge_preview, ecosystem, name)
        if preview["blocked_by_pin"]:
            raise ValueError("package is pinned")
        if not payload.get("revalidate") and payload.get("confirmation") != preview["confirmation"]:
            raise ValueError("confirmation does not match")
        self._progress(task_id, 20)
        if ecosystem == "pypi":
            result = await self._purge_pypi(name)
        elif ecosystem == "npm":
            result = await asyncio.to_thread(self._purge_npm, task_id, name)
        else:
            raise ValueError("unknown ecosystem")
        self._progress(task_id, 90)
        return {**result, "preview": preview}

    async def _purge_pypi(self, name: str) -> dict[str, object]:
        auth_file = self.data_dir / "pypi" / "client" / "auth.json"
        auth_data = json.loads(auth_file.read_text(encoding="utf-8"))["auth"]
        credentials = next(iter(auth_data.values()))[0]
        serialized = base64.b64encode(
            f"{credentials[0]}:{credentials[1]}".encode("ascii")
        ).decode("ascii")
        url = f"http://127.0.0.1:3141/root/pypi/{quote(name, safe='')}?force=1"
        async with httpx.AsyncClient(timeout=90) as client:
            response = await client.delete(url, headers={"X-Devpi-Auth": serialized})
        if response.status_code not in {200, 404}:
            response.raise_for_status()
        return {"engine": "devpi", "status_code": response.status_code}

    def _purge_npm(self, task_id: str, name: str) -> dict[str, object]:
        storage = (self.data_dir / "npm" / "storage").resolve()
        target = (storage / Path(*name.split("/"))).resolve()
        if storage not in target.parents or not target.is_dir() or target.is_symlink():
            raise FileNotFoundError("npm package cache was not found")
        trash = self.trash_dir / f"{task_id}-{name.replace('/', '_')}"
        if trash.exists():
            raise FileExistsError("purge trash target already exists")
        shutil.move(str(target), str(trash))
        return {"engine": "verdaccio", "recoverable": True, "trash_id": trash.name}

    async def _prefetch(
        self, task_id: str, payload: dict[str, object]
    ) -> dict[str, object]:
        ecosystem = str(payload["ecosystem"])
        content = str(payload["content"])
        specs: list[str] = []
        if ecosystem == "pypi":
            for line in content.splitlines():
                match = REQUIREMENT_NAME.match(line.strip())
                if match and not line.lstrip().startswith("#"):
                    specs.append(
                        match.group(1)
                        + (f"=={match.group(2)}" if match.group(2) else "")
                    )
        elif ecosystem == "npm":
            payload_json = json.loads(content)
            for path, item in payload_json.get("packages", {}).items():
                if not path.startswith("node_modules/") or not item.get("version"):
                    continue
                package_name = path.removeprefix("node_modules/")
                specs.append(f"{package_name}@{item['version']}")
        else:
            raise ValueError("unknown ecosystem")
        specs = list(dict.fromkeys(specs))[:500]
        completed = 0
        destination = self.tmp_dir / task_id
        destination.mkdir(mode=0o700)
        try:
            for index, spec in enumerate(specs):
                if await asyncio.to_thread(self._cancel_requested, task_id):
                    break
                if ecosystem == "pypi":
                    command = (
                        "python",
                        "-m",
                        "pip",
                        "download",
                        "--no-deps",
                        "--disable-pip-version-check",
                        "--index-url",
                        "http://127.0.0.1:3141/root/pypi/+simple/",
                        "--dest",
                        str(destination),
                        spec,
                    )
                else:
                    command = (
                        "npm",
                        "pack",
                        spec,
                        "--registry=http://127.0.0.1:4873/",
                        f"--pack-destination={destination}",
                        "--ignore-scripts",
                    )
                process = await asyncio.create_subprocess_exec(
                    *command,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                if await process.wait() != 0:
                    raise RuntimeError("prefetch client failed")
                completed += 1
                self._progress(task_id, int(((index + 1) / max(len(specs), 1)) * 95))
        finally:
            shutil.rmtree(destination, ignore_errors=True)
        return {"requested": len(specs), "completed": completed}
