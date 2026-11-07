from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import socket
import sqlite3
import subprocess
import time
from pathlib import Path
from typing import Any

from sqlalchemy import MetaData, text

from . import __version__
from .backup import BackupManager
from .database import Database

ALLOWED_DATA_ROOTS = ("control-plane", "npm", "pypi", "logs")
HEARTBEAT_MAX_AGE_SECONDS = 30
OFFLINE_CONFIRMATION = "I_HAVE_STOPPED_MRK"


class RestoreError(RuntimeError):
    pass


def _assert_offline(data_dir: Path) -> None:
    heartbeat = data_dir / "control-plane" / "runtime-heartbeat"
    if heartbeat.is_file() and time.time() - heartbeat.stat().st_mtime < HEARTBEAT_MAX_AGE_SECONDS:
        raise RestoreError("MRK is still running; stop the service before restore")


def _read_secret(path: Path) -> str:
    if not path.is_file() or path.is_symlink() or path.stat().st_size > 4096:
        raise RestoreError("passphrase file is missing or unsafe")
    value = path.read_text(encoding="utf-8").strip()
    if not 16 <= len(value) <= 1024:
        raise RestoreError("passphrase file must contain 16-1024 characters")
    return value


def _load_plan(data_dir: Path, plan_id: str) -> dict[str, Any]:
    if re.fullmatch(r"[a-f0-9]{32}", plan_id) is None:
        raise RestoreError("invalid restore plan id")
    path = data_dir / "control-plane" / "restore-plans" / f"{plan_id}.json"
    if not path.is_file() or path.is_symlink():
        raise RestoreError("restore plan not found")
    plan = json.loads(path.read_text(encoding="utf-8"))
    if plan.get("format") != 1 or plan.get("plan_id") != plan_id:
        raise RestoreError("invalid restore plan")
    if int(plan.get("expires_at", 0)) < int(time.time()):
        raise RestoreError("restore plan has expired")
    return plan


def _apply_logical_database(database: Database, path: Path) -> None:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if payload.get("format") != 1 or not isinstance(payload.get("tables"), dict):
        raise RestoreError("logical database snapshot is invalid")
    tables_payload: dict[str, list[dict[str, Any]]] = payload["tables"]
    metadata = MetaData()
    with database.engine.begin() as connection:
        metadata.reflect(bind=connection, resolve_fks=True)
        backup_revision_rows = tables_payload.get("alembic_version")
        if (
            not isinstance(backup_revision_rows, list)
            or len(backup_revision_rows) != 1
            or not isinstance(backup_revision_rows[0], dict)
            or not isinstance(backup_revision_rows[0].get("version_num"), str)
        ):
            raise RestoreError("backup migration revision is missing or invalid")
        current_revision = connection.execute(
            text("SELECT version_num FROM alembic_version")
        ).scalar_one_or_none()
        backup_revision = backup_revision_rows[0]["version_num"]
        if current_revision != backup_revision:
            raise RestoreError(
                "backup schema revision does not match the running application "
                f"({backup_revision!r} != {current_revision!r})"
            )
        application_tables = {
            name: table
            for name, table in metadata.tables.items()
            if name != "alembic_version"
        }
        unknown = set(tables_payload) - set(application_tables) - {"alembic_version"}
        if unknown:
            raise RestoreError(f"backup contains unknown database tables: {sorted(unknown)}")
        ordered = [
            table for table in metadata.sorted_tables if table.name in application_tables
        ]
        for table in reversed(ordered):
            connection.execute(table.delete())
        for table in ordered:
            rows = tables_payload.get(table.name, [])
            if rows:
                connection.execute(table.insert(), rows)
        if database.dialect == "postgresql":
            preparer = database.engine.dialect.identifier_preparer
            for table in ordered:
                primary = list(table.primary_key.columns)
                if len(primary) != 1 or not primary[0].autoincrement:
                    continue
                table_name = preparer.quote(table.name)
                column_name = preparer.quote(primary[0].name)
                sequence_query = (  # noqa: S608 - reflected and dialect-quoted identifiers
                    "SELECT setval(pg_get_serial_sequence(:table_name, :column_name), "  # noqa: S608
                    f"COALESCE(MAX({column_name}), 1), COUNT(*) > 0) FROM {table_name}"  # noqa: S608
                )
                connection.execute(
                    text(sequence_query),
                    {"table_name": table.name, "column_name": primary[0].name},
                )


def _swap_tree(
    current: Path,
    restored: Path,
    rollback: Path,
    skip: frozenset[str] = frozenset(),
) -> None:
    current.mkdir(parents=True, exist_ok=True, mode=0o700)
    restored.mkdir(parents=True, exist_ok=True, mode=0o700)
    rollback.mkdir(parents=True, exist_ok=True, mode=0o700)
    for source in sorted(current.rglob("*"), reverse=True):
        if source.is_symlink():
            raise RestoreError(f"active data contains a symlink: {source}")
        if not source.is_file():
            continue
        relative = source.relative_to(current)
        if relative.as_posix() in skip:
            continue
        target = rollback / relative
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.replace(source, target)
    for source in sorted(restored.rglob("*")):
        if not source.is_file():
            continue
        relative = source.relative_to(restored)
        if relative.as_posix() in skip:
            continue
        target = current / relative
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.replace(source, target)


def _sqlite_snapshot(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with sqlite3.connect(source) as source_db, sqlite3.connect(destination) as target_db:
        source_db.backup(target_db)
    destination.chmod(0o600)


def _sqlite_restore(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with sqlite3.connect(source) as source_db, sqlite3.connect(destination) as target_db:
        source_db.backup(target_db)
        target_db.execute("PRAGMA wal_checkpoint(TRUNCATE)")


class RestoreExecutor:
    def __init__(self, data_dir: Path, database: Database) -> None:
        self.data_dir = data_dir.resolve()
        self.database = database
        self.manager = BackupManager(self.data_dir, __version__, database=database)

    def apply(
        self,
        plan_id: str,
        passphrase: str,
        confirmation: str,
        offline_confirmation: str,
    ) -> dict[str, object]:
        if offline_confirmation != OFFLINE_CONFIRMATION:
            raise RestoreError("offline confirmation phrase does not match")
        _assert_offline(self.data_dir)
        plan = _load_plan(self.data_dir, plan_id)
        if confirmation != plan.get("apply_confirmation"):
            raise RestoreError("apply confirmation phrase does not match")

        work = self.data_dir / "tmp" / f"restore-{plan_id}-{os.getpid()}"
        stage = work / "payload"
        work.mkdir(parents=True, exist_ok=False, mode=0o700)
        rollback_root = (
            self.data_dir
            / "backups"
            / "restore-rollbacks"
            / f"{int(time.time())}-{plan_id}"
        )
        rollback_root.mkdir(parents=True, exist_ok=False, mode=0o700)
        moved: list[str] = []
        try:
            extracted = self.manager.extract_validated(
                str(plan["filename"]), passphrase, stage
            )
            if extracted["backup_id"] != plan["backup_id"]:
                raise RestoreError("restore plan does not match backup")
            for child in stage.iterdir():
                if child.name not in ALLOWED_DATA_ROOTS:
                    raise RestoreError(f"backup contains unsupported root: {child.name}")
            for name in ALLOWED_DATA_ROOTS:
                (stage / name).mkdir(parents=True, exist_ok=True, mode=0o700)

            rollback_backup = self.manager.create(passphrase)
            journal = {
                "format": 1,
                "plan_id": plan_id,
                "backup_id": plan["backup_id"],
                "rollback_backup": rollback_backup["filename"],
                "state": "applying",
                "started_at": int(time.time()),
            }
            journal_path = rollback_root / "journal.json"
            journal_path.write_text(json.dumps(journal, sort_keys=True), encoding="utf-8")
            journal_path.chmod(0o600)

            if self.database.is_embedded_sqlite:
                self.database.dispose()
            for name in ALLOWED_DATA_ROOTS:
                current = self.data_dir / name
                rollback = rollback_root / "data" / name
                skip = (
                    frozenset(
                        {
                            "control-plane.sqlite3",
                            "control-plane.sqlite3-wal",
                            "control-plane.sqlite3-shm",
                            "tasks.sqlite3",
                            "tasks.sqlite3-wal",
                            "tasks.sqlite3-shm",
                        }
                    )
                    if name == "control-plane" and self.database.is_embedded_sqlite
                    else frozenset()
                )
                _swap_tree(current, stage / name, rollback, skip)
                moved.append(name)

            sqlite_rollbacks: list[tuple[Path, Path]] = []
            if self.database.is_embedded_sqlite:
                for filename in ("control-plane.sqlite3", "tasks.sqlite3"):
                    source = stage / "control-plane" / filename
                    current = self.data_dir / "control-plane" / filename
                    if not source.is_file():
                        continue
                    if current.is_file():
                        rollback = rollback_root / "sqlite" / filename
                        _sqlite_snapshot(current, rollback)
                        sqlite_rollbacks.append((rollback, current))
                    _sqlite_restore(source, current)

            logical = self.data_dir / "control-plane" / "database-logical.json"
            if not self.database.is_embedded_sqlite:
                if not logical.is_file():
                    raise RestoreError("logical database snapshot is missing")
                _apply_logical_database(self.database, logical)
                logical.unlink()

            receipt_dir = self.data_dir / "control-plane" / "restore-receipts"
            receipt_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
            receipt = {
                **journal,
                "state": "applied",
                "completed_at": int(time.time()),
                "rollback_data": str(rollback_root.relative_to(self.data_dir)),
            }
            receipt_path = receipt_dir / f"{plan_id}.json"
            receipt_path.write_text(
                json.dumps(receipt, sort_keys=True, separators=(",", ":")),
                encoding="utf-8",
            )
            receipt_path.chmod(0o600)
            journal["state"] = "applied"
            journal["completed_at"] = receipt["completed_at"]
            journal_path.write_text(json.dumps(journal, sort_keys=True), encoding="utf-8")
            return receipt
        except Exception:
            for name in reversed(moved):
                current = self.data_dir / name
                failed = rollback_root / "failed-restored-data" / name
                rollback = rollback_root / "data" / name
                _swap_tree(current, rollback, failed)
            if "sqlite_rollbacks" in locals():
                for rollback, current in sqlite_rollbacks:
                    if rollback.is_file():
                        _sqlite_restore(rollback, current)
            raise
        finally:
            if work.exists():
                shutil.rmtree(work, ignore_errors=True)


def _wait_for_port(host: str, port: int, timeout: float = 20.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return
        except OSError:
            time.sleep(0.2)
    raise RestoreError("embedded PGlite did not become ready")


def _start_embedded_pglite(data_dir: Path, database_url: str) -> subprocess.Popen[bytes] | None:
    if "127.0.0.1:5433" not in database_url and "localhost:5433" not in database_url:
        return None
    try:
        with socket.create_connection(("127.0.0.1", 5433), timeout=0.3):
            raise RestoreError("database port is already active; restore must run offline")
    except OSError:
        pass
    executable = Path("/opt/pglite/node_modules/.bin/pglite-server")
    if not executable.is_file():
        raise RestoreError("embedded PGlite runtime is unavailable")
    process = subprocess.Popen(  # noqa: S603 - fixed in-image executable and fixed arguments
        [
            str(executable),
            f"--db={data_dir / 'database' / 'pglite'}",
            "--port=5433",
            "--host=127.0.0.1",
            "--max-connections=1",
        ]
    )
    _wait_for_port("127.0.0.1", 5433)
    return process


def run() -> None:
    parser = argparse.ArgumentParser(description="Apply a validated MRK backup offline")
    subparsers = parser.add_subparsers(dest="command", required=True)
    apply_parser = subparsers.add_parser("apply")
    apply_parser.add_argument("--plan", required=True)
    apply_parser.add_argument("--passphrase-file", type=Path, required=True)
    apply_parser.add_argument("--confirmation", required=True)
    apply_parser.add_argument("--offline-confirm", required=True)
    args = parser.parse_args()

    data_dir = Path(os.getenv("MRK_DATA_DIR", "/data")).resolve()
    _assert_offline(data_dir)
    passphrase = _read_secret(args.passphrase_file)
    database_url = os.getenv("MRK_DATABASE_URL", "").strip() or None
    pglite: subprocess.Popen[bytes] | None = None
    try:
        if database_url:
            pglite = _start_embedded_pglite(data_dir, database_url)
        database = Database(data_dir, database_url)
        executor = RestoreExecutor(data_dir, database)
        receipt = executor.apply(
            args.plan,
            passphrase,
            args.confirmation,
            args.offline_confirm,
        )
        print(json.dumps(receipt, sort_keys=True))
    finally:
        passphrase = "\0" * len(passphrase)
        if pglite is not None:
            pglite.terminate()
            try:
                pglite.wait(timeout=10)
            except subprocess.TimeoutExpired:
                pglite.kill()


if __name__ == "__main__":
    run()
