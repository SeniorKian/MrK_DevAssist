from __future__ import annotations

import argparse
import contextlib
import json
import os
import re
import shutil
import socket
import subprocess
import time
from pathlib import Path
from typing import Any

from sqlalchemy import MetaData, text

from . import __version__
from .backup import DATA_ROOTS, BackupManager
from .database import Database
from .models import AuditEvent

ALLOWED_DATA_ROOTS = DATA_ROOTS
HEARTBEAT_MAX_AGE_SECONDS = 30
OFFLINE_CONFIRMATION = "I_HAVE_STOPPED_MRK"
DEFAULT_ENGINE_PORTS = "4873,3141,3142,8080"
LOCK_NAME = "restore.lock"


class RestoreError(RuntimeError):
    pass


def _engine_ports() -> list[int]:
    raw = os.getenv("MRK_RESTORE_ENGINE_PORTS", DEFAULT_ENGINE_PORTS)
    ports: list[int] = []
    for item in raw.split(","):
        item = item.strip()
        if item.isdigit() and 0 < int(item) < 65536:
            ports.append(int(item))
    return ports


def _port_open(port: int) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.3):
            return True
    except OSError:
        return False


def _assert_offline(data_dir: Path) -> None:
    heartbeat = data_dir / "control-plane" / "runtime-heartbeat"
    if heartbeat.is_file() and time.time() - heartbeat.stat().st_mtime < HEARTBEAT_MAX_AGE_SECONDS:
        raise RestoreError("Pishkar is still running; stop the service before restore")
    # The package engines write into npm/ and pypi/ independently of the
    # control plane; swapping those trees under a live engine corrupts them.
    busy = [port for port in _engine_ports() if _port_open(port)]
    if busy:
        raise RestoreError(
            f"MRK services are still listening on ports {busy}; stop them before restore"
        )


def restore_in_progress(data_dir: Path) -> bool:
    """True while an offline restore holds its lock (startup should refuse)."""
    lock = data_dir / "tmp" / LOCK_NAME
    if not lock.exists():
        return False
    try:
        import fcntl
    except ImportError:  # pragma: no cover - non-POSIX development hosts
        return True
    try:
        with lock.open("a") as handle:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        return False
    except OSError:
        return True


class _RestoreLock:
    """Exclusive restore lock; released automatically if the process dies (POSIX)."""

    def __init__(self, data_dir: Path) -> None:
        self.path = data_dir / "tmp" / LOCK_NAME
        self.handle: Any = None

    def __enter__(self) -> _RestoreLock:
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            import fcntl
        except ImportError:  # pragma: no cover - non-POSIX development hosts
            try:
                self.handle = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            except FileExistsError:
                raise RestoreError("another restore is in progress") from None
            return self
        self.handle = self.path.open("a")
        try:
            fcntl.flock(self.handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            self.handle.close()
            raise RestoreError("another restore is in progress") from None
        return self

    def __exit__(self, *_exc: object) -> None:
        if isinstance(self.handle, int):
            os.close(self.handle)
            with contextlib.suppress(OSError):
                self.path.unlink()
            return
        if self.handle is not None:
            self.handle.close()
            with contextlib.suppress(OSError):
                self.path.unlink()


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


def _write_journal(path: Path, journal: dict[str, Any]) -> None:
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(json.dumps(journal, sort_keys=True), encoding="utf-8")
    temporary.chmod(0o600)
    os.replace(temporary, path)


def _rollback_units(
    data_dir: Path, rollback_root: Path, units: dict[str, dict[str, bool]]
) -> list[str]:
    """Reverse the directory swaps recorded in ``units``; returns errors (empty = clean)."""
    errors: list[str] = []
    for unit, state in reversed(list(units.items())):
        current = data_dir / unit
        try:
            if state.get("moved_in") and os.path.lexists(current):
                failed = rollback_root / "failed-restored-data" / unit
                failed.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                os.replace(current, failed)
            state["moved_in"] = False
            saved = rollback_root / "data" / unit
            if state.get("moved_out") and os.path.lexists(saved):
                current.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                os.replace(saved, current)
            state["moved_out"] = False
        except OSError as exc:
            errors.append(f"{unit}: {exc}")
    return errors


class RestoreExecutor:
    def __init__(self, data_dir: Path, database: Database) -> None:
        self.data_dir = data_dir.resolve()
        self.database = database
        self.manager = BackupManager(self.data_dir, __version__, database=database)

    def _check_stage(self, stage: Path, units: list[str]) -> None:
        for directory, _dirnames, filenames in os.walk(stage):
            for filename in filenames:
                relative = os.path.relpath(os.path.join(directory, filename), stage)
                relative = relative.replace("\\", "/")
                if not any(relative.startswith(f"{unit}/") for unit in units):
                    raise RestoreError(f"backup contains unsupported path: {relative}")
        for unit in units:
            if unit.split("/", 1)[0] not in ALLOWED_DATA_ROOTS:
                raise RestoreError(f"backup contains unsupported root: {unit}")
            (stage / unit).mkdir(parents=True, exist_ok=True, mode=0o700)
            current = self.data_dir / unit
            if os.path.islink(current) or (
                "/" in unit and os.path.islink(current.parent)
            ):
                raise RestoreError(f"active data root is a symlink: {unit}")
        control = stage / "control-plane"
        if "control-plane" in units:
            if self.database.is_embedded_sqlite:
                if not (control / "control-plane.sqlite3").is_file():
                    # Swapping in a control-plane tree without its database
                    # would boot an empty appliance into first-run setup.
                    raise RestoreError(
                        "backup has no SQLite database; it was taken with a different "
                        "database backend"
                    )
            elif not (control / "database-logical.json").is_file():
                raise RestoreError("logical database snapshot is missing")

    def _record_audit(self, plan: dict[str, Any], result: str) -> None:
        try:
            with self.database.session() as db, db.begin():
                db.add(
                    AuditEvent(
                        actor_user_id=plan.get("created_by_user_id"),
                        action="backup.restore.apply",
                        object_type="backup",
                        object_id=str(plan.get("backup_id"))[:255],
                        result=result,
                        source_ip=None,
                        request_id=f"restore-{plan['plan_id']}"[:128],
                        occurred_at=int(time.time()),
                    )
                )
        except Exception as exc:  # the restore itself must not fail on audit
            print(json.dumps({"warning": "cannot record restore audit", "error": str(exc)}))

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
        with _RestoreLock(self.data_dir):
            return self._apply_locked(plan_id, passphrase, confirmation)

    def _apply_locked(
        self, plan_id: str, passphrase: str, confirmation: str
    ) -> dict[str, object]:
        plan = _load_plan(self.data_dir, plan_id)
        if confirmation != plan.get("apply_confirmation"):
            raise RestoreError("apply confirmation phrase does not match")

        work = self.data_dir / "tmp" / f"restore-{plan_id}-{os.getpid()}"
        stage = work / "payload"
        work.mkdir(parents=True, exist_ok=False, mode=0o700)
        rollback_root = (
            self.data_dir / "backups" / "restore-rollbacks" / f"{int(time.time())}-{plan_id}"
        )
        rollback_root.mkdir(parents=True, exist_ok=False, mode=0o700)
        journal_path = rollback_root / "journal.json"
        units: dict[str, dict[str, bool]] = {}
        journal: dict[str, Any] = {
            "format": 2,
            "plan_id": plan_id,
            "backup_id": plan["backup_id"],
            "state": "staging",
            "started_at": int(time.time()),
            "dialect": self.database.dialect,
            "units": units,
            "database_applied": False,
        }
        _write_journal(journal_path, journal)
        try:
            extracted = self.manager.extract_validated(
                str(plan["filename"]), passphrase, stage
            )
            if extracted["backup_id"] != plan["backup_id"]:
                raise RestoreError("restore plan does not match backup")
            unit_names = [str(unit) for unit in extracted["roots"]]  # type: ignore[union-attr]
            self._check_stage(stage, unit_names)

            if self.database.is_embedded_sqlite:
                self.database.dispose()
            else:
                # Taken before anything changes so a failed apply can put the
                # database back as well as the files.
                self.manager._snapshot_logical_database(  # noqa: SLF001
                    rollback_root / "database-logical.json"
                )
            journal["state"] = "applying"
            for unit in unit_names:
                units[unit] = {"moved_out": False, "moved_in": False}
            _write_journal(journal_path, journal)

            for unit in unit_names:
                current = self.data_dir / unit
                saved = rollback_root / "data" / unit
                if os.path.lexists(current):
                    saved.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                    os.replace(current, saved)
                    units[unit]["moved_out"] = True
                    _write_journal(journal_path, journal)
                current.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                os.replace(stage / unit, current)
                units[unit]["moved_in"] = True
                _write_journal(journal_path, journal)

            if not self.database.is_embedded_sqlite and "control-plane" in units:
                logical = self.data_dir / "control-plane" / "database-logical.json"
                journal["database_applied"] = True
                _write_journal(journal_path, journal)
                _apply_logical_database(self.database, logical)
                logical.unlink()

            receipt_dir = self.data_dir / "control-plane" / "restore-receipts"
            receipt_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
            previous = rollback_root / "data" / "control-plane" / "restore-receipts"
            if previous.is_dir():
                for old in previous.glob("*.json"):
                    if not (receipt_dir / old.name).exists() and not old.is_symlink():
                        shutil.copy2(old, receipt_dir / old.name)
            receipt = {
                "format": 2,
                "plan_id": plan_id,
                "backup_id": plan["backup_id"],
                "profile": extracted["profile"],
                "roots": unit_names,
                "state": "applied",
                "started_at": journal["started_at"],
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
            _write_journal(journal_path, journal)
            self._record_audit(plan, "success")
            return receipt
        except BaseException as exc:
            errors = self._rollback(rollback_root, journal, journal_path)
            if errors:
                raise RestoreError(
                    "restore failed and rollback is incomplete; run "
                    f"'mrk-restore recover --rollback {rollback_root.name}': {errors}"
                ) from exc
            self._record_audit(plan, "failure")
            raise
        finally:
            if work.exists():
                shutil.rmtree(work, ignore_errors=True)

    def _rollback(
        self, rollback_root: Path, journal: dict[str, Any], journal_path: Path
    ) -> list[str]:
        units: dict[str, dict[str, bool]] = journal.get("units", {})
        touched = any(state.get("moved_out") or state.get("moved_in") for state in units.values())
        if self.database.is_embedded_sqlite:
            self.database.dispose()
        errors = _rollback_units(self.data_dir, rollback_root, units)
        if journal.get("database_applied") and not self.database.is_embedded_sqlite:
            snapshot = rollback_root / "database-logical.json"
            try:
                _apply_logical_database(self.database, snapshot)
                journal["database_applied"] = False
            except Exception as exc:
                errors.append(f"database: {exc}")
        journal["state"] = "rollback_failed" if errors else ("rolled_back" if touched else "failed")
        journal["errors"] = errors
        try:
            _write_journal(journal_path, journal)
        except OSError as exc:
            errors.append(f"journal: {exc}")
        return errors

    def recover(self, rollback_name: str) -> dict[str, object]:
        """Finish the rollback of an interrupted restore from its journal."""
        if re.fullmatch(r"[0-9]+-[a-f0-9]{32}", rollback_name) is None:
            raise RestoreError("invalid rollback name")
        _assert_offline(self.data_dir)
        with _RestoreLock(self.data_dir):
            rollback_root = self.data_dir / "backups" / "restore-rollbacks" / rollback_name
            journal_path = rollback_root / "journal.json"
            if not journal_path.is_file() or journal_path.is_symlink():
                raise RestoreError("restore journal not found")
            journal = json.loads(journal_path.read_text(encoding="utf-8"))
            if journal.get("format") != 2:
                raise RestoreError("unsupported restore journal")
            if journal.get("state") in {"applied", "rolled_back", "failed"}:
                return {"state": journal["state"], "changed": False}
            errors = self._rollback(rollback_root, journal, journal_path)
            if errors:
                raise RestoreError(f"rollback is still incomplete: {errors}")
            return {"state": journal["state"], "changed": True}


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
    if _port_open(5433):
        raise RestoreError("database port is already active; restore must run offline")
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
    parser = argparse.ArgumentParser(description="Apply a validated Pishkar backup offline")
    subparsers = parser.add_subparsers(dest="command", required=True)
    apply_parser = subparsers.add_parser("apply")
    apply_parser.add_argument("--plan", required=True)
    apply_parser.add_argument("--passphrase-file", type=Path, required=True)
    apply_parser.add_argument("--confirmation", required=True)
    apply_parser.add_argument("--offline-confirm", required=True)
    recover_parser = subparsers.add_parser("recover")
    recover_parser.add_argument("--rollback", required=True)
    args = parser.parse_args()

    data_dir = Path(os.getenv("MRK_DATA_DIR", "/data")).resolve()
    _assert_offline(data_dir)
    passphrase = _read_secret(args.passphrase_file) if args.command == "apply" else ""
    database_url = os.getenv("MRK_DATABASE_URL", "").strip() or None
    pglite: subprocess.Popen[bytes] | None = None
    try:
        if database_url:
            pglite = _start_embedded_pglite(data_dir, database_url)
        database = Database(data_dir, database_url)
        executor = RestoreExecutor(data_dir, database)
        if args.command == "recover":
            result = executor.recover(args.rollback)
        else:
            result = executor.apply(
                args.plan,
                passphrase,
                args.confirmation,
                args.offline_confirm,
            )
        print(json.dumps(result, sort_keys=True))
    finally:
        if pglite is not None:
            pglite.terminate()
            try:
                pglite.wait(timeout=10)
            except subprocess.TimeoutExpired:
                pglite.kill()


if __name__ == "__main__":
    run()
