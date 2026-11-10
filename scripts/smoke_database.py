from __future__ import annotations

import json
import os
import secrets
import sys
import tempfile
from pathlib import Path

from mrk_control_plane.auth import AuthStore
from mrk_control_plane.backup import BackupManager
from mrk_control_plane.catalog import PackageCatalog
from mrk_control_plane.database import Database
from mrk_control_plane.restore import OFFLINE_CONFIRMATION, RestoreExecutor
from mrk_control_plane.tasks import TaskManager
from sqlalchemy import text


def main() -> int:
    database_url = os.environ["MRK_SMOKE_DATABASE_URL"]
    with tempfile.TemporaryDirectory(prefix="mrk-db-smoke-") as temporary:
        data_dir = Path(temporary)
        artifact = data_dir / "npm" / "storage" / "smoke" / "artifact.tgz"
        artifact.parent.mkdir(parents=True, exist_ok=True)
        artifact.write_bytes(b"db-restore-original")
        database = Database(data_dir, database_url)
        database.initialize()
        suffix = secrets.token_hex(4)
        username = f"smoke-{suffix}"
        password = f"smoke-test-password-{secrets.token_urlsafe(18)}"
        auth = AuthStore(data_dir, database=database)
        user_id = auth.create_user(username, password, "owner", None)
        authenticated = auth.authenticate(username, password, "127.0.0.1", "smoke")
        if authenticated is None:
            raise RuntimeError("database authentication round trip failed")
        tasks = TaskManager(data_dir, PackageCatalog(data_dir), database=database)
        task_id = tasks.enqueue("integrity.scan", {}, user_id)
        queued = tasks.get_payload(task_id)
        backup = BackupManager(data_dir, "smoke", database=database)
        backup_result = backup.create("smoke-backup-passphrase-123", profile="full")
        backup_validation = backup.validate(
            str(backup_result["filename"]), "smoke-backup-passphrase-123"
        )
        restore_plan = backup.create_restore_plan(
            str(backup_result["filename"]),
            "smoke-backup-passphrase-123",
            str(backup_validation["confirmation"]),
            user_id,
        )
        artifact.write_bytes(b"db-restore-mutated")
        auth.create_user(
            f"extra-{suffix}",
            f"extra-test-password-{secrets.token_urlsafe(18)}",
            "viewer",
            user_id,
        )
        restore_receipt = RestoreExecutor(data_dir, database).apply(
            str(restore_plan["plan_id"]),
            "smoke-backup-passphrase-123",
            str(restore_plan["apply_confirmation"]),
            OFFLINE_CONFIRMATION,
        )
        restore_ok = (
            restore_receipt["state"] == "applied"
            and artifact.read_bytes() == b"db-restore-original"
            and len(auth.list_users()) == 1
        )
        with database.engine.connect() as connection:
            revision = connection.execute(
                text("SELECT version_num FROM alembic_version")
            ).scalar_one()
        checks = {
            "authentication": "ok",
            "task_repository": "ok" if queued else "failed",
            "encrypted_backup": ("ok" if backup_validation.get("valid") is True else "failed"),
            "offline_restore": "ok" if restore_ok else "failed",
        }
        print(
            json.dumps(
                {"dialect": database.dialect, "migration": revision, **checks},
                sort_keys=True,
            )
        )
        database.dispose()
    failed = sorted(name for name, state in checks.items() if state != "ok")
    if failed:
        print(f"database smoke test failed: {', '.join(failed)}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
