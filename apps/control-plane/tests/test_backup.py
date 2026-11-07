import sqlite3
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from mrk_control_plane.backup import BackupManager
from mrk_control_plane.config import Settings
from mrk_control_plane.database import Database
from mrk_control_plane.main import create_app
from mrk_control_plane.restore import OFFLINE_CONFIRMATION, RestoreError, RestoreExecutor

from .helpers import login_owner

PASSPHRASE = "correct-horse-battery-staple-42"  # noqa: S105 - test-only fixture


def test_encrypted_backup_round_trip_and_wrong_secret(tmp_path: Path) -> None:
    artifact = tmp_path / "npm" / "storage" / "sample" / "sample.tgz"
    artifact.parent.mkdir(parents=True)
    artifact.write_bytes(b"immutable package bytes")
    database = tmp_path / "control-plane" / "control-plane.sqlite3"
    database.parent.mkdir(parents=True)
    with sqlite3.connect(database) as connection:
        connection.execute("CREATE TABLE sample(value TEXT)")
        connection.execute("INSERT INTO sample VALUES('ok')")

    manager = BackupManager(tmp_path, "test")
    created = manager.create(PASSPHRASE)

    assert created["cipher"] == "AES-256-GCM"
    assert created["kdf"]["name"] == "scrypt"
    assert manager.list()[0]["backup_id"] == created["backup_id"]
    validated = manager.validate(str(created["filename"]), PASSPHRASE)
    assert validated["valid"] is True
    assert validated["entry_count"] == 2
    assert validated["isolated_only"] is True
    with pytest.raises(ValueError, match="authentication failed"):
        manager.validate(str(created["filename"]), "wrong-passphrase-value")


def test_backup_api_requires_permission_and_validates_isolated(tmp_path: Path) -> None:
    app = create_app(Settings.for_test(tmp_path))
    with TestClient(app) as client:
        login = login_owner(client)
        headers = {"X-CSRF-Token": str(login["csrf_token"])}
        created = client.post(
            "/api/v1/backups",
            headers=headers,
            json={"passphrase": PASSPHRASE},
        )
        assert created.status_code == 201

        listed = client.get("/api/v1/backups")
        assert listed.status_code == 200
        assert listed.json()["items"][0]["backup_id"] == created.json()["backup_id"]

        validated = client.post(
            f"/api/v1/backups/{created.json()['filename']}/validate",
            headers=headers,
            json={"passphrase": PASSPHRASE},
        )
        assert validated.status_code == 200
        assert validated.json()["valid"] is True

        rejected = client.post(
            f"/api/v1/backups/{created.json()['filename']}/validate",
            headers=headers,
            json={"passphrase": "definitely-wrong-secret"},
        )
        assert rejected.status_code == 409


def test_restore_plan_requires_confirmation_and_applies_only_offline(tmp_path: Path) -> None:
    artifact = tmp_path / "npm" / "storage" / "sample" / "sample.tgz"
    artifact.parent.mkdir(parents=True)
    artifact.write_bytes(b"original-cache-content")
    app = create_app(Settings.for_test(tmp_path))
    with TestClient(app) as client:
        login = login_owner(client)
        headers = {"X-CSRF-Token": str(login["csrf_token"])}
        created = client.post(
            "/api/v1/backups", headers=headers, json={"passphrase": PASSPHRASE}
        ).json()
        validated = client.post(
            f"/api/v1/backups/{created['filename']}/validate",
            headers=headers,
            json={"passphrase": PASSPHRASE},
        ).json()
        rejected = client.post(
            f"/api/v1/backups/{created['filename']}/restore-plan",
            headers=headers,
            json={"passphrase": PASSPHRASE, "confirmation": "RESTORE definitely-wrong"},
        )
        assert rejected.status_code == 409
        planned = client.post(
            f"/api/v1/backups/{created['filename']}/restore-plan",
            headers=headers,
            json={
                "passphrase": PASSPHRASE,
                "confirmation": validated["confirmation"],
            },
        )
        assert planned.status_code == 200
        plan = planned.json()
        assert plan["passphrase_persisted"] is False
        assert plan["requires_offline_apply"] is True
        online_database = Database(tmp_path)
        with pytest.raises(RestoreError, match="still running"):
            RestoreExecutor(tmp_path, online_database).apply(
                str(plan["plan_id"]),
                PASSPHRASE,
                str(plan["apply_confirmation"]),
                OFFLINE_CONFIRMATION,
            )
        online_database.dispose()

    assert not (tmp_path / "control-plane" / "runtime-heartbeat").exists()
    artifact.write_bytes(b"mutated-after-backup")
    database = Database(tmp_path)
    executor = RestoreExecutor(tmp_path, database)
    receipt = executor.apply(
        str(plan["plan_id"]),
        PASSPHRASE,
        str(plan["apply_confirmation"]),
        OFFLINE_CONFIRMATION,
    )
    assert receipt["state"] == "applied"
    assert artifact.read_bytes() == b"original-cache-content"
    assert (tmp_path / "control-plane" / "restore-receipts").is_dir()
