import sqlite3
import time
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


@pytest.fixture(autouse=True)
def _no_engine_port_checks(monkeypatch: pytest.MonkeyPatch) -> None:
    # Developer machines may run unrelated services on the engine ports.
    monkeypatch.setenv("MRK_RESTORE_ENGINE_PORTS", "")
    monkeypatch.setenv("MRK_BACKUP_MIN_FREE_BYTES", "0")


def wait_for_task(client: TestClient, task_id: str, timeout: float = 60) -> dict[str, object]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        for item in client.get("/api/v1/tasks").json()["items"]:
            if item["id"] == task_id and item["state"] in {"succeeded", "failed", "cancelled"}:
                return item
        time.sleep(0.1)
    raise AssertionError(f"task {task_id} did not finish")


def create_backup(
    client: TestClient, headers: dict[str, str], profile: str = "full"
) -> dict[str, object]:
    response = client.post(
        "/api/v1/backups",
        headers=headers,
        json={"passphrase": PASSPHRASE, "profile": profile},
    )
    assert response.status_code == 202
    task = wait_for_task(client, str(response.json()["task_id"]))
    assert task["state"] == "succeeded", task
    return dict(task["result"])  # type: ignore[arg-type]


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
    created = manager.create(PASSPHRASE, "full")

    assert created["cipher"] == "AES-256-GCM-STREAM"
    assert created["format"] == 2
    assert created["kdf"]["name"] == "scrypt"
    listed = manager.list()[0]
    assert listed["backup_id"] == created["backup_id"]
    assert listed["profile"] == "full"
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
        created = create_backup(client, headers, "config")

        listed = client.get("/api/v1/backups")
        assert listed.status_code == 200
        item = listed.json()["items"][0]
        assert item["backup_id"] == created["backup_id"]
        assert item["profile"] == "config"
        assert item["format"] == 2

        validated = client.post(
            f"/api/v1/backups/{created['filename']}/validate",
            headers=headers,
            json={"passphrase": PASSPHRASE},
        )
        assert validated.status_code == 200
        assert validated.json()["valid"] is True

        rejected = client.post(
            f"/api/v1/backups/{created['filename']}/validate",
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
        created = create_backup(client, headers, "full")
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
    database.dispose()


def test_mounts_below_reads_only_mounts_inside_the_data_dir(tmp_path: Path) -> None:
    from mrk_control_plane.restore import _mounts_below

    mountinfo = tmp_path / "mountinfo"
    mountinfo.write_text(
        "36 35 0:30 / / rw - overlay overlay rw\n"
        "40 36 8:1 /storage /data rw - ext4 /dev/sda1 rw\n"
        "41 40 8:1 /storage/npm /data/npm rw - ext4 /dev/sda1 rw\n"
        "42 40 8:1 /storage/s3 /data/modules/s3 rw - ext4 /dev/sda1 rw\n"
        "43 40 8:1 /x /data/my\\040dir rw - ext4 /dev/sda1 rw\n"
        "44 36 8:1 /y /database rw - ext4 /dev/sda1 rw\n"
        "short line\n",
        encoding="utf-8",
    )
    assert _mounts_below(Path("/data"), mountinfo) == [
        Path("/data/npm"),
        Path("/data/modules/s3"),
        Path("/data/my dir"),
    ]
    assert _mounts_below(Path("/data"), tmp_path / "missing") == []


@pytest.mark.parametrize("mount", ["npm", "npm/storage"])
def test_restore_refuses_a_data_root_on_a_separate_mount(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mount: str
) -> None:
    from mrk_control_plane import restore as restore_module

    stage = tmp_path / "stage"
    (stage / "npm").mkdir(parents=True)
    (stage / "pypi").mkdir()
    data_dir = tmp_path / "data"
    (data_dir / "npm" / "storage").mkdir(parents=True)
    executor = RestoreExecutor.__new__(RestoreExecutor)
    executor.data_dir = data_dir
    monkeypatch.setattr(restore_module, "_mounts_below", lambda _root: [data_dir / mount])
    with pytest.raises(RestoreError, match="separate mount"):
        executor._check_stage(stage, ["npm"])  # noqa: SLF001
    # A unit that is not on that mount is still accepted.
    executor._check_stage(stage, ["pypi"])  # noqa: SLF001
