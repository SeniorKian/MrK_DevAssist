from pathlib import Path

import pytest
from mrk_control_plane.catalog import PackageCatalog
from mrk_control_plane.tasks import TaskManager


def test_task_queue_cancel_and_retry_payload(tmp_path: Path) -> None:
    manager = TaskManager(tmp_path, PackageCatalog(tmp_path))
    task_id = manager.enqueue(
        "package.revalidate",
        {"ecosystem": "pypi", "name": "sampleproject"},
        actor_user_id=1,
    )

    listed = manager.list()
    assert listed[0]["id"] == task_id
    assert listed[0]["state"] == "pending"
    assert manager.stats()["pending"] == 1
    assert manager.get_payload(task_id) == (
        "package.revalidate",
        {"ecosystem": "pypi", "name": "sampleproject"},
        1,
    )
    assert manager.get_retry_payload(task_id) is None
    assert manager.cancel(task_id) is True
    assert manager.list()[0]["state"] == "cancelled"
    assert manager.stats()["cancelled"] == 1
    assert manager.get_retry_payload(task_id) == (
        "package.revalidate",
        {"ecosystem": "pypi", "name": "sampleproject"},
        1,
    )
    assert manager.cancel(task_id) is False


def test_task_queue_rejects_unknown_kind(tmp_path: Path) -> None:
    manager = TaskManager(tmp_path, PackageCatalog(tmp_path))
    with pytest.raises(ValueError, match="unsupported task kind"):
        manager.enqueue("shell.exec", {}, actor_user_id=1)


def test_integrity_scan_hashes_artifacts_and_checks_database(tmp_path: Path) -> None:
    artifact = tmp_path / "npm" / "storage" / "sample" / "sample-1.0.0.tgz"
    artifact.parent.mkdir(parents=True)
    artifact.write_bytes(b"artifact-content")
    manager = TaskManager(tmp_path, PackageCatalog(tmp_path))
    task_id = manager.enqueue("integrity.scan", {}, actor_user_id=1)

    result = manager._integrity_scan(task_id)

    assert result["healthy"] is True
    assert result["files_scanned"] == 1
    assert result["bytes_scanned"] == len(b"artifact-content")
    assert result["databases"] == {"tasks.sqlite3": "ok"}
