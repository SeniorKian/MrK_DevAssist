"""Regression tests for the tasks / catalog / backup / restore audit fixes."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import io
import json
import os
import socket
import struct
import tarfile
import time
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from fastapi.testclient import TestClient
from mrk_control_plane import restore as restore_module
from mrk_control_plane.auth import AuthStore
from mrk_control_plane.backup import MAGIC, BackupCancelled, BackupError, BackupManager
from mrk_control_plane.catalog import PackageCatalog, pypi_identity
from mrk_control_plane.config import Settings
from mrk_control_plane.database import Database
from mrk_control_plane.main import create_app
from mrk_control_plane.models import AuditEvent, Task
from mrk_control_plane.restore import (
    OFFLINE_CONFIRMATION,
    RestoreError,
    RestoreExecutor,
    _assert_offline,
)
from mrk_control_plane.tasks import (
    RetryRejected,
    TaskError,
    TaskManager,
    canonical_version,
    parse_prefetch_specs,
)
from sqlalchemy import select

from .helpers import login_owner

PASSPHRASE = "regression-backup-passphrase-1"  # noqa: S105 - test-only fixture


@pytest.fixture(autouse=True)
def _isolated_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MRK_RESTORE_ENGINE_PORTS", "")
    monkeypatch.setenv("MRK_BACKUP_MIN_FREE_BYTES", "0")
    monkeypatch.setenv("MRK_CATALOG_CACHE_SECONDS", "0")


def _npm_package(data_dir: Path, name: str, tarballs: dict[str, bytes] | None = None) -> Path:
    directory = data_dir / "npm" / "storage" / Path(*name.split("/"))
    directory.mkdir(parents=True, exist_ok=True)
    versions: dict[str, object] = {}
    for version, content in (tarballs or {}).items():
        basename = f"{name.rsplit('/', 1)[-1]}-{version}.tgz"
        (directory / basename).write_bytes(content)
        digest = base64.b64encode(hashlib.sha512(content).digest()).decode("ascii")
        versions[version] = {
            "dist": {
                "tarball": f"https://registry.npmjs.org/{name}/-/{basename}",
                "integrity": f"sha512-{digest}",
                "shasum": hashlib.sha1(content).hexdigest(),  # noqa: S324 - npm reference
            }
        }
    (directory / "package.json").write_text(
        json.dumps({"name": name, "versions": versions}), encoding="utf-8"
    )
    return directory


# -- task state machine --------------------------------------------------------


def test_restart_does_not_strand_cancelled_or_backup_tasks(tmp_path: Path) -> None:
    manager = TaskManager(tmp_path, PackageCatalog(tmp_path))
    rows = {
        "a" * 24: ("integrity.scan", "running", True),
        "b" * 24: ("backup.create", "running", False),
        "c" * 24: ("backup.create", "pending", False),
        "d" * 24: ("package.prefetch", "running", False),
    }
    with manager.db.session() as db, db.begin():
        for task_id, (kind, state, cancel) in rows.items():
            db.add(
                Task(
                    id=task_id, kind=kind, state=state, payload={}, actor_user_id=1,
                    progress=5, created_at=1, cancel_requested=cancel,
                )
            )
    restarted = TaskManager(tmp_path, PackageCatalog(tmp_path))
    states = {item["id"]: (item["state"], item["error_code"]) for item in restarted.list()}
    assert states["a" * 24] == ("cancelled", None)
    assert states["b" * 24] == ("failed", "interrupted")
    assert states["c" * 24] == ("failed", "key_unavailable")
    assert states["d" * 24] == ("pending", None)


def test_running_purge_is_not_cancellable(tmp_path: Path) -> None:
    manager = TaskManager(tmp_path, PackageCatalog(tmp_path))
    task_id = manager.enqueue("package.purge", {"ecosystem": "npm", "name": "x"}, 1)
    claimed = manager._claim()  # noqa: SLF001
    assert claimed is not None and claimed[0] == task_id
    assert manager.cancel(task_id) is False
    assert manager.list()[0]["cancellable"] is False


def test_cancel_during_run_keeps_the_result(tmp_path: Path) -> None:
    manager = TaskManager(tmp_path, PackageCatalog(tmp_path))
    task_id = manager.enqueue("integrity.scan", {}, 1)

    async def fake_execute(running_id: str, _kind: str, _payload: dict) -> dict:
        assert manager.cancel(running_id) is True
        manager._stop.set()  # noqa: SLF001
        return {"partial": True}

    manager._execute = fake_execute  # type: ignore[method-assign]  # noqa: SLF001
    asyncio.run(manager.run())
    item = manager.list()[0]
    assert item["id"] == task_id
    assert item["state"] == "cancelled"
    assert item["result"] == {"partial": True}


def test_task_outcome_is_audited(tmp_path: Path) -> None:
    events: list[tuple] = []
    manager = TaskManager(
        tmp_path, PackageCatalog(tmp_path), audit=lambda *args: events.append(args)
    )
    task_id = manager.enqueue("integrity.scan", {}, 7)

    async def fake_execute(_task_id: str, _kind: str, _payload: dict) -> dict:
        manager._stop.set()  # noqa: SLF001
        raise TaskError("boom")

    manager._execute = fake_execute  # type: ignore[method-assign]  # noqa: SLF001
    asyncio.run(manager.run())
    assert manager.list()[0]["error_code"] == "boom"
    assert (7, "task.integrity.scan", "task", task_id, "failure") in events


def test_purge_retry_requires_fresh_confirmation(tmp_path: Path) -> None:
    _npm_package(tmp_path, "left-pad", {"1.3.0": b"tgz"})
    manager = TaskManager(tmp_path, PackageCatalog(tmp_path))
    task_id = manager.enqueue(
        "package.purge",
        {"ecosystem": "npm", "name": "left-pad", "confirmation": "PURGE npm/left-pad"},
        1,
    )
    assert manager.cancel(task_id)
    with pytest.raises(RetryRejected) as rejected:
        manager.retry(task_id, 2)
    assert rejected.value.status_code == 400
    retry_id = manager.retry(task_id, 2, "PURGE npm/left-pad")
    assert manager.get_payload(retry_id) == (
        "package.purge",
        {"ecosystem": "npm", "name": "left-pad", "confirmation": "PURGE npm/left-pad"},
        2,
    )


def test_retry_api_requires_confirmation_for_purge(tmp_path: Path) -> None:
    _npm_package(tmp_path, "left-pad", {"1.3.0": b"tgz"})
    app = create_app(Settings.for_test(tmp_path))
    client = TestClient(app)  # no lifespan: the worker stays idle
    try:
        headers = {"X-CSRF-Token": str(login_owner(client)["csrf_token"])}
        mismatch = client.post(
            "/api/v1/packages/npm/left-pad/purge",
            headers=headers,
            json={"confirmation": "PURGE npm/other"},
        )
        assert mismatch.status_code == 409
        created = client.post(
            "/api/v1/packages/npm/left-pad/purge",
            headers=headers,
            json={"confirmation": "PURGE npm/left-pad"},
        )
        assert created.status_code == 202
        task_id = created.json()["task_id"]
        assert client.post(f"/api/v1/tasks/{task_id}/cancel", headers=headers).status_code == 200
        assert client.post(f"/api/v1/tasks/{task_id}/retry", headers=headers).status_code == 400
        retried = client.post(
            f"/api/v1/tasks/{task_id}/retry",
            headers=headers,
            json={"confirmation": "PURGE npm/left-pad"},
        )
        assert retried.status_code == 202
        actions = [(row["action"], row["result"]) for row in client.get(
            "/api/v1/audit-events?limit=50"
        ).json()["items"]]
        assert ("package.purge", "attempt") in actions
        assert ("task.retry", "failure") in actions
    finally:
        client.close()


# -- catalog -------------------------------------------------------------------


def test_pypi_policies_are_pep503_normalized(tmp_path: Path) -> None:
    files = tmp_path / "pypi" / "server" / "+files" / "root" / "pypi" / "+f" / "abc" / "def"
    files.mkdir(parents=True)
    (files / "Foo.Bar-1.0.tar.gz").write_bytes(b"sdist")
    (files / "foo_bar-1.0-py3-none-any.whl").write_bytes(b"wheel")
    catalog = PackageCatalog(tmp_path)
    catalog.set_policy("pypi", "foo-bar", pinned=True)
    preview = catalog.purge_preview("pypi", "Foo_Bar")
    assert preview["name"] == "foo-bar"
    assert preview["blocked_by_pin"] is True
    assert catalog.lookup("pypi", "FOO.BAR")["versions"] == ["1.0"]
    assert pypi_identity("foo_bar-1.0-py3-none-any.whl") == ("foo-bar", "1.0")


def test_legacy_policy_keys_are_normalized(tmp_path: Path) -> None:
    catalog = PackageCatalog(tmp_path)
    catalog.policy_file.write_text(
        json.dumps({"pypi:Foo.Bar": {"quarantined": True, "quarantine_reason": "cve"}}),
        encoding="utf-8",
    )
    assert catalog.is_quarantined("pypi", "foo-bar") is True
    with pytest.raises(ValueError, match="invalid package name"):
        catalog.set_policy("npm", "../../etc", pinned=True)


def test_exact_lookup_is_not_capped_by_search(tmp_path: Path) -> None:
    for index in range(510):
        _npm_package(tmp_path, f"@scope/react-{index}")
    _npm_package(tmp_path, "react")
    catalog = PackageCatalog(tmp_path)
    assert len(catalog.search("react", "npm", 500)) == 500
    assert catalog.purge_preview("npm", "react")["name"] == "react"
    assert len(catalog.all_packages("npm")) == 511


# -- purge / trash -------------------------------------------------------------


def test_purge_moves_to_trash_and_trash_round_trips(tmp_path: Path) -> None:
    _npm_package(tmp_path, "@scope/pkg", {"1.0.0": b"content"})
    catalog = PackageCatalog(tmp_path)
    manager = TaskManager(tmp_path, catalog)
    task_id = manager.enqueue("package.purge", {}, 1)
    result = asyncio.run(
        manager._purge(  # noqa: SLF001
            task_id,
            {"ecosystem": "npm", "name": "@scope/pkg", "confirmation": "PURGE npm/@scope/pkg"},
        )
    )
    package_dir = tmp_path / "npm" / "storage" / "@scope" / "pkg"
    assert not package_dir.exists()
    trash_id = str(result["trash_id"])
    listed = manager.list_trash()
    assert listed[0]["trash_id"] == trash_id
    assert listed[0]["name"] == "@scope/pkg"
    assert listed[0]["expires_at"] > listed[0]["trashed_at"]
    manager.restore_trash(trash_id)
    assert (package_dir / "pkg-1.0.0.tgz").read_bytes() == b"content"
    assert manager.list_trash() == []


def test_trash_expiry(tmp_path: Path) -> None:
    _npm_package(tmp_path, "old", {"1.0.0": b"x"})
    manager = TaskManager(tmp_path, PackageCatalog(tmp_path))
    trash_id = str(manager._purge_npm("t", "old")["trash_id"])  # noqa: SLF001
    assert manager.expire_trash(now=int(time.time())) == []
    assert manager.expire_trash(now=int(time.time()) + 365 * 86400) == [trash_id]
    assert manager.list_trash() == []


def test_purge_refuses_symlinked_package_directory(tmp_path: Path) -> None:
    real = _npm_package(tmp_path, "real", {"1.0.0": b"x"})
    link = tmp_path / "npm" / "storage" / "alias"
    try:
        os.symlink(real, link, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are not available")
    manager = TaskManager(tmp_path, PackageCatalog(tmp_path))
    with pytest.raises(FileNotFoundError):
        manager._purge_npm("t", "alias")  # noqa: SLF001
    assert real.is_dir()


def test_trash_api_list_restore_and_delete(tmp_path: Path) -> None:
    _npm_package(tmp_path, "one", {"1.0.0": b"a"})
    _npm_package(tmp_path, "two", {"1.0.0": b"b"})
    app = create_app(Settings.for_test(tmp_path))
    client = TestClient(app)
    try:
        headers = {"X-CSRF-Token": str(login_owner(client)["csrf_token"])}
        side = TaskManager(tmp_path, PackageCatalog(tmp_path), database=Database(tmp_path))
        first = str(side._purge_npm("t1", "one")["trash_id"])  # noqa: SLF001
        second = str(side._purge_npm("t2", "two")["trash_id"])  # noqa: SLF001
        items = client.get("/api/v1/packages/trash").json()["items"]
        assert {item["trash_id"] for item in items} == {first, second}
        assert set(items[0]) == {
            "trash_id", "ecosystem", "name", "trashed_at", "size_bytes", "expires_at"
        }
        restored = client.post(f"/api/v1/packages/trash/{first}/restore", headers=headers)
        assert restored.status_code == 200
        assert (tmp_path / "npm" / "storage" / "one" / "one-1.0.0.tgz").is_file()
        wrong = client.request(
            "DELETE",
            f"/api/v1/packages/trash/{second}",
            headers=headers,
            json={"confirmation": "DELETE something-else"},
        )
        assert wrong.status_code == 400
        deleted = client.request(
            "DELETE",
            f"/api/v1/packages/trash/{second}",
            headers=headers,
            json={"confirmation": f"DELETE {second}"},
        )
        assert deleted.status_code == 200
        assert client.get("/api/v1/packages/trash").json()["items"] == []
        actions = {
            (row["action"], row["result"])
            for row in client.get("/api/v1/audit-events?limit=50").json()["items"]
        }
        assert ("package.trash.delete", "attempt") in actions
        assert ("package.trash.delete", "success") in actions
        assert ("package.trash.restore", "success") in actions
    finally:
        client.close()


# -- revalidate / prefetch -----------------------------------------------------


def test_revalidate_and_prefetch_refuse_quarantined_packages(tmp_path: Path) -> None:
    catalog = PackageCatalog(tmp_path)
    catalog.set_policy("npm", "left-pad", quarantined=True, quarantine_reason="cve")
    manager = TaskManager(tmp_path, catalog)
    with pytest.raises(TaskError) as refused:
        asyncio.run(
            manager._execute(  # noqa: SLF001
                "t", "package.revalidate", {"ecosystem": "npm", "name": "left-pad"}
            )
        )
    assert refused.value.code == "package_quarantined"

    fetched: list[str] = []

    async def fake_npm(_client: object, name: str, _version: str) -> None:
        fetched.append(name)

    manager._prefetch_npm = fake_npm  # type: ignore[method-assign]  # noqa: SLF001
    lock = {
        "packages": {
            "node_modules/left-pad": {"version": "1.3.0"},
            "node_modules/is-odd": {"version": "3.0.1"},
        }
    }
    task_id = manager.enqueue("package.prefetch", {}, 1)
    result = asyncio.run(
        manager._prefetch(  # noqa: SLF001
            task_id, {"ecosystem": "npm", "content": json.dumps(lock)}
        )
    )
    assert fetched == ["is-odd"]
    assert result["skipped_quarantined"] == 1


def test_prefetch_requirement_parsing_and_version_equality() -> None:
    specs = parse_prefetch_specs("pypi", "foo[bar]==1.0\nDjango == 4.2\nx==1.0.*\n")
    assert specs == [("foo", "1.0"), ("Django", "4.2"), ("x", None)]
    assert canonical_version("1.0") == canonical_version("1.0.0")
    assert canonical_version("1.0RC1") == canonical_version("1.0rc1")
    assert canonical_version("1.0") != canonical_version("1.1")
    with pytest.raises(ValueError):
        parse_prefetch_specs("npm", "[]")


# -- integrity -----------------------------------------------------------------


def test_integrity_scan_compares_reference_hashes_and_uses_ledger(tmp_path: Path) -> None:
    package = _npm_package(tmp_path, "demo", {"1.0.0": b"good", "2.0.0": b"original"})
    (package / "demo-2.0.0.tgz").write_bytes(b"tampered")
    good = b"wheel-content"
    digest = hashlib.sha256(good).hexdigest()
    devpi = tmp_path / "pypi" / "server" / "+files" / "root" / "pypi" / "+f"
    (devpi / digest[:3] / digest[3:16]).mkdir(parents=True)
    (devpi / digest[:3] / digest[3:16] / "demo-1.0-py3-none-any.whl").write_bytes(good)
    (devpi / "abc" / "0123456789abc").mkdir(parents=True)
    (devpi / "abc" / "0123456789abc" / "demo-2.0.tar.gz").write_bytes(b"corrupt")
    manager = TaskManager(tmp_path, PackageCatalog(tmp_path))
    task_id = manager.enqueue("integrity.scan", {}, 1)

    first = manager._integrity_scan(task_id)  # noqa: SLF001
    assert first["healthy"] is False
    assert first["verified"] == 2
    assert first["mismatched"] == 2
    assert {issue["path"] for issue in first["issues"]} == {
        "npm/storage/demo/demo-2.0.0.tgz",
        "pypi/server/+files/root/pypi/+f/abc/0123456789abc/demo-2.0.tar.gz",
    }
    second = manager._integrity_scan(task_id)  # noqa: SLF001
    assert second["ledger_hits"] == 4
    assert second["bytes_hashed"] == 0
    full = manager._integrity_scan(task_id, full=True)  # noqa: SLF001
    assert full["ledger_hits"] == 0


# -- backup format -------------------------------------------------------------


def _records(blob: bytes) -> tuple[int, list[tuple[int, int]]]:
    header_length = struct.unpack(">I", blob[8:12])[0]
    offset = 12 + header_length
    start = offset
    records: list[tuple[int, int]] = []
    while offset < len(blob):
        _flag, length = struct.unpack(">BI", blob[offset : offset + 5])
        records.append((offset, offset + 5 + length))
        offset += 5 + length
    return start, records


def test_v2_backup_detects_truncation_tampering_and_trailing_data(tmp_path: Path) -> None:
    (tmp_path / "control-plane").mkdir()
    (tmp_path / "control-plane" / "settings.json").write_text("{}", encoding="utf-8")
    manager = BackupManager(tmp_path, "test")
    created = manager.create(PASSPHRASE, "config")
    path = manager.backup_dir / str(created["filename"])
    original = path.read_bytes()
    _start, records = _records(original)
    assert manager.validate(path.name, PASSPHRASE)["valid"] is True

    variants = {
        "truncated": original[: records[-1][0]],
        "trailing": original + b"x",
        "tampered": original[: records[0][1] - 1]
        + bytes([original[records[0][1] - 1] ^ 1])
        + original[records[0][1] :],
        "cut": original[:-7],
    }
    for label, blob in variants.items():
        path.write_bytes(blob)
        with pytest.raises(ValueError):
            manager.validate(path.name, PASSPHRASE)
        assert label


def _write_v1_backup(data_dir: Path, files: dict[str, bytes]) -> str:
    buffer = io.BytesIO()
    entries = []
    with tarfile.open(fileobj=buffer, mode="w:gz", format=tarfile.PAX_FORMAT) as archive:
        for name, content in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(content)
            archive.addfile(info, io.BytesIO(content))
            entries.append(
                {"path": name, "size": len(content), "sha256": hashlib.sha256(content).hexdigest()}
            )
        manifest = json.dumps({"format": 1, "entries": entries}).encode("utf-8")
        info = tarfile.TarInfo("manifest.json")
        info.size = len(manifest)
        archive.addfile(info, io.BytesIO(manifest))
    salt, nonce = os.urandom(16), os.urandom(12)
    header = json.dumps(
        {
            "format": 1,
            "backup_id": "mrk-legacy-0001",
            "created_at": 1,
            "app_version": "old",
            "cipher": "AES-256-GCM",
            "kdf": {"name": "scrypt", "n": 2**15, "r": 8, "p": 1},
            "salt": base64.b64encode(salt).decode("ascii"),
            "nonce": base64.b64encode(nonce).decode("ascii"),
            "manifest_sha256": hashlib.sha256(manifest).hexdigest(),
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    key = Scrypt(salt=salt, length=32, n=2**15, r=8, p=1).derive(PASSPHRASE.encode())
    encryptor = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
    encryptor.authenticate_additional_data(header)
    body = encryptor.update(buffer.getvalue()) + encryptor.finalize() + encryptor.tag
    target = data_dir / "backups" / "encrypted" / "mrk-legacy-0001.mrkbak"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(MAGIC + struct.pack(">I", len(header)) + header + body)
    return target.name


def test_format1_backups_remain_readable(tmp_path: Path) -> None:
    manager = BackupManager(tmp_path, "test")
    filename = _write_v1_backup(tmp_path, {"npm/storage/a/a.tgz": b"legacy"})
    listed = manager.list()[0]
    assert (listed["format"], listed["profile"]) == (1, "full")
    assert manager.validate(filename, PASSPHRASE)["entry_count"] == 1
    stage = tmp_path / "tmp" / "stage"
    manager.extract_validated(filename, PASSPHRASE, stage)
    assert (stage / "npm" / "storage" / "a" / "a.tgz").read_bytes() == b"legacy"


def test_config_profile_skips_caches_and_full_includes_them(tmp_path: Path) -> None:
    for relative in (
        "npm/storage/a/a.tgz",
        "pypi/server/+files/x.whl",
        "npm/auth/htpasswd",
        "control-plane/package-policies.json",
        "logs/app.log",
        "database/other/file",
    ):
        (tmp_path / relative).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / relative).write_bytes(b"x")
    manager = BackupManager(tmp_path, "test")
    config = {relative for _path, relative in manager._source_files("config")}  # noqa: SLF001
    full = {relative for _path, relative in manager._source_files("full")}  # noqa: SLF001
    assert config == {"npm/auth/htpasswd", "control-plane/package-policies.json", "logs/app.log"}
    assert full == config | {"npm/storage/a/a.tgz", "pypi/server/+files/x.whl"}


def test_backup_free_space_cancel_and_retention(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "control-plane").mkdir()
    (tmp_path / "control-plane" / "a.json").write_text("{}", encoding="utf-8")
    manager = BackupManager(tmp_path, "test")
    with pytest.raises(BackupCancelled):
        manager.create(PASSPHRASE, "config", should_stop=lambda: True)
    assert list(manager.backup_dir.iterdir()) == []

    created = [manager.create(PASSPHRASE, "config") for _ in range(3)]
    assert len(manager.prune(retain_count=2, retain_days=0)) == 1
    assert len(manager.list()) == 2
    assert len(manager.prune(retain_count=0, retain_days=1)) == 0
    assert created

    monkeypatch.setenv("MRK_BACKUP_MIN_FREE_BYTES", str(10**18))
    with pytest.raises(BackupError) as space:
        manager.create(PASSPHRASE, "config")
    assert space.value.error_code == "insufficient_space"
    assert not list(manager.backup_dir.glob(".*.tmp"))


def test_backup_api_runs_as_task(tmp_path: Path) -> None:
    app = create_app(Settings.for_test(tmp_path))
    with TestClient(app) as client:
        headers = {"X-CSRF-Token": str(login_owner(client)["csrf_token"])}
        rejected = client.post(
            "/api/v1/backups",
            headers=headers,
            json={"passphrase": PASSPHRASE, "profile": "everything"},
        )
        assert rejected.status_code == 422
        created = client.post(
            "/api/v1/backups", headers=headers, json={"passphrase": PASSPHRASE}
        )
        assert created.status_code == 202
        task_id = created.json()["task_id"]
        deadline = time.monotonic() + 60
        state = "pending"
        while time.monotonic() < deadline and state in {"pending", "running"}:
            item = next(
                row for row in client.get("/api/v1/tasks").json()["items"] if row["id"] == task_id
            )
            state = item["state"]
            time.sleep(0.1)
        assert state == "succeeded"
        assert "passphrase" not in json.dumps(item)
        backups = client.get("/api/v1/backups").json()["items"]
        assert backups[0]["profile"] == "config"
        retry = client.post(f"/api/v1/tasks/{task_id}/retry", headers=headers)
        assert retry.status_code == 409


# -- restore -------------------------------------------------------------------


def _sqlite_appliance(tmp_path: Path) -> tuple[Database, int]:
    database = Database(tmp_path)
    database.initialize()
    user_id = AuthStore(tmp_path, database=database).create_user(
        "restore-owner", "restore-owner-password-123", "owner", None
    )
    _npm_package(tmp_path, "cached", {"1.0.0": b"backup-era"})
    return database, user_id


def _plan(manager: BackupManager, user_id: int, profile: str = "full") -> dict[str, object]:
    created = manager.create(PASSPHRASE, profile)
    validated = manager.validate(str(created["filename"]), PASSPHRASE)
    return manager.create_restore_plan(
        str(created["filename"]), PASSPHRASE, str(validated["confirmation"]), user_id
    )


def test_failed_restore_rolls_back_every_unit_and_keeps_sqlite_db(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database, user_id = _sqlite_appliance(tmp_path)
    manager = BackupManager(tmp_path, "test", database=database)
    plan = _plan(manager, user_id)
    tarball = tmp_path / "npm" / "storage" / "cached" / "cached-1.0.0.tgz"
    tarball.write_bytes(b"current")
    real_replace = os.replace

    def failing_replace(source: object, target: object) -> None:
        if Path(str(source)).parts[-2:] == ("payload", "npm"):
            raise OSError("simulated failure while swapping npm")
        real_replace(source, target)  # type: ignore[arg-type]

    monkeypatch.setattr(restore_module.os, "replace", failing_replace)
    with pytest.raises(OSError, match="simulated"):
        RestoreExecutor(tmp_path, database).apply(
            str(plan["plan_id"]), PASSPHRASE, str(plan["apply_confirmation"]),
            OFFLINE_CONFIRMATION,
        )
    monkeypatch.setattr(restore_module.os, "replace", real_replace)
    assert tarball.read_bytes() == b"current"
    assert (tmp_path / "control-plane" / "control-plane.sqlite3").is_file()
    assert AuthStore(tmp_path, database=database).has_users()
    journals = list((tmp_path / "backups" / "restore-rollbacks").glob("*/journal.json"))
    assert json.loads(journals[0].read_text(encoding="utf-8"))["state"] == "rolled_back"
    database.dispose()


def test_successful_restore_is_audited_and_consumes_plan(tmp_path: Path) -> None:
    database, user_id = _sqlite_appliance(tmp_path)
    manager = BackupManager(tmp_path, "test", database=database)
    plan = _plan(manager, user_id)
    tarball = tmp_path / "npm" / "storage" / "cached" / "cached-1.0.0.tgz"
    tarball.write_bytes(b"current")
    receipt = RestoreExecutor(tmp_path, database).apply(
        str(plan["plan_id"]), PASSPHRASE, str(plan["apply_confirmation"]), OFFLINE_CONFIRMATION
    )
    assert receipt["state"] == "applied"
    assert tarball.read_bytes() == b"backup-era"
    with database.session() as db:
        actions = db.scalars(select(AuditEvent.action)).all()
    assert "backup.restore.apply" in actions
    with pytest.raises(RestoreError, match="not found"):
        RestoreExecutor(tmp_path, database).apply(
            str(plan["plan_id"]), PASSPHRASE, str(plan["apply_confirmation"]),
            OFFLINE_CONFIRMATION,
        )
    database.dispose()


def test_sqlite_restore_refuses_backup_without_database(tmp_path: Path) -> None:
    (tmp_path / "control-plane").mkdir()
    (tmp_path / "control-plane" / "settings.json").write_text("{}", encoding="utf-8")
    plan = _plan(BackupManager(tmp_path, "test"), 1, "config")
    database = Database(tmp_path)
    database.initialize()
    with pytest.raises(RestoreError, match="no SQLite database"):
        RestoreExecutor(tmp_path, database).apply(
            str(plan["plan_id"]), PASSPHRASE, str(plan["apply_confirmation"]),
            OFFLINE_CONFIRMATION,
        )
    assert (tmp_path / "control-plane" / "control-plane.sqlite3").is_file()
    database.dispose()


def test_restore_refuses_while_engines_listen(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        monkeypatch.setenv("MRK_RESTORE_ENGINE_PORTS", str(listener.getsockname()[1]))
        with pytest.raises(RestoreError, match="still listening"):
            _assert_offline(tmp_path)


def test_trash_round_trips_when_npm_storage_is_a_separate_mount(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A rename between two mounts fails with EXDEV; the move then copies instead."""
    import errno

    from mrk_control_plane import tasks as tasks_module

    _npm_package(tmp_path, "@scope/pkg", {"1.0.0": b"content"})
    manager = TaskManager(tmp_path, PackageCatalog(tmp_path))
    storage = tmp_path / "npm" / "storage"
    real_replace = os.replace

    def replace(source: object, target: object) -> None:
        inside = [storage in Path(str(item)).parents for item in (source, target)]
        if inside[0] != inside[1]:
            raise OSError(errno.EXDEV, "Invalid cross-device link")
        real_replace(source, target)  # type: ignore[arg-type]

    monkeypatch.setattr(tasks_module.os, "replace", replace)
    package_dir = storage / "@scope" / "pkg"
    trash_id = str(manager._purge_npm("t", "@scope/pkg")["trash_id"])  # noqa: SLF001
    assert not package_dir.exists()
    payload = manager.trash_dir / trash_id / "payload"
    assert (payload / "pkg-1.0.0.tgz").read_bytes() == b"content"
    manager.restore_trash(trash_id)
    assert (package_dir / "pkg-1.0.0.tgz").read_bytes() == b"content"
    assert not (package_dir.parent / ".pkg.partial").exists()
    assert manager.list_trash() == []
