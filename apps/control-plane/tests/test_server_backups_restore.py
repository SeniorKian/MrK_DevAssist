"""Restore and test restore of server backup runs (docs/28 S6)."""

from __future__ import annotations

import hashlib
import io
import os
import tarfile
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from mrk_control_plane.models import ServerBackupRun
from mrk_control_plane.modules import server_backups
from mrk_control_plane.modules.server_backups_crypto import StreamEncryptor
from mrk_control_plane.modules.server_backups_restore import (
    RestoreError,
    extract_tar,
    validate_target,
)

from . import test_server_backups as base
from .test_server_backups import _login_as, make_job, wait_runs

env = base.env  # shared fixture: agent fake, S3 fake, signed-in owner

BASE = "/api/v1/server-backups"


def wait_restore(client: TestClient, restore_id: str, timeout: float = 30.0) -> dict:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        item = client.get(f"{BASE}/restores/{restore_id}").json()
        if item["state"] != "running":
            return item
        time.sleep(0.05)
    raise AssertionError("restore did not finish")


def _backup(env, kind: str = "volume") -> tuple[dict, dict, dict]:
    client, headers = env["client"], env["headers"]
    destination = client.post(f"{BASE}/destinations", headers=headers,
                              json={"name": "Local", "kind": "local", "config": {}}).json()
    source = ({"kind": "volume", "volume": "app_data"} if kind == "volume"
              else {"kind": "postgres", "container": "app-db"})
    job = make_job(client, headers, f"Job {kind}", source, destination["id"])
    assert client.post(f"{BASE}/jobs/{job['id']}/run", headers=headers).status_code == 202
    run = wait_runs(client, job["id"])[0]
    assert run["state"] == "succeeded", run
    return destination, job, run


def _tar(members: list[tuple[tarfile.TarInfo, bytes | None]]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:", format=tarfile.PAX_FORMAT) as archive:
        for info, data in members:
            if data is not None:
                info.size = len(data)
            archive.addfile(info, io.BytesIO(data) if data is not None else None)
    return buffer.getvalue()


def _file(name: str) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.mode = 0o644
    return info


# ----- pure helpers --------------------------------------------------------------------------


def test_validate_target() -> None:
    assert validate_target(None) is None and validate_target("  ") is None
    assert validate_target("app/restore-1") == "app/restore-1"
    for bad in ("../x", "a/../b", ".hidden", "a b", "/etc/x" + "/y" * 5, "a\\b", 12):
        with pytest.raises(RestoreError):
            validate_target(bad)


@pytest.mark.parametrize("name", ["../evil.txt", "a/../../evil.txt", "/abs/evil.txt",
                                  "ok/..\\evil"])
def test_extract_rejects_traversal(tmp_path: Path, name: str) -> None:
    tar_path = tmp_path / "bad.tar"
    tar_path.write_bytes(_tar([(_file("fine.txt"), b"ok"), (_file(name), b"evil")]))
    with pytest.raises(RestoreError) as caught:
        extract_tar(tar_path, tmp_path / "out")
    assert caught.value.code == "unsafe_archive"
    assert not (tmp_path / "evil.txt").exists() and not list(tmp_path.rglob("evil*"))


def test_extract_skips_escaping_links_and_specials(tmp_path: Path) -> None:
    link = tarfile.TarInfo("escape")
    link.type, link.linkname = tarfile.SYMTYPE, "../../etc/passwd"
    hard = tarfile.TarInfo("hard")
    hard.type, hard.linkname = tarfile.LNKTYPE, "fine.txt"
    directory = tarfile.TarInfo("dir")
    directory.type, directory.mode = tarfile.DIRTYPE, 0o755
    tar_path = tmp_path / "t.tar"
    tar_path.write_bytes(_tar([(directory, None), (_file("dir/fine.txt"), b"hello"),
                               (link, None), (hard, None)]))
    stats = extract_tar(tar_path, tmp_path / "out")
    assert (tmp_path / "out" / "dir" / "fine.txt").read_bytes() == b"hello"
    assert stats["files"] == 1 and stats["skipped"] == 2
    assert not os.path.lexists(tmp_path / "out" / "escape")


# ----- through the API ------------------------------------------------------------------------


def test_restore_volume_happy_path(env) -> None:
    client, headers = env["client"], env["headers"]
    _dest, job, run = _backup(env)
    wrong = client.post(f"{BASE}/runs/{run['id']}/restore", headers=headers,
                        json={"confirmation": "nope"})
    assert wrong.status_code == 422 and wrong.json()["error"]["code"] == "confirmation_mismatch"
    bad = client.post(f"{BASE}/runs/{run['id']}/restore", headers=headers,
                      json={"confirmation": job["name"], "target": "../outside"})
    assert bad.json()["error"]["code"] == "invalid_target"

    started = client.post(f"{BASE}/runs/{run['id']}/restore", headers=headers,
                          json={"confirmation": job["name"], "target": "restored/app"})
    assert started.status_code == 202, started.text
    result = wait_restore(client, started.json()["restore_id"])
    assert result["state"] == "succeeded", result
    assert result["mode"] == "restore" and result["progress"] == 100
    folder = Path(result["path"])
    assert folder == env["data_dir"] / "modules/server-backups/restores/restored/app"
    assert (folder / "readme.txt").read_text() == "volume file"
    assert (folder / "nested" / "blob.bin").stat().st_size == 600_000
    assert result["details"]["files"] == 2
    # No staging folder is left behind; an existing folder is never overwritten.
    root = folder.parent.parent
    assert not [p for p in root.iterdir() if p.name.startswith(".")]
    again = client.post(f"{BASE}/runs/{run['id']}/restore", headers=headers,
                        json={"confirmation": job["name"], "target": "restored/app"})
    assert again.status_code == 409 and again.json()["error"]["code"] == "target_exists"
    assert (folder / "readme.txt").read_text() == "volume file"

    listed = client.get(f"{BASE}/restores?run_id={run['id']}").json()["items"]
    assert [item["id"] for item in listed] == [result["id"]]
    audit = client.get("/api/v1/audit-events?limit=200").json()
    actions = {item["action"] for item in audit.get("items", [])}
    assert {"server_backup.run.restore", "server_backup.restore"} <= actions
    assert any(event.type == "server_backup.restored" for event in env["events"])


def test_restore_database_dump_and_test_restore(env) -> None:
    client, headers, fake = env["client"], env["headers"], env["fake"]
    _dest, job, run = _backup(env, "postgres")
    started = client.post(f"{BASE}/runs/{run['id']}/restore", headers=headers,
                          json={"confirmation": job["name"]})
    result = wait_restore(client, started.json()["restore_id"])
    assert result["state"] == "succeeded", result
    dump = Path(result["path"]) / result["details"]["file"]
    assert dump.name == "postgres.pgdump" and dump.read_bytes() == fake.dump_stdout

    verify = client.post(f"{BASE}/runs/{run['id']}/verify", headers=headers)
    assert verify.status_code == 202
    checked = wait_restore(client, verify.json()["restore_id"])
    assert checked["state"] == "succeeded" and checked["mode"] == "verify", checked
    assert checked["path"] is None
    restores = env["data_dir"] / "modules/server-backups/restores"
    assert not [p for p in restores.iterdir() if p.name.startswith(".")]


def test_test_restore_detects_tampering_and_schedule(env) -> None:
    client, headers = env["client"], env["headers"]
    destination, job, run = _backup(env)
    artifact = Path(destination["config"]["path"]) / run["object_key"]
    data = bytearray(artifact.read_bytes())
    data[-10] ^= 0xFF
    artifact.write_bytes(bytes(data))
    verify = client.post(f"{BASE}/runs/{run['id']}/verify", headers=headers)
    checked = wait_restore(client, verify.json()["restore_id"])
    assert checked["state"] == "failed" and checked["error_code"] == "checksum_mismatch"
    failed = [e for e in env["events"] if e.type == "server_backup.verify_failed"]
    assert failed and failed[0].severity == "error"
    # Same damage with a matching recorded digest: decryption authentication catches it.
    database = env["app"].state.database
    with database.session() as db, db.begin():
        db.get(ServerBackupRun, run["id"]).sha256 = hashlib.sha256(bytes(data)).hexdigest()
    verify = client.post(f"{BASE}/runs/{run['id']}/verify", headers=headers)
    checked = wait_restore(client, verify.json()["restore_id"])
    assert checked["state"] == "failed" and checked["error_code"] == "artifact_damaged"

    # Periodic test restore: invalid cron refused; a due schedule tests the newest run.
    assert client.put(f"{BASE}/verify-settings", headers=headers,
                      json={"schedule": "nope"}).json()["error"]["code"] == "invalid_schedule"
    saved = client.put(f"{BASE}/verify-settings", headers=headers,
                       json={"schedule": "0 4 * * 0"}).json()
    assert saved["schedule"] == "0 4 * * 0" and saved["next_run_at"] > time.time()
    service = server_backups.ACTIVE_SERVICE
    assert service is not None
    started = client.portal.call(service.restores.tick, float(saved["next_run_at"]) + 1)
    assert len(started) == 1
    scheduled = wait_restore(client, started[0])
    assert scheduled["trigger"] == "schedule" and scheduled["run_id"] == run["id"]
    assert client.get(f"{BASE}/verify-settings").json()["next_run_at"] > saved["next_run_at"]
    cleared = client.put(f"{BASE}/verify-settings", headers=headers, json={"schedule": None})
    assert cleared.json() == {"schedule": None, "next_run_at": None}


def test_restore_rejects_traversal_archive(env) -> None:
    client, headers = env["client"], env["headers"]
    destination, job, run = _backup(env)
    passphrase = client.post(f"{BASE}/jobs/{job['id']}/key", headers=headers).json()["passphrase"]
    evil = _tar([(_file("ok.txt"), b"ok"), (_file("../../../escaped.txt"), b"evil")])
    encryptor = StreamEncryptor(
        passphrase, backup_id="srv-evil", source={"kind": "volume", "volume": "app_data"},
        payload_name="app_data.tar", compression="none", job_id=job["id"], key_ref="ref",
    )
    blob = encryptor.update(evil) + encryptor.finish()
    (Path(destination["config"]["path"]) / run["object_key"]).write_bytes(blob)
    database = env["app"].state.database
    with database.session() as db, db.begin():
        db.get(ServerBackupRun, run["id"]).sha256 = hashlib.sha256(blob).hexdigest()

    started = client.post(f"{BASE}/runs/{run['id']}/restore", headers=headers,
                          json={"confirmation": job["name"], "target": "evil"})
    result = wait_restore(client, started.json()["restore_id"])
    assert result["state"] == "failed" and result["error_code"] == "unsafe_archive", result
    assert not list(env["data_dir"].parent.rglob("escaped.txt"))
    restores = env["data_dir"] / "modules/server-backups/restores"
    assert not (restores / "evil").exists()
    assert not [p for p in restores.iterdir() if p.name.startswith(".")]


def test_restore_permissions_and_csrf(env) -> None:
    client, owner = env["client"], env["headers"]
    _dest, job, run = _backup(env)
    body = {"confirmation": job["name"]}
    # CSRF: the session cookie alone is not enough.
    assert client.post(f"{BASE}/runs/{run['id']}/restore", json=body).status_code == 403
    assert client.post(f"{BASE}/runs/{run['id']}/verify").status_code == 403
    assert client.put(f"{BASE}/verify-settings", json={"schedule": None}).status_code == 403
    owner_cookies = dict(client.cookies)
    for role, can_read in (("viewer", False), ("operator", True)):
        client.cookies.clear()
        client.cookies.update(owner_cookies)
        headers = _login_as(client, owner, f"restore-{role}", role)
        assert client.post(f"{BASE}/runs/{run['id']}/restore", headers=headers,
                           json=body).status_code == 403
        assert client.post(f"{BASE}/runs/{run['id']}/verify", headers=headers).status_code == 403
        assert (client.get(f"{BASE}/restores").status_code == 200) == can_read
    assert not (env["data_dir"] / "modules/server-backups/restores").exists() or not any(
        (env["data_dir"] / "modules/server-backups/restores").iterdir())
