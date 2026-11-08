"""Backup download, server-side clean-up, host memory totals and Dokploy deep links."""

from __future__ import annotations

import asyncio
import json
import os
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient
from mrk_control_plane.backup import MAGIC_V2, BackupManager
from mrk_control_plane.catalog import PackageCatalog
from mrk_control_plane.config import Settings
from mrk_control_plane.main import create_app
from mrk_control_plane.modules import dokploy, dokploy_client, monitoring, updates
from mrk_control_plane.modules import dokploy_normalize as norm
from mrk_control_plane.tasks import TaskManager, cleanup_confirmation

from .helpers import login_owner

PASSPHRASE = "correct-horse-battery-staple-42"  # noqa: S105 - test-only fixture
PASSWORD = "a-long-role-password-123"  # noqa: S105 - test-only fixture


@pytest.fixture(autouse=True)
def _isolated(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MRK_RESTORE_ENGINE_PORTS", "")
    monkeypatch.setenv("MRK_BACKUP_MIN_FREE_BYTES", "0")
    for name in ("MRK_AGENT_URL", "MRK_AGENT_KEY_FILE", "MRK_DOKPLOY_URL",
                 "MRK_DOKPLOY_API_KEY_FILE"):
        monkeypatch.delenv(name, raising=False)


def role_client(owner: TestClient, headers: dict[str, str], role: str):
    created = owner.post(
        "/api/v1/users",
        headers=headers,
        json={"username": f"{role}1", "password": PASSWORD, "role": role},
    )
    assert created.status_code == 201, created.text
    client = TestClient(owner.app)
    login = client.post("/api/v1/auth/login", json={"username": f"{role}1", "password": PASSWORD})
    assert login.status_code == 200
    return client, {"X-CSRF-Token": str(login.json()["csrf_token"])}


def wait_for_task(client: TestClient, task_id: str, timeout: float = 60) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        for item in client.get("/api/v1/tasks").json()["items"]:
            if item["id"] == task_id and item["state"] in {"succeeded", "failed", "cancelled"}:
                return item
        time.sleep(0.05)
    raise AssertionError(f"task {task_id} did not finish")


def audit_actions(client: TestClient) -> list[tuple[str, str | None, str]]:
    items = client.get("/api/v1/audit-events?limit=500").json()["items"]
    return [(item["action"], item.get("object_id"), item["result"]) for item in items]


def npm_package(root: Path, name: str, size: int, mtime: float) -> None:
    directory = root / "npm" / "storage" / name
    directory.mkdir(parents=True)
    (directory / "package.json").write_text(
        json.dumps({"name": name, "versions": {"1.0.0": {}}}), encoding="utf-8"
    )
    tarball = directory / f"{name}-1.0.0.tgz"
    tarball.write_bytes(b"x" * size)
    os.utime(tarball, (mtime, mtime))
    os.utime(directory / "package.json", (mtime, mtime))


# ----- 1. backup download ----------------------------------------------------------


def test_backup_download_streams_encrypted_file_and_is_audited(tmp_path: Path) -> None:
    app = create_app(Settings.for_test(tmp_path))
    with TestClient(app) as client:
        headers = {"X-CSRF-Token": str(login_owner(client)["csrf_token"])}
        response = client.post(
            "/api/v1/backups", headers=headers, json={"passphrase": PASSPHRASE, "profile": "config"}
        )
        task = wait_for_task(client, str(response.json()["task_id"]))
        assert task["state"] == "succeeded", task
        filename = str(task["result"]["filename"])
        backup_id = str(task["result"]["backup_id"])
        on_disk = (tmp_path / "backups" / "encrypted" / filename).read_bytes()

        for ref in (filename, backup_id):
            download = client.get(f"/api/v1/backups/{ref}/download")
            assert download.status_code == 200, download.text
            assert download.content == on_disk  # byte-for-byte, never decrypted
            assert download.content.startswith(MAGIC_V2)
            assert PASSPHRASE.encode() not in download.content
            assert download.headers["content-type"] == "application/octet-stream"
            assert download.headers["content-disposition"] == f'attachment; filename="{filename}"'
            assert download.headers["cache-control"] == "no-store"

        assert client.get("/api/v1/backups/nope.mrkbak/download").status_code == 404
        assert client.get("/api/v1/backups/unknown-id/download").status_code == 404
        assert client.get("/api/v1/backups/..%2Fsecret.mrkbak/download").status_code in {404, 409}
        actions = audit_actions(client)
        assert ("backup.download", filename, "success") in actions
        assert ("backup.download", "nope.mrkbak", "failure") in actions

        operator, _ = role_client(client, headers, "operator")  # backup:read only
        assert operator.get("/api/v1/backups").status_code == 200
        assert operator.get(f"/api/v1/backups/{filename}/download").status_code == 403
        assert TestClient(app).get(f"/api/v1/backups/{filename}/download").status_code == 401


def test_resolve_download_skips_invalid_archives(tmp_path: Path) -> None:
    manager = BackupManager(tmp_path, "test")
    (manager.backup_dir / "broken.mrkbak").write_bytes(b"not a backup")
    with pytest.raises(ValueError):
        manager.resolve_download("broken.mrkbak")
    with pytest.raises(FileNotFoundError):
        manager.resolve_download("some-id")
    with pytest.raises(ValueError):
        manager.resolve_download("x" * 200)


# ----- 2. server-side clean-up --------------------------------------------------------


def test_cleanup_task_purges_candidates_respecting_pins(tmp_path: Path) -> None:
    now = time.time()
    npm_package(tmp_path, "old-a", 100, now - 3000)
    npm_package(tmp_path, "old-b", 200, now - 2000)
    npm_package(tmp_path, "pinned-c", 300, now - 4000)
    catalog = PackageCatalog(tmp_path)
    catalog.set_policy("npm", "pinned-c", pinned=True)
    manager = TaskManager(tmp_path, catalog)
    task_id = manager.enqueue(
        "lifecycle.cleanup",
        {
            "candidates": [
                {"ecosystem": "npm", "name": "old-a"},
                {"ecosystem": "npm", "name": "pinned-c"},
                {"ecosystem": "npm", "name": "gone"},
                {"ecosystem": "npm", "name": "old-b"},
            ]
        },
        actor_user_id=1,
    )
    result = asyncio.run(manager._cleanup(task_id, manager.get_payload(task_id)[1]))  # noqa: SLF001
    assert [item["name"] for item in result["purged"]] == ["old-a", "old-b"]
    assert all(item["recoverable"] and item["trash_id"] for item in result["purged"])
    assert {(item["name"], item["reason"]) for item in result["skipped"]} == {
        ("pinned-c", "package_pinned"),
        ("gone", "not_cached"),
    }
    assert result["reclaimed_bytes"] == result["trashed_bytes"] > 0
    assert result["freed_immediately_bytes"] == 0
    assert not (tmp_path / "npm" / "storage" / "old-a").exists()
    assert (tmp_path / "npm" / "storage" / "pinned-c").exists()
    assert {item["name"] for item in manager.list_trash()} == {"old-a", "old-b"}


def test_cleanup_stops_at_target_bytes(tmp_path: Path) -> None:
    now = time.time()
    npm_package(tmp_path, "one", 500, now - 3000)
    npm_package(tmp_path, "two", 500, now - 2000)
    manager = TaskManager(tmp_path, PackageCatalog(tmp_path))
    payload: dict[str, Any] = {
        "candidates": [{"ecosystem": "npm", "name": "one"}, {"ecosystem": "npm", "name": "two"}],
        "target_bytes": 10,
    }
    task_id = manager.enqueue("lifecycle.cleanup", payload, actor_user_id=1)
    result = asyncio.run(manager._cleanup(task_id, payload))  # noqa: SLF001
    assert [item["name"] for item in result["purged"]] == ["one"]
    assert result["skipped"] == [{"ecosystem": "npm", "name": "two", "reason": "target_reached"}]


def test_cleanup_api_enqueues_one_task(tmp_path: Path) -> None:
    now = time.time()
    npm_package(tmp_path, "stale", 1000, now - 5000)
    npm_package(tmp_path, "fresh", 1000, now - 10)
    npm_package(tmp_path, "keep", 1000, now - 9000)
    app = create_app(Settings.for_test(tmp_path))
    with TestClient(app) as client:
        headers = {"X-CSRF-Token": str(login_owner(client)["csrf_token"])}
        pin = client.put(
            "/api/v1/packages/npm/keep/policy", headers=headers, json={"pinned": True}
        )
        assert pin.status_code == 200, pin.text
        preview = client.get("/api/v1/lifecycle/cleanup-preview?target_percent=20").json()
        assert preview["confirmation"].startswith("CLEANUP ")

        body = {
            "candidates": [
                {"ecosystem": "npm", "name": "stale"},
                {"ecosystem": "npm", "name": "keep"},
            ],
            "confirmation": "CLEANUP 2 PACKAGES",
        }
        assert client.post("/api/v1/lifecycle/cleanup", json=body).status_code == 403  # CSRF
        wrong = client.post("/api/v1/lifecycle/cleanup", headers=headers, json=body)
        assert wrong.status_code == 409
        assert wrong.json()["error"]["expected_confirmation"] == cleanup_confirmation(1)
        none = client.post(
            "/api/v1/lifecycle/cleanup", headers=headers, json={"confirmation": "x"}
        )
        assert none.status_code == 422
        both = client.post(
            "/api/v1/lifecycle/cleanup",
            headers=headers,
            json={**body, "target_bytes": 5},
        )
        assert both.status_code == 422

        started = client.post(
            "/api/v1/lifecycle/cleanup",
            headers=headers,
            json={**body, "confirmation": "CLEANUP 1 PACKAGES"},
        )
        assert started.status_code == 202, started.text
        payload = started.json()
        assert payload["kind"] == "lifecycle.cleanup" and payload["candidate_count"] == 1
        assert payload["skipped"] == [
            {"ecosystem": "npm", "name": "keep", "reason": "package_pinned"}
        ]
        task = wait_for_task(client, payload["task_id"])
        assert task["kind"] == "lifecycle.cleanup" and task["state"] == "succeeded", task
        assert [item["name"] for item in task["result"]["purged"]] == ["stale"]
        assert (tmp_path / "npm" / "storage" / "fresh").exists()
        assert not (tmp_path / "npm" / "storage" / "stale").exists()
        trash = client.get("/api/v1/packages/trash").json()["items"]
        assert [item["name"] for item in trash] == ["stale"]
        actions = audit_actions(client)
        assert ("lifecycle.cleanup", "cleanup", "failure") in actions
        assert ("lifecycle.cleanup.enqueue", payload["task_id"], "success") in actions
        assert ("package.purge", "npm:stale", "success") in actions

        by_bytes = client.post(
            "/api/v1/lifecycle/cleanup",
            headers=headers,
            json={"target_bytes": 1, "confirmation": "CLEANUP 1 PACKAGES"},
        )
        assert by_bytes.status_code == 202, by_bytes.text
        task = wait_for_task(client, by_bytes.json()["task_id"])
        assert [item["name"] for item in task["result"]["purged"]] == ["fresh"]

        nothing = client.post(
            "/api/v1/lifecycle/cleanup",
            headers=headers,
            json={"target_bytes": 1, "confirmation": "CLEANUP 0 PACKAGES"},
        )
        assert nothing.status_code == 409
        assert nothing.json()["error"]["code"] == "nothing_to_clean"


# ----- 3. host memory / disk totals -----------------------------------------------------


class FakeAgent:
    def __init__(self, payload: dict[str, Any]) -> None:
        self.payload = payload

    def resolve(self):
        return ("panel", "http://agent:8080", b"k")

    async def call(self, path: str):
        return self.payload if path == "/v1/metrics" else {"host": {"cpu_count": 2}}


def test_host_metrics_latest_has_absolute_totals(tmp_path: Path) -> None:
    from mrk_control_plane.database import Database

    database = Database(tmp_path)
    database.initialize()
    clock = [1_800_000_000.0]
    ctx = SimpleNamespace(data_dir=tmp_path, database=database,
                          events=SimpleNamespace(publish=lambda event: None))
    payload = {
        "ts": clock[0],
        "host": {
            "cpu_percent": 12.5, "load1": 0.5, "cpu_count": 2,
            "mem_total_bytes": 8_000, "mem_used_bytes": 2_000,
            "disks": [
                {"path": "/", "total_bytes": 1000, "used_bytes": 100},
                {"path": "/data", "total_bytes": 4000, "used_bytes": 3000},
            ],
        },
        "containers": [],
    }
    service = monitoring.MonitoringService(ctx, agent=FakeAgent(payload),  # type: ignore[arg-type]
                                           clock=lambda: clock[0])
    assert service.host_series("1h")["latest"] is None
    asyncio.run(service.poll())
    view = service.host_series("1h")
    assert view["latest"] == {
        "ts": int(clock[0]), "source": "agent", "cpu_percent": 12.5, "load1": 0.5,
        "mem_total_bytes": 8_000, "mem_used_bytes": 2_000, "mem_percent": 25.0,
        "disk_path": "/data", "disk_total_bytes": 4000, "disk_used_bytes": 3000,
        "disk_percent": 75.0,
    }
    assert "points" in view and "resolution" in view
    clock[0] += 3600  # stale sample and no recent minute: no latest
    assert service.host_series("1h")["latest"] is None


def test_host_snapshot_tolerates_bad_payloads() -> None:
    assert monitoring.host_snapshot(None, 1) is None
    snap = monitoring.host_snapshot({"host": {"mem_total_bytes": "x", "disks": "y"}}, 1)
    assert snap is not None
    assert snap["mem_total_bytes"] is None and snap["disk_total_bytes"] is None


# ----- 4. Dokploy deep links -----------------------------------------------------------

API_KEY = "dokployAPIkey_" + "x" * 40  # noqa: S105 - test-only fixture
PANEL = "http://dokploy.lan:3000"
PROJECT_ALL = [
    {
        "projectId": "proj1",
        "name": "Shop",
        "environments": [
            {
                "environmentId": "env1",
                "name": "production",
                "applications": [{"applicationId": "app1", "name": "web"}],
                "compose": [{"composeId": "cmp1", "name": "workers"}],
            }
        ],
    }
]
PROJECT_ONE = {
    "projectId": "proj1",
    "environments": [
        {
            "environmentId": "env1",
            "applications": [{"applicationId": "app1", "name": "web", "appName": "shop-web-1a2b",
                              "env": "SECRET=1"}],
            "compose": [{"composeId": "cmp1", "name": "workers", "appName": "shop-workers-9z"}],
        }
    ],
}


def test_app_name_index_and_service_url() -> None:
    index: dict[str, dict[str, Any]] = {}
    assert norm.app_name_index(PROJECT_ALL[0], index) is False
    assert norm.app_name_index(PROJECT_ONE, index) is True
    assert index["shop-web-1a2b"] == {"type": "application", "id": "app1", "name": "web",
                                      "project_id": "proj1", "environment_id": "env1"}
    assert dokploy.DokployService.service_url(PANEL + "/", index["shop-workers-9z"]) == (
        f"{PANEL}/dashboard/project/proj1/environment/env1/services/compose/cmp1"
    )
    old = {**index["shop-web-1a2b"], "environment_id": None}
    assert dokploy.DokployService.service_url(PANEL, old).endswith(
        "/dashboard/project/proj1/services/application/app1"
    )
    ref = updates._dokploy_ref  # noqa: SLF001
    assert ref({"name": "x", "swarm_service": "shop-web-1a2b"}, index)["id"] == "app1"
    assert ref({"name": "shop-web-1a2b.1.abcdef"}, index)["id"] == "app1"
    assert ref({"name": "shop-workers-9z-worker-1"}, index)["id"] == "cmp1"
    assert ref({"name": "postgres-1"}, index) is None


def test_updates_images_carry_dokploy_url(tmp_path: Path, monkeypatch) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.headers.get("x-api-key") != API_KEY:
            return httpx.Response(401, json={"message": "Unauthorized"})
        procedure = request.url.path.removeprefix("/api/")
        answers = {
            "settings.getDokployVersion": "v0.31.0",
            "project.all": PROJECT_ALL,
            "project.one": PROJECT_ONE,
        }
        if procedure in answers:
            return httpx.Response(200, json=answers[procedure])
        return httpx.Response(404, json={"message": "Not found", "code": "NOT_FOUND"})

    monkeypatch.setattr(
        dokploy_client, "TRANSPORT_FACTORY", lambda: httpx.MockTransport(handler)
    )
    monkeypatch.setenv("MRK_DOKPLOY_POLL_SECONDS", "0")
    app = create_app(Settings.for_test(tmp_path / "cp"))
    with TestClient(app) as client:
        headers = {"X-CSRF-Token": str(login_owner(client)["csrf_token"])}
        before = client.get("/api/v1/updates/images").json()
        assert before["dokploy"] == {"configured": False, "panel_url": None, "matched": 0,
                                     "error_code": None}
        configured = client.put(
            "/api/v1/dokploy/config", headers=headers, json={"url": PANEL + "/api",
                                                              "api_key": API_KEY},
        )
        assert configured.status_code == 200, configured.text
        config = client.get("/api/v1/dokploy/config").json()
        assert config["url"] == config["panel_url"] == PANEL

        groups = updates.UpdatesService.build_groups(
            [
                {"name": "shop-web-1a2b.1.xyz", "image": "nginx:latest", "state": "running",
                 "labels_subset": {"com.docker.swarm.service.name": "shop-web-1a2b"}},
                {"name": "other", "image": "nginx:latest", "state": "running"},
                {"name": "shop-workers-9z-worker-1", "image": "redis:7", "state": "running",
                 "labels_subset": {"com.docker.compose.project": "shop-workers-9z"}},
            ],
            None,
            {"include_stopped": False},
        )
        items = [
            {"reference": group["raw"], "containers": group["containers"]} for group in groups
        ]
        principal = SimpleNamespace(allows=lambda permission: True)
        view: dict[str, Any] = {"items": items}
        info = asyncio.run(updates.annotate_dokploy(view, principal))
        assert info == {"configured": True, "panel_url": PANEL, "matched": 2, "error_code": None}
        nginx, redis = view["items"]
        assert nginx["dokploy_url"] == (
            f"{PANEL}/dashboard/project/proj1/environment/env1/services/application/app1"
        )
        assert nginx["containers"][0]["dokploy_service"] == {
            "type": "application", "id": "app1", "name": "web", "project_id": "proj1"
        }
        assert nginx["containers"][1]["dokploy_url"] is None
        assert redis["dokploy_url"].endswith("/services/compose/cmp1")
        assert "SECRET" not in json.dumps(view)

        denied = {"items": json.loads(json.dumps(items))}
        no_perm = SimpleNamespace(allows=lambda permission: permission != "dokploy:read")
        assert asyncio.run(updates.annotate_dokploy(denied, no_perm))["configured"] is False
        assert denied["items"][0]["dokploy_url"] is None

        listed = client.get("/api/v1/updates/images").json()
        assert listed["dokploy"]["configured"] is True
        assert listed["dokploy"]["panel_url"] == PANEL
