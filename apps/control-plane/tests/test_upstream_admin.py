from pathlib import Path

from fastapi.testclient import TestClient
from mrk_control_plane.config import Settings
from mrk_control_plane.main import create_app

from .helpers import login_owner


def test_upstream_crud_block_offline_and_health_timeline(tmp_path: Path, monkeypatch) -> None:
    app = create_app(Settings.for_test(tmp_path))

    async def fake_probe(
        url: str, timeout_seconds: int, authorization: str | None
    ) -> dict[str, object]:
        assert url == "https://packages.example.com/simple/"
        assert timeout_seconds == 10
        assert authorization == "Bearer private-upstream-token"
        return {
            "ok": True,
            "url": url,
            "stages": [
                {"name": "dns", "status": "ok", "latency_ms": 1.5},
                {"name": "tcp", "status": "ok", "latency_ms": 2.5},
                {"name": "tls", "status": "ok", "latency_ms": 3.5},
                {"name": "http", "status": "ok", "latency_ms": 4.5},
            ],
        }

    monkeypatch.setattr("mrk_control_plane.main.probe_upstream", fake_probe)

    with TestClient(app) as client:
        csrf = str(login_owner(client)["csrf_token"])
        initial = client.get("/api/v1/upstreams")
        assert initial.status_code == 200
        assert [item["name"] for item in initial.json()["items"]] == [
            "npmjs.org",
            "Liara npm",
            "pypi.org",
            "Liara",
        ]

        rejected = client.post(
            "/api/v1/upstreams",
            headers={"X-CSRF-Token": csrf},
            json={
                "name": "local",
                "ecosystem": "pypi",
                "url": "https://127.0.0.1/simple/",
                "priority": 30,
                "timeout_seconds": 10,
            },
        )
        assert rejected.status_code == 409

        created = client.post(
            "/api/v1/upstreams",
            headers={"X-CSRF-Token": csrf},
            json={
                "name": "Backup",
                "ecosystem": "pypi",
                "url": "https://packages.example.com/simple/",
                "priority": 30,
                "timeout_seconds": 10,
            },
        )
        assert created.status_code == 201
        upstream_id = str(created.json()["id"])

        credential = client.put(
            f"/api/v1/upstreams/{upstream_id}/credential",
            headers={"X-CSRF-Token": csrf},
            json={
                "credential_type": "bearer",
                "token": "private-upstream-token",
            },
        )
        assert credential.status_code == 200
        assert credential.json()["configured"] is True
        assert "token" not in credential.text
        assert "credential_ref" not in credential.text
        encrypted_store = (
            tmp_path / "control-plane" / "upstream-secrets.json"
        ).read_text(encoding="utf-8")
        assert "private-upstream-token" not in encrypted_store
        listed = client.get("/api/v1/upstreams").json()["items"]
        configured = next(item for item in listed if item["id"] == upstream_id)
        assert configured["credential_configured"] is True
        assert "credential_ref" not in configured

        tested = client.post(
            "/api/v1/upstreams/test",
            headers={"X-CSRF-Token": csrf},
            json={"upstream_id": upstream_id},
        )
        assert tested.status_code == 200
        assert tested.json()["ok"] is True
        timeline = client.get(f"/api/v1/upstreams/{upstream_id}/health")
        assert timeline.status_code == 200
        assert len(timeline.json()["items"]) == 1
        health = timeline.json()["items"][0]
        assert health["upstream_id"] == upstream_id
        assert health["total_latency_ms"] == 12
        assert [stage["name"] for stage in health["stages"]] == [
            "dns",
            "tcp",
            "tls",
            "http",
        ]
        assert "url" not in health

        removed = client.delete(
            f"/api/v1/upstreams/{upstream_id}/credential",
            headers={"X-CSRF-Token": csrf},
        )
        assert removed.status_code == 200
        assert removed.json() == {"configured": False}

        updated = client.patch(
            f"/api/v1/upstreams/{upstream_id}",
            headers={"X-CSRF-Token": csrf},
            json={"priority": 5, "enabled": False},
        )
        assert updated.status_code == 200
        assert updated.json()["priority"] == 5

        blocked = client.post(
            f"/api/v1/upstreams/{upstream_id}/block",
            headers={"X-CSRF-Token": csrf},
            json={"reason": "maintenance", "duration_seconds": 300},
        )
        assert blocked.status_code == 200
        assert blocked.json()["blocked_reason"] == "maintenance"
        assert client.post(
            f"/api/v1/upstreams/{upstream_id}/unblock",
            headers={"X-CSRF-Token": csrf},
        ).status_code == 200

        offline = client.put(
            "/api/v1/ecosystems/pypi/offline",
            headers={"X-CSRF-Token": csrf},
            json={"offline": True},
        )
        assert offline.status_code == 200
        assert (tmp_path / "control-plane" / "pypi-offline").is_file()
        assert client.put(
            "/api/v1/ecosystems/pypi/offline",
            headers={"X-CSRF-Token": csrf},
            json={"offline": False},
        ).status_code == 200

        mismatch = client.request(
            "DELETE",
            f"/api/v1/upstreams/{upstream_id}",
            headers={"X-CSRF-Token": csrf},
            json={"confirmation": "wrong-name"},
        )
        assert mismatch.status_code == 409
        deleted = client.request(
            "DELETE",
            f"/api/v1/upstreams/{upstream_id}",
            headers={"X-CSRF-Token": csrf},
            json={"confirmation": "Backup"},
        )
        assert deleted.status_code == 204
        assert all(
            item["id"] != upstream_id
            for item in client.get("/api/v1/upstreams").json()["items"]
        )


def test_last_enabled_upstream_requires_offline_mode(tmp_path: Path) -> None:
    app = create_app(Settings.for_test(tmp_path))

    with TestClient(app) as client:
        csrf = str(login_owner(client)["csrf_token"])
        pypi = [
            item
            for item in client.get("/api/v1/upstreams").json()["items"]
            if item["ecosystem"] == "pypi"
        ]
        primary, fallback = pypi

        disabled = client.patch(
            f"/api/v1/upstreams/{fallback['id']}",
            headers={"X-CSRF-Token": csrf},
            json={"enabled": False},
        )
        assert disabled.status_code == 200

        rejected_disable = client.patch(
            f"/api/v1/upstreams/{primary['id']}",
            headers={"X-CSRF-Token": csrf},
            json={"enabled": False},
        )
        assert rejected_disable.status_code == 409
        assert rejected_disable.json()["error"]["code"] == "invalid_upstream"

        rejected_delete = client.request(
            "DELETE",
            f"/api/v1/upstreams/{primary['id']}",
            headers={"X-CSRF-Token": csrf},
            json={"confirmation": primary["name"]},
        )
        assert rejected_delete.status_code == 409
        assert rejected_delete.json()["error"]["code"] == "unsafe_upstream_delete"

        offline = client.put(
            "/api/v1/ecosystems/pypi/offline",
            headers={"X-CSRF-Token": csrf},
            json={"offline": True},
        )
        assert offline.status_code == 200
        deleted = client.request(
            "DELETE",
            f"/api/v1/upstreams/{primary['id']}",
            headers={"X-CSRF-Token": csrf},
            json={"confirmation": primary["name"]},
        )
        assert deleted.status_code == 204
