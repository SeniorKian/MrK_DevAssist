from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient
from mrk_control_plane.config import Settings
from mrk_control_plane.main import create_app
from mrk_control_plane.modules import build_mirror, build_mirror_coverage, dokploy_client
from mrk_control_plane.modules import build_mirror_env as envblock

from .test_dokploy import FakeDokploy, configure, owner_headers

NPM = "https://npm.example.com/"
PYPI = "https://pypi.example.com/root/pypi/+simple/"


@pytest.fixture
def fake(monkeypatch) -> FakeDokploy:
    state = FakeDokploy()
    monkeypatch.setattr(
        dokploy_client, "TRANSPORT_FACTORY", lambda: httpx.MockTransport(state.handler))
    for name in ("MRK_DOKPLOY_URL", "MRK_DOKPLOY_API_KEY_FILE", "MRK_DOKPLOY_CACHE_SECONDS"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("MRK_DOKPLOY_POLL_SECONDS", "0")
    return state


def _urls(client: TestClient, headers: dict[str, str], **extra: Any) -> dict[str, Any]:
    response = client.put("/api/v1/build-mirrors/settings", headers=headers, json={
        "npm_url": NPM, "pypi_url": PYPI, "registry_host": "reg.example.com", **extra})
    assert response.status_code == 200, response.text
    return response.json()


def test_apply_and_remove_keep_the_customer_env(tmp_path: Path, fake: FakeDokploy) -> None:
    app = create_app(Settings.for_test(tmp_path / "cp"))
    with TestClient(app) as client:
        headers = owner_headers(client)
        assert configure(client, headers).status_code == 200
        settings = _urls(client, headers)
        assert settings["endpoints"]["npm"] == NPM and settings["enabled"] is False

        projects = client.get("/api/v1/build-mirrors/projects").json()
        by_id = {item["id"]: item for item in projects["items"]}
        assert by_id["app1"]["eligible"] is True and by_id["app1"]["state"] == "missing"
        assert by_id["cmp1"]["eligible"] is False and by_id["cmp1"]["reason"] == "compose_build"
        assert "topsecret" not in json.dumps(projects)  # env values never leave the panel

        applied = client.post("/api/v1/build-mirrors/projects/apply", headers=headers,
                              json={"all": True})
        assert applied.status_code == 200, applied.text
        results = {item["id"]: item for item in applied.json()["results"]}
        assert results["app1"]["result"] == "applied"
        assert results["cmp1"] == {"type": "compose", "id": "cmp1", "result": "skipped",
                                   "reason": "compose_build"}
        saved = fake.saved_env["app1"]
        assert saved.startswith("DATABASE_URL=postgres://u:topsecret@db/app\n\n" + envblock.BEGIN)
        assert f"NPM_CONFIG_REGISTRY={NPM}" in saved and f"UV_DEFAULT_INDEX={PYPI}" in saved
        save_call = fake.calls("application.saveEnvironment")[-1]
        assert json.loads(save_call.content)["buildArgs"] == "NPM_TOKEN=npm_secret_value"
        assert client.get("/api/v1/build-mirrors/settings").json()["enabled"] is True

        again = client.post("/api/v1/build-mirrors/projects/apply", headers=headers,
                            json={"targets": [{"type": "application", "id": "app1"}]})
        assert again.json()["results"][0]["result"] == "unchanged"
        state = {i["id"]: i for i in client.get("/api/v1/build-mirrors/projects").json()["items"]}
        assert state["app1"]["state"] == "applied"

        bad = client.post("/api/v1/build-mirrors/projects/apply", headers=headers,
                          json={"targets": [{"type": "application", "id": "nope"}]})
        assert bad.status_code == 422

        removed = client.post("/api/v1/build-mirrors/projects/remove", headers=headers,
                              json={"all": True})
        assert removed.status_code == 200
        assert fake.saved_env["app1"] == "DATABASE_URL=postgres://u:topsecret@db/app"
        assert client.get("/api/v1/build-mirrors/settings").json()["enabled"] is False


def test_status_command_and_report(tmp_path: Path, fake: FakeDokploy) -> None:
    app = create_app(Settings.for_test(tmp_path / "cp"))
    with TestClient(app) as client:
        headers = owner_headers(client)
        missing = client.get("/api/v1/build-mirrors/command?action=install")
        assert missing.status_code == 409
        assert missing.json()["error"]["code"] == "build_mirror_registry_missing"

        assert configure(client, headers).status_code == 200
        _urls(client, headers)
        command = client.get("/api/v1/build-mirrors/command?action=install&restart=true").json()
        assert command["command"].startswith(
            "sudo bash -s -- install --registry reg.example.com --npm " + NPM)
        assert "--allow-restart <<'DEVASSIST_SCRIPT'\n#!/usr/bin/env bash" in (
            command["command"])
        assert command["command"].endswith("\nDEVASSIST_SCRIPT\n")

        status = client.get("/api/v1/build-mirrors/status").json()
        checks = {item["id"]: item for item in status["checks"]}
        assert checks["dokploy"]["state"] == "ok"
        assert checks["npm_mirror"]["state"] == "ok"
        assert checks["agent"]["code"] == "agent_not_configured"
        assert checks["server"]["code"] == "server_unknown"
        assert checks["projects"]["code"] == "projects_pending"
        assert status["overall"] in {"warn", "fail"}
        report = client.get("/api/v1/build-mirrors/report").json()["text"]
        assert "projects_pending" in report and "topsecret" not in report

        rejected = client.put("/api/v1/build-mirrors/settings", headers=headers,
                              json={"npm_url": "ftp://x"})
        assert rejected.status_code == 422


def test_server_checks_explain_each_layer() -> None:
    facts = {"host_root": True, "docker": True, "builder": "absent",
             "daemon": {"mirrors": ["https://reg.example.com"]},
             "live_mirrors": [],
             "marker": {"valid": True, "registry": "https://reg.example.com",
                        "buildkit_file": "/x/buildkitd.default.toml", "test": "mirror_auth"}}
    checks = {c["id"]: c for c in build_mirror.BuildMirrorService._server_checks(
        facts, "reg.example.com", {})}
    assert checks["server"]["code"] == "script_applied"
    assert checks["daemon_file"]["state"] == "ok"
    assert checks["daemon_live"]["code"] == "docker_reload_needed"
    assert checks["self_test"] == {"id": "self_test", "state": "fail", "code": "test_mirror_auth",
                                   "params": {}}
    assert "default_builder" not in checks
    none = build_mirror.BuildMirrorService._server_checks(
        {"host_root": True, "marker": None, "daemon": {"mirrors": []}, "docker": False},
        "reg.example.com", {})
    assert {c["code"] for c in none} == {"script_not_run", "daemon_no_mirror",
                                         "docker_unreachable"}


def test_coverage_estimate_from_build_logs() -> None:
    analyze = build_mirror_coverage.analyze
    full = analyze(["#8 RUN npm ci", "added 120 packages"], NPM, PYPI)
    assert full["result"] == "full" and full["tools"] == ["npm"]
    pip = analyze([f"Looking in indexes: {PYPI}", "pip install -r requirements.txt"], NPM, PYPI)
    assert pip["result"] == "full" and pip["mirror_seen"] is True
    direct = analyze(["pip install x", "Downloading https://files.pythonhosted.org/x.whl"],
                     NPM, PYPI)
    assert direct["result"] == "none" and direct["direct"]["pypi"] == 1
    yarn = analyze(["yarn install v1.22.22", "[1/4] Resolving packages..."], NPM, PYPI)
    assert yarn["result"] == "partial" and yarn["gaps"] == ["yarn_v1_lock"]
    assert analyze(["Step 1/3 : FROM nginx"], NPM, PYPI)["result"] == "unknown"
