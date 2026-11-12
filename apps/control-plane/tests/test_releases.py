"""Panel versions and updates: release check, service upgrades, panel self-update."""

from __future__ import annotations

import base64
import time
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient
from mrk_control_plane.agent import signing
from mrk_control_plane.config import Settings
from mrk_control_plane.main import create_app
from mrk_control_plane.modules import releases
from mrk_control_plane.modules.releases import pick_latest, set_env_line

from .test_dokploy import _login_as
from .test_install_auto import (  # noqa: F401 - pytest fixtures
    FakeCoolify,
    agent_backend,
    connect_coolify,
    connect_dokploy,
    fakes,
    owner,
    wait_job,
)
from .test_install_wizard import env_value

GHCR_CHALLENGE = ('Bearer realm="https://ghcr.io/token",service="ghcr.io",'
                  'scope="repository:seniorkian/mrk-panel:pull"')


class FakeGhcr:
    def __init__(self) -> None:
        self.pages: list[list[str]] = [["latest", "0.1", "0.1.0", "0.2.0", "v0.3.0", "0.9.0-rc1"],
                                       ["0.2.5", "1.0", "sha-abc"]]
        self.requests: list[httpx.Request] = []
        self.token_requests: list[httpx.Request] = []
        self.status: int | None = None

    def handler(self, request: httpx.Request) -> httpx.Response:
        host = request.headers.get("host") or request.url.host
        assert host == "ghcr.io"
        if request.url.path == "/token":
            self.token_requests.append(request)
            return httpx.Response(200, json={"token": "tok-ghcr"})
        self.requests.append(request)
        if self.status is not None:
            return httpx.Response(self.status)
        assert request.url.path == "/v2/seniorkian/mrk-panel/tags/list"
        if request.headers.get("authorization") != "Bearer tok-ghcr":
            return httpx.Response(401, headers={"www-authenticate": GHCR_CHALLENGE})
        page = int(request.url.params.get("last") == "0.9.0-rc1")
        headers = {}
        if page == 0:
            headers["link"] = ('</v2/seniorkian/mrk-panel/tags/list?n=1000&last=0.9.0-rc1>; '
                               'rel="next"')
        return httpx.Response(200, headers=headers,
                              json={"name": "seniorkian/mrk-panel", "tags": self.pages[page]})


@pytest.fixture
def ghcr(monkeypatch):
    fake = FakeGhcr()
    monkeypatch.setattr(releases, "TRANSPORT_FACTORY", lambda: httpx.MockTransport(fake.handler))
    monkeypatch.setattr(releases, "RESOLVER", lambda host, port, config: ["140.82.112.33"])
    monkeypatch.setattr(releases, "POLL_SECONDS", 0.01)
    monkeypatch.setattr(releases, "CONNECT_DELAY_SECONDS", 0.01)
    monkeypatch.setattr(releases, "CONNECT_ATTEMPTS", 3)
    for name in ("MRK_PANEL_RUNTIME", "MRK_IMAGE_REGISTRY", "MRK_IMAGE_TAG"):
        monkeypatch.delenv(name, raising=False)
    return fake


def wait_release_job(client: TestClient, job_id: str) -> dict[str, Any]:
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        job = client.get(f"/api/v1/releases/jobs/{job_id}").json()
        if job["status"] != "running":
            return job
        time.sleep(0.02)
    raise AssertionError("job did not finish")


def restarts_with_same_key(fake: Any) -> list[bytes]:
    """The agent is already running: a redeploy must bring it back with the same key."""
    original = fake.start_agent
    keys: list[bytes] = []

    def restart(key: bytes) -> None:
        if not keys:
            original(key)
        keys.append(key)

    fake.start_agent = restart
    return keys


def actions(client: TestClient) -> list[str]:
    return [item["action"] for item in client.get("/api/v1/audit-events").json()["items"]]


# ----- units ----------------------------------------------------------------


def test_pick_latest_and_env_line() -> None:
    assert pick_latest(["latest", "0.1", "0.2.0", "v0.10.0", "0.9.9", "1.0.0-rc1"]) == (
        "0.10.0", "v0.10.0")
    assert pick_latest(["v1.2.3", "1.2.3"]) == ("1.2.3", "1.2.3")
    assert pick_latest(["latest", "01.2.3", "sha-1"]) is None
    env = "# c\nMRK_IMAGE=old\nMRK_AGENT_PAIRING_KEY=k=1\n"
    changed = set_env_line(env, "MRK_IMAGE", "new")
    assert changed == "# c\nMRK_IMAGE=new\nMRK_AGENT_PAIRING_KEY=k=1\n"
    assert set_env_line("A=1", "MRK_PANEL_IMAGE", "x") == "A=1\nMRK_PANEL_IMAGE=x\n"


# ----- check ----------------------------------------------------------------


def test_check_lists_tags_with_token_and_notifies_once(tmp_path: Path, ghcr, monkeypatch) -> None:
    monkeypatch.setenv("MRK_IMAGE_TAG", "0.2.0")
    with TestClient(create_app(Settings.for_test(tmp_path / "cp"))) as client:
        assert client.get("/api/v1/releases/status").status_code == 401
        headers = owner(client)
        published: list[Any] = []
        events = releases.ACTIVE_SERVICE.ctx.events
        monkeypatch.setattr(events, "publish", published.append)
        before = client.get("/api/v1/releases/status").json()
        assert before["current"] == {"version": "0.2.0", "image_tag": "0.2.0", "runtime": "docker"}
        assert before["latest"]["version"] is None and before["update_available"] is False
        assert client.post("/api/v1/releases/check").status_code == 403  # CSRF
        checked = client.post("/api/v1/releases/check", headers=headers).json()
        assert checked["latest"]["version"] == "0.3.0" and checked["latest"]["tag"] == "v0.3.0"
        assert checked["latest"]["error_code"] is None and checked["update_available"] is True
        assert checked["latest"]["notes_url"] == (
            "https://github.com/SeniorKian/MrK_DevAssist/releases/tag/v0.3.0")
        client.post("/api/v1/releases/check", headers=headers)
        assert client.get("/api/v1/releases/summary").json() == {
            "current": "0.2.0", "latest": "0.3.0", "update_available": True}
        status = client.get("/api/v1/releases/status").json()
        assert status["update_available"] is True and status["panel"]["method"] == "compose"
        assert "release.check" in actions(client)
    (token,) = {str(request.url) for request in ghcr.token_requests}
    assert "scope=repository%3Aseniorkian%2Fmrk-panel%3Apull" in token
    assert "service=ghcr.io" in token
    assert ghcr.requests[0].headers.get("authorization") is None
    assert len(ghcr.requests) >= 3  # 401, page 1, page 2 (the second check again)
    assert [event.type for event in published] == ["release.available"]
    assert published[0].details["version"] == "0.3.0"
    # The cache survives a restart.
    with TestClient(create_app(Settings.for_test(tmp_path / "cp"))) as client:
        owner(client)
        assert client.get("/api/v1/releases/status").json()["latest"]["version"] == "0.3.0"


def test_check_failure_keeps_last_version(tmp_path: Path, ghcr) -> None:
    with TestClient(create_app(Settings.for_test(tmp_path / "cp"))) as client:
        headers = owner(client)
        client.post("/api/v1/releases/check", headers=headers)
        ghcr.status = 503
        failed = client.post("/api/v1/releases/check", headers=headers).json()
        assert failed["latest"]["error_code"] == "unreachable"
        assert failed["latest"]["version"] == "0.3.0"
        ghcr.status = 302  # redirects are never followed
        assert client.post("/api/v1/releases/check",
                           headers=headers).json()["latest"]["error_code"] == "unreachable"
        ghcr.status = 404
        assert client.post("/api/v1/releases/check",
                           headers=headers).json()["latest"]["error_code"] == "not_found"


def test_status_for_native_panel(tmp_path: Path, ghcr, monkeypatch) -> None:
    monkeypatch.setenv("MRK_PANEL_RUNTIME", "native")
    with TestClient(create_app(Settings.for_test(tmp_path / "cp"))) as client:
        headers = owner(client)
        client.post("/api/v1/releases/check", headers=headers)
        status = client.get("/api/v1/releases/status").json()
        assert status["current"]["runtime"] == "native"
        assert status["panel"]["method"] == "native" and status["panel"]["can_auto"] is False
        command = status["panel"]["commands"][0]["command"]
        assert "git checkout v0.3.0" in command and "install-native.sh upgrade" in command
        refused = client.post("/api/v1/releases/panel/upgrade", headers=headers,
                              json={"version": "0.3.0", "confirmation": "UPDATE"})
        assert refused.status_code == 409 and refused.json()["error"]["code"] == "manual_upgrade"
        ids = {item["id"] for item in status["services"]}
        assert {"agent", "git", "registry"} <= ids
        assert all(item["needs_update"] is False for item in status["services"])


# ----- service upgrades -----------------------------------------------------


def test_dokploy_service_upgrade_keeps_pairing_key(tmp_path: Path, fakes, ghcr,  # noqa: F811
                                                    monkeypatch) -> None:
    dokploy = fakes["dokploy"]
    keys = restarts_with_same_key(dokploy)
    monkeypatch.setenv("MRK_IMAGE_TAG", "0.1.0")
    with TestClient(create_app(Settings.for_test(tmp_path / "cp"))) as client:
        headers = owner(client)
        connect_dokploy(client, headers)
        started = client.post("/api/v1/install/agent/auto", headers=headers,
                              json={"target": "dokploy", "project_id": "p1",
                                    "environment_id": "e1", "env": {"MRK_DOCKER_GID": "988"}})
        assert wait_job(client, started.json()["id"])["status"] == "succeeded"
        key = env_value(dokploy.env_text, "MRK_AGENT_PAIRING_KEY")
        agent = next(item for item in client.get("/api/v1/releases/status").json()["services"]
                     if item["id"] == "agent")
        assert agent["deployed_image"] == "ghcr.io/seniorkian/mrk-agent:0.1.0"
        assert agent["needs_update"] is False and agent["target"] == "dokploy"
        assert agent["can_auto"] is True and agent["connection"] == "connected"

        monkeypatch.setenv("MRK_IMAGE_TAG", "0.2.0")  # the panel was updated
        agent = next(item for item in client.get("/api/v1/releases/status").json()["services"]
                     if item["id"] == "agent")
        assert agent["needs_update"] is True and agent["image"].endswith("mrk-agent:0.2.0")
        assert client.post("/api/v1/releases/services/agent/upgrade").status_code == 403
        dokploy.requests.clear()
        upgrade = client.post("/api/v1/releases/services/agent/upgrade", headers=headers)
        assert upgrade.status_code == 202, upgrade.text
        job = wait_release_job(client, upgrade.json()["id"])
        assert job["status"] == "succeeded", job
        assert job["connection"] == "connected" and job["deployed"] is True
        agent = next(item for item in client.get("/api/v1/releases/status").json()["services"]
                     if item["id"] == "agent")
        assert agent["needs_update"] is False
        assert agent["deployed_image"] == "ghcr.io/seniorkian/mrk-agent:0.2.0"
        assert {"release.upgrade.start", "release.upgrade.deploy",
                "release.upgrade.done"} <= set(actions(client))
        assert key not in upgrade.text + str(job)
    procedures = [name for name, _ in dokploy.requests]
    assert "compose.create" not in procedures
    assert procedures.index("compose.update") < procedures.index("compose.deploy")
    update = next(body for name, body in dokploy.requests if name == "compose.update")
    # The compose file is already the current one: only the env line changes.
    assert update["composeId"] == "c1" and "composeFile" not in update
    assert "sourceType" not in update
    assert env_value(update["env"], "MRK_IMAGE") == "ghcr.io/seniorkian/mrk-agent:0.2.0"
    assert env_value(update["env"], "MRK_AGENT_PAIRING_KEY") == key
    assert env_value(update["env"], "MRK_DOCKER_GID") == "988"
    assert update["env"].count("MRK_IMAGE=") == 1
    assert len(keys) == 2 and keys[0] == keys[1]


class UpgradableCoolify(FakeCoolify):
    def handler(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path.removeprefix("/api/v1")
        if request.headers.get("authorization") and request.method == "PATCH":
            import json

            body = json.loads(request.content)
            if path == "/services/svc1":
                self.requests.append((request.method, path, body))
                self.compose_raw = base64.b64decode(body["docker_compose_raw"]).decode()
                return httpx.Response(200, json={"uuid": "svc1"})
            if path == "/services/svc1/envs/bulk" and self.envs:
                # Coolify upserts the given keys and keeps the others.
                self.requests.append((request.method, path, body))
                merged = {item["key"]: item for item in self.envs}
                merged.update({item["key"]: item for item in body["data"]})
                self.envs = list(merged.values())
                return httpx.Response(201, json=[])
        if (request.method, path) == ("POST", "/services/svc1/restart"):
            self.requests.append((request.method, path, None))
            key = next(item["value"] for item in self.envs
                       if item["key"] == "MRK_AGENT_PAIRING_KEY")
            self.start_agent(signing.decode_key(key))
            return httpx.Response(200, json={"message": "Restart request queued."})
        return super().handler(request)


def test_coolify_service_upgrade_patches_only_the_image(
    tmp_path: Path, fakes, ghcr, monkeypatch, agent_backend,  # noqa: F811
) -> None:
    from mrk_control_plane.modules import coolify_client

    coolify = UpgradableCoolify(agent_backend["start"])
    keys = restarts_with_same_key(coolify)
    monkeypatch.setattr(coolify_client, "TRANSPORT_FACTORY",
                        lambda: httpx.MockTransport(coolify.handler))
    monkeypatch.setenv("MRK_IMAGE_TAG", "0.1.0")
    with TestClient(create_app(Settings.for_test(tmp_path / "cp"))) as client:
        headers = owner(client)
        assert connect_coolify(client, headers).status_code == 200
        started = client.post("/api/v1/install/agent/auto", headers=headers,
                              json={"target": "coolify", "project_id": "cp1", "server_id": "s1"})
        assert wait_job(client, started.json()["id"])["status"] == "succeeded"
        key = next(item["value"] for item in coolify.envs
                   if item["key"] == "MRK_AGENT_PAIRING_KEY")
        monkeypatch.setenv("MRK_IMAGE_TAG", "0.2.0")
        coolify.requests.clear()
        upgrade = client.post("/api/v1/releases/services/agent/upgrade", headers=headers)
        assert upgrade.status_code == 202, upgrade.text
        job = wait_release_job(client, upgrade.json()["id"])
        assert job["status"] == "succeeded", job
    sent = [(method, path) for method, path, _ in coolify.requests]
    assert ("PATCH", "/services/svc1") in sent and ("POST", "/services/svc1/restart") in sent
    bulk = next(body for method, path, body in coolify.requests
                if path == "/services/svc1/envs/bulk")
    assert bulk == {"data": [{"key": "MRK_IMAGE", "value": "ghcr.io/seniorkian/mrk-agent:0.2.0",
                              "is_literal": True}]}
    values = {item["key"]: item["value"] for item in coolify.envs}
    assert values["MRK_AGENT_PAIRING_KEY"] == key
    assert values["MRK_IMAGE"].endswith("mrk-agent:0.2.0")
    assert "mrk-net" in coolify.compose_raw
    assert len(keys) == 2 and keys[0] == keys[1]


def test_manual_upgrade_path(tmp_path: Path, ghcr, agent_backend, monkeypatch) -> None:  # noqa: F811
    monkeypatch.setenv("MRK_IMAGE_TAG", "0.1.0")
    with TestClient(create_app(Settings.for_test(tmp_path / "cp"))) as client:
        headers = owner(client)
        bundle = client.post("/api/v1/install/agent/bundle", headers=headers, json={}).json()
        key = env_value(bundle["env"], "MRK_AGENT_PAIRING_KEY")
        agent_backend["start"](signing.decode_key(key))
        assert client.post("/api/v1/install/agent/connect", headers=headers,
                           json={}).json()["connection"] == "connected"
        monkeypatch.setenv("MRK_IMAGE_TAG", "0.2.0")
        agent = next(item for item in client.get("/api/v1/releases/status").json()["services"]
                     if item["id"] == "agent")
        assert agent["needs_update"] is True and agent["can_auto"] is False
        assert agent["target"] is None
        refused = client.post("/api/v1/releases/services/agent/upgrade", headers=headers)
        assert refused.status_code == 409 and refused.json()["error"]["code"] == "manual_upgrade"
        manual = client.get("/api/v1/releases/services/agent/manual").json()
        assert manual["env_change"] == "MRK_IMAGE=ghcr.io/seniorkian/mrk-agent:0.2.0"
        assert "mrk-net" in manual["compose"] and key not in manual["compose"]
        assert manual["commands"] == ["docker compose pull", "docker compose up -d"]
        assert set(manual["steps"]) == {"dokploy", "coolify", "compose"}
        git = client.get("/api/v1/releases/services/git/manual").json()
        assert git["env_change"] is None and "gitea/gitea" in git["compose"]
        assert client.get("/api/v1/releases/services/nope/manual").status_code == 404
        assert client.post("/api/v1/releases/services/agent/mark-updated").status_code == 403
        marked = client.post("/api/v1/releases/services/agent/mark-updated", headers=headers)
        assert marked.json()["deployed_image"].endswith("mrk-agent:0.2.0")
        agent = next(item for item in client.get("/api/v1/releases/status").json()["services"]
                     if item["id"] == "agent")
        assert agent["needs_update"] is False
        # The pairing key is unchanged: the connection still works.
        assert agent["connection"] == "connected"
        assert "release.mark_updated" in actions(client)


# ----- panel self-update ----------------------------------------------------


def test_panel_self_upgrade_through_dokploy(tmp_path: Path, fakes, ghcr,  # noqa: F811
                                            monkeypatch) -> None:
    dokploy = fakes["dokploy"]
    monkeypatch.setenv("MRK_IMAGE_TAG", "0.2.0")
    detected = {"inside_dokploy": True, "dokploy_connected": True,
                "dokploy_service_type": "compose", "dokploy_service_id": "c-panel"}

    async def fake_detected(self):
        return detected

    monkeypatch.setattr(releases.ReleasesService, "_detected", fake_detected)
    with TestClient(create_app(Settings.for_test(tmp_path / "cp"))) as client:
        headers = owner(client)
        connect_dokploy(client, headers)
        body = {"version": "0.3.0", "confirmation": "UPDATE"}
        unknown = client.post("/api/v1/releases/panel/upgrade", headers=headers, json=body)
        assert unknown.status_code == 409 and unknown.json()["error"]["code"] == "latest_unknown"
        client.post("/api/v1/releases/check", headers=headers)
        panel = client.get("/api/v1/releases/status").json()["panel"]
        assert panel["method"] == "dokploy" and panel["can_auto"] is True
        command = panel["commands"][0]["command"]
        assert command == "MRK_PANEL_IMAGE=ghcr.io/seniorkian/mrk-panel:0.3.0"

        assert client.post("/api/v1/releases/panel/upgrade", json=body).status_code == 403
        typo = client.post("/api/v1/releases/panel/upgrade", headers=headers,
                           json={"version": "0.3.0", "confirmation": "update"})
        assert typo.status_code == 422 and typo.json()["error"]["code"] == "confirmation_required"
        for bad in ("0.4.0", "v0.3.0", "0.3.0-rc1", "latest"):
            wrong = client.post("/api/v1/releases/panel/upgrade", headers=headers,
                                json={"version": bad, "confirmation": "UPDATE"})
            assert wrong.status_code == 422, bad

        dokploy.env_text = ("POSTGRES_PASSWORD=keep-me\n"
                            "MRK_PANEL_IMAGE=ghcr.io/seniorkian/mrk-panel:0.2.0\n")
        # A compose file that does not read MRK_PANEL_IMAGE would not change: refused.
        dokploy.compose_file = "services:\n  mrk-panel:\n    image: x/mrk-panel:0.2.0\n"
        fixed = client.post("/api/v1/releases/panel/upgrade", headers=headers, json=body)
        assert fixed.status_code == 409 and fixed.json()["error"]["code"] == "manual_upgrade"
        dokploy.compose_file = "services:\n  mrk-panel:\n    image: ${MRK_PANEL_IMAGE}\n"
        dokploy.requests.clear()
        dokploy.deploy_result = "running"  # the panel restarts; the request returns at once
        done = client.post("/api/v1/releases/panel/upgrade", headers=headers, json=body)
        assert done.status_code == 202, done.text
        assert done.json() == {"version": "0.3.0",
                               "image": "ghcr.io/seniorkian/mrk-panel:0.3.0",
                               "status": "deploying", "shared_variable": None}
        assert "release.panel.upgrade" in actions(client)

        client.cookies.clear()
        operator_headers = _login_as(client, owner(client)["X-CSRF-Token"], "operator")
        denied = client.post("/api/v1/releases/panel/upgrade", headers=operator_headers, json=body)
        assert denied.status_code == 403
        # operator may operate services but has no agent:write
        assert client.post("/api/v1/releases/services/agent/upgrade",
                           headers=operator_headers).status_code == 403
        assert client.get("/api/v1/releases/status").status_code == 200
    update = next(body for name, body in dokploy.requests if name == "compose.update")
    assert set(update) == {"composeId", "env"} and update["composeId"] == "c-panel"
    assert env_value(update["env"], "MRK_PANEL_IMAGE") == "ghcr.io/seniorkian/mrk-panel:0.3.0"
    assert env_value(update["env"], "POSTGRES_PASSWORD") == "keep-me"
    deploy = next(body for name, body in dokploy.requests if name == "compose.deploy")
    assert deploy["composeId"] == "c-panel"


def test_panel_upgrade_moves_the_shared_project_version(tmp_path: Path, fakes, ghcr,  # noqa: F811
                                                         monkeypatch) -> None:
    """MRK_PANEL_IMAGE=...:${{project.MRK_VERSION}}: the project variable moves, not the line."""
    dokploy = fakes["dokploy"]
    monkeypatch.setenv("MRK_IMAGE_TAG", "0.2.0")
    detected = {"inside_dokploy": True, "dokploy_connected": True,
                "dokploy_service_type": "compose", "dokploy_service_id": "c-panel"}

    async def fake_detected(self):
        return detected

    monkeypatch.setattr(releases.ReleasesService, "_detected", fake_detected)
    reference = "ghcr.io/seniorkian/mrk-panel:${{project.MRK_VERSION}}"
    dokploy.env_text = f"MRK_PANEL_IMAGE={reference}\n"
    dokploy.project_env = "# one version for every service\nMRK_VERSION=0.2.0\nOTHER=x\n"
    dokploy.compose_file = "services:\n  mrk-panel:\n    image: ${MRK_PANEL_IMAGE}\n"
    dokploy.deploy_result = "running"
    with TestClient(create_app(Settings.for_test(tmp_path / "cp"))) as client:
        headers = owner(client)
        connect_dokploy(client, headers)
        client.post("/api/v1/releases/check", headers=headers)
        done = client.post("/api/v1/releases/panel/upgrade", headers=headers,
                           json={"version": "0.3.0", "confirmation": "UPDATE"})
        assert done.status_code == 202, done.text
        assert done.json()["shared_variable"] == "project.MRK_VERSION"
    names = [name for name, _ in dokploy.requests]
    assert "compose.update" not in names and "compose.deploy" in names
    assert env_value(dokploy.env_text, "MRK_PANEL_IMAGE") == reference
    assert env_value(dokploy.project_env, "MRK_VERSION") == "0.3.0"
    assert env_value(dokploy.project_env, "OTHER") == "x"
    assert dokploy.project_env.startswith("# one version for every service")


def test_service_upgrade_keeps_shared_version_and_edited_compose(
    tmp_path: Path, fakes, ghcr, monkeypatch,  # noqa: F811
) -> None:
    """The admin's ${{project.MRK_VERSION}} line and edited compose file survive an update."""
    dokploy = fakes["dokploy"]
    keys = restarts_with_same_key(dokploy)
    monkeypatch.setenv("MRK_IMAGE_TAG", "0.1.0")
    with TestClient(create_app(Settings.for_test(tmp_path / "cp"))) as client:
        headers = owner(client)
        connect_dokploy(client, headers)
        started = client.post("/api/v1/install/agent/auto", headers=headers,
                              json={"target": "dokploy", "project_id": "p1",
                                    "environment_id": "e1", "env": {"MRK_DOCKER_GID": "988"}})
        assert wait_job(client, started.json()["id"])["status"] == "succeeded"
        reference = "ghcr.io/seniorkian/mrk-agent:${{project.MRK_VERSION}}"
        env = dokploy.env_text.replace("MRK_IMAGE=ghcr.io/seniorkian/mrk-agent:0.1.0",
                                       f"MRK_IMAGE={reference}")
        dokploy.env_text = env
        dokploy.project_env = "MRK_VERSION=0.1.0\n"
        dokploy.compose_file += "# my bind mounts\n"
        edited = dokploy.compose_file
        monkeypatch.setenv("MRK_IMAGE_TAG", "0.2.0")
        dokploy.requests.clear()
        upgrade = client.post("/api/v1/releases/services/agent/upgrade", headers=headers)
        job = wait_release_job(client, upgrade.json()["id"])
        assert job["status"] == "succeeded", job
        assert {"shared_version_changed", "compose_customized"} <= set(job["warnings"])
    names = [name for name, _ in dokploy.requests]
    assert "compose.update" not in names and "compose.deploy" in names
    assert dokploy.env_text == env and dokploy.compose_file == edited
    assert env_value(dokploy.project_env, "MRK_VERSION") == "0.2.0"
    assert len(keys) == 2 and keys[0] == keys[1]
