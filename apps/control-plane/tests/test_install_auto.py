"""Automatic install through Dokploy / Coolify (docs/44 phase 6)."""

from __future__ import annotations

import base64
import json
import logging
import time
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient
from mrk_control_plane.agent import signing
from mrk_control_plane.config import Settings
from mrk_control_plane.main import create_app
from mrk_control_plane.modules import coolify_client, dokploy_client, install_auto
from mrk_control_plane.modules.coolify_client import validate_coolify_url

from .helpers import login_owner
from .test_dokploy import _login_as
from .test_install_wizard import agent_backend, env_value  # noqa: F401 - pytest fixture

DOKPLOY_KEY = "dokployAPIkey_" + "y" * 40  # noqa: S105 - test-only fixture
COOLIFY_TOKEN = "3|coolifyTOKEN" + "z" * 40  # noqa: S105 - test-only fixture
DOKPLOY_URL = "http://dokploy.lan:3000"
COOLIFY_URL = "http://coolify.lan:8000"


class FakeDokploy:
    def __init__(self, start_agent) -> None:
        self.start_agent = start_agent
        self.requests: list[tuple[str, Any]] = []
        self.compose: dict[str, Any] = {}
        self.status = "idle"
        self.deploy_result = "done"
        self.existing = False
        self.env_text = ""

    def project(self) -> dict[str, Any]:
        compose = [{"composeId": "c-old", "name": "mrk-agent"}] if self.existing else []
        return {"projectId": "p1", "name": "Apps", "environments": [
            {"environmentId": "e1", "name": "production", "compose": compose}]}

    def handler(self, request: httpx.Request) -> httpx.Response:
        assert request.url.host == "dokploy.lan"
        if request.headers.get("x-api-key") != DOKPLOY_KEY:
            return httpx.Response(401, json={"message": "Unauthorized"})
        procedure = request.url.path.removeprefix("/api/")
        body = json.loads(request.content) if request.method == "POST" else dict(request.url.params)
        self.requests.append((procedure, body))
        if procedure == "settings.getDokployVersion":
            return httpx.Response(200, json="v0.25.3")
        if procedure == "project.all":
            return httpx.Response(200, json=[self.project()])
        if procedure == "project.one":
            if body.get("projectId") == "p2":
                return httpx.Response(200, json={"projectId": "p2", "environments": [
                    {"environmentId": "e2", "name": "production", "compose": []}]})
            return httpx.Response(200, json=self.project())
        if procedure == "project.create":
            return httpx.Response(200, json={"project": {"projectId": "p2"},
                                             "environment": {"environmentId": "e2"}})
        if procedure == "compose.create":
            return httpx.Response(200, json={"composeId": "c1", "appName": "mrk-agent-abc"})
        if procedure == "compose.update":
            self.env_text = body["env"]
            return httpx.Response(200, json={"composeId": body["composeId"], "env": body["env"]})
        if procedure == "compose.deploy":
            self.status = self.deploy_result
            if self.deploy_result == "done":
                key = env_value(self.env_text, "MRK_AGENT_PAIRING_KEY")
                self.start_agent(signing.decode_key(key))
            return httpx.Response(200, json={"success": True, "message": "Deployment queued"})
        if procedure == "compose.one":
            return httpx.Response(200, json={"composeId": body["composeId"],
                                             "composeStatus": self.status, "env": self.env_text})
        return httpx.Response(404, json={"message": "Not found"})


class FakeCoolify:
    def __init__(self, start_agent) -> None:
        self.start_agent = start_agent
        self.requests: list[tuple[str, str, Any]] = []
        self.envs: list[dict[str, Any]] = []
        self.compose_raw = ""
        self.create_status = 201
        self.servers: list[dict[str, Any]] = [
            {"uuid": "s1", "name": "localhost", "ip": "host.docker.internal",
             "settings": {"is_reachable": True}},
            {"uuid": "s2", "name": "remote", "ip": "10.0.0.9", "settings": {"is_reachable": True}},
        ]
        self.running = False

    def handler(self, request: httpx.Request) -> httpx.Response:
        assert request.url.host == "coolify.lan"
        if request.headers.get("authorization") != f"Bearer {COOLIFY_TOKEN}":
            return httpx.Response(401, json={"message": "Unauthenticated."})
        path = request.url.path.removeprefix("/api/v1")
        body = json.loads(request.content) if request.content else None
        self.requests.append((request.method, path, body))
        route = (request.method, path)
        if route == ("GET", "/version"):
            return httpx.Response(200, text="4.0.0-beta.420")
        if route == ("GET", "/projects"):
            return httpx.Response(200, json=[{"id": 1, "uuid": "cp1", "name": "Main"}])
        if route == ("GET", "/projects/cp1/environments"):
            return httpx.Response(200, json=[{"id": 7, "uuid": "ce1", "name": "production"}])
        if route == ("GET", "/servers"):
            return httpx.Response(200, json=self.servers)
        if route == ("GET", "/services"):
            return httpx.Response(200, json=[])
        if route == ("POST", "/services"):
            if self.create_status != 201:
                return httpx.Response(self.create_status,
                                      json={"message": "Server has many destinations"})
            self.compose_raw = base64.b64decode(body["docker_compose_raw"]).decode()
            return httpx.Response(201, json={"uuid": "svc1", "domains": []})
        if route == ("PATCH", "/services/svc1/envs/bulk"):
            self.envs = body["data"]
            return httpx.Response(201, json=[])
        if route == ("POST", "/services/svc1/start"):
            key = next(item["value"] for item in self.envs
                       if item["key"] == "MRK_AGENT_PAIRING_KEY")
            self.start_agent(signing.decode_key(key))
            self.running = True
            return httpx.Response(200, json={"message": "Service starting request queued."})
        if route == ("GET", "/services/svc1"):
            status = "running:healthy" if self.running else "starting"
            return httpx.Response(200, json={"uuid": "svc1", "name": "mrk-agent",
                                             "status": status})
        return httpx.Response(404, json={"message": "Not found."})


@pytest.fixture
def fakes(monkeypatch, agent_backend):  # noqa: F811 - pytest fixture
    dokploy = FakeDokploy(agent_backend["start"])
    coolify = FakeCoolify(agent_backend["start"])
    monkeypatch.setattr(dokploy_client, "TRANSPORT_FACTORY",
                        lambda: httpx.MockTransport(dokploy.handler))
    monkeypatch.setattr(coolify_client, "TRANSPORT_FACTORY",
                        lambda: httpx.MockTransport(coolify.handler))
    for name in ("MRK_DOKPLOY_URL", "MRK_DOKPLOY_API_KEY_FILE", "MRK_DOKPLOY_ALLOW_LOOPBACK",
                 "MRK_COOLIFY_ALLOW_LOOPBACK", "MRK_DOKPLOY_CACHE_SECONDS"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("MRK_DOKPLOY_POLL_SECONDS", "0")
    monkeypatch.setattr(install_auto, "POLL_SECONDS", 0.01)
    monkeypatch.setattr(install_auto, "CONNECT_DELAY_SECONDS", 0.01)
    monkeypatch.setattr(install_auto, "CONNECT_ATTEMPTS", 3)
    return {"dokploy": dokploy, "coolify": coolify}


def owner(client: TestClient) -> dict[str, str]:
    return {"X-CSRF-Token": str(login_owner(client)["csrf_token"])}


def connect_dokploy(client: TestClient, headers: dict[str, str]) -> None:
    response = client.put("/api/v1/dokploy/config", headers=headers,
                          json={"url": DOKPLOY_URL, "api_key": DOKPLOY_KEY,
                                "rate_limit_per_second": 20})
    assert response.status_code == 200, response.text


def connect_coolify(client: TestClient, headers: dict[str, str]) -> httpx.Response:
    return client.put("/api/v1/coolify/config", headers=headers,
                      json={"url": COOLIFY_URL + "/api/v1", "token": COOLIFY_TOKEN})


def wait_job(client: TestClient, job_id: str) -> dict[str, Any]:
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        job = client.get(f"/api/v1/install/auto/jobs/{job_id}").json()
        if job["status"] != "running":
            return job
        time.sleep(0.02)
    raise AssertionError("job did not finish")


# ----- units ----------------------------------------------------------------


def test_validate_coolify_url_and_env_pairs() -> None:
    assert validate_coolify_url("http://coolify.lan:8000/api/v1/") == "http://coolify.lan:8000"
    for bad in ("ftp://coolify.lan", "http://169.254.169.254", "http://u:p@coolify.lan",
                "http://127.0.0.1:8000", "http://coolify.lan/?x=1"):
        with pytest.raises(ValueError, match="Coolify"):
            validate_coolify_url(bad)
    assert validate_coolify_url("http://127.0.0.1:8000", allow_loopback=True)
    assert install_auto.env_pairs("# c\nA=1\n\nB=x=y\n") == [("A", "1"), ("B", "x=y")]


# ----- Coolify connection ---------------------------------------------------


def test_coolify_config_lifecycle(tmp_path: Path, fakes, caplog) -> None:
    caplog.set_level(logging.DEBUG)
    with TestClient(create_app(Settings.for_test(tmp_path / "cp"))) as client:
        assert client.get("/api/v1/coolify/config").status_code == 401
        headers = owner(client)
        assert client.get("/api/v1/coolify/config").json()["configured"] is False
        unsafe = client.put("/api/v1/coolify/config",
                            json={"url": COOLIFY_URL, "token": COOLIFY_TOKEN})
        assert unsafe.status_code == 403
        bad = client.put("/api/v1/coolify/config", headers=headers,
                         json={"url": "http://169.254.169.254", "token": COOLIFY_TOKEN})
        assert bad.status_code == 422 and bad.json()["error"]["code"] == "invalid_coolify_url"
        no_token = client.put("/api/v1/coolify/config", headers=headers, json={"url": COOLIFY_URL})
        assert no_token.json()["error"]["code"] == "coolify_token_required"

        saved = connect_coolify(client, headers)
        assert saved.status_code == 200
        assert saved.json()["url"] == COOLIFY_URL and saved.json()["token_configured"] is True
        tested = client.post("/api/v1/coolify/test", headers=headers).json()
        assert tested["ok"] is True and tested["version"] == "4.0.0-beta.420"
        wrong = client.post("/api/v1/coolify/test", headers=headers,
                            json={"token": "0|wrong-token-value-123456"}).json()
        assert wrong == {"ok": False, "latency_ms": wrong["latency_ms"],
                         "error_code": "coolify_auth_failed"}
        # Same URL without a token keeps the stored one; a new URL needs it again.
        assert client.put("/api/v1/coolify/config", headers=headers,
                          json={"url": COOLIFY_URL}).status_code == 200
        moved = client.put("/api/v1/coolify/config", headers=headers,
                           json={"url": "http://other.lan:8000"})
        assert moved.json()["error"]["code"] == "coolify_token_required"

        everything = client.get("/api/v1/coolify/config").text + client.get(
            "/api/v1/install/targets").text
        assert COOLIFY_TOKEN not in everything
        assert client.request("DELETE", "/api/v1/coolify/config", headers=headers,
                              json={}).status_code == 422
        gone = client.request("DELETE", "/api/v1/coolify/config", headers=headers,
                              json={"confirmation": "DISCONNECT"})
        assert gone.json()["configured"] is False
        actions = [item["action"] for item in client.get("/api/v1/audit-events").json()["items"]]
        assert {"coolify.config.update", "coolify.test", "coolify.disconnect"} <= set(actions)
    assert COOLIFY_TOKEN not in caplog.text
    for path in (tmp_path / "cp").rglob("coolify.json"):
        assert COOLIFY_TOKEN not in path.read_text(encoding="utf-8")


def test_targets_list_what_each_platform_offers(tmp_path: Path, fakes) -> None:
    with TestClient(create_app(Settings.for_test(tmp_path / "cp"))) as client:
        headers = owner(client)
        empty = client.get("/api/v1/install/targets").json()
        assert empty["dokploy"]["configured"] is False and empty["coolify"]["configured"] is False
        assert empty["same_host_required"] is True
        connect_dokploy(client, headers)
        assert connect_coolify(client, headers).status_code == 200
        targets = client.get("/api/v1/install/targets?refresh=true").json()
    dokploy, coolify = targets["dokploy"], targets["coolify"]
    assert dokploy["reachable"] is True and dokploy["panel_url"] == DOKPLOY_URL
    assert dokploy["projects"] == [{"id": "p1", "name": "Apps", "legacy": False,
                                    "environments": [{"id": "e1", "name": "production"}]}]
    assert coolify["reachable"] is True
    assert coolify["projects"] == [{"id": "cp1", "name": "Main",
                                    "environments": [{"id": "ce1", "name": "production"}]}]
    assert coolify["servers"][0] == {"id": "s1", "name": "localhost", "local": True,
                                     "reachable": True}
    assert coolify["servers"][1]["local"] is False


# ----- auto install ---------------------------------------------------------


def test_dokploy_auto_install_creates_deploys_and_connects(tmp_path: Path, fakes, caplog) -> None:
    caplog.set_level(logging.DEBUG)
    dokploy = fakes["dokploy"]
    with TestClient(create_app(Settings.for_test(tmp_path / "cp"))) as client:
        headers = owner(client)
        early = client.post("/api/v1/install/agent/auto", headers=headers,
                            json={"target": "dokploy"})
        assert early.status_code == 409
        assert early.json()["error"]["code"] == "dokploy_not_configured"
        connect_dokploy(client, headers)
        assert client.post("/api/v1/install/agent/auto",
                           json={"target": "dokploy"}).status_code == 403  # CSRF
        bad = client.post("/api/v1/install/agent/auto", headers=headers,
                          json={"target": "dokploy", "project_id": "../x"})
        assert bad.status_code == 422
        started = client.post("/api/v1/install/agent/auto", headers=headers,
                              json={"target": "dokploy", "project_id": "p1",
                                    "environment_id": "e1", "env": {"MRK_DOCKER_GID": "988"}})
        assert started.status_code == 202, started.text
        job = wait_job(client, started.json()["id"])
        assert job["status"] == "succeeded", job
        assert job["connection"] == "connected" and job["deployed"] is True
        assert job["resource_id"] == "c1" and job["reused"] is False
        assert job["resource_url"] == (f"{DOKPLOY_URL}/dashboard/project/p1/environment/e1"
                                       "/services/compose/c1")
        assert client.get("/api/v1/agent/status").json()["configured"] is True
        assert install_auto.deployment_for(tmp_path / "cp", "agent") == {
            "target": "dokploy", "compose_id": "c1", "service_name": "mrk-agent",
            "project_id": "p1", "environment_id": "e1",
            "updated_at": install_auto.deployment_for(tmp_path / "cp", "agent")["updated_at"],
        }
        texts = started.text + json.dumps(job) + client.get("/api/v1/install/targets").text
        actions = [item["action"] for item in client.get("/api/v1/audit-events").json()["items"]]
    procedures = [name for name, _body in dokploy.requests]
    assert procedures.index("compose.create") < procedures.index("compose.update") < \
        procedures.index("compose.deploy") < procedures.index("compose.one")
    create = next(body for name, body in dokploy.requests if name == "compose.create")
    assert create["environmentId"] == "e1" and create["name"] == "mrk-agent"
    update = next(body for name, body in dokploy.requests if name == "compose.update")
    assert update["sourceType"] == "raw" and "mrk-net" in update["composeFile"]
    assert env_value(update["env"], "MRK_DOCKER_GID") == "988"
    key = env_value(update["env"], "MRK_AGENT_PAIRING_KEY")
    assert key not in texts and key not in caplog.text and DOKPLOY_KEY not in caplog.text
    assert {"install.auto.start", "install.auto.create", "install.auto.deploy",
            "install.auto.connect"} <= set(actions)


def test_dokploy_new_project_reuse_and_failed_deploy(tmp_path: Path, fakes) -> None:
    dokploy = fakes["dokploy"]
    with TestClient(create_app(Settings.for_test(tmp_path / "cp"))) as client:
        headers = owner(client)
        connect_dokploy(client, headers)
        dokploy.deploy_result = "error"
        started = client.post("/api/v1/install/agent/auto", headers=headers,
                              json={"target": "dokploy"}).json()
        job = wait_job(client, started["id"])
        assert job["status"] == "failed" and job["error_code"] == "deploy_failed"
        assert job["project_id"] == "p2" and job["deployed"] is False
        retry = client.post(f"/api/v1/install/auto/jobs/{job['id']}/connect", headers=headers)
        assert retry.status_code == 409 and retry.json()["error"]["code"] == "not_deployed"
        create = next(body for name, body in dokploy.requests if name == "compose.create")
        assert create["environmentId"] == "e2"

        dokploy.existing = True
        dokploy.deploy_result = "done"
        dokploy.requests.clear()
        started = client.post("/api/v1/install/agent/auto", headers=headers,
                              json={"target": "dokploy", "project_id": "p1"}).json()
        job = wait_job(client, started["id"])
        assert job["status"] == "succeeded" and job["reused"] is True
        assert job["resource_id"] == "c-old"
        assert "compose.create" not in [name for name, _ in dokploy.requests]
        missing = client.get("/api/v1/install/auto/jobs/nope-nope-nope")
        assert missing.status_code == 404


def test_coolify_auto_install_creates_deploys_and_connects(tmp_path: Path, fakes, caplog) -> None:
    caplog.set_level(logging.DEBUG)
    coolify = fakes["coolify"]
    with TestClient(create_app(Settings.for_test(tmp_path / "cp"))) as client:
        headers = owner(client)
        assert connect_coolify(client, headers).status_code == 200
        started = client.post("/api/v1/install/agent/auto", headers=headers,
                              json={"target": "coolify", "project_id": "cp1",
                                    "environment_name": "production", "server_id": "s1"})
        assert started.status_code == 202, started.text
        job = wait_job(client, started.json()["id"])
        assert job["status"] == "succeeded", job
        assert job["resource_id"] == "svc1" and "server_not_local" not in job["warnings"]
        deployment = install_auto.deployment_for(tmp_path / "cp", "agent")
        assert deployment is not None and deployment["target"] == "coolify"
        assert deployment["uuid"] == "svc1" and deployment["server_id"] == "s1"
        assert install_auto.deployment_for(tmp_path / "cp", "dns") is None
        texts = started.text + json.dumps(job)
    create = next(body for method, path, body in coolify.requests
                  if (method, path) == ("POST", "/services"))
    assert create["server_uuid"] == "s1" and create["project_uuid"] == "cp1"
    assert create["environment_name"] == "production" and create["instant_deploy"] is False
    assert "mrk-net" in coolify.compose_raw
    names = {item["key"] for item in coolify.envs}
    assert {"MRK_IMAGE", "MRK_AGENT_PAIRING_KEY"} <= names
    assert all(item["is_literal"] for item in coolify.envs)
    key = next(item["value"] for item in coolify.envs if item["key"] == "MRK_AGENT_PAIRING_KEY")
    assert key not in texts and key not in caplog.text and COOLIFY_TOKEN not in caplog.text


def test_coolify_errors_and_remote_server_warning(tmp_path: Path, fakes) -> None:
    coolify = fakes["coolify"]
    with TestClient(create_app(Settings.for_test(tmp_path / "cp"))) as client:
        headers = owner(client)
        assert connect_coolify(client, headers).status_code == 200
        coolify.create_status = 422
        started = client.post("/api/v1/install/agent/auto", headers=headers,
                              json={"target": "coolify", "project_id": "cp1", "server_id": "s2"})
        job = wait_job(client, started.json()["id"])
        assert job["status"] == "failed" and job["error_code"] == "coolify_rejected"
        assert "server_not_local" in job["warnings"]
        assert "many destinations" in job["message"]

        coolify.servers.append({"uuid": "s3", "name": "third", "ip": "10.0.0.10"})
        coolify.servers.pop(0)  # no local server and more than one: the operator must pick
        started = client.post("/api/v1/install/agent/auto", headers=headers,
                              json={"target": "coolify", "project_id": "cp1"})
        job = wait_job(client, started.json()["id"])
        assert job["error_code"] == "server_required"


def test_permissions(tmp_path: Path, fakes) -> None:
    with TestClient(create_app(Settings.for_test(tmp_path / "cp"))) as client:
        headers = owner(client)
        connect_dokploy(client, headers)
        assert connect_coolify(client, headers).status_code == 200
        unsupported = client.post("/api/v1/install/nope/auto", headers=headers,
                                  json={"target": "coolify"})
        assert unsupported.status_code == 404
        for role, expected in (("viewer", (403, 403)), ("operator", (200, 403))):
            client.cookies.clear()
            role_headers = _login_as(client, owner(client)["X-CSRF-Token"], role)
            assert client.get("/api/v1/install/targets").status_code == expected[0], role
            # The operator role may operate services but has no agent:write.
            auto = client.post("/api/v1/install/agent/auto", headers=role_headers,
                               json={"target": "coolify"})
            assert auto.status_code == expected[1], role
            assert client.put("/api/v1/coolify/config", headers=role_headers,
                              json={"url": COOLIFY_URL, "token": COOLIFY_TOKEN}
                              ).status_code == expected[0], role
