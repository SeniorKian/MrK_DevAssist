from __future__ import annotations

import asyncio
import json
import logging
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient
from mrk_control_plane.auth import ROLE_PERMISSIONS
from mrk_control_plane.config import Settings
from mrk_control_plane.main import create_app
from mrk_control_plane.modules import dokploy, dokploy_client
from mrk_control_plane.modules import dokploy_normalize as norm
from mrk_control_plane.modules.dokploy_client import (
    DokployError,
    TokenBucket,
    validate_api_key,
    validate_dokploy_url,
)

from .helpers import login_owner

API_KEY = "dokployAPIkey_" + "x" * 40  # noqa: S105 - test-only fixture
PANEL = "http://dokploy.lan:3000"


def iso(seconds_ago: float) -> str:
    stamp = datetime.now(UTC) - timedelta(seconds=seconds_ago)
    return stamp.isoformat().replace("+00:00", "Z")


# Shapes follow Dokploy v0.31.0 (project.all for an owner/admin key: databases
# carry only their id; *.one carries env and secrets that must never leak).
PROJECT_ALL = [
    {
        "projectId": "proj1",
        "name": "Shop",
        "description": "storefront",
        "createdAt": iso(9000),
        "organizationId": "org1",
        "env": "PROJECT_SECRET=hunter2",
        "projectTags": [],
        "environments": [
            {
                "environmentId": "env1",
                "name": "production",
                "isDefault": True,
                "applications": [
                    {"applicationId": "app1", "name": "web", "applicationStatus": "done"}
                ],
                "compose": [{"composeId": "cmp1", "name": "workers", "composeStatus": "error"}],
                "postgres": [{"postgresId": "pg1"}],
                "mysql": [],
                "mariadb": [],
                "mongo": [],
                "redis": [{"redisId": "rd1"}],
                "libsql": [{"libsqlId": "ls1"}],
            }
        ],
    }
]

PROJECT_ONE = {
    "projectId": "proj1",
    "name": "Shop",
    "environments": [
        {
            "environmentId": "env1",
            "name": "production",
            "applications": [
                {"applicationId": "app1", "name": "web", "applicationStatus": "done"}
            ],
            "compose": [{"composeId": "cmp1", "name": "workers", "composeStatus": "error"}],
            "postgres": [
                {"postgresId": "pg1", "name": "main-db", "appName": "shop-pg-abc",
                 "applicationStatus": "done"}
            ],
            "redis": [
                {"redisId": "rd1", "name": "cache", "appName": "shop-redis-x",
                 "applicationStatus": "idle"}
            ],
        }
    ],
}


def centralized() -> list[dict[str, Any]]:
    return [
        {
            "deploymentId": "dep-old-ok",
            "title": "Manual deployment",
            "status": "done",
            "createdAt": iso(5000),
            "finishedAt": iso(4900),
            "applicationId": "app1",
            "composeId": None,
            "application": {"name": "web", "environment": {"project": {"name": "Shop"}}},
        },
        {
            "deploymentId": "dep-new-ok",
            "title": "Rebuild deployment",
            "status": "done",
            "createdAt": iso(600),
            "finishedAt": iso(590),
            "applicationId": "app1",
            "composeId": None,
            "application": {"name": "web", "environment": {"project": {"name": "Shop"}}},
        },
        {
            "deploymentId": "dep-ancient-err",
            "title": "Manual deployment",
            "status": "error",
            "createdAt": iso(86400),
            "finishedAt": iso(86300),
            "errorMessage": "old failure",
            "applicationId": None,
            "composeId": "cmp1",
            "compose": {"name": "workers", "environment": {"project": {"name": "Shop"}}},
        },
        {
            "deploymentId": "dep-recent-err",
            "title": "Manual deployment",
            "status": "error",
            "createdAt": iso(40),
            "finishedAt": iso(30),
            "errorMessage": "build failed: password=supersecret",
            "applicationId": None,
            "composeId": "cmp1",
            "compose": {"name": "workers", "environment": {"project": {"name": "Shop"}}},
        },
    ]


APPLICATION_ONE = {
    "applicationId": "app1",
    "name": "web",
    "appName": "shop-web-1a2b",
    "description": None,
    "applicationStatus": "done",
    "sourceType": "github",
    "buildType": "nixpacks",
    "createdAt": iso(9000),
    "env": "DATABASE_URL=postgres://u:topsecret@db/app",
    "buildArgs": "NPM_TOKEN=npm_secret_value",
    "environment": {
        "environmentId": "env1",
        "name": "production",
        "env": "ENV_SECRET=1",
        "project": {"projectId": "proj1", "name": "Shop", "env": "PROJECT_SECRET=hunter2"},
    },
    "domains": [
        {"domainId": "d1", "host": "shop.example.com", "path": "/", "https": True, "port": 3000},
        {"domainId": "d2", "host": "shop.example.com", "path": "/api", "https": True,
         "port": 3000},
    ],
    "deployments": [
        {"deploymentId": "dep-old-ok", "title": "Manual deployment", "status": "done",
         "createdAt": iso(5000), "finishedAt": iso(4900), "logPath": "/etc/dokploy/logs/x"},
        {"deploymentId": "dep-new-ok", "title": "Rebuild deployment", "status": "done",
         "createdAt": iso(600), "finishedAt": iso(590), "logPath": "/etc/dokploy/logs/y"},
    ],
    "github": {"githubId": "g1"},
    "server": None,
}

POSTGRES_ONE = {
    "postgresId": "pg1",
    "name": "main-db",
    "appName": "shop-pg-abc",
    "databasePassword": "pg-very-secret",
    "databaseUser": "shop",
    "dockerImage": "postgres:16",
    "applicationStatus": "done",
    "environment": {"environmentId": "env1", "name": "production",
                    "project": {"projectId": "proj1", "name": "Shop"}},
    "backups": [],
}


class FakeDokploy:
    """Minimal stand-in for Dokploy's /api/<router>.<procedure> surface."""

    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []
        self.online = True
        self.status_override: int | None = None
        self.old_version = False
        self.deployments = centralized()
        self.projects = json.loads(json.dumps(PROJECT_ALL))
        # procedure -> (status, json body): answer that procedure this way instead.
        self.overrides: dict[str, tuple[int, Any]] = {}
        # docs/48: env text written through saveEnvironment / compose.update.
        self.saved_env: dict[str, str] = {}

    def calls(self, procedure: str | None = None) -> list[httpx.Request]:
        if procedure is None:
            return list(self.requests)
        return [r for r in self.requests if r.url.path == f"/api/{procedure}"]

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if not self.online:
            raise httpx.ConnectError("refused", request=request)
        assert request.url.host == "dokploy.lan"
        if request.headers.get("x-api-key") != API_KEY:
            return httpx.Response(401, json={"message": "Unauthorized"})
        if self.status_override is not None:
            return httpx.Response(self.status_override, json={"message": "nope"})
        procedure = request.url.path.removeprefix("/api/")
        if procedure in self.overrides:
            status, payload = self.overrides[procedure]
            return httpx.Response(status, json=payload)
        query = dict(request.url.params)
        body = json.loads(request.content) if request.method == "POST" else None
        not_found = httpx.Response(404, json={"message": "Not found", "code": "NOT_FOUND"})
        gets: dict[str, Any] = {
            "settings.getDokployVersion": lambda: "v0.31.0",
            "project.all": lambda: self.projects,
            "project.one": lambda: PROJECT_ONE,
            "deployment.allCentralized": lambda: self.deployments,
            "domain.byApplicationId": lambda: APPLICATION_ONE["domains"],
            "domain.byComposeId": lambda: [{"host": "workers.example.com", "path": "/"}],
            "application.one": lambda: {**APPLICATION_ONE, **(
                {"env": self.saved_env["app1"]} if "app1" in self.saved_env else {})},
            "compose.one": lambda: {"composeId": "cmp1", "name": "devassist-s3",
                                    "composeStatus": "done", "domains": [],
                                    "env": self.saved_env.get("cmp1", "")},
            "postgres.one": lambda: POSTGRES_ONE,
            "deployment.readLogs": lambda: "step 1\nAuthorization: Bearer abc.def\nstep 3\n",
        }
        if self.old_version and procedure in {
            "deployment.allCentralized", "deployment.readLogs", "settings.getDokployVersion"
        }:
            return not_found
        if request.method == "GET" and procedure in gets:
            if procedure == "application.one" and query.get("applicationId") != "app1":
                return httpx.Response(404, json={"message": "Application not found",
                                                 "code": "NOT_FOUND"})
            if procedure == "deployment.readLogs" and query.get("deploymentId") == "missing":
                return httpx.Response(404, json={"message": "Deployment not found",
                                                 "code": "NOT_FOUND"})
            return httpx.Response(200, json=gets[procedure]())
        if request.method == "POST":
            assert request.headers["content-type"].startswith("application/json")
            router, _, action = procedure.partition(".")
            if procedure == "application.saveEnvironment":
                assert isinstance(body, dict) and body.get("applicationId") == "app1"
                assert "buildArgs" in body  # resent, never dropped
                self.saved_env["app1"] = body["env"]
                return httpx.Response(200, json=True)
            if procedure == "compose.update":
                assert isinstance(body, dict) and set(body) == {"composeId", "env"}
                self.saved_env[body["composeId"]] = body["env"]
                return httpx.Response(200, json=True)
            if action in {"deploy", "redeploy", "start", "stop", "reload"}:
                assert isinstance(body, dict)
                if router == "application" and body.get("applicationId") != "app1":
                    return httpx.Response(404, json={"message": "Application not found"})
                if action in {"deploy", "redeploy"} and router != "postgres":
                    return httpx.Response(200)  # Dokploy returns no body
                return httpx.Response(200, json={**APPLICATION_ONE, "returned": True})
        return not_found


@pytest.fixture
def fake(monkeypatch) -> FakeDokploy:
    state = FakeDokploy()
    monkeypatch.setattr(
        dokploy_client, "TRANSPORT_FACTORY", lambda: httpx.MockTransport(state.handler)
    )
    for name in ("MRK_DOKPLOY_URL", "MRK_DOKPLOY_API_KEY_FILE", "MRK_DOKPLOY_ALLOW_LOOPBACK",
                 "MRK_DOKPLOY_RATE_LIMIT_PER_SECOND", "MRK_DOKPLOY_CACHE_SECONDS"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("MRK_DOKPLOY_POLL_SECONDS", "0")
    return state


def configure(client: TestClient, headers: dict[str, str], **extra: Any) -> httpx.Response:
    body = {"url": PANEL, "api_key": API_KEY, "rate_limit_per_second": 20, **extra}
    return client.put("/api/v1/dokploy/config", headers=headers, json=body)


def owner_headers(client: TestClient) -> dict[str, str]:
    return {"X-CSRF-Token": str(login_owner(client)["csrf_token"])}


# ----- pure units --------------------------------------------------------------


def test_validate_dokploy_url() -> None:
    assert validate_dokploy_url("http://dokploy.lan:3000/") == "http://dokploy.lan:3000"
    assert validate_dokploy_url("https://10.0.0.5/api") == "https://10.0.0.5"
    assert validate_dokploy_url("https://example.com/dokploy/api/") == (
        "https://example.com/dokploy"
    )
    assert validate_dokploy_url("http://[fd00::1]:3000") == "http://[fd00::1]:3000"
    assert validate_dokploy_url("http://192.168.1.10:3000") == "http://192.168.1.10:3000"
    for bad in (
        "ftp://dokploy.lan", "http://user:pw@dokploy.lan", "http://dokploy.lan/?a=1",
        "http://dokploy.lan/#x", "http://", "http://169.254.169.254", "http://[fe80::1]",
        "http://127.0.0.1:3000", "http://localhost:3000", "http://0.0.0.0:3000",
        "http://[::ffff:127.0.0.1]", "http://a b", "http://h:99999", "javascript:alert(1)",
        "http://dokploy.lan/../x",
    ):
        with pytest.raises(ValueError):
            validate_dokploy_url(bad)
    assert validate_dokploy_url("http://127.0.0.1:3000", allow_loopback=True) == (
        "http://127.0.0.1:3000"
    )
    with pytest.raises(ValueError):
        validate_dokploy_url("http://169.254.169.254", allow_loopback=True)


def test_validate_api_key() -> None:
    assert validate_api_key(f"  {API_KEY}\n") == API_KEY
    for bad in ("short", "x" * 513, "has space in the middle of it", "tab\tinside-the-key-0000"):
        with pytest.raises(ValueError):
            validate_api_key(bad)


def test_token_bucket_waits_then_rejects() -> None:
    now = [100.0]
    slept: list[float] = []

    async def fake_sleep(seconds: float) -> None:
        slept.append(seconds)
        now[0] += seconds

    async def scenario() -> None:
        bucket = TokenBucket(2.0, clock=lambda: now[0], sleep=fake_sleep)
        assert await bucket.acquire(5) == 0.0
        assert await bucket.acquire(5) == 0.0  # burst of 2
        assert await bucket.acquire(5) == pytest.approx(0.5)
        with pytest.raises(DokployError) as info:
            await bucket.acquire(0.1)
        assert info.value.code == "dokploy_rate_limited" and info.value.status_code == 429
        now[0] += 10
        assert await bucket.acquire(0) == 0.0

    asyncio.run(scenario())
    assert slept == [pytest.approx(0.5)]


def test_normalize_project_tree_and_old_shape() -> None:
    latest = norm.latest_by_service(centralized())
    tree = norm.project_tree(
        PROJECT_ALL,
        details={"proj1": PROJECT_ONE},
        latest=latest,
        domains={("application", "app1"): ["shop.example.com"]},
    )
    assert len(tree) == 1
    project = tree[0]
    assert set(project) == {"id", "name", "description", "default_environment_id", "services"}
    assert project["id"] == "proj1" and project["description"] == "storefront"
    assert project["default_environment_id"] == "env1"
    by_id = {service["id"]: service for service in project["services"]}
    assert set(by_id) == {"app1", "cmp1", "pg1", "rd1"}  # libsql is outside the contract
    assert by_id["app1"] == {
        "id": "app1",
        "type": "application",
        "name": "web",
        "environment": "production",
        "environment_id": "env1",
        "status": "done",
        "domains": ["shop.example.com"],
        "last_deployment": {
            "status": "done",
            "created_at": latest[("application", "app1")]["createdAt"],
            "title": "Rebuild deployment",
        },
    }
    assert by_id["cmp1"]["status"] == "error"
    assert by_id["cmp1"]["last_deployment"]["status"] == "error"
    assert by_id["pg1"]["name"] == "main-db" and by_id["pg1"]["type"] == "postgres"
    assert by_id["rd1"]["status"] == "idle" and by_id["rd1"]["last_deployment"] is None
    assert "hunter2" not in json.dumps(tree)
    assert norm.services_missing_names(PROJECT_ALL[0]) is True

    # Pre-environment Dokploy: services directly on the project.
    old = [{"projectId": "p", "name": "Old", "applications": [
        {"applicationId": "a", "name": "api", "applicationStatus": "weird"}]}]
    old_tree = norm.project_tree(old)
    assert old_tree[0]["services"][0]["status"] == "unknown"
    assert old_tree[0]["services"][0]["environment"] is None
    assert old_tree[0]["services"][0]["environment_id"] is None
    assert old_tree[0]["default_environment_id"] is None

    # project.one outline keeps what the tree / appName index need and drops secrets.
    outline = norm.project_outline({**PROJECT_ONE, "env": "PROJECT_SECRET=hunter2"})
    assert "hunter2" not in json.dumps(outline)
    assert norm.project_tree(PROJECT_ALL, details={"proj1": outline}) == norm.project_tree(
        PROJECT_ALL, details={"proj1": PROJECT_ONE}
    )
    index: dict[str, Any] = {}
    norm.app_name_index(outline, index)
    assert index["shop-pg-abc"]["environment_id"] == "env1"


def test_normalize_service_detail_is_whitelisted() -> None:
    detail = norm.service_detail("application", "app1", APPLICATION_ONE)
    text = json.dumps(detail)
    for secret in ("topsecret", "npm_secret_value", "hunter2", "ENV_SECRET", "logPath"):
        assert secret not in text
    assert detail["project"] == {"id": "proj1", "name": "Shop"}
    assert detail["domains"] == ["shop.example.com", "shop.example.com/api"]
    assert [d["id"] for d in detail["deployments"]] == ["dep-new-ok", "dep-old-ok"]
    assert set(detail["deployments"][0]) == {
        "id", "status", "title", "created_at", "finished_at", "error_message"
    }
    db = norm.service_detail("postgres", "pg1", POSTGRES_ONE)
    assert "pg-very-secret" not in json.dumps(db)
    assert db["deployments"] == [] and db["docker_image"] == "postgres:16"


# ----- control-plane API ----------------------------------------------------------


def test_config_lifecycle_and_secret_handling(tmp_path: Path, fake: FakeDokploy, caplog) -> None:
    caplog.set_level(logging.DEBUG)
    app = create_app(Settings.for_test(tmp_path / "cp"))
    with TestClient(app) as client:
        assert client.get("/api/v1/dokploy/config").status_code == 401
        headers = owner_headers(client)
        view = client.get("/api/v1/dokploy/config").json()
        assert view["configured"] is False and view["source"] is None and view["url"] is None
        missing = client.get("/api/v1/dokploy/projects")
        assert missing.status_code == 409
        assert missing.json()["error"]["code"] == "dokploy_not_configured"
        assert client.post("/api/v1/dokploy/test", headers=headers).status_code == 409

        assert client.put(
            "/api/v1/dokploy/config", json={"url": PANEL, "api_key": API_KEY}
        ).status_code == 403  # CSRF
        for bad_url in ("ftp://x.lan", "http://u:p@dokploy.lan", "http://169.254.169.254",
                        "http://127.0.0.1:3000"):
            bad = client.put("/api/v1/dokploy/config", headers=headers,
                             json={"url": bad_url, "api_key": API_KEY})
            assert bad.status_code == 422, bad_url
        no_key = client.put("/api/v1/dokploy/config", headers=headers, json={"url": PANEL})
        assert no_key.status_code == 422
        assert no_key.json()["error"]["code"] == "dokploy_api_key_required"

        # Test candidate settings before saving them.
        candidate = client.post(
            "/api/v1/dokploy/test", headers=headers, json={"url": PANEL, "api_key": API_KEY}
        ).json()
        assert candidate["ok"] is True and candidate["version"] == "v0.31.0"
        wrong = client.post(
            "/api/v1/dokploy/test", headers=headers,
            json={"url": PANEL, "api_key": "w" * 40},
        ).json()
        assert wrong["ok"] is False and wrong["error_code"] == "dokploy_auth_failed"

        saved = configure(client, headers, cache_seconds=30)
        assert saved.status_code == 200, saved.text
        view = saved.json()
        assert view["configured"] is True and view["source"] == "panel"
        assert view["url"] == PANEL and view["api_key_configured"] is True
        assert view["cache_seconds"] == 30 and view["rate_limit_per_second"] == 20
        stored = (tmp_path / "cp" / "control-plane" / "dokploy.json").read_text()
        assert API_KEY not in stored and "secret_ref" in stored

        test = client.post("/api/v1/dokploy/test", headers=headers).json()
        assert test["ok"] is True and test["version"] == "v0.31.0" and test["latency_ms"] >= 0
        assert client.get("/api/v1/dokploy/config").json()["version"] == "v0.31.0"

        # URL-only update keeps the stored key.
        renamed = client.put("/api/v1/dokploy/config", headers=headers,
                             json={"url": PANEL + "/api"})
        assert renamed.status_code == 200 and renamed.json()["url"] == PANEL
        assert client.post("/api/v1/dokploy/test", headers=headers).json()["ok"] is True
        # A different panel URL never reuses the stored key.
        moved = client.put("/api/v1/dokploy/config", headers=headers,
                           json={"url": "http://elsewhere.lan:3000"})
        assert moved.status_code == 422
        assert moved.json()["error"]["code"] == "dokploy_api_key_required"
        probe = client.post("/api/v1/dokploy/test", headers=headers,
                            json={"url": "http://elsewhere.lan:3000"})
        assert probe.status_code == 422
        assert all(r.url.host == "dokploy.lan" for r in fake.calls())

        wrong_confirm = client.request("DELETE", "/api/v1/dokploy/config", headers=headers,
                                       json={"confirmation": "yes"})
        assert wrong_confirm.status_code == 422
        gone = client.request("DELETE", "/api/v1/dokploy/config", headers=headers,
                              json={"confirmation": "DISCONNECT"})
        assert gone.status_code == 200 and gone.json()["configured"] is False
        assert not (tmp_path / "cp" / "control-plane" / "dokploy.json").exists()

        audit = client.get("/api/v1/audit-events").json()
        actions = [item["action"] for item in audit.get("items", [])]
        assert {"dokploy.config.update", "dokploy.test", "dokploy.disconnect"} <= set(actions)
        assert API_KEY not in json.dumps(audit)

    assert all(r.headers["x-api-key"] in {API_KEY, "w" * 40} for r in fake.calls())
    assert API_KEY not in caplog.text


def test_projects_detail_cache_and_actions(tmp_path: Path, fake: FakeDokploy) -> None:
    app = create_app(Settings.for_test(tmp_path / "cp"))
    with TestClient(app) as client:
        headers = owner_headers(client)
        assert configure(client, headers).status_code == 200

        first = client.get("/api/v1/dokploy/projects")
        assert first.status_code == 200, first.text
        payload = first.json()
        assert payload["partial"] is False
        services = {s["id"]: s for s in payload["items"][0]["services"]}
        assert services["app1"]["domains"] == ["shop.example.com", "shop.example.com/api"]
        assert services["cmp1"]["domains"] == ["workers.example.com"]
        assert services["pg1"]["name"] == "main-db"
        assert "hunter2" not in first.text
        assert len(fake.calls("project.one")) == 1
        count = len(fake.calls())

        # Cached: no further Dokploy traffic.
        assert client.get("/api/v1/dokploy/projects").json() == payload
        assert len(fake.calls()) == count

        detail = client.get("/api/v1/dokploy/services/application/app1")
        assert detail.status_code == 200
        assert "topsecret" not in detail.text and "npm_secret_value" not in detail.text
        assert detail.json()["deployments"][0]["id"] == "dep-new-ok"
        client.get("/api/v1/dokploy/services/application/app1")
        assert len(fake.calls("application.one")) == 1

        db = client.get("/api/v1/dokploy/services/postgres/pg1")
        assert db.status_code == 200 and "pg-very-secret" not in db.text

        assert client.get("/api/v1/dokploy/services/application/nope").status_code == 404
        assert client.get("/api/v1/dokploy/services/libsql/x").status_code == 422
        assert client.get("/api/v1/dokploy/services/application/bad%20id").status_code == 422

        # Actions need CSRF.
        assert client.post("/api/v1/dokploy/services/application/app1/deploy").status_code == 403
        deployed = client.post("/api/v1/dokploy/services/application/app1/deploy",
                               headers=headers)
        assert deployed.status_code == 200 and deployed.json() == {"ok": True}
        sent = fake.calls("application.deploy")[-1]
        assert sent.method == "POST"
        assert json.loads(sent.content)["applicationId"] == "app1"

        # Cache invalidated after the action.
        before = len(fake.calls("project.all"))
        client.get("/api/v1/dokploy/projects")
        assert len(fake.calls("project.all")) == before + 1

        assert client.post("/api/v1/dokploy/services/compose/cmp1/redeploy",
                           headers=headers).json() == {"ok": True}
        assert client.post("/api/v1/dokploy/services/application/app1/start",
                           headers=headers).json() == {"ok": True}

        # Stop requires the exact service name.
        no_confirm = client.post("/api/v1/dokploy/services/application/app1/stop",
                                 headers=headers)
        assert no_confirm.status_code == 422
        assert no_confirm.json()["error"]["code"] == "confirmation_required"
        bad_confirm = client.post("/api/v1/dokploy/services/application/app1/stop",
                                  headers=headers, json={"confirmation": "WEB"})
        assert bad_confirm.status_code == 422
        assert not fake.calls("application.stop")
        stopped = client.post("/api/v1/dokploy/services/application/app1/stop",
                              headers=headers, json={"confirmation": "web"})
        assert stopped.status_code == 200 and stopped.json() == {"ok": True}
        assert "topsecret" not in stopped.text
        assert len(fake.calls("application.stop")) == 1

        # Database redeploy maps to the non-destructive reload with appName.
        assert client.post("/api/v1/dokploy/services/postgres/pg1/redeploy",
                           headers=headers).json() == {"ok": True}
        reload_body = json.loads(fake.calls("postgres.reload")[-1].content)
        assert reload_body == {"postgresId": "pg1", "appName": "shop-pg-abc"}
        assert not fake.calls("postgres.rebuild")

        assert client.post("/api/v1/dokploy/services/application/app1/delete",
                           headers=headers).status_code == 422
        missing = client.post("/api/v1/dokploy/services/application/nope/deploy",
                              headers=headers)
        assert missing.status_code == 404

        audit = client.get("/api/v1/audit-events?limit=200").json()
        records = [(i["action"], i.get("result")) for i in audit.get("items", [])]
        actions = [action for action, _result in records]
        for expected in ("dokploy.service.deploy", "dokploy.service.redeploy",
                         "dokploy.service.start", "dokploy.service.stop"):
            assert expected in actions
        assert ("dokploy.service.stop", "failure") in records


def test_s3_dashboard_discovers_and_redeploys_compose(
    tmp_path: Path, fake: FakeDokploy
) -> None:
    fake.projects[0]["environments"][0]["compose"][0]["name"] = "devassist-s3"
    app = create_app(Settings.for_test(tmp_path / "cp"))
    with TestClient(app) as client:
        headers = owner_headers(client)
        assert configure(client, headers).status_code == 200

        state = client.get("/api/v1/s3/dokploy", headers=headers)
        assert state.status_code == 200, state.text
        # A name match is only a suggestion: it is never redeployed before it is saved.
        assert state.json()["target"] is None
        suggestion = state.json()["suggestion"]
        assert suggestion["compose_id"] == "cmp1" and suggestion["source"] == "name"
        assert "x-api-key" not in state.text.lower() and API_KEY not in state.text

        refused = client.post("/api/v1/s3/dokploy/redeploy", headers=headers, json={})
        assert refused.status_code == 409, refused.text
        assert refused.json()["error"]["code"] == "s3_dokploy_target_required"
        assert not fake.calls("compose.redeploy")

        saved = client.put("/api/v1/s3/dokploy", headers=headers, json={"compose_id": "cmp1"})
        assert saved.status_code == 200, saved.text
        assert saved.json()["target"]["source"] == "saved"
        assert client.get("/api/v1/s3/dokploy", headers=headers).json()["target"][
            "source"] == "saved"

        deployed = client.post("/api/v1/s3/dokploy/redeploy", headers=headers, json={})
        assert deployed.status_code == 200, deployed.text
        assert deployed.json()["target"]["compose_id"] == "cmp1"
        sent = fake.calls("compose.redeploy")[-1]
        assert json.loads(sent.content) == {
            "composeId": "cmp1",
            "title": "Redeploy from DevAssist",
        }
        audit = client.get("/api/v1/audit-events?limit=200").json()["items"]
        records = {(i["action"], i.get("result"), i.get("object_type"), i.get("object_id"))
                   for i in audit}
        assert ("dokploy.service.redeploy", "failure", "dokploy", "compose") in records
        assert ("dokploy.service.redeploy", "success", "dokploy", "compose:cmp1") in records
        assert ("s3.dokploy_target.update", "success", "dokploy", "compose:cmp1") in records


def test_deployment_log_and_feature_detection(tmp_path: Path, fake: FakeDokploy) -> None:
    app = create_app(Settings.for_test(tmp_path / "cp"))
    with TestClient(app) as client:
        headers = owner_headers(client)
        assert configure(client, headers).status_code == 200
        log = client.get("/api/v1/dokploy/deployments/dep-new-ok/log?tail=50").json()
        assert log["available"] is True and log["lines"][0] == "step 1"
        assert "abc.def" not in json.dumps(log)
        sent = fake.calls("deployment.readLogs")[-1]
        assert sent.url.params["tail"] == "50"
        assert client.get("/api/v1/dokploy/deployments/missing/log").status_code == 404
        assert client.get("/api/v1/dokploy/deployments/a.b/log").status_code == 422

        fake.old_version = True
        dokploy.ACTIVE_SERVICE.reset()
        old = client.get("/api/v1/dokploy/deployments/dep-new-ok/log").json()
        assert old == {"available": False, "lines": [], "truncated": False}
        tree = client.get("/api/v1/dokploy/projects").json()
        assert all(s["last_deployment"] is None for s in tree["items"][0]["services"])
        test = client.post("/api/v1/dokploy/test", headers=headers).json()
        assert test["ok"] is True and "version" not in test


def test_error_mapping(tmp_path: Path, fake: FakeDokploy) -> None:
    app = create_app(Settings.for_test(tmp_path / "cp"))
    with TestClient(app) as client:
        headers = owner_headers(client)
        assert configure(client, headers, cache_seconds=0).status_code == 200

        fake.status_override = 401
        failed = client.get("/api/v1/dokploy/projects")
        assert failed.status_code == 502
        assert failed.json()["error"]["code"] == "dokploy_auth_failed"
        assert "nope" in failed.json()["error"]["message"]  # Dokploy's own words are kept
        assert API_KEY not in failed.text

        fake.status_override = 429
        limited = client.get("/api/v1/dokploy/projects")
        assert limited.status_code == 429
        assert limited.json()["error"]["code"] == "dokploy_rate_limited"

        fake.status_override = 302
        assert client.get("/api/v1/dokploy/projects").json()["error"]["code"] == (
            "dokploy_unreachable"
        )
        fake.status_override = 500
        broken = client.get("/api/v1/dokploy/projects")
        assert broken.status_code == 502
        assert broken.json()["error"]["code"] == "dokploy_failed"
        assert broken.json()["error"]["message"] == "Dokploy returned HTTP 500: nope"
        # Dokploy answered, so the connection itself is fine.
        assert client.get("/api/v1/dokploy/config").json()["reachable"] is True

        fake.status_override = None
        fake.online = False
        down = client.get("/api/v1/dokploy/projects")
        assert down.status_code == 502 and down.json()["error"]["code"] == "dokploy_unreachable"
        view = client.get("/api/v1/dokploy/config").json()
        # One failure is a blip: reported, but not yet "unreachable".
        assert view["reachable"] is True and view["last_error_code"] == "dokploy_unreachable"
        assert view["last_error"].startswith("Dokploy is unreachable")
        client.get("/api/v1/dokploy/projects")
        assert client.get("/api/v1/dokploy/config").json()["reachable"] is False

        fake.online = True
        back = client.get("/api/v1/dokploy/projects")
        assert back.status_code == 200
        # The health comes with the list, so the page needs no second round trip.
        assert back.json()["reachable"] is True and back.json()["last_error"] is None
        assert back.json()["last_error_code"] is None
        assert client.get("/api/v1/dokploy/config").json()["last_error"] is None

        # MRK-side rate limit protects Dokploy: an exhausted bucket answers 429 at once.
        fake.online = True
        service = dokploy.ACTIVE_SERVICE
        service.client.bucket = TokenBucket(0.01, burst=1)
        service.client.max_wait_seconds = 0
        service.client.set_rate = lambda _rate: None  # keep the tiny bucket for this test
        assert client.get("/api/v1/dokploy/services/application/app1").status_code == 200
        before = len(fake.calls())
        throttled = client.get("/api/v1/dokploy/services/postgres/pg1")
        assert throttled.status_code == 429
        assert throttled.json()["error"]["code"] == "dokploy_rate_limited"
        assert len(fake.calls()) == before


def test_poller_events(tmp_path: Path, fake: FakeDokploy) -> None:
    app = create_app(Settings.for_test(tmp_path / "cp"))
    events: list[Any] = []
    with TestClient(app) as client:
        async def collect(event) -> None:
            events.append(event)

        app.state.events.subscribe(collect)
        headers = owner_headers(client)
        assert configure(client, headers, cache_seconds=0).status_code == 200
        service = dokploy.ACTIVE_SERVICE

        def poll() -> None:
            try:
                client.portal.call(service.poll_once, 60.0)
            except DokployError as exc:  # the background loop logs and retries
                assert exc.code == "dokploy_unreachable"
            client.portal.call(asyncio.sleep, 0.05)

        poll()
        failed = [e for e in events if e.type == "dokploy.deploy_failed"]
        # Only the recent failure is reported after start; the day-old one is history.
        assert [e.details["deployment_id"] for e in failed] == ["dep-recent-err"]
        assert failed[0].severity == "error"
        assert failed[0].dedupe_key == "dokploy.deploy_failed:dep-recent-err"
        assert "supersecret" not in failed[0].message
        assert failed[0].details["service_name"] == "workers"

        poll()  # same data: nothing new
        assert len([e for e in events if e.type == "dokploy.deploy_failed"]) == 1

        fake.deployments.append({
            "deploymentId": "dep-next-err", "title": "Webhook", "status": "error",
            "createdAt": iso(5), "applicationId": "app1",
            "application": {"name": "web"},
        })
        poll()
        ids = [e.details["deployment_id"] for e in events if e.type == "dokploy.deploy_failed"]
        assert ids == ["dep-recent-err", "dep-next-err"]

        fake.online = False
        poll()
        poll()
        fake.online = True
        poll()
        reach = [e.type for e in events if e.type.startswith("dokploy.") and "reach" in e.type]
        assert reach == ["dokploy.unreachable", "dokploy.reachable"]
        assert all(
            e.dedupe_key == "dokploy.reachability"
            for e in events if e.type in {"dokploy.unreachable", "dokploy.reachable"}
        )

        # Old Dokploy without allCentralized: fall back to service status transitions.
        fake.old_version = True
        service.reset()
        poll()  # seeds (cmp1 already in error)
        fake.projects[0]["environments"][0]["applications"][0]["applicationStatus"] = "error"
        poll()
        fallback = [e for e in events if e.type == "dokploy.deploy_failed"
                    and e.dedupe_key.startswith("dokploy.deploy_failed:application:")]
        assert len(fallback) == 1 and fallback[0].details["service_id"] == "app1"


def test_env_config_wins(tmp_path: Path, fake: FakeDokploy, monkeypatch) -> None:
    key_file = tmp_path / "dokploy.key"
    key_file.write_text(API_KEY + "\n")
    monkeypatch.setenv("MRK_DOKPLOY_URL", PANEL)
    monkeypatch.setenv("MRK_DOKPLOY_API_KEY_FILE", str(key_file))
    app = create_app(Settings.for_test(tmp_path / "cp"))
    with TestClient(app) as client:
        headers = owner_headers(client)
        view = client.get("/api/v1/dokploy/config").json()
        assert view["source"] == "env" and view["configured"] is True
        assert API_KEY not in json.dumps(view)
        blocked = configure(client, headers)
        assert blocked.status_code == 409
        assert blocked.json()["error"]["code"] == "dokploy_managed_by_environment"
        assert client.request("DELETE", "/api/v1/dokploy/config", headers=headers,
                              json={"confirmation": "DISCONNECT"}).status_code == 409
        assert client.get("/api/v1/dokploy/projects").status_code == 200


def _login_as(client: TestClient, owner_csrf: str, role: str) -> dict[str, str]:
    username = f"{role}1"
    password = f"a-long-{role}-password-123"
    created = client.post(
        "/api/v1/users",
        headers={"X-CSRF-Token": owner_csrf},
        json={"username": username, "password": password, "role": role},
    )
    assert created.status_code == 201, created.text
    session = client.post("/api/v1/auth/login", json={"username": username,
                                                       "password": password}).json()
    return {"X-CSRF-Token": str(session["csrf_token"])}


def test_rbac(tmp_path: Path, fake: FakeDokploy) -> None:
    app = create_app(Settings.for_test(tmp_path / "cp"))
    has_dokploy_permissions = "dokploy:read" in ROLE_PERMISSIONS["admin"]
    with TestClient(app) as client:
        owner_csrf = owner_headers(client)["X-CSRF-Token"]
        assert configure(client, {"X-CSRF-Token": owner_csrf}).status_code == 200
        roles = ["viewer"] + (["admin", "operator", "developer"] if has_dokploy_permissions
                              else [])
        for role in roles:
            client.cookies.clear()
            owner_csrf = owner_headers(client)["X-CSRF-Token"]
            headers = _login_as(client, owner_csrf, role)
            expected = {
                # role: (read, deploy, write)
                "viewer": (False, False, False),
                "developer": (True, False, False),
                "operator": (True, True, False),
                "admin": (True, True, True),
            }[role]
            read = client.get("/api/v1/dokploy/projects").status_code
            assert (read == 200) is expected[0], (role, read)
            assert (client.get("/api/v1/dokploy/config").status_code == 200) is expected[0]
            deploy = client.post("/api/v1/dokploy/services/application/app1/deploy",
                                 headers=headers).status_code
            assert (deploy == 200) is expected[1], (role, deploy)
            write = client.post("/api/v1/dokploy/test", headers=headers).status_code
            assert (write == 200) is expected[2], (role, write)
            if not expected[2]:
                assert configure(client, headers).status_code == 403


# ----- harmony with Dokploy v0.31 ---------------------------------------------------


def test_upstream_error_shapes_and_mapping() -> None:
    parse = dokploy_client.parse_upstream_error
    assert parse(b'{"message": "Service not found"}') == ("Service not found", None)
    zod = json.dumps({"message": "Input validation failed", "issues": [
        {"path": ["composeId"], "message": "Required"}, {"path": [], "message": "Bad"}]})
    assert parse(zod.encode())[0] == "Input validation failed: composeId: Required; Bad"
    envelope = json.dumps({"error": {"json": {"message": "Compose not found", "data": {
        "code": "NOT_FOUND", "httpStatus": 404}}}})
    assert parse(envelope.encode()) == ("Compose not found", "NOT_FOUND")
    assert parse(b'{"error": {"message": "boom"}}') == ("boom", None)
    assert parse(b"<html>") == ("", None)
    assert "hunter2" not in parse(b'{"message": "failed: password=hunter2"}')[0]

    mapped = dokploy_client.DokployClient._map_status  # noqa: SLF001
    gone = mapped(400, b'{"message": "Service not found"}')
    assert gone.code == "dokploy_not_found" and gone.status_code == 404
    assert not gone.procedure_missing and gone.message == "Service not found"
    assert mapped(400, envelope.encode()).code == "dokploy_not_found"
    missing = mapped(404, b'{"message": "Not found", "code": "NOT_FOUND"}')
    assert missing.procedure_missing and missing.code == "dokploy_not_found"
    rejected = mapped(400, zod.encode())
    assert rejected.code == "dokploy_rejected" and "composeId: Required" in rejected.message
    # A known key refused one resource is not "the key was rejected".
    refused = mapped(401, b'{"message": "You are not authorized to access this project"}')
    assert refused.code == "dokploy_forbidden" and "not authorized" in refused.message
    assert mapped(401, b'{"message": "Unauthorized"}').code == "dokploy_auth_failed"
    assert mapped(401, b'{"message": "You are not authorized"}', probe=True).code == (
        "dokploy_auth_failed"
    )
    assert mapped(403, b'{"message": "Permission denied"}').code == "dokploy_forbidden"
    server = mapped(500, b'{"message": "column x does not exist"}')
    assert server.code == "dokploy_failed" and server.message.endswith("column x does not exist")
    assert not server.connection_failure and mapped(302, b"").connection_failure


class _Records(logging.Handler):
    def __init__(self) -> None:
        super().__init__(logging.DEBUG)
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)


def test_one_failed_procedure_is_not_an_outage(tmp_path: Path, fake: FakeDokploy) -> None:
    app = create_app(Settings.for_test(tmp_path / "cp"))
    captured = _Records()
    client_logger = logging.getLogger(dokploy_client.__name__)
    client_logger.addHandler(captured)
    client_logger.setLevel(logging.INFO)
    events: list[Any] = []
    with TestClient(app) as client:
        async def collect(event) -> None:
            events.append(event)

        app.state.events.subscribe(collect)
        headers = owner_headers(client)
        assert configure(client, headers, cache_seconds=0).status_code == 200
        assert client.get("/api/v1/dokploy/projects").status_code == 200

        # Item procedures failing (500, forbidden) leave Dokploy reachable and quiet.
        fake.overrides["application.one"] = (500, {"message": "db hiccup"})
        broken = client.get("/api/v1/dokploy/services/application/app1")
        assert broken.status_code == 502 and broken.json()["error"]["code"] == "dokploy_failed"
        fake.overrides["application.one"] = (401, {"message": "You are not authorized"})
        refused = client.get("/api/v1/dokploy/services/application/app1")
        assert refused.json()["error"]["code"] == "dokploy_forbidden"
        view = client.get("/api/v1/dokploy/config").json()
        assert view["reachable"] is True and view["last_error"] is None
        client.portal.call(asyncio.sleep, 0.05)
        assert not [e for e in events if "reach" in e.type]
        # One INFO line per non-2xx answer, with Dokploy's words but never the key.
        lines = [r for r in captured.records
                 if r.getMessage() == "dokploy answered with an error"]
        assert any(getattr(r, "procedure", "") == "application.one"
                   and getattr(r, "upstream_message", "") == "db hiccup" for r in lines)
        assert all(API_KEY not in str(r.__dict__) for r in captured.records)

        # Removed in Dokploy: v0.31 answers HTTP 400 "Service not found".
        fake.overrides["application.one"] = (400, {"message": "Service not found"})
        gone = client.get("/api/v1/dokploy/services/application/app1")
        assert gone.status_code == 404
        assert gone.json()["error"]["code"] == "dokploy_service_not_found"
        fake.overrides["compose.deploy"] = (400, {"message": "Compose not found"})
        action = client.post("/api/v1/dokploy/services/compose/cmp1/deploy", headers=headers)
        assert action.status_code == 404
        assert action.json()["error"]["code"] == "dokploy_service_not_found"

        # Test returns Dokploy's reason with the code.
        fake.overrides["settings.getDokployVersion"] = (401, {"message": "Invalid API key"})
        tested = client.post("/api/v1/dokploy/test", headers=headers).json()
        assert tested["ok"] is False and tested["error_code"] == "dokploy_auth_failed"
        assert "Invalid API key" in tested["message"]
        fake.overrides.clear()

        # Two connection failures in a row are an outage, announced once; then recovery.
        fake.online = False
        for _ in range(3):
            client.get("/api/v1/dokploy/projects")
        fake.online = True
        assert client.get("/api/v1/dokploy/projects").status_code == 200
        client.portal.call(asyncio.sleep, 0.05)
        assert [e.type for e in events if "reach" in e.type] == [
            "dokploy.unreachable", "dokploy.reachable"
        ]
    client_logger.removeHandler(captured)


def test_failure_notifications_survive_restart(tmp_path: Path, fake: FakeDokploy) -> None:
    def run(collect_into: list[Any], configure_first: bool) -> None:
        app = create_app(Settings.for_test(tmp_path / "cp"))
        with TestClient(app) as client:
            async def collect(event) -> None:
                collect_into.append(event)

            app.state.events.subscribe(collect)
            headers = owner_headers(client) if configure_first else None
            if headers is not None:
                assert configure(client, headers, cache_seconds=0).status_code == 200
            client.portal.call(dokploy.ACTIVE_SERVICE.poll_once, 60.0)
            client.portal.call(asyncio.sleep, 0.05)

    first: list[Any] = []
    run(first, True)
    assert [e.details["deployment_id"] for e in first if e.type == "dokploy.deploy_failed"] == [
        "dep-recent-err"
    ]
    state = json.loads((tmp_path / "cp" / "control-plane" / "dokploy-state.json").read_text())
    assert "dep-recent-err" in state["seen_failures"]

    fake.deployments.append({
        "deploymentId": "dep-while-down", "status": "error", "createdAt": iso(10),
        "composeId": "cmp1", "compose": {"name": "workers"},
    })
    second: list[Any] = []
    run(second, False)  # a restart: same data dir, config already saved
    failed = [e.details["deployment_id"] for e in second if e.type == "dokploy.deploy_failed"]
    assert failed == ["dep-while-down"]  # only the new failure, not dep-recent-err again


def test_links_public_url_and_routing_invalidation(
    tmp_path: Path, fake: FakeDokploy, monkeypatch
) -> None:
    from mrk_control_plane.modules import services as services_module

    invalidated: list[int] = []

    class Routing:
        def invalidate(self) -> None:
            invalidated.append(1)

    class Active:
        routing = Routing()

    app = create_app(Settings.for_test(tmp_path / "cp"))
    with TestClient(app) as client:
        monkeypatch.setattr(services_module, "ACTIVE_SERVICE", Active())
        headers = owner_headers(client)
        view = configure(client, headers).json()
        assert invalidated, "saving the Dokploy config re-checks domain routing"
        assert view["panel_url"] == PANEL and view["public_url"] is None

        bad = configure(client, headers, public_url="ftp://x.lan")
        assert bad.status_code == 422
        assert bad.json()["error"]["code"] == "invalid_dokploy_public_url"
        view = configure(client, headers, public_url="https://dokploy.example.com/").json()
        assert view["public_url"] == "https://dokploy.example.com"
        assert view["panel_url"] == "https://dokploy.example.com" and view["url"] == PANEL
        # A save without public_url keeps it; "" clears it.
        kept = client.put("/api/v1/dokploy/config", headers=headers, json={"url": PANEL})
        assert kept.json()["public_url"] == "https://dokploy.example.com"

        tree = client.get("/api/v1/dokploy/projects").json()
        project = tree["items"][0]
        assert project["url"] == (
            "https://dokploy.example.com/dashboard/project/proj1/environment/env1"
        )
        services = {s["id"]: s for s in project["services"]}
        assert services["cmp1"]["url"] == (
            "https://dokploy.example.com/dashboard/project/proj1/environment/env1"
            "/services/compose/cmp1"
        )
        assert all(r.url.host == "dokploy.lan" for r in fake.calls())  # API stays internal

        cleared = configure(client, headers, public_url="").json()
        assert cleared["public_url"] is None and cleared["panel_url"] == PANEL


def test_project_one_is_cached_and_budgeted(tmp_path: Path, fake: FakeDokploy) -> None:
    app = create_app(Settings.for_test(tmp_path / "cp"))
    with TestClient(app) as client:
        headers = owner_headers(client)
        assert configure(client, headers, cache_seconds=0).status_code == 200
        for _ in range(3):
            assert client.get("/api/v1/dokploy/projects").status_code == 200
        index = client.portal.call(dokploy.ACTIVE_SERVICE.app_index)
        assert index["shop-pg-abc"]["id"] == "pg1"
        # Page loads and the appName index share one cached (secret-free) project.one.
        assert len(fake.calls("project.one")) == 1
        cached = dokploy.ACTIVE_SERVICE.cache.get("project-one:proj1")
        assert "hunter2" not in json.dumps(cached)
    assert dokploy.APP_INDEX_PROJECT_BUDGET <= 10


def test_background_calls_yield_to_page_loads() -> None:
    now = [0.0]

    async def fake_sleep(seconds: float) -> None:
        now[0] += seconds

    async def scenario() -> None:
        bucket = TokenBucket(2.0, clock=lambda: now[0], sleep=fake_sleep)
        # Full bucket (2): background may take one and leaves one for a page load.
        assert await bucket.acquire_background(10) == 0.0
        assert await bucket.acquire(0) == 0.0
        # Empty: background waits for spare capacity instead of reserving a slot.
        waited = await bucket.acquire_background(10)
        assert waited > 0
        with pytest.raises(DokployError) as info:
            await bucket.acquire_background(0.01)
        assert info.value.code == "dokploy_rate_limited"

    asyncio.run(scenario())


def test_container_labels_map_to_dokploy_services() -> None:
    from mrk_control_plane.agent.docker_client import labels_subset

    stack = {
        "com.docker.stack.namespace": "devassist-mrkpanel-x1",
        "com.docker.swarm.service.name": "devassist-mrkpanel-x1_mrk-panel",
        "traefik.http.middlewares.auth.basicauth.users": "admin:$apr1$secret",
    }
    subset = labels_subset(stack, ())
    assert subset["com.docker.stack.namespace"] == "devassist-mrkpanel-x1"
    assert "traefik.http.middlewares.auth.basicauth.users" not in subset
    assert dokploy.app_name_candidates(subset)[0] == "devassist-mrkpanel-x1"
    index = {"devassist-mrkpanel-x1": {"type": "compose", "id": "c1"}}
    assert dokploy.ref_for_labels(subset, index) == {"type": "compose", "id": "c1"}
    # Without the namespace label the swarm name's prefix still finds it.
    older = {"com.docker.swarm.service.name": "devassist-mrkpanel-x1_mrk-panel"}
    assert dokploy.ref_for_labels(older, index) == {"type": "compose", "id": "c1"}
    plain = {"com.docker.compose.project": "shop-workers-9z"}
    assert dokploy.app_name_candidates(plain) == ["shop-workers-9z"]
