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
            "application.one": lambda: APPLICATION_ONE,
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
    assert set(project) == {"id", "name", "description", "services"}
    assert project["id"] == "proj1" and project["description"] == "storefront"
    by_id = {service["id"]: service for service in project["services"]}
    assert set(by_id) == {"app1", "cmp1", "pg1", "rd1"}  # libsql is outside the contract
    assert by_id["app1"] == {
        "id": "app1",
        "type": "application",
        "name": "web",
        "environment": "production",
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
        assert client.get("/api/v1/dokploy/projects").status_code == 502

        fake.status_override = None
        fake.online = False
        down = client.get("/api/v1/dokploy/projects")
        assert down.status_code == 502 and down.json()["error"]["code"] == "dokploy_unreachable"
        assert client.get("/api/v1/dokploy/config").json()["reachable"] is False

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
