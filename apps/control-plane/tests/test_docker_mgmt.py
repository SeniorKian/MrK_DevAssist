"""Gate 17 Docker management + container logs (control-plane side, docs/29 §3)."""

from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs

import httpx
import pytest
from fastapi.testclient import TestClient
from mrk_control_plane.agent import signing
from mrk_control_plane.config import Settings
from mrk_control_plane.main import create_app
from mrk_control_plane.modules import host_agent, host_agent_docker
from mrk_control_plane.modules.host_agent_docker import (
    JobLimitError,
    JobRegistry,
    LogFilterError,
    build_line_filter,
)

from .helpers import login_owner

KEY = bytes(range(32))
KEY_TEXT = signing.encode_key(KEY)
PASSWORD = "a-long-role-password-123"  # noqa: S105 - test-only fixture
PLAN_TOKEN = "a" * 64
PROTECTED_ID = "p" * 12 + "0" * 52
APP_ID = "b" * 64

CONTAINERS = [
    {"id": PROTECTED_ID, "name": "dokploy-postgres", "protected": True, "state": "running"},
    {"id": APP_ID, "name": "app-web", "protected": False, "state": "running"},
]
LOG_LINES = [
    {"ts": "2026-11-08T10:00:00Z", "stream": "stdout", "text": "GET / 200"},
    {"ts": "2026-11-08T10:00:01Z", "stream": "stderr", "text": "db password=hunter2 failed"},
    {"ts": "2026-11-08T10:00:02Z", "stream": "stdout", "text": "Authorization: Bearer abc.def"},
    {"ts": "2026-11-08T10:00:03Z", "stream": "stdout", "text": "ERROR worker crashed"},
]


class FakeAgent:
    """Implements the docs/29 §2 agent contract and verifies every signature."""

    def __init__(self) -> None:
        self.verifier = signing.RequestVerifier(KEY)
        self.seen: list[tuple[str, str, Any]] = []
        self.stream_delay = 0.0
        self.stream_forever = False
        self.stream_closed = False
        self.agent_protected = {PROTECTED_ID}

    async def handler(self, request: httpx.Request) -> httpx.Response:
        body = await request.aread()
        raw_path = request.url.raw_path.decode()
        self.verifier.verify(request.method, raw_path, request.headers, body)
        payload = json.loads(body) if body else None
        path = request.url.path
        self.seen.append((request.method, path, payload))
        query = {key: values[0] for key, values in parse_qs(request.url.query.decode()).items()}
        if path == "/v1/info":
            return httpx.Response(
                200,
                json={"version": "1", "capabilities": {"docker": True}, "docker": {},
                      "host": {"hostname": "node", "cpu_count": 4}},
            )
        if path == "/v1/docker/containers":
            return httpx.Response(200, json={"items": CONTAINERS})
        if request.method == "POST" and path.startswith("/v1/docker/containers/"):
            container_id, action = path.split("/")[4:6]
            item = next((c for c in CONTAINERS if c["id"] == container_id), None)
            if item is None or action not in ("start", "stop", "restart"):
                return httpx.Response(404, json={"error": "not_found"})
            if item["id"] in self.agent_protected and not payload.get("allow_protected"):
                return httpx.Response(403, json={"error": "protected"})
            return httpx.Response(200, json={"ok": True})
        if path == "/v1/docker/images/pull":
            if payload["image"].startswith("broken/"):
                return httpx.Response(422, json={"error": "invalid_image"})
            return httpx.Response(200, json={"ok": True, "digest": "sha256:" + "d" * 64})
        if path == "/v1/docker/prune/preview":
            return httpx.Response(
                200,
                json={"token": PLAN_TOKEN, "containers": [], "images": [
                    {"id": "sha256:1", "tags": [], "size_bytes": 1234}], "networks": [],
                    "build_cache_bytes": 0, "reclaimable_bytes": 1234},
            )
        if path == "/v1/docker/prune":
            if payload["token"] != PLAN_TOKEN:
                return httpx.Response(409, json={"error": "plan_changed"})
            return httpx.Response(
                200,
                json={"removed": {"containers": 0, "images": 1, "networks": 0},
                      "reclaimed_bytes": 1234, "errors": []},
            )
        if path.endswith("/logs"):
            if "missing" in path:
                return httpx.Response(404, json={"error": "not_found"})
            if query.get("follow") == "1":
                return httpx.Response(
                    200,
                    headers={"content-type": "application/x-ndjson"},
                    content=self._ndjson(),
                )
            return httpx.Response(200, json={"lines": LOG_LINES, "truncated": False})
        return httpx.Response(404, json={"error": "not_found"})

    async def _ndjson(self):
        try:
            for line in LOG_LINES:
                if self.stream_delay:
                    await asyncio.sleep(self.stream_delay)
                yield (json.dumps(line) + "\n").encode()
            yield b"not json\n"
            while self.stream_forever:
                await asyncio.sleep(0.05)
        finally:
            self.stream_closed = True


@pytest.fixture
def agent(monkeypatch) -> FakeAgent:
    fake = FakeAgent()
    monkeypatch.setattr(
        host_agent, "TRANSPORT_FACTORY", lambda: httpx.MockTransport(fake.handler)
    )
    monkeypatch.delenv("MRK_AGENT_URL", raising=False)
    monkeypatch.delenv("MRK_AGENT_KEY_FILE", raising=False)
    return fake


def paired_client(tmp_path: Path) -> tuple[TestClient, dict[str, str]]:
    app = create_app(Settings.for_test(tmp_path / "cp"))
    client = TestClient(app)
    client.__enter__()
    headers = {"X-CSRF-Token": str(login_owner(client)["csrf_token"])}
    paired = client.put(
        "/api/v1/agent/config",
        headers=headers,
        json={"url": "http://mrk-agent:7070", "key": KEY_TEXT},
    )
    assert paired.status_code == 200, paired.text
    return client, headers


def role_client(owner: TestClient, owner_headers: dict[str, str], role: str):
    created = owner.post(
        "/api/v1/users",
        headers=owner_headers,
        json={"username": f"{role}1", "password": PASSWORD, "role": role},
    )
    assert created.status_code == 201, created.text
    client = TestClient(owner.app)
    login = client.post("/api/v1/auth/login", json={"username": f"{role}1", "password": PASSWORD})
    assert login.status_code == 200
    return client, {"X-CSRF-Token": str(login.json()["csrf_token"])}


def audit_actions(client: TestClient) -> list[tuple[str, str | None, str]]:
    items = client.get("/api/v1/audit-events", params={"limit": 500}).json()["items"]
    return [(item["action"], item["object_id"], item["result"]) for item in items]


# ----- RBAC / CSRF -------------------------------------------------------------


ACTION_BODY = {"action": "restart"}
PRUNE_BODY = {"token": PLAN_TOKEN, "targets": ["images"], "images_mode": "dangling",
              "confirmation": "PRUNE"}
ENDPOINTS: list[tuple[str, str, Any, str, bool]] = [
    # method, path, json, permission, csrf required
    ("POST", f"/api/v1/agent/containers/{APP_ID}/action", ACTION_BODY, "docker:operate", True),
    ("POST", "/api/v1/agent/images/pull", {"image": "nginx:1.27"}, "docker:operate", True),
    ("GET", "/api/v1/agent/jobs/" + "0" * 24, None, "docker:operate", False),
    ("POST", "/api/v1/agent/prune/preview", {"targets": ["images"]}, "docker:prune", False),
    ("POST", "/api/v1/agent/prune", PRUNE_BODY, "docker:prune", True),
    ("GET", f"/api/v1/agent/containers/{APP_ID}/logs", None, "logs:read", False),
    ("GET", f"/api/v1/agent/containers/{APP_ID}/logs/stream", None, "logs:read", False),
]
ALLOWED = {
    "docker:operate": {"owner", "admin", "operator"},
    "docker:prune": {"owner", "admin"},
    "logs:read": {"owner", "admin", "operator"},
}


def test_docker_endpoints_rbac_and_csrf(tmp_path: Path, agent: FakeAgent) -> None:
    owner, owner_headers = paired_client(tmp_path)
    try:
        roles = {"owner": (owner, owner_headers)}
        for role in ("admin", "operator", "developer", "viewer"):
            roles[role] = role_client(owner, owner_headers, role)
        for method, path, body, permission, csrf in ENDPOINTS:
            for role, (client, headers) in roles.items():
                response = client.request(method, path, headers=headers, json=body)
                if role in ALLOWED[permission]:
                    assert response.status_code != 403, (role, path, response.text)
                else:
                    assert response.status_code == 403, (role, path)
            if csrf:
                no_csrf = owner.request(method, path, json=body)
                assert no_csrf.status_code == 403
                assert no_csrf.json()["error"]["code"] == "csrf_failed"
        anonymous = TestClient(owner.app)
        for method, path, body, _permission, _csrf in ENDPOINTS:
            assert anonymous.request(method, path, json=body).status_code == 401
    finally:
        owner.__exit__(None, None, None)


# ----- container actions -----------------------------------------------------------


def test_container_actions_protected_confirmation_and_audit(
    tmp_path: Path, agent: FakeAgent
) -> None:
    client, headers = paired_client(tmp_path)
    events: list[Any] = []

    async def collect(event) -> None:
        events.append(event)

    client.app.state.events.subscribe(collect)
    try:
        url = f"/api/v1/agent/containers/{APP_ID}/action"
        ok = client.post(url, headers=headers, json={"action": "restart"})
        assert ok.status_code == 200
        assert ok.json() == {"ok": True, "id": APP_ID, "name": "app-web", "action": "restart"}
        assert ("POST", f"/v1/docker/containers/{APP_ID}/restart",
                {"timeout_seconds": 10, "allow_protected": False}) in agent.seen

        # Protected: refused without allow_protected, refused with a wrong name.
        protected_url = "/api/v1/agent/containers/dokploy-postgres/action"
        denied = client.post(protected_url, headers=headers, json={"action": "stop"})
        assert denied.status_code == 403
        assert denied.json()["error"]["code"] == "container_protected"
        wrong = client.post(
            protected_url,
            headers=headers,
            json={"action": "stop", "allow_protected": True, "confirmation": "dokploy"},
        )
        assert wrong.status_code == 422
        assert wrong.json()["error"]["code"] == "confirmation_required"
        assert not any(path.endswith("/stop") for _m, path, _b in agent.seen)

        confirmed = client.post(
            protected_url,
            headers=headers,
            json={"action": "stop", "allow_protected": True,
                  "confirmation": "dokploy-postgres"},
        )
        assert confirmed.status_code == 200 and confirmed.json()["id"] == PROTECTED_ID
        assert ("POST", f"/v1/docker/containers/{PROTECTED_ID}/stop",
                {"timeout_seconds": 10, "allow_protected": True}) in agent.seen

        # Short-id lookup, unknown container, invalid ref, invalid body.
        short = client.post(
            f"/api/v1/agent/containers/{APP_ID[:12]}/action", headers=headers,
            json={"action": "start"},
        )
        assert short.status_code == 200 and short.json()["name"] == "app-web"
        missing = client.post(
            "/api/v1/agent/containers/nope/action", headers=headers, json={"action": "start"}
        )
        assert missing.status_code == 404
        assert missing.json()["error"]["code"] == "container_not_found"
        bad_ref = client.post(
            "/api/v1/agent/containers/-x/action", headers=headers, json={"action": "start"}
        )
        assert bad_ref.status_code == 422
        assert client.post(url, headers=headers, json={"action": "kill"}).status_code == 422
        assert client.post(
            url, headers=headers, json={"action": "start", "extra": 1}
        ).status_code == 422

        actions = audit_actions(client)
        assert ("docker.container.restart", "app-web", "attempted") in actions
        assert ("docker.container.restart", "app-web", "success") in actions
        assert ("docker.container.stop", "dokploy-postgres", "denied") in actions
        assert ("docker.container.stop", "dokploy-postgres", "attempted") in actions
        assert ("docker.container.stop", "dokploy-postgres", "success") in actions
    finally:
        client.__exit__(None, None, None)
    types = [event.type for event in events]
    assert "container.restarted" in types and "container.stopped" in types
    assert all(event.severity == "info" for event in events if event.type.startswith("container"))


def test_container_action_agent_protection_and_unconfigured(
    tmp_path: Path, agent: FakeAgent, monkeypatch
) -> None:
    client, headers = paired_client(tmp_path)
    try:
        # The agent stays authoritative: if it says protected, the control plane says 403.
        monkeypatch.setitem(CONTAINERS[0], "protected", False)
        result = client.post(
            "/api/v1/agent/containers/dokploy-postgres/action",
            headers=headers,
            json={"action": "restart"},
        )
        assert result.status_code == 403
        assert result.json()["error"]["code"] == "container_protected"
        assert ("docker.container.restart", "dokploy-postgres", "failure") in audit_actions(
            client
        )
        client.request(
            "DELETE", "/api/v1/agent/config", headers=headers, json={"confirmation": "UNPAIR"}
        )
        unconfigured = client.post(
            f"/api/v1/agent/containers/{APP_ID}/action", headers=headers,
            json={"action": "restart"},
        )
        assert unconfigured.status_code == 409
        assert unconfigured.json()["error"]["code"] == "agent_not_configured"
        pull = client.post("/api/v1/agent/images/pull", headers=headers, json={"image": "nginx"})
        assert pull.status_code == 409
    finally:
        client.__exit__(None, None, None)


# ----- image pull jobs ---------------------------------------------------------------


def wait_job(client: TestClient, job_id: str) -> dict[str, Any]:
    deadline = time.monotonic() + 5
    while True:
        job = client.get(f"/api/v1/agent/jobs/{job_id}").json()
        if job["state"] != "running" or time.monotonic() > deadline:
            return job
        time.sleep(0.02)


def test_image_pull_jobs(tmp_path: Path, agent: FakeAgent) -> None:
    client, headers = paired_client(tmp_path)
    try:
        started = client.post(
            "/api/v1/agent/images/pull", headers=headers, json={"image": "nginx:1.27"}
        )
        assert started.status_code == 202
        job = wait_job(client, started.json()["job_id"])
        assert job["kind"] == "image_pull" and job["state"] == "succeeded"
        assert job["result"]["digest"].startswith("sha256:")
        assert job["started_at"] <= job["finished_at"]

        failed = client.post(
            "/api/v1/agent/images/pull", headers=headers, json={"image": "broken/img"}
        )
        failed_job = wait_job(client, failed.json()["job_id"])
        assert failed_job["state"] == "failed" and failed_job["error_code"] == "agent_rejected"

        for bad in ("UPPER/case", "nginx latest", "../etc", "a" * 300, "nginx@sha256:xyz"):
            response = client.post("/api/v1/agent/images/pull", headers=headers,
                                   json={"image": bad})
            assert response.status_code == 422, bad
        for good in ("registry.local:5000/team/app:v1.2", "ghcr.io/org/x@sha256:" + "f" * 64):
            assert host_agent_docker.IMAGE_REF.fullmatch(good), good
        assert client.get("/api/v1/agent/jobs/" + "0" * 24).status_code == 404
        assert client.get("/api/v1/agent/jobs/not-a-job").status_code == 404

        actions = audit_actions(client)
        assert ("docker.image.pull", "nginx:1.27", "attempted") in actions
        assert ("docker.image.pull", "nginx:1.27", "success") in actions
        assert ("docker.image.pull", "broken/img", "failure") in actions
    finally:
        client.__exit__(None, None, None)


def test_job_registry_is_bounded_and_expires() -> None:
    now = [1000.0]
    registry = JobRegistry(max_jobs=3, ttl_seconds=60, max_running=2, clock=lambda: now[0])
    first = registry.create("image_pull", "a")
    second = registry.create("image_pull", "b")
    with pytest.raises(JobLimitError):
        registry.create("image_pull", "c")  # two running already
    registry.finish(first, result={"ok": True})
    third = registry.create("image_pull", "c")
    registry.finish(second, error_code="agent_timeout")
    registry.finish(third)
    fourth = registry.create("image_pull", "d")  # evicts the oldest finished job
    assert registry.get(first.id) is None and registry.get(fourth.id) is not None
    assert registry.get(second.id).state == "failed"
    now[0] += 61
    assert registry.get(second.id) is None and registry.get(third.id) is None
    assert registry.get(fourth.id) is not None  # still running, never expires

    async def cancel() -> None:
        registry.spawn(asyncio.sleep(10))
        await registry.stop()

    asyncio.run(cancel())
    assert registry.get(fourth.id).error_code == "cancelled"


# ----- prune --------------------------------------------------------------------------


def test_prune_preview_confirmation_token_and_audit(tmp_path: Path, agent: FakeAgent) -> None:
    client, headers = paired_client(tmp_path)
    events: list[Any] = []

    async def collect(event) -> None:
        events.append(event)

    client.app.state.events.subscribe(collect)
    try:
        preview = client.post(
            "/api/v1/agent/prune/preview",
            headers=headers,
            json={"targets": ["images", "containers", "images"], "images_mode": "unused"},
        )
        assert preview.status_code == 200 and preview.json()["token"] == PLAN_TOKEN
        assert ("POST", "/v1/docker/prune/preview",
                {"targets": ["containers", "images"], "images_mode": "unused"}) in agent.seen
        for bad in ({"targets": []}, {"targets": ["volumes"]}, {"targets": ["images"],
                                                                "images_mode": "all"}):
            assert client.post("/api/v1/agent/prune/preview", headers=headers,
                               json=bad).status_code == 422

        base = {"targets": ["images"], "images_mode": "dangling"}
        no_confirm = client.post(
            "/api/v1/agent/prune", headers=headers,
            json={**base, "token": PLAN_TOKEN, "confirmation": "prune"},
        )
        assert no_confirm.status_code == 422
        assert no_confirm.json()["error"]["code"] == "confirmation_required"
        bad_token = client.post(
            "/api/v1/agent/prune", headers=headers,
            json={**base, "token": "xyz", "confirmation": "PRUNE"},
        )
        assert bad_token.status_code == 422 and bad_token.json()["error"]["code"] == (
            "invalid_token"
        )
        assert client.post("/api/v1/agent/prune", headers=headers,
                           json={**base, "confirmation": "PRUNE"}).status_code == 422
        assert not any(path == "/v1/docker/prune" for _m, path, _b in agent.seen)

        changed = client.post(
            "/api/v1/agent/prune", headers=headers,
            json={**base, "token": "b" * 64, "confirmation": "PRUNE"},
        )
        assert changed.status_code == 409 and changed.json()["error"]["code"] == "plan_changed"

        done = client.post(
            "/api/v1/agent/prune", headers=headers,
            json={**base, "token": PLAN_TOKEN, "confirmation": "PRUNE"},
        )
        assert done.status_code == 200 and done.json()["reclaimed_bytes"] == 1234
        assert ("POST", "/v1/docker/prune",
                {"token": PLAN_TOKEN, "targets": ["images"], "images_mode": "dangling"}
                ) in agent.seen
        actions = audit_actions(client)
        object_id = "targets=images;images=dangling"
        assert ("docker.prune", object_id, "attempted") in actions
        assert ("docker.prune", object_id, "failure") in actions
        assert ("docker.prune", object_id + ";reclaimed_bytes=1234", "success") in actions
    finally:
        client.__exit__(None, None, None)
    pruned = [event for event in events if event.type == "docker.pruned"]
    assert len(pruned) == 1 and pruned[0].severity == "info"
    assert pruned[0].details["reclaimed_bytes"] == 1234


# ----- logs ------------------------------------------------------------------------------


def test_line_filter_substring_and_regex() -> None:
    assert build_line_filter(None) is None and build_line_filter("") is None
    substring = build_line_filter("error")
    assert substring("An ERROR here") and not substring("fine")
    pattern = build_line_filter(r"^err(or)?\s", regex=True)
    assert pattern("ERROR worker") and not pattern("no error ")
    for bad in ("(", "(a+)+$", "x" * 201):
        with pytest.raises(LogFilterError):
            build_line_filter(bad, regex=True)
    # In substring mode regex syntax is literal.
    assert build_line_filter("(a+)+")("x (a+)+ y")


def test_logs_json_redaction_search_and_audit(tmp_path: Path, agent: FakeAgent) -> None:
    client, headers = paired_client(tmp_path)
    try:
        url = f"/api/v1/agent/containers/{APP_ID}/logs"
        everything = client.get(url, params={"tail": 50, "since": 10, "until": 20})
        assert everything.status_code == 200
        body = everything.json()
        assert body["truncated"] is False and len(body["lines"]) == 4
        text = json.dumps(body)
        assert "hunter2" not in text and "abc.def" not in text and "[REDACTED]" in text
        request = next(
            item for item in agent.seen if item[1].endswith("/logs")
        )
        assert request[0] == "GET"

        searched = client.get(url, params={"search": "error"}).json()["lines"]
        assert [line["text"] for line in searched] == ["ERROR worker crashed"]
        # Searching for a secret never reveals it (filter runs on redacted text).
        assert client.get(url, params={"search": "hunter2"}).json()["lines"] == []
        regex = client.get(url, params={"search": r"^(GET|ERROR)\b", "regex": "true"}).json()
        assert len(regex["lines"]) == 2
        invalid = client.get(url, params={"search": "(", "regex": "true"})
        assert invalid.status_code == 422 and invalid.json()["error"]["code"] == "invalid_search"
        assert client.get(url, params={"tail": 0}).status_code == 422
        assert client.get(url, params={"tail": 5001}).status_code == 422
        missing = client.get("/api/v1/agent/containers/missing/logs")
        assert missing.status_code == 404
        assert missing.json()["error"]["code"] == "container_not_found"

        views = [entry for entry in audit_actions(client) if entry[0] == "logs.view"]
        assert views.count(("logs.view", APP_ID, "success")) == 4
        assert ("logs.view", "missing", "failure") in views
        assert "hunter2" not in json.dumps(client.get("/api/v1/audit-events").json())
    finally:
        client.__exit__(None, None, None)


def parse_sse(raw: str) -> tuple[list[tuple[str, Any]], list[str]]:
    events: list[tuple[str, Any]] = []
    comments: list[str] = []
    for block in raw.split("\n\n"):
        if not block.strip():
            continue
        name, data = None, None
        for line in block.split("\n"):
            if line.startswith(":"):
                comments.append(line[1:].strip())
            elif line.startswith("event: "):
                name = line[7:]
            elif line.startswith("data: "):
                data = json.loads(line[6:])
        if name:
            events.append((name, data))
    return events, comments


def test_logs_sse_stream_framing_redaction_and_end(tmp_path: Path, agent: FakeAgent) -> None:
    client, _headers = paired_client(tmp_path)
    try:
        url = f"/api/v1/agent/containers/{APP_ID}/logs/stream"
        with client.stream("GET", url, params={"tail": 10}) as response:
            assert response.status_code == 200
            assert response.headers["content-type"].startswith("text/event-stream")
            assert response.headers["x-accel-buffering"] == "no"
            raw = "".join(response.iter_text())
        events, _comments = parse_sse(raw)
        assert [name for name, _ in events] == ["line"] * 4 + ["end"]
        assert events[-1][1] == {"reason": "agent_closed"}
        assert "hunter2" not in raw and "abc.def" not in raw
        assert events[1][1]["stream"] == "stderr"
        follow = next(item for item in agent.seen if item[1].endswith("/logs"))
        assert follow[0] == "GET"
        assert agent.stream_closed

        with client.stream("GET", url, params={"search": "worker"}) as response:
            searched, _ = parse_sse("".join(response.iter_text()))
        assert [data["text"] for name, data in searched if name == "line"] == [
            "ERROR worker crashed"
        ]
        views = [entry for entry in audit_actions(client) if entry[0] == "logs.view"]
        assert len(views) == 2  # one audit row per request, never per line
        assert client.get(url, params={"search": "(", "regex": "true"}).status_code == 422
        missing = client.get("/api/v1/agent/containers/missing/logs/stream")
        assert missing.status_code == 404
    finally:
        client.__exit__(None, None, None)


def test_logs_sse_keepalive_and_max_duration(
    tmp_path: Path, agent: FakeAgent, monkeypatch
) -> None:
    monkeypatch.setattr(host_agent_docker, "STREAM_KEEPALIVE_SECONDS", 0.05)
    monkeypatch.setattr(host_agent_docker, "STREAM_MAX_SECONDS", 0.6)
    agent.stream_delay = 0.12
    agent.stream_forever = True
    client, _headers = paired_client(tmp_path)
    try:
        started = time.monotonic()
        with client.stream("GET", f"/api/v1/agent/containers/{APP_ID}/logs/stream") as response:
            raw = "".join(response.iter_text())
        assert time.monotonic() - started < 5
        events, comments = parse_sse(raw)
        assert "keepalive" in comments
        assert events[-1] == ("end", {"reason": "timeout"})
        assert [name for name, _ in events].count("line") == 4
        assert agent.stream_closed  # the agent connection is closed at the deadline
    finally:
        client.__exit__(None, None, None)
