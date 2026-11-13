from __future__ import annotations

import asyncio
import json
import os
import re
import time
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient
from mrk_control_plane.agent import main as agent_main
from mrk_control_plane.agent import signing
from mrk_control_plane.agent.app import AgentConfig, create_agent_app
from mrk_control_plane.agent.docker_client import (
    DockerClient,
    DockerNotAllowed,
    check_allowed,
    validate_container_ref,
)
from mrk_control_plane.agent.host_metrics import collect, parse_meminfo
from mrk_control_plane.agent.protection import ProtectionRules
from mrk_control_plane.config import Settings
from mrk_control_plane.main import create_app
from mrk_control_plane.modules import host_agent

from .helpers import login_owner

KEY = bytes(range(32))
KEY_TEXT = signing.encode_key(KEY)

CONTAINERS = [
    {
        "Id": "a" * 64,
        "Names": ["/dokploy-postgres"],
        "Image": "postgres:16",
        "State": "running",
        "Status": "Up 3 days",
        "Created": 1700000000,
        "Ports": [{"IP": "127.0.0.1", "PrivatePort": 5432, "PublicPort": 5432, "Type": "tcp"}],
        "Labels": {"traefik.http.middlewares.auth.basicauth.users": "admin:$apr1$secret"},
    },
    {
        "Id": "b" * 64,
        "Names": ["/mrk-mirror-1"],
        "Image": "mrk/package-mirror:dev",
        "State": "running",
        "Status": "Up 1 hour",
        "Created": 1700000100,
        "Ports": [],
        "Labels": {"com.docker.compose.project": "mrk", "com.docker.compose.service": "x"},
    },
    {
        "Id": "c" * 64,
        "Names": ["/app-web"],
        "Image": "nginx",
        "State": "exited",
        "Status": "Exited (0)",
        "Created": 1700000200,
        "Labels": {"com.dokploy.app": "web"},
    },
]


def fake_docker_handler(seen: list[httpx.Request]):
    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        assert request.method == "GET"
        path = request.url.path
        if path == "/version":
            return httpx.Response(200, json={"Version": "27.3.1", "ApiVersion": "1.47"})
        assert path.startswith("/v1.47/")
        path = path.removeprefix("/v1.47")
        payloads = {
            "/info": {"ContainersRunning": 2, "Containers": 3},
            "/containers/json": CONTAINERS,
            "/images/json": [{}, {}],
            "/volumes": {"Volumes": [{}]},
            "/networks": [{}, {}, {}],
            "/system/df": {
                "LayersSize": 1000,
                "Images": [{"Size": 600}],
                "Containers": [{"SizeRw": 5}],
                "Volumes": [{"UsageData": {"Size": 70}}, {"UsageData": {"Size": -1}}],
                "BuildCache": [],
            },
        }
        return httpx.Response(200, json=payloads[path])

    return handler


def fake_proc(tmp_path: Path) -> tuple[Path, Path]:
    proc = tmp_path / "proc"
    (proc / "sys" / "kernel").mkdir(parents=True)
    (proc / "meminfo").write_text(
        "MemTotal:       16303180 kB\nMemFree:  1000 kB\nMemAvailable:   8151590 kB\n"
    )
    (proc / "loadavg").write_text("0.52 0.40 0.31 1/523 12345\n")
    (proc / "uptime").write_text("12345.67 54321.00\n")
    (proc / "stat").write_text("cpu  1 2 3\ncpu0 1 2 3\ncpu1 1 2 3\ncpu2 1 2 3\nintr 1\n")
    (proc / "sys" / "kernel" / "osrelease").write_text("6.8.0-45-generic\n")
    (proc / "sys" / "kernel" / "hostname").write_text("container-host\n")
    root = tmp_path / "root"
    (root / "etc").mkdir(parents=True)
    (root / "etc" / "hostname").write_text("prod-node-1\n")
    return proc, root


def agent_app(tmp_path: Path, seen: list[httpx.Request] | None = None):
    proc, root = fake_proc(tmp_path)
    config = AgentConfig(key=KEY, proc_dir=proc, root_paths=[root])
    return create_agent_app(
        config, docker_transport=httpx.MockTransport(
            fake_docker_handler(seen if seen is not None else [])
        )
    )


def signed_get(client: TestClient, path: str, key: bytes = KEY, **kwargs) -> httpx.Response:
    return client.get(path, headers=signing.sign_headers(key, "GET", path, b"", **kwargs))


# ----- signing ---------------------------------------------------------------


def test_sign_and_verify_roundtrip_and_rejections() -> None:
    verifier = signing.RequestVerifier(KEY)
    headers = signing.sign_headers(KEY, "GET", "/v1/info?x=1", b"")
    verifier.verify("GET", "/v1/info?x=1", headers, b"")

    with pytest.raises(signing.SignatureError) as replay:
        verifier.verify("GET", "/v1/info?x=1", headers, b"")
    assert replay.value.reason == "replay"

    for method, path, body in (("POST", "/v1/info?x=1", b""), ("GET", "/v1/info", b""),
                               ("GET", "/v1/info?x=1", b"x")):
        fresh = signing.sign_headers(KEY, "GET", "/v1/info?x=1", b"")
        with pytest.raises(signing.SignatureError) as bad:
            verifier.verify(method, path, fresh, body)
        assert bad.value.reason == "bad_signature"

    wrong_key = signing.sign_headers(b"\x01" * 32, "GET", "/v1/info", b"")
    with pytest.raises(signing.SignatureError):
        verifier.verify("GET", "/v1/info", wrong_key, b"")

    stale = signing.sign_headers(KEY, "GET", "/v1/info", b"", now=time.time() - 31)
    with pytest.raises(signing.SignatureError) as skew:
        verifier.verify("GET", "/v1/info", stale, b"")
    assert skew.value.reason == "clock_skew"
    future = signing.sign_headers(KEY, "GET", "/v1/info", b"", now=time.time() + 45)
    with pytest.raises(signing.SignatureError):
        verifier.verify("GET", "/v1/info", future, b"")

    with pytest.raises(signing.SignatureError) as missing:
        verifier.verify("GET", "/v1/info", {}, b"")
    assert missing.value.reason == "missing_headers"


def test_nonce_cache_expires_and_is_bounded() -> None:
    cache = signing.NonceCache(ttl_seconds=60, max_size=2)
    cache.add("n1", now=0)
    cache.add("n2", now=1)
    with pytest.raises(signing.SignatureError) as full:
        cache.add("n3", now=2)
    assert full.value.reason == "nonce_cache_full"
    cache.add("n3", now=60.5)  # n1 expired
    with pytest.raises(signing.SignatureError):
        cache.add("n2", now=60.7)
    cache.add("n1", now=62)  # n1 may be reused after its window


def test_key_encoding() -> None:
    assert signing.decode_key(KEY_TEXT) == KEY
    assert signing.decode_key(KEY_TEXT + "=") == KEY
    for bad in ("", "short", signing.encode_key(b"x" * 31), "not base64!" * 4):
        with pytest.raises(ValueError):
            signing.decode_key(bad)


def test_key_file_generated_once_with_private_mode(tmp_path: Path) -> None:
    key, created = agent_main.load_or_create_key(tmp_path / "state")
    assert created and len(key) == 32
    again, created_again = agent_main.load_or_create_key(tmp_path / "state")
    assert again == key and not created_again
    if os.name == "posix":
        assert (tmp_path / "state" / "agent.key").stat().st_mode & 0o777 == 0o600
    assert agent_main.parse_listen("127.0.0.1:7070") == ("127.0.0.1", 7070)
    with pytest.raises(ValueError):
        agent_main.parse_listen("7070")


# ----- allowlist / protection / metrics -------------------------------------


def test_docker_allowlist_is_read_only() -> None:
    for path in ("/version", "/info", "/images/json", "/volumes", "/networks", "/system/df",
                 "/containers/abc123/json", "/containers/my_app.web-1/json"):
        check_allowed("GET", path)
    check_allowed("GET", "/containers/json", {"all": "1"})
    rejected = [
        ("POST", "/containers/json", None),
        ("DELETE", "/containers/abc/json", None),
        ("GET", "/containers/abc/exec", None),
        ("POST", "/containers/abc/exec", None),
        ("GET", "/containers/../images/json", None),
        ("GET", "/containers/%2e%2e/json", None),
        ("GET", "/containers/abc/../json", None),
        ("GET", "//info", None),
        ("GET", "/info?x=1", None),
        ("GET", "/build", None),
        ("GET", "/containers/json", {"filters": "{}"}),
        ("GET", "/containers/json", {"all": "1", "size": "1"}),
        ("GET", "/exec/abc/json", None),
        ("GET", "/containers/abc/logs", None),
        ("GET", "/v1.47/info", None),
    ]
    for method, path, params in rejected:
        with pytest.raises(DockerNotAllowed):
            check_allowed(method, path, params)
    for bad in ("..", "-x", "a/b", "a..b", ""):
        with pytest.raises(DockerNotAllowed):
            validate_container_ref(bad)


def test_docker_client_negotiates_version_and_never_sends_disallowed() -> None:
    seen: list[httpx.Request] = []
    client = DockerClient(transport=httpx.MockTransport(fake_docker_handler(seen)))

    async def scenario() -> None:
        containers = await client.containers()
        assert len(containers) == 3
        assert client.api_version == "1.47"
        with pytest.raises(DockerNotAllowed):
            await client.inspect_container("../images")
        with pytest.raises(DockerNotAllowed):
            await client._get("/containers/abc/exec")
        await client.aclose()

    asyncio.run(scenario())
    assert [request.url.path for request in seen] == ["/version", "/v1.47/containers/json"]
    assert seen[1].url.query == b"all=1"


def test_protected_detection_and_env_override(monkeypatch) -> None:
    rules = ProtectionRules.default()
    assert rules.is_protected(["/dokploy"], {})
    assert rules.is_protected(["/dokploy-traefik"], {})
    assert rules.is_protected(["/dokploy.1.abcdef"], {})
    assert rules.is_protected(["/x"], {"com.docker.compose.project": "dokploy"})
    assert rules.is_protected(["/x"], {"com.dokploy.app": "1"})
    assert rules.is_protected(["/x"], {"dokploy.managed": "true"})
    assert rules.is_protected(["/x"], {"com.docker.swarm.service.name": "dokploy-redis"})
    assert not rules.is_protected(["/dokployer"], {})
    assert not rules.is_protected(["/mrk-mirror"], {"com.docker.compose.project": "mrk"})

    monkeypatch.setenv("MRK_AGENT_PROTECTED_NAME_REGEX", r"^/?(dokploy|db)(-|$)")
    monkeypatch.setenv("MRK_AGENT_PROTECTED_LABEL_PREFIXES", "")
    monkeypatch.setenv("MRK_AGENT_PROTECTED_COMPOSE_PROJECTS", "infra")
    custom = ProtectionRules.from_env()
    assert custom.is_protected(["/db-main"], {})
    assert custom.is_protected(["/x"], {"com.docker.compose.project": "infra"})
    assert not custom.is_protected(["/x"], {"com.dokploy.app": "1"})
    monkeypatch.setenv("MRK_AGENT_PROTECTED_NAME_REGEX", "(")
    with pytest.raises(ValueError):
        ProtectionRules.from_env()


def test_host_metrics_from_fake_proc(tmp_path: Path) -> None:
    proc, root = fake_proc(tmp_path)
    data = collect(proc, [root])
    assert data["hostname"] == "prod-node-1"
    assert data["kernel"] == "6.8.0-45-generic"
    assert data["uptime_seconds"] == 12345.67
    assert data["cpu_count"] == 3
    assert data["loadavg"] == [0.52, 0.40, 0.31]
    assert data["memory"] == {"total_bytes": 16303180 * 1024, "available_bytes": 8151590 * 1024}
    if hasattr(os, "statvfs"):
        assert data["disks"][0]["total_bytes"] > 0
    assert parse_meminfo("Bad line\nMemTotal: x kB\n") == {}


# ----- agent HTTP API --------------------------------------------------------


def test_agent_api_requires_signatures(tmp_path: Path) -> None:
    with TestClient(agent_app(tmp_path)) as client:
        health = client.get("/v1/health")
        assert health.status_code == 200 and health.json() == {"status": "ok"}
        assert client.get("/v1/info").status_code == 401
        assert client.get("/v1/unknown").status_code == 401
        assert client.post("/v1/info").status_code == 405
        assert client.post("/v1/health").status_code == 405
        assert signed_get(client, "/v1/info", key=b"\x02" * 32).status_code == 401
        stale = signed_get(client, "/v1/info", now=time.time() - 120)
        assert stale.status_code == 401 and stale.json()["reason"] == "clock_skew"

        headers = signing.sign_headers(KEY, "GET", "/v1/info", b"")
        assert client.get("/v1/info", headers=headers).status_code == 200
        replay = client.get("/v1/info", headers=headers)
        assert replay.status_code == 401 and replay.json()["reason"] == "replay"
        # A signature for one path cannot be used for another.
        moved = signing.sign_headers(KEY, "GET", "/v1/info", b"")
        assert client.get("/v1/docker/containers", headers=moved).status_code == 401


def test_agent_info_containers_and_summary(tmp_path: Path) -> None:
    seen: list[httpx.Request] = []
    with TestClient(agent_app(tmp_path, seen)) as client:
        info = signed_get(client, "/v1/info").json()
        assert info["capabilities"] == {"docker": True, "host_metrics": True, "firewall": False,
                                        "traefik_file": False, "dns_facts": True,
                                        "build_mirror_facts": True}
        assert info["docker"] == {
            "version": "27.3.1",
            "api_version": "1.47",
            "containers_running": 2,
            "containers_total": 3,
        }
        assert info["host"]["hostname"] == "prod-node-1"

        items = signed_get(client, "/v1/docker/containers").json()["items"]
        by_name = {item["name"]: item for item in items}
        assert by_name["dokploy-postgres"]["protected"] is True
        assert by_name["app-web"]["protected"] is True
        assert by_name["mrk-mirror-1"]["protected"] is False
        # Arbitrary labels (which may carry secrets) are not exposed.
        assert by_name["dokploy-postgres"]["labels_subset"] == {}
        assert by_name["app-web"]["labels_subset"] == {"com.dokploy.app": "web"}
        assert set(by_name["mrk-mirror-1"]) == {
            "id", "name", "image", "state", "status", "health", "created", "ports", "labels_subset",
            "protected", "image_id", "networks",
        }

        summary = signed_get(client, "/v1/docker/summary").json()
        assert summary["images"] == 2 and summary["volumes"] == 1 and summary["networks"] == 3
        assert summary["disk_usage"]["volumes_size"] == 70
        assert summary["disk_usage"]["images_size"] == 600
    assert all(request.method == "GET" for request in seen)


def test_agent_info_serves_docker_facts_from_a_short_cache(tmp_path: Path) -> None:
    seen: list[httpx.Request] = []
    with TestClient(agent_app(tmp_path, seen)) as client:
        first = signed_get(client, "/v1/info").json()

        def docker_calls() -> int:
            return len([item for item in seen if item.url.path.endswith(("/version", "/info"))])

        assert docker_calls() == 2
        for _ in range(3):
            assert signed_get(client, "/v1/info").json()["docker"] == first["docker"]
        # The panel's reachability probe must not hit the (slow) daemon every time.
        assert docker_calls() == 2


def test_name_resolution_errors_are_detected() -> None:
    import socket

    from mrk_control_plane.components import is_name_resolution_error

    wrapped = httpx.ConnectError("[Errno -2] Name or service not known")
    assert is_name_resolution_error(wrapped)
    try:
        try:
            raise socket.gaierror(11001, "getaddrinfo failed")
        except socket.gaierror as inner:
            raise httpx.ConnectError("connect failed") from inner
    except httpx.ConnectError as outer:
        assert is_name_resolution_error(outer)
    assert not is_name_resolution_error(httpx.ConnectError("[Errno 111] Connection refused"))
    error = host_agent.HostAgentService._connection_error("http://mrk-agent:7070", wrapped)
    assert error.code == "agent_name_unresolved" and "mrk-net" in error.message
    assert host_agent.HostAgentService._connection_error(
        "http://mrk-agent:7070", httpx.ConnectError("refused")).code == "agent_unreachable"


def test_reachability_hysteresis() -> None:
    from mrk_control_plane.components import Reachability

    now = [0.0]
    health = Reachability(3, 20.0, clock=lambda: now[0])
    assert health.record(False) is None and health.reachable is None
    now[0] = 10
    assert health.record(False) is None
    assert health.record(False) is None  # 3 failures, but only 10 s apart
    now[0] = 25
    assert health.record(False) == "offline" and health.reachable is False
    assert health.record(False) is None  # published once
    assert health.record(True) == "online" and health.failures == 0
    assert health.record(False) is None and health.reachable is True  # one blip
    assert health.record(False, immediate=True) == "offline"


def test_agent_without_docker_reports_capability_false(tmp_path: Path) -> None:
    proc, root = fake_proc(tmp_path)
    config = AgentConfig(
        key=KEY, docker_socket=str(tmp_path / "missing.sock"), proc_dir=proc, root_paths=[root]
    )
    with TestClient(create_agent_app(config)) as client:
        info = signed_get(client, "/v1/info").json()
        assert info["capabilities"]["docker"] is False and info["docker"] is None
        assert signed_get(client, "/v1/docker/containers").status_code == 503


# ----- control-plane module -------------------------------------------------


@pytest.fixture
def agent_transport(tmp_path: Path, monkeypatch):
    """Route the control plane's outbound agent calls into an in-process agent app."""
    state = {"online": True, "app": agent_app(tmp_path / "agent")}

    class Switchable(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            if not state["online"]:
                raise httpx.ConnectError("refused", request=request)
            return await httpx.ASGITransport(app=state["app"]).handle_async_request(request)

    monkeypatch.setattr(host_agent, "TRANSPORT_FACTORY", Switchable)
    monkeypatch.delenv("MRK_AGENT_URL", raising=False)
    monkeypatch.delenv("MRK_AGENT_KEY_FILE", raising=False)
    return state


def test_control_plane_pairing_status_events_and_unpair(tmp_path: Path, agent_transport) -> None:
    app = create_app(Settings.for_test(tmp_path / "cp"))
    events: list[object] = []

    with TestClient(app) as client:
        async def collect_event(event) -> None:
            events.append(event)

        app.state.events.subscribe(collect_event)
        assert client.get("/api/v1/agent/status").status_code == 401
        csrf = str(login_owner(client)["csrf_token"])
        headers = {"X-CSRF-Token": csrf}

        status = client.get("/api/v1/agent/status").json()
        assert status["configured"] is False and status["source"] is None
        assert client.get("/api/v1/agent/containers").json()["error"]["code"] == (
            "agent_not_configured"
        )
        assert client.post("/api/v1/agent/test", headers=headers).status_code == 409

        body = {"url": "http://mrk-agent:7070", "key": KEY_TEXT}
        assert client.put("/api/v1/agent/config", json=body).status_code == 403  # no CSRF
        for bad_url in ("ftp://mrk-agent:7070", "http://user:pw@mrk-agent:7070",
                        "http://mrk-agent:7070/x", "http://mrk-agent:7070/?a=1", "http://"):
            bad = client.put("/api/v1/agent/config", headers=headers,
                             json={"url": bad_url, "key": KEY_TEXT})
            assert bad.status_code == 422, bad_url
        bad_key = client.put(
            "/api/v1/agent/config",
            headers=headers,
            json={"url": "http://mrk-agent:7070", "key": "A" * 42},
        )
        assert bad_key.status_code == 422
        no_key = client.put(
            "/api/v1/agent/config", headers=headers, json={"url": "http://mrk-agent:7070"}
        )
        assert no_key.json()["error"]["code"] == "agent_key_required"

        paired = client.put("/api/v1/agent/config", headers=headers, json=body)
        assert paired.status_code == 200
        paired_status = paired.json()
        assert paired_status["configured"] is True and paired_status["source"] == "panel"
        assert paired_status["reachable"] is True
        assert paired_status["version"] and paired_status["capabilities"]["docker"] is True
        assert paired_status["host"]["hostname"] == "prod-node-1"
        stored = (tmp_path / "cp" / "control-plane" / "agent.json").read_text()
        assert KEY_TEXT not in stored and "secret_ref" in stored

        items = client.get("/api/v1/agent/containers").json()["items"]
        assert any(item["protected"] for item in items)
        assert client.get("/api/v1/agent/summary").json()["networks"] == 3
        test = client.post("/api/v1/agent/test", headers=headers).json()
        assert test["ok"] is True and test["latency_ms"] >= 0

        # URL-only update keeps the stored key.
        renamed = client.put(
            "/api/v1/agent/config", headers=headers, json={"url": "http://mrk-agent:7070/"}
        )
        assert renamed.status_code == 200 and renamed.json()["reachable"] is True

        agent_transport["online"] = False
        offline = client.post("/api/v1/agent/test", headers=headers).json()
        assert offline == {"ok": False, "latency_ms": offline["latency_ms"],
                           "error_code": "agent_unreachable"}
        assert client.get("/api/v1/agent/containers").json()["error"]["code"] == (
            "agent_unreachable"
        )
        assert client.post("/api/v1/agent/test", headers=headers).json()["ok"] is False
        # Hysteresis: two failed probes are not an outage yet (no flip, no event).
        still = client.get("/api/v1/agent/status").json()
        assert still["reachable"] is True and still["consecutive_failures"] == 2
        assert still["error_code"] == "agent_unreachable"
        assert not [event for event in events if event.type == "agent.offline"]
        assert client.post("/api/v1/agent/test", headers=headers).json()["ok"] is False
        down = client.get("/api/v1/agent/status").json()
        assert down["reachable"] is False and down["consecutive_failures"] == 3
        agent_transport["online"] = True
        assert client.post("/api/v1/agent/test", headers=headers).json()["ok"] is True

        # Wrong key on the agent side -> auth failure.
        agent_transport["app"] = create_agent_app(
            AgentConfig(key=b"\x09" * 32, docker_socket=str(tmp_path / "none.sock"))
        )
        failed = client.post("/api/v1/agent/test", headers=headers).json()
        assert failed["error_code"] == "agent_auth_failed"
        assert client.get("/api/v1/agent/summary").json()["error"]["code"] == "agent_auth_failed"

        wrong = client.request(
            "DELETE", "/api/v1/agent/config", headers=headers, json={"confirmation": "yes"}
        )
        assert wrong.status_code == 422
        unpaired = client.request(
            "DELETE", "/api/v1/agent/config", headers=headers, json={"confirmation": "UNPAIR"}
        )
        assert unpaired.status_code == 200 and unpaired.json()["configured"] is False
        assert not (tmp_path / "cp" / "control-plane" / "agent.json").exists()

        audit = client.get("/api/v1/audit-events").json()
        actions = [item["action"] for item in audit.get("items", [])]
        assert "agent.config.update" in actions and "agent.unpair" in actions
        assert KEY_TEXT not in json.dumps(audit)

    types = [event.type for event in events]
    # online->offline once after 3 failures, offline->online, then online->offline at
    # once for an auth failure (a retry cannot fix a rejected key).
    assert types == ["agent.offline", "agent.online", "agent.offline"]
    assert all(event.dedupe_key == "agent.reachability" for event in events)
    assert events[0].severity == "error" and events[1].severity == "info"


def test_control_plane_env_config_wins_and_is_read_only(
    tmp_path: Path, agent_transport, monkeypatch
) -> None:
    key_file = tmp_path / "agent.key"
    key_file.write_text(KEY_TEXT + "\n")
    monkeypatch.setenv("MRK_AGENT_URL", "http://mrk-agent:7070")
    monkeypatch.setenv("MRK_AGENT_KEY_FILE", str(key_file))
    app = create_app(Settings.for_test(tmp_path / "cp"))
    with TestClient(app) as client:
        headers = {"X-CSRF-Token": str(login_owner(client)["csrf_token"])}
        status = client.get("/api/v1/agent/status").json()
        assert status["source"] == "env" and status["reachable"] is True
        blocked = client.put(
            "/api/v1/agent/config",
            headers=headers,
            json={"url": "http://other:7070", "key": KEY_TEXT},
        )
        assert blocked.status_code == 409
        assert blocked.json()["error"]["code"] == "agent_managed_by_environment"
        assert client.request(
            "DELETE", "/api/v1/agent/config", headers=headers, json={"confirmation": "UNPAIR"}
        ).status_code == 409


def test_control_plane_agent_rbac(tmp_path: Path, agent_transport) -> None:
    app = create_app(Settings.for_test(tmp_path / "cp"))
    with TestClient(app) as client:
        csrf = str(login_owner(client)["csrf_token"])
        created = client.post(
            "/api/v1/users",
            headers={"X-CSRF-Token": csrf},
            json={"username": "viewer1", "password": "a-long-viewer-password-123",
                  "role": "viewer"},
        )
        assert created.status_code == 201
        client.post("/api/v1/auth/logout", headers={"X-CSRF-Token": csrf})
        viewer = client.post(
            "/api/v1/auth/login",
            json={"username": "viewer1", "password": "a-long-viewer-password-123"},
        ).json()
        viewer_headers = {"X-CSRF-Token": str(viewer["csrf_token"])}
        assert client.get("/api/v1/agent/status").status_code == 403
        assert client.get("/api/v1/agent/containers").status_code == 403
        assert client.put(
            "/api/v1/agent/config",
            headers=viewer_headers,
            json={"url": "http://mrk-agent:7070", "key": KEY_TEXT},
        ).status_code == 403
        assert client.post("/api/v1/agent/test", headers=viewer_headers).status_code == 403


def test_validate_agent_url_normalizes() -> None:
    assert host_agent.validate_agent_url("http://mrk-agent:7070/") == "http://mrk-agent:7070"
    assert host_agent.validate_agent_url("https://10.0.0.5") == "https://10.0.0.5"
    assert host_agent.validate_agent_url("http://[fd00::1]:7070") == "http://[fd00::1]:7070"
    for bad in ("http://a b:1", "http://host:99999", "javascript:alert(1)"):
        with pytest.raises(ValueError):
            host_agent.validate_agent_url(bad)
    assert re.fullmatch(r"[A-Za-z0-9_-]{43}", KEY_TEXT)
