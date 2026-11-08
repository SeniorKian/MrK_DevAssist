"""Gate 17 Host Agent: logs, metrics, container actions, image pull and prune."""

from __future__ import annotations

import asyncio
import json
import struct
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient
from mrk_control_plane.agent import cgroups, host_metrics, signing
from mrk_control_plane.agent.app import AgentConfig, create_agent_app
from mrk_control_plane.agent.docker_client import (
    DockerClient,
    DockerNotAllowed,
    check_allowed,
    parse_image_reference,
)
from mrk_control_plane.agent.logs import LogDecoder
from mrk_control_plane.agent.protection import ProtectionRules
from mrk_control_plane.agent.prune import build_plan, plan_token

KEY = bytes(range(32))
API = "/v1.47"
DOKPLOY_ID = "a" * 64
APP_ID = "b" * 64
STOPPED_ID = "c" * 64
TTY_ID = "d" * 64
SWARM_TASK_ID = "e" * 64
STOPPED_DOKPLOY_ID = "f" * 64
IMG_USED = "sha256:" + "1" * 64
IMG_STOPPED_USE = "sha256:" + "2" * 64
IMG_DANGLING = "sha256:" + "3" * 64
IMG_UNUSED_TAGGED = "sha256:" + "4" * 64
IMG_DOKPLOY = "sha256:" + "5" * 64
IMG_FAILS = "sha256:" + "6" * 64
NET_USED = "7" * 64
NET_FREE = "8" * 64
NET_DOKPLOY = "9" * 64
NET_BRIDGE = "0" * 64
NET_SWARM = "ab" * 32


def _container(cid, name, state, image_id, labels=None, networks=None):
    return {
        "Id": cid,
        "Names": [f"/{name}"],
        "Image": name,
        "ImageID": image_id,
        "State": state,
        "Status": state,
        "Labels": labels or {},
        "NetworkSettings": {"Networks": networks or {}},
    }


CONTAINERS = [
    _container(DOKPLOY_ID, "dokploy", "running", IMG_USED,
               networks={"dokploy-network": {"NetworkID": NET_DOKPLOY}}),
    _container(APP_ID, "app-web", "running", IMG_USED,
               networks={"app-net": {"NetworkID": NET_USED}}),
    _container(STOPPED_ID, "old-job", "exited", IMG_STOPPED_USE),
    _container(TTY_ID, "tty-box", "running", IMG_USED),
    _container(SWARM_TASK_ID, "svc.1.x", "exited", IMG_USED,
               labels={"com.docker.swarm.task.id": "t1"}),
    _container(STOPPED_DOKPLOY_ID, "dokploy-redis", "exited", IMG_USED),
]
IMAGES = [
    {"Id": IMG_USED, "RepoTags": ["nginx:1.27"], "Size": 100},
    {"Id": IMG_STOPPED_USE, "RepoTags": ["<none>:<none>"], "Size": 200},
    {"Id": IMG_DANGLING, "RepoTags": None, "Size": 300},
    {"Id": IMG_UNUSED_TAGGED, "RepoTags": ["redis:7"], "Size": 400},
    {"Id": IMG_DOKPLOY, "RepoTags": ["dokploy/dokploy:latest"], "Size": 500},
    {"Id": IMG_FAILS, "RepoTags": [], "Size": 600},
]
NETWORKS = [
    {"Id": NET_BRIDGE, "Name": "bridge", "Scope": "local"},
    {"Id": NET_USED, "Name": "app-net", "Scope": "local"},
    {"Id": NET_FREE, "Name": "leftover", "Scope": "local"},
    {"Id": NET_DOKPLOY, "Name": "dokploy-network", "Scope": "swarm"},
    {"Id": NET_SWARM, "Name": "overlay-x", "Scope": "swarm"},
    {"Id": "cd" * 32, "Name": "dokploy-internal", "Scope": "local"},
]
DF = {
    "Containers": [{"Id": STOPPED_ID, "SizeRw": 50}],
    "BuildCache": [{"Size": 70, "InUse": False}, {"Size": 1000, "InUse": True}],
}


def frame(stream: int, payload: bytes) -> bytes:
    return struct.pack(">BxxxI", stream, len(payload)) + payload


class FakeDocker:
    """A tiny Docker Engine API double for an httpx MockTransport."""

    def __init__(self) -> None:
        self.seen: list[httpx.Request] = []
        self.containers = [dict(item) for item in CONTAINERS]
        self.images = [dict(item) for item in IMAGES]
        self.log_body: bytes | None = None
        self.log_stream = None
        self.pull_lines: list[dict] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.seen.append(request)
        path = request.url.path
        if path == "/version":
            return httpx.Response(200, json={"Version": "27.3.1", "ApiVersion": "1.47"})
        assert path.startswith(API + "/")
        path = path.removeprefix(API)
        method = request.method
        by_ref = {c["Id"]: c for c in self.containers}
        by_ref.update({c["Names"][0].lstrip("/"): c for c in self.containers})
        if method == "GET":
            if path == "/containers/json":
                return httpx.Response(200, json=self.containers)
            if path == "/images/json":
                return httpx.Response(200, json=self.images)
            if path == "/networks":
                return httpx.Response(200, json=NETWORKS)
            if path == "/system/df":
                return httpx.Response(200, json=DF)
            parts = path.split("/")
            if len(parts) == 4 and parts[1] == "containers":
                container = by_ref.get(parts[2])
                if container is None:
                    return httpx.Response(404, json={"message": "No such container"})
                if parts[3] == "json":
                    return httpx.Response(200, json={
                        "Id": container["Id"],
                        "Name": container["Names"][0],
                        "Config": {"Tty": container["Id"] == TTY_ID,
                                   "Labels": container["Labels"]},
                    })
                if parts[3] == "logs":
                    if self.log_stream is not None:
                        return httpx.Response(200, content=self.log_stream())
                    return httpx.Response(200, content=self.log_body or b"")
        if method == "POST":
            if path.startswith("/containers/"):
                return httpx.Response(204)
            if path == "/images/create":
                body = b"".join(json.dumps(line).encode() + b"\r\n" for line in self.pull_lines)
                return httpx.Response(200, content=body)
            if path == "/build/prune":
                return httpx.Response(200, json={"CachesDeleted": ["x"], "SpaceReclaimed": 70})
        if method == "DELETE":
            if path == f"/images/{IMG_FAILS}":
                return httpx.Response(409, json={"message": "conflict: image is in use"})
            if path.startswith(("/containers/", "/networks/")):
                return httpx.Response(204)
            if path.startswith("/images/"):
                return httpx.Response(200, json=[{"Deleted": path.rsplit("/", 1)[-1]}])
        return httpx.Response(500, json={"message": f"unexpected {method} {path}"})


def make_app(tmp_path: Path, fake: FakeDocker, **overrides) -> TestClient:
    proc = tmp_path / "proc"
    proc.mkdir(exist_ok=True)
    (proc / "meminfo").write_text("MemTotal: 1000 kB\nMemAvailable: 250 kB\n")
    (proc / "loadavg").write_text("0.40 0.30 0.20 1/100 1\n")
    (proc / "stat").write_text("cpu  100 0 100 800 0 0 0 0 0 0\n")
    overrides.setdefault("cgroup_dir", tmp_path / "nocgroup")
    config = AgentConfig(key=KEY, proc_dir=proc, root_paths=[tmp_path], **overrides)
    return TestClient(create_agent_app(config, docker_transport=httpx.MockTransport(fake.handler)))


def signed(client: TestClient, method: str, path: str, body: object | None = None, **kwargs):
    raw = b"" if body is None else json.dumps(body).encode()
    headers = signing.sign_headers(KEY, method, path, raw)
    if raw:
        headers["Content-Type"] = "application/json"
    return client.request(method, path, content=raw, headers=headers, **kwargs)


def docker_calls(fake: FakeDocker, method: str | None = None) -> list[str]:
    return [
        f"{r.method} {r.url.path.removeprefix(API)}"
        + (f"?{r.url.query.decode()}" if r.url.query else "")
        for r in fake.seen
        if r.url.path != "/version" and (method is None or r.method == method)
    ]


# ----- allowlist ------------------------------------------------------------


def test_allowlist_gate17_allowed_combinations() -> None:
    check_allowed("POST", "/containers/abc/start")
    check_allowed("POST", "/containers/my-app_1/stop", {"t": "10"})
    check_allowed("POST", "/containers/abc/restart", {"t": "300"})
    check_allowed("POST", "/containers/abc/restart")
    check_allowed("POST", "/images/create", {"fromImage": "ghcr.io/org/app", "tag": "1.2"})
    check_allowed("POST", "/images/create", {"fromImage": "nginx", "tag": "sha256:" + "a" * 64})
    check_allowed("POST", "/build/prune")
    check_allowed("DELETE", f"/containers/{'a' * 64}", {"v": "0"})
    check_allowed("DELETE", f"/images/sha256:{'a' * 64}", {"noprune": "0"})
    check_allowed("DELETE", f"/networks/{'a' * 64}")
    check_allowed("GET", "/containers/abc/logs",
                  {"stdout": "1", "stderr": "1", "tail": "5000", "timestamps": "1",
                   "since": "1", "until": "2", "follow": "1"})


def test_allowlist_gate17_rejections() -> None:
    full = "a" * 64
    rejected = [
        ("POST", "/containers/abc/exec", None),
        ("POST", "/exec/abc/start", None),
        ("POST", "/containers/create", None),
        ("POST", "/containers/abc/kill", None),
        ("POST", "/containers/abc/stop", {"t": "301"}),
        ("POST", "/containers/abc/stop", {"signal": "KILL"}),
        ("POST", "/containers/prune", None),
        ("POST", "/images/prune", None),
        ("POST", "/networks/prune", None),
        ("POST", "/volumes/prune", None),
        ("POST", "/system/prune", None),
        ("POST", "/build", None),
        ("POST", "/build/prune", {"all": "1"}),
        ("POST", "/images/create", {"fromImage": "nginx"}),
        ("POST", "/images/create", {"fromSrc": "http://x", "tag": "1"}),
        ("POST", "/images/create", {"fromImage": "Bad/Upper", "tag": "1"}),
        ("POST", "/images/create", {"fromImage": "nginx", "tag": "1", "platform": "x"}),
        ("DELETE", f"/volumes/{full}", None),
        ("DELETE", "/volumes/data", None),
        ("DELETE", f"/containers/{full}", {"force": "1"}),
        ("DELETE", f"/containers/{full}", {"v": "1"}),
        ("DELETE", "/containers/app-web", None),
        ("DELETE", "/containers/prune", None),
        ("DELETE", f"/images/sha256:{full}", {"force": "1"}),
        ("DELETE", "/images/nginx", None),
        ("DELETE", "/networks/bridge", None),
        ("PUT", "/containers/abc/archive", None),
        ("GET", "/containers/abc/logs", {"stdout": "1", "stderr": "1"}),
        ("GET", "/containers/abc/logs", {"stdout": "1", "stderr": "1", "tail": "5001"}),
        ("GET", "/containers/abc/logs", {"stdout": "1", "stderr": "1", "tail": "all"}),
        ("POST", "/containers/../start", None),
        ("POST", "/containers/abc/../../build/prune", None),
        ("DELETE", f"/containers/%2e%2e/{full}", None),
        ("POST", "//build/prune", None),
    ]
    for method, path, params in rejected:
        with pytest.raises(DockerNotAllowed):
            check_allowed(method, path, params)


def test_image_reference_validation() -> None:
    assert parse_image_reference("nginx") == ("nginx", "latest")
    assert parse_image_reference("nginx:1.27-alpine") == ("nginx", "1.27-alpine")
    assert parse_image_reference("localhost:5000/team/app:v1") == ("localhost:5000/team/app", "v1")
    registry = "Registry.Example.com/a/b"
    assert parse_image_reference(registry) == (registry, "latest")
    digest = "sha256:" + "f" * 64
    assert parse_image_reference(f"ghcr.io/org/app@{digest}") == ("ghcr.io/org/app", digest)
    assert parse_image_reference(f"app:1@{digest}") == ("app", digest)
    for bad in ("", " nginx", "NGINX", "Org/app", "nginx:", "nginx:-x", "nginx:" + "a" * 129,
                "a//b", "a/../b", "nginx@sha256:short", "nginx@md5:" + "a" * 32,
                "-nginx", "nginx:tág", "x" * 300, None, 5, "nginx;rm", "a b"):
        with pytest.raises(ValueError):
            parse_image_reference(bad)


# ----- logs -----------------------------------------------------------------


def test_log_decoder_demuxes_frames_split_across_chunks() -> None:
    body = (
        frame(1, b"2026-11-08T10:00:00.123456789Z hello\n2026-11-08T10:00:01Z wor")
        + frame(2, b"2026-11-08T10:00:02Z oops\r\n")
        + frame(1, b"ld\n")
        + frame(1, b"2026-11-08T10:00:03Z no newline")
    )
    decoder = LogDecoder(tty=False)
    lines = []
    for index in range(0, len(body), 5):
        lines += decoder.feed(body[index : index + 5])
    lines += decoder.flush()
    assert lines == [
        {"ts": "2026-11-08T10:00:00.123456789Z", "stream": "stdout", "text": "hello"},
        {"ts": "2026-11-08T10:00:02Z", "stream": "stderr", "text": "oops"},
        {"ts": "2026-11-08T10:00:01Z", "stream": "stdout", "text": "world"},
        {"ts": "2026-11-08T10:00:03Z", "stream": "stdout", "text": "no newline"},
    ]


def test_log_decoder_tty_is_plain_stdout() -> None:
    decoder = LogDecoder(tty=True, timestamps=False)
    raw = b"2026-11-08T10:00:00Z \x01\x00\x00\x00 not a frame\n2026-11-08T10:00:01Z b\n"
    lines = decoder.feed(raw) + decoder.flush()
    assert [line["stream"] for line in lines] == ["stdout", "stdout"]
    assert lines[0]["text"] == "\x01\x00\x00\x00 not a frame"
    assert all(line["ts"] is None for line in lines)


def test_logs_endpoint_json_validation_and_tty(tmp_path: Path) -> None:
    fake = FakeDocker()
    fake.log_body = frame(1, b"2026-11-08T10:00:00Z a\n") + frame(2, b"2026-11-08T10:00:01Z b\n")
    with make_app(tmp_path, fake) as client:
        response = signed(client, "GET", "/v1/docker/containers/app-web/logs?tail=10&since=5")
        assert response.status_code == 200
        assert response.json() == {
            "lines": [
                {"ts": "2026-11-08T10:00:00Z", "stream": "stdout", "text": "a"},
                {"ts": "2026-11-08T10:00:01Z", "stream": "stderr", "text": "b"},
            ],
            "truncated": False,
        }
        logs_call = [c for c in docker_calls(fake) if "/logs" in c][-1]
        assert logs_call.startswith(f"GET /containers/{APP_ID}/logs?")
        assert "tail=10" in logs_call and "since=5" in logs_call and "follow" not in logs_call

        fake.log_body = b"2026-11-08T10:00:00Z plain tty\n"
        tty = signed(client, "GET", "/v1/docker/containers/tty-box/logs").json()
        assert tty["lines"] == [{"ts": "2026-11-08T10:00:00Z", "stream": "stdout",
                                 "text": "plain tty"}]

        for query in ("tail=5001", "tail=-1", "tail=all", "since=x", "follow=2",
                      "since=10&until=5", "timestamps=yes"):
            bad = signed(client, "GET", f"/v1/docker/containers/app-web/logs?{query}")
            assert bad.status_code == 422, query
        assert signed(client, "GET", "/v1/docker/containers/missing/logs").status_code == 404
        assert signed(client, "GET", "/v1/docker/containers/..x/logs").status_code == 422


def test_logs_json_is_capped(tmp_path: Path) -> None:
    fake = FakeDocker()
    line = b"2026-11-08T10:00:00Z " + b"x" * 60000 + b"\n"
    fake.log_body = b"".join(frame(1, line) for _ in range(120))  # ~7 MB
    with make_app(tmp_path, fake) as client:
        payload = signed(client, "GET", "/v1/docker/containers/app-web/logs").json()
    assert payload["truncated"] is True
    assert 0 < sum(len(item["text"]) for item in payload["lines"]) <= 5 * 1024 * 1024


def test_logs_follow_streams_ndjson_and_stops_at_cap(tmp_path: Path) -> None:
    fake = FakeDocker()

    async def endless():
        yield frame(1, b"2026-11-08T10:00:00Z first\n")
        yield frame(2, b"2026-11-08T10:00:01Z second\n")
        await asyncio.sleep(3600)  # Docker would keep the stream open forever
        yield b""

    fake.log_stream = endless
    with make_app(tmp_path, fake, log_follow_max_seconds=0.5) as client:
        response = signed(client, "GET", "/v1/docker/containers/app-web/logs?follow=1&tail=0")
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("application/x-ndjson")
        lines = [json.loads(item) for item in response.text.splitlines()]
    assert [line["text"] for line in lines] == ["first", "second"]
    assert [line["stream"] for line in lines] == ["stdout", "stderr"]
    assert any("follow=1" in call for call in docker_calls(fake))


# ----- metrics ----------------------------------------------------------------


def test_cpu_sampler_delta_and_net_dev() -> None:
    sampler = host_metrics.CpuSampler()
    assert sampler.sample("cpu  100 0 100 800 0 0 0 0 0 0\n") is None
    assert sampler.sample("cpu  150 0 150 850 50 0 0 0 0 0\n") == 50.0
    assert sampler.sample("cpu  150 0 150 850 50 0 0 0 0 0\n") is None  # no time passed
    assert sampler.sample("garbage") is None
    net = (
        "Inter-|   Receive |  Transmit\n face |bytes packets\n"
        "    lo: 999 1 0 0 0 0 0 0 999 1 0 0 0 0 0 0\n"
        "  eth0: 1000 5 0 0 0 0 0 0 2000 6 0 0 0 0 0 0\n"
        "  ens4: 10 1 0 0 0 0 0 0 20 1 0 0 0 0 0 0\n"
        "docker0: 77 1 0 0 0 0 0 0 77 1 0 0 0 0 0 0\n"
        "veth12: 55 1 0 0 0 0 0 0 55 1 0 0 0 0 0 0\n"
    )
    assert host_metrics.parse_net_dev(net) == (1010, 2020)
    assert host_metrics.parse_net_dev("") is None


def test_net_dev_prefers_host_pid1_namespace(tmp_path: Path) -> None:
    (tmp_path / "net").mkdir()
    (tmp_path / "net" / "dev").write_text("eth0: 1 0 0 0 0 0 0 0 1 0 0 0 0 0 0 0\n")
    assert host_metrics.net_dev_path(tmp_path) == tmp_path / "net" / "dev"
    (tmp_path / "1" / "net").mkdir(parents=True)
    (tmp_path / "1" / "net" / "dev").write_text("eth0: 9 0 0 0 0 0 0 0 9 0 0 0 0 0 0 0\n")
    assert host_metrics.net_dev_path(tmp_path) == tmp_path / "1" / "net" / "dev"


def fake_cgroup(root: Path) -> None:
    root.mkdir(parents=True, exist_ok=True)
    (root / "cgroup.controllers").write_text("cpu io memory pids\n")
    systemd = root / "system.slice" / f"docker-{DOKPLOY_ID}.scope"
    systemd.mkdir(parents=True)
    (systemd / "cpu.stat").write_text("usage_usec 123456\nuser_usec 100000\nsystem_usec 23456\n")
    (systemd / "memory.current").write_text("1048576\n")
    (systemd / "memory.max").write_text("max\n")
    (systemd / "io.stat").write_text(
        "8:0 rbytes=100 wbytes=200 rios=1 wios=2 dbytes=0 dios=0\n"
        "8:16 rbytes=1 wbytes=2 rios=1 wios=1 dbytes=0 dios=0\n"
    )
    cgroupfs = root / "docker" / APP_ID
    cgroupfs.mkdir(parents=True)
    (cgroupfs / "cpu.stat").write_text("usage_usec 42\n")
    (cgroupfs / "memory.current").write_text("2048\n")
    (cgroupfs / "memory.max").write_text("268435456\n")


def test_cgroup_parsing_both_layouts(tmp_path: Path) -> None:
    root = tmp_path / "cgroup"
    fake_cgroup(root)
    assert cgroups.available(root)
    assert cgroups.read_container(root, DOKPLOY_ID) == {
        "cpu_usage_usec": 123456, "mem_bytes": 1048576, "mem_limit_bytes": None,
        "io_read_bytes": 101, "io_write_bytes": 202,
    }
    assert cgroups.read_container(root, APP_ID) == {
        "cpu_usage_usec": 42, "mem_bytes": 2048, "mem_limit_bytes": 268435456,
        "io_read_bytes": 0, "io_write_bytes": 0,
    }
    assert cgroups.read_container(root, STOPPED_ID) is None
    assert cgroups.read_container(root, "../../etc") is None
    assert not cgroups.available(tmp_path / "missing")


def test_metrics_endpoint(tmp_path: Path) -> None:
    fake = FakeDocker()
    root = tmp_path / "cgroup"
    fake_cgroup(root)
    with make_app(tmp_path, fake, cgroup_dir=root) as client:
        first = signed(client, "GET", "/v1/metrics").json()
        assert first["host"]["cpu_percent"] is None
        assert first["host"]["load1"] == 0.4
        assert first["host"]["mem_total_bytes"] == 1024000
        assert first["host"]["mem_used_bytes"] == 768000
        for disk in first["host"]["disks"]:  # empty where os.statvfs is missing (Windows)
            assert set(disk) == {"path", "total_bytes", "used_bytes"}
        assert first["host"]["net_rx_bytes"] is None
        items = {item["name"]: item for item in first["containers"]}
        assert set(items) == {"dokploy", "app-web"}
        assert items["dokploy"]["protected"] is True
        assert items["dokploy"]["cpu_usage_usec"] == 123456
        assert items["app-web"]["protected"] is False
        assert items["app-web"]["mem_limit_bytes"] == 268435456

        (tmp_path / "proc" / "stat").write_text("cpu  200 0 100 900 0 0 0 0 0 0\n")
        second = signed(client, "GET", "/v1/metrics").json()
        assert second["host"]["cpu_percent"] == 50.0
    # Container list is cached for 10 s: one Docker list for two metrics calls.
    assert docker_calls(fake).count("GET /containers/json?all=1") == 1

    with make_app(tmp_path, FakeDocker()) as client:  # no cgroup mount
        assert signed(client, "GET", "/v1/metrics").json()["containers"] is None


# ----- actions ----------------------------------------------------------------


def test_container_actions_and_protected_guard(tmp_path: Path) -> None:
    fake = FakeDocker()
    with make_app(tmp_path, fake) as client:
        ok = signed(client, "POST", "/v1/docker/containers/app-web/restart",
                    {"timeout_seconds": 20})
        assert ok.status_code == 200 and ok.json() == {"ok": True}
        assert signed(client, "POST", "/v1/docker/containers/app-web/start").json() == {"ok": True}

        blocked = signed(client, "POST", "/v1/docker/containers/dokploy/stop", {})
        assert blocked.status_code == 403 and blocked.json() == {"error": "protected"}
        allowed = signed(client, "POST", "/v1/docker/containers/dokploy/stop",
                         {"allow_protected": True, "timeout_seconds": 0})
        assert allowed.status_code == 200

        for body in ({"timeout_seconds": 301}, {"timeout_seconds": -1},
                     {"timeout_seconds": "10"}, {"timeout_seconds": True},
                     {"allow_protected": "yes"}, [1]):
            bad = signed(client, "POST", "/v1/docker/containers/app-web/stop", body)
            assert bad.status_code == 422, body
        assert signed(client, "POST", "/v1/docker/containers/missing/stop").status_code == 404
        assert signed(client, "POST", "/v1/docker/containers/app-web/kill").status_code == 405
        # Unsigned or tampered POSTs never reach Docker.
        assert client.post("/v1/docker/containers/app-web/stop", json={}).status_code == 401
        headers = signing.sign_headers(KEY, "POST", "/v1/docker/containers/app-web/stop", b"{}")
        tampered = client.post("/v1/docker/containers/app-web/stop",
                               content=b'{"allow_protected":true}', headers=headers)
        assert tampered.status_code == 401
        assert client.post("/v1/docker/summary").status_code == 405
        assert client.delete("/v1/docker/containers/app-web").status_code == 405

    posts = docker_calls(fake, "POST")
    assert posts == [
        f"POST /containers/{APP_ID}/restart?t=20",
        f"POST /containers/{APP_ID}/start",
        f"POST /containers/{DOKPLOY_ID}/stop?t=0",
    ]


# ----- image pull -------------------------------------------------------------


def test_image_pull(tmp_path: Path) -> None:
    fake = FakeDocker()
    digest = "sha256:" + "e" * 64
    fake.pull_lines = [
        {"status": "Pulling from library/nginx", "id": "1.27"},
        {"status": "Downloading", "progressDetail": {"current": 1, "total": 2}},
        {"status": f"Digest: {digest}"},
        {"status": "Status: Downloaded newer image for nginx:1.27"},
    ]
    with make_app(tmp_path, fake) as client:
        ok = signed(client, "POST", "/v1/docker/images/pull", {"image": "nginx:1.27"})
        assert ok.status_code == 200 and ok.json() == {"ok": True, "digest": digest}

        fake.pull_lines = [{"status": "Pulling"},
                           {"errorDetail": {"message": "manifest unknown"},
                            "error": "manifest unknown"}]
        failed = signed(client, "POST", "/v1/docker/images/pull", {"image": "nginx:nope"})
        assert failed.status_code == 502
        assert failed.json() == {"error": "pull_failed", "message": "manifest unknown"}

        for body in ({"image": "UPPER"}, {"image": ""}, {}, {"image": ["x"]}):
            assert signed(client, "POST", "/v1/docker/images/pull", body).status_code == 422
    assert docker_calls(fake, "POST") == [
        "POST /images/create?fromImage=nginx&tag=1.27",
        "POST /images/create?fromImage=nginx&tag=nope",
    ]


# ----- prune ------------------------------------------------------------------


def test_prune_plan_exclusions() -> None:
    rules = ProtectionRules.default()
    all_targets = ["containers", "images", "build_cache", "networks"]
    plan = build_plan(targets=all_targets, images_mode="dangling", containers=CONTAINERS,
                      images=IMAGES, networks=NETWORKS, df=DF, rules=rules)
    # Only the plain stopped container: not running, swarm task or protected ones.
    assert plan["containers"] == [{"id": STOPPED_ID, "name": "old-job", "size_bytes": 50}]
    # Dangling only, and never an image used by any container (even a stopped one).
    assert [item["id"] for item in plan["images"]] == [IMG_DANGLING, IMG_FAILS]
    # Default, used, swarm-scoped and protected networks are excluded.
    assert plan["networks"] == [{"id": NET_FREE, "name": "leftover"}]
    assert plan["build_cache_bytes"] == 70
    assert plan["reclaimable_bytes"] == 50 + 300 + 600 + 70
    assert "volumes" not in plan

    unused = build_plan(targets=["images"], images_mode="unused", containers=CONTAINERS,
                        images=IMAGES, networks=NETWORKS, df=DF, rules=rules)
    ids = [item["id"] for item in unused["images"]]
    assert ids == [IMG_DANGLING, IMG_UNUSED_TAGGED, IMG_FAILS]
    assert IMG_DOKPLOY not in ids and IMG_USED not in ids and IMG_STOPPED_USE not in ids
    assert unused["containers"] == [] and unused["networks"] == []
    assert unused["token"] != plan["token"]
    # The token ignores volatile byte counts but changes with the items.
    assert plan_token(all_targets, "dangling", {**plan, "build_cache_bytes": 1}) == plan["token"]
    assert plan_token(all_targets, "dangling", {**plan, "networks": []}) != plan["token"]


def test_prune_preview_execute_and_token_mismatch(tmp_path: Path) -> None:
    fake = FakeDocker()
    request = {"targets": ["containers", "images", "networks", "build_cache"],
               "images_mode": "dangling"}
    with make_app(tmp_path, fake) as client:
        preview = signed(client, "POST", "/v1/docker/prune/preview", request)
        assert preview.status_code == 200
        plan = preview.json()
        assert len(plan["token"]) == 64
        assert {"containers", "images", "networks", "build_cache_bytes",
                "reclaimable_bytes"} <= set(plan)

        wrong = signed(client, "POST", "/v1/docker/prune", {**request, "token": "0" * 64})
        assert wrong.status_code == 409 and wrong.json() == {"error": "plan_changed"}
        assert docker_calls(fake, "DELETE") == []

        # Something changed between preview and execute -> refused.
        fake.images.append({"Id": "sha256:" + "7" * 64, "RepoTags": [], "Size": 1})
        changed = signed(client, "POST", "/v1/docker/prune", {**request, "token": plan["token"]})
        assert changed.status_code == 409
        fake.images.pop()

        result = signed(client, "POST", "/v1/docker/prune", {**request, "token": plan["token"]})
        assert result.status_code == 200
        body = result.json()
        assert body["removed"] == {"containers": 1, "images": 1, "networks": 1}
        assert body["reclaimed_bytes"] == 50 + 300 + 70
        assert body["errors"] == [{"type": "image", "id": IMG_FAILS,
                                   "message": "conflict: image is in use"}]

        for bad in ({"targets": ["volumes"]}, {"targets": []},
                    {"targets": ["images"], "images_mode": "all"},
                    {"targets": ["images", "images"]}):
            assert signed(client, "POST", "/v1/docker/prune/preview", bad).status_code == 422
        assert signed(client, "POST", "/v1/docker/prune", request).status_code == 422

    assert docker_calls(fake, "DELETE") == [
        f"DELETE /containers/{STOPPED_ID}?v=0",
        f"DELETE /images/{IMG_DANGLING}?noprune=0",
        f"DELETE /images/{IMG_FAILS}?noprune=0",
        f"DELETE /networks/{NET_FREE}",
    ]
    assert docker_calls(fake, "POST") == ["POST /build/prune"]
    # No bulk prune endpoint and nothing touching volumes was ever called.
    assert not any("/prune" in call and "build" not in call for call in docker_calls(fake))
    assert not any("/volumes" in call for call in docker_calls(fake))


def test_docker_client_refuses_disallowed_writes_before_sending() -> None:
    fake = FakeDocker()
    client = DockerClient(transport=httpx.MockTransport(fake.handler))

    async def scenario() -> None:
        with pytest.raises(DockerNotAllowed):
            await client.remove_container("app-web")  # names are not accepted for DELETE
        with pytest.raises(DockerNotAllowed):
            await client.remove_image("nginx")
        with pytest.raises(DockerNotAllowed):
            await client.container_action("abc", "kill", 10)
        with pytest.raises(DockerNotAllowed):
            await client._request("POST", "/containers/prune")
        await client.aclose()

    asyncio.run(scenario())
    assert fake.seen == []


def test_logs_follow_stops_when_client_disconnects(tmp_path: Path, monkeypatch) -> None:
    from mrk_control_plane.agent import app as agent_app_module

    monkeypatch.setattr(agent_app_module, "_DISCONNECT_POLL_SECONDS", 0.05)
    fake = FakeDocker()
    closed = asyncio.Event()

    async def endless():
        try:
            yield frame(1, b"2026-11-08T10:00:00Z hi\n")
            await asyncio.sleep(3600)
            yield b""
        finally:
            closed.set()

    fake.log_stream = endless
    client = make_app(tmp_path, fake, log_follow_max_seconds=60)
    app = client.app
    path = "/v1/docker/containers/app-web/logs"
    query = "follow=1"
    headers = signing.sign_headers(KEY, "GET", f"{path}?{query}", b"")
    scope = {
        "type": "http", "asgi": {"version": "3.0", "spec_version": "2.4"},
        "http_version": "1.1", "method": "GET", "scheme": "http", "path": path,
        "raw_path": path.encode(), "query_string": query.encode(), "root_path": "",
        "headers": [(k.lower().encode(), v.encode()) for k, v in headers.items()],
        "client": ("127.0.0.1", 1), "server": ("agent", 7070),
    }
    sent: list[dict] = []

    async def scenario() -> None:
        loop = asyncio.get_running_loop()
        state = {"calls": 0, "gone_at": loop.time() + 0.2}

        async def receive():
            # Like a server: a queued disconnect is returned at once, else it blocks.
            state["calls"] += 1
            if state["calls"] == 1:
                return {"type": "http.request", "body": b"", "more_body": False}
            if loop.time() < state["gone_at"]:
                await asyncio.sleep(state["gone_at"] - loop.time())
            return {"type": "http.disconnect"}

        async def send(message):
            sent.append(message)

        await asyncio.wait_for(app(scope, receive, send), timeout=10)

    asyncio.run(scenario())
    body = b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")
    assert json.loads(body.splitlines()[0])["text"] == "hi"
    assert closed.is_set()
