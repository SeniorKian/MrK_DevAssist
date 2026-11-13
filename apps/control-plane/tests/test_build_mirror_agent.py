from __future__ import annotations

import json
from pathlib import Path

import httpx
from fastapi.testclient import TestClient
from mrk_control_plane.agent import build_facts
from mrk_control_plane.agent.app import AgentConfig, create_agent_app
from mrk_control_plane.agent.signing import sign_headers

KEY = b"k" * 32


def _root(tmp_path: Path) -> Path:
    root = tmp_path / "host"
    (root / "etc" / "docker").mkdir(parents=True)
    (root / "etc" / "devassist").mkdir(parents=True)
    (root / "etc" / "docker" / "daemon.json").write_text(json.dumps({
        "registry-mirrors": ["https://reg.example.com", "not a url", "ftp://x"],
        "dns": ["172.17.0.1"], "secret-ish": "x"}), encoding="utf-8")
    (root / "etc" / "devassist" / "build-mirror.json").write_text(json.dumps({
        "version": "1", "applied_at": 1700000000, "registry": "https://reg.example.com",
        "daemon_mirror": True, "daemon_reloaded": True, "test": "ok",
        "test_detail": "<script>bad</script>", "unknown": "dropped"}), encoding="utf-8")
    return root


def _docker(request: httpx.Request) -> httpx.Response:
    if request.url.path.endswith("/version"):
        return httpx.Response(200, json={"ApiVersion": "1.47", "Version": "28.5.2"})
    if request.url.path.endswith("/info"):
        return httpx.Response(200, json={"ServerVersion": "28.5.2", "RegistryConfig": {
            "Mirrors": ["https://reg.example.com/"]}})
    if request.url.path.endswith("/containers/json"):
        return httpx.Response(200, json=[
            {"Names": ["/buildx_buildkit_mrk-mirror0"], "State": "running"}])
    return httpx.Response(404, json={"message": "no"})


def test_build_facts_are_whitelisted(tmp_path: Path) -> None:
    facts = build_facts.collect(_root(tmp_path))
    assert facts["daemon"] == {"present": True, "valid": True,
                               "mirrors": ["https://reg.example.com"]}
    marker = facts["marker"]
    assert marker["registry"] == "https://reg.example.com" and marker["test"] == "ok"
    assert "test_detail" not in marker and "unknown" not in marker
    assert build_facts.collect(None) == {"host_root": False, "daemon": None, "marker": None}
    empty = tmp_path / "empty"
    empty.mkdir()
    assert build_facts.collect(empty)["daemon"]["present"] is False
    assert build_facts.collect(empty)["marker"] is None
    assert build_facts.builder_state([{"Names": ["/other"]}]) == "absent"


def test_build_facts_route_is_signed_and_reads_docker(tmp_path: Path) -> None:
    root = _root(tmp_path)
    config = AgentConfig(key=KEY, root_paths=[root], host_root=root,
                         docker_socket=str(tmp_path / "docker.sock"))
    app = create_agent_app(config, docker_transport=httpx.MockTransport(_docker))
    with TestClient(app) as client:
        path = "/v1/build-mirror/facts"
        assert client.get(path).status_code == 401
        body = client.get(path, headers=sign_headers(KEY, "GET", path, b"")).json()
        assert body["docker"] is True
        assert body["live_mirrors"] == ["https://reg.example.com"]
        assert body["builder"] == "running" and body["docker_version"] == "28.5.2"
        assert body["daemon"]["mirrors"] == ["https://reg.example.com"]
