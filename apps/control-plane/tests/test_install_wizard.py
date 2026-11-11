"""Add-service wizard (docs/44): catalog, generated files, pairing and connect."""

from __future__ import annotations

import re
from pathlib import Path

import httpx
import pytest
import yaml
from fastapi.testclient import TestClient
from mrk_control_plane.agent import main as agent_main
from mrk_control_plane.agent import signing
from mrk_control_plane.agent.app import AgentConfig, create_agent_app
from mrk_control_plane.config import Settings
from mrk_control_plane.firewall import main as firewall_main
from mrk_control_plane.main import create_app
from mrk_control_plane.modules import host_agent, install_catalog

from .helpers import login_owner
from .test_host_agent import fake_docker_handler, fake_proc


def env_value(env_text: str, name: str) -> str:
    match = re.search(rf"^{name}=(.*)$", env_text, re.MULTILINE)
    assert match, name
    return match.group(1)


@pytest.fixture
def agent_backend(tmp_path: Path, monkeypatch):
    """Route the panel's agent calls to an in-process agent built from a given key."""
    state: dict[str, object] = {"app": None}

    class Transport(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            app = state["app"]
            if app is None:
                raise httpx.ConnectError("refused", request=request)
            return await httpx.ASGITransport(app=app).handle_async_request(request)

    def start(key: bytes) -> None:
        proc, root = fake_proc(tmp_path / "agent")
        config = AgentConfig(key=key, proc_dir=proc, root_paths=[root])
        state["app"] = create_agent_app(
            config, docker_transport=httpx.MockTransport(fake_docker_handler([]))
        )

    monkeypatch.setattr(host_agent, "TRANSPORT_FACTORY", Transport)
    for name in ("MRK_AGENT_URL", "MRK_AGENT_KEY_FILE", "MRK_FIREWALL_URL",
                 "MRK_FIREWALL_KEY_FILE", "MRK_IMAGE_REGISTRY", "MRK_IMAGE_TAG"):
        monkeypatch.delenv(name, raising=False)
    state["start"] = start
    return state


def test_catalog_lists_ready_and_planned_services(tmp_path: Path, agent_backend) -> None:
    with TestClient(create_app(Settings.for_test(tmp_path / "cp"))) as client:
        assert client.get("/api/v1/install/catalog").status_code == 401
        login_owner(client)
        items = {item["id"]: item for item in client.get("/api/v1/install/catalog").json()["items"]}
    ready = {key for key, value in items.items() if value["availability"] == "ready"}
    planned = {key for key, value in items.items() if value["availability"] == "planned"}
    assert ready == {"agent", "dns", "firewall", "s3", "npm", "pypi", "git", "registry"}
    assert planned == set()
    assert items["agent"]["image"] == "ghcr.io/seniorkian/mrk-agent:latest"
    assert items["agent"]["connection"] == "not_connected"
    assert items["agent"]["methods"] == ["dokploy", "coolify", "compose"]
    assert items["npm"]["image"] == "ghcr.io/seniorkian/mrk-npm:latest"


def test_bundle_then_connect_pairs_the_agent(tmp_path: Path, agent_backend, monkeypatch) -> None:
    monkeypatch.setenv("MRK_IMAGE_TAG", "1.2.3")
    with TestClient(create_app(Settings.for_test(tmp_path / "cp"))) as client:
        headers = {"X-CSRF-Token": str(login_owner(client)["csrf_token"])}
        # Connecting before any files exist has no key to pair with.
        early = client.post("/api/v1/install/agent/connect", headers=headers, json={})
        assert early.status_code == 409 and early.json()["error"]["code"] == "bundle_required"
        assert client.post("/api/v1/install/agent/bundle", json={}).status_code == 403  # CSRF

        bad = client.post("/api/v1/install/agent/bundle", headers=headers,
                          json={"env": {"MRK_DOCKER_GID": "x; rm"}})
        assert bad.status_code == 422
        unknown = client.post("/api/v1/install/agent/bundle", headers=headers,
                              json={"env": {"MRK_AGENT_USER": "0:0"}})
        assert unknown.status_code == 422

        bundle = client.post("/api/v1/install/agent/bundle", headers=headers,
                             json={"env": {"MRK_DOCKER_GID": "988"}, "method": "dokploy"}).json()
        assert bundle["image"] == "ghcr.io/seniorkian/mrk-agent:1.2.3"
        assert env_value(bundle["env"], "MRK_IMAGE") == bundle["image"]
        assert env_value(bundle["env"], "MRK_DOCKER_GID") == "988"
        key_text = env_value(bundle["env"], "MRK_AGENT_PAIRING_KEY")
        assert len(signing.decode_key(key_text)) == 32
        compose = yaml.safe_load(bundle["compose"])
        assert compose["networks"]["mrk-net"] == {"name": "mrk-net", "external": True}

        # The agent seeds its key file from the env the wizard generated.
        key, created = agent_main.load_or_create_key(tmp_path / "agent-state", key_text)
        assert created is False and key == signing.decode_key(key_text)

        # Not running yet: the connection is saved but unreachable.
        first = client.post("/api/v1/install/agent/connect", headers=headers, json={}).json()
        assert first["connection"] == "unreachable"

        agent_backend["start"](key)
        second = client.post("/api/v1/install/agent/connect", headers=headers, json={}).json()
        assert second == {"id": "agent", "connection": "connected"}
        status = client.get("/api/v1/agent/status").json()
        assert status["configured"] is True and status["url"] == "http://mrk-agent:7070"

        items = {item["id"]: item for item in client.get("/api/v1/install/catalog").json()["items"]}
        assert items["agent"]["connection"] == "connected"
        # The key never leaves the panel except in the one bundle response.
        assert key_text not in client.get("/api/v1/install/catalog").text


def test_unknown_services_cannot_be_bundled(tmp_path: Path, agent_backend) -> None:
    with TestClient(create_app(Settings.for_test(tmp_path / "cp"))) as client:
        headers = {"X-CSRF-Token": str(login_owner(client)["csrf_token"])}
        unknown = client.post("/api/v1/install/nope/bundle", headers=headers, json={})
        assert unknown.status_code == 404


def test_dns_bundle_has_no_pairing_key(tmp_path: Path, agent_backend) -> None:
    with TestClient(create_app(Settings.for_test(tmp_path / "cp"))) as client:
        headers = {"X-CSRF-Token": str(login_owner(client)["csrf_token"])}
        bundle = client.post("/api/v1/install/dns/bundle", headers=headers,
                             json={"env": {"MRK_DNS_LISTEN": "10.0.0.5:53"}}).json()
    assert bundle["pairing"] is False and "PAIRING" not in bundle["env"]
    assert env_value(bundle["env"], "MRK_DNS_LISTEN") == "10.0.0.5:53"
    compose = yaml.safe_load(bundle["compose"])
    assert compose["volumes"]["mrk-dns-run"] == {"name": "mrk-dns-run", "external": True}


def test_every_ready_template_is_valid_compose() -> None:
    for item in install_catalog.INSTALLABLE:
        # Git and the registry run official pinned images (tests/test_git_registry.py).
        if item.availability != "ready" or item.upstream_image:
            continue
        compose = yaml.safe_load(item.compose)
        (service,) = compose["services"].values()
        assert service["image"].startswith("${MRK_IMAGE:?")
        assert service["read_only"] is True and service["cap_drop"] == ["ALL"]
        published = {
            "s3": "${MRK_S3_BIND:-127.0.0.1}:${MRK_S3_PORT:-9000}:9000",
            "npm": "${MRK_NPM_BIND:-127.0.0.1}:${MRK_NPM_PORT:-4873}:4873",
            "pypi": "${MRK_PYPI_BIND:-127.0.0.1}:${MRK_PYPI_PORT:-3141}:3141",
        }
        if item.id in published:
            # Only the client-facing port, and on loopback unless the operator changes it.
            assert service["ports"] == [published[item.id]]
        else:
            assert "ports" not in service  # nothing is published to the Internet
        if item.pairing_env:
            assert f"${{{item.pairing_env}:?" in item.compose


def test_seeded_key_replaces_an_older_key_file(tmp_path: Path) -> None:
    old, _ = firewall_main.load_or_create_key(tmp_path)
    new_text = signing.encode_key(bytes(range(32)))
    key, created = firewall_main.load_or_create_key(tmp_path, new_text)
    assert key == bytes(range(32)) and key != old and created is False
    assert firewall_main.load_or_create_key(tmp_path) == (key, False)


def test_image_registry_and_tag_are_validated(monkeypatch) -> None:
    monkeypatch.setenv("MRK_IMAGE_REGISTRY", "registry.example.com:5000/team/")
    monkeypatch.setenv("MRK_IMAGE_TAG", "v1.0.0")
    assert install_catalog.image_ref("dns") == "registry.example.com:5000/team/mrk-dns:v1.0.0"
    monkeypatch.setenv("MRK_IMAGE_REGISTRY", "evil\nregistry")
    monkeypatch.setenv("MRK_IMAGE_TAG", "bad tag")
    assert install_catalog.image_ref("dns") == "ghcr.io/seniorkian/mrk-dns:latest"


def test_native_panel_gets_loopback_and_host_folder_variants(monkeypatch) -> None:
    monkeypatch.setenv("MRK_PANEL_RUNTIME", "native")
    for item in install_catalog.INSTALLABLE:
        # Git and the registry run official pinned images (tests/test_git_registry.py).
        if item.availability != "ready" or item.upstream_image:
            continue
        text = install_catalog.compose_for(item)
        compose = yaml.safe_load(text)
        (service,) = compose["services"].values()
        # A native panel is not on Docker's network, so no stack may need mrk-net.
        assert "mrk-net" not in (compose.get("networks") or {})
        assert "mrk-net" not in (service.get("networks") or {})
        if item.id == "agent":
            assert service["ports"] == ["127.0.0.1:7070:7070"]
        if item.id == "s3":
            assert "127.0.0.1:9001:9001" in service["ports"]
        if item.id == "dns":
            assert "/run/mrk-dns:/run/mrk-dns" in service["volumes"]
        if item.id == "firewall":
            assert "/run/mrk-firewall:/run/mrk-firewall" in service["volumes"]
    agent = install_catalog.INSTALL_INDEX["agent"]
    assert install_catalog.default_url(agent) == "http://127.0.0.1:7070"
    monkeypatch.delenv("MRK_PANEL_RUNTIME")
    assert install_catalog.compose_for(agent) == agent.compose
