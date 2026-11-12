"""npm and PyPI in their own containers (docs/44): wizard connect, config hand-off, routing."""

from __future__ import annotations

import asyncio
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient
from mrk_control_plane import process_control, remote_services
from mrk_control_plane.config import Settings
from mrk_control_plane.main import create_app
from mrk_control_plane.modules import install_catalog
from mrk_control_plane.modules.domains_routing import RoutingError, own_stack

from .helpers import login_owner


@pytest.fixture
def registry_server():
    """A stand-in for Verdaccio and devpi: answers their health paths."""

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            ok = self.path in {"/-/ping", "/+status"}
            self.send_response(200 if ok else 404)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b"{}")

        def log_message(self, *_args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield server.server_address[1]
    server.shutdown()


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for name in ("MRK_PANEL_RUNTIME", "MRK_HOST_DATA_DIR", "MRK_NPM_ENABLED"):
        monkeypatch.delenv(name, raising=False)


def test_connect_npm_and_pypi_turns_them_on(tmp_path: Path, registry_server) -> None:
    settings = Settings.for_test(tmp_path / "cp")
    with TestClient(create_app(settings)) as client:
        headers = {"X-CSRF-Token": str(login_owner(client)["csrf_token"])}
        items = {i["id"]: i for i in client.get("/api/v1/install/catalog").json()["items"]}
        assert items["npm"]["connection"] == "not_connected"
        assert items["pypi"]["connection"] == "not_connected"
        assert settings.npm_enabled is False

        # The bundle already writes Verdaccio's config into the shared npm folder.
        bundle = client.post("/api/v1/install/npm/bundle", headers=headers, json={}).json()
        compose = yaml.safe_load(bundle["compose"])
        assert compose["volumes"]["mrk-npm-data"] == {"name": "mrk-npm-data", "external": True}
        generated = settings.data_dir / "npm" / "config" / "generated.yaml"
        text = generated.read_text(encoding="utf-8")
        assert "storage: /data/npm/storage" in text and "listen: 0.0.0.0:4873" in text
        assert "/opt/verdaccio/plugins" in text  # quota plugin, as inside mrk-npm
        assert json.loads(generated.with_name("generated.env.json").read_text()) is not None

        url = f"http://127.0.0.1:{registry_server}"
        npm = client.post("/api/v1/install/npm/connect", headers=headers, json={"url": url})
        assert npm.json() == {"id": "npm", "connection": "connected"}, npm.text
        pypi = client.post("/api/v1/install/pypi/connect", headers=headers, json={"url": url})
        assert pypi.json() == {"id": "pypi", "connection": "connected"}, pypi.text

        # The live settings follow at once (no restart), and the readiness never
        # depends on a registry in another container.
        assert settings.npm_enabled is True and settings.npm_health_port == registry_server
        assert settings.pypi_enabled is True and settings.pypi_health_host == "127.0.0.1"
        services = {i["id"]: i for i in client.get("/api/v1/services").json()["items"]}
        assert services["npm"]["state"] == "running"
        assert services["pypi"]["state"] == "running"

        bad = client.post("/api/v1/install/npm/connect", headers=headers,
                          json={"url": "ftp://x:1"})
        assert bad.status_code == 422

    # A restart keeps them on.
    again = Settings.for_test(tmp_path / "cp")
    remote_services.apply(again)
    assert again.npm_enabled is True and again.pypi_enabled is True


def test_reload_rewrites_the_npm_config_for_a_separate_verdaccio(tmp_path: Path) -> None:
    settings = Settings.for_test(tmp_path / "cp")
    remote_services.connect(settings, "npm", "mrk-npm", 4873)
    target = settings.data_dir / "npm" / "config" / "generated.yaml"
    assert not target.exists()
    assert process_control.restart_verdaccio_if_managed() is True
    assert target.is_file()


def test_repeated_npm_config_write_does_not_restart_verdaccio(tmp_path: Path) -> None:
    settings = Settings.for_test(tmp_path / "cp")
    target = remote_services.write_npm_config(settings.data_dir)
    env_path = target.with_name(remote_services.ENV_FILE)
    fixed = 1_700_000_000_123_456_789
    os.utime(target, ns=(fixed, fixed))
    os.utime(env_path, ns=(fixed, fixed))
    config_mtime = target.stat().st_mtime_ns
    env_mtime = env_path.stat().st_mtime_ns

    assert remote_services.write_npm_config(settings.data_dir) == target
    assert target.stat().st_mtime_ns == config_mtime
    assert env_path.stat().st_mtime_ns == env_mtime


def test_npm_environment_is_written_before_the_yaml_is_replaced(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The runner restarts Verdaccio as soon as the YAML changes, so it must
    # never see a new YAML next to the previous environment file.
    settings = Settings.for_test(tmp_path / "cp")
    replaced: list[str] = []
    real_replace = os.replace

    def recording_replace(source: object, target: object) -> None:
        replaced.append(Path(str(target)).name)
        real_replace(source, target)

    monkeypatch.setattr(os, "replace", recording_replace)
    remote_services.write_npm_config(settings.data_dir)
    assert replaced == [remote_services.ENV_FILE, "generated.yaml"]


def test_npm_pypi_targets_are_validated(tmp_path: Path) -> None:
    settings = Settings.for_test(tmp_path / "cp")
    for host, port in (("bad host", 4873), ("mrk-npm", 0), ("x" * 300, 1)):
        with pytest.raises(ValueError):
            remote_services.connect(settings, "npm", host, port)
    assert remote_services.load(settings.data_dir) == {}


def test_domains_route_to_the_service_own_stack(tmp_path: Path) -> None:
    settings = Settings.for_test(tmp_path / "cp")
    remote_services.connect(settings, "npm", "mrk-npm", 4873)
    own = own_stack(settings.data_dir, "npm")
    assert own == {"host": "mrk-npm", "port": 4873, "service_name": "mrk-npm", "compose_id": None}
    assert own_stack(settings.data_dir, "pypi") is None

    from mrk_control_plane.modules.domains_routing import Routing

    class Ctx:
        data_dir = settings.data_dir

    routing = Routing(Ctx(), lambda: {"cert_resolver": "letsencrypt"})
    detected = {"dokploy_service_type": "compose", "dokploy_service_id": "panel-compose"}
    with pytest.raises(RoutingError) as caught:
        asyncio.run(routing._dokploy_body("npm", "npm.example.com", True, detected))  # noqa: SLF001
    assert caught.value.code == "service_in_own_stack"
    steps = routing.instructions("npm", "npm.example.com", True, detected)
    assert steps["dokploy"]["service_name"] == "mrk-npm" and steps["dokploy"]["port"] == 4873

    # Installed by the panel through Dokploy: the domain goes on that compose.
    state = settings.data_dir / "control-plane" / "install.json"
    state.write_text(json.dumps({"npm": {"deployment": {
        "target": "dokploy", "compose_id": "cmp-npm", "service_name": "mrk-npm"}}}))
    body = asyncio.run(
        routing._dokploy_body("npm", "npm.example.com", True, detected))  # noqa: SLF001
    assert body["composeId"] == "cmp-npm" and body["serviceName"] == "mrk-npm"
    assert body["port"] == 4873


def test_own_stack_compose_is_found_when_the_recorded_one_is_gone(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A stack re-created in Dokploy (stale id) or pasted by hand (no id) is found by name."""
    from mrk_control_plane.modules import dokploy
    from mrk_control_plane.modules.dokploy_client import DokployError
    from mrk_control_plane.modules.domains_routing import Routing

    settings = Settings.for_test(tmp_path / "cp")
    remote_services.connect(settings, "npm", "mrk-npm", 4873)
    files = {
        "cmp-panel": "services:\n  mrk-panel:\n    image: x\n",
        "cmp-new": "services:\n  mrk-npm:  # registry\n    image: x\n",
    }
    asked: list[str] = []

    class FakeDokploy:
        async def call(self, procedure: str, params: dict[str, str]) -> dict[str, str]:
            assert procedure == "compose.one"
            asked.append(params["composeId"])
            if params["composeId"] not in files:
                raise DokployError("dokploy_rejected", 409, "Service not found")
            return {"composeFile": files[params["composeId"]]}

        async def _projects_raw(self) -> list[dict[str, object]]:
            return [{"projectId": "p1", "name": "DevAssist", "environments": [{
                "name": "production",
                "compose": [{"composeId": key, "name": "panel" if key == "cmp-panel" else "npm"}
                            for key in files],
            }]}]

    monkeypatch.setattr(dokploy, "ACTIVE_SERVICE", FakeDokploy())

    class Ctx:
        data_dir = settings.data_dir

    routing = Routing(Ctx(), lambda: {"cert_resolver": "letsencrypt"})
    detected = {"dokploy_service_type": "compose", "dokploy_service_id": "cmp-panel"}
    state = settings.data_dir / "control-plane" / "install.json"
    for recorded in ("cmp-deleted", None):
        state.write_text(json.dumps({"npm": {"deployment": {
            "target": "dokploy", "compose_id": recorded, "service_name": "mrk-npm"}}}))
        routing._own_compose.clear()  # noqa: SLF001
        body = asyncio.run(
            routing._dokploy_body("npm", "npm.example.com", True, detected))  # noqa: SLF001
        assert body["composeId"] == "cmp-new" and body["serviceName"] == "mrk-npm"

    # Remembered: the next domain within a minute asks Dokploy nothing at all ...
    asked.clear()
    asyncio.run(routing._dokploy_body("npm", "cdn.example.com", True, detected))  # noqa: SLF001
    assert asked == []
    # ... and later checks only the Compose it found.
    routing._own_hit.clear()  # noqa: SLF001
    asyncio.run(routing._dokploy_body("npm", "cdn.example.com", True, detected))  # noqa: SLF001
    assert asked == ["cmp-new"]


def test_native_registry_stacks_use_the_host_data_path(monkeypatch) -> None:
    monkeypatch.setenv("MRK_PANEL_RUNTIME", "native")
    monkeypatch.setenv("MRK_HOST_DATA_DIR", "/srv/devassist")
    npm = yaml.safe_load(install_catalog.compose_for(install_catalog.INSTALL_INDEX["npm"],
                                                     Path("/data")))
    (service,) = npm["services"].values()
    assert service["volumes"] == ["/srv/devassist/npm:/data/npm"]
    assert "volumes" not in npm and "networks" not in npm
    pypi = yaml.safe_load(install_catalog.compose_for(install_catalog.INSTALL_INDEX["pypi"],
                                                      Path("/data")))
    (service,) = pypi["services"].values()
    assert service["network_mode"] == "host" and "ports" not in service
    assert "127.0.0.1:3142" in service["environment"]["MRK_PYPI_UPSTREAM_URL"]
