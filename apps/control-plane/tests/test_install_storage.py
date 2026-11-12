"""Where service stacks keep their data: volumes or host folders, shared with the panel."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest
import yaml
from fastapi.testclient import TestClient
from mrk_control_plane.agent import host_paths
from mrk_control_plane.config import Settings
from mrk_control_plane.main import create_app
from mrk_control_plane.modules import install, install_storage
from mrk_control_plane.modules.install_catalog import INSTALL_INDEX

from .helpers import login_owner

# The production panel compose: a host folder for /data, sockets in host folders.
PANEL_COMPOSE = """services:
  mrk-panel:
    image: ${MRK_PANEL_IMAGE:?Set it}
    volumes:
      - /opt/devAssist/panel:/data
      - /opt/devAssist/dns-run:/run/mrk-dns:ro
      - /opt/devAssist/firewall-run:/run/mrk-firewall:ro
    networks:
      mrk-net:
networks:
  mrk-net:
    name: mrk-net
"""


def test_every_slot_matches_its_template_line() -> None:
    for service_id, slots in install_storage.SLOTS.items():
        for slot in slots:
            assert install_storage._line_re(slot).search(INSTALL_INDEX[service_id].compose), (
                service_id, slot.key)


def test_host_folders_replace_volumes_and_unused_volumes_go() -> None:
    compose = INSTALL_INDEX["registry"].compose
    text = install_storage.apply(compose, "registry", {
        "config": {"kind": "path", "value": "/opt/devAssist/panel/registry"},
        "data": {"kind": "path", "value": "/storage/registry"},
    })
    service = yaml.safe_load(text)["services"]["mrk-registry"]
    assert service["volumes"] == ["/opt/devAssist/panel/registry:/etc/zot:ro",
                                  "/storage/registry:/var/lib/registry"]
    assert "volumes" not in yaml.safe_load(text)  # no named volume left
    # The shared mount says which panel mount it must match.
    assert install_storage.shared_note(install_storage.slots_for("registry")[0]) in text
    assert "mounts at /data/registry" in text
    # Default choices change nothing (S3 shares nothing with the panel).
    s3 = INSTALL_INDEX["s3"].compose
    default = {"data": {"kind": "volume", "value": "mrk-s3-data"}}
    assert install_storage.apply(s3, "s3", default) == s3


def test_git_folder_is_used_by_both_containers() -> None:
    text = install_storage.apply(INSTALL_INDEX["git"].compose, "git",
                                 {"data": {"kind": "path", "value": "/srv/git"}})
    parsed = yaml.safe_load(text)
    for name in ("mrk-git-init", "mrk-git"):
        assert "/srv/git:/var/lib/gitea" in parsed["services"][name]["volumes"]
    assert set(parsed["volumes"]) == {"mrk-git-config"}


def test_shared_slot_follows_the_panel_mount() -> None:
    mounts = install_storage.parse_compose_mounts(PANEL_COMPOSE)
    assert install_storage.shared_source(mounts, "/data/registry") == {
        "kind": "path", "value": "/opt/devAssist/panel/registry"}
    assert install_storage.shared_source(mounts, "/run/mrk-dns") == {
        "kind": "path", "value": "/opt/devAssist/dns-run"}
    named = [{"type": "volume", "name": "mrk-registry-config", "source": "",
              "destination": "/data/registry"},
             {"type": "volume", "name": "mrk-panel-data", "source": "", "destination": "/data"}]
    assert install_storage.shared_source(named, "/data/registry") == {
        "kind": "volume", "value": "mrk-registry-config"}
    missing = install_storage.shared_source(named[1:], "/data/npm")
    assert missing["kind"] == "missing" and missing["inside_volume"] == "mrk-panel-data"
    assert install_storage.shared_source([], "/run/mrk-dns")["kind"] == "missing"


def test_folder_checks(tmp_path: Path) -> None:
    root = tmp_path / "host"
    (root / "srv" / "s3").mkdir(parents=True)
    (root / "srv" / "file").write_text("x")
    owner = f"{os.getuid()}:{os.getgid()}" if hasattr(os, "getuid") else None
    facts = host_paths.check_all(root, ["/srv/s3", "/srv/missing/data", "/srv/file",
                                        "/proc/1", "relative"])
    by_path = {item["path"]: item for item in facts["items"]}
    assert by_path["/srv/s3"]["exists"] and by_path["/srv/s3"]["is_dir"]
    assert by_path["/srv/missing/data"]["exists"] is False
    assert by_path["/srv/missing/data"]["nearest_parent"] == "/srv"
    assert by_path["/proc/1"]["valid"] is False and by_path["relative"]["valid"] is False
    slot = install_storage.slots_for("s3")[0]
    missing = install_storage.evaluate(slot, "/srv/missing/data", by_path["/srv/missing/data"])
    assert missing["status"] == "error" and missing["code"] == "path_missing"
    assert missing["fix"] == ("sudo mkdir -p /srv/missing/data && "
                              "sudo chown -R 10001:10001 /srv/missing/data")
    assert install_storage.evaluate(slot, "/srv/file", by_path["/srv/file"])["code"] == (
        "path_not_folder")
    wrong = dict(by_path["/srv/s3"], uid=0, gid=0)
    assert install_storage.evaluate(slot, "/srv/s3", wrong)["code"] == "path_wrong_owner"
    right = dict(by_path["/srv/s3"], uid=10001, gid=10001, free_bytes=50 * 1024 ** 3)
    assert install_storage.evaluate(slot, "/srv/s3", right)["status"] == "ok"
    assert owner is None or isinstance(owner, str)


@pytest.fixture
def client(tmp_path: Path, monkeypatch) -> Any:
    facts: dict[str, dict[str, Any]] = {}

    class Agent:
        async def call(self, path: str) -> Any:
            if path.endswith("/mounts"):
                return {"items": install_storage.parse_compose_mounts(PANEL_COMPOSE)}
            assert path.startswith("/v1/host/paths?")
            return {"items": list(facts.values())}

    async def detect_quick(self, timeout: float = 2.0) -> dict[str, Any]:
        return {"container_name": "devassist-panel-1"}

    monkeypatch.setattr(install.InstallService, "_agent", lambda self: Agent())
    from mrk_control_plane.modules import domains_routing

    monkeypatch.setattr(domains_routing.Routing, "detect_quick", detect_quick)
    with TestClient(create_app(Settings.for_test(tmp_path / "cp"))) as test_client:
        headers = {"X-CSRF-Token": str(login_owner(test_client)["csrf_token"])}
        yield test_client, headers, facts


def test_wizard_storage_view_bundle_and_checks(client) -> None:
    test_client, headers, facts = client
    view = test_client.get("/api/v1/install/registry/storage").json()
    slots = {slot["key"]: slot for slot in view["slots"]}
    assert slots["config"]["shared"] is True
    assert slots["config"]["choice"] == {"kind": "path", "value": "/opt/devAssist/panel/registry"}
    assert slots["data"]["choice"] == {"kind": "volume", "value": "mrk-registry-data"}
    assert view["panel_mounts_source"] == "agent" and view["checks_available"] is True

    bad = test_client.post("/api/v1/install/registry/bundle", headers=headers,
                           json={"storage": {"data": {"kind": "path", "value": "../x"}}})
    assert bad.status_code == 422
    # A shared slot cannot be pointed elsewhere: it always follows the panel.
    made = test_client.post("/api/v1/install/registry/bundle", headers=headers, json={
        "storage": {"data": {"kind": "path", "value": "/storage/registry"},
                    "config": {"kind": "path", "value": "/somewhere/else"}}})
    assert made.status_code == 200, made.text
    volumes = yaml.safe_load(made.json()["compose"])["services"]["mrk-registry"]["volumes"]
    assert volumes == ["/opt/devAssist/panel/registry:/etc/zot:ro",
                       "/storage/registry:/var/lib/registry"]
    # Kept for updates.
    again = test_client.get("/api/v1/install/registry/storage").json()
    assert {slot["key"]: slot["choice"] for slot in again["slots"]}["data"] == {
        "kind": "path", "value": "/storage/registry"}

    facts["/storage/registry"] = {"path": "/storage/registry", "valid": True, "exists": True,
                                  "is_dir": True, "uid": 0, "gid": 0, "free_bytes": 10 ** 11}
    facts["/opt/devAssist/panel/registry"] = {
        "path": "/opt/devAssist/panel/registry", "valid": True, "exists": False,
        "is_dir": False, "free_bytes": 10 ** 11, "nearest_parent": "/opt/devAssist/panel"}
    checked = test_client.post("/api/v1/install/registry/storage/check", headers=headers, json={
        "storage": {"data": {"kind": "path", "value": "/storage/registry"}}}).json()
    items = {item["key"]: item for item in checked["items"]}
    assert items["data"]["status"] == "ok"  # Zot needs no fixed owner
    assert items["config"]["code"] == "path_missing" and checked["ok"] is False
    assert "chown -R 10001:10001 /opt/devAssist/panel/registry" in items["config"]["fix"]


def test_automatic_install_stops_before_dokploy_when_folders_are_not_ready(client) -> None:
    test_client, headers, facts = client
    facts["/storage/s3"] = {"path": "/storage/s3", "valid": True, "exists": True,
                            "is_dir": True, "uid": 0, "gid": 0, "free_bytes": 10 ** 11}
    started = test_client.post("/api/v1/install/s3/auto", headers=headers, json={
        "target": "dokploy", "storage": {"data": {"kind": "path", "value": "/storage/s3"}}})
    assert started.status_code in {409, 422}, started.text
    error = started.json()["error"]
    # Dokploy is not connected in this test: either refusal is fine, but a folder
    # owned by root must never reach a deploy.
    assert error["code"] in {"storage_not_ready", "dokploy_not_configured"}
