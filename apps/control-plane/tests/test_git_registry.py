# ruff: noqa: S105, S106 - throwaway test passwords and tokens
"""Git (Gitea) and the Docker image registry (Zot) as wizard services (docs/46)."""

from __future__ import annotations

import json
import re
from pathlib import Path

import bcrypt
import httpx
import pytest
import yaml
from fastapi.testclient import TestClient
from mrk_control_plane.config import Settings
from mrk_control_plane.main import create_app
from mrk_control_plane.modules import git_service, install_catalog, registry_service

from .helpers import login_owner


def env_value(text: str, name: str) -> str:
    match = re.search(rf"^{name}=(.*)$", text, re.MULTILINE)
    assert match, name
    return match.group(1)


class FakeGitea:
    def __init__(self, password: str) -> None:
        self.password = password
        self.repos: list[dict] = []
        self.users: list[dict] = []
        self.calls: list[tuple[str, str, dict]] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        body = json.loads(request.content) if request.content else {}
        self.calls.append((request.method, path, body))
        auth = request.headers.get("authorization", "")
        if path == "/api/v1/users/mrk-panel/tokens":
            import base64

            expected = "Basic " + base64.b64encode(f"mrk-panel:{self.password}".encode()).decode()
            if auth != expected:
                return httpx.Response(401, json={"message": "unauthorized"})
            return httpx.Response(201, json={"sha1": "tok-123", "name": body["name"]})
        if auth != "token tok-123":
            return httpx.Response(401, json={"message": "no token"})
        if path == "/api/v1/version":
            return httpx.Response(200, json={"version": "1.24.7"})
        if path == "/api/v1/repos/search":
            return httpx.Response(200, json={"ok": True, "data": self.repos})
        if path == "/api/v1/user/repos" and request.method == "POST":
            repo = {"id": 1, "name": body["name"], "full_name": f"mrk-panel/{body['name']}",
                    "owner": {"login": "mrk-panel"}, "private": body["private"],
                    "clone_url": "http://git/x.git", "ssh_url": "ssh://git/x.git"}
            self.repos.append(repo)
            return httpx.Response(201, json=repo)
        if path == "/api/v1/repos/migrate":
            name = body["repo_name"]
            repo = {"id": 2, "name": name, "full_name": f"mrk-panel/{name}",
                    "owner": {"login": "mrk-panel"}, "mirror": True, "private": body["private"]}
            self.repos.append(repo)
            return httpx.Response(201, json=repo)
        if path == "/api/v1/admin/users" and request.method == "POST":
            user = {"id": 5, "login": body["username"], "email": body["email"]}
            self.users.append(user)
            return httpx.Response(201, json=user)
        if path.startswith("/api/v1/repos/") and request.method == "DELETE":
            return httpx.Response(204)
        return httpx.Response(404, json={"message": "not found"})


@pytest.fixture
def app_client(tmp_path: Path, monkeypatch):
    for name in ("MRK_PANEL_RUNTIME", "MRK_HOST_DATA_DIR"):
        monkeypatch.delenv(name, raising=False)
    settings = Settings.for_test(tmp_path / "cp")
    with TestClient(create_app(settings)) as client:
        headers = {"X-CSRF-Token": str(login_owner(client)["csrf_token"])}
        yield client, headers, settings


def test_git_bundle_connect_and_manage(app_client, monkeypatch) -> None:
    client, headers, _settings = app_client
    assert client.get("/api/v1/git/status").json()["connected"] is False
    bundle = client.post("/api/v1/install/git/bundle", headers=headers, json={
        "env": {"MRK_GIT_ROOT_URL": "https://git.example.com/"}}).json()
    password = env_value(bundle["env"], "MRK_GIT_ADMIN_PASSWORD")
    compose = yaml.safe_load(bundle["compose"])
    assert set(compose["services"]) == {"mrk-git-init", "mrk-git"}
    assert "@sha256:" in compose["services"]["mrk-git"]["image"]

    fake = FakeGitea(password)
    monkeypatch.setattr(git_service, "TRANSPORT_FACTORY", lambda: httpx.MockTransport(fake))
    result = client.post("/api/v1/install/git/connect", headers=headers, json={}).json()
    assert result == {"id": "git", "connection": "connected"}
    status = client.get("/api/v1/git/status").json()
    assert status["version"] == "1.24.7" and status["public_url"] == "https://git.example.com/"
    # Only the token is kept; the bootstrap password is never stored by the git module.
    state = (_settings.data_dir / "control-plane" / "git.json").read_text()
    assert password not in state and "tok-123" not in state

    created = client.post("/api/v1/git/repos", headers=headers,
                          json={"name": "app", "private": True})
    assert created.status_code == 201 and created.json()["full_name"] == "mrk-panel/app"
    mirror = client.post("/api/v1/git/mirrors", headers=headers, json={
        "source_url": "https://github.com/octocat/Hello-World", "name": "hello",
        "private": True, "interval": "8h"})
    assert mirror.status_code == 201 and mirror.json()["mirror"] is True
    for bad in ("http://github.com/x", "https://127.0.0.1/x", "https://localhost/x",
                "https://user:pw@github.com/x"):
        rejected = client.post("/api/v1/git/mirrors", headers=headers,
                               json={"source_url": bad, "name": "x", "private": True})
        assert rejected.status_code == 422, bad
    listed = client.get("/api/v1/git/repos").json()
    assert {item["name"] for item in listed["items"]} == {"app", "hello"}

    user = client.post("/api/v1/git/users", headers=headers,
                       json={"login": "sara", "email": "sara@example.com"}).json()
    assert user["user"]["login"] == "sara" and len(user["password"]) >= 16

    wrong = client.request("DELETE", "/api/v1/git/repos/mrk-panel/app", headers=headers,
                           json={"confirmation": "app"})
    assert wrong.status_code == 422
    deleted = client.request("DELETE", "/api/v1/git/repos/mrk-panel/app", headers=headers,
                             json={"confirmation": "mrk-panel/app"})
    assert deleted.json() == {"ok": True}
    assert client.post("/api/v1/git/repos", json={"name": "x"}).status_code == 403  # CSRF


def test_git_connect_with_wrong_password_reports_unreachable(app_client, monkeypatch) -> None:
    client, headers, _settings = app_client
    client.post("/api/v1/install/git/bundle", headers=headers, json={})
    monkeypatch.setattr(git_service, "TRANSPORT_FACTORY",
                        lambda: httpx.MockTransport(FakeGitea("other-password")))
    result = client.post("/api/v1/install/git/connect", headers=headers, json={}).json()
    assert result["connection"] == "unreachable"
    assert client.get("/api/v1/git/status").json()["connected"] is False


def test_registry_files_users_and_settings(app_client, monkeypatch) -> None:
    client, headers, settings = app_client
    bundle = client.post("/api/v1/install/registry/bundle", headers=headers, json={
        "env": {"MRK_REGISTRY_PUBLIC": "registry.example.com"}}).json()
    compose = yaml.safe_load(bundle["compose"])
    assert compose["volumes"]["mrk-registry-config"] == {"name": "mrk-registry-config",
                                                         "external": True}
    folder = settings.data_dir / "registry"
    config = json.loads((folder / "config.json").read_text())
    sync = config["extensions"]["sync"]["registries"]
    assert sync[-1]["content"][0]["destination"] == "/"  # Docker Hub last, at the root
    assert sync[-1]["urls"][0] == "https://registry-1.docker.io"
    assert config["http"]["accessControl"]["adminPolicy"]["users"] == ["mrk-panel"]

    seen: list[httpx.Request] = []

    def zot(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.url.path == "/v2/":
            return httpx.Response(200, json={})
        if request.url.path == "/v2/_catalog":
            return httpx.Response(200, json={"repositories": ["library/nginx", "team/app"]})
        if request.url.path == "/v2/team/app/tags/list":
            return httpx.Response(200, json={"name": "team/app", "tags": ["2.0", "1.0"]})
        return httpx.Response(404)

    monkeypatch.setattr(registry_service, "TRANSPORT_FACTORY", lambda: httpx.MockTransport(zot))
    result = client.post("/api/v1/install/registry/connect", headers=headers, json={}).json()
    assert result == {"id": "registry", "connection": "connected"}
    assert client.get("/api/v1/registry/status").json()["endpoint"] == "registry.example.com"
    assert [item["name"] for item in client.get("/api/v1/registry/repos").json()["items"]] == [
        "library/nginx", "team/app"]
    assert client.get("/api/v1/registry/repos/team/app/tags").json()["tags"] == ["1.0", "2.0"]
    assert all(request.headers["authorization"].startswith("Basic ") for request in seen)

    created = client.post("/api/v1/registry/users", headers=headers,
                          json={"name": "ci", "access": "push"}).json()
    htpasswd = (folder / "htpasswd").read_text().splitlines()
    entry = next(line for line in htpasswd if line.startswith("ci:"))
    assert bcrypt.checkpw(created["password"].encode(), entry.split(":", 1)[1].encode())
    assert any(line.startswith("mrk-panel:$2b$") for line in htpasswd)
    policies = json.loads((folder / "config.json").read_text())[
        "http"]["accessControl"]["repositories"]["**"]["policies"]
    assert {"users": ["ci"], "actions": ["read", "create", "update"]} in policies
    state = (settings.data_dir / "control-plane" / "registry.json").read_text()
    assert created["password"] not in state

    duplicate = client.post("/api/v1/registry/users", headers=headers,
                            json={"name": "ci", "access": "pull"})
    assert duplicate.status_code == 409

    saved = client.put("/api/v1/registry/settings", headers=headers, json={
        "anonymous_pull": True, "upstreams": [
            {"id": "docker.io", "name": "Docker Hub", "destination": "/",
             "urls": ["https://docker.arvancloud.ir", "https://registry-1.docker.io"],
             "enabled": True},
            {"id": "ghcr.io", "destination": "/ghcr.io", "urls": ["https://ghcr.io"]}]})
    assert saved.status_code == 200, saved.text
    assert [item["id"] for item in saved.json()["upstreams"]] == ["ghcr.io", "docker.io"]
    config = json.loads((folder / "config.json").read_text())
    assert config["http"]["accessControl"]["repositories"]["**"]["anonymousPolicy"] == ["read"]
    for bad in ({"urls": ["http://x.example"]}, {"urls": []}, {"destination": "no-slash"}):
        upstream = {"id": "x", "destination": "/x", "urls": ["https://x.example"], **bad}
        rejected = client.put("/api/v1/registry/settings", headers=headers,
                              json={"anonymous_pull": False, "upstreams": [upstream]})
        assert rejected.status_code == 422, bad

    # The settings route accepts public repositories (0.3.0 rejected the field).
    public = client.put("/api/v1/registry/settings", headers=headers, json={
        "anonymous_pull": False, "public_repositories": ["seniorkian/**"], "upstreams": []})
    assert public.status_code == 200, public.text
    assert public.json()["public_repositories"] == ["seniorkian/**"]
    config = json.loads((folder / "config.json").read_text())
    assert config["http"]["accessControl"]["repositories"]["seniorkian/**"]["anonymousPolicy"] == [
        "read"]

    assert client.request("DELETE", "/api/v1/registry/users/ci", headers=headers).json() == {
        "ok": True}
    assert "ci:" not in (folder / "htpasswd").read_text()
    help_text = client.get("/api/v1/registry/help").json()
    assert "registry.example.com" in help_text["daemon_mirror_json"]


def test_git_and_registry_templates_are_hardened() -> None:
    for service_id in ("git", "registry"):
        item = install_catalog.INSTALL_INDEX[service_id]
        compose = yaml.safe_load(install_catalog.compose_for(item))
        for name, service in compose["services"].items():
            assert service["read_only"] is True and service["cap_drop"] == ["ALL"], name
            assert "no-new-privileges:true" in service["security_opt"], name
            assert "@sha256:" in service["image"], name
            for port in service.get("ports") or []:
                assert port.startswith("${MRK_") and ":-127.0.0.1}" in port, port


def test_registry_public_repositories_open_only_those() -> None:
    from mrk_control_plane.modules import registry_service

    settings = registry_service.validate_settings({
        "anonymous_pull": False, "public_repositories": ["seniorkian/**", "Tools/cli"],
        "upstreams": []})
    assert settings["public_repositories"] == ["seniorkian/**", "tools/cli"]
    users = [{"name": "ci", "access": "push"}]
    config = registry_service.render_config(settings, users)
    repos = config["http"]["accessControl"]["repositories"]
    assert "anonymousPolicy" not in repos["**"]  # the mirrors stay private
    assert repos["seniorkian/**"]["anonymousPolicy"] == ["read"]
    assert repos["seniorkian/**"]["policies"] == repos["**"]["policies"]
    for bad in ("**", "*", "../x", "a b", "/abs"):
        with pytest.raises(registry_service.RegistryError):
            registry_service.validate_settings({"public_repositories": [bad], "upstreams": []})
