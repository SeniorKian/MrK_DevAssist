"""«My space» (docs/43): workspaces, plans, ownership isolation, quotas, view-as, S3 keys."""

from __future__ import annotations

import json
import os
import re
import socket
import threading
import time
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient
from mrk_control_plane import dns_client, process_control
from mrk_control_plane.config import Settings
from mrk_control_plane.main import create_app
from mrk_control_plane.modules import my_dns, my_packages, s3_client, services
from mrk_control_plane.modules import tenancy as tenancy_module
from mrk_control_plane.modules.s3_policy import validate_policy, workspace_policy
from mrk_control_plane.verdaccio_runtime import build_runtime_config

from .helpers import login_owner
from .test_dns import TOKEN as DNS_TOKEN
from .test_dns import FakeEngine as FakeDns
from .test_s3_admin import FakeEngine as FakeS3

PASSWORD = "a-long-user-password-123"  # noqa: S105 - test-only fixture
MY = "/api/v1/my"
ADMIN = "/api/v1/admin"


# ----------------------------------------------------------------------------- fixtures


@pytest.fixture
def env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> dict[str, Any]:
    for name in list(os.environ):
        if name.startswith(("MRK_DNS_", "MRK_DOMAINS_", "MRK_AGENT_", "MRK_DOKPLOY_")):
            monkeypatch.delenv(name, raising=False)
    run = tmp_path / "run"
    run.mkdir()
    socket_file, token_file = run / "admin.sock", run / "admin.token"
    socket_file.write_bytes(b"")
    token_file.write_text(DNS_TOKEN + "\n", encoding="utf-8")
    monkeypatch.setenv("MRK_DNS_ADMIN_SOCKET", str(socket_file))
    monkeypatch.setenv("MRK_DNS_ADMIN_TOKEN_FILE", str(token_file))
    monkeypatch.setenv("MRK_DOKPLOY_POLL_SECONDS", "0")
    links = tmp_path / "links"
    links.mkdir()
    monkeypatch.setenv("MRK_S3_LINKS_ROOT", str(links))
    monkeypatch.setattr(process_control, "supervisor_available", lambda: False)
    monkeypatch.setattr(services, "PROBES", None)
    dns = FakeDns()
    monkeypatch.setattr(dns_client, "TRANSPORT_FACTORY", dns.transport)
    s3 = FakeS3(tmp_path / "cp")
    monkeypatch.setattr(s3_client, "TRANSPORT_FACTORY", lambda: httpx.MockTransport(s3.handler))
    monkeypatch.setattr(my_packages, "RELOAD_NPM", lambda: True)
    txt: dict[str, list[str]] = {}
    monkeypatch.setattr(my_dns, "LOOKUP", lambda name, rtype: txt.get(f"{rtype}:{name}", []))
    return {"dns": dns, "s3": s3, "txt": txt, "cp": tmp_path / "cp"}


class Space:
    """The owner (admin) client plus helpers to create «my space» users."""

    def __init__(self, client: TestClient, env: dict[str, Any]) -> None:
        self.client = client
        self.env = env
        self.headers = {"X-CSRF-Token": str(login_owner(client)["csrf_token"])}

    def admin(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        return self.client.request(method, ADMIN + path, headers=self.headers, **kwargs)

    def settings(self, **values: Any) -> None:
        response = self.admin("PUT", "/tenancy/settings", json=values)
        assert response.status_code == 200, response.text

    def user(self, username: str, role: str = "customer", email: str | None = None) -> User:
        created = self.client.post("/api/v1/users", headers=self.headers, json={
            "username": username, "password": PASSWORD, "role": role,
            **({"email": email} if email else {})})
        assert created.status_code == 201, created.text
        return User(self, username)

    def workspace_patch(self, workspace_id: str, **body: Any) -> dict[str, Any]:
        response = self.admin("PATCH", f"/workspaces/{workspace_id}", json=body)
        assert response.status_code == 200, response.text
        return response.json()


class User:
    def __init__(self, space: Space, username: str) -> None:
        self.space = space
        self.username = username
        self.client = TestClient(space.client.app)
        login = self.client.post("/api/v1/auth/login",
                                 json={"username": username, "password": PASSWORD})
        assert login.status_code == 200, login.text
        self.id = int(login.json()["user"]["id"])
        self.headers = {"X-CSRF-Token": str(login.json()["csrf_token"])}
        me = self.get("/me")
        assert me.status_code == 200, me.text
        self.personal = me.json()["current"]
        self.slug = next(item["slug"] for item in me.json()["workspaces"]
                         if item["id"] == self.personal)

    def call(self, method: str, path: str, *, ws: str | None = None,
             **kwargs: Any) -> httpx.Response:
        headers = dict(self.headers)
        headers.update(kwargs.pop("headers", {}))
        if ws:
            headers["X-Workspace"] = ws
        return self.client.request(method, MY + path, headers=headers, **kwargs)

    def get(self, path: str, **kwargs: Any) -> httpx.Response:
        return self.call("GET", path, **kwargs)

    def post(self, path: str, body: Any = None, **kwargs: Any) -> httpx.Response:
        return self.call("POST", path, json=body if body is not None else {}, **kwargs)


@pytest.fixture
def space(env: dict[str, Any], tmp_path: Path):
    app = create_app(Settings.for_test(tmp_path / "cp"))
    with TestClient(app) as client:
        result = Space(client, env)
        result.settings(enabled=True, verify_domains=False)
        yield result


def unlimited(space: Space, user: User) -> None:
    space.workspace_patch(user.personal, plan_id="unlimited")


def zone(user: User, name: str, ws: str | None = None) -> dict[str, Any]:
    response = user.post("/dns/zones", {"name": name, "template_id": None}, ws=ws)
    assert response.status_code == 201, response.text
    return response.json()


def bucket(user: User, name: str, ws: str | None = None) -> None:
    response = user.post("/s3/buckets", {"name": name}, ws=ws)
    assert response.status_code == 201, response.text


def code(response: httpx.Response) -> str:
    return str(response.json()["error"]["code"])


# ----------------------------------------------------------------------------- off = unchanged


def test_disabled_leaves_everything_as_before(env: dict[str, Any], tmp_path: Path) -> None:
    app = create_app(Settings.for_test(tmp_path / "cp"))
    with TestClient(app) as client:
        headers = {"X-CSRF-Token": str(login_owner(client)["csrf_token"])}
        response = client.get(f"{MY}/me")
        assert response.status_code == 404 and code(response) == "tenancy_disabled"
        assert client.get("/api/v1/auth/registration-status").json() == {"enabled": False}
        roles = [item["id"] for item in client.get("/api/v1/roles").json()["items"]]
        assert "customer" not in roles
        # The admin area exists to prepare plans before switching it on.
        plans = client.get(f"{ADMIN}/plans").json()["items"]
        assert [item["id"] for item in plans] == ["basic", "pro", "unlimited"]
        assert client.put(f"{ADMIN}/tenancy/settings", headers=headers,
                          json={"enabled": True}).json()["enabled"] is True
        assert "customer" in [item["id"] for item in client.get("/api/v1/roles").json()["items"]]
        snapshot = json.loads((tmp_path / "cp" / "modules" / "s3" / "config.json").read_text())
        assert snapshot["quota_groups"] == [] and snapshot["bucket_hosts"] == {}


def test_customer_has_no_server_permission(space: Space) -> None:
    alice = space.user("alice")
    for path in ("/api/v1/users", "/api/v1/dns/zones", "/api/v1/s3/buckets", f"{ADMIN}/plans",
                 "/api/v1/audit-events"):
        assert alice.client.get(path).status_code == 403, path
    me = alice.get("/me").json()
    assert me["user"]["role"] == "customer"
    personal = me["workspaces"][0]
    assert personal["kind"] == "personal" and personal["role"] == "owner"
    assert personal["plan"]["id"] == "basic" and personal["limits"]["features"]["dns"] is True
    assert personal["usage"]["dns_zones"] == 0


# ----------------------------------------------------------------------------- plans (admin)


def test_plan_crud_and_guards(space: Space) -> None:
    created = space.admin("POST", "/plans", json={
        "id": "tiny", "name_fa": "کوچک", "name_en": "Tiny", "features": {"dns": True},
        "quotas": {"dns_zones": 1, "dns_record_types": ["a", "TXT"]}})
    assert created.status_code == 201, created.text
    plan = created.json()
    assert plan["features"]["s3"] is False and plan["quotas"]["dns_record_types"] == ["A", "TXT"]
    bad = space.admin("POST", "/plans", json={"name_fa": "x", "name_en": "x",
                                              "features": {"root_shell": True}})
    assert bad.status_code == 422
    bad = space.admin("POST", "/plans", json={"name_fa": "x", "name_en": "x",
                                              "quotas": {"dns_zones": -1}})
    assert bad.status_code == 422
    updated = space.admin("PUT", "/plans/tiny", json={"quotas": {"dns_zones": None}})
    assert updated.status_code == 200 and updated.json()["quotas"]["dns_zones"] is None
    assert updated.json()["quotas"]["dns_record_types"] == ["A", "TXT"]
    alice = space.user("alice")
    space.workspace_patch(alice.personal, plan_id="tiny")
    in_use = space.admin("DELETE", "/plans/tiny")
    assert in_use.status_code == 409 and code(in_use) == "plan_in_use"
    assert code(space.admin("DELETE", "/plans/basic")) == "plan_builtin"
    space.workspace_patch(alice.personal, plan_id="basic")
    assert space.admin("DELETE", "/plans/tiny").status_code == 200
    assert space.admin("GET", "/plans/tiny").status_code in {404, 405}


# ----------------------------------------------------------------------------- isolation sweep


def _walk(routes: list[Any], prefix: str = "") -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    for route in routes:
        if hasattr(route, "methods") and hasattr(route, "path"):
            for method in sorted(route.methods):
                found.append((method, prefix + route.path))
        elif hasattr(route, "original_router"):
            found.extend(_walk(route.original_router.routes,
                               prefix + route.include_context.prefix))
    return found


def my_routes() -> list[tuple[str, str]]:
    assert tenancy_module.MY_ROUTER is not None
    routes = _walk(tenancy_module.MY_ROUTER.routes)
    # The router's own prefix is part of APIRoute.path already.
    return [(method, path) for method, path in routes if method != "HEAD"]


def build_world(space: Space, env: dict[str, Any]) -> dict[str, Any]:
    alice, bob = space.user("alice"), space.user("bob")
    carol = space.user("carol")
    for user in (alice, bob):
        unlimited(space, user)
    team = bob.post("/workspaces", {"name": "Bob team"})
    assert team.status_code == 201, team.text
    team_id = team.json()["id"]
    added = bob.post(f"/workspaces/{team_id}/members", {"user": "carol", "role": "member"})
    assert added.status_code == 201, added.text
    invite = bob.post(f"/workspaces/{team_id}/invites", {"email": "x@example.test",
                                                          "role": "viewer"})
    assert invite.status_code == 201, invite.text
    zone(bob, "bob.example")
    record = bob.post("/dns/zones/bob.example/records",
                      {"name": "www", "type": "A", "data": {"address": "192.0.2.10"}})
    assert record.status_code == 201, record.text
    bucket(bob, "bob-files")
    key = bob.post("/s3/keys", {"name": "ci", "access": "read_write", "buckets": ["bob-files"]})
    assert key.status_code == 201, key.text
    domain = bob.post("/s3/buckets/bob-files/domains", {"host": "cdn.bob.example"})
    assert domain.status_code == 201, domain.text
    token = bob.post("/tokens", {"name": "bob key", "scopes": ["my.dns:read"]})
    assert token.status_code == 201, token.text
    pkg = bob.post("/packages/tokens", {"ecosystem": "npm", "name": "publish"})
    assert pkg.status_code == 201, pkg.text
    package_dir = env["cp"] / "npm" / "storage" / f"@{bob.slug}" / "lib"
    package_dir.mkdir(parents=True)
    (package_dir / "package.json").write_text(json.dumps(
        {"name": f"@{bob.slug}/lib", "versions": {"1.0.0": {}}, "dist-tags": {"latest": "1.0.0"}}))
    zone(alice, "alice.example")
    bucket(alice, "alice-files")
    return {"alice": alice, "bob": bob, "carol": carol, "team": team_id,
            "invite": invite.json()["id"], "record": record.json()["id"],
            "identity": key.json()["id"], "token": token.json()["id"],
            "pkg_token": pkg.json()["id"]}


def test_isolation_sweep_every_my_route_with_foreign_ids(space: Space, env: dict[str, Any]
                                                          ) -> None:
    world = build_world(space, env)
    alice, bob = world["alice"], world["bob"]
    values = {
        "workspace_id": world["team"], "zone": "bob.example", "record_id": world["record"],
        "name": "bob-files", "identity_id": world["identity"], "host": "cdn.bob.example",
        "token_id": str(world["token"]), "user_id": str(world["carol"].id),
        "invite_id": world["invite"], "ecosystem": "npm", "version": "1.0.0",
    }
    routes = my_routes()
    assert len(routes) >= 45, routes
    checked = 0
    for method, path in routes:
        params = re.findall(r"{([a-z_]+)(?::path)?}", path)
        url = path
        for param in params:
            value = values[param]
            if param == "name" and "/packages/" in path:
                value = f"@{bob.slug}/lib"
            if param == "token_id" and "/packages/" in path:
                value = world["pkg_token"]
            url = re.sub(r"{" + param + r"(?::path)?}", value, url, count=1)
        url = url.removeprefix(MY)
        if params:
            response = alice.call(method, url, json={} if method != "GET" else None)
            assert response.status_code == 404, (method, path, response.status_code,
                                                 response.text)
            checked += 1
        # Every route, with bob's workspace named in the header.
        response = alice.call(method, url, ws=bob.personal,
                              json={} if method != "GET" else None)
        assert response.status_code == 404, ("header", method, path, response.status_code,
                                             response.text)
    assert checked >= 30
    # Nothing of bob's changed.
    assert "bob.example" in env["dns"].zones
    assert [item["name"] for item in bob.get("/s3/buckets").json()["items"]] == ["bob-files"]
    assert len(bob.get("/s3/keys").json()["items"]) == 1
    assert [item["name"] for item in bob.get("/dns/zones").json()["items"]] == ["bob.example"]
    # A body naming bob's resource is never used: ids come from the path only.
    response = alice.post("/tokens", {"name": "sneaky", "scopes": ["my.dns:read"],
                                      "workspace_id": bob.personal})
    assert response.status_code == 404
    key = alice.post("/s3/keys", {"name": "x", "access": "read_only", "buckets": ["bob-files"]})
    assert key.status_code == 404
    lists = {path: alice.get(path).json() for path in ("/dns/zones", "/s3/buckets", "/s3/keys")}
    assert "bob" not in json.dumps(lists)


# ----------------------------------------------------------------------------- roles


def test_viewer_cannot_write(space: Space, env: dict[str, Any]) -> None:
    alice, carol = space.user("alice"), space.user("carol")
    unlimited(space, alice)
    team = alice.post("/workspaces", {"name": "Team"}).json()["id"]
    assert alice.post(f"/workspaces/{team}/members",
                      {"user": "carol", "role": "viewer"}).status_code == 201
    zone(alice, "team.example", ws=team)
    bucket(alice, "team-files", ws=team)
    writes = [
        ("POST", "/dns/zones", {"name": "carol.example"}),
        ("POST", "/dns/zones/team.example/records",
         {"name": "x", "type": "A", "data": {"address": "192.0.2.1"}}),
        ("DELETE", "/dns/zones/team.example", {"confirmation": "team.example"}),
        ("POST", "/s3/buckets", {"name": "carol-files"}),
        ("POST", "/s3/buckets/team-files/folders", {"prefix": "x/"}),
        ("DELETE", "/s3/buckets/team-files/objects", {"keys": ["a"]}),
        ("POST", "/s3/keys", {"name": "k", "access": "read_only", "buckets": ["team-files"]}),
        ("POST", "/packages/tokens", {"ecosystem": "npm", "name": "abc"}),
        ("POST", f"/workspaces/{team}/members", {"user": "alice", "role": "viewer"}),
    ]
    for method, path, body in writes:
        response = carol.call(method, path, ws=team, json=body)
        assert response.status_code == 403, (path, response.text)
    for path in ("/dns/zones", "/dns/zones/team.example/records", "/s3/buckets",
                 "/s3/buckets/team-files/objects", "/packages", f"/workspaces/{team}/members"):
        assert carol.get(path, ws=team).status_code == 200, path
    escalation = carol.post("/tokens", {"name": "write key", "scopes": ["my.dns:write"]},
                            ws=team)
    assert escalation.status_code == 403 and code(escalation) == "permission_escalation"


def test_role_escalation_attempts(space: Space) -> None:
    alice, dave = space.user("alice"), space.user("dave")
    eve, mike = space.user("eve"), space.user("mike")
    unlimited(space, alice)
    team = alice.post("/workspaces", {"name": "Team"}).json()["id"]
    assert alice.post(f"/workspaces/{team}/members",
                      {"user": "dave", "role": "admin"}).status_code == 201
    assert alice.post(f"/workspaces/{team}/members",
                      {"user": "mike", "role": "member"}).status_code == 201
    members = f"/workspaces/{team}/members"
    # An admin may not hand out admin or owner, nor touch the owner or themself.
    for role in ("admin", "owner"):
        response = dave.post(members, {"user": "eve", "role": role})
        assert response.status_code == 403 and code(response) == "permission_escalation", role
        invite = dave.post(f"/workspaces/{team}/invites", {"email": "e@example.test",
                                                           "role": role})
        assert invite.status_code == 403, role
    assert dave.call("PATCH", f"{members}/{alice.id}", json={"role": "viewer"}).status_code == 403
    assert dave.call("PATCH", f"{members}/{dave.id}", json={"role": "owner"}).status_code == 403
    assert dave.call("DELETE", f"{members}/{alice.id}").status_code == 403
    # A member cannot manage members at all; nor can anyone give a role via a token.
    assert mike.post(members, {"user": "eve", "role": "viewer"}).status_code == 403
    assert mike.call("PATCH", f"{members}/{mike.id}", json={"role": "admin"}).status_code == 403
    assert dave.post(members, {"user": "eve", "role": "member"}).status_code == 201
    assert dave.call("PATCH", f"{members}/{mike.id}", json={"role": "viewer"}).status_code == 200
    # The owner can make another owner; the last owner cannot leave.
    assert alice.call("PATCH", f"{members}/{dave.id}", json={"role": "owner"}).status_code == 200
    assert alice.call("DELETE", f"{members}/{alice.id}").status_code == 200
    last = dave.call("DELETE", f"{members}/{dave.id}")
    assert last.status_code == 409 and code(last) == "last_owner"
    # The personal workspace has no members.
    personal = alice.post(f"/workspaces/{alice.personal}/members", {"user": "eve",
                                                                    "role": "viewer"})
    assert personal.status_code == 409 and code(personal) == "personal_workspace"
    assert eve.get(f"/workspaces/{team}/members").status_code == 200


def test_invite_accept_requires_matching_email(space: Space) -> None:
    alice = space.user("alice")
    unlimited(space, alice)
    frank = space.user("frank", email="frank@example.test")
    gina = space.user("gina", email="gina@example.test")
    team = alice.post("/workspaces", {"name": "Team"}).json()["id"]
    invite = alice.post(f"/workspaces/{team}/invites", {"email": "frank@example.test",
                                                         "role": "member"}).json()
    assert gina.post("/invites/accept", {"token": invite["token"]}).status_code == 404
    accepted = frank.post("/invites/accept", {"token": invite["token"]})
    assert accepted.status_code == 200 and accepted.json() == {"workspace_id": team,
                                                               "role": "member"}
    assert frank.post("/invites/accept", {"token": invite["token"]}).status_code == 404
    assert frank.get("/dns/zones", ws=team).status_code == 200


# ----------------------------------------------------------------------------- tokens


def test_scope_limited_workspace_tokens(space: Space) -> None:
    alice, bob = space.user("alice"), space.user("bob")
    zone(alice, "alice.example")
    created = alice.post("/tokens", {"name": "dns reader", "scopes": ["my.dns:read"]})
    assert created.status_code == 201, created.text
    token = created.json()["token"]
    bearer = TestClient(space.client.app)
    auth = {"Authorization": f"Bearer {token}"}
    assert bearer.get(f"{MY}/dns/zones", headers=auth).status_code == 200
    denied = bearer.post(f"{MY}/dns/zones", headers=auth, json={"name": "x.example"})
    assert denied.status_code == 403 and code(denied) == "forbidden"
    assert bearer.get(f"{MY}/s3/buckets", headers=auth).status_code == 403
    assert bearer.get(f"{MY}/dns/zones", headers={**auth, "X-Workspace": bob.personal}
                      ).status_code == 404
    # Never a server permission, never token or member management.
    for path in ("/api/v1/users", "/api/v1/dns/zones", "/api/v1/tokens"):
        assert bearer.get(path, headers=auth).status_code == 403, path
    assert bearer.post(f"{MY}/tokens", headers=auth,
                       json={"name": "child", "scopes": ["my.dns:read"]}).status_code == 403
    unknown = alice.post("/tokens", {"name": "admin", "scopes": ["user:write"]})
    assert unknown.status_code == 422
    # A server-management key does not open «my space».
    admin_token = space.client.post("/api/v1/tokens", headers=space.headers, json={
        "name": "ci-key", "scopes": ["dns:read"], "expires_in_seconds": 3600}).json()["token"]
    assert bearer.get(f"{MY}/me", headers={"Authorization": f"Bearer {admin_token}"}
                      ).status_code == 403
    # IP allow-list: the test client is not inside 203.0.113.0/24.
    pinned = alice.post("/tokens", {"name": "pinned", "scopes": ["my.dns:read"],
                                    "ip_allow": ["203.0.113.0/24"]}).json()["token"]
    assert bearer.get(f"{MY}/dns/zones", headers={"Authorization": f"Bearer {pinned}"}
                      ).status_code == 403
    # Revoked keys stop at once; tokens are not listed in the server key list.
    assert alice.call("DELETE", f"/tokens/{created.json()['id']}").status_code == 200
    assert bearer.get(f"{MY}/dns/zones", headers=auth).status_code == 401
    assert all(item["name"] != "dns reader"
               for item in space.client.get("/api/v1/tokens").json()["items"])


# ----------------------------------------------------------------------------- quotas


def test_quota_overflow(space: Space, env: dict[str, Any]) -> None:
    alice = space.user("alice")
    space.workspace_patch(alice.personal, quota_overrides={
        "dns_zones": 1, "s3_buckets": 1, "dns_records_per_zone": 1, "api_tokens": 1,
        "s3_keys": 1})
    zone(alice, "one.example")
    second = alice.post("/dns/zones", {"name": "two.example"})
    assert second.status_code == 409
    assert second.json()["error"].items() >= {"code": "quota_exceeded", "quota": "dns_zones",
                                              "limit": 1, "used": 1}.items()
    assert "two.example" not in env["dns"].zones
    ok = alice.post("/dns/zones/one.example/records",
                    {"name": "a", "type": "A", "data": {"address": "192.0.2.1"}})
    assert ok.status_code == 201, ok.text
    over = alice.post("/dns/zones/one.example/records",
                      {"name": "b", "type": "A", "data": {"address": "192.0.2.2"}})
    assert over.status_code == 409 and over.json()["error"]["quota"] == "dns_records_per_zone"
    bucket(alice, "alice-one")
    over = alice.post("/s3/buckets", {"name": "alice-two"})
    assert over.status_code == 409 and over.json()["error"]["quota"] == "s3_buckets"
    assert alice.post("/s3/keys", {"name": "a", "access": "read_only",
                                   "buckets": ["alice-one"]}).status_code == 201
    over = alice.post("/s3/keys", {"name": "b", "access": "read_only", "buckets": ["alice-one"]})
    assert over.status_code == 409 and over.json()["error"]["quota"] == "s3_keys"
    assert alice.post("/tokens", {"name": "one", "scopes": ["my.dns:read"]}).status_code == 201
    over = alice.post("/tokens", {"name": "two", "scopes": ["my.dns:read"]})
    assert over.status_code == 409 and over.json()["error"]["quota"] == "api_tokens"
    # Plan features: the basic plan has no public links, teams or DNSSEC.
    public = alice.call("PATCH", "/s3/buckets/alice-one", json={"public_read": True})
    assert public.status_code == 403 and public.json()["error"]["feature"] == "s3_public_links"
    team = alice.post("/workspaces", {"name": "Team"})
    assert team.status_code == 403 and code(team) == "feature_disabled"
    usage = alice.get("/me").json()["workspaces"][0]["usage"]
    assert usage["dns_zones"] == 1 and usage["s3_buckets"] == 1 and usage["s3_keys"] == 1
    # The engine snapshot carries the workspace byte/object quota for its buckets.
    snapshot = json.loads((env["cp"] / "modules" / "s3" / "config.json").read_text())
    group = next(item for item in snapshot["quota_groups"] if item["id"] == alice.personal)
    assert group["buckets"] == ["alice-one"] and group["bytes"] == 5 * 1024**3


def test_record_validation_before_the_engine(space: Space, env: dict[str, Any]) -> None:
    alice = space.user("alice")
    zone(alice, "alice.example")
    before = len(env["dns"].requests)
    cases = [
        ({"name": "x", "type": "NS", "data": {"nameserver": "ns.evil.example"}},
         "dns_record_type_not_allowed"),
        ({"name": "x", "type": "A", "data": {"address": "not-an-ip; rm -rf /"}}, None),
        ({"name": "x", "type": "BOGUS", "data": {}}, None),
        ({"name": "a b", "type": "TXT", "data": {"text": "hi"}}, None),
        ({"name": "x", "type": "MX", "data": {"preference": 10, "exchange": "mx;evil"}}, None),
        ({"name": "x", "type": "A", "data": {"address": "192.0.2.1"}, "view": "internal"}, None),
    ]
    for body, expected in cases:
        response = alice.post("/dns/zones/alice.example/records", body)
        assert response.status_code == 422, (body, response.text)
        if expected:
            assert code(response) == expected
    assert not [item for item in env["dns"].requests[before:] if item[0] != "GET"]


def test_zone_conflicts_and_system_names(space: Space) -> None:
    alice, bob = space.user("alice"), space.user("bob")
    zone(alice, "shared.example")
    for name in ("shared.example", "sub.shared.example", "example", "mrk.internal",
                 "x.mrk.internal"):
        response = bob.post("/dns/zones", {"name": name})
        assert response.status_code == 409 and code(response) == "zone_unavailable", name
    # A zone the admin made (owned by the system) is not claimable either.
    made = space.client.post("/api/v1/dns/zones", headers=space.headers,
                             json={"name": "system.example", "template_id": None})
    assert made.status_code == 201, made.text
    assert code(bob.post("/dns/zones", {"name": "system.example"})) == "zone_unavailable"
    assert code(alice.post("/dns/zones", {"name": "www.system.example"})) == "zone_unavailable"


def test_domain_verification(space: Space, env: dict[str, Any]) -> None:
    space.settings(verify_domains=True)
    alice = space.user("alice")
    created = zone(alice, "proof.example")
    assert created["status"] == "pending_verification"
    assert env["dns"].zones["proof.example"]["disabled"] is True
    info = alice.get("/dns/zones/proof.example/verification").json()
    txt = info["methods"][0]
    assert txt["kind"] == "txt" and txt["name"] == "_pishkar-verify.proof.example"
    assert info["verified"] is False
    assert alice.post("/dns/zones/proof.example/verify").json()["verified"] is False
    env["txt"]["TXT:_pishkar-verify.proof.example"] = [txt["value"]]
    result = alice.post("/dns/zones/proof.example/verify").json()
    assert result == {"verified": True, "method": "txt", "status": "active"}
    assert env["dns"].zones["proof.example"]["disabled"] is False
    assert alice.get("/dns/zones").json()["items"][0]["status"] == "active"


# ----------------------------------------------------------------------------- suspended


def test_suspended_workspace_is_read_only(space: Space, env: dict[str, Any]) -> None:
    alice = space.user("alice")
    zone(alice, "alice.example")
    bucket(alice, "alice-files")
    space.workspace_patch(alice.personal, status="suspended")
    for method, path, body in [
        ("POST", "/dns/zones", {"name": "more.example"}),
        ("POST", "/dns/zones/alice.example/records",
         {"name": "a", "type": "A", "data": {"address": "192.0.2.1"}}),
        ("POST", "/s3/buckets", {"name": "alice-more"}),
        ("POST", "/s3/buckets/alice-files/folders", {"prefix": "x/"}),
        ("POST", "/tokens", {"name": "key", "scopes": ["my.dns:read"]}),
    ]:
        response = alice.call(method, path, json=body)
        assert response.status_code == 423 and code(response) == "workspace_suspended", path
    assert alice.get("/dns/zones").status_code == 200
    assert alice.get("/s3/buckets").status_code == 200
    snapshot = json.loads((env["cp"] / "modules" / "s3" / "config.json").read_text())
    assert next(item for item in snapshot["buckets"]
                if item["name"] == "alice-files")["frozen"] is True


# ----------------------------------------------------------------------------- view as


def test_view_as_is_read_only_and_audited(space: Space) -> None:
    alice = space.user("alice")
    zone(alice, "alice.example")
    started = space.admin("POST", f"/workspaces/{alice.personal}/view-as", json={})
    assert started.status_code == 201, started.text
    view = {"X-View-As": started.json()["token"]}
    me = space.client.get(f"{MY}/me", headers=view).json()
    assert me["current"] == alice.personal and me["view_as"]["write"] is False
    assert [item["id"] for item in me["workspaces"]] == [alice.personal]
    assert space.client.get(f"{MY}/dns/zones", headers=view).json()["items"][0]["name"] \
        == "alice.example"
    denied = space.client.post(f"{MY}/dns/zones", headers={**space.headers, **view},
                               json={"name": "admin.example"})
    assert denied.status_code == 403
    assert space.client.post(f"{MY}/tokens", headers={**space.headers, **view},
                             json={"name": "x", "scopes": ["my.dns:read"]}).status_code == 403
    # Another workspace through the same grant: 404.
    assert space.client.get(f"{MY}/dns/zones", headers={**view, "X-Workspace": "ws_000000000000"}
                            ).status_code == 404
    # Someone else cannot use the grant.
    bob = space.user("bob")
    assert bob.client.get(f"{MY}/dns/zones", headers=view).status_code == 403
    # The owner sees the visit in their own activity, with on_behalf_of.
    activity = alice.get("/activity").json()["items"]
    visits = [item for item in activity if item["action"] == "tenancy.view_as.request"]
    assert visits and all(item["on_behalf_of"] == alice.id for item in visits)
    assert any(item["action"] == "tenancy.view_as.start" for item in activity)
    audit = space.client.get("/api/v1/audit-events?action=tenancy.view_as").json()["items"]
    assert audit and audit[0]["workspace_id"] == alice.personal
    # A write grant lets the admin act, still on the record.
    write = space.admin("POST", f"/workspaces/{alice.personal}/view-as", json={"write": True})
    wview = {"X-View-As": write.json()["token"]}
    made = space.client.post(f"{MY}/dns/zones/alice.example/records",
                             headers={**space.headers, **wview},
                             json={"name": "a", "type": "A", "data": {"address": "192.0.2.1"}})
    assert made.status_code == 201, made.text
    actions = [item for item in alice.get("/activity").json()["items"]
               if item["action"] == "my.dns.record.create"]
    assert actions[0]["on_behalf_of"] == alice.id and actions[0]["actor_user_id"] != alice.id
    assert space.client.request("DELETE", f"{ADMIN}/view-as",
                                headers={**space.headers, **wview}).json() == {"ended": True}
    assert space.client.get(f"{MY}/me", headers=wview).status_code == 403
    # Writing «view as» needs its own permission.
    operator = space.user("opal", role="operator")
    assert operator.client.post(f"{ADMIN}/workspaces/{alice.personal}/view-as",
                                headers=operator.headers, json={}).status_code == 403


# ----------------------------------------------------------------------------- sign-up


def test_signup_modes(space: Space) -> None:
    form = {"display_name": "New Person", "email": "new@example.test", "password": PASSWORD,
            "password_confirmation": PASSWORD}
    anon = TestClient(space.client.app)
    assert anon.get("/api/v1/auth/registration-status").json() == {"enabled": False,
                                                                    "mode": "off"}
    assert anon.post("/api/v1/auth/register", json=form).status_code == 409
    space.settings(signup="approval")
    pending = anon.post("/api/v1/auth/register", json=form)
    assert pending.status_code == 202 and pending.json() == {"status": "pending_approval"}
    assert anon.post("/api/v1/auth/login", json={"username": "new@example.test",
                                                 "password": PASSWORD}).status_code == 401
    signups = space.admin("GET", "/signups").json()["items"]
    assert len(signups) == 1 and signups[0]["user"]["email"] == "new@example.test"
    approved = space.admin("POST", f"/signups/{signups[0]['id']}/approve", json={"plan_id": "pro"})
    assert approved.status_code == 200 and approved.json()["status"] == "approved"
    login = anon.post("/api/v1/auth/login", json={"username": "new@example.test",
                                                  "password": PASSWORD})
    assert login.status_code == 200 and login.json()["user"]["role"] == "customer"
    me = anon.get(f"{MY}/me").json()
    assert me["workspaces"][0]["plan"]["id"] == "pro"
    space.settings(signup="open")
    opened = TestClient(space.client.app).post("/api/v1/auth/register", json={
        **form, "email": "open@example.test"})
    assert opened.status_code == 201 and opened.json()["user"]["role"] == "customer"


def test_admin_area_local_only(space: Space) -> None:
    space.settings(admin_area_local_only=True)
    remote = TestClient(space.client.app, client=("8.8.8.8", 5000))
    remote.cookies.update(space.client.cookies)
    blocked = remote.get("/api/v1/users")
    assert blocked.status_code == 403 and code(blocked) == "admin_area_local_only"
    assert remote.get(f"{MY}/me").status_code == 200
    local = TestClient(space.client.app, client=("127.0.0.1", 5000))
    local.cookies.update(space.client.cookies)
    assert local.get("/api/v1/users").status_code == 200


# ----------------------------------------------------------------------------- packages


def test_npm_scope_and_pypi_index(space: Space, env: dict[str, Any],
                                  monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    alice, bob = space.user("alice"), space.user("bob")
    basic = alice.post("/packages/tokens", {"ecosystem": "npm", "name": "publish"})
    assert basic.status_code == 403 and code(basic) == "feature_disabled"
    unlimited(space, alice)
    created = alice.post("/packages/tokens", {"ecosystem": "npm", "name": "publish"})
    assert created.status_code == 201, created.text
    body = created.json()
    assert body["username"].startswith(f"pk-{alice.slug}-") and body["token"]
    htpasswd = (env["cp"] / "npm" / "auth" / "htpasswd").read_text()
    assert body["username"] in htpasswd and body["token"] not in htpasswd
    (env["cp"] / "npm" / "auth" / "htpasswd").write_text(htpasswd + "ci-admin:{SHA}x\n")
    config_path, _env = build_runtime_config(env["cp"])
    config = config_path.read_text()
    assert f'"@{alice.slug}/*":' in config
    rule = config.split(f'"@{alice.slug}/*":', 1)[1].split("\n  ", 4)
    assert body["username"] in rule[1] and "proxy" not in config.split(
        f'"@{alice.slug}/*":', 1)[1].split("'@*/*'")[0]
    assert "publish: ci-admin" in config  # workspace users may not publish elsewhere
    # Quota: over npm_bytes switches publishing off.
    package_dir = env["cp"] / "npm" / "storage" / f"@{alice.slug}" / "lib"
    package_dir.mkdir(parents=True)
    (package_dir / "package.json").write_text(json.dumps({
        "name": f"@{alice.slug}/lib", "versions": {"1.0.0": {}, "1.1.0": {}},
        "dist-tags": {"latest": "1.1.0"}, "time": {}}))
    (package_dir / "lib-1.1.0.tgz").write_bytes(b"x" * 4000)
    space.workspace_patch(alice.personal, quota_overrides={"npm_bytes": 1000})
    listing = alice.get("/packages").json()["npm"]
    assert listing["publish_allowed"] is False and listing["packages"][0]["versions"] == [
        "1.0.0", "1.1.0"]
    tenancy_json = json.loads((env["cp"] / "npm" / "config" / "tenancy.json").read_text())
    assert tenancy_json["scopes"][0]["publish"] is False
    deleted = alice.call("DELETE", f"/packages/npm/@{alice.slug}/lib/versions/1.1.0")
    assert deleted.status_code == 200, deleted.text
    assert alice.get("/packages").json()["npm"]["publish_allowed"] is True
    assert bob.call("DELETE", f"/packages/npm/@{alice.slug}/lib/versions/1.0.0").status_code == 404
    # PyPI: devpi index <slug>/dev and an upload user per token (fake devpi).
    calls: list[tuple[str, str, Any]] = []

    def devpi(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content) if request.content else None
        calls.append((request.method, request.url.path, body))
        if request.url.path == "/+login":
            return httpx.Response(200, json={"result": {"password": "tok"}})
        return httpx.Response(200, json={"result": {}})

    password = tmp_path / "root-password"
    password.write_text("root-secret")
    monkeypatch.setenv("MRK_PYPI_ROOT_PASSWORD_FILE", str(password))
    monkeypatch.setattr(my_packages, "TRANSPORT_FACTORY", lambda: httpx.MockTransport(devpi))
    made = alice.post("/packages/tokens", {"ecosystem": "pypi", "name": "twine"})
    assert made.status_code == 201, made.text
    user = made.json()["username"]
    assert ("PUT", f"/{user}", {"password": made.json()["token"], "email": ""}) in calls
    index = next(item for item in calls if item[:2] == ("PUT", f"/{alice.slug}/dev"))
    assert index[2]["bases"] == ["root/pypi"] and index[2]["acl_upload"] == [user]
    tokens = alice.get("/packages/tokens").json()["items"]
    assert {item["ecosystem"] for item in tokens} == {"npm", "pypi"}
    assert alice.call("DELETE", f"/packages/tokens/{made.json()['id']}").status_code == 200
    assert ("DELETE", f"/{user}", None) in calls


# ----------------------------------------------------------------------------- admin ops


def test_admin_workspace_delete_and_transfer(space: Space, env: dict[str, Any]) -> None:
    alice = space.user("alice")
    zone(alice, "alice.example")
    bucket(alice, "alice-files")
    detail = space.admin("GET", f"/workspaces/{alice.personal}").json()
    assert {item["kind"] for item in detail["resources"]} == {"dns_zone", "s3_bucket"}
    moved = space.admin("POST", "/ownership/transfer", json={
        "kind": "dns_zone", "resource_id": "alice.example", "workspace_id": None})
    assert moved.status_code == 200
    assert alice.get("/dns/zones").json()["items"] == []
    assert alice.get("/dns/zones/alice.example").status_code == 404
    wrong = space.admin("DELETE", f"/workspaces/{alice.personal}?confirmation=nope")
    assert wrong.status_code == 422 and code(wrong) == "confirmation_mismatch"
    slug = alice.slug
    gone = space.admin("DELETE", f"/workspaces/{alice.personal}?confirmation={slug}&mode=delete")
    assert gone.status_code == 200 and gone.json()["resources"] == {"removed": 1}
    assert ("alice-files", "force") in [(b, "force") for b, _ in env["s3"].deleted] or \
        env["s3"].deleted
    assert "alice.example" in env["dns"].zones  # transferred to the system first
    listed = space.admin("GET", "/workspaces").json()["items"]
    assert alice.personal not in [item["id"] for item in listed]


# ----------------------------------------------------------------------------- real S3 engine


def _serve(app: Any) -> tuple[Any, int]:
    import uvicorn

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(app, log_config=None, access_log=False,
                                           lifespan="off"))
    threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True).start()
    for _ in range(200):
        if server.started:
            break
        time.sleep(0.02)
    return server, port


def test_workspace_key_cannot_touch_another_workspace_bucket(space: Space,
                                                               env: dict[str, Any]) -> None:
    boto3 = pytest.importorskip("boto3")
    from botocore.config import Config
    from botocore.exceptions import ClientError
    from mrk_control_plane.s3engine.engine import Engine
    from mrk_control_plane.s3engine.settings import EngineSettings
    from mrk_control_plane.secret_store import SecretStore

    alice, bob = space.user("alice"), space.user("bob")
    bucket(alice, "alice-files")
    bucket(alice, "alice-other")
    bucket(bob, "bob-files")
    key = alice.post("/s3/keys", {"name": "ci", "access": "admin", "buckets": ["alice-files"]})
    assert key.status_code == 201, key.text
    secret = key.json()
    bob_key = bob.post("/s3/keys", {"name": "ci", "access": "read_write",
                                    "buckets": ["bob-files"]}).json()
    # Quotas for alice: 1000 bytes, 3 files across her buckets.
    space.workspace_patch(alice.personal, quota_overrides={"s3_bytes": 1000, "s3_objects": 3})
    cp = env["cp"]
    settings = EngineSettings(data_root=cp / "modules" / "s3", secret_data_dir=cp,
                              link_roots=(cp / "links",), fsync_policy="none", hash_rate_bytes=0,
                              disk_block_percent=100)
    engine = Engine(settings, SecretStore(cp))
    server, port = _serve(engine.api)
    try:
        def client(akid: str, sk: str) -> Any:
            return boto3.client(
                "s3", endpoint_url=f"http://127.0.0.1:{port}", region_name="us-east-1",
                aws_access_key_id=akid, aws_secret_access_key=sk,
                config=Config(s3={"addressing_style": "path"}, signature_version="s3v4",
                              retries={"max_attempts": 1}))

        s3a = client(secret["access_key_id"], secret["secret_access_key"])
        public_policy = json.dumps({"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Principal": "*", "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::alice-files/*"}]})
        s3a.put_object(Bucket="alice-files", Key="a.txt", Body=b"hello")
        assert s3a.get_object(Bucket="alice-files", Key="a.txt")["Body"].read() == b"hello"
        for call in (
            lambda: s3a.put_object(Bucket="bob-files", Key="x", Body=b"x"),
            lambda: s3a.list_objects_v2(Bucket="bob-files"),
            lambda: s3a.get_object(Bucket="bob-files", Key="x"),
            lambda: s3a.put_object(Bucket="alice-other", Key="x", Body=b"x"),
            lambda: s3a.delete_bucket(Bucket="alice-files"),
            lambda: s3a.create_bucket(Bucket="alice-new"),
        ):
            with pytest.raises(ClientError) as caught:
                call()
            assert caught.value.response["Error"]["Code"] == "AccessDenied"
        with pytest.raises(ClientError) as caught:  # never allowed; unsupported anyway
            s3a.put_bucket_policy(Bucket="alice-files", Policy=public_policy)
        assert caught.value.response["Error"]["Code"] in {"AccessDenied", "NotImplemented"}
        s3b = client(bob_key["access_key_id"], bob_key["secret_access_key"])
        s3b.put_object(Bucket="bob-files", Key="b.txt", Body=b"b" * 2000)  # bob: no limit hit
        with pytest.raises(ClientError) as caught:
            s3b.get_object(Bucket="alice-files", Key="a.txt")
        assert caught.value.response["Error"]["Code"] == "AccessDenied"
        # The workspace quota is enforced by the engine on writes.
        with pytest.raises(ClientError) as caught:
            s3a.put_object(Bucket="alice-files", Key="big", Body=b"x" * 2000)
        assert caught.value.response["Error"]["Code"] == "QuotaExceeded"
        s3a.put_object(Bucket="alice-files", Key="b.txt", Body=b"b")
        s3a.put_object(Bucket="alice-files", Key="c.txt", Body=b"c")
        with pytest.raises(ClientError) as caught:
            s3a.put_object(Bucket="alice-files", Key="d.txt", Body=b"d")
        assert caught.value.response["Error"]["Code"] == "QuotaExceeded"
        s3a.put_object(Bucket="alice-files", Key="c.txt", Body=b"cc")  # overwrite is fine
        # Suspending the workspace freezes its buckets in the engine too.
        space.workspace_patch(alice.personal, status="suspended")
        engine.snapshots.reload(force=True)
        with pytest.raises(ClientError) as caught:
            s3a.delete_object(Bucket="alice-files", Key="c.txt")
        assert caught.value.response["Error"]["Code"] == "AccessDenied"
        assert s3a.get_object(Bucket="alice-files", Key="c.txt")["Body"].read() == b"cc"
    finally:
        server.should_exit = True
        time.sleep(0.2)
        engine.close()


def test_workspace_policy_never_widens() -> None:
    assert workspace_policy("admin", [])["Statement"] == []
    policy = workspace_policy("admin", ["a-files"])
    validate_policy(policy)
    text = json.dumps(policy)
    assert '"*"' not in text and "PutBucketPolicy" not in text and "DeleteBucket\"" not in text
    with pytest.raises(ValueError):
        workspace_policy("custom", ["a-files"])
