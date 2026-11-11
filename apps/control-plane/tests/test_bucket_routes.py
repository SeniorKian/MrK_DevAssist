"""Routes of verified bucket domains (docs/43 §0.1): modes, rollback, isolation, clean-up."""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest
from mrk_control_plane.modules import bucket_routes, dokploy_client, domains_routing, services

from . import test_my_space
from .test_my_space import Space, User, bucket, code, unlimited, zone
from .test_services_domains import API_KEY, PANEL_URL, FakeAgent, FakeDokploy

DOMAINS = "/api/v1/domains"
# The «my space» fixtures, shared with test_my_space.
env = test_my_space.env
space = test_my_space.space


def routes() -> bucket_routes.BucketRoutes:
    assert services.ACTIVE_SERVICE is not None
    return services.ACTIVE_SERVICE.bucket_routes


def owner_with_bucket(space: Space, name: str = "alice") -> User:
    user = space.user(name)
    unlimited(space, user)
    zone(user, f"{name}.example")
    bucket(user, f"{name}-files")
    return user


def attach(user: User, host: str, bucket_name: str | None = None) -> dict[str, Any]:
    target = bucket_name or f"{user.username}-files"
    response = user.post(f"/s3/buckets/{target}/domains", {"host": host})
    assert response.status_code == 201, response.text
    return response.json()


def admin_routes(space: Space) -> dict[str, Any]:
    response = space.client.get(f"{DOMAINS}/bucket-routes", headers=space.headers)
    assert response.status_code == 200, response.text
    return response.json()


def admin_item(space: Space, host: str) -> dict[str, Any]:
    return next(item for item in admin_routes(space)["items"] if item["host"] == host)


def use_traefik(space: Space, monkeypatch: pytest.MonkeyPatch, agent: FakeAgent) -> None:
    monkeypatch.setattr(routes().service.routing, "agent", lambda: agent)
    monkeypatch.setattr(domains_routing.socket, "gethostname", lambda: "abcdef123456")
    enabled = space.client.put(f"{DOMAINS}/routing", headers=space.headers,
                               json={"mode": "auto", "traefik_file_enabled": True})
    assert enabled.json()["effective_mode"] == "traefik_file", enabled.text


def file_hosts(agent: FakeAgent) -> list[str]:
    method, path, payload = agent.requests[-1]
    if path == "/v1/traefik/domains/delete":
        return []
    assert (method, path) == ("POST", "/v1/traefik/domains")
    return [host for item in payload["services"] if item["service"] == "s3"
            for host in item["hosts"]]


# ----------------------------------------------------------------------------- manual


def test_manual_mode_gives_admin_steps_and_workspace_only_a_state(space: Space) -> None:
    alice = owner_with_bucket(space)
    created = attach(alice, "cdn.alice.example")
    assert created["verified"] is True
    assert created["route"] == {"state": "manual", "error_code": None}
    listed = alice.get("/s3/buckets/alice-files/domains").json()["items"]
    assert listed[0]["route"]["state"] == "manual"
    # Server internals (Dokploy project, ports, steps) never reach the workspace.
    assert "instructions" not in str(listed) and "9000" not in str(listed)

    item = admin_item(space, "cdn.alice.example")
    assert item["bucket"] == "alice-files" and item["workspace_slug"] == alice.slug
    route = item["route"]
    assert route["state"] == "manual" and route["mode"] == "manual"
    assert route["instructions"]["dokploy"]["port"] == 9000
    assert route["instructions"]["dokploy"]["host"] == "cdn.alice.example"
    assert any("cdn.alice.example" in step for step in route["instructions"]["steps_fa"])


def test_admin_bucket_custom_domain_maps_host_and_is_cleaned_up(space: Space) -> None:
    created_bucket = space.client.post(
        "/api/v1/s3/buckets", headers=space.headers, json={"name": "sedamod"}
    )
    assert created_bucket.status_code == 201, created_bucket.text

    created = space.client.post(
        "/api/v1/s3/buckets/sedamod/domains",
        headers=space.headers,
        json={"host": "s3.sedamod.example"},
    )
    assert created.status_code == 201, created.text
    item = created.json()
    assert item["host"] == "s3.sedamod.example"
    assert item["bucket"] == "sedamod" and item["source"] == "admin"
    assert item["route"]["state"] == "manual"

    snapshot = json.loads(
        (space.env["cp"] / "modules" / "s3" / "config.json").read_text(encoding="utf-8")
    )
    assert snapshot["bucket_hosts"] == {"s3.sedamod.example": "sedamod"}
    aggregate = admin_item(space, "s3.sedamod.example")
    assert aggregate["source"] == "admin" and aggregate["workspace_slug"] is None

    duplicate = space.client.post(
        "/api/v1/s3/buckets/sedamod/domains",
        headers=space.headers,
        json={"host": "s3.sedamod.example"},
    )
    assert duplicate.status_code == 409 and code(duplicate) == "domain_exists"

    removed = space.client.request(
        "DELETE",
        "/api/v1/s3/buckets/sedamod/domains/s3.sedamod.example",
        headers=space.headers,
    )
    assert removed.status_code == 200, removed.text
    snapshot = json.loads(
        (space.env["cp"] / "modules" / "s3" / "config.json").read_text(encoding="utf-8")
    )
    assert snapshot["bucket_hosts"] == {}

    space.client.post(
        "/api/v1/s3/buckets/sedamod/domains",
        headers=space.headers,
        json={"host": "cdn.sedamod.example"},
    )
    deleted = space.client.request(
        "DELETE",
        "/api/v1/s3/buckets/sedamod",
        headers=space.headers,
        json={"confirmation": "sedamod", "force": True},
    )
    assert deleted.status_code == 200, deleted.text
    assert routes().admin_domains_for("sedamod") == []
    assert "cdn.sedamod.example" not in routes().records()


def admin_bucket(space: Space, name: str) -> None:
    created = space.client.post("/api/v1/s3/buckets", headers=space.headers, json={"name": name})
    assert created.status_code == 201, created.text


def admin_domain(space: Space, bucket_name: str, host: str) -> httpx.Response:
    return space.client.post(f"/api/v1/s3/buckets/{bucket_name}/domains",
                             headers=space.headers, json={"host": host})


def audit_records(space: Space) -> list[tuple[str, str | None, str | None]]:
    items = space.client.get("/api/v1/audit-events?limit=200",
                             headers=space.headers).json()["items"]
    return [(item["action"], item.get("result"), item.get("object_id")) for item in items]


def test_admin_and_workspace_bucket_domains_never_overlap(space: Space) -> None:
    alice = owner_with_bucket(space)
    attach(alice, "cdn.alice.example")
    admin_bucket(space, "shared")

    # The admin cannot take a workspace domain or a name inside a workspace zone.
    for host in ("cdn.alice.example", "img.alice.example", "alice.example"):
        refused = admin_domain(space, "shared", host)
        assert refused.status_code == 409 and code(refused) == "domain_exists", host
    assert routes().admin_domains() == {}

    assert admin_domain(space, "shared", "files.shared.example").status_code == 201
    # A workspace cannot claim an admin bucket domain, a name inside it or above it.
    for host in ("files.shared.example", "a.files.shared.example", "shared.example"):
        refused = alice.post("/s3/buckets/alice-files/domains", {"host": host})
        assert refused.status_code == 409 and code(refused) == "domain_unavailable", host
    snapshot = json.loads(
        (space.env["cp"] / "modules" / "s3" / "config.json").read_text(encoding="utf-8")
    )
    assert snapshot["bucket_hosts"]["files.shared.example"] == "shared"


def test_admin_bucket_domain_route_errors_are_reported_and_audited(
        space: Space, monkeypatch: pytest.MonkeyPatch) -> None:
    admin_bucket(space, "errs")

    async def boom(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        raise RuntimeError("routing exploded")

    with monkeypatch.context() as patch:
        patch.setattr(routes(), "ensure", boom)
        failed = admin_domain(space, "errs", "a.errs.example")
        assert failed.status_code == 502 and code(failed) == "bucket_domain_route_failed"
    # Rolled back: neither the mapping nor the engine host is left behind.
    assert routes().admin_domains() == {}
    assert ("s3.bucket_domain.create", "failure", "a.errs.example") in audit_records(space)

    assert admin_domain(space, "errs", "b.errs.example").status_code == 201
    with monkeypatch.context() as patch:
        patch.setattr(routes(), "ensure", boom)
        retried = space.client.post("/api/v1/s3/buckets/errs/domains/B.Errs.Example./retry",
                                    headers=space.headers)
        assert retried.status_code == 502 and code(retried) == "bucket_domain_route_failed"
    assert ("s3.bucket_domain.retry", "failure", "b.errs.example") in audit_records(space)

    with monkeypatch.context() as patch:
        patch.setattr(bucket_routes, "active", lambda: None)
        unavailable = space.client.post("/api/v1/s3/buckets/errs/domains/b.errs.example/retry",
                                        headers=space.headers)
        assert unavailable.status_code == 503 and code(unavailable) == "routing_unavailable"

    with monkeypatch.context() as patch:
        patch.setattr(routes(), "remove", boom)
        patch.setattr(routes(), "reconcile_soon", lambda: None)
        deleted = space.client.request("DELETE", "/api/v1/s3/buckets/errs/domains/b.errs.example",
                                       headers=space.headers)
        assert deleted.status_code == 502 and code(deleted) == "bucket_domain_route_failed"
    # The engine no longer maps the host; the leftover route is reconciled later.
    assert routes().admin_domains() == {}
    assert ("s3.bucket_domain.delete", "failure", "b.errs.example") in audit_records(space)

    missing = space.client.request("DELETE", "/api/v1/s3/buckets/errs/domains/not a host",
                                   headers=space.headers)
    assert missing.status_code == 404 and code(missing) == "domain_not_found"


def test_unverified_domain_is_not_routed(space: Space, env: dict[str, Any]) -> None:
    alice = owner_with_bucket(space)
    created = attach(alice, "files.other.example")
    assert created["verified"] is False
    assert created["route"] == {"state": "unverified", "error_code": None}
    assert "files.other.example" not in routes().records()
    retry = alice.post("/s3/buckets/alice-files/domains/files.other.example/route")
    assert retry.status_code == 409 and code(retry) == "domain_not_verified"
    # Proving it with the TXT record routes it in the same call.
    value = created["verification"]["value"]
    env["txt"][f"TXT:{created['verification']['name']}"] = [value]
    verified = alice.post("/s3/buckets/alice-files/domains/files.other.example/verify").json()
    assert verified == {"verified": True, "route": {"state": "manual", "error_code": None}}


# ----------------------------------------------------------------------------- traefik file


def test_traefik_file_route_created_and_removed(space: Space,
                                                monkeypatch: pytest.MonkeyPatch) -> None:
    agent = FakeAgent(writable=True)
    use_traefik(space, monkeypatch, agent)
    alice = owner_with_bucket(space)
    created = attach(alice, "cdn.alice.example")
    assert created["route"] == {"state": "ok", "error_code": None}
    assert file_hosts(agent) == ["cdn.alice.example"]
    payload = agent.requests[-1][2]
    assert payload["services"][0]["https"] is True
    assert payload["target_host"] == "mrk-stack-mrk-mirror-1"
    # A service domain of S3 shares the same router entry; both stay in the file.
    service_domain = space.client.post(DOMAINS, headers=space.headers,
                                       json={"service_id": "s3", "host": "s3.example.net"})
    assert service_domain.status_code == 201, service_domain.text
    assert sorted(file_hosts(agent)) == ["cdn.alice.example", "s3.example.net"]

    deleted = alice.call("DELETE", "/s3/buckets/alice-files/domains/cdn.alice.example")
    assert deleted.status_code == 200, deleted.text
    assert file_hosts(agent) == ["s3.example.net"]
    assert "cdn.alice.example" not in routes().records()


def test_traefik_write_failure_rolls_back_and_retry_routes(
        space: Space, monkeypatch: pytest.MonkeyPatch) -> None:
    agent = FakeAgent(writable=True)
    use_traefik(space, monkeypatch, agent)
    alice = owner_with_bucket(space)
    original = agent.request
    failures = {"left": 1}

    async def flaky(method: str, path: str, body: Any = None, **kw: Any) -> Any:
        if failures["left"] and path == "/v1/traefik/domains":
            failures["left"] -= 1
            agent.requests.append((method, path, body))
            raise domains_routing.RoutingError("agent_unreachable", 502, "down")
        return await original(method, path, body, **kw)

    monkeypatch.setattr(agent, "request", flaky)
    created = attach(alice, "cdn.alice.example")
    assert created["route"] == {"state": "failed", "error_code": "traefik_write_failed"}
    # Rolled back: the file was rewritten without the host.
    assert file_hosts(agent) == []
    assert admin_item(space, "cdn.alice.example")["route"]["upstream_code"] == (
        "agent_unreachable")

    retried = alice.post("/s3/buckets/alice-files/domains/cdn.alice.example/route")
    assert retried.status_code == 200, retried.text
    assert retried.json()["route"] == {"state": "ok", "error_code": None}
    assert file_hosts(agent) == ["cdn.alice.example"]


def test_turning_routing_off_removes_routes(space: Space,
                                            monkeypatch: pytest.MonkeyPatch) -> None:
    agent = FakeAgent(writable=True)
    use_traefik(space, monkeypatch, agent)
    alice = owner_with_bucket(space)
    attach(alice, "cdn.alice.example")
    assert file_hosts(agent) == ["cdn.alice.example"]
    routes().service.store.put_settings({"route_bucket_domains": False}, None)
    done = space.client.post(f"{DOMAINS}/bucket-routes/reconcile", headers=space.headers)
    assert done.status_code == 200, done.text
    assert file_hosts(agent) == []
    assert admin_routes(space)["enabled"] is False
    item = admin_item(space, "cdn.alice.example")
    assert item["route"]["state"] == "off"

    routes().service.store.put_settings({"route_bucket_domains": True}, None)
    space.client.post(f"{DOMAINS}/bucket-routes/reconcile", headers=space.headers)
    assert file_hosts(agent) == ["cdn.alice.example"]


# ----------------------------------------------------------------------------- dokploy api


@pytest.fixture
def dokploy(monkeypatch: pytest.MonkeyPatch, space: Space) -> FakeDokploy:
    fake = FakeDokploy()
    monkeypatch.setattr(dokploy_client, "TRANSPORT_FACTORY",
                        lambda: httpx.MockTransport(fake.handler))
    monkeypatch.setattr(domains_routing.socket, "gethostname", lambda: "abcdef123456")
    configured = space.client.put("/api/v1/dokploy/config", headers=space.headers,
                                  json={"url": PANEL_URL, "api_key": API_KEY,
                                        "rate_limit_per_second": 20})
    assert configured.status_code == 200, configured.text
    agent = FakeAgent(writable=False)
    monkeypatch.setattr(routes().service.routing, "agent", lambda: agent)
    routes().service.routing.invalidate()
    return fake


def test_dokploy_route_created_pending_redeploy_and_removed(space: Space,
                                                            dokploy: FakeDokploy) -> None:
    alice = owner_with_bucket(space)
    created = attach(alice, "cdn.alice.example")
    # Compose: Dokploy writes the labels on the next deploy (admin's call).
    assert created["route"] == {"state": "pending", "error_code": None}
    sent = dokploy.created[0]
    assert {key: sent[key] for key in ("host", "port", "https", "composeId", "serviceName")} == {
        "host": "cdn.alice.example", "port": 9000, "https": True, "composeId": "cmp1",
        "serviceName": "mrk-mirror"}
    route = admin_item(space, "cdn.alice.example")["route"]
    assert route["mode"] == "dokploy_api" and route["redeploy_required"] is True
    assert route["suggested_action"]["endpoint"].endswith("/compose/cmp1/redeploy")
    assert not [r for r in dokploy.requests if r.url.path.endswith(".redeploy")]

    # After the admin redeployed, a retry confirms Dokploy has it.
    retried = space.client.post(f"{DOMAINS}/bucket-routes/cdn.alice.example/retry",
                                headers=space.headers)
    assert retried.status_code == 200, retried.text
    assert retried.json()["route"]["state"] == "ok"
    assert len(dokploy.created) == 1

    gone = alice.call("DELETE", "/s3/buckets/alice-files/domains/cdn.alice.example")
    assert gone.status_code == 200
    assert dokploy.created == []


def test_dokploy_conflicts_are_refused(space: Space, dokploy: FakeDokploy) -> None:
    alice = space.user("alice")
    unlimited(space, alice)
    zone(alice, "example.com")
    bucket(alice, "alice-files")
    taken = alice.post("/s3/buckets/alice-files/domains", {"host": "shop.example.com"})
    assert taken.status_code == 409 and code(taken) == "domain_unavailable"
    assert dokploy.created == []


def test_dokploy_record_failure_rolls_back_the_domain(space: Space, dokploy: FakeDokploy,
                                                      monkeypatch: pytest.MonkeyPatch) -> None:
    alice = owner_with_bucket(space)
    original = bucket_routes.BucketRoutes._put

    def broken(self: Any, host: str, record: dict[str, Any] | None) -> None:
        if record is not None and record.get("dokploy_domain_id"):
            raise RuntimeError("database is gone")
        original(self, host, record)

    monkeypatch.setattr(bucket_routes.BucketRoutes, "_put", broken)
    created = attach(alice, "cdn.alice.example")
    assert created["route"]["state"] == "pending"  # no record: waiting for the next try
    # The Dokploy domain created a moment earlier was removed again.
    assert dokploy.created == []
    assert [r for r in dokploy.requests if r.url.path.endswith("domain.delete")]


# ----------------------------------------------------------------------------- isolation


def test_isolation_and_host_conflicts(space: Space) -> None:
    alice = owner_with_bucket(space)
    bob = owner_with_bucket(space, "bob")
    attach(bob, "cdn.bob.example")
    # Alice cannot see, retry or take bob's domain.
    hidden = alice.post("/s3/buckets/bob-files/domains/cdn.bob.example/route")
    assert hidden.status_code == 404
    mine = alice.post("/s3/buckets/alice-files/domains/cdn.bob.example/route")
    assert mine.status_code == 404
    taken = alice.post("/s3/buckets/alice-files/domains", {"host": "cdn.bob.example"})
    assert taken.status_code == 409 and code(taken) == "domain_unavailable"
    # A service domain cannot take a bucket's host either.
    clash = space.client.post(DOMAINS, headers=space.headers,
                              json={"service_id": "npm", "host": "cdn.bob.example"})
    assert clash.status_code == 409 and clash.json()["error"]["code"] == "domain_exists"
    assert clash.json()["error"]["owner"] == {"kind": "bucket"}
    # Workspace users have no access to the admin route list.
    assert alice.client.get(f"{DOMAINS}/bucket-routes").status_code == 403
    assert routes().records()["cdn.bob.example"]["workspace_id"] == bob.personal


def test_bucket_delete_and_ownership_transfer_remove_routes(
        space: Space, monkeypatch: pytest.MonkeyPatch) -> None:
    agent = FakeAgent(writable=True)
    use_traefik(space, monkeypatch, agent)
    alice = owner_with_bucket(space)
    attach(alice, "cdn.alice.example")
    attach(alice, "img.alice.example")
    assert sorted(file_hosts(agent)) == ["cdn.alice.example", "img.alice.example"]

    moved = space.admin("POST", "/ownership/transfer", json={
        "kind": "bucket_domain", "resource_id": "img.alice.example", "workspace_id": None})
    assert moved.status_code == 200
    space.client.post(f"{DOMAINS}/bucket-routes/reconcile", headers=space.headers)
    assert file_hosts(agent) == ["cdn.alice.example"]

    removed = alice.call("DELETE", "/s3/buckets/alice-files",
                         json={"confirmation": "alice-files", "force": True})
    assert removed.status_code == 200, removed.text
    assert file_hosts(agent) == []
    assert routes().records() == {}
