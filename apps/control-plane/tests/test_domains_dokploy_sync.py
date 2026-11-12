"""Domains in harmony with Dokploy (docs/35): read-back, adoption, redeploy wait, honest checks."""

from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Any

import httpx
import pytest
from mrk_control_plane.modules import dokploy_client, domains_routing, services
from mrk_control_plane.modules.domains_verify import InternalRoute, verify_domain

from .test_services_domains import (
    API_KEY,
    PANEL_URL,
    SERVER_IP,
    FakeAgent,
    FakeDokploy,
    FakeProbes,
    add,
    app_client,
    isolated,
)

# Fixtures shared with test_services_domains.
__all__ = ["app_client", "isolated"]


class DokployWithDomains(FakeDokploy):
    """Full domain items (port, serviceName, https), deployments and a named Compose."""

    def __init__(self) -> None:
        super().__init__()
        self.deployments: dict[str, list[dict[str, Any]]] = {"cmp1": [
            {"deploymentId": "d1", "status": "done", "createdAt": "2026-01-01T00:00:00.000Z"}]}
        self.create_error: tuple[int, str] | None = None
        self.delete_error: tuple[int, str] | None = None

    def handler(self, request: httpx.Request) -> httpx.Response:
        procedure = request.url.path.removeprefix("/api/")
        params = dict(request.url.params)
        if procedure == "domain.byComposeId":
            self.requests.append(request)
            return httpx.Response(200, json=[
                item for item in self.created
                if item.get("composeId", "cmp1") == params["composeId"]])
        if procedure == "deployment.allByCompose":
            self.requests.append(request)
            return httpx.Response(200, json=self.deployments.get(params["composeId"], []))
        if procedure == "domain.create" and self.create_error:
            self.requests.append(request)
            return httpx.Response(self.create_error[0], json={"message": self.create_error[1]})
        if procedure == "domain.delete" and self.delete_error:
            self.requests.append(request)
            return httpx.Response(self.delete_error[0], json={"message": self.delete_error[1]})
        response = super().handler(request)
        if procedure == "compose.one" and response.status_code == 200:
            # compose.one carries the Compose's domains (the conflict check caches them).
            detail = json.loads(response.content)
            detail["domains"] = [entry for entry in self.created
                                 if entry.get("composeId", "cmp1") == params["composeId"]]
            return httpx.Response(200, json=detail)
        return response

    def put(self, host: str, port: int, *, service: str = "mrk-mirror", https: bool = True,
            domain_id: str | None = None, compose: str = "cmp1") -> str:
        domain_id = domain_id or f"manual{len(self.created) + 1}"
        self.created.append({"host": host, "path": "/", "port": port, "serviceName": service,
                             "https": https, "domainId": domain_id, "composeId": compose,
                             "createdAt": "2026-02-01T00:00:00.000Z"})
        return domain_id


@pytest.fixture
def dokploy(monkeypatch: pytest.MonkeyPatch) -> DokployWithDomains:
    fake = DokployWithDomains()
    monkeypatch.setattr(dokploy_client, "TRANSPORT_FACTORY",
                        lambda: httpx.MockTransport(fake.handler))
    monkeypatch.setattr(domains_routing.socket, "gethostname", lambda: "abcdef123456")
    return fake


def connect(client: Any, headers: dict[str, str], monkeypatch: pytest.MonkeyPatch,
            agent: FakeAgent | None = None) -> FakeAgent:
    configured = client.put("/api/v1/dokploy/config", headers=headers,
                            json={"url": PANEL_URL, "api_key": API_KEY,
                                  "rate_limit_per_second": 20})
    assert configured.status_code == 200, configured.text
    agent = agent or FakeAgent(writable=False)
    assert services.ACTIVE_SERVICE is not None
    monkeypatch.setattr(services.ACTIVE_SERVICE.routing, "agent", lambda: agent)
    services.ACTIVE_SERVICE.routing.invalidate()
    return agent


def reconcile(client: Any, headers: dict[str, str]) -> dict[str, Any]:
    response = client.post("/api/v1/domains/reconcile", headers=headers)
    assert response.status_code == 200, response.text
    return response.json()


def domain(client: Any, host: str) -> dict[str, Any]:
    return next(item for item in client.get("/api/v1/domains").json()["items"]
                if item["host"] == host)


# ----------------------------------------------------------------------------- checks


def test_checks_go_through_the_internal_traefik(isolated: FakeProbes) -> None:
    isolated.dns["dash.example.com"] = [SERVER_IP]
    isolated.local.add("dokploy-traefik")
    isolated.http["dash.example.com"] = {"ok": True, "status_code": 200,
                                         "matched_service": "panel"}
    health = asyncio.run(verify_domain(
        host="dash.example.com", service_id="panel", https=True, expected_ips=[SERVER_IP],
        probes=isolated.probes(), internal=InternalRoute("dokploy-traefik")))
    assert health["problem_code"] is None and health["checked_via"] == "traefik_internal"
    # The real SNI/Host, sent to Traefik inside the Docker network (no hairpin NAT).
    assert ("tls", "dash.example.com", "dokploy-traefik", 443) in isolated.calls
    assert ("http", "dash.example.com", "dokploy-traefik", 443) in isolated.calls
    assert health["dns"]["ok"] is True  # DNS still from the public records


def test_own_address_timeout_is_not_an_alarm(isolated: FakeProbes) -> None:
    isolated.dns["dash.example.com"] = [SERVER_IP]
    isolated.tls["dash.example.com"] = {"connected": False, "verified": False,
                                        "error": "TimeoutError", "timeout": True}
    health = asyncio.run(verify_domain(
        host="dash.example.com", service_id="panel", https=True, expected_ips=[SERVER_IP],
        probes=isolated.probes(), internal=InternalRoute("dokploy-traefik")))
    assert health["notice"] == "not_checkable_from_server"
    assert health["problem_code"] is None and health["checked_via"] == "public"
    # A refused connection is a real answer: unreachable.
    isolated.tls["dash.example.com"] = {"connected": False, "verified": False,
                                        "error": "ConnectionRefusedError"}
    refused = asyncio.run(verify_domain(
        host="dash.example.com", service_id="panel", https=True, expected_ips=[SERVER_IP],
        probes=isolated.probes()))
    assert refused["problem_code"] == "unreachable" and refused["notice"] is None


def test_not_checkable_domain_raises_no_event(app_client, isolated: FakeProbes) -> None:
    client, headers, events, _data_dir = app_client
    isolated.dns["dash.example.com"] = [SERVER_IP]
    isolated.tls["dash.example.com"] = {"connected": False, "verified": False,
                                        "error": "TimeoutError", "timeout": True}
    created = add(client, headers, "panel", "dash.example.com", mode="manual").json()["domain"]
    checked = client.post(f"/api/v1/domains/{created['id']}/verify", headers=headers).json()
    assert checked["health"]["notice"] == "not_checkable_from_server"
    time.sleep(0.2)
    assert "domain.unhealthy" not in [event.type for event in events]
    home = client.get("/api/v1/home").json()
    assert not [item for item in home["attention"] if item["rule"] == "domain_problem"]
    # Manual rows carry the server's own steps (right stack and port).
    listed = domain(client, "dash.example.com")
    assert listed["instructions"]["dokploy"]["port"] == 8080
    assert listed["source"] == "panel" and listed["pending_redeploy"] is False


# ----------------------------------------------------------------------------- read-back


def test_reconcile_upgrades_imports_and_marks_removed(app_client, dokploy, monkeypatch,
                                                      isolated: FakeProbes) -> None:
    client, headers, events, _data_dir = app_client
    # Added by hand while detection failed: a manual row Dokploy already has.
    manual = add(client, headers, "panel", "dash.example.com", mode="manual")
    assert manual.status_code == 201, manual.text
    connect(client, headers, monkeypatch)
    dokploy.put("dash.example.com", 8080, domain_id="dash1")
    dokploy.put("files.example.com", 9000, https=False, domain_id="files1")
    dokploy.put("other.example.com", 5432, domain_id="db1")  # not a DevAssist service
    result = reconcile(client, headers)
    assert result["status"] == "ok", result
    assert (result["upgraded"], result["imported"]) == (1, 1)
    dash = domain(client, "dash.example.com")
    assert dash["mode"] == "dokploy_api" and dash["dokploy_domain_id"] == "dash1"
    files = domain(client, "files.example.com")
    assert files["service_id"] == "s3" and files["source"] == "dokploy"
    assert files["https"] is False and files["mode"] == "dokploy_api"
    hosts = [item["host"] for item in client.get("/api/v1/domains").json()["items"]]
    assert "other.example.com" not in hosts
    # Synced at once: the S3 public endpoint now uses the imported domain.
    assert client.get("/api/v1/s3/settings").json()["public_endpoint"] == (
        "http://files.example.com")
    assert not [r for r in dokploy.requests if r.url.path.endswith("domain.create")]

    # Removed in Dokploy: marked, no alarm, kept (the panel row is never dropped silently).
    time.sleep(0.3)  # the background checks of the imported rows
    seen = len(events)
    dokploy.created = [item for item in dokploy.created if item["domainId"] != "files1"]
    assert reconcile(client, headers)["removed"] == 1
    files = domain(client, "files.example.com")
    assert files["removed_in_dokploy"] is True
    checked = client.post(f"/api/v1/domains/{files['id']}/verify", headers=headers).json()
    assert checked["health"]["notice"] == "removed_in_dokploy"
    assert checked["health"]["problem_code"] is None
    time.sleep(0.2)
    assert "domain.unhealthy" not in [event.type for event in events[seen:]]
    # Back in Dokploy: the mark goes away.
    dokploy.put("files.example.com", 9000, https=False, domain_id="files1")
    assert reconcile(client, headers)["restored"] == 1
    assert domain(client, "files.example.com")["removed_in_dokploy"] is False


def test_bucket_hosts_are_never_imported_as_service_domains(app_client, dokploy,
                                                            monkeypatch) -> None:
    client, headers, _events, _data_dir = app_client
    connect(client, headers, monkeypatch)
    assert client.post("/api/v1/s3/buckets", headers=headers,
                       json={"name": "sapra"}).status_code == 201
    assert services.ACTIVE_SERVICE is not None
    services.ACTIVE_SERVICE.bucket_routes.set_admin_domain("s3.sapra.example", "sapra")
    dokploy.put("s3.sapra.example", 9000, domain_id="b1")
    assert reconcile(client, headers)["imported"] == 0
    assert client.get("/api/v1/domains").json()["items"] == []


# ----------------------------------------------------------------------------- create


def test_create_adopts_the_services_own_dokploy_domain(app_client, dokploy, monkeypatch) -> None:
    client, headers, _events, _data_dir = app_client
    dokploy.put("npm.example.com", 4873, domain_id="npm1")
    dokploy.put("pypi.example.com", 4873, domain_id="x2")
    connect(client, headers, monkeypatch)
    adopted = add(client, headers, "npm", "npm.example.com")
    assert adopted.status_code == 201, adopted.text
    body = adopted.json()
    assert body["applied"]["adopted"] is True, (body["applied"], body["domain"])
    assert body["applied"]["redeploy_required"] is False
    assert body["domain"]["mode"] == "dokploy_api" and body["domain"]["dokploy_domain_id"] == (
        "npm1")
    assert body["domain"]["source"] == "dokploy"
    assert not [r for r in dokploy.requests if r.url.path.endswith("domain.create")]
    # Same Compose but npm's port, asked for pypi: refused (a conflict, or already
    # imported for npm by the read-back that runs after Dokploy is connected).
    clash = add(client, headers, "pypi", "pypi.example.com")
    assert clash.status_code == 409
    assert clash.json()["error"]["code"] in {"domain_in_use", "domain_exists"}


def test_new_dokploy_domain_waits_for_a_deploy_without_alarms(app_client, dokploy, monkeypatch,
                                                             isolated: FakeProbes) -> None:
    client, headers, events, _data_dir = app_client
    connect(client, headers, monkeypatch)
    created = add(client, headers, "npm", "npm.example.com")
    assert created.status_code == 201, created.text
    body = created.json()
    assert body["applied"]["redeploy_required"] is True
    row = domain(client, "npm.example.com")
    assert row["pending_redeploy"] is True
    assert row["suggested_action"]["endpoint"] == "/api/v1/dokploy/services/compose/cmp1/redeploy"
    checked = client.post(f"/api/v1/domains/{row['id']}/verify", headers=headers).json()
    assert checked["health"]["notice"] == "pending_redeploy"
    assert checked["health"]["held_problem_code"] == "dns_missing"
    assert checked["health"]["problem_code"] is None
    time.sleep(0.2)
    assert "domain.unhealthy" not in [event.type for event in events]
    # No new deployment yet: still waiting.
    assert reconcile(client, headers)["deployed"] == 0
    assert domain(client, "npm.example.com")["pending_redeploy"] is True
    # The admin deployed; Dokploy reports a NEW finished deployment.
    dokploy.deployments["cmp1"].append(
        {"deploymentId": "d2", "status": "done", "createdAt": "2026-03-01T00:00:00.000Z"})
    assert reconcile(client, headers)["deployed"] == 1
    assert domain(client, "npm.example.com")["pending_redeploy"] is False


def test_dokploy_errors_keep_their_meaning_and_are_logged(app_client, dokploy, monkeypatch,
                                                          caplog) -> None:
    client, headers, _events, _data_dir = app_client
    connect(client, headers, monkeypatch)
    dokploy.create_error = (400, "Compose not found")
    with caplog.at_level(logging.WARNING, logger="mrk_control_plane.modules.domains_routing"):
        failed = add(client, headers, "npm", "npm.example.com")
    assert failed.status_code == 409, failed.text
    error = failed.json()["error"]
    assert error["code"] == "dokploy_target_missing"
    assert "Compose not found" in error["upstream_message"]
    record = next(item for item in caplog.records if "domain.create" in item.getMessage())
    assert record.error_code == "dokploy_not_found" and record.upstream_status == 400
    assert client.get("/api/v1/domains").json()["items"] == []


def test_failed_save_rolls_the_dokploy_domain_back(app_client, dokploy, monkeypatch) -> None:
    client, headers, _events, _data_dir = app_client
    connect(client, headers, monkeypatch)
    assert services.ACTIVE_SERVICE is not None

    async def broken_sync() -> dict[str, Any]:
        raise RuntimeError("sync exploded")

    monkeypatch.setattr(services.ACTIVE_SERVICE, "sync", broken_sync)
    try:
        failed = add(client, headers, "npm", "npm.example.com")
    except RuntimeError:
        pass
    else:
        assert failed.status_code == 500
    assert dokploy.created == []
    assert [r for r in dokploy.requests if r.url.path.endswith("domain.delete")]
    assert services.ACTIVE_SERVICE.list_domains() == []


def test_auto_mode_refuses_to_go_manual_when_dokploy_cannot_be_read(app_client, dokploy,
                                                                     monkeypatch) -> None:
    client, headers, _events, _data_dir = app_client
    connect(client, headers, monkeypatch)
    dokploy.online = False
    failed = add(client, headers, "npm", "npm.example.com")
    assert failed.status_code == 409 and failed.json()["error"]["code"] == (
        "routing_detection_failed")
    assert client.get("/api/v1/domains").json()["items"] == []
    # Choosing manual on purpose still works.
    assert add(client, headers, "npm", "npm.example.com", mode="manual").status_code == 201
    # A failed detection is not kept for minutes: Dokploy back -> found again soon.
    assert services.ACTIVE_SERVICE is not None
    cached = services.ACTIVE_SERVICE.routing._detected  # noqa: SLF001
    assert cached is not None and cached[2] == domains_routing.DETECT_FAIL_TTL_SECONDS


class NamedPanelDokploy(DokployWithDomains):
    """The panel's Compose is found by the service it defines, not by container labels."""

    def handler(self, request: httpx.Request) -> httpx.Response:
        procedure = request.url.path.removeprefix("/api/")
        if procedure == "compose.one":
            self.requests.append(request)
            return httpx.Response(200, json={"composeId": "cmp1", "name": "panel",
                                             "composeFile": "services:\n  mrk-panel:\n"
                                                            "    image: x\n"})
        response = super().handler(request)
        if procedure == "project.all":
            projects = json.loads(response.content)
            projects[0]["environments"][0]["compose"][0].update(
                {"name": "panel", "appName": "devassist-panel-x"})
            return httpx.Response(200, json=projects)
        return response


def test_detection_finds_the_panel_compose_without_label_match(app_client, monkeypatch) -> None:
    client, headers, _events, _data_dir = app_client
    fake = NamedPanelDokploy()
    monkeypatch.setattr(dokploy_client, "TRANSPORT_FACTORY",
                        lambda: httpx.MockTransport(fake.handler))
    # Another hostname: the agent cannot tell which container is the panel.
    monkeypatch.setattr(domains_routing.socket, "gethostname", lambda: "somethingelse")
    connect(client, headers, monkeypatch)
    view = client.get("/api/v1/domains/routing?refresh=true").json()
    assert view["detected"]["inside_dokploy"] is True
    assert view["detected"]["detected_by"] == "compose_lookup"
    assert view["detected"]["dokploy_service_id"] == "cmp1"
    assert view["effective_mode"] == "dokploy_api"
    created = add(client, headers, "panel", "dash.example.com")
    assert created.status_code == 201, created.text
    assert fake.created[0]["serviceName"] == "mrk-panel"


# ----------------------------------------------------------------------------- delete


def test_panel_domain_in_use_needs_explicit_confirmation(app_client, dokploy, monkeypatch) -> None:
    client, headers, _events, _data_dir = app_client
    first = add(client, headers, "panel", "dash.example.com", mode="manual").json()["domain"]
    second = add(client, headers, "panel", "admin.example.com", mode="manual").json()["domain"]
    on_domain = {**headers, "Host": "dash.example.com"}
    refused = client.request("DELETE", f"/api/v1/domains/{first['id']}", headers=on_domain,
                             json={"confirmation": "dash.example.com"})
    assert refused.status_code == 409, refused.text
    assert refused.json()["error"]["code"] == "panel_domain_in_use"
    assert refused.json()["error"]["in_use_now"] is True
    # Another panel domain (not in use) goes; then the last one needs the flag too.
    assert client.request("DELETE", f"/api/v1/domains/{second['id']}", headers=headers,
                          json={"confirmation": "admin.example.com"}).status_code == 200
    last = client.request("DELETE", f"/api/v1/domains/{first['id']}", headers=headers,
                          json={"confirmation": "dash.example.com"})
    assert last.status_code == 409 and last.json()["error"]["last_panel_domain"] is True
    done = client.request("DELETE", f"/api/v1/domains/{first['id']}", headers=headers,
                          json={"confirmation": "dash.example.com", "confirm_current": True})
    assert done.status_code == 200, done.text


def test_delete_of_a_domain_already_gone_in_dokploy_succeeds(app_client, dokploy,
                                                             monkeypatch) -> None:
    client, headers, _events, _data_dir = app_client
    connect(client, headers, monkeypatch)
    created = add(client, headers, "npm", "npm.example.com").json()["domain"]
    dokploy.delete_error = (400, "Domain not found")
    gone = client.request("DELETE", f"/api/v1/domains/{created['id']}", headers=headers,
                          json={"confirmation": "npm.example.com"})
    assert gone.status_code == 200, gone.text
    assert client.get("/api/v1/domains").json()["items"] == []
