"""My services + service domains (docs/35): hosts, routing modes, sync, verification, RBAC."""

from __future__ import annotations

import asyncio
import json
import os
import time
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient
from mrk_control_plane import process_control
from mrk_control_plane.agent import traefik
from mrk_control_plane.agent.app import AgentConfig, create_agent_app
from mrk_control_plane.agent.signing import sign_headers
from mrk_control_plane.config import Settings
from mrk_control_plane.main import create_app
from mrk_control_plane.middleware import TrustedHostsHolder
from mrk_control_plane.modules import dokploy_client, domains_routing, services
from mrk_control_plane.modules.domains_hosts import HostError, canonical_host
from mrk_control_plane.modules.domains_verify import Probes, identify, verify_domain
from mrk_control_plane.modules.services_catalog import SERVICE_INDEX, state_from_programs

from .helpers import login_owner

PASSWORD = "a-long-role-password-123"  # noqa: S105 - test-only fixture
API_KEY = "dokployAPIkey_" + "y" * 40  # noqa: S105 - test-only fixture
PANEL_URL = "http://dokploy.lan:3000"
KEY = b"\x07" * 32
SERVER_IP = "203.0.113.10"


# ----------------------------------------------------------------------------- fakes


class FakeProbes:
    """DNS/TLS/HTTP answers per host for verification tests."""

    def __init__(self) -> None:
        self.dns: dict[str, list[str]] = {}
        self.tls: dict[str, dict[str, Any]] = {}
        self.http: dict[str, dict[str, Any]] = {}

    def probes(self) -> Probes:
        async def resolve(host: str) -> list[str]:
            return list(self.dns.get(host, []))

        async def tls(host: str, _address: str) -> dict[str, Any]:
            return self.tls.get(host, {"connected": True, "verified": True,
                                       "expires_at": int(time.time()) + 60 * 86400,
                                       "issuer": "Let's Encrypt", "hostname_match": True})

        async def http(host: str, _address: str, _path: str, _https: bool) -> dict[str, Any]:
            return self.http.get(host, {"ok": False, "status_code": None,
                                        "matched_service": None})

        return Probes(resolve, tls, http)


class FakeSupervisor:
    def __init__(self) -> None:
        self.states = {name: "RUNNING" for name in
                       ("verdaccio", "devpi", "pypi-router", "s3-engine", "pglite",
                        "control-plane")}
        self.calls: list[tuple[str, str]] = []

    def status(self, names):
        return {name: {"state": self.states[name], "description": ""} for name in names
                if name in self.states}

    def action(self, name: str, action: str) -> None:
        if name not in process_control.CONTROLLABLE_PROGRAMS:
            raise process_control.SupervisorError("program_not_controllable", "no")
        self.calls.append((name, action))
        self.states[name] = "STOPPED" if action == "stop" else "RUNNING"


class FakeAgent:
    def __init__(self, *, writable: bool = True) -> None:
        self.writable = writable
        self.requests: list[tuple[str, str, Any]] = []
        self.container = {
            "id": "abcdef1234567890", "name": "mrk-stack-mrk-mirror-1",
            "labels_subset": {"com.docker.compose.project": "mrk-stack-abc123",
                              "com.docker.compose.service": "mrk-mirror"},
            "networks": ["dokploy-network", "mrk-stack-abc123_default"],
        }
        self.reachable = True

    def resolve(self):
        return "panel", "http://mrk-agent:7070", KEY

    async def call(self, path: str):
        if path == "/v1/docker/containers":
            return {"items": [self.container]}
        if path == "/v1/traefik/status":
            return {"configured": True, "writable": self.writable, "file_present": False}
        raise AssertionError(path)

    async def request(self, method: str, path: str, body: Any = None, **_kw: Any):
        self.requests.append((method, path, body))
        if path == "/v1/traefik/domains":
            traefik.render(body)  # the agent would reject an invalid payload
        return {"ok": True}


class FakeDokploy:
    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []
        self.created: list[dict[str, Any]] = []
        self.online = True
        self.other_domains = [{"host": "shop.example.com", "path": "/", "domainId": "x1"}]

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if not self.online:
            raise httpx.ConnectError("down", request=request)
        procedure = request.url.path.removeprefix("/api/")
        params = dict(request.url.params)
        if procedure == "project.all":
            return httpx.Response(200, json=[{
                "projectId": "p1", "name": "Infra",
                "environments": [{
                    "environmentId": "e1", "name": "production",
                    "applications": [{"applicationId": "app1", "name": "shop",
                                      "appName": "shop-app-1", "applicationStatus": "done"}],
                    "compose": [{"composeId": "cmp1", "name": "mrk",
                                 "appName": "mrk-stack-abc123", "composeStatus": "done"}],
                }],
            }])
        if procedure == "domain.byApplicationId":
            return httpx.Response(200, json=self.other_domains)
        if procedure == "domain.byComposeId":
            return httpx.Response(200, json=[
                {"host": item["host"], "path": "/", "domainId": item["domainId"]}
                for item in self.created
            ])
        if procedure == "compose.one":
            assert params.get("composeId") == "cmp1"
            return httpx.Response(200, json={"composeId": "cmp1", "name": "mrk",
                                             "appName": "mrk-stack-abc123",
                                             "environment": {"environmentId": "e1",
                                                             "project": {"projectId": "p1",
                                                                         "name": "Infra"}}})
        if procedure == "settings.getDokployVersion":
            return httpx.Response(200, json="v0.31.0")
        if request.method == "POST" and procedure == "domain.create":
            body = json.loads(request.content)
            item = {**body, "domainId": f"dom{len(self.created) + 1}"}
            self.created.append(item)
            return httpx.Response(200, json=item)
        if request.method == "POST" and procedure == "domain.update":
            body = json.loads(request.content)
            for item in self.created:
                if item["domainId"] == body["domainId"]:
                    item.update(body)
            return httpx.Response(200, json=True)
        if request.method == "POST" and procedure == "domain.delete":
            body = json.loads(request.content)
            self.created = [item for item in self.created if item["domainId"] != body["domainId"]]
            return httpx.Response(200, json=True)
        return httpx.Response(404, json={"message": "Not found"})


@pytest.fixture(autouse=True)
def isolated(monkeypatch):
    fake = FakeProbes()
    monkeypatch.setattr(services, "PROBES", fake.probes())
    for name in list(os.environ):
        if name.startswith(("MRK_DOMAINS_", "MRK_DOKPLOY_", "MRK_AGENT_")) or name in {
            "MRK_SERVER_PUBLIC_IPS", "MRK_PYPI_OUTSIDE_URL",
        }:
            monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("MRK_DOKPLOY_POLL_SECONDS", "0")
    monkeypatch.setattr(process_control, "supervisor_available", lambda: False)
    return fake


@pytest.fixture
def supervisor(monkeypatch) -> FakeSupervisor:
    fake = FakeSupervisor()
    monkeypatch.setattr(process_control, "supervisor_available", lambda: True)
    monkeypatch.setattr(process_control, "program_status", fake.status)
    monkeypatch.setattr(process_control, "program_action", fake.action)
    return fake


@pytest.fixture
def dokploy(monkeypatch) -> FakeDokploy:
    fake = FakeDokploy()
    monkeypatch.setattr(dokploy_client, "TRANSPORT_FACTORY",
                        lambda: httpx.MockTransport(fake.handler))
    monkeypatch.setattr(domains_routing.socket, "gethostname", lambda: "abcdef123456")
    return fake


@pytest.fixture
def app_client(tmp_path: Path):
    app = create_app(Settings.for_test(tmp_path / "cp"))
    with TestClient(app) as client:
        headers = {"X-CSRF-Token": str(login_owner(client)["csrf_token"])}
        events: list[Any] = []

        async def collect(event) -> None:
            events.append(event)

        app.state.events.subscribe(collect)
        yield client, headers, events, tmp_path / "cp"


def role_client(owner: TestClient, headers: dict[str, str], role: str):
    created = owner.post("/api/v1/users", headers=headers,
                         json={"username": f"{role}1", "password": PASSWORD, "role": role})
    assert created.status_code == 201, created.text
    client = TestClient(owner.app)
    login = client.post("/api/v1/auth/login",
                        json={"username": f"{role}1", "password": PASSWORD})
    return client, {"X-CSRF-Token": str(login.json()["csrf_token"])}


def add(client, headers, service_id: str, host: str, **extra: Any) -> httpx.Response:
    return client.post("/api/v1/domains", headers=headers,
                       json={"service_id": service_id, "host": host, **extra})


# ----------------------------------------------------------------------------- units


def test_canonical_host_rules() -> None:
    assert canonical_host("  Panel.Example.COM. ") == "panel.example.com"
    assert canonical_host("مخزن.example.com") == "مخزن".encode("idna").decode() + ".example.com"
    assert canonical_host("bücher.example.de") == "xn--bcher-kva.example.de"
    for bad, reason in (
        ("https://a.example.com", "invalid_format"), ("a.example.com/x", "invalid_format"),
        ("*.example.com", "wildcard_not_allowed"), ("a.example.com:8443", "port_not_allowed"),
        ("203.0.113.5", "ip_not_allowed"), ("[2001:db8::1]", "ip_not_allowed"),
        ("localhost", "invalid_format"), ("x.localhost", "reserved_name"),
        ("a b.example.com", "invalid_format"), ("-bad.example.com", "invalid_format"),
        ("", "required"), ("a..example.com", "invalid_format"), ("a.b.123", "invalid_format"),
        ("a`) || Host(`evil.com", "invalid_format"),
    ):
        with pytest.raises(HostError) as caught:
            canonical_host(bad)
        assert caught.value.reason_code == reason, bad


def test_supervisor_status_parsing_and_allowlist() -> None:
    parsed = process_control.parse_status(
        "verdaccio                        RUNNING   pid 12, uptime 0:01:00\n"
        "devpi                            STOPPED   Not started\n"
        "evil                             RUNNING   pid 1\n"
        "garbage line\n"
    )
    assert parsed == {"verdaccio": {"state": "RUNNING", "description": "pid 12, uptime 0:01:00"},
                      "devpi": {"state": "STOPPED", "description": "Not started"}}
    for name in ("pglite", "control-plane", "devpi-configure", "sh"):
        with pytest.raises(process_control.SupervisorError):
            process_control.program_action(name, "stop")
    with pytest.raises(process_control.SupervisorError):
        process_control.program_action("verdaccio", "kill")
    pypi = SERVICE_INDEX["pypi"]
    assert state_from_programs(pypi, None) == ("unknown", "supervisor_unavailable")
    assert state_from_programs(pypi, {"devpi": {"state": "RUNNING"},
                                      "pypi-router": {"state": "RUNNING"}})[0] == "running"
    assert state_from_programs(pypi, {"devpi": {"state": "STOPPED"},
                                      "pypi-router": {"state": "RUNNING"}})[0] == "degraded"
    assert state_from_programs(pypi, {"devpi": {"state": "STOPPED"},
                                      "pypi-router": {"state": "STOPPED"}})[0] == "stopped"


def test_trusted_hosts_holder_keeps_wildcards_and_adds_extras() -> None:
    holder = TrustedHostsHolder(("localhost", "*.lan"))
    assert holder.allows("a.lan") == (True, False)
    assert holder.allows("panel.example.com") == (False, False)
    holder.set_extra(["Panel.Example.com", "*.bad.com"])
    assert holder.allows("panel.example.com") == (True, False)
    assert holder.allows("x.bad.com")[0] is False
    assert TrustedHostsHolder(("*",)).allows("anything")[0] is True
    with pytest.raises(ValueError):
        TrustedHostsHolder(("a*.example.com",))


def test_traefik_render_is_structured_and_strict() -> None:
    payload = {
        "target_host": "mrk-mirror",
        "entrypoints": {"web": "web", "websecure": "websecure"},
        "cert_resolver": "letsencrypt",
        "redirect_middleware": "redirect-to-https@file",
        "services": [
            {"service": "panel", "hosts": ["mrk.example.com", "admin.example.com"],
             "https": True},
            {"service": "pypi", "hosts": ["pypi.example.com", "py.example.com"], "https": True},
            {"service": "s3", "hosts": ["s3.example.com"], "https": False},
        ],
    }
    text = traefik.render(payload)
    assert text.startswith("# Managed by MRK")
    doc = json.loads("\n".join(line for line in text.splitlines() if not line.startswith("#")))
    routers = doc["http"]["routers"]
    secure = routers["mrk-panel-websecure"]
    assert secure["rule"] == "Host(`mrk.example.com`) || Host(`admin.example.com`)"
    assert secure["entryPoints"] == ["websecure"]
    assert secure["tls"] == {"certResolver": "letsencrypt"}
    assert routers["mrk-panel-web"]["middlewares"] == ["redirect-to-https@file"]
    assert doc["http"]["services"]["mrk-panel"]["loadBalancer"]["servers"] == [
        {"url": "http://mrk-mirror:8080"}]
    assert doc["http"]["services"]["mrk-pypi"]["loadBalancer"]["servers"] == [
        {"url": "http://mrk-mirror:3141"}]
    # PyPI: one router per host with its own X-Outside-Url.
    assert routers["mrk-pypi-1-websecure"]["middlewares"] == ["mrk-pypi-outside-1"]
    assert doc["http"]["middlewares"]["mrk-pypi-outside-1"]["headers"][
        "customRequestHeaders"] == {"X-Outside-Url": "https://py.example.com"}
    assert "tls" not in routers["mrk-s3-web"]
    assert doc["http"]["services"]["mrk-s3"]["loadBalancer"]["servers"][0]["url"].endswith(
        ":9000")
    bad_payloads = [
        {**payload, "services": [{"service": "ssh", "hosts": ["a.example.com"]}]},
        {**payload, "services": [{"service": "panel", "hosts": ["a`) || Host(`b.com"]}]},
        {**payload, "services": [{"service": "panel", "hosts": ["A.example.com"]}]},
        {**payload, "target_host": "evil:1234/x"},
        {**payload, "cert_resolver": "le\nx"},
        {**payload, "raw_yaml": "http: {}"},
        {**payload, "services": [{"service": "panel", "hosts": ["a.example.com"],
                                  "url": "http://evil"}]},
        {**payload, "services": [{"service": "panel", "hosts": ["a.example.com"]},
                                 {"service": "npm", "hosts": ["a.example.com"]}]},
        [],
    ]
    for bad in bad_payloads:
        with pytest.raises(traefik.TraefikPayloadError):
            traefik.render(bad)


def signed(client: TestClient, method: str, path: str, body: Any = None) -> httpx.Response:
    raw = b"" if body is None else json.dumps(body, separators=(",", ":")).encode()
    headers = sign_headers(KEY, method, path, raw)
    if body is not None:
        headers["Content-Type"] = "application/json"
    return client.request(method, path, content=raw, headers=headers)


def test_agent_traefik_endpoint_writes_only_its_file(tmp_path: Path, monkeypatch) -> None:
    dynamic = tmp_path / "dynamic"
    dynamic.mkdir()
    (dynamic / "acme.json").write_text("{}", encoding="utf-8")
    (dynamic / "other-app.yml").write_text("http: {}\n", encoding="utf-8")
    config = AgentConfig(key=KEY, docker_socket=str(tmp_path / "none.sock"))
    payload = {"target_host": "mrk-mirror",
               "services": [{"service": "npm", "hosts": ["npm.example.com"], "https": True}]}
    with TestClient(create_agent_app(config)) as client:
        assert signed(client, "GET", "/v1/traefik/status").json()["configured"] is False
        assert signed(client, "POST", "/v1/traefik/domains", payload).status_code == 404
        monkeypatch.setenv("MRK_AGENT_TRAEFIK_DYNAMIC_DIR", str(dynamic))
        status = signed(client, "GET", "/v1/traefik/status").json()
        assert status == {"configured": True, "writable": True, "file_present": False}
        assert signed(client, "GET", "/v1/info").json()["capabilities"]["traefik_file"] is True
        # unsigned and non-allowlisted POSTs are rejected before anything runs
        assert client.post("/v1/traefik/domains", json=payload).status_code == 401
        assert signed(client, "POST", "/v1/traefik/other", payload).status_code == 405
        bad = signed(client, "POST", "/v1/traefik/domains",
                     {**payload, "target_host": "../../etc"})
        assert bad.status_code == 422 and bad.json()["error"] == "invalid_payload"
        written = signed(client, "POST", "/v1/traefik/domains", payload)
        assert written.status_code == 200 and written.json()["file"] == "mrk-domains.yml"
        text = (dynamic / "mrk-domains.yml").read_text(encoding="utf-8")
        assert "Host(`npm.example.com`)" in text and "mrk-mirror:4873" in text
        assert sorted(item.name for item in dynamic.iterdir()) == [
            "acme.json", "mrk-domains.yml", "other-app.yml"]
        assert (dynamic / "acme.json").read_text(encoding="utf-8") == "{}"
        removed = signed(client, "POST", "/v1/traefik/domains/delete", {})
        assert removed.json() == {"ok": True, "removed": True}
        assert sorted(item.name for item in dynamic.iterdir()) == ["acme.json", "other-app.yml"]
    monkeypatch.setenv("MRK_AGENT_TRAEFIK_DYNAMIC_DIR", "relative/dir")
    assert traefik.resolve_dir() is None


def test_traefik_write_refuses_symlinks(tmp_path: Path) -> None:
    dynamic = tmp_path / "dynamic"
    dynamic.mkdir()
    victim = tmp_path / "victim.txt"
    victim.write_text("keep", encoding="utf-8")
    try:
        (dynamic / "mrk-domains.yml").symlink_to(victim)
    except OSError:
        pytest.skip("symlinks not available")
    with pytest.raises(OSError):
        traefik.write(dynamic, "x")
    with pytest.raises(OSError):
        traefik.delete(dynamic)
    assert victim.read_text(encoding="utf-8") == "keep"


def test_verification_problem_codes(isolated: FakeProbes) -> None:
    probes = isolated.probes()
    now = time.time()

    def run(host: str, service: str = "npm", https: bool = True,
            expected: list[str] | None = None) -> dict[str, Any]:
        return asyncio.run(verify_domain(host=host, service_id=service, https=https,
                                         expected_ips=expected or [], probes=probes))

    assert run("missing.example.com")["problem_code"] == "dns_missing"
    isolated.dns["a.example.com"] = ["198.51.100.7"]
    assert run("a.example.com", expected=[SERVER_IP])["problem_code"] == "dns_wrong_ip"
    isolated.dns["loop.example.com"] = ["127.0.0.1"]
    assert run("loop.example.com")["problem_code"] == "dns_wrong_ip"
    isolated.dns["b.example.com"] = [SERVER_IP]
    isolated.http["b.example.com"] = {"ok": True, "status_code": 200, "matched_service": "panel"}
    result = run("b.example.com", expected=[SERVER_IP])
    assert result["problem_code"] == "wrong_service"
    assert result["dns"] == {"ok": True, "addresses": [SERVER_IP], "expected": [SERVER_IP]}
    isolated.http["b.example.com"] = {"ok": True, "status_code": 200, "matched_service": "npm"}
    healthy = run("b.example.com", expected=[SERVER_IP])
    assert healthy["problem_code"] is None and healthy["reach"]["ok"] is True
    assert healthy["tls"]["ok"] is True and healthy["tls"]["issuer"] == "Let's Encrypt"
    isolated.tls["b.example.com"] = {"connected": True, "verified": True,
                                     "expires_at": int(now) + 3 * 86400, "issuer": "LE"}
    assert run("b.example.com")["problem_code"] == "tls_expiring"
    isolated.tls["b.example.com"] = {"connected": True, "verified": False,
                                     "error": "self-signed", "expires_at": int(now) + 90 * 86400}
    assert run("b.example.com")["problem_code"] == "tls_invalid"
    isolated.tls["b.example.com"] = {"connected": False, "verified": False}
    isolated.http["b.example.com"] = {"ok": False}
    assert run("b.example.com")["problem_code"] == "tls_missing"
    assert run("b.example.com", https=False)["problem_code"] == "unreachable"
    assert identify(httpx.Headers({"x-mrk-service": "panel"}), b"") == "panel"
    assert identify(httpx.Headers({"x-powered-by": "verdaccio/6.1.2"}), b"") == "npm"
    assert identify(httpx.Headers({"server": "MRK", "x-amz-request-id": "1"}), b"") == "s3"
    assert identify(httpx.Headers({}), b'{"type": "apiconfig", "result": {}}') == "pypi"
    assert identify(httpx.Headers({"server": "nginx"}), b"<html>") is None


# ----------------------------------------------------------------------------- services API


def test_services_list_and_actions_with_fake_supervisor(app_client, supervisor) -> None:
    client, headers, _events, data_dir = app_client
    listing = client.get("/api/v1/services")
    assert listing.status_code == 200
    payload = listing.json()
    ids = [item["id"] for item in payload["items"]]
    assert ids == ["panel", "npm", "pypi", "s3", "agent", "firewall", "dns", "git", "registry"]
    by_id = {item["id"]: item for item in payload["items"]}
    assert by_id["panel"]["state"] == "running" and by_id["panel"]["controllable"] is False
    assert by_id["panel"]["actions"] == [] and by_id["panel"]["internal_port"] == 8080
    # Settings.for_test leaves npm/pypi disabled: shown as disabled, not controllable.
    assert by_id["npm"]["state"] == "disabled" and by_id["npm"]["controllable"] is False
    s3 = by_id["s3"]
    assert s3["state"] == "running" and s3["controllable"] is True
    assert s3["actions"] == ["start", "stop", "restart"] and s3["internal_port"] == 9000
    assert set(s3["usage"]) >= {"disk_bytes", "items", "last_activity_at", "requests_24h"}
    assert by_id["agent"]["state"] == "not_installed"
    assert by_id["agent"]["reason_code"] == "agent_not_configured"
    assert set(payload["routing"]) == {"mode", "effective_mode", "detected", "detecting"}
    assert payload["routing"]["effective_mode"] == "manual"

    def act(service_id: str, **body: Any) -> httpx.Response:
        return client.post(f"/api/v1/services/{service_id}/actions", headers=headers, json=body)

    assert client.post("/api/v1/services/s3/actions", json={"action": "stop"}).status_code == 403
    wrong = act("s3", action="stop", confirmation="S3!")
    assert wrong.status_code == 422 and wrong.json()["error"]["code"] == "confirmation_mismatch"
    assert act("s3", action="restart").json()["error"]["code"] == "confirmation_mismatch"
    stopped = act("s3", action="stop", confirmation="s3")
    assert stopped.status_code == 200, stopped.text
    assert stopped.json() == {"id": "s3", "action": "stop", "state": "stopped",
                              "reason_code": None}
    assert supervisor.calls == [("s3-engine", "stop")]
    assert json.loads((data_dir / "control-plane" / "stopped-services.json").read_text())[
        "services"] == ["s3"]
    listed = {item["id"]: item for item in client.get("/api/v1/services").json()["items"]}
    assert listed["s3"]["state"] == "stopped" and listed["s3"]["reason_code"] == "stopped_by_user"
    assert act("s3", action="start").json()["state"] == "running"
    assert not json.loads((data_dir / "control-plane" / "stopped-services.json").read_text())[
        "services"]
    assert act("panel", action="restart", confirmation="panel").json()["error"]["code"] == (
        "service_not_controllable")
    assert act("agent", action="start").json()["error"]["code"] == "service_not_controllable"
    assert act("npm", action="start").json()["error"]["code"] == "service_action_not_allowed"
    assert act("nope", action="start").json()["error"]["code"] == "service_not_found"
    assert act("s3", action="kill").json()["error"]["code"] == "service_action_not_allowed"
    actions = [item["action"] for item in client.get("/api/v1/audit-events").json()["items"]]
    assert actions.count("services.action") >= 2


def test_services_without_supervisor_are_not_controllable(app_client) -> None:
    client, headers, _events, _data_dir = app_client
    items = {item["id"]: item for item in client.get("/api/v1/services").json()["items"]}
    assert items["s3"]["controllable"] is False
    assert items["s3"]["reason_code"] == "supervisor_unavailable"
    assert items["s3"]["state"] in {"unknown", "running"}
    result = client.post("/api/v1/services/s3/actions", headers=headers,
                         json={"action": "start"})
    assert result.json()["error"]["code"] == "service_not_controllable"


# ----------------------------------------------------------------------------- domains API


def test_manual_mode_crud_primary_and_trusted_hosts(app_client) -> None:
    client, headers, _events, _data_dir = app_client
    assert client.get("/", headers={"Host": "mrk.example.com"}).status_code == 400
    invalid = add(client, headers, "panel", "https://mrk.example.com")
    assert invalid.status_code == 422
    error = invalid.json()["error"]
    assert error["code"] == "invalid_host"
    assert error["fields"] == [{"field": "host", "reason_code": "invalid_format"}]
    assert add(client, headers, "agent", "a.example.com").json()["error"]["code"] == (
        "invalid_service")
    assert add(client, headers, "panel", "a.example.com", mode="magic").json()["error"][
        "code"] == "invalid_routing_mode"
    created = add(client, headers, "panel", "MRK.Example.com.")
    assert created.status_code == 201, created.text
    body = created.json()
    domain = body["domain"]
    assert domain["host"] == "mrk.example.com" and domain["primary"] is True
    assert domain["mode"] == "manual" and domain["https"] is True
    assert body["applied"]["mode"] == "manual" and body["applied"]["conflict_check"] == "skipped"
    assert body["instructions"]["dokploy"]["port"] == 8080
    assert body["instructions"]["dokploy"]["host"] == "mrk.example.com"
    assert len(body["instructions"]["steps_fa"]) == len(body["instructions"]["steps_en"]) >= 5
    assert body["sync"]["panel"] == {"status": "applied", "hosts": ["mrk.example.com"]}
    # The new panel host is accepted right away (no restart).
    assert client.get("/health/live", headers={"Host": "mrk.example.com"}).status_code == 200
    assert client.get("/health/live").headers["x-mrk-service"] == "panel"

    duplicate = add(client, headers, "npm", "mrk.example.com")
    assert duplicate.status_code == 409
    owner = duplicate.json()["error"]["owner"]
    assert duplicate.json()["error"]["code"] == "domain_exists"
    assert owner["kind"] == "mrk" and owner["service_id"] == "panel" and owner["name"]

    second = add(client, headers, "panel", "admin.example.com", https=False).json()["domain"]
    assert second["primary"] is False
    services_view = {item["id"]: item for item in client.get("/api/v1/services").json()["items"]}
    assert services_view["panel"]["public_url"] == "https://mrk.example.com"
    assert [item["host"] for item in services_view["panel"]["domains"]] == [
        "mrk.example.com", "admin.example.com"]
    assert "health" in services_view["panel"]["domains"][0]

    promoted = client.patch(f"/api/v1/domains/{second['id']}", headers=headers,
                            json={"primary": True})
    assert promoted.status_code == 200 and promoted.json()["domain"]["primary"] is True
    assert "health" in promoted.json()
    listing = client.get("/api/v1/domains").json()["items"]
    assert [(item["host"], item["primary"]) for item in listing] == [
        ("admin.example.com", True), ("mrk.example.com", False)]
    services_view = {item["id"]: item for item in client.get("/api/v1/services").json()["items"]}
    assert services_view["panel"]["public_url"] == "http://admin.example.com"

    wrong = client.request("DELETE", f"/api/v1/domains/{second['id']}", headers=headers,
                           json={"confirmation": "nope"})
    assert wrong.status_code == 422 and wrong.json()["error"]["code"] == "confirmation_mismatch"
    deleted = client.request("DELETE", f"/api/v1/domains/{second['id']}", headers=headers,
                             json={"confirmation": "admin.example.com"})
    assert deleted.status_code == 200
    remaining = client.get("/api/v1/domains").json()["items"]
    assert [(item["host"], item["primary"]) for item in remaining] == [("mrk.example.com", True)]
    assert client.get("/health/live", headers={"Host": "admin.example.com"}).status_code == 400
    assert client.patch("/api/v1/domains/missing", headers=headers,
                        json={"primary": True}).json()["error"]["code"] == "domain_not_found"
    actions = [item["action"] for item in client.get("/api/v1/audit-events").json()["items"]]
    assert {"domain.create", "domain.update", "domain.delete"} <= set(actions)


def test_routing_view_and_put(app_client) -> None:
    client, headers, _events, _data_dir = app_client
    view = client.get("/api/v1/domains/routing").json()
    assert view["mode"] == "auto" and view["effective_mode"] == "manual"
    assert view["available_modes"] == ["manual"]
    assert {card["id"] for card in view["guidance"]} == {
        "dokploy_compose_install", "join_dokploy_network", "agent_traefik_mount"}
    assert all({"title_fa", "title_en", "body_fa", "body_en", "code"} <= set(card)
               for card in view["guidance"])
    assert "dokploy-network" in view["guidance"][1]["code"]
    bad = client.put("/api/v1/domains/routing", headers=headers, json={"mode": "x"})
    assert bad.json()["error"]["code"] == "invalid_routing_mode"
    forced = client.put("/api/v1/domains/routing", headers=headers,
                        json={"mode": "traefik_file"})
    assert forced.status_code == 200 and forced.json()["mode"] == "traefik_file"
    unavailable = add(client, headers, "npm", "npm.example.com")
    assert unavailable.status_code == 409
    assert unavailable.json()["error"]["code"] == "traefik_dir_unavailable"
    assert unavailable.json()["error"]["available_modes"] == ["manual"]
    assert add(client, headers, "npm", "npm.example.com", mode="manual").status_code == 201
    registry = client.get("/api/v1/settings/registry").json()
    keys = {item["key"]: item for group in registry["groups"] for item in group["items"]}
    assert keys["domains.routing_mode"]["value"] == "traefik_file"
    assert keys["domains.verify_interval_seconds"]["value"] == 21600


def test_dokploy_api_mode_conflicts_create_update_delete(app_client, dokploy, monkeypatch) -> None:
    client, headers, _events, _data_dir = app_client
    configured = client.put("/api/v1/dokploy/config", headers=headers,
                            json={"url": PANEL_URL, "api_key": API_KEY,
                                  "rate_limit_per_second": 20})
    assert configured.status_code == 200, configured.text
    agent = FakeAgent(writable=False)
    monkeypatch.setattr(services.ACTIVE_SERVICE.routing, "agent", lambda: agent)
    view = client.get("/api/v1/domains/routing?refresh=true").json()
    detected = view["detected"]
    assert detected["inside_dokploy"] is True and detected["dokploy_connected"] is True
    assert detected["dokploy_service_type"] == "compose"
    assert detected["dokploy_service_id"] == "cmp1"
    assert detected["dokploy_project"] == "Infra" and detected["dokploy_service"] == "mrk"
    assert detected["on_dokploy_network"] is True
    assert view["effective_mode"] == "dokploy_api"
    assert view["available_modes"] == ["dokploy_api", "manual"]

    conflict = add(client, headers, "npm", "shop.example.com")
    assert conflict.status_code == 409
    error = conflict.json()["error"]
    assert error["code"] == "domain_in_use"
    assert error["owner"] == {"kind": "dokploy", "name": "shop", "project": "Infra",
                              "service": "shop", "service_type": "application",
                              "service_id": "app1"}

    created = add(client, headers, "npm", "npm.example.com")
    assert created.status_code == 201, created.text
    body = created.json()
    assert body["domain"]["mode"] == "dokploy_api" and body["domain"]["dokploy_domain_id"] == (
        "dom1")
    assert body["applied"]["redeploy_required"] is True
    assert body["applied"]["suggested_action"]["endpoint"] == (
        "/api/v1/dokploy/services/compose/cmp1/redeploy")
    sent = dokploy.created[0]
    assert {key: sent[key] for key in ("host", "path", "port", "https", "certificateType",
                                       "composeId", "serviceName", "domainType")} == {
        "host": "npm.example.com", "path": "/", "port": 4873, "https": True,
        "certificateType": "letsencrypt", "composeId": "cmp1", "serviceName": "mrk-mirror",
        "domainType": "compose"}
    # MRK never redeploys on its own.
    assert not [r for r in dokploy.requests if r.url.path.endswith(".redeploy")]

    changed = client.patch(f"/api/v1/domains/{body['domain']['id']}", headers=headers,
                           json={"https": False})
    assert changed.status_code == 200, changed.text
    assert dokploy.created[0]["https"] is False and dokploy.created[0]["certificateType"] == (
        "none")
    deleted = client.request("DELETE", f"/api/v1/domains/{body['domain']['id']}",
                             headers=headers, json={"confirmation": "npm.example.com"})
    assert deleted.status_code == 200 and dokploy.created == []

    # Dokploy down: conflict check is skipped (warned), not blocking; dokploy_api then fails.
    dokploy.online = False
    services.ACTIVE_SERVICE.routing.invalidate()
    manual = add(client, headers, "pypi", "pypi.example.com", mode="manual")
    assert manual.status_code == 201
    assert manual.json()["applied"]["conflict_check"] == "skipped"


def test_traefik_file_mode_writes_through_agent(app_client, monkeypatch) -> None:
    client, headers, _events, _data_dir = app_client
    agent = FakeAgent(writable=True)
    monkeypatch.setattr(services.ACTIVE_SERVICE.routing, "agent", lambda: agent)
    monkeypatch.setattr(domains_routing.socket, "gethostname", lambda: "abcdef123456")
    enabled = client.put("/api/v1/domains/routing", headers=headers,
                         json={"mode": "auto", "traefik_file_enabled": True})
    assert enabled.json()["effective_mode"] == "traefik_file"
    first = add(client, headers, "s3", "s3.example.com")
    assert first.status_code == 201, first.text
    add(client, headers, "s3", "files.example.com")
    method, path, payload = agent.requests[-1]
    assert (method, path) == ("POST", "/v1/traefik/domains")
    assert payload["target_host"] == "mrk-stack-mrk-mirror-1"
    assert payload["services"] == [{"service": "s3", "hosts": ["s3.example.com",
                                                               "files.example.com"],
                                    "https": True}]
    assert payload["cert_resolver"] == "letsencrypt"
    for item in client.get("/api/v1/domains").json()["items"]:
        client.request("DELETE", f"/api/v1/domains/{item['id']}", headers=headers,
                       json={"confirmation": item["host"]})
    assert agent.requests[-1][1] == "/v1/traefik/domains/delete"


def test_sync_s3_and_pypi_respects_manual_values(app_client) -> None:
    client, headers, _events, data_dir = app_client
    created = add(client, headers, "s3", "s3.example.com", mode="manual").json()
    assert created["sync"]["s3"]["status"] == "applied"
    settings = client.get("/api/v1/s3/settings").json()
    assert settings["public_endpoint"] == "https://s3.example.com"
    assert settings["virtual_host_suffix"] == "s3.example.com"
    add(client, headers, "s3", "files.example.com", mode="manual")
    snapshot = json.loads((data_dir / "modules" / "s3" / "config.json").read_text())
    assert snapshot["virtual_host_suffixes"] == ["s3.example.com", "files.example.com"]
    # A value set by hand on the S3 page is kept.
    put = client.put("/api/v1/s3/settings", headers=headers,
                     json={"public_endpoint": "https://manual.example.net"})
    assert put.status_code == 200
    second = client.get("/api/v1/domains").json()["items"]
    files = next(item for item in second if item["host"] == "files.example.com")
    result = client.patch(f"/api/v1/domains/{files['id']}", headers=headers,
                          json={"primary": True}).json()
    assert result["sync"]["s3"]["status"] == "manual_override"
    assert result["sync"]["s3"]["manual_keys"] == ["public_endpoint"]
    settings = client.get("/api/v1/s3/settings").json()
    assert settings["public_endpoint"] == "https://manual.example.net"
    assert settings["virtual_host_suffix"] == "files.example.com"

    pypi = add(client, headers, "pypi", "pypi.example.com", mode="manual").json()
    assert pypi["sync"]["pypi"]["outside_url"] == "https://pypi.example.com"
    assert pypi["sync"]["pypi"]["restart_required"] is True  # no supervisor here
    assert (data_dir / "pypi" / "outside-url").read_text().strip() == "https://pypi.example.com"
    client.request("DELETE", f"/api/v1/domains/{pypi['domain']['id']}", headers=headers,
                   json={"confirmation": "pypi.example.com"})
    assert not (data_dir / "pypi" / "outside-url").exists()
    home = client.get("/api/v1/home").json()
    assert "s3_public_endpoint_missing" not in {item["rule"] for item in home["attention"]}


def test_verify_endpoint_stores_health_and_emits_events(app_client, isolated) -> None:
    client, headers, events, _data_dir = app_client
    created = add(client, headers, "npm", "npm.example.com", mode="manual").json()["domain"]
    verified = client.post(f"/api/v1/domains/{created['id']}/verify", headers=headers)
    assert verified.status_code == 200
    health = verified.json()["health"]
    assert health["problem_code"] == "dns_missing" and health["checked_at"]
    assert set(health) >= {"dns", "tls", "reach", "checked_at", "problem_code"}
    stored = client.get("/api/v1/domains").json()["items"][0]["health"]
    assert stored["problem_code"] == "dns_missing"
    isolated.dns["npm.example.com"] = [SERVER_IP]
    isolated.tls["npm.example.com"] = {"connected": True, "verified": True,
                                       "expires_at": int(time.time()) + 2 * 86400,
                                       "issuer": "LE", "hostname_match": True}
    isolated.http["npm.example.com"] = {"ok": True, "status_code": 200,
                                        "matched_service": "npm"}
    expiring = client.post(f"/api/v1/domains/{created['id']}/verify", headers=headers).json()
    assert expiring["health"]["problem_code"] == "tls_expiring"
    time.sleep(0.2)
    types = [event.type for event in events]
    assert "domain.unhealthy" in types and "domain.cert_expiring" in types
    home = client.get("/api/v1/home").json()
    problems = [item for item in home["attention"] if item["rule"] == "domain_problem"]
    assert problems and problems[0]["params"]["host"] == "npm.example.com"
    assert problems[0]["action"]["route"] == f"#/services?domain={created['id']}"
    assert {"my_services", "add_domain"} <= {item["id"] for item in home["quick_actions"]}


def test_permissions_by_role(app_client) -> None:
    client, headers, _events, _data_dir = app_client
    viewer, viewer_headers = role_client(client, headers, "viewer")
    assert viewer.get("/api/v1/services").status_code == 200
    assert viewer.get("/api/v1/domains").status_code == 200
    assert viewer.post("/api/v1/services/s3/actions", headers=viewer_headers,
                       json={"action": "start"}).status_code == 403
    assert add(viewer, viewer_headers, "panel", "v.example.com").status_code == 403
    operator, operator_headers = role_client(client, headers, "operator")
    assert operator.post("/api/v1/services/s3/actions", headers=operator_headers,
                         json={"action": "start"}).status_code != 403
    assert add(operator, operator_headers, "panel", "o.example.com").status_code == 403
    assert client.get("/api/v1/services").status_code == 200
    anonymous = TestClient(client.app)
    assert anonymous.get("/api/v1/services").status_code == 401
    catalog = client.get("/api/v1/permissions").json()
    ids = {perm["id"] for group in catalog["groups"] for perm in group["permissions"]}
    assert {"services:read", "services:operate", "domains:read", "domains:write"} <= ids


def test_pypi_outside_url_file_is_read_by_devpi_start_script() -> None:
    script = (Path(__file__).resolve().parents[3] / "deploy" / "images" / "pypi" /
              "devpi-start.sh").read_text(encoding="utf-8")
    assert 'outside_url="${MRK_PYPI_OUTSIDE_URL:-}"' in script
    assert '/pypi/outside-url"' in script and "--outside-url" in script
    assert "grep -Eq '^https?://[A-Za-z0-9.-]+(:[0-9]{1,5})?$'" in script


def test_detection_is_single_flight_and_never_blocks_long(monkeypatch) -> None:
    """Concurrent page loads share one detection (protects Dokploy from bursts)."""
    routing = domains_routing.Routing(ctx=None, settings=lambda: {})
    calls = 0

    async def slow_detect() -> dict[str, Any]:
        nonlocal calls
        calls += 1
        await asyncio.sleep(0.2)
        return {"inside_dokploy": False}

    monkeypatch.setattr(routing, "_detect", slow_detect)

    async def scenario() -> None:
        results = await asyncio.gather(*(routing.detect() for _ in range(5)))
        assert calls == 1
        assert all(item == {"inside_dokploy": False} for item in results)
        routing.invalidate()
        # A slow first detection does not hold the services page.
        assert await routing.detect_quick(timeout=0.01) is None
        await asyncio.sleep(0.3)
        assert await routing.detect_quick(timeout=0.01) == {"inside_dokploy": False}
        assert calls == 2

    asyncio.run(scenario())
