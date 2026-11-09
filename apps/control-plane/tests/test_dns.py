"""MRK DNS panel module (docs/37 §4): client, endpoints, RBAC, setup guide, services sync."""

from __future__ import annotations

import asyncio
import copy
import os
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, PlainTextResponse
from fastapi.testclient import TestClient
from mrk_control_plane import dns_client, process_control
from mrk_control_plane.agent import dns_facts
from mrk_control_plane.agent.app import AgentConfig, create_agent_app
from mrk_control_plane.agent.signing import sign_headers
from mrk_control_plane.auth import PERMISSION_REQUIRES, ROLE_PERMISSIONS
from mrk_control_plane.config import Settings
from mrk_control_plane.main import create_app
from mrk_control_plane.modules import dns, dns_setup, dns_validate, services
from mrk_control_plane.settings_registry import registry

from .helpers import login_owner

PASSWORD = "a-long-role-password-123"  # noqa: S105 - test-only fixture
TOKEN = "engine-token-0123456789abcdef"  # noqa: S105 - test-only fixture
KEY = b"\x09" * 32


# ----------------------------------------------------------------------------- fake engine


def _err(status: int, code: str, message: str = "", fields: list | None = None) -> JSONResponse:
    error: dict[str, Any] = {"code": code, "message": message or code}
    if fields:
        error["fields"] = fields
    return JSONResponse(status_code=status, content={"error": error})


class FakeEngine:
    """In-memory engine implementing the docs/37 §2 admin API."""

    def __init__(self) -> None:
        self.requests: list[tuple[str, str, Any]] = []
        self.down = False
        self.settings: dict[str, Any] = {
            "config_version": 1,
            "listen": [{"address": "127.0.0.1:53", "udp": True, "tcp": True},
                       {"address": "172.17.0.1:53", "udp": True, "tcp": True}],
            "recursion": {"enabled": True, "allow": ["127.0.0.0/8", "172.16.0.0/12"]},
            "query_allow": ["127.0.0.0/8", "172.16.0.0/12"],
            "upstreams": [{"id": "cf", "address": "1.1.1.1:53", "enabled": True}],
            "upstream_strategy": "fastest",
            "cache": {"max_bytes": 67108864, "min_ttl": 0, "max_ttl": 86400},
            "limits": {"client_qps": 200},
            "minimal_any": True, "refuse_any": False, "rebinding_protection": True,
            "overrides": {"enabled": True},
        }
        self.zones: dict[str, dict[str, Any]] = {}
        self.records: dict[str, list[dict[str, Any]]] = {}
        self.overrides: list[dict[str, Any]] = []
        self.counter = 0
        self.resolve_rcode = "NOERROR"
        self.listeners_ok = True
        self.app = self._build()

    def _id(self) -> str:
        self.counter += 1
        return f"id{self.counter}"

    def _build(self) -> FastAPI:
        app = FastAPI()
        engine = self

        @app.middleware("http")
        async def auth(request: Request, call_next):
            body = await request.body()
            engine.requests.append((request.method, request.url.path,
                                    body.decode(errors="replace") if body else None))
            if request.headers.get("authorization") != f"Bearer {TOKEN}":
                return _err(401, "unauthorized")
            return await call_next(request)

        @app.get("/v1/status")
        async def status():
            return {"version": "0.1.0", "started_at": 1, "uptime_s": 10,
                    "listeners": [{"address": "127.0.0.1:53", "proto": "udp",
                                   "ok": engine.listeners_ok},
                                  {"address": "172.17.0.1:53", "proto": "udp", "ok": True}],
                    "qps_1s": 1, "qps_1m": 1, "queries_total": 5,
                    "cache": {"entries": 1, "bytes": 1, "max_bytes": 2, "hit_ratio": 0.5},
                    "upstreams": [], "pressure": "normal", "memory_bytes": 1,
                    "goroutines": 3, "config_version": engine.settings["config_version"]}

        @app.get("/v1/settings")
        async def get_settings():
            return engine.settings

        @app.put("/v1/settings")
        async def put_settings(request: Request):
            body = await request.json()
            if body.get("config_version") != engine.settings["config_version"]:
                return _err(409, "config_conflict")
            engine.settings = {**body, "config_version": body["config_version"] + 1}
            return engine.settings

        @app.get("/v1/zones")
        async def zones():
            return {"items": list(engine.zones.values())}

        @app.post("/v1/zones")
        async def create_zone(request: Request):
            body = await request.json()
            if body["name"] in engine.zones:
                return _err(409, "zone_exists")
            engine.zones[body["name"]] = {"name": body["name"], "type": body["type"],
                                          "serial": 2026110801, "records": 0,
                                          "disabled": False, "updated_at": 1}
            engine.records[body["name"]] = []
            return JSONResponse(status_code=201, content=engine.zones[body["name"]])

        def zone_or_404(name: str):
            return engine.zones.get(name)

        @app.get("/v1/zones/{zone}")
        async def get_zone(zone: str):
            if zone_or_404(zone) is None:
                return _err(404, "zone_not_found")
            return engine.zones[zone]

        @app.patch("/v1/zones/{zone}")
        async def patch_zone(zone: str, request: Request):
            if zone_or_404(zone) is None:
                return _err(404, "zone_not_found")
            engine.zones[zone].update(await request.json())
            return engine.zones[zone]

        @app.delete("/v1/zones/{zone}")
        async def delete_zone(zone: str):
            if engine.zones.pop(zone, None) is None:
                return _err(404, "zone_not_found")
            engine.records.pop(zone, None)
            return JSONResponse(status_code=204, content=None)

        @app.get("/v1/zones/{zone}/export")
        async def export(zone: str):
            if zone_or_404(zone) is None:
                return _err(404, "zone_not_found")
            return PlainTextResponse(f"$ORIGIN {zone}.\n@ 3600 IN SOA ns. host. 1 2 3 4 5\n")

        @app.post("/v1/zones/{zone}/import")
        async def import_zone(zone: str, request: Request):
            body = await request.json()
            if "BROKEN" in body["text"]:
                return _err(422, "import_invalid", "line 1",
                            [{"field": "text", "reason_code": "parse_error"}])
            return {"imported": 1, "replace": body["replace"]}

        @app.get("/v1/zones/{zone}/history")
        async def history(zone: str):
            return {"items": [{"version": 1, "serial": 2026110801, "at": 1}]}

        @app.post("/v1/zones/{zone}/rollback")
        async def rollback(zone: str, request: Request):
            body = await request.json()
            if body["version"] == 99:
                return _err(404, "version_not_found")
            return {"ok": True, "version": body["version"]}

        @app.get("/v1/zones/{zone}/records")
        async def records(zone: str):
            if zone_or_404(zone) is None:
                return _err(404, "zone_not_found")
            return {"items": engine.records[zone]}

        def cname_conflict(zone: str, body: dict[str, Any], skip: str | None = None) -> bool:
            same = [item for item in engine.records[zone]
                    if item["name"] == body["name"] and item["id"] != skip]
            return bool(same) and (body["type"] == "CNAME"
                                   or any(item["type"] == "CNAME" for item in same))

        @app.post("/v1/zones/{zone}/records")
        async def create_record(zone: str, request: Request):
            if zone_or_404(zone) is None:
                return _err(404, "zone_not_found")
            body = await request.json()
            if cname_conflict(zone, body):
                return _err(409, "cname_conflict",
                            fields=[{"field": "name", "reason_code": "cname_conflict"}])
            item = {"id": engine._id(), **body}
            engine.records[zone].append(item)
            return JSONResponse(status_code=201, content=item)

        @app.put("/v1/zones/{zone}/records/{rid}")
        async def put_record(zone: str, rid: str, request: Request):
            for index, item in enumerate(engine.records.get(zone, [])):
                if item["id"] == rid:
                    engine.records[zone][index] = {"id": rid, **(await request.json())}
                    return engine.records[zone][index]
            return _err(404, "record_not_found")

        @app.delete("/v1/zones/{zone}/records/{rid}")
        async def delete_record(zone: str, rid: str):
            before = len(engine.records.get(zone, []))
            engine.records[zone] = [i for i in engine.records.get(zone, []) if i["id"] != rid]
            if len(engine.records[zone]) == before:
                return _err(404, "record_not_found")
            return {"ok": True}

        @app.get("/v1/overrides")
        async def overrides():
            return {"items": engine.overrides}

        @app.post("/v1/overrides")
        async def create_override(request: Request):
            item = {"id": engine._id(), **(await request.json())}
            engine.overrides.append(item)
            return JSONResponse(status_code=201, content=item)

        @app.put("/v1/overrides/{oid}")
        async def put_override(oid: str, request: Request):
            for index, item in enumerate(engine.overrides):
                if item["id"] == oid:
                    engine.overrides[index] = {"id": oid, **(await request.json())}
                    return engine.overrides[index]
            return _err(404, "override_not_found")

        @app.delete("/v1/overrides/{oid}")
        async def delete_override(oid: str):
            before = len(engine.overrides)
            engine.overrides = [item for item in engine.overrides if item["id"] != oid]
            if len(engine.overrides) == before:
                return _err(404, "override_not_found")
            return {"ok": True}

        @app.post("/v1/resolve")
        async def resolve(request: Request):
            body = await request.json()
            return {"rcode": engine.resolve_rcode,
                    "answers": [{"name": body["name"], "type": body["type"], "ttl": 60,
                                 "data": "93.184.215.14"}],
                    "source": "upstream", "upstream": "cf", "rtt_ms": 12}

        @app.post("/v1/cache/flush")
        async def flush(request: Request):
            return {"flushed": 3}

        return app

    def transport(self, _socket: str) -> httpx.AsyncBaseTransport:
        if self.down:
            class Down(httpx.AsyncBaseTransport):
                async def handle_async_request(self, request):
                    raise httpx.ConnectError("refused", request=request)

            return Down()
        return httpx.ASGITransport(app=self.app)


class FakeAgent:
    def __init__(self, facts: dict[str, Any] | None, error: str | None = None) -> None:
        self.facts = facts
        self.error = error
        self.paths: list[str] = []

    def resolve(self):
        return "panel", "http://mrk-agent:7070", KEY

    async def request(self, method: str, path: str, body: Any = None, **_kw: Any):
        self.paths.append(path)
        if self.error:
            from mrk_control_plane.modules.host_agent import AgentError

            raise AgentError(self.error, 502, self.error)
        return copy.deepcopy(self.facts)


def facts(**changes: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "host_proc": True,
        "host_root": True,
        "port_53": {"readable": True, "owners_complete": False, "items": [
            {"proto": "udp", "family": 4, "address": "127.0.0.53", "port": 53,
             "process": None, "process_hint": "systemd-resolved"},
        ]},
        "systemd_resolved_running": True,
        "resolv_conf": {"present": True, "symlink": "../run/systemd/resolve/stub-resolv.conf",
                        "managed_by": "systemd-resolved", "resolved_mode": "stub",
                        "truncated": False, "nameservers": ["127.0.0.53"], "search": [],
                        "options": ["edns0"]},
        "resolved": {"present": True, "dns": [], "fallback_dns": [], "dns_stub_listener": None,
                     "stub_disabled": False, "domains": [], "dropins": [], "mrk_dropin": False},
        "docker_daemon": {"present": True, "valid": True, "dns": None,
                          "keys": ["log-driver"]},
        "docker_bridge_gateway": "172.17.0.1",
    }
    for key, value in changes.items():
        base[key] = value
    return base


def configured_facts() -> dict[str, Any]:
    return facts(
        port_53={"readable": True, "owners_complete": True, "items": [
            {"proto": "udp", "family": 4, "address": "127.0.0.1", "port": 53,
             "process": {"pid": 77, "comm": "mrk-dns"}},
            {"proto": "udp", "family": 4, "address": "172.17.0.1", "port": 53,
             "process": None},
        ]},
        resolv_conf={"present": True, "symlink": "/run/systemd/resolve/resolv.conf",
                     "managed_by": "systemd-resolved", "resolved_mode": "uplink",
                     "truncated": False, "nameservers": ["127.0.0.1", "1.1.1.1"],
                     "search": [], "options": []},
        resolved={"present": True, "dns": ["127.0.0.1", "1.1.1.1"], "fallback_dns": ["1.1.1.1"],
                  "dns_stub_listener": "no", "stub_disabled": True, "domains": [],
                  "dropins": ["mrk.conf"], "mrk_dropin": True},
        docker_daemon={"present": True, "valid": True, "dns": ["172.17.0.1", "1.1.1.1"],
                       "keys": ["dns", "log-driver"]},
    )


# ----------------------------------------------------------------------------- fixtures


@pytest.fixture(autouse=True)
def isolated(monkeypatch, tmp_path: Path):
    for name in list(os.environ):
        if name.startswith(("MRK_DNS_", "MRK_DOMAINS_", "MRK_AGENT_", "MRK_DOKPLOY_")):
            monkeypatch.delenv(name, raising=False)
    socket = tmp_path / "run" / "admin.sock"
    token = tmp_path / "run" / "admin.token"
    monkeypatch.setenv("MRK_DNS_ADMIN_SOCKET", str(socket))
    monkeypatch.setenv("MRK_DNS_ADMIN_TOKEN_FILE", str(token))
    monkeypatch.setenv("MRK_DOKPLOY_POLL_SECONDS", "0")
    monkeypatch.setattr(process_control, "supervisor_available", lambda: False)
    monkeypatch.setattr(services, "PROBES", None)
    return socket, token


@pytest.fixture
def engine(monkeypatch, isolated) -> FakeEngine:
    socket, token = isolated
    socket.parent.mkdir(parents=True, exist_ok=True)
    socket.write_bytes(b"")  # stands in for the unix socket file
    token.write_text(TOKEN + "\n", encoding="utf-8")
    fake = FakeEngine()
    monkeypatch.setattr(dns_client, "TRANSPORT_FACTORY", fake.transport)
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
        yield client, headers, events


def role_client(owner: TestClient, headers: dict[str, str], role: str):
    created = owner.post("/api/v1/users", headers=headers,
                         json={"username": f"{role}1", "password": PASSWORD, "role": role})
    assert created.status_code == 201, created.text
    client = TestClient(owner.app)
    login = client.post("/api/v1/auth/login",
                        json={"username": f"{role}1", "password": PASSWORD})
    return client, {"X-CSRF-Token": str(login.json()["csrf_token"])}


def fresh_status() -> None:
    assert dns.ACTIVE_SERVICE is not None
    dns.ACTIVE_SERVICE._status_at = 0.0
    dns.ACTIVE_SERVICE._setup = None
    dns.ACTIVE_SERVICE._facts = None


# ----------------------------------------------------------------------------- status/errors


def test_status_not_installed_and_engine_routes_503(app_client) -> None:
    client, headers, _events = app_client
    body = client.get("/api/v1/dns/status").json()
    assert body["installed"] is False and body["reachable"] is False
    assert body["error_code"] == "dns_not_installed" and body["engine"] is None
    assert body["setup_complete"] is False
    response = client.get("/api/v1/dns/zones")
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "dns_not_installed"
    setup = client.get("/api/v1/dns/setup").json()
    assert [step["id"] for step in setup["steps"]] == list(dns_setup.STEP_IDS)
    first = setup["steps"][0]
    assert first["state"] == "todo" and first["detail_code"] == "not_installed"
    assert first["commands"][0]["code"] == "docker compose --profile dns up -d mrk-dns"
    # Without an agent every host step is unknown but still has full commands.
    by_id = {step["id"]: step for step in setup["steps"]}
    for sid in ("port_53_free", "host_resolver", "docker_daemon"):
        assert by_id[sid]["state"] == "unknown"
        assert by_id[sid]["detail_code"] == "agent_not_configured"
        assert by_id[sid]["commands"]


def test_status_reachable_unreachable_and_events(app_client, engine) -> None:
    client, _headers, events = app_client
    fresh_status()
    body = client.get("/api/v1/dns/status").json()
    assert body["installed"] and body["reachable"] and body["error_code"] is None
    assert body["engine"]["version"] == "0.1.0"
    engine.down = True
    fresh_status()
    body = client.get("/api/v1/dns/status").json()
    assert body["installed"] and not body["reachable"]
    assert body["error_code"] == "dns_unreachable" and body["reason"] == "connect_failed"
    response = client.get("/api/v1/dns/zones")
    assert response.status_code == 502 and response.json()["error"]["code"] == "dns_unreachable"
    engine.down = False
    fresh_status()
    client.get("/api/v1/dns/status")
    types = [event.type for event in events]
    assert "dns.unreachable" in types and "dns.recovered" in types


def test_wrong_token_and_missing_token(app_client, engine, isolated) -> None:
    client, _headers, _events = app_client
    _socket, token = isolated
    token.write_text("wrong-token", encoding="utf-8")
    response = client.get("/api/v1/dns/zones")
    assert response.status_code == 502
    assert response.json()["error"] == response.json()["error"] | {
        "code": "dns_unreachable", "reason": "auth_failed"}
    token.unlink()
    response = client.get("/api/v1/dns/zones")
    assert response.json()["error"]["reason"] == "token_unavailable"


def test_error_mapping_unit() -> None:
    cases = {
        (409, "config_conflict"): ("dns_config_conflict", 409),
        (409, "zone_exists"): ("dns_zone_exists", 409),
        (404, "zone_not_found"): ("dns_zone_not_found", 404),
        (404, "record_not_found"): ("dns_record_not_found", 404),
        (400, "record_invalid"): ("dns_record_invalid", 422),
        (409, "cname_conflict"): ("dns_cname_conflict", 409),
        (422, "invalid_zone_name"): ("invalid_zone_name", 422),
        (418, "something_new"): ("dns_something_new", 418),
    }
    for (status, code), expected in cases.items():
        body = (b'{"error":{"code":"%s","message":"m","fields":[{"field":"x",'
                b'"reason_code":"bad","junk":1}]}}' % code.encode())
        error = dns_client.map_engine_error(status, body)
        assert (error.code, error.status_code) == expected
        assert error.fields == [{"field": "x", "reason_code": "bad"}]
    assert dns_client.map_engine_error(500, b"oops").code == "dns_unreachable"
    assert dns_client.map_engine_error(401, b"").extra["reason"] == "auth_failed"


# ----------------------------------------------------------------------------- zones/records


def test_zone_record_lifecycle_and_audit(app_client, engine) -> None:
    client, headers, _events = app_client
    created = client.post("/api/v1/dns/zones", headers=headers,
                          json={"name": "Bücher.Example.", "type": "primary"})
    assert created.status_code == 201, created.text
    assert created.json()["name"] == "xn--bcher-kva.example"
    assert client.post("/api/v1/dns/zones", headers=headers,
                       json={"name": "xn--bcher-kva.example"}).json()["error"]["code"] == (
        "dns_zone_exists")
    bad = client.post("/api/v1/dns/zones", headers=headers, json={"name": "bad_zone!.com"})
    assert bad.status_code == 422 and bad.json()["error"]["code"] == "invalid_zone_name"
    assert bad.json()["error"]["fields"][0]["field"] == "name"
    zone = "xn--bcher-kva.example"
    assert client.get("/api/v1/dns/zones").json()["items"][0]["name"] == zone
    assert client.get(f"/api/v1/dns/zones/{zone}").json()["type"] == "primary"
    missing = client.get("/api/v1/dns/zones/nothing.example")
    assert missing.status_code == 404 and missing.json()["error"]["code"] == "dns_zone_not_found"
    patched = client.patch(f"/api/v1/dns/zones/{zone}", headers=headers, json={"disabled": True})
    assert patched.json()["disabled"] is True

    record = client.post(f"/api/v1/dns/zones/{zone}/records", headers=headers, json={
        "name": "www", "type": "a", "ttl": 300, "data": {"address": "192.0.2.10"}})
    assert record.status_code == 201, record.text
    assert record.json()["type"] == "A" and record.json()["comment"] == ""
    rid = record.json()["id"]
    conflict = client.post(f"/api/v1/dns/zones/{zone}/records", headers=headers, json={
        "name": "www", "type": "CNAME", "data": {"target": "other.example."}})
    assert conflict.status_code == 409 and conflict.json()["error"]["code"] == (
        "dns_cname_conflict")
    mx = client.post(f"/api/v1/dns/zones/{zone}/records", headers=headers, json={
        "name": "@", "type": "MX", "data": {"preference": 10, "exchange": "Mail.Example.com."}})
    assert mx.json()["data"] == {"preference": 10, "exchange": "mail.example.com"}
    srv = client.post(f"/api/v1/dns/zones/{zone}/records", headers=headers, json={
        "name": "_sip._tcp", "type": "SRV",
        "data": {"priority": 1, "weight": 5, "port": 5060, "target": "sip.example.com"}})
    assert srv.status_code == 201
    invalid = client.post(f"/api/v1/dns/zones/{zone}/records", headers=headers, json={
        "name": "x", "type": "A", "data": {"address": "::1"}})
    assert invalid.status_code == 422
    assert invalid.json()["error"]["code"] == "dns_record_invalid"
    assert invalid.json()["error"]["fields"] == [
        {"field": "data.address", "reason_code": "invalid_ipv4"}]
    put = client.put(f"/api/v1/dns/zones/{zone}/records/{rid}", headers=headers, json={
        "name": "www", "type": "A", "ttl": 60, "data": {"address": "192.0.2.11"}})
    assert put.json()["data"]["address"] == "192.0.2.11"
    gone = client.put(f"/api/v1/dns/zones/{zone}/records/nope", headers=headers, json={
        "name": "www", "type": "A", "data": {"address": "192.0.2.11"}})
    assert gone.status_code == 404 and gone.json()["error"]["code"] == "dns_record_not_found"
    assert client.delete(f"/api/v1/dns/zones/{zone}/records/{rid}",
                         headers=headers).json() == {"deleted": rid}
    assert len(client.get(f"/api/v1/dns/zones/{zone}/records").json()["items"]) == 2

    exported = client.get(f"/api/v1/dns/zones/{zone}/export").json()
    assert exported["zone"] == zone and exported["text"].startswith("$ORIGIN")
    imported = client.post(f"/api/v1/dns/zones/{zone}/import", headers=headers,
                           json={"text": "www 60 IN A 192.0.2.1\n", "replace": True})
    assert imported.json() == {"imported": 1, "replace": True}
    broken = client.post(f"/api/v1/dns/zones/{zone}/import", headers=headers,
                         json={"text": "BROKEN", "replace": False})
    assert broken.status_code == 422 and broken.json()["error"]["code"] == "dns_import_invalid"
    assert client.get(f"/api/v1/dns/zones/{zone}/history").json()["items"][0]["version"] == 1
    assert client.post(f"/api/v1/dns/zones/{zone}/rollback", headers=headers,
                       json={"version": 1}).json()["ok"] is True
    lost = client.post(f"/api/v1/dns/zones/{zone}/rollback", headers=headers,
                       json={"version": 99})
    assert lost.status_code == 404 and lost.json()["error"]["code"] == "dns_version_not_found"

    wrong = client.request("DELETE", f"/api/v1/dns/zones/{zone}", headers=headers,
                           json={"confirmation": "other"})
    assert wrong.status_code == 422 and wrong.json()["error"]["code"] == "confirmation_mismatch"
    assert wrong.json()["error"]["expected_confirmation"] == zone
    deleted = client.request("DELETE", f"/api/v1/dns/zones/{zone}", headers=headers,
                             json={"confirmation": zone})
    assert deleted.json() == {"deleted": zone}

    audit = client.get("/api/v1/audit-events?limit=100")
    if audit.status_code == 200:
        text = audit.text
        for action in ("dns.zone.create", "dns.zone.update", "dns.zone.delete",
                       "dns.zone.import", "dns.zone.rollback", "dns.record.create",
                       "dns.record.update", "dns.record.delete"):
            assert action in text, action


def test_csrf_required_for_changes(app_client, engine) -> None:
    client, _headers, _events = app_client
    response = client.post("/api/v1/dns/zones", json={"name": "example.com"})
    assert response.status_code == 403
    assert not [item for item in engine.requests if item[0] == "POST"]


# ----------------------------------------------------------------------------- settings/tools


def test_engine_settings_validation_and_conflict(app_client, engine) -> None:
    client, headers, _events = app_client
    current = client.get("/api/v1/dns/settings").json()
    assert current["config_version"] == 1
    opened = copy.deepcopy(current)
    opened["recursion"]["allow"] = ["0.0.0.0/0"]
    response = client.put("/api/v1/dns/settings", headers=headers, json=opened)
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "dns_settings_invalid"
    assert response.json()["error"]["fields"][0] == {"field": "recursion.allow.0",
                                                     "reason_code": "open_resolver"}
    bad = copy.deepcopy(current)
    bad["listen"] = [{"address": "nope"}]
    bad["upstreams"] = [{"id": "x", "address": "ftp://x"}]
    fields = {item["field"] for item in client.put("/api/v1/dns/settings", headers=headers,
                                                     json=bad).json()["error"]["fields"]}
    assert fields == {"listen.0.address", "upstreams.0.address"}
    current["upstreams"].append({"id": "dot", "address": "tls://9.9.9.9:853#dns.quad9.net",
                                 "enabled": True})
    saved = client.put("/api/v1/dns/settings", headers=headers, json=current)
    assert saved.status_code == 200 and saved.json()["config_version"] == 2
    stale = client.put("/api/v1/dns/settings", headers=headers, json=current)
    assert stale.status_code == 409 and stale.json()["error"]["code"] == "dns_config_conflict"


def test_resolve_and_flush(app_client, engine) -> None:
    client, headers, _events = app_client
    answer = client.post("/api/v1/dns/resolve", headers=headers,
                         json={"name": "Example.COM.", "type": "aaaa", "client_ip": "10.0.0.5"})
    assert answer.status_code == 200 and answer.json()["source"] == "upstream"
    sent = [item for item in engine.requests if item[1] == "/v1/resolve"][-1][2]
    assert '"name":"example.com"' in sent and '"type":"AAAA"' in sent
    assert client.post("/api/v1/dns/resolve", headers=headers,
                       json={"name": "a b"}).status_code == 422
    assert client.post("/api/v1/dns/cache/flush", headers=headers,
                       json={}).json() == {"flushed": 3}
    assert client.post("/api/v1/dns/cache/flush", headers=headers,
                       json={"name": "bad name"}).status_code == 422


# ----------------------------------------------------------------------------- overrides


def test_overrides_crud_and_managed_guard(app_client, engine) -> None:
    client, headers, _events = app_client
    created = client.post("/api/v1/dns/overrides", headers=headers, json={
        "name": "App.Example.com", "type": "A", "value": "10.0.0.7", "source": "services"})
    assert created.status_code == 201, created.text
    assert created.json()["source"] == "user" and created.json()["name"] == "app.example.com"
    assert created.json()["ttl"] == 300
    oid = created.json()["id"]
    updated = client.put(f"/api/v1/dns/overrides/{oid}", headers=headers, json={
        "name": "app.example.com", "type": "CNAME", "value": "target.example.com"})
    assert updated.json()["type"] == "CNAME"
    bad = client.post("/api/v1/dns/overrides", headers=headers,
                      json={"name": "x.example.com", "type": "MX", "value": "1"})
    assert bad.status_code == 422 and bad.json()["error"]["fields"][0]["field"] == "type"
    engine.overrides.append({"id": "svc1", "name": "npm.example.com", "type": "A",
                             "value": "172.17.0.1", "ttl": 60, "source": "services",
                             "disabled": False})
    blocked = client.request("DELETE", "/api/v1/dns/overrides/svc1", headers=headers)
    assert blocked.status_code == 409
    assert blocked.json()["error"]["code"] == "dns_override_managed"
    missing = client.request("DELETE", "/api/v1/dns/overrides/none", headers=headers)
    assert missing.status_code == 404
    assert client.request("DELETE", f"/api/v1/dns/overrides/{oid}",
                          headers=headers).json() == {"deleted": oid}
    assert [item["id"] for item in client.get("/api/v1/dns/overrides").json()["items"]] == [
        "svc1"]


# ----------------------------------------------------------------------------- permissions


def test_role_defaults_and_catalog() -> None:
    assert {"dns:read", "dns:write", "dns:logs", "dns:admin"} <= ROLE_PERMISSIONS["admin"]
    assert {"dns:read", "dns:write"} <= ROLE_PERMISSIONS["operator"]
    assert not {"dns:logs", "dns:admin"} & ROLE_PERMISSIONS["operator"]
    for role in ("developer", "viewer"):
        assert "dns:read" in ROLE_PERMISSIONS[role]
        assert not {"dns:write", "dns:logs", "dns:admin"} & ROLE_PERMISSIONS[role]
    assert PERMISSION_REQUIRES["dns:write"] == {"dns:read"}


def test_permissions_per_role(app_client, engine) -> None:
    owner, headers, _events = app_client
    viewer, viewer_headers = role_client(owner, headers, "viewer")
    operator, operator_headers = role_client(owner, headers, "operator")
    assert viewer.get("/api/v1/dns/status").status_code == 200
    assert viewer.get("/api/v1/dns/zones").status_code == 200
    assert viewer.get("/api/v1/dns/setup").status_code == 200
    assert viewer.post("/api/v1/dns/zones", headers=viewer_headers,
                       json={"name": "a.example"}).status_code == 403
    assert viewer.get("/api/v1/dns/settings").status_code == 403
    assert operator.post("/api/v1/dns/zones", headers=operator_headers,
                         json={"name": "a.example"}).status_code == 201
    assert operator.post("/api/v1/dns/cache/flush", headers=operator_headers,
                         json={}).status_code == 200
    assert operator.get("/api/v1/dns/settings").status_code == 403
    assert operator.put("/api/v1/dns/integration", headers=operator_headers,
                        json={"services_overrides": True}).status_code == 403
    assert owner.get("/api/v1/dns/settings").status_code == 200


# ----------------------------------------------------------------------------- setup guide


def setup_with(client, agent: FakeAgent | None, monkeypatch) -> dict[str, Any]:
    fresh_status()
    monkeypatch.setattr(dns.ACTIVE_SERVICE, "agent", lambda: agent)
    return {step["id"]: step for step in
            client.get("/api/v1/dns/setup?refresh=true").json()["steps"]}


def test_setup_detects_systemd_resolved_stub_and_missing_docker_dns(
    app_client, engine, monkeypatch
) -> None:
    client, _headers, _events = app_client
    agent = FakeAgent(facts())
    steps = setup_with(client, agent, monkeypatch)
    assert agent.paths == ["/v1/dns/facts"]
    assert steps["engine_running"]["state"] == "done"
    # resolved's stub on 127.0.0.53 does not collide with 127.0.0.1:53.
    assert steps["port_53_free"]["state"] == "done"
    host = steps["host_resolver"]
    assert (host["state"], host["detail_code"]) == ("todo", "systemd_resolved_stub")
    codes = "\n".join(item["code"] for item in host["commands"])
    assert "/etc/systemd/resolved.conf.d/mrk.conf" in codes
    assert "DNSStubListener=no" in codes and "DNS=127.0.0.1 1.1.1.1" in codes
    assert "sudo ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf" in codes
    assert "cp -P /etc/resolv.conf /etc/resolv.conf.mrk-backup" in codes
    assert any("stub-resolv.conf" in item["code"] for item in host["revert"])
    docker = steps["docker_daemon"]
    assert (docker["state"], docker["detail_code"]) == ("todo", "dns_not_set")
    docker_codes = {item["id"]: item for item in docker["commands"]}
    assert '.dns = ["172.17.0.1", "1.1.1.1"]' in docker_codes["daemon_json_merge"]["code"]
    assert "daemon.json.mrk-backup" in docker_codes["daemon_json_merge"]["code"]
    assert docker_codes["docker_restart"]["danger"] is True
    assert "Dokploy" in docker_codes["docker_restart"]["note_en"]
    assert docker["revert"]
    verify = steps["verify_from_host"]
    assert (verify["state"], verify["detail_code"]) == ("todo", "engine_ok_host_not_using")
    assert any("dig @127.0.0.1" in item["code"] for item in verify["commands"])
    container = steps["verify_from_container"]
    assert container["detail_code"] == "docker_dns_not_set"
    assert "docker run --rm busybox" in container["commands"][0]["code"]
    for step in steps.values():
        for command in (*step["commands"], *step["revert"]):
            assert command["title_fa"] and command["title_en"] and command["code"]


def test_setup_complete_and_status_flag(app_client, engine, monkeypatch) -> None:
    client, _headers, _events = app_client
    steps = setup_with(client, FakeAgent(configured_facts()), monkeypatch)
    states = {sid: (step["state"], step["detail_code"]) for sid, step in steps.items()}
    assert states == {
        "engine_running": ("done", "running"),
        "port_53_free": ("done", "held_by_mrk"),
        "host_resolver": ("done", "uses_mrk"),
        "docker_daemon": ("done", "uses_mrk"),
        "verify_from_host": ("done", "ok"),
        "verify_from_container": ("unknown", "manual_check"),
    }
    dns.ACTIVE_SERVICE._status_at = 0.0
    assert client.get("/api/v1/dns/status").json()["setup_complete"] is True


def test_setup_conflicts_and_partial_configs(app_client, engine, monkeypatch) -> None:
    client, _headers, _events = app_client
    held = configured_facts()
    held["port_53"] = {"readable": True, "owners_complete": True, "items": [
        {"proto": "udp", "family": 4, "address": "0.0.0.0", "port": 53,  # noqa: S104
         "process": {"pid": 9, "comm": "dnsmasq"}}]}
    held["docker_daemon"] = {"present": True, "valid": True, "dns": ["172.17.0.1"], "keys": []}
    held["resolv_conf"]["nameservers"] = ["127.0.0.1"]
    steps = setup_with(client, FakeAgent(held), monkeypatch)
    port = steps["port_53_free"]
    assert (port["state"], port["detail_code"]) == ("warning", "port_in_use")
    assert port["params"]["process"] == "dnsmasq" and port["params"]["unit"] == "dnsmasq"
    assert any("systemctl disable --now dnsmasq" in c["code"] for c in port["commands"])
    assert any("systemctl enable --now dnsmasq" in c["code"] for c in port["revert"])
    assert steps["docker_daemon"]["detail_code"] == "no_fallback"
    assert steps["host_resolver"]["detail_code"] == "no_fallback"

    invalid = configured_facts()
    invalid["docker_daemon"] = {"present": True, "valid": False, "dns": None, "keys": []}
    invalid["resolv_conf"] = {"present": True, "symlink": None, "managed_by": "static",
                              "resolved_mode": None, "truncated": False,
                              "nameservers": ["8.8.8.8"], "search": [], "options": []}
    invalid["systemd_resolved_running"] = False
    steps = setup_with(client, FakeAgent(invalid), monkeypatch)
    assert steps["docker_daemon"]["detail_code"] == "daemon_json_invalid"
    assert steps["host_resolver"]["detail_code"] == "static_resolv_conf"
    assert any(c["id"] == "resolv_conf_static" for c in steps["host_resolver"]["commands"])

    missing = configured_facts()
    missing["docker_daemon"] = {"present": False, "valid": None, "dns": None, "keys": []}
    steps = setup_with(client, FakeAgent(missing), monkeypatch)
    assert steps["docker_daemon"]["detail_code"] == "daemon_json_missing"

    steps = setup_with(client, FakeAgent(None, error="agent_not_found"), monkeypatch)
    assert steps["port_53_free"]["detail_code"] == "agent_unsupported"
    steps = setup_with(client, FakeAgent(None, error="agent_unreachable"), monkeypatch)
    assert steps["docker_daemon"]["detail_code"] == "agent_unreachable"


def test_setup_engine_problems(app_client, engine, monkeypatch) -> None:
    client, _headers, _events = app_client
    engine.listeners_ok = False
    steps = setup_with(client, FakeAgent(configured_facts()), monkeypatch)
    assert steps["engine_running"]["detail_code"] == "listener_failed"
    engine.listeners_ok = True
    engine.resolve_rcode = "SERVFAIL"
    steps = setup_with(client, FakeAgent(configured_facts()), monkeypatch)
    assert steps["verify_from_host"]["detail_code"] == "resolve_failed"
    engine.down = True
    steps = setup_with(client, FakeAgent(configured_facts()), monkeypatch)
    assert steps["engine_running"]["detail_code"] == "engine_unreachable"
    assert steps["verify_from_host"]["detail_code"] == "engine_not_running"


def test_setup_complete_requires_checkable_steps() -> None:
    steps = [{"id": sid, "state": "done"} for sid in dns_setup.STEP_IDS]
    assert dns_setup.setup_complete(steps)
    steps[-1]["state"] = "todo"
    assert not dns_setup.setup_complete(steps)
    steps[-1]["state"] = "unknown"
    steps[2]["state"] = "warning"
    assert not dns_setup.setup_complete(steps)


# ----------------------------------------------------------------------------- services sync


def test_services_overrides_follow_domains(app_client, engine) -> None:
    client, headers, _events = app_client
    created = client.post("/api/v1/domains", headers=headers,
                          json={"service_id": "npm", "host": "npm.example.com",
                                "mode": "manual"})
    assert created.status_code == 201, created.text
    assert created.json()["sync"]["dns"]["status"] == "disabled"
    assert engine.overrides == []
    engine.overrides.append({"id": "u1", "name": "pypi.example.com", "type": "A",
                             "value": "10.9.9.9", "ttl": 60, "source": "user",
                             "disabled": False})
    view = client.put("/api/v1/dns/integration", headers=headers,
                      json={"services_overrides": True, "internal_zone_enabled": True})
    assert view.status_code == 200, view.text
    body = view.json()
    assert body["settings"]["services_overrides"] is True
    assert body["effective_target"] == "172.17.0.1"
    assert body["last_sync"]["status"] == "applied"
    managed = [item for item in engine.overrides if item["source"] == "services"]
    assert [(item["name"], item["type"], item["value"]) for item in managed] == [
        ("npm.example.com", "A", "172.17.0.1")]
    assert "mrk.internal" in engine.zones
    names = sorted(item["name"] for item in engine.records["mrk.internal"])
    assert names == ["npm", "panel", "pypi", "s3"]

    # A user override of the same name wins; the panel does not add a second one.
    second = client.post("/api/v1/domains", headers=headers,
                         json={"service_id": "pypi", "host": "pypi.example.com",
                               "mode": "manual"})
    assert second.json()["sync"]["dns"]["skipped"] == ["pypi.example.com"]
    domain_id = created.json()["domain"]["id"]
    client.request("DELETE", f"/api/v1/domains/{domain_id}", headers=headers,
                   json={"confirmation": "npm.example.com"})
    assert [item for item in engine.overrides if item["source"] == "services"] == []

    third = client.post("/api/v1/domains", headers=headers,
                        json={"service_id": "s3", "host": "s3.example.com", "mode": "manual"})
    assert third.json()["sync"]["dns"]["created"] == 1
    view = client.put("/api/v1/dns/integration", headers=headers,
                      json={"services_override_target": "10.0.0.2"})
    assert view.json()["last_sync"]["updated"] >= 1
    assert [item["value"] for item in engine.overrides if item["source"] == "services"] == [
        "10.0.0.2"]
    view = client.put("/api/v1/dns/integration", headers=headers,
                      json={"services_overrides": False, "internal_zone_enabled": False})
    assert view.json()["last_sync"]["status"] == "disabled"
    assert [item for item in engine.overrides if item["source"] == "services"] == []
    assert "mrk.internal" not in engine.zones
    assert client.put("/api/v1/dns/integration", headers=headers,
                      json={"services_override_target": "nope"}).status_code == 422


def test_dns_service_card(app_client, engine) -> None:
    client, _headers, _events = app_client
    fresh_status()
    card = next(item for item in client.get("/api/v1/services").json()["items"]
                if item["id"] == "dns")
    assert card["state"] == "running" and card["controllable"] is False
    assert card["internal_port"] == 53 and card["actions"] == []
    assert card["manage_route"] == "#/dns/status" and card["domains_supported"] is False
    engine.down = True
    fresh_status()
    card = next(item for item in client.get("/api/v1/services").json()["items"]
                if item["id"] == "dns")
    assert (card["state"], card["reason_code"]) == ("degraded", "dns_unreachable")


def test_dns_card_not_installed(app_client) -> None:
    client, _headers, _events = app_client
    card = next(item for item in client.get("/api/v1/services").json()["items"]
                if item["id"] == "dns")
    assert (card["state"], card["reason_code"]) == ("not_installed", "dns_not_installed")


def test_home_rule_only_when_installed(app_client, engine) -> None:
    client, _headers, _events = app_client
    from mrk_control_plane.modules import home

    engine.down = True
    fresh_status()
    home.LAST_SERVICE.invalidate()
    rules = {item["rule"] for item in client.get("/api/v1/home").json()["attention"]}
    assert "dns_unreachable" in rules
    assert "setup_dns" in {step["id"] for step in client.get("/api/v1/home").json()["checklist"]}


# ----------------------------------------------------------------------------- settings registry


def test_registry_entries() -> None:
    specs = registry().specs
    for key in ("dns.services_overrides", "dns.services_override_target",
                "dns.internal_zone_enabled", "dns.fallback_servers"):
        assert specs[key].source == "runtime" and specs[key].module == "dns"
        assert specs[key].write_permission == "dns:admin"
        assert specs[key].default == dns.DEFAULT_SETTINGS[key.split(".", 1)[1]]
    envs = {spec.env for spec in specs.values() if spec.env}
    assert {"MRK_DNS_ADMIN_SOCKET", "MRK_DNS_ADMIN_TOKEN_FILE", "MRK_DNS_DATA_DIR",
            "MRK_DNS_LISTEN", "MRK_DNS_GOMEMLIMIT", "MRK_DNS_LOG_LEVEL", "MRK_DNS_CPUS",
            "MRK_DNS_MEMORY", "MRK_DNS_PIDS"} <= envs


def test_registry_writes_through_module(app_client) -> None:
    client, headers, _events = app_client
    response = client.put("/api/v1/settings/registry/dns.internal_zone_enabled",
                          headers=headers, json={"value": True})
    assert response.status_code == 200, response.text
    assert dns.ACTIVE_SERVICE.get_settings()["internal_zone_enabled"] is True


# ----------------------------------------------------------------------------- validation units


def test_validation_units() -> None:
    assert dns_validate.canonical_zone("10.IN-ADDR.arpa.") == "10.in-addr.arpa"
    assert dns_validate.canonical_zone("internal") == "internal"
    for bad, reason in (("*.example.com", "wildcard_not_allowed"), ("1.2.3.4", "ip_not_allowed"),
                        ("a..b", "invalid_format"), ("", "required"), (5, "invalid_type")):
        with pytest.raises(dns_validate.DnsInputError) as info:
            dns_validate.canonical_zone(bad)
        assert info.value.fields[0]["reason_code"] == reason
    assert dns_validate.relative_name("WWW.Example.com.", "example.com") == "www"
    assert dns_validate.relative_name("example.com.", "example.com") == "@"
    assert dns_validate.relative_name("*", "example.com") == "*"
    with pytest.raises(dns_validate.DnsInputError):
        dns_validate.relative_name("www.other.org.", "example.com")
    with pytest.raises(dns_validate.DnsInputError) as info:
        dns_validate.record_body({"type": "SOA", "data": {}}, "example.com", creating=True)
    assert info.value.fields[0]["reason_code"] == "soa_managed"
    with pytest.raises(dns_validate.DnsInputError) as info:
        dns_validate.record_body({"name": "@", "type": "CNAME", "data": {"target": "x.org"}},
                                 "example.com", creating=True)
    assert info.value.fields[0]["reason_code"] == "cname_at_apex"
    caa = dns_validate.record_body({"name": "@", "type": "CAA", "ttl": 0, "data": {
        "flags": 0, "tag": "Issue", "value": "letsencrypt.org"}}, "example.com", creating=True)
    assert caa["data"]["tag"] == "issue" and caa["ttl"] == 0
    with pytest.raises(dns_validate.DnsInputError):
        dns_validate.record_body({"name": "a", "type": "TXT", "ttl": 604801,
                                  "data": {"text": "x"}}, "example.com", creating=True)
    assert dns_validate.upstream_address("https://dns.google/dns-query")
    with pytest.raises(ValueError):
        dns_validate.upstream_address("https://user:pw@dns.google/dns-query")


# ----------------------------------------------------------------------------- agent facts


def _proc(tmp_path: Path) -> Path:
    proc = tmp_path / "proc"
    (proc / "1" / "net").mkdir(parents=True)
    header = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt" \
             "   uid  timeout inode\n"
    (proc / "1" / "net" / "udp").write_text(
        header
        + "  1: 3500007F:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000"
          "   991        0 4444 2 0000000000000000 0\n"
        + "  2: 0100007F:1F90 00000000:0000 07 00000000:00000000 00:00000000 00000000"
          "     0        0 5555 2 0000000000000000 0\n"
        + "  3: 00000000:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000"
          "     0        0 6666 2 0000000000000000 0\n",
        encoding="utf-8")
    (proc / "1" / "net" / "tcp").write_text(
        header
        + "  0: 3500007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000"
          "   991        0 4445 1 0000000000000000 100 0 0 10 0\n"
        + "  1: 3500007F:0035 0100007F:9C40 01 00000000:00000000 00:00000000 00000000"
          "   991        0 4446 1 0000000000000000 100 0 0 10 0\n",
        encoding="utf-8")
    (proc / "1" / "net" / "udp6").write_text(
        header
        + "  0: 00000000000000000000000001000000:0035 00000000000000000000000000000000:0000"
          " 07 00000000:00000000 00:00000000 00000000     0        0 7777 2 0 0\n",
        encoding="utf-8")
    (proc / "1" / "comm").write_text("systemd\n", encoding="utf-8")
    (proc / "300" / "fd").mkdir(parents=True)
    (proc / "300" / "comm").write_text("dnsmasq\n", encoding="utf-8")
    (proc / "300" / "fd" / "5").write_text("", encoding="utf-8")
    (proc / "400").mkdir()
    (proc / "400" / "comm").write_text("systemd-resolve\n", encoding="utf-8")
    return proc


def _root(tmp_path: Path) -> Path:
    root = tmp_path / "root"
    (root / "etc" / "systemd" / "resolved.conf.d").mkdir(parents=True)
    (root / "etc" / "docker").mkdir(parents=True)
    (root / "etc" / "resolv.conf").write_text(
        "# generated\nnameserver 127.0.0.53\nnameserver not-an-ip\noptions edns0 trust-ad\n"
        "search lan\n", encoding="utf-8")
    (root / "etc" / "systemd" / "resolved.conf").write_text(
        "[Resolve]\n#DNS=\nFallbackDNS=1.1.1.1#cloudflare-dns.com 9.9.9.9\n", encoding="utf-8")
    (root / "etc" / "systemd" / "resolved.conf.d" / "mrk.conf").write_text(
        "[Resolve]\nDNS=127.0.0.1 [2606:4700::1111]:53\nDNSStubListener=no\n", encoding="utf-8")
    (root / "etc" / "systemd" / "resolved.conf.d" / "../evil").write_text("x", encoding="utf-8")
    (root / "etc" / "docker" / "daemon.json").write_text(
        '{"dns": ["172.17.0.1", "bogus"], "log-driver": "json-file", "registry-mirrors": []}',
        encoding="utf-8")
    return root


def test_parse_proc_net_and_files(tmp_path: Path, monkeypatch) -> None:
    proc = _proc(tmp_path)
    real_readlink = os.readlink

    def fake_readlink(path, *args, **kwargs):
        if str(path).replace("\\", "/").endswith("300/fd/5"):
            return "socket:[6666]"
        return real_readlink(path, *args, **kwargs)

    monkeypatch.setattr(dns_facts.os, "readlink", fake_readlink)
    result = dns_facts.collect(proc, _root(tmp_path))
    items = result["port_53"]["items"]
    assert {(item["proto"], item["address"]) for item in items} == {
        ("udp", "127.0.0.53"), ("udp", "0.0.0.0"), ("tcp", "127.0.0.53"), ("udp", "::1")}  # noqa: S104
    wildcard = next(item for item in items if item["address"] == "0.0.0.0")  # noqa: S104
    assert wildcard["process"] == {"pid": 300, "comm": "dnsmasq"}
    stub = next(item for item in items if item["address"] == "127.0.0.53")
    assert stub["process_hint"] == "systemd-resolved"
    assert all("inode" not in item for item in items)
    assert result["systemd_resolved_running"] is True
    resolv = result["resolv_conf"]
    assert resolv["nameservers"] == ["127.0.0.53"] and resolv["managed_by"] == "static"
    assert resolv["search"] == ["lan"] and "edns0" in resolv["options"]
    resolved = result["resolved"]
    assert resolved["dns"] == ["127.0.0.1", "2606:4700::1111"]
    assert resolved["fallback_dns"] == ["1.1.1.1", "9.9.9.9"]
    assert resolved["stub_disabled"] is True and resolved["dropins"] == ["mrk.conf"]
    daemon = result["docker_daemon"]
    assert daemon == {"present": True, "valid": True, "dns": ["172.17.0.1"],
                      "keys": ["dns", "log-driver", "registry-mirrors"]}


def test_facts_degrade_without_mounts(tmp_path: Path) -> None:
    result = dns_facts.collect(Path("/proc"), tmp_path / "missing")
    assert result["host_proc"] is False and result["port_53"]["readable"] is False
    assert result["resolv_conf"] is None and result["docker_daemon"] is None


def test_daemon_json_is_capped(tmp_path: Path) -> None:
    root = _root(tmp_path)
    (root / "etc" / "docker" / "daemon.json").write_text(
        '{"x": "' + "a" * (dns_facts.MAX_FILE_BYTES + 10) + '"}', encoding="utf-8")
    assert dns_facts.docker_daemon_facts(root) == {"present": True, "valid": False,
                                                   "dns": None, "keys": []}


def test_symlinks_are_clamped_inside_root(tmp_path: Path, monkeypatch) -> None:
    root = tmp_path / "root"
    (root / "etc").mkdir(parents=True)
    (root / "run" / "systemd" / "resolve").mkdir(parents=True)
    (root / "run" / "systemd" / "resolve" / "stub-resolv.conf").write_text(
        "nameserver 127.0.0.53\n", encoding="utf-8")
    (tmp_path / "secret.conf").write_text("nameserver 6.6.6.6\n", encoding="utf-8")
    links = {
        root / "etc" / "resolv.conf": "../run/systemd/resolve/stub-resolv.conf",
        root / "etc" / "escape": "../../../../secret.conf",
        root / "etc" / "abs": "/run/systemd/resolve/stub-resolv.conf",
        root / "etc" / "loop": "/etc/loop",
    }
    real_is_symlink = Path.is_symlink
    real_readlink = os.readlink
    monkeypatch.setattr(Path, "is_symlink",
                        lambda self: self in links or real_is_symlink(self))
    monkeypatch.setattr(dns_facts.os, "readlink",
                        lambda path, *a, **k: links.get(Path(path)) or real_readlink(path))
    stub = root / "run" / "systemd" / "resolve" / "stub-resolv.conf"
    assert dns_facts.resolve_in_root(root, "etc/resolv.conf") == stub
    assert dns_facts.resolve_in_root(root, "etc/abs") == stub
    escaped = dns_facts.resolve_in_root(root, "etc/escape")
    assert escaped == root / "secret.conf"  # clamped at the root, never tmp_path/secret.conf
    assert dns_facts.resolve_in_root(root, "etc/loop") is None
    facts_value = dns_facts.resolv_conf_facts(root)
    assert facts_value["nameservers"] == ["127.0.0.53"]
    assert facts_value["managed_by"] == "systemd-resolved"
    assert facts_value["resolved_mode"] == "stub"


def test_agent_endpoint_signed_read_only(tmp_path: Path, monkeypatch) -> None:
    proc = _proc(tmp_path)
    (proc / "meminfo").write_text("MemTotal: 1 kB\n", encoding="utf-8")
    root = _root(tmp_path)
    config = AgentConfig(key=KEY, proc_dir=proc, root_paths=[root], host_root=root,
                         docker_socket=str(tmp_path / "no-docker.sock"))
    app = create_agent_app(config)
    with TestClient(app) as client:
        path = "/v1/dns/facts"
        assert client.get(path).status_code == 401
        signed = client.get(path, headers=sign_headers(KEY, "GET", path, b""))
        assert signed.status_code == 200
        body = signed.json()
        assert body["resolv_conf"]["nameservers"] == ["127.0.0.53"]
        assert body["docker_bridge_gateway"] is None
        assert "secret" not in signed.text
        query = "/v1/dns/facts?path=/etc/shadow"
        again = client.get(query, headers=sign_headers(KEY, "GET", query, b""))
        assert again.json() == body  # parameters are ignored: the paths are fixed
        post = client.post(path, headers=sign_headers(KEY, "POST", path, b""))
        assert post.status_code == 405
        info = client.get("/v1/info", headers=sign_headers(KEY, "GET", "/v1/info", b""))
        assert info.json()["capabilities"]["dns_facts"] is True


def test_client_timeout_maps_to_unreachable(engine, monkeypatch) -> None:
    class Slow(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request):
            raise httpx.ReadTimeout("slow", request=request)

    monkeypatch.setattr(dns_client, "TRANSPORT_FACTORY", lambda _path: Slow())
    with pytest.raises(dns_client.DnsError) as info:
        asyncio.run(dns_client.DnsClient().status())
    assert info.value.code == "dns_unreachable" and info.value.extra["reason"] == "timeout"


def test_integration_works_without_engine(app_client) -> None:
    client, headers, _events = app_client
    view = client.put("/api/v1/dns/integration", headers=headers,
                      json={"services_overrides": True, "fallback_servers": ["9.9.9.9"]})
    assert view.status_code == 200, view.text
    body = view.json()
    assert body["settings"]["services_overrides"] is True
    assert body["settings"]["fallback_servers"] == ["9.9.9.9"]
    assert body["last_sync"]["status"] == "not_installed"
    assert body["internal_names"] == ["panel.mrk.internal", "npm.mrk.internal",
                                      "pypi.mrk.internal", "s3.mrk.internal"]
    assert client.get("/api/v1/dns/integration").json()["effective_target"] == "172.17.0.1"
    bad = client.put("/api/v1/dns/integration", headers=headers, json={"nope": 1})
    assert bad.status_code == 422 and bad.json()["error"]["code"] == "invalid_settings"


def test_upstream_ids_accept_client_generated() -> None:
    payload = {"config_version": 3, "upstreams": [
        {"id": "quad9-3", "address": "9.9.9.9:53", "enabled": True},
        {"id": "cf_1.v2", "address": "https://cloudflare-dns.com/dns-query", "enabled": True}]}
    assert dns_validate.engine_settings(payload) is payload
    with pytest.raises(dns_validate.DnsInputError):
        dns_validate.engine_settings({"config_version": 3, "upstreams": [
            {"id": "bad id!", "address": "9.9.9.9"}]})
