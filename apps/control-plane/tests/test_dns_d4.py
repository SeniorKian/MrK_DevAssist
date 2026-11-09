"""MRK DNS D4 panel side (docs/40 §5): resolution/DNSSEC/encrypted settings and warnings,
resolve switches, DNSSEC, certificates, DoH tokens, device guides, the Apple profile,
notifications, home rules and the ``dns-doh`` service."""

from __future__ import annotations

import copy
import json
import plistlib
import time
from pathlib import Path
from typing import Any

import pytest
from fastapi import Request
from fastapi.responses import JSONResponse, Response
from fastapi.testclient import TestClient
from mrk_control_plane import dns_client
from mrk_control_plane.agent import traefik
from mrk_control_plane.config import Settings
from mrk_control_plane.main import create_app
from mrk_control_plane.modules import (
    dns,
    dns_encrypted,
    dns_monitor,
    dns_validate,
    dns_validate_d4,
    domains_verify,
    home,
    services,
)

from .helpers import login_owner
from .test_dns import TOKEN, FakeEngine, role_client
from .test_dns import isolated as isolated  # noqa: F401 - fixture re-export

CERT = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
KEY = "-----BEGIN PRIVATE KEY-----\nSECRETKEYMATERIAL\n-----END PRIVATE KEY-----\n"
DOH_TOKEN = "tok_" + "A" * 39  # noqa: S105 - test-only fixture


def _err(status: int, code: str, **extra: Any) -> JSONResponse:
    return JSONResponse(status_code=status, content={"error": {"code": code, "message": code,
                                                               **extra}})


class D4Engine(FakeEngine):
    def __init__(self) -> None:
        super().__init__()
        self.settings.update({
            "resolution": {"mode": "forward", "qname_minimization": "relaxed",
                           "ip_versions": "ipv4", "case_randomization": True,
                           "root_hints": [], "allow_private_ns": False, "max_referrals": 30,
                           "max_queries_per_resolution": 100, "max_ns_per_zone": 13,
                           "query_timeout_ms": 1500, "resolve_timeout_ms": 4000,
                           "infra_cache_entries": 10000},
            "dnssec": {"mode": "validate", "trust_anchor_auto_update": True,
                       "negative_trust_anchors": [], "auto_insecure_local": True,
                       "aggressive_nsec": True, "nsec3_max_iterations": 150, "bogus_ttl": 60,
                       "sig_skew_seconds": 3600},
            "encrypted": {
                "dot": {"enabled": False, "listen": ["0.0.0.0:853"]},
                "doq": {"enabled": False, "listen": ["0.0.0.0:853"]},
                "doh": {"enabled": False, "listen": ["0.0.0.0:443"], "tls": True,
                        "path": "/dns-query", "allow_get": True,
                        "trusted_proxies": ["127.0.0.0/8", "172.16.0.0/12"]},
                "allow": None, "max_connections": 2000, "max_connections_per_client": 50,
                "idle_timeout_ms": 30000, "max_streams_per_connection": 100,
                "handshake_timeout_ms": 5000},
        })
        self.tls: dict[str, Any] = {"present": False, "source": None, "names": [],
                                    "self_signed": False}
        self.tokens: list[dict[str, Any]] = []
        self.events: list[dict[str, Any]] = []
        self.status_extra: dict[str, Any] = {}
        self.listener_in_use = False
        self._d4_routes()

    def add_event(self, kind: str, data: dict[str, Any], severity: str = "error") -> None:
        seq = (self.events[-1]["seq"] if self.events else 0) + 1
        self.events.append({"seq": seq, "ts": 1, "type": kind, "severity": severity,
                            "data": data})

    def _d4_routes(self) -> None:
        app = self.app
        engine = self
        # Replace the D1 status/resolve routes with D4-aware ones.
        app.router.routes = [route for route in app.router.routes
                             if getattr(route, "path", "") not in {"/v1/status",
                                                                   "/v1/resolve"}]

        @app.get("/v1/status")
        async def status():
            return {"version": "0.4.0", "uptime_s": 10, "listeners": [
                {"address": "127.0.0.1:53", "proto": "udp", "ok": True}],
                "config_version": engine.settings["config_version"], **engine.status_extra}

        @app.post("/v1/resolve")
        async def resolve(request: Request):
            body = await request.json()
            result = {"rcode": "NOERROR", "answers": [], "source": "recursive",
                      "dnssec": {"status": "secure"}, "ede": [], "echo": body}
            if body.get("trace"):
                result["trace"] = [{"step": 1, "zone": ".", "server": "198.41.0.4",
                                    "qname": body["name"], "qtype": "NS", "rcode": "NOERROR",
                                    "rtt_ms": 10}]
            return result

        @app.get("/v1/dnssec")
        async def get_dnssec():
            return {"mode": "validate", "trust_anchors": [
                {"key_tag": 20326, "algorithm": 8, "state": "valid", "since": "2017-02-02"}],
                "updated_at": None, "negative_trust_anchors": [],
                "counters": {"secure": 1, "insecure": 2, "bogus": 0, "indeterminate": 0}}

        @app.post("/v1/dnssec/refresh")
        async def refresh_dnssec():
            return {"mode": "validate", "trust_anchors": [], "updated_at": "now",
                    "error": "timeout"}

        @app.get("/v1/tls")
        async def get_tls():
            # A buggy engine leaking a key must still never reach the browser.
            return {**engine.tls, "key_pem": KEY}

        @app.put("/v1/tls")
        async def put_tls(request: Request):
            body = await request.json()
            if "BAD" in body["cert_pem"]:
                return _err(422, "tls_invalid", reason_code="key_mismatch")
            engine.tls = {"present": True, "source": "uploaded", "subject": "CN=dns.example.com",
                          "names": ["dns.example.com", "*.example.com"], "issuer": "CA",
                          "not_after": "2099-01-01T00:00:00Z", "fingerprint_sha256": "ab12cd",
                          "self_signed": False, "key_type": "ecdsa-p256"}
            return engine.tls

        @app.post("/v1/tls/self-signed")
        async def self_signed(request: Request):
            body = await request.json()
            engine.tls = {"present": True, "source": "self_signed", "names": body["names"],
                          "not_after": "2099-01-01T00:00:00Z", "fingerprint_sha256": "ff00",
                          "self_signed": True}
            return engine.tls

        @app.delete("/v1/tls")
        async def delete_tls():
            if engine.listener_in_use:
                return _err(409, "certificate_in_use")
            engine.tls = {"present": False, "source": None, "names": [], "self_signed": False}
            return Response(status_code=204)

        @app.get("/v1/doh/tokens")
        async def list_tokens():
            return {"items": [{k: v for k, v in item.items() if k != "token"}
                              for item in engine.tokens]}

        @app.post("/v1/doh/tokens")
        async def create_token(request: Request):
            body = await request.json()
            item = {"id": f"t{len(engine.tokens) + 1}", "name": body["name"],
                    "qps": body.get("qps", 50), "created_at": "2026-11-09T00:00:00Z",
                    "queries": 0}
            engine.tokens.append(item)
            return JSONResponse(status_code=201, content={**item, "token": DOH_TOKEN})

        @app.patch("/v1/doh/tokens/{tid}")
        async def patch_token(tid: str, request: Request):
            for item in engine.tokens:
                if item["id"] == tid:
                    item.update(await request.json())
                    return item
            return _err(404, "token_not_found")

        @app.delete("/v1/doh/tokens/{tid}")
        async def delete_token(tid: str):
            before = len(engine.tokens)
            engine.tokens = [item for item in engine.tokens if item["id"] != tid]
            if len(engine.tokens) == before:
                return _err(404, "token_not_found")
            return Response(status_code=204)

        @app.get("/v1/events")
        async def events(request: Request):
            after = int(request.query_params.get("after", "0"))
            return {"items": [item for item in engine.events if item["seq"] > after],
                    "next": engine.events[-1]["seq"] if engine.events else 0}


@pytest.fixture
def engine(monkeypatch, isolated) -> D4Engine:  # noqa: F811
    socket, token = isolated
    socket.parent.mkdir(parents=True, exist_ok=True)
    socket.write_bytes(b"")
    token.write_text(TOKEN + "\n", encoding="utf-8")
    fake = D4Engine()
    monkeypatch.setattr(dns_client, "TRANSPORT_FACTORY", fake.transport)
    monkeypatch.setattr(dns_monitor, "MONITOR_ENABLED", False)
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


def audit_text(client: TestClient) -> str:
    response = client.get("/api/v1/audit-events?limit=200")
    assert response.status_code == 200, response.text
    return response.text


def fields_of(response) -> dict[str, str]:
    return {item["field"]: item["reason_code"] for item in response.json()["error"]["fields"]}


def put(client, headers, change) -> Any:
    current = client.get("/api/v1/dns/settings").json()
    change(current)
    return client.put("/api/v1/dns/settings", headers=headers, json=current)


def enable_plain_doh(engine: D4Engine) -> None:
    engine.settings["encrypted"]["doh"].update(
        {"enabled": True, "tls": False, "listen": ["127.0.0.1:8053", "172.17.0.1:8053"]})
    assert dns.ACTIVE_SERVICE is not None
    dns.ACTIVE_SERVICE.invalidate_settings()


# ----------------------------------------------------------------------------- settings


def test_d4_settings_validation(app_client, engine) -> None:
    client, headers, _events = app_client

    def bad(current: dict[str, Any]) -> None:
        current["resolution"].update({
            "mode": "magic", "qname_minimization": "loose", "query_timeout_ms": 5000,
            "resolve_timeout_ms": 2000, "max_referrals": 0, "case_randomization": "yes",
            "root_hints": [{"name": "a.root.test", "ipv4": "10.0.0.1"},
                           {"name": "a.root.test.", "ipv6": "::1"},
                           {"name": "b.root.test"},
                           {"name": "c.root.test", "ipv4": "::1"}],
            "surprise": 1})
        current["dnssec"].update({
            "mode": "strict", "bogus_ttl": 99999,
            "negative_trust_anchors": [
                {"domain": "corp.lan", "expires_at": "2027-01-01T00:00:00Z"},
                {"domain": "CORP.lan."},
                {"domain": "bad name", "reason": "x" * 300},
                {"domain": "ok.lan", "expires_at": "tomorrow"}]})
        current["encrypted"]["allow"] = ["0.0.0.0/0"]
        current["encrypted"]["dot"]["listen"] = ["127.0.0.1:53"]  # main tcp listener
        current["encrypted"]["doq"]["listen"] = ["nope"]
        current["encrypted"]["doh"].update({"tls": False, "listen": ["0.0.0.0:8053"],
                                            "path": "dns-query",
                                            "trusted_proxies": ["::/0"]})
        current["encrypted"]["max_connections"] = 1

    response = put(client, headers, bad)
    assert response.status_code == 422, response.text
    assert response.json()["error"]["code"] == "dns_settings_invalid"
    fields = fields_of(response)
    assert fields == {
        "resolution.mode": "invalid_choice",
        "resolution.qname_minimization": "invalid_choice",
        "resolution.case_randomization": "invalid_type",
        "resolution.max_referrals": "out_of_range",
        "resolution.surprise": "unknown_field",
        "resolution.root_hints.1.name": "duplicate",
        "resolution.root_hints.2": "address_required",
        "resolution.root_hints.3.ipv4": "invalid_address",
        "resolution.resolve_timeout_ms": "less_than_query_timeout",
        "dnssec.mode": "invalid_choice",
        "dnssec.bogus_ttl": "out_of_range",
        "dnssec.negative_trust_anchors.1.domain": "duplicate",
        "dnssec.negative_trust_anchors.2.domain": "invalid_name",
        "dnssec.negative_trust_anchors.2.reason": "too_long",
        "dnssec.negative_trust_anchors.3.expires_at": "invalid_time",
        "encrypted.allow.0": "open_resolver",
        "encrypted.max_connections": "out_of_range",
        "encrypted.dot.listen.0": "listen_conflict",
        "encrypted.doq.listen.0": "invalid_address",
        "encrypted.doh.path": "invalid_format",
        "encrypted.doh.trusted_proxies.0": "too_broad",
        "encrypted.doh.listen.0": "plain_doh_public",
    }
    # Nothing invalid reached the engine.
    assert not [item for item in engine.requests if item[0] == "PUT"
                and item[1] == "/v1/settings"]


def test_d4_listen_conflicts_unit() -> None:
    def errors(encrypted: dict[str, Any]) -> dict[str, str]:
        payload = {"listen": [{"address": "0.0.0.0:53", "udp": True, "tcp": True}],
                   "encrypted": encrypted}
        return {item["field"]: item["reason_code"]
                for item in dns_validate_d4.d4_settings_errors(payload)}

    # dot (tcp) and doq (udp) may share :853
    assert errors({"dot": {"listen": ["0.0.0.0:853"]}, "doq": {"listen": ["0.0.0.0:853"]}}) == {}
    assert errors({"dot": {"listen": ["0.0.0.0:853"]},
                   "doh": {"listen": ["127.0.0.1:853"]}}) == {
        "encrypted.doh.listen.0": "listen_conflict"}
    assert errors({"doh": {"listen": ["10.0.0.1:53"]}}) == {
        "encrypted.doh.listen.0": "listen_conflict"}
    assert errors({"dot": {"enabled": True, "listen": []}}) == {
        "encrypted.dot.listen": "invalid_type"}
    # IPv6 and private plain DoH
    assert errors({"doh": {"tls": False, "listen": ["[::1]:8053", "172.17.0.1:8053"]}}) == {}
    assert errors({"doh": {"tls": False, "listen": ["[2606:4700::1111]:8053"]}}) == {
        "encrypted.doh.listen.0": "plain_doh_public"}


def test_quic_upstream_and_valid_d4_save(app_client, engine) -> None:
    client, headers, _events = app_client
    assert dns_validate.upstream_address("quic://dns.adguard-dns.com") == (
        "quic://dns.adguard-dns.com")
    assert dns_validate.upstream_address("quic://94.140.14.14:853#dns.adguard-dns.com")
    with pytest.raises(ValueError):
        dns_validate.upstream_address("quic://bad host")

    def good(current: dict[str, Any]) -> None:
        current["upstreams"].append({"id": "doq", "address": "quic://94.140.14.14:853",
                                     "enabled": True})
        current["dnssec"]["negative_trust_anchors"] = [
            {"domain": "corp.lan", "reason": "internal", "expires_at": "2027-01-01T00:00:00Z"}]
        current["resolution"]["root_hints"] = [{"name": "a.root.test", "ipv4": "10.0.0.1"}]

    response = put(client, headers, good)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["config_version"] == 2 and body["warnings"] == []
    # The panel's own `warnings` never reaches the engine settings document.
    assert "warnings" not in engine.settings


def test_settings_warnings(app_client, engine) -> None:
    client, headers, _events = app_client
    engine.tls = {"present": True, "source": "self_signed", "names": ["dns.example.com"],
                  "self_signed": True}

    def recursive_public(current: dict[str, Any]) -> None:
        current["resolution"]["mode"] = "recursive"
        current["encrypted"]["dot"]["enabled"] = True
        current["encrypted"]["doh"]["enabled"] = True

    response = put(client, headers, recursive_public)
    assert response.status_code == 200, response.text
    codes = [item["code"] for item in response.json()["warnings"]]
    assert codes == ["recursive_needs_outbound_53", "doh_public_needs_token",
                     "self_signed_certificate"]
    # GET carries the same advice; a token removes the DoH one.
    engine.tokens.append({"id": "t1", "name": "phone", "qps": 50})
    codes = [item["code"] for item in client.get("/api/v1/dns/settings").json()["warnings"]]
    assert codes == ["recursive_needs_outbound_53", "self_signed_certificate"]

    # Unit: private-only allow + plain DoH published through a Traefik domain.
    settings = copy.deepcopy(engine.settings)
    settings["resolution"]["mode"] = "forward"
    settings["encrypted"]["doh"].update({"tls": False, "listen": ["127.0.0.1:8053"]})
    settings["encrypted"]["dot"]["enabled"] = False
    assert dns_validate_d4.settings_warnings(settings, tokens=0, certificate=None,
                                             plain_domains=1) == [
        {"code": "doh_public_needs_token"}]
    assert dns_validate_d4.settings_warnings(settings, tokens=0, certificate=None,
                                             plain_domains=0) == []
    settings["encrypted"]["allow"] = ["0.0.0.0/1"]  # an Internet range: no token needed
    assert dns_validate_d4.settings_warnings(settings, tokens=0, certificate=None,
                                             plain_domains=1) == []


# ----------------------------------------------------------------------------- resolve


def test_resolve_switches_and_trace_permission(app_client, engine) -> None:
    client, headers, _events = app_client
    answer = client.post("/api/v1/dns/resolve", headers=headers, json={
        "name": "isc.org", "type": "A", "dnssec": True, "cd": False, "trace": True,
        "no_cache": True})
    assert answer.status_code == 200, answer.text
    body = answer.json()
    assert body["echo"] == {"name": "isc.org", "type": "A", "dnssec": True, "cd": False,
                            "trace": True, "no_cache": True}
    assert body["trace"][0]["zone"] == "." and body["dnssec"]["status"] == "secure"
    bad = client.post("/api/v1/dns/resolve", headers=headers,
                      json={"name": "isc.org", "cd": "yes"})
    assert bad.status_code == 422 and fields_of(bad) == {"cd": "invalid_type"}
    viewer, viewer_headers = role_client(client, headers, "viewer")
    assert viewer.post("/api/v1/dns/resolve", headers=viewer_headers,
                       json={"name": "isc.org", "dnssec": False}).status_code == 200
    assert viewer.post("/api/v1/dns/resolve", headers=viewer_headers,
                       json={"name": "isc.org", "trace": True}).status_code == 403
    operator, operator_headers = role_client(client, headers, "operator")
    assert operator.post("/api/v1/dns/resolve", headers=operator_headers,
                         json={"name": "isc.org", "trace": True}).status_code == 200


# ----------------------------------------------------------------------------- dnssec / tls


def test_dnssec_view_and_refresh(app_client, engine) -> None:
    client, headers, _events = app_client
    view = client.get("/api/v1/dns/dnssec").json()
    assert view["trust_anchors"][0]["key_tag"] == 20326
    refreshed = client.post("/api/v1/dns/dnssec/refresh", headers=headers)
    assert refreshed.status_code == 200 and refreshed.json()["error"] == "timeout"
    assert "dns.dnssec.refresh" in audit_text(client)
    operator, operator_headers = role_client(client, headers, "operator")
    assert operator.get("/api/v1/dns/dnssec").status_code == 200
    assert operator.post("/api/v1/dns/dnssec/refresh",
                         headers=operator_headers).status_code == 403
    assert client.post("/api/v1/dns/dnssec/refresh").status_code == 403  # CSRF


def test_tls_upload_never_leaks_the_key(app_client, engine, caplog) -> None:
    client, headers, _events = app_client
    caplog.set_level("DEBUG")
    view = client.get("/api/v1/dns/tls")
    assert view.status_code == 200 and "key_pem" not in view.json()
    bad = client.put("/api/v1/dns/tls", headers=headers,
                     json={"cert_pem": "hello", "key_pem": "x" * (65 * 1024)})
    assert bad.status_code == 422 and bad.json()["error"]["code"] == "dns_tls_invalid"
    assert fields_of(bad) == {"cert_pem": "bad_pem", "key_pem": "too_large"}
    assert client.put("/api/v1/dns/tls", headers=headers,
                      json={"cert_pem": CERT, "key_pem": KEY, "x": 1}).status_code == 422
    mismatch = client.put("/api/v1/dns/tls", headers=headers,
                          json={"cert_pem": CERT + "BAD", "key_pem": KEY})
    assert mismatch.status_code == 422
    assert mismatch.json()["error"]["code"] == "dns_tls_invalid"
    assert mismatch.json()["error"]["reason_code"] == "key_mismatch"
    assert fields_of(mismatch) == {"body": "key_mismatch"}
    saved = client.put("/api/v1/dns/tls", headers=headers,
                       json={"cert_pem": CERT, "key_pem": KEY})
    assert saved.status_code == 200, saved.text
    assert saved.json()["fingerprint_sha256"] == "ab12cd" and "key_pem" not in saved.json()
    audit = audit_text(client)
    assert "dns.tls.upload" in audit and "ab12cd" in audit
    assert "SECRETKEYMATERIAL" not in audit
    assert "SECRETKEYMATERIAL" not in caplog.text
    assert "SECRETKEYMATERIAL" not in mismatch.text + bad.text
    operator, operator_headers = role_client(client, headers, "operator")
    assert operator.get("/api/v1/dns/tls").status_code == 200
    assert operator.put("/api/v1/dns/tls", headers=operator_headers,
                        json={"cert_pem": CERT, "key_pem": KEY}).status_code == 403


def test_self_signed_and_delete(app_client, engine) -> None:
    client, headers, _events = app_client
    bad = client.post("/api/v1/dns/tls/self-signed", headers=headers,
                      json={"names": ["ok.example.com", "bad name", "*.*.x"]})
    assert bad.status_code == 422
    assert set(fields_of(bad)) == {"names.1", "names.2"}
    assert client.post("/api/v1/dns/tls/self-signed", headers=headers,
                       json={"names": []}).status_code == 422
    made = client.post("/api/v1/dns/tls/self-signed", headers=headers,
                       json={"names": ["DNS.Example.com.", "10.0.0.5", "dns.example.com"]})
    assert made.status_code == 200, made.text
    assert engine.tls["names"] == ["dns.example.com", "10.0.0.5"]
    engine.listener_in_use = True
    in_use = client.delete("/api/v1/dns/tls", headers=headers)
    assert in_use.status_code == 409
    assert in_use.json()["error"]["code"] == "dns_certificate_in_use"
    engine.listener_in_use = False
    assert client.delete("/api/v1/dns/tls", headers=headers).json() == {"deleted": True}
    text = audit_text(client)
    assert "dns.tls.self_signed" in text and "dns.tls.delete" in text


def test_d4_engine_error_mapping() -> None:
    cases = {
        (409, "certificate_required"): ("dns_certificate_required", 409),
        (404, "token_not_found"): ("dns_token_not_found", 404),
        (422, "tls_invalid"): ("dns_tls_invalid", 422),
        (409, "certificate_in_use"): ("dns_certificate_in_use", 409),
        (400, "listen_conflict"): ("dns_listen_conflict", 422),
        (422, "plain_doh_public"): ("dns_plain_doh_public", 422),
    }
    for (status, code), expected in cases.items():
        mapped = dns_client.map_engine_error(
            status, json.dumps({"error": {"code": code}}).encode())
        assert (mapped.code, mapped.status_code) == expected


# ----------------------------------------------------------------------------- tokens


def test_doh_tokens_lifecycle(app_client, engine) -> None:
    client, headers, _events = app_client
    engine.settings["encrypted"]["doh"].update({"enabled": True, "listen": ["0.0.0.0:443"]})
    engine.tls = {"present": True, "source": "uploaded", "names": ["*.example.com",
                                                                   "dns.example.com"],
                  "self_signed": False, "not_after": "2099-01-01T00:00:00Z"}
    bad = client.post("/api/v1/dns/doh/tokens", headers=headers,
                      json={"name": "", "qps": 0, "other": 1})
    assert bad.status_code == 422 and bad.json()["error"]["code"] == "dns_token_invalid"
    bad = client.post("/api/v1/dns/doh/tokens", headers=headers, json={"name": "x" * 65,
                                                                       "qps": 20000})
    assert fields_of(bad) == {"name": "too_long", "qps": "out_of_range"}
    created = client.post("/api/v1/dns/doh/tokens", headers=headers,
                          json={"name": "  Ali's phone ", "qps": 20})
    assert created.status_code == 201, created.text
    body = created.json()
    assert body["token"] == DOH_TOKEN and body["name"] == "Ali's phone"
    assert body["urls"] == {"doh": f"https://dns.example.com/dns-query/{DOH_TOKEN}"}
    listed = client.get("/api/v1/dns/doh/tokens").json()["items"]
    assert listed[0]["id"] == "t1" and "token" not in listed[0]
    patched = client.patch("/api/v1/dns/doh/tokens/t1", headers=headers, json={"qps": 99})
    assert patched.status_code == 200 and patched.json()["qps"] == 99
    assert client.patch("/api/v1/dns/doh/tokens/t1", headers=headers,
                        json={}).status_code == 422
    assert client.delete("/api/v1/dns/doh/tokens/t1", headers=headers).json() == {
        "deleted": "t1"}
    missing = client.delete("/api/v1/dns/doh/tokens/t1", headers=headers)
    assert missing.status_code == 404
    assert missing.json()["error"]["code"] == "dns_token_not_found"
    text = audit_text(client)
    for action in ("dns.doh_token.create", "dns.doh_token.update", "dns.doh_token.delete"):
        assert action in text
    assert DOH_TOKEN not in text
    developer, developer_headers = role_client(client, headers, "developer")
    assert developer.get("/api/v1/dns/doh/tokens").status_code == 200
    assert developer.post("/api/v1/dns/doh/tokens", headers=developer_headers,
                          json={"name": "x"}).status_code == 403


# ----------------------------------------------------------------------------- devices


def test_clients_view_unit() -> None:
    base = D4Engine().settings
    off = dns_encrypted.clients_view(base, None, [], [])
    assert off["doh_url"] is None and off["dot_name"] is None and off["ip"] is None
    assert all(item == {"id": item["id"], "available": False, "reason": "encrypted_disabled"}
               for item in off["guides"])
    assert [item["id"] for item in off["guides"]] == list(dns_encrypted.GUIDES)

    settings = copy.deepcopy(base)
    settings["encrypted"]["dot"]["enabled"] = True
    settings["encrypted"]["doh"].update({"enabled": True, "listen": ["0.0.0.0:8443"]})
    self_signed = {"present": True, "source": "self_signed", "self_signed": True,
                   "names": ["dns.example.com"]}
    view = dns_encrypted.clients_view(settings, self_signed, [], ["203.0.113.7"])
    assert view["doh_url"] == "https://dns.example.com:8443/dns-query"
    assert view["dot_name"] == "dns.example.com" and view["ip"] == "203.0.113.7"
    assert view["certificate"]["trusted"] is False
    guides = {item["id"]: item for item in view["guides"]}
    assert guides["android"]["reason"] == "certificate_untrusted"
    assert guides["chrome"]["reason"] == "certificate_untrusted"

    uploaded = {**self_signed, "source": "uploaded", "self_signed": False,
                "not_after": "2099-01-01T00:00:00Z"}
    view = dns_encrypted.clients_view(settings, uploaded, [], [])
    guides = {item["id"]: item for item in view["guides"]}
    assert view["certificate"]["trusted"] is True and view["ip"] is None
    assert guides["android"] == {"id": "android", "available": True}
    assert guides["windows"]["reason"] == "no_ip" and guides["linux"]["reason"] == "no_ip"
    expired = {**uploaded, "not_after": "2001-01-01T00:00:00Z"}
    assert dns_encrypted.clients_view(settings, expired, [], [])["certificate"][
        "trusted"] is False

    # Plain DoH behind Traefik: the domain's https URL, trusted for DoH only.
    plain = copy.deepcopy(base)
    plain["encrypted"]["doh"].update({"enabled": True, "tls": False,
                                      "listen": ["127.0.0.1:8053"]})
    view = dns_encrypted.clients_view(plain, None, [
        {"host": "old.example.com", "https": False, "primary": True},
        {"host": "doh.example.com", "https": True, "primary": False}], ["203.0.113.7"])
    assert view["doh_url"] == "https://doh.example.com/dns-query"
    guides = {item["id"]: item for item in view["guides"]}
    assert guides["firefox"]["available"] and guides["windows"]["available"]
    assert guides["ios"]["available"] and guides["android"]["reason"] == "dot_disabled"


def test_clients_route_and_apple_profile(app_client, engine) -> None:
    client, headers, _events = app_client
    none = client.post("/api/v1/dns/encrypted/apple-profile", headers=headers, json={})
    assert none.status_code == 422 and none.json()["error"]["code"] == "dns_profile_invalid"
    engine.settings["encrypted"]["dot"]["enabled"] = True
    engine.tls = {"present": True, "source": "uploaded", "names": ["dns.example.com"],
                  "self_signed": False}
    dns.ACTIVE_SERVICE.invalidate_settings()
    view = client.get("/api/v1/dns/encrypted/clients").json()
    assert view["dot_name"] == "dns.example.com" and view["doh_url"] is None

    for bad, field in ((({"doh_url": "http://dns.example.com/dns-query"}), "doh_url"),
                       ({"doh_url": "https://u:p@dns.example.com/q"}, "doh_url"),
                       ({"doh_url": "https://dns.example.com/q?x=<1>"}, "doh_url"),
                       ({"dot_name": "10.0.0.1"}, "dot_name"),
                       ({"name": "a\nb"}, "name")):
        response = client.post("/api/v1/dns/encrypted/apple-profile", headers=headers,
                               json=bad)
        assert response.status_code == 422, bad
        assert field in fields_of(response)
    assert client.post("/api/v1/dns/encrypted/apple-profile", headers=headers,
                       json={"other": 1}).status_code == 422

    default = client.post("/api/v1/dns/encrypted/apple-profile", headers=headers, json={})
    assert default.status_code == 200
    assert default.headers["content-type"].startswith("application/x-apple-aspen-config")
    assert "mrk-dns.mobileconfig" in default.headers["content-disposition"]
    profile = plistlib.loads(default.content)
    inner = profile["PayloadContent"][0]
    assert profile["PayloadType"] == "Configuration"
    assert inner["PayloadType"] == "com.apple.dnsSettings.managed"
    assert inner["DNSSettings"] == {"DNSProtocol": "TLS", "ServerName": "dns.example.com"}

    custom = client.post("/api/v1/dns/encrypted/apple-profile", headers=headers, json={
        "doh_url": "https://DNS.example.com:443/dns-query/abc", "name": "Home <&> DNS"})
    inner = plistlib.loads(custom.content)["PayloadContent"][0]
    assert inner["DNSSettings"] == {"DNSProtocol": "HTTPS",
                                    "ServerURL": "https://dns.example.com/dns-query/abc"}
    assert inner["PayloadDisplayName"] == "Home <&> DNS"
    assert b"<&>" not in custom.content  # escaped by plistlib
    # dns:read is enough, but CSRF is required.
    viewer, viewer_headers = role_client(client, headers, "viewer")
    assert viewer.post("/api/v1/dns/encrypted/apple-profile", headers=viewer_headers,
                       json={}).status_code == 200
    assert viewer.post("/api/v1/dns/encrypted/apple-profile", json={}).status_code == 403


# ----------------------------------------------------------------------------- notifications


def test_d4_events_become_notifications(app_client, engine) -> None:
    client, _headers, events = app_client
    mon = dns.ACTIVE_SERVICE.monitor
    assert client.portal.call(mon.poll_events) == 0
    engine.add_event("dnssec.trust_anchor_failed", {"error": "timeout"})
    engine.add_event("dnssec.trust_anchor_updated", {"anchors": []}, "info")
    engine.add_event("dnssec.bogus_spike", {"count": 300, "names": [f"n{i}.example"
                                                                    for i in range(15)]},
                     "warning")
    engine.add_event("tls.certificate_expiring", {"days_left": 7}, "warning")
    engine.add_event("tls.certificate_expiring", {"days_left": 7}, "warning")  # dedupe
    engine.add_event("tls.certificate_expiring", {"days_left": 3}, "warning")
    engine.add_event("tls.certificate_expired", {})
    engine.add_event("resolution.priming_failed", {"error": "no root server answered"})
    engine.add_event("listener.failed", {"address": "0.0.0.0:853", "proto": "dot"})
    assert client.portal.call(mon.poll_events) == 6
    client.get("/api/v1/dns/status")  # let the app loop deliver the events
    found = [(event.type, event.severity, event.dedupe_key) for event in events
             if event.module == "dns" and event.type.startswith(("dns.dnssec", "dns.tls",
                                                                 "dns.priming"))]
    assert found == [
        ("dns.dnssec_trust_anchor_failed", "error", "dns.dnssec_trust_anchor_failed"),
        ("dns.dnssec_bogus_spike", "warning", "dns.dnssec_bogus_spike"),
        ("dns.tls_certificate_expiring", "warning", "dns.tls_certificate_expiring.7"),
        ("dns.tls_certificate_expiring", "warning", "dns.tls_certificate_expiring.3"),
        ("dns.tls_certificate_expired", "error", "dns.tls_certificate_expired"),
        ("dns.priming_failed", "error", "dns.priming_failed"),
    ]
    spike = next(event for event in events if event.type == "dns.dnssec_bogus_spike")
    assert spike.details["count"] == 300 and len(spike.details["names"]) == 10
    assert spike.details["route"] == "#/dns/monitor"


# ----------------------------------------------------------------------------- home


def test_d4_home_rules(app_client, engine) -> None:
    client, headers, _events = app_client
    engine.status_extra = {
        "listeners": [{"address": "0.0.0.0:853", "proto": "dot", "ok": True}],
        "encrypted": {"connections": {"dot": 1, "doh": 0, "doq": 0},
                      "certificate": {"present": True, "not_after": "2026-11-12T00:00:00Z",
                                      "self_signed": False, "days_left": 2}},
        "dnssec": {"mode": "validate", "trust_anchors": [
            {"key_tag": 20326, "algorithm": 8, "state": "revoked", "since": "x"}],
            "trust_anchor_updated_at": None, "trust_anchor_error": "timeout"},
    }
    dns.ACTIVE_SERVICE._status_at = 0.0
    home.LAST_SERVICE.invalidate()
    rules = {item["rule"]: item for item in client.get("/api/v1/home").json()["attention"]}
    cert = rules["dns_certificate_expiring"]
    assert cert["severity"] == "error" and cert["params"]["days_left"] == 2
    assert cert["action"]["route"] == "#/dns/encrypted"
    anchor = rules["dns_trust_anchor_problem"]
    assert anchor["severity"] == "error" and anchor["params"]["valid_anchors"] == 0
    assert anchor["action"]["route"] == "#/dns/settings"
    viewer, _vh = role_client(client, headers, "viewer")
    seen = {item["rule"] for item in viewer.get("/api/v1/home").json()["attention"]}
    assert {"dns_certificate_expiring", "dns_trust_anchor_problem"} <= seen


def test_d4_home_rules_unit() -> None:
    def rules(d4: dict[str, Any]) -> list[tuple[str, str]]:
        facts = {"dns": {"installed": True, "reachable": True, "pressure": None, "d4": d4}}
        return [(item["rule"], item["severity"]) for item in home.evaluate(facts, time.time())]

    cert = {"present": True, "days_left": 10}
    assert rules({"certificate": cert, "encrypted_in_use": True}) == [
        ("dns_certificate_expiring", "warning")]
    assert rules({"certificate": cert, "encrypted_in_use": False}) == []
    assert rules({"certificate": {"present": True, "days_left": 30},
                  "encrypted_in_use": True}) == []
    ok = {"mode": "validate", "trust_anchors": [{"state": "valid"}, {"state": "pending"}]}
    assert rules({"dnssec": ok}) == []
    assert rules({"dnssec": {**ok, "mode": "off", "trust_anchor_error": "x"}}) == []
    assert rules({"dnssec": {**ok, "trust_anchor_error": "x"}}) == [
        ("dns_trust_anchor_problem", "error")]
    assert home._dns_d4({"listeners": [{"proto": "doh", "tls": False}]})[
        "encrypted_in_use"] is False


# ----------------------------------------------------------------------------- dns-doh service


def test_dns_doh_service_follows_plain_doh(app_client, engine) -> None:
    client, headers, _events = app_client
    ids = [item["id"] for item in client.get("/api/v1/services").json()["items"]]
    assert "dns-doh" not in ids
    refused = client.post("/api/v1/domains", headers=headers, json={
        "service_id": "dns-doh", "host": "doh.example.com", "mode": "manual"})
    assert refused.status_code == 409
    assert refused.json()["error"]["code"] == "dns_doh_plain_disabled"

    enable_plain_doh(engine)
    dns.ACTIVE_SERVICE._status_at = 0.0  # the app started before the fake engine
    card = next(item for item in client.get("/api/v1/services").json()["items"]
                if item["id"] == "dns-doh")
    assert card["internal_port"] == 8053 and card["domains_supported"] is True
    assert card["manage_route"] == "#/dns/encrypted" and card["state"] == "running"
    created = client.post("/api/v1/domains", headers=headers, json={
        "service_id": "dns-doh", "host": "doh.example.com", "mode": "manual"})
    assert created.status_code in {200, 201}, created.text
    instructions = created.json()["instructions"]
    assert instructions["traefik"]["upstream"] == "http://172.17.0.1:8053"
    # encrypted/clients uses the service's https domain.
    view = client.get("/api/v1/dns/encrypted/clients").json()
    assert view["doh_url"] == "https://doh.example.com/dns-query"
    assert view["plain_doh"] is True and view["certificate"]["trusted"] is True

    # Traefik file payload: dns-doh carries its own target and port.
    service = services.ACTIVE_SERVICE
    payload = service.routing.traefik_payload(
        [{"service_id": "dns-doh", "host": "doh.example.com", "primary": True, "https": True},
         {"service_id": "panel", "host": "mrk.example.com", "primary": True, "https": True}],
        {"container_name": "mrk-mirror"})
    entries = {item["service"]: item for item in payload["services"]}
    assert entries["dns-doh"]["target_host"] == "172.17.0.1"
    assert entries["dns-doh"]["port"] == 8053 and "port" not in entries["panel"]
    rendered = json.loads("\n".join(line for line in traefik.render(payload).splitlines()
                                    if not line.startswith("#")))
    servers = rendered["http"]["services"]
    assert servers["mrk-dns-doh"]["loadBalancer"]["servers"] == [
        {"url": "http://172.17.0.1:8053"}]
    assert servers["mrk-panel"]["loadBalancer"]["servers"] == [{"url": "http://mrk-mirror:8080"}]
    # Only dns-doh may name its own target.
    bad = {**payload, "services": [{"service": "panel", "hosts": ["a.example.com"],
                                    "target_host": "10.0.0.1"}]}
    with pytest.raises(traefik.TraefikPayloadError):
        traefik.render(bad)
    with pytest.raises(traefik.TraefikPayloadError):
        traefik.render({**payload, "services": [{"service": "dns-doh", "hosts": [
            "a.example.com"], "target_host": "evil host", "port": 8053}]})

    # Turning plain DoH off keeps the card while a domain remains.
    engine.settings["encrypted"]["doh"]["enabled"] = False
    dns.ACTIVE_SERVICE.invalidate_settings()
    card = next(item for item in client.get("/api/v1/services").json()["items"]
                if item["id"] == "dns-doh")
    assert (card["state"], card["reason_code"]) == ("disabled", "doh_plain_disabled")


def test_doh_domain_probe_is_recognised() -> None:
    import httpx

    headers = httpx.Headers({"content-type": "application/dns-message"})
    assert domains_verify.identify(headers, b"\x00") == "dns-doh"
    assert domains_verify.PROBE_PATHS["dns-doh"].startswith("/dns-query?dns=")
