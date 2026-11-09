"""MRK DNS final phase, panel side (docs/41 §5–§6): domain templates (CRUD, variables,
preview, one-change apply, default on create), secondary zones and per-zone sections,
TSIG, zone signing, filtering, backup/restore pass-through, notifications, home rules."""

from __future__ import annotations

import gzip
import json
from pathlib import Path
from typing import Any

import pytest
from fastapi import Request
from fastapi.responses import JSONResponse, Response
from fastapi.testclient import TestClient
from mrk_control_plane import dns_client
from mrk_control_plane.config import Settings
from mrk_control_plane.main import create_app
from mrk_control_plane.modules import (
    dns,
    dns_filters,
    dns_final,
    dns_monitor,
    dns_templates,
    dns_validate,
    home,
)

from .helpers import login_owner
from .test_dns import TOKEN, role_client
from .test_dns import isolated as isolated  # noqa: F401 - fixture re-export
from .test_dns_d4 import D4Engine

TSIG_SECRET = "c2VjcmV0LXNlY3JldC1zZWNyZXQtc2VjcmV0LTEyMzQ="  # noqa: S105 - test-only
PRIVATE = "PRIVATE-KEY-MATERIAL"


def _err(status: int, code: str, **extra: Any) -> JSONResponse:
    return JSONResponse(status_code=status, content={"error": {"code": code, "message": code,
                                                               **extra}})


def _unquote(text: str) -> str:
    out, index = [], 0
    while index < len(text):
        char = text[index]
        if char == "\\" and text[index + 1:index + 4].isdigit():
            out.append(chr(int(text[index + 1:index + 4])))
            index += 4
        elif char == "\\":
            out.append(text[index + 1])
            index += 2
        else:
            out.append(char)
            index += 1
    return "".join(out)


def tokens(line: str) -> list[str]:
    """Whitespace split that keeps "quoted strings" (with backslash escapes) whole."""
    out, index = [], 0
    while index < len(line):
        if line[index].isspace():
            index += 1
            continue
        start = index
        if line[index] == '"':
            index += 1
            while line[index] != '"':
                index += 2 if line[index] == "\\" else 1
            index += 1
        else:
            while index < len(line) and not line[index].isspace():
                index += 1
        out.append(line[start:index])
    return out


def parse_zone(text: str, zone: str) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
    """Just enough of RFC 1035 for what the panel writes."""
    records: list[dict[str, Any]] = []
    soa = None
    for line in text.splitlines():
        if not line.strip() or line.startswith((";", "$")):
            continue
        parts = tokens(line)
        owner, ttl, _klass, rtype, rest = parts[0], int(parts[1]), parts[2], parts[3], parts[4:]
        name = "@" if owner == f"{zone}." else owner[: -len(zone) - 2]

        def host(value: str) -> str:
            return value if value == "." else value.rstrip(".")

        if rtype in {"A", "AAAA"}:
            data: dict[str, Any] = {"address": rest[0]}
        elif rtype in {"CNAME", "PTR"}:
            data = {"target": host(rest[0])}
        elif rtype == "NS":
            data = {"nameserver": host(rest[0])}
        elif rtype == "MX":
            data = {"preference": int(rest[0]), "exchange": host(rest[1])}
        elif rtype == "TXT":
            data = {"text": "".join(_unquote(item[1:-1]) for item in rest)}
        elif rtype == "CAA":
            data = {"flags": int(rest[0]), "tag": rest[1], "value": _unquote(rest[2][1:-1])}
        elif rtype == "SRV":
            data = {"priority": int(rest[0]), "weight": int(rest[1]), "port": int(rest[2]),
                    "target": host(rest[3])}
        elif rtype == "SOA":
            soa = {"ttl": ttl, "data": {"mname": host(rest[0]), "rname": host(rest[1]),
                                        "refresh": int(rest[3]), "retry": int(rest[4]),
                                        "expire": int(rest[5]), "minimum": int(rest[6])}}
            continue
        else:
            raise AssertionError(rtype)
        records.append({"name": name, "type": rtype, "ttl": ttl, "data": data,
                        "disabled": False, "comment": ""})
    return records, soa


class FinalEngine(D4Engine):
    def __init__(self) -> None:
        super().__init__()
        self.soa: dict[str, dict[str, Any]] = {}
        self.versions: dict[str, int] = {}
        self.imports: list[dict[str, Any]] = []
        self.tsig: list[dict[str, Any]] = []
        self.restored: list[bytes] = []
        self.backup = gzip.compress(b"manifest v1\n" + b"x" * 64)
        self.patches: list[dict[str, Any]] = []
        self._final_routes()

    def _final_routes(self) -> None:
        app = self.app
        engine = self
        replaced = {("POST", "/v1/zones"), ("GET", "/v1/zones/{zone}/records"),
                    ("POST", "/v1/zones/{zone}/import"), ("GET", "/v1/zones/{zone}"),
                    ("PATCH", "/v1/zones/{zone}")}
        app.router.routes = [
            route for route in app.router.routes
            if not any((method, getattr(route, "path", "")) in replaced
                       for method in getattr(route, "methods", set()) or set())
        ]

        @app.post("/v1/zones")
        async def create_zone(request: Request):
            body = await request.json()
            name = body["name"]
            if name in engine.zones:
                return _err(409, "zone_exists")
            engine.zones[name] = {"name": name, "type": body["type"], "serial": 1,
                                  "records": 0, "disabled": False, "updated_at": 1, **{
                                      key: body[key] for key in ("primaries", "tsig_key",
                                                                 "notify_allow", "forwarders")
                                      if key in body}}
            engine.versions[name] = 1
            engine.records[name] = []
            if body["type"] == "primary":
                engine.soa[name] = {"ttl": 900, "data": {
                    "mname": f"ns1.{name}", "rname": f"hostmaster.{name}", "refresh": 3600,
                    "retry": 600, "expire": 604800, "minimum": 300}}
                engine.records[name].append({"id": engine._id(), "name": "@", "type": "NS",
                                             "ttl": 14400, "data": {"nameserver": f"ns1.{name}"},
                                             "disabled": False, "comment": ""})
            return JSONResponse(status_code=201, content=engine.zones[name])

        @app.get("/v1/zones/{zone}")
        async def get_zone(zone: str):
            if zone not in engine.zones:
                return _err(404, "zone_not_found")
            return {**engine.zones[zone], "version": engine.versions[zone]}

        @app.patch("/v1/zones/{zone}")
        async def patch_zone(zone: str, request: Request):
            if zone not in engine.zones:
                return _err(404, "zone_not_found")
            body = await request.json()
            engine.patches.append(body)
            engine.zones[zone].update(body)
            return engine.zones[zone]

        @app.get("/v1/zones/{zone}/records")
        async def records(zone: str):
            if zone not in engine.zones:
                return _err(404, "zone_not_found")
            soa = engine.soa.get(zone)
            head = [{"id": "soa", "name": "@", "type": "SOA", "ttl": soa["ttl"],
                     "data": {**soa["data"], "serial": 2026110901}}] if soa else []
            return {"items": head + engine.records[zone]}

        @app.post("/v1/zones/{zone}/import")
        async def import_zone(zone: str, request: Request):
            body = await request.json()
            engine.imports.append(body)
            parsed, soa = parse_zone(body["text"], zone)
            for item in parsed:
                item["id"] = engine._id()
            if body["replace"]:
                apex_ns = [item for item in engine.records[zone]
                           if item["name"] == "@" and item["type"] == "NS"]
                engine.records[zone] = parsed + ([] if any(
                    item["type"] == "NS" and item["name"] == "@" for item in parsed)
                    else apex_ns)
            else:
                engine.records[zone].extend(parsed)
            if soa is not None:
                engine.soa[zone] = soa
            engine.versions[zone] += 1
            return {"added": len(parsed), "skipped": 0, "serial": 2026110902,
                    "version": engine.versions[zone]}

        @app.post("/v1/zones/{zone}/refresh")
        async def refresh(zone: str):
            if engine.zones.get(zone, {}).get("type") != "secondary":
                return _err(409, "zone_type_mismatch")
            return {"refreshed": True, "serial": 7}

        @app.get("/v1/zones/{zone}/dnssec")
        async def zone_dnssec(zone: str):
            return {"enabled": True, "keys": [{"tag": 1, "role": "ksk",
                                               "algorithm": "ECDSAP256SHA256", "created": "x",
                                               "state": "active", "private_key": PRIVATE}],
                    "ds": [{"digest_type": 2, "digest": "ab", "text": f"{zone}. IN DS 1 13 2 ab"}],
                    "next_resign": "y"}

        @app.post("/v1/zones/{zone}/dnssec/rollover")
        async def rollover(zone: str, request: Request):
            return {"started": (await request.json())["role"]}

        @app.get("/v1/tsig")
        async def list_tsig():
            # A buggy engine leaking secrets must still not reach the browser.
            return {"items": [{**item, "secret": TSIG_SECRET} for item in engine.tsig]}

        @app.post("/v1/tsig")
        async def create_tsig(request: Request):
            body = await request.json()
            if any(item["name"] == body["name"] for item in engine.tsig):
                return _err(409, "tsig_exists")
            engine.tsig.append({"name": body["name"], "algorithm": body["algorithm"]})
            return JSONResponse(status_code=201, content={
                "name": body["name"], "algorithm": body["algorithm"],
                "secret": body.get("secret") or TSIG_SECRET})

        @app.delete("/v1/tsig/{name}")
        async def delete_tsig(name: str):
            before = len(engine.tsig)
            engine.tsig = [item for item in engine.tsig if item["name"] != name]
            if len(engine.tsig) == before:
                return _err(404, "tsig_not_found")
            return Response(status_code=204)

        @app.get("/v1/filtering/status")
        async def filtering_status():
            return {"lists": [{"id": "ads", "entries": 10, "updated_at": "x"}],
                    "total_entries": 10, "blocked_1h": 3}

        @app.post("/v1/filtering/refresh")
        async def filtering_refresh():
            return {"started": True}

        @app.post("/v1/filtering/check")
        async def filtering_check(request: Request):
            body = await request.json()
            return {"blocked": body["name"].startswith("ads."), "list_id": "ads",
                    "rule": "ads.example.com", "echo": body}

        @app.get("/v1/backup")
        async def backup():
            return Response(content=engine.backup, media_type="application/gzip")

        @app.post("/v1/restore")
        async def restore(request: Request):
            data = await request.body()
            if request.headers.get("content-type") != "application/gzip":
                return _err(415, "unsupported_media")
            if b"BAD" in gzip.decompress(data):
                return _err(422, "restore_invalid", fields=[
                    {"field": "manifest", "reason_code": "version"}])
            engine.restored.append(data)
            return {"restored": True, "zones": 2}


@pytest.fixture
def engine(monkeypatch, isolated) -> FinalEngine:  # noqa: F811
    socket, token = isolated
    socket.parent.mkdir(parents=True, exist_ok=True)
    socket.write_bytes(b"")
    token.write_text(TOKEN + "\n", encoding="utf-8")
    fake = FinalEngine()
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


def audit_rows(client: TestClient) -> list[dict[str, Any]]:
    response = client.get("/api/v1/audit-events?limit=200")
    assert response.status_code == 200, response.text
    body = response.json()
    return body["items"] if isinstance(body, dict) else body


def actions(client: TestClient) -> dict[str, list[str | None]]:
    out: dict[str, list[str | None]] = {}
    for row in audit_rows(client):
        out.setdefault(row["action"], []).append(row.get("object_id"))
    return out


def fields_of(response) -> dict[str, str]:
    return {item["field"]: item["reason_code"] for item in response.json()["error"]["fields"]}


def set_server_ips(*ips: str) -> None:
    from mrk_control_plane.modules import services

    service = services.ACTIVE_SERVICE
    assert service is not None
    service.put_settings({"server_public_ips": list(ips)}, None)


def custom_template(**changes: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "name": "Shop",
        "description": "Shop site",
        "zone": {"ttl": 600, "soa": None, "ns": []},
        "records": [
            {"name": "@", "type": "A", "data": {"address": "{server_ipv4}"}},
            {"name": "shop", "type": "CNAME", "data": {"target": "{domain}"}},
            {"name": "@", "type": "TXT", "data": {"text": "token={shop_token}"}, "ttl": 300},
        ],
        "variables": [{"key": "shop_token", "label_fa": "توکن", "label_en": "Token",
                       "default": None, "required": True}],
    }
    body.update(changes)
    return body


# ----------------------------------------------------------------------------- templates


def test_builtin_templates_listed_and_read_only(app_client, engine) -> None:
    client, headers, _events = app_client
    body = client.get("/api/v1/dns/templates").json()
    ids = [item["id"] for item in body["items"]]
    assert ids[:6] == ["website", "website_email", "google_workspace", "microsoft_365",
                       "dokploy_apps", "security_only"]
    assert body["default_template_id"] == "website"
    website = body["items"][0]
    assert website["builtin"] is True and website["is_default"] is True
    assert website["name_fa"] == "وب‌سایت ساده" and website["name_en"] == "Simple website"
    assert {"domain", "server_ipv4", "server_ipv6", "mail_host", "dkim_value"} <= set(
        body["variables"]["standard"])
    google = client.get("/api/v1/dns/templates/google_workspace").json()
    mx = [item for item in google["records"] if item["type"] == "MX"]
    assert mx == [{"name": "@", "type": "MX", "data": {"preference": 1,
                                                       "exchange": "smtp.google.com"}}]
    put = client.put("/api/v1/dns/templates/website", headers=headers,
                     json=custom_template())
    assert put.status_code == 409 and put.json()["error"]["code"] == "dns_template_builtin"
    gone = client.delete("/api/v1/dns/templates/website", headers=headers)
    assert gone.status_code == 409
    assert client.get("/api/v1/dns/templates/nope").status_code == 404
    # Every built-in is a valid template for any domain (static check passes).
    for item in body["items"][:6]:
        dns_templates.template_body({key: item[key] for key in ("name", "description", "zone",
                                                                "records", "variables")})


def test_template_crud_copy_validation_and_audit(app_client, engine) -> None:
    client, headers, _events = app_client
    bad = client.post("/api/v1/dns/templates", headers=headers, json=custom_template(
        records=[{"name": "@", "type": "A", "data": {"address": "{nope}"}},
                 {"name": "x", "type": "SOA", "data": {}},
                 {"name": "y", "type": "MX", "data": {"preference": "10", "exchange": "a.b"}}],
        variables=[{"key": "domain", "label_fa": "x"}, {"key": "Bad-Key", "label_fa": "x"}]))
    assert bad.status_code == 422 and bad.json()["error"]["code"] == "dns_template_invalid"
    fields = fields_of(bad)
    assert fields["records.1.type"] == "invalid_choice"
    assert fields["records.2.data.preference"] == "invalid_type"
    assert fields["variables.0.key"] == "reserved"
    assert fields["variables.1.key"] == "invalid_format"
    assert fields["records.0.data.address"] == "unknown_variable"
    # A static record that can never be valid is caught at save time.
    static = client.post("/api/v1/dns/templates", headers=headers, json=custom_template(
        records=[{"name": "@", "type": "A", "data": {"address": "not-an-ip"}}]))
    assert static.status_code == 422
    assert fields_of(static) == {"records.0.data.address": "invalid_ipv4"}

    created = client.post("/api/v1/dns/templates", headers=headers, json=custom_template())
    assert created.status_code == 201, created.text
    item = created.json()
    assert item["id"].startswith("tpl_") and item["builtin"] is False
    assert item["records"][2]["ttl"] == 300 and item["records"][0]["ttl"] is None
    changed = client.put(f"/api/v1/dns/templates/{item['id']}", headers=headers,
                         json=custom_template(name="Shop 2"))
    assert changed.status_code == 200 and changed.json()["name"] == "Shop 2"
    copy = client.post("/api/v1/dns/templates", headers=headers,
                       json={"copy_from": "google_workspace"})
    assert copy.status_code == 201, copy.text
    assert copy.json()["name"] == "Google Workspace (copy)"
    assert copy.json()["copied_from"] == "google_workspace"
    edited = client.put(f"/api/v1/dns/templates/{copy.json()['id']}", headers=headers,
                        json={**{key: copy.json()[key] for key in ("zone", "records",
                                                                   "variables")},
                              "name": "My Google"})
    assert edited.status_code == 200
    default = client.put("/api/v1/dns/templates/default", headers=headers,
                         json={"template_id": item["id"]})
    assert default.status_code == 200 and default.json() == {"default_template_id": item["id"]}
    assert client.put("/api/v1/dns/templates/default", headers=headers,
                      json={"template_id": "tpl_missing"}).status_code == 404
    settings = client.get("/api/v1/settings/dns.default_template_id")
    if settings.status_code == 200:
        assert settings.json()["value"] == item["id"]
    deleted = client.delete(f"/api/v1/dns/templates/{item['id']}", headers=headers)
    assert deleted.status_code == 200
    assert deleted.json() == {"deleted": item["id"], "default_template_id": "website"}
    assert client.get(f"/api/v1/dns/templates/{item['id']}").status_code == 404
    seen = actions(client)
    assert seen["dns.template.create"][-1] == item["id"]
    assert "dns.template.update" in seen and "dns.template.delete" in seen
    assert seen["dns.template.copy"] == [f"google_workspace->{copy.json()['id']}"]
    assert seen["dns.template.default"] == [item["id"]]


def test_template_permissions(app_client, engine) -> None:
    client, headers, _events = app_client
    viewer, vh = role_client(client, headers, "viewer")
    operator, oh = role_client(client, headers, "operator")
    assert viewer.get("/api/v1/dns/templates").status_code == 200
    assert viewer.post("/api/v1/dns/templates/website/preview", headers=vh,
                       json={"zone": "example.com"}).status_code == 200
    assert viewer.post("/api/v1/dns/templates", headers=vh,
                       json=custom_template()).status_code == 403
    assert operator.post("/api/v1/dns/templates", headers=oh,
                         json=custom_template()).status_code == 403
    assert operator.put("/api/v1/dns/templates/default", headers=oh,
                        json={"template_id": None}).status_code == 403
    client.post("/api/v1/dns/zones", headers=headers,
                json={"name": "example.com", "template_id": None})
    assert viewer.post("/api/v1/dns/zones/example.com/apply-template", headers=vh,
                       json={"template_id": "security_only"}).status_code == 403
    applied = operator.post("/api/v1/dns/zones/example.com/apply-template", headers=oh,
                            json={"template_id": "security_only"})
    assert applied.status_code == 200, applied.text
    # CSRF is required on preview (a POST) too.
    assert viewer.post("/api/v1/dns/templates/website/preview",
                       json={"zone": "example.com"}).status_code == 403


def test_variables_render_and_skip(app_client, engine) -> None:
    client, headers, _events = app_client
    set_server_ips("203.0.113.7")
    created = client.post("/api/v1/dns/templates", headers=headers, json=custom_template())
    tid = created.json()["id"]
    missing = client.post(f"/api/v1/dns/templates/{tid}/preview", headers=headers,
                          json={"zone": "Shop.Example"})
    assert missing.status_code == 422
    assert missing.json()["error"]["code"] == "dns_template_variables_invalid"
    assert fields_of(missing) == {"variables.shop_token": "required"}
    unknown = client.post(f"/api/v1/dns/templates/{tid}/preview", headers=headers,
                          json={"zone": "shop.example", "variables": {"shop_token": "a",
                                                                      "domain": "evil.com",
                                                                      "server_ipv4": "::1"}})
    assert fields_of(unknown) == {"variables.domain": "unknown_field",
                                  "variables.server_ipv4": "invalid_ipv4"}
    preview = client.post(f"/api/v1/dns/templates/{tid}/preview", headers=headers,
                          json={"zone": "shop.example", "variables": {"shop_token": "abc"}})
    assert preview.status_code == 200, preview.text
    body = preview.json()
    assert body["zone_exists"] is False and body["can_apply"] is True
    assert body["variables"]["server_ipv4"] == "203.0.113.7"
    assert body["variables"]["domain"] == "shop.example"
    records = [(item["status"], item["record"]["name"], item["record"]["type"],
                item["record"]["ttl"], item["record"]["data"]) for item in body["items"]]
    assert records == [
        ("new", "@", "A", 600, {"address": "203.0.113.7"}),
        ("new", "shop", "CNAME", 600, {"target": "shop.example"}),
        ("new", "@", "TXT", 300, {"text": "token=abc"}),
    ]
    # Built-in website: no IPv6 on this server, so the AAAA records are skipped.
    website = client.post("/api/v1/dns/templates/website/preview", headers=headers,
                          json={"zone": "example.com"}).json()
    assert website["summary"] == {"new": 2, "duplicate": 0, "conflict": 0, "skipped": 2}
    skipped = [item for item in website["items"] if item["status"] == "skipped"]
    assert {item["variable"] for item in skipped} == {"server_ipv6"}
    # The user may give the IPv6 address by hand.
    with_v6 = client.post("/api/v1/dns/templates/website/preview", headers=headers,
                          json={"zone": "example.com",
                                "variables": {"server_ipv6": "2001:db8::7"}}).json()
    assert with_v6["summary"]["new"] == 4
    # Microsoft 365: the MX host is built from the domain.
    m365 = client.post("/api/v1/dns/templates/microsoft_365/preview", headers=headers,
                       json={"zone": "contoso.com"}).json()
    mx = next(item for item in m365["items"] if item["record"]["type"] == "MX")
    assert mx["record"]["data"] == {"preference": 0,
                                    "exchange": "contoso-com.mail.protection.outlook.com"}
    # No server address known: a warning and the A records are skipped.
    set_server_ips()
    unknown_ip = client.post("/api/v1/dns/templates/dokploy_apps/preview", headers=headers,
                             json={"zone": "apps.example"}).json()
    assert {"code": "server_ipv4_unknown"} in unknown_ip["warnings"]
    assert unknown_ip["summary"]["new"] == 1  # only CAA


def test_preview_classifies_and_apply_is_one_change(app_client, engine) -> None:
    client, headers, _events = app_client
    set_server_ips("203.0.113.7")
    assert client.post("/api/v1/dns/zones", headers=headers,
                       json={"name": "example.com", "template_id": ""}).status_code == 201
    engine.records["example.com"] += [
        {"id": "r-a", "name": "@", "type": "A", "ttl": 300, "data": {"address": "198.51.100.1"},
         "disabled": False, "comment": "old host"},
        {"id": "r-www", "name": "www", "type": "A", "ttl": 300,
         "data": {"address": "203.0.113.7"}, "disabled": False, "comment": ""},
        {"id": "r-spf", "name": "@", "type": "TXT", "ttl": 300,
         "data": {"text": "v=spf1 include:old.example ~all"}, "disabled": False, "comment": ""},
        {"id": "r-keep", "name": "@", "type": "TXT", "ttl": 300,
         "data": {"text": "keep \"me\""}, "disabled": False, "comment": ""},
    ]
    preview = client.post("/api/v1/dns/templates/website_email/preview", headers=headers,
                          json={"zone": "example.com"}).json()
    by = {(item["record"]["name"], item["record"]["type"]): item for item in preview["items"]}
    assert by[("www", "A")]["status"] == "duplicate"
    assert by[("@", "A")]["status"] == "conflict"
    assert [other["id"] for other in by[("@", "A")]["conflicts"]] == ["r-a"]
    assert by[("@", "MX")]["status"] == "new"
    assert by[("@", "MX")]["record"]["data"]["exchange"] == "mail.example.com"
    assert by[("@", "TXT")]["status"] == "conflict"  # a second SPF record
    assert by[("_dmarc", "TXT")]["record"]["data"]["text"] == "v=DMARC1; p=quarantine"
    assert preview["can_apply"] is False
    assert preview["summary"] == {"new": 3, "duplicate": 1, "conflict": 2, "skipped": 3}
    assert preview["replace_effects"]["removes"] == 2
    assert preview["replace_effects"]["comments_dropped"] == 0

    refused = client.post("/api/v1/dns/zones/example.com/apply-template", headers=headers,
                          json={"template_id": "website_email"})
    assert refused.status_code == 409
    error = refused.json()["error"]
    assert error["code"] == "dns_template_conflict"
    assert {(item["name"], item["type"]) for item in error["conflicts"]} == {("@", "A"),
                                                                             ("@", "TXT")}
    assert engine.imports == []

    applied = client.post("/api/v1/dns/zones/example.com/apply-template", headers=headers,
                          json={"template_id": "website_email", "replace_conflicts": True})
    assert applied.status_code == 200, applied.text
    result = applied.json()
    assert result["applied"] is True and result["mode"] == "replace"
    assert result["added"] == 5 and result["replaced"] == 2 and result["version"] == 2
    assert len(engine.imports) == 1 and engine.imports[0]["replace"] is True
    names = {(item["name"], item["type"], json.dumps(item["data"], sort_keys=True))
             for item in engine.records["example.com"]}
    assert ("@", "A", json.dumps({"address": "203.0.113.7"})) in names
    assert ("@", "A", json.dumps({"address": "198.51.100.1"})) not in names
    assert ("@", "TXT", json.dumps({"text": "keep \"me\""})) in names  # kept untouched
    assert ("@", "NS", json.dumps({"nameserver": "ns1.example.com"})) in names
    assert ("@", "CAA", json.dumps({"flags": 0, "tag": "issue", "value": "letsencrypt.org"},
                                   sort_keys=True)) in names
    assert engine.soa["example.com"]["data"]["mname"] == "ns1.example.com"  # SOA kept
    # Applying again: nothing new, no engine change.
    again = client.post("/api/v1/dns/zones/example.com/apply-template", headers=headers,
                        json={"template_id": "website_email"}).json()
    assert again["applied"] is False and again["summary"]["new"] == 0
    assert len(engine.imports) == 1
    assert "example.com:website_email" in actions(client)["dns.zone.apply_template"]


def test_apply_add_only_and_unsafe_replace(app_client, engine) -> None:
    client, headers, _events = app_client
    set_server_ips("203.0.113.7")
    client.post("/api/v1/dns/zones", headers=headers,
                json={"name": "quiet.example", "template_id": None})
    added = client.post("/api/v1/dns/zones/quiet.example/apply-template", headers=headers,
                        json={"template_id": "security_only"})
    assert added.status_code == 200
    assert added.json()["mode"] == "add" and added.json()["added"] == 4
    assert engine.imports[-1]["replace"] is False
    text = engine.imports[-1]["text"]
    assert "SOA" not in text and 'quiet.example. 3600 IN MX 0 .' in text
    assert '"v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s"' in text
    # A turned-off record would be lost by a whole-zone replace: refused.
    engine.records["quiet.example"].append({
        "id": "r-off", "name": "old", "type": "A", "ttl": 60, "data": {"address": "192.0.2.1"},
        "disabled": True, "comment": ""})
    engine.records["quiet.example"].append({
        "id": "r-old", "name": "www", "type": "A", "ttl": 60, "data": {"address": "192.0.2.9"},
        "disabled": False, "comment": ""})
    unsafe = client.post("/api/v1/dns/zones/quiet.example/apply-template", headers=headers,
                         json={"template_id": "website", "replace_conflicts": True})
    assert unsafe.status_code == 409
    assert unsafe.json()["error"]["code"] == "dns_template_replace_unsafe"
    # Secondary / unknown zones cannot take a template.
    assert client.post("/api/v1/dns/zones/none.example/apply-template", headers=headers,
                       json={"template_id": "website"}).status_code == 404
    client.post("/api/v1/dns/zones", headers=headers,
                json={"name": "copy.example", "type": "secondary",
                      "primaries": ["192.0.2.53"]})
    mismatch = client.post("/api/v1/dns/zones/copy.example/apply-template", headers=headers,
                           json={"template_id": "website"})
    assert mismatch.status_code == 409
    assert mismatch.json()["error"]["code"] == "dns_zone_type_mismatch"


def test_long_txt_is_split_and_escaped() -> None:
    text = 'v=DKIM1; k=rsa; p="' + "A" * 400
    line = dns_templates.zone_line("example.com", {"name": "sel._domainkey", "type": "TXT",
                                                   "ttl": 60, "data": {"text": text}})
    assert line.startswith("sel._domainkey.example.com. 60 IN TXT ")
    chunks = tokens(line)[4:]
    assert len(chunks) == 2
    records, _soa = parse_zone(line, "example.com")
    assert records[0]["data"]["text"] == text


def test_default_template_on_zone_create(app_client, engine) -> None:
    client, headers, _events = app_client
    set_server_ips("203.0.113.7", "2001:db8::7")
    created = client.post("/api/v1/dns/zones", headers=headers, json={"name": "site.example"})
    assert created.status_code == 201, created.text
    body = created.json()
    assert body["name"] == "site.example"
    assert body["template"]["template_id"] == "website" and body["template"]["applied"] is True
    assert body["template"]["added"] == 4
    assert len(engine.imports) == 1
    types = sorted((item["name"], item["type"]) for item in engine.records["site.example"])
    assert types == [("@", "A"), ("@", "AAAA"), ("@", "NS"), ("www", "A"), ("www", "AAAA")]
    # «No template» and a chosen template.
    none = client.post("/api/v1/dns/zones", headers=headers,
                       json={"name": "bare.example", "template_id": None}).json()
    assert none["template"] is None and len(engine.imports) == 1
    chosen = client.post("/api/v1/dns/zones", headers=headers,
                         json={"name": "mail.example", "template_id": "google_workspace",
                               "variables": {"dkim_value": "v=DKIM1; k=rsa; p=MIIB"}}).json()
    assert chosen["template"]["template_id"] == "google_workspace"
    assert any(item["name"] == "google._domainkey" for item in engine.records["mail.example"])
    # A bad value fails before the zone exists.
    bad = client.post("/api/v1/dns/zones", headers=headers,
                      json={"name": "bad.example", "template_id": "website",
                            "variables": {"server_ipv4": "nope"}})
    assert bad.status_code == 422 and "bad.example" not in engine.zones
    assert client.post("/api/v1/dns/zones", headers=headers,
                       json={"name": "x.example", "template_id": "tpl_gone"}).status_code == 404
    assert "x.example" not in engine.zones
    secondary_tpl = client.post("/api/v1/dns/zones", headers=headers,
                                json={"name": "s.example", "type": "secondary",
                                      "primaries": ["192.0.2.1"], "template_id": "website"})
    assert fields_of(secondary_tpl) == {"template_id": "not_allowed"}
    # A template with its own SOA/NS replaces the engine's defaults on a fresh zone.
    own = client.post("/api/v1/dns/templates", headers=headers, json=custom_template(
        zone={"ttl": 600, "soa": {"hostmaster": "admin@site.example", "refresh": 7200,
                                  "retry": 900, "expire": 1209600, "minimum": 60},
              "ns": ["ns1.provider.net", "ns2.provider.net"]},
        records=[], variables=[])).json()
    client.put("/api/v1/dns/templates/default", headers=headers, json={"template_id": own["id"]})
    fresh = client.post("/api/v1/dns/zones", headers=headers, json={"name": "own.example"})
    assert fresh.status_code == 201 and fresh.json()["template"]["mode"] == "replace"
    ns = sorted(item["data"]["nameserver"] for item in engine.records["own.example"]
                if item["type"] == "NS")
    assert ns == ["ns1.provider.net", "ns2.provider.net"]
    assert engine.soa["own.example"]["data"] == {
        "mname": "ns1.provider.net", "rname": "admin.site.example", "refresh": 7200,
        "retry": 900, "expire": 1209600, "minimum": 60}
    seen = actions(client)
    assert "site.example:website" in seen["dns.zone.apply_template"]
    assert "site.example" in seen["dns.zone.create"]
    # The variable values (a DKIM key here) never reach the audit log.
    assert "MIIB" not in json.dumps(audit_rows(client))


def test_default_template_setting_validation(app_client, engine) -> None:
    client, headers, _events = app_client
    with pytest.raises(dns.SettingsError):
        dns.validate_settings({"default_template_id": "a b"}, dict(dns.DEFAULT_SETTINGS))
    assert dns.validate_settings({"default_template_id": None},
                                 dict(dns.DEFAULT_SETTINGS))["default_template_id"] == ""
    off = client.put("/api/v1/dns/templates/default", headers=headers, json={"template_id": ""})
    assert off.json() == {"default_template_id": None}
    created = client.post("/api/v1/dns/zones", headers=headers, json={"name": "plain.example"})
    assert created.json()["template"] is None and engine.imports == []


# ----------------------------------------------------------------------------- zones D5


def test_secondary_zone_validation_and_refresh(app_client, engine) -> None:
    client, headers, _events = app_client
    bad = client.post("/api/v1/dns/zones", headers=headers,
                      json={"name": "sec.example", "type": "secondary",
                            "primaries": ["host.example", "192.0.2.1:99999"],
                            "notify_allow": ["0.0.0.0/0"], "tsig_key": "bad key"})
    assert bad.status_code == 422 and bad.json()["error"]["code"] == "dns_zone_invalid"
    assert fields_of(bad) == {"primaries.0": "invalid_address", "primaries.1": "invalid_address",
                              "tsig_key": "invalid_key_name", "notify_allow.0": "too_broad"}
    assert fields_of(client.post("/api/v1/dns/zones", headers=headers, json={
        "name": "sec.example", "type": "secondary"})) == {"primaries": "required"}
    assert fields_of(client.post("/api/v1/dns/zones", headers=headers, json={
        "name": "p.example", "primaries": ["192.0.2.1"]})) == {"primaries": "not_allowed"}
    created = client.post("/api/v1/dns/zones", headers=headers, json={
        "name": "sec.example", "type": "secondary", "primaries": ["192.0.2.1", "[2001:db8::1]"],
        "tsig_key": "XFR.Key.", "notify_allow": ["10.0.0.7/24"]})
    assert created.status_code == 201, created.text
    sent = json.loads([body for method, path, body in engine.requests
                       if method == "POST" and path == "/v1/zones"][-1])
    assert sent == {"name": "sec.example", "type": "secondary",
                    "primaries": ["192.0.2.1:53", "[2001:db8::1]:53"], "tsig_key": "xfr.key",
                    "notify_allow": ["10.0.0.0/24"]}
    assert created.json()["template"] is None
    refreshed = client.post("/api/v1/dns/zones/sec.example/refresh", headers=headers)
    assert refreshed.status_code == 200 and refreshed.json()["serial"] == 7
    client.post("/api/v1/dns/zones", headers=headers,
                json={"name": "prim.example", "template_id": None})
    wrong = client.post("/api/v1/dns/zones/prim.example/refresh", headers=headers)
    assert wrong.status_code == 409 and wrong.json()["error"]["code"] == "dns_zone_type_mismatch"
    viewer, vh = role_client(client, headers, "viewer")
    assert viewer.post("/api/v1/dns/zones/sec.example/refresh", headers=vh).status_code == 403
    assert actions(client)["dns.zone.refresh"][-1] == "sec.example"


def test_zone_sections_patch(app_client, engine) -> None:
    client, headers, _events = app_client
    client.post("/api/v1/dns/zones", headers=headers,
                json={"name": "example.com", "template_id": None})
    bad = client.patch("/api/v1/dns/zones/example.com", headers=headers, json={
        "transfer": {"allow": ["0.0.0.0/0"], "tsig_key": "ok-key", "x": 1},
        "notify": {"enabled": True, "targets": []},
        "update": {"enabled": True, "require_tsig": True, "tsig_key": None, "allow": ["::/0"]},
        "dnssec": {"enabled": True, "algorithm": "RSASHA1", "denial": "nsec3",
                   "signature_validity_days": 7, "refresh_days": 7,
                   "nsec3": {"iterations": 500, "salt": "xyz"}},
        "views": [{"group_id": "lan"}, {"group_id": "lan"}],
    })
    assert bad.status_code == 422 and bad.json()["error"]["code"] == "dns_zone_invalid"
    assert fields_of(bad) == {
        "transfer.x": "unknown_field", "transfer.allow.0": "too_broad",
        "notify.targets": "required", "update.allow.0": "too_broad",
        "update.tsig_key": "required", "dnssec.algorithm": "invalid_choice",
        "dnssec.refresh_days": "not_below_validity", "dnssec.nsec3.iterations": "out_of_range",
        "dnssec.nsec3.salt": "invalid_format", "views.1.group_id": "duplicate",
    }
    good = client.patch("/api/v1/dns/zones/example.com", headers=headers, json={
        "transfer": {"allow": ["192.0.2.53"], "tsig_key": "XFR-Key"},
        "notify": {"enabled": True, "targets": ["192.0.2.53"]},
        "update": {"enabled": False, "allow": [], "require_tsig": True},
        "dnssec": {"enabled": True, "algorithm": "ED25519", "denial": "nsec3",
                   "nsec3": {"iterations": 0, "salt": "", "opt_out": False},
                   "signature_validity_days": 14, "refresh_days": 3},
        "views": [{"group_id": "lan", "records_override": True}],
    })
    assert good.status_code == 200, good.text
    assert engine.patches[-1]["transfer"] == {"allow": ["192.0.2.53/32"], "tsig_key": "xfr-key"}
    assert engine.patches[-1]["notify"]["targets"] == ["192.0.2.53:53"]
    assert "example.com:dnssec,notify,transfer,update,views" in actions(client)[
        "dns.zone.update"]
    operator, oh = role_client(client, headers, "operator")
    assert operator.patch("/api/v1/dns/zones/example.com", headers=oh,
                          json={"dnssec": {"enabled": False}}).status_code == 200
    # Records accept a split-horizon view.
    record = client.post("/api/v1/dns/zones/example.com/records", headers=headers, json={
        "name": "intranet", "type": "A", "data": {"address": "10.0.0.5"}, "view": "lan"})
    assert record.status_code == 201 and record.json()["view"] == "lan"
    assert fields_of(client.post("/api/v1/dns/zones/example.com/records", headers=headers, json={
        "name": "x", "type": "A", "data": {"address": "10.0.0.5"}, "view": "bad view"})) == {
        "view": "invalid_format"}


def test_zone_dnssec_and_rollover(app_client, engine) -> None:
    client, headers, _events = app_client
    view = client.get("/api/v1/dns/zones/example.com/dnssec")
    assert view.status_code == 200
    assert PRIVATE not in view.text and view.json()["ds"][0]["digest"] == "ab"
    assert view.json()["keys"][0]["role"] == "ksk"
    bad = client.post("/api/v1/dns/zones/example.com/dnssec/rollover", headers=headers,
                      json={"role": "both"})
    assert fields_of(bad) == {"role": "invalid_choice"}
    ok = client.post("/api/v1/dns/zones/example.com/dnssec/rollover", headers=headers,
                     json={"role": "zsk"})
    assert ok.status_code == 200 and ok.json() == {"started": "zsk"}
    assert actions(client)["dns.zone.dnssec_rollover"] == ["example.com:zsk"]


def test_tsig_keys(app_client, engine) -> None:
    client, headers, _events = app_client
    bad = client.post("/api/v1/dns/tsig", headers=headers,
                      json={"name": "", "algorithm": "md5", "secret": "!!", "x": 1})
    assert bad.status_code == 422 and bad.json()["error"]["code"] == "dns_tsig_invalid"
    assert fields_of(bad) == {"x": "unknown_field", "name": "required",
                              "algorithm": "invalid_choice", "secret": "invalid_base64"}
    short = client.post("/api/v1/dns/tsig", headers=headers,
                        json={"name": "k", "secret": "c2hvcnQ="})
    assert fields_of(short) == {"secret": "out_of_range"}
    created = client.post("/api/v1/dns/tsig", headers=headers,
                          json={"name": "XFR-Key.", "algorithm": "hmac-sha512",
                                "secret": TSIG_SECRET})
    assert created.status_code == 201, created.text
    assert created.json()["secret"] == TSIG_SECRET  # shown once, in the create answer
    generated = client.post("/api/v1/dns/tsig", headers=headers, json={"name": "auto"})
    assert generated.status_code == 201 and generated.json()["algorithm"] == "hmac-sha256"
    dup = client.post("/api/v1/dns/tsig", headers=headers, json={"name": "auto"})
    assert dup.status_code == 409 and dup.json()["error"]["code"] == "dns_tsig_exists"
    listed = client.get("/api/v1/dns/tsig")
    assert listed.status_code == 200 and TSIG_SECRET not in listed.text
    assert [item["name"] for item in listed.json()["items"]] == ["xfr-key", "auto"]
    operator, oh = role_client(client, headers, "operator")
    assert operator.get("/api/v1/dns/tsig").status_code == 200
    assert operator.post("/api/v1/dns/tsig", headers=oh, json={"name": "o"}).status_code == 403
    assert operator.delete("/api/v1/dns/tsig/auto", headers=oh).status_code == 403
    deleted = client.delete("/api/v1/dns/tsig/auto", headers=headers)
    assert deleted.status_code == 200 and deleted.json() == {"deleted": "auto"}
    missing = client.delete("/api/v1/dns/tsig/auto", headers=headers)
    assert missing.status_code == 404 and missing.json()["error"]["code"] == "dns_tsig_not_found"
    seen = actions(client)
    assert {"auto", "xfr-key"} <= set(seen["dns.tsig.create"])
    assert seen["dns.tsig.delete"][-1] == "auto"
    assert TSIG_SECRET not in json.dumps(audit_rows(client))


# ----------------------------------------------------------------------------- filtering


def test_filtering_settings_validation(app_client, engine) -> None:
    client, headers, _events = app_client
    current = client.get("/api/v1/dns/settings").json()
    current["filtering"] = {
        "enabled": True, "action": "drop", "safe_search": "yes",
        "lists": [{"id": "ads", "name": "Ads", "url": "http://lists.example/ads.txt",
                   "format": "hosts", "enabled": True, "update_hours": 24},
                  {"id": "ads", "name": "", "url": "https://u:p@x.example/l", "format": "x",
                   "update_hours": 0}],
        "allow": ["good.example", "*.cdn.example", "bad name"], "block": [],
    }
    current["client_groups"] = [
        {"id": "kids", "name": "Kids", "networks": ["10.0.5.0/24"], "filtering": "on",
         "lists": ["ads", "missing"], "upstreams": ["cf", "nope"]},
        {"id": "kids", "name": "", "networks": [], "filtering": "maybe"},
    ]
    bad = client.put("/api/v1/dns/settings", headers=headers, json=current)
    assert bad.status_code == 422 and bad.json()["error"]["code"] == "dns_settings_invalid"
    assert fields_of(bad) == {
        "filtering.safe_search": "invalid_type", "filtering.action": "invalid_choice",
        "filtering.lists.0.url": "https_required", "filtering.lists.1.id": "duplicate",
        "filtering.lists.1.name": "invalid_format", "filtering.lists.1.url": "invalid_url",
        "filtering.lists.1.format": "invalid_choice",
        "filtering.lists.1.update_hours": "out_of_range", "filtering.allow.2": "invalid_name",
        "client_groups.0.lists.1": "unknown_list", "client_groups.0.upstreams.1":
        "unknown_upstream", "client_groups.1.id": "duplicate",
        "client_groups.1.name": "invalid_format", "client_groups.1.networks": "required",
        "client_groups.1.filtering": "invalid_choice",
    }
    current = client.get("/api/v1/dns/settings").json()
    current["filtering"] = {"enabled": True, "action": "nxdomain", "safe_search": False,
                            "lists": [{"id": "ads", "name": "Ads", "format": "hosts",
                                       "url": "https://lists.example/ads.txt",
                                       "enabled": True, "update_hours": 24}],
                            "allow": ["Good.Example."], "block": ["*.Tracker.example"]}
    current["client_groups"] = [{"id": "lan", "name": "LAN", "networks": ["10.0.0.7/24"],
                                 "filtering": "inherit", "lists": ["ads"]}]
    good = client.put("/api/v1/dns/settings", headers=headers, json=current)
    assert good.status_code == 200, good.text
    saved = engine.settings
    assert saved["filtering"]["allow"] == ["good.example"]
    assert saved["filtering"]["block"] == ["*.tracker.example"]
    assert saved["client_groups"][0]["networks"] == ["10.0.0.0/24"]
    operator, oh = role_client(client, headers, "operator")
    assert operator.put("/api/v1/dns/settings", headers=oh, json=current).status_code == 403


def test_filtering_status_refresh_check(app_client, engine) -> None:
    client, headers, _events = app_client
    viewer, vh = role_client(client, headers, "viewer")
    status = viewer.get("/api/v1/dns/filtering/status")
    assert status.status_code == 200 and status.json()["blocked_1h"] == 3
    check = viewer.post("/api/v1/dns/filtering/check", headers=vh, json={"name": "ADS.Example."})
    assert check.status_code == 200
    assert check.json()["blocked"] is True and check.json()["echo"] == {"name": "ads.example"}
    bad = viewer.post("/api/v1/dns/filtering/check", headers=vh, json={"name": "a b"})
    assert bad.status_code == 422 and bad.json()["error"]["code"] == "dns_query_invalid"
    assert viewer.post("/api/v1/dns/filtering/refresh", headers=vh).status_code == 403
    refreshed = client.post("/api/v1/dns/filtering/refresh", headers=headers)
    assert refreshed.status_code == 200 and refreshed.json() == {"started": True}
    assert "dns.filtering.refresh" in actions(client)
    assert "blocked" in dns_filters.SOURCES and dns_filters.SOURCES[-1] == "blocked"
    logs = client.get("/api/v1/dns/logs?source=blocked")
    assert logs.status_code != 422


# ----------------------------------------------------------------------------- backup


def test_backup_download_and_restore(app_client, engine) -> None:
    client, headers, _events = app_client
    operator, oh = role_client(client, headers, "operator")
    assert operator.get("/api/v1/dns/backup").status_code == 403
    download = client.get("/api/v1/dns/backup")
    assert download.status_code == 200
    assert download.content == engine.backup
    assert download.headers["content-type"] == "application/gzip"
    assert download.headers["content-disposition"].startswith(
        'attachment; filename="mrk-dns-backup-')
    upload = {"Content-Type": "application/gzip", **headers}
    wrong = client.post("/api/v1/dns/restore", headers=upload, content=engine.backup)
    assert wrong.status_code == 422
    assert wrong.json()["error"]["code"] == "confirmation_mismatch"
    assert wrong.json()["error"]["expected_confirmation"] == "RESTORE"
    not_gzip = client.post("/api/v1/dns/restore?confirmation=RESTORE", headers=upload,
                           content=b"plain text, not a backup")
    assert not_gzip.status_code == 422
    assert fields_of(not_gzip) == {"file": "not_gzip"}
    invalid = client.post("/api/v1/dns/restore?confirmation=RESTORE", headers=upload,
                          content=gzip.compress(b"BAD manifest"))
    assert invalid.status_code == 422
    assert invalid.json()["error"]["code"] == "dns_restore_invalid"
    ok = client.post("/api/v1/dns/restore?confirmation=restore", headers=upload,
                     content=engine.backup)
    assert ok.status_code == 200, ok.text
    assert ok.json() == {"restored": True, "zones": 2}
    assert engine.restored == [engine.backup]
    assert client.post("/api/v1/dns/restore?confirmation=RESTORE",
                       headers={"Content-Type": "application/gzip"},
                       content=engine.backup).status_code == 403  # CSRF
    assert operator.post("/api/v1/dns/restore?confirmation=RESTORE",
                         headers={"Content-Type": "application/gzip", **oh},
                         content=engine.backup).status_code == 403
    seen = actions(client)
    assert seen["dns.backup.download"][0].startswith("sha256:")
    assert len(seen["dns.backup.restore"]) == 2  # one failure (invalid), one success


# ----------------------------------------------------------------------------- events/home


def test_final_events_become_notifications_and_home(app_client, engine) -> None:
    client, headers, events = app_client
    service = dns.ACTIVE_SERVICE
    mon = service.monitor
    assert client.portal.call(mon.poll_events) == 0
    engine.add_event("zone.secondary_expired", {"zone": "sec.example", "error": "expired"})
    engine.add_event("zone.transfer_failed", {"zone": "sec.example", "primary": "192.0.2.1",
                                              "error": "refused"}, "warning")
    engine.add_event("zone.transfer_failed", {"zone": "sec.example", "error": "refused"},
                     "warning")  # dedupe
    engine.add_event("filtering.list_failed", {"list_id": "ads", "name": "Ads",
                                               "error": "timeout"}, "warning")
    engine.add_event("dnssec.signing_failed", {"zone": "example.com", "error": "no key"})
    assert client.portal.call(mon.poll_events) == 4
    client.get("/api/v1/dns/status")
    found = [(event.type, event.severity, event.dedupe_key) for event in events
             if event.module == "dns" and event.type in {
                 "dns.secondary_expired", "dns.transfer_failed", "dns.filter_list_failed",
                 "dns.dnssec_signing_failed"}]
    assert found == [
        ("dns.secondary_expired", "error", "dns.secondary_expired.sec.example"),
        ("dns.transfer_failed", "warning", "dns.transfer_failed.sec.example"),
        ("dns.filter_list_failed", "warning", "dns.filter_list_failed.ads"),
        ("dns.dnssec_signing_failed", "error", "dns.dnssec_signing_failed.example.com"),
    ]
    listed = next(event for event in events if event.type == "dns.filter_list_failed")
    assert listed.details["route"] == "#/dns/blocking"
    service._status_at = 0.0
    home.LAST_SERVICE.invalidate()
    viewer, _vh = role_client(client, headers, "viewer")
    rules = {item["id"]: item for item in viewer.get("/api/v1/home").json()["attention"]}
    secondary = rules["dns_secondary_problem:sec.example"]
    assert secondary["severity"] == "error" and secondary["params"]["expired"] is True
    assert secondary["action"]["route"] == "#/dns/names?zone=sec.example"
    signing = rules["dns_signing_problem:example.com"]
    assert signing["severity"] == "error" and signing["params"]["error"] == "no key"
    # A recovery event and the zone poll clear them.
    engine.add_event("zone.secondary_refreshed", {"zone": "sec.example"}, "info")
    client.portal.call(mon.poll_events)
    assert [item["kind"] for item in service.cached_zone_problems()] == ["signing"]
    client.post("/api/v1/dns/zones", headers=headers, json={
        "name": "sec.example", "type": "secondary", "primaries": ["192.0.2.1"]})
    engine.zones["sec.example"]["secondary"] = {"serial": 1, "last_refresh": 1,
                                                "last_success": 1, "next_refresh": 2,
                                                "expires_at": "2000-01-01T00:00:00Z"}
    client.portal.call(service.refresh_zone_problems)
    problems = service.cached_zone_problems()
    assert [(item["kind"], item["zone"], item["expired"]) for item in problems] == [
        ("secondary", "sec.example", True)]
    engine.zones["sec.example"]["secondary"]["expires_at"] = "2999-01-01T00:00:00Z"
    engine.zones["sec.example"]["secondary"]["error"] = "connection refused"
    client.portal.call(service.refresh_zone_problems)
    service._status_at = 0.0
    home.LAST_SERVICE.invalidate()
    rules = {item["id"]: item for item in client.get("/api/v1/home").json()["attention"]}
    assert rules["dns_secondary_problem:sec.example"]["severity"] == "warning"


def test_unit_helpers() -> None:
    assert dns_validate.zone_patch_body({"views": []}) == {"views": []}
    assert dns_final._global("10.0.0.1") is None
    assert str(dns_final._global("8.8.8.8")) == "8.8.8.8"
    assert dns.zone_view_problems({"type": "primary", "dnssec": {
        "enabled": True, "error": "x"}}, 0) == {"signing": {"error": "x"}}
    assert dns.zone_view_problems({"type": "secondary", "secondary": {
        "expires_at": 10**13}}, 0) == {}
    assert dns_templates.rdata("CAA", {"flags": 0, "tag": "ISSUE", "value": 'a"b'}) == \
        '0 issue "a\\"b"'
    assert dns_templates.rdata("MX", {"preference": 0, "exchange": "."}) == "0 ."
    assert dns_templates.rdata("SRV", {"priority": 1, "weight": 2, "port": 443,
                                       "target": "x.example"}) == "1 2 443 x.example."
