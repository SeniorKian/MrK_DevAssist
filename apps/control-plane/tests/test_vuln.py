"""Gate 19 S8: feed import, end-to-end scan with a fake agent, ignores, events, API RBAC."""

from __future__ import annotations

import asyncio
import base64
import io
import json
import time
import zipfile
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient
from mrk_control_plane.auth import ROLE_PERMISSIONS
from mrk_control_plane.config import Settings
from mrk_control_plane.database import Database
from mrk_control_plane.main import create_app
from mrk_control_plane.modules import vuln
from mrk_control_plane.modules.host_agent import AgentError
from mrk_control_plane.modules.vuln_settings import (
    DEFAULT_SETTINGS,
    SettingsError,
    validate_ignore,
    validate_settings,
)
from mrk_control_plane.netresolve import NetworkSettingsStore
from mrk_control_plane.secret_store import SecretStore

from .helpers import login_owner

PASSWORD = "a-long-role-password-123"  # noqa: S105 - test-only fixture
IMG_DEB = "sha256:" + "1" * 64
IMG_NODE = "sha256:" + "2" * 64
C1, C2, C3, C4 = ("c" * 63 + "1", "c" * 63 + "2", "c" * 63 + "3", "c" * 63 + "4")
CRIT = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
HIGH = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"


def osv(advisory_id, ecosystem, name, fixed, *, vector=None, aliases=(), extra=None, **fields):
    record = {
        "id": advisory_id,
        "summary": f"{name} issue",
        "aliases": list(aliases),
        "affected": [
            {
                "package": {"ecosystem": ecosystem, "name": name},
                "ranges": [{"type": "ECOSYSTEM",
                            "events": [{"introduced": "0"}, {"fixed": fixed}]}],
            }
        ],
    }
    if vector:
        record["severity"] = [{"type": "CVSS_V3", "score": vector}]
    record.update(extra or {})
    record.update(fields)
    return record


def zip_of(records: list[dict[str, Any]]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for record in records:
            archive.writestr(f"{record['id']}.json", json.dumps(record))
        archive.writestr("README.txt", "not a record")
    return buffer.getvalue()


class FeedServer:
    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []
        self.status: dict[str, int] = {}
        self.feeds: dict[str, list[dict[str, Any]]] = {
            "Debian": [
                osv("DEBIAN-CVE-2023-0001", "Debian:12", "openssl", "3.0.13-1~deb12u1",
                    vector=CRIT, upstream=["CVE-2023-0001"]),
                osv("DEBIAN-CVE-2023-0002", "Debian:12", "zlib", "1:1.3.dfsg-1",
                    vector=HIGH, upstream=["CVE-2023-0002"]),
                osv("DEBIAN-CVE-2023-0003", "Debian:11", "openssl", "9.9-1", vector=CRIT),
                osv("DEBIAN-CVE-2023-0004", "Debian:12", "openssl", "3.0.1-1", vector=CRIT),
                osv("DEBIAN-CVE-2023-0005", "Debian:12", "openssl", "9.9-1", vector=CRIT,
                    withdrawn="2024-01-01T00:00:00Z"),
            ],
            "npm": [
                osv("GHSA-aaaa-bbbb-cccc", "npm", "lodash", "4.17.21",
                    aliases=["CVE-2021-23337"], database_specific={"severity": "HIGH"}),
            ],
        }
        self.version = 1

    def body(self, feed: str) -> bytes:
        return zip_of(self.feeds[feed])

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        path = request.url.path
        feed = path.removeprefix("/").removesuffix("/all.zip").replace("%20", " ")
        if feed in self.status:
            return httpx.Response(self.status[feed])
        if feed not in self.feeds:
            return httpx.Response(404)
        etag = f'"{feed}-{self.version}"'
        if request.headers.get("if-none-match") == etag:
            return httpx.Response(304, headers={"ETag": etag})
        return httpx.Response(200, content=self.body(feed),
                              headers={"ETag": etag, "Content-Type": "application/zip"})


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


DEB_FILES = {
    "files": [
        {"path": "/etc/os-release", "note": None, "entries": [
            {"name": "os-release", "data_b64": b64(b"ID=debian\nVERSION_ID=12\n")}]},
        {"path": "/var/lib/dpkg/status", "note": None, "entries": [
            {"name": "status", "data_b64": b64(
                b"Package: libssl3\nStatus: install ok installed\nSource: openssl\n"
                b"Version: 3.0.11-1~deb12u2\n\n"
                b"Package: openssl\nStatus: install ok installed\nVersion: 3.0.11-1~deb12u2\n\n"
                b"Package: zlib1g\nStatus: install ok installed\nSource: zlib\n"
                b"Version: 1:1.2.13.dfsg-1\n")}]},
    ],
    "missing": [], "errors": [],
}
NODE_FILES = {
    "files": [
        {"path": "/app/package-lock.json", "note": None, "entries": [
            {"name": "package-lock.json", "data_b64": b64(json.dumps(
                {"packages": {"node_modules/lodash": {"version": "4.17.20"}}}).encode())}]},
    ],
}


class FakeAgent:
    def __init__(self) -> None:
        self.configured = True
        self.file_requests: list[str] = []
        self.containers = [
            {"id": C1, "name": "web-1", "image": "app:1", "image_id": IMG_DEB,
             "state": "running", "protected": False},
            {"id": C2, "name": "web-2", "image": "app:1", "image_id": IMG_DEB,
             "state": "running", "protected": False},
            {"id": C3, "name": "node", "image": "node-app:2", "image_id": IMG_NODE,
             "state": "running", "protected": False},
            {"id": C4, "name": "old", "image": "old:1", "image_id": "sha256:" + "9" * 64,
             "state": "exited", "protected": False},
        ]

    def resolve(self):
        return ("panel", "http://agent:8080", b"k") if self.configured else (None, None, None)

    async def call(self, path: str):
        if path == "/v1/docker/containers":
            return {"items": self.containers}
        if path == "/v1/docker/images":
            return {"items": [{"id": IMG_DEB, "repo_tags": ["app:1"],
                               "repo_digests": ["app@sha256:" + "d" * 64]}]}
        raise AssertionError(path)

    async def request(self, method, path, body=None, *, timeout=None, max_bytes=0):
        assert method == "GET" and max_bytes > 0
        self.file_requests.append(path)
        if C1 in path or C2 in path:
            return DEB_FILES
        if C3 in path:
            return NODE_FILES
        raise AgentError("agent_not_found", 404, "missing")


class Recorder:
    def __init__(self) -> None:
        self.events: list[Any] = []

    def publish(self, event) -> None:
        self.events.append(event)


class Clock:
    def __init__(self) -> None:
        self.now = 1_800_000_000.0

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def feed_server(monkeypatch):
    server = FeedServer()
    monkeypatch.setattr(vuln, "TRANSPORT_FACTORY", lambda: httpx.MockTransport(server.handler))
    monkeypatch.setattr(vuln, "RESOLVER", lambda host, port, config: ["93.184.216.34"])
    return server


def make_service(tmp_path: Path, agent: FakeAgent | None = None):
    database = Database(tmp_path)
    database.initialize()
    events = Recorder()
    clock = Clock()
    ctx = SimpleNamespace(
        data_dir=tmp_path,
        network_settings=NetworkSettingsStore(tmp_path),
        secret_store=SecretStore(tmp_path),
        events=events,
        database=database,
    )
    service = vuln.VulnService(ctx, agent=agent or FakeAgent(), clock=clock)  # type: ignore
    return service, events, clock


def run(coro):
    return asyncio.run(coro)


# ----- settings ------------------------------------------------------------------------


def test_settings_validation() -> None:
    assert validate_settings({}) == DEFAULT_SETTINGS
    value = validate_settings({"ecosystems_extra": ["PyPI", "Debian:12", "PyPI"],
                               "severities_to_notify": ["high", "critical"],
                               "feed_base_url": "https://mirror.example/osv/"})
    assert value["ecosystems_extra"] == ["PyPI", "Debian"]
    assert value["severities_to_notify"] == ["critical", "high"]
    assert value["feed_base_url"] == "https://mirror.example/osv"
    for bad in ({"interval_hours": 0}, {"ecosystems_extra": ["Maven"]},
                {"feed_base_url": "ftp://x"}, {"feed_base_url": "https://u:p@x"},
                {"severities_to_notify": ["unknown"]}, {"nope": 1}, {"enabled": "yes"},
                {"feed_max_mb": 1}):
        with pytest.raises(SettingsError):
            validate_settings(bad)
    with pytest.raises(SettingsError):
        validate_ignore({"reason": "x"})
    with pytest.raises(SettingsError):
        validate_ignore({"advisory": "CVE-1", "reason": "x", "expires_at": 5}, now=10)


# ----- feeds -----------------------------------------------------------------------------


def test_feed_import_and_conditional_refresh(tmp_path: Path, feed_server: FeedServer) -> None:
    service, _events, clock = make_service(tmp_path)
    settings = service.settings
    assert run(service.refresh_feeds(["Debian", "npm"], settings)) == {}
    feeds = service.osv.feeds()
    assert feeds["Debian"]["records"] == 4  # withdrawn record skipped
    assert feeds["Debian"]["etag"] == '"Debian-1"'
    assert feeds["Debian"]["url"].endswith("/Debian/all.zip")
    assert (tmp_path / "modules" / "vuln" / "osv.sqlite").exists()
    assert not list((tmp_path / "modules" / "vuln" / "downloads").iterdir())
    matches = service.osv.lookup("Debian:12", ["openssl", "zlib"])
    assert {m.id for m in matches["openssl"]} == {"DEBIAN-CVE-2023-0001", "DEBIAN-CVE-2023-0004"}
    assert matches["openssl"][0].aliases == ["CVE-2023-0001"] or matches["openssl"][1].aliases
    assert service.osv.lookup("Debian:11", ["openssl"])["openssl"][0].id == "DEBIAN-CVE-2023-0003"
    first = len(feed_server.requests)
    run(service.refresh_feeds(["Debian"], settings))
    assert len(feed_server.requests) == first  # inside the recheck window
    clock.now += 2 * 3600
    run(service.refresh_feeds(["Debian"], settings))
    last = feed_server.requests[-1]
    assert last.headers["if-none-match"] == '"Debian-1"'
    assert service.osv.feeds()["Debian"]["checked_at"] == clock.now
    assert service.osv.feeds()["Debian"]["records"] == 4


def test_feed_errors_and_size_cap(tmp_path: Path, feed_server: FeedServer) -> None:
    service, _events, _clock = make_service(tmp_path)
    feed_server.status["Debian"] = 503
    errors = run(service.refresh_feeds(["Debian"], service.settings))
    assert errors == {"Debian": "http_503"}
    assert service.osv.feeds()["Debian"]["status"] == "error"
    del feed_server.status["Debian"]
    feed_server.feeds["Debian"] = [
        osv(f"DEBIAN-CVE-2024-{i:04d}", "Debian:12", "pkg", "1.0", summary="x" * 4000)
        for i in range(1200)
    ]
    service.state["settings"]["feed_max_mb"] = 16
    big = run(service.refresh_feeds(["Debian"], service.settings))
    assert big == {}
    # Uncompressed cap: 16 MiB * 8 is plenty here; a tiny cap must reject.
    zip_path = tmp_path / "f.zip"
    zip_path.write_bytes(feed_server.body("Debian"))
    from mrk_control_plane.modules.vuln_osv import FeedImportError

    with pytest.raises(FeedImportError):
        service.osv.import_zip("Debian", zip_path, max_total_bytes=1000)
    assert service.osv.feeds()["Debian"]["records"] == 1200  # failed import rolled back
    bad = tmp_path / "bad.zip"
    bad.write_bytes(b"not a zip")
    with pytest.raises(FeedImportError):
        service.osv.import_zip("Debian", bad, max_total_bytes=10**9)


# ----- end-to-end scan -----------------------------------------------------------------------


def test_scan_end_to_end_ignores_and_event_dedupe(
    tmp_path: Path, feed_server: FeedServer
) -> None:
    agent = FakeAgent()
    service, events, clock = make_service(tmp_path, agent)
    result = run(service.run_scan("manual"))
    assert result["ok"] is True and result["images"] == 2
    # Dedupe per image: one package-files request per image id; stopped skipped.
    assert len(agent.file_requests) == 2
    assert not any(C4 in path for path in agent.file_requests)
    view = service.images_view()
    images = {item["image_id"]: item for item in view["items"]}
    deb = images[IMG_DEB]
    assert deb["os"]["ecosystem"] == "Debian:12"
    assert deb["digest"] == "sha256:" + "d" * 64
    assert deb["packages_scanned"] == 3
    assert {c["name"] for c in deb["containers"]} == {"web-1", "web-2"}
    assert deb["counts"] == {"critical": 1, "high": 1, "medium": 0, "low": 0, "unknown": 0}
    assert deb["status"] == "critical" and deb["fixable"] == 2
    assert images[IMG_NODE]["counts"]["high"] == 1
    assert images[IMG_NODE]["status"] == "warning"

    findings = service.findings_view(IMG_DEB, None, None, True, 100, 0)
    assert findings is not None and findings["total"] == 2
    top = findings["items"][0]
    assert top["id"] == "DEBIAN-CVE-2023-0001" and top["severity"] == "critical"
    assert top["package"] == "openssl" and top["binaries"] == ["libssl3"]
    assert top["installed"] == "3.0.11-1~deb12u2" and top["fixed"] == "3.0.13-1~deb12u1"
    assert top["aliases"] == ["CVE-2023-0001"] and top["score"] == 9.8
    assert top["ecosystem"] == "Debian:12"
    assert service.findings_view(IMG_DEB, ["high"], None, True, 100, 0)["total"] == 1
    assert service.findings_view(IMG_DEB, None, "cve-2023-0002", True, 100, 0)["total"] == 1
    assert service.findings_view(IMG_DEB, None, "zlib1g", True, 100, 0)["total"] == 1
    assert service.findings_view(IMG_DEB, None, "nomatch", True, 100, 0)["total"] == 0
    assert service.findings_view("1" * 64, None, None, True, 1, 0)["total"] == 2  # bare hex
    assert service.findings_view("sha256:" + "f" * 64, None, None, True, 1, 0) is None

    # Events: one per image and severity, deduplicated per image+advisory.
    types = sorted((e.type, e.details["image_id"]) for e in events.events)
    assert types == [("vuln.new_critical", IMG_DEB), ("vuln.new_high", IMG_DEB),
                     ("vuln.new_high", IMG_NODE)]
    critical = next(e for e in events.events if e.type == "vuln.new_critical")
    assert critical.severity == "critical" and "web-1" in critical.message
    assert critical.details["advisories"] == ["DEBIAN-CVE-2023-0001"]
    events.events.clear()
    clock.now += 3600
    run(service.run_scan("schedule"))
    assert events.events == []
    assert len(agent.file_requests) == 2  # inventory cache per image id

    # Ignore rules: advisory by alias glob, package pattern, expiry.
    rule = service.add_ignore({"advisory": "CVE-2023-000*", "image": "app:*",
                               "reason": "accepted risk"}, None)
    deb = {i["image_id"]: i for i in service.images_view()["items"]}[IMG_DEB]
    assert deb["counts"]["critical"] == 0 and deb["counts"]["high"] == 0 and deb["ignored"] == 2
    assert deb["status"] == "secure"
    hidden = service.findings_view(IMG_DEB, None, None, False, 100, 0)
    assert hidden["total"] == 0
    shown = service.findings_view(IMG_DEB, None, None, True, 100, 0)
    assert all(f["ignored"] and f["ignore_id"] == rule["id"] for f in shown["items"])
    assert service.delete_ignore(rule["id"]) is True and service.delete_ignore("ab") is False
    expiring = service.add_ignore({"package": "lodash", "reason": "dev only",
                                   "expires_at": int(clock.now) + 60}, 7)
    node = {i["image_id"]: i for i in service.images_view()["items"]}[IMG_NODE]
    assert node["counts"]["high"] == 0
    clock.now += 120
    node = {i["image_id"]: i for i in service.images_view()["items"]}[IMG_NODE]
    assert node["counts"]["high"] == 1
    assert next(r for r in service.ignore_rules() if r["id"] == expiring["id"])["expired"]

    # A new advisory appears in the feed: only it is notified (ignored ones are not).
    service.add_ignore({"advisory": "DEBIAN-CVE-2023-0007", "reason": "n/a"}, None)
    feed_server.feeds["Debian"].append(
        osv("DEBIAN-CVE-2023-0006", "Debian:12", "openssl", "3.0.12-1", vector=CRIT))
    feed_server.feeds["Debian"].append(
        osv("DEBIAN-CVE-2023-0007", "Debian:12", "zlib", "1:9.0-1", vector=CRIT))
    feed_server.version = 2
    clock.now += 2 * 3600
    run(service.run_scan("schedule"))
    assert [(e.type, e.details["advisories"]) for e in events.events] == [
        ("vuln.new_critical", ["DEBIAN-CVE-2023-0006"])
    ]
    first_seen = {f["id"]: f["first_seen"]
                  for f in service.findings_view(IMG_DEB, None, None, True, 100, 0)["items"]}
    assert first_seen["DEBIAN-CVE-2023-0001"] < first_seen["DEBIAN-CVE-2023-0006"]

    # An image that stops running disappears from results.
    agent.containers = [c for c in agent.containers if c["id"] != C3]
    run(service.run_scan("manual"))
    assert {i["image_id"] for i in service.images_view()["items"]} == {IMG_DEB}
    summary = service.summary_view()
    assert summary["images"] == 1 and summary["counts"]["critical"] == 2
    assert summary["images_by_status"]["critical"] == 1


def test_scan_feed_unavailable_and_agent_errors(tmp_path: Path, feed_server: FeedServer) -> None:
    agent = FakeAgent()
    service, events, _clock = make_service(tmp_path, agent)
    feed_server.status["Debian"] = 500
    run(service.run_scan())
    deb = {i["image_id"]: i for i in service.images_view()["items"]}[IMG_DEB]
    assert deb["status"] == "error"
    assert {"code": "http_500", "feed": "Debian"} in deb["errors"]
    feeds = {f["ecosystem"]: f for f in service.feeds_view()["items"]}
    assert feeds["Debian"]["needed"] and feeds["Debian"]["status"] == "error"
    assert feeds["npm"]["records"] == 1

    async def broken(_path):
        raise AgentError("agent_unreachable", 502, "down")

    agent.call = broken  # type: ignore[method-assign]
    result = run(service.run_scan())
    assert result == {"ok": False, "error_code": "agent_unreachable"}
    assert service.next_run_at() == service.state["last_attempt_at"] + vuln.RETRY_SECONDS


# ----- API ----------------------------------------------------------------------------------


def role_client(owner: TestClient, headers: dict[str, str], role: str):
    created = owner.post(
        "/api/v1/users",
        headers=headers,
        json={"username": f"{role}1", "password": PASSWORD, "role": role},
    )
    assert created.status_code == 201, created.text
    client = TestClient(owner.app)
    login = client.post("/api/v1/auth/login", json={"username": f"{role}1", "password": PASSWORD})
    assert login.status_code == 200
    return client, {"X-CSRF-Token": str(login.json()["csrf_token"])}


def allowed(role: str, permission: str) -> bool:
    granted = ROLE_PERMISSIONS[role]
    return "*" in granted or permission in granted


def test_vuln_api_rbac_scan_settings_ignores(
    tmp_path: Path, monkeypatch, feed_server: FeedServer
) -> None:
    monkeypatch.delenv("MRK_AGENT_URL", raising=False)
    monkeypatch.delenv("MRK_AGENT_KEY_FILE", raising=False)
    app = create_app(Settings.for_test(tmp_path / "cp"))
    with TestClient(app) as owner:
        headers = {"X-CSRF-Token": str(login_owner(owner)["csrf_token"])}
        service = vuln.ACTIVE_SERVICE
        assert service is not None
        agent = FakeAgent()
        agent.configured = False
        service.agent = agent

        roles = {"owner": (owner, headers)}
        for role in ("admin", "operator", "developer", "viewer"):
            roles[role] = role_client(owner, headers, role)
        for role, (client, role_headers) in roles.items():
            can_read = allowed(role, "vuln:read")
            can_write = allowed(role, "vuln:write")
            for path in ("/api/v1/vuln/summary", "/api/v1/vuln/images",
                         "/api/v1/vuln/settings", "/api/v1/vuln/ignores",
                         "/api/v1/vuln/feeds"):
                assert client.get(path).status_code == (200 if can_read else 403), (role, path)
            put = client.put("/api/v1/vuln/settings", headers=role_headers,
                             json={"interval_hours": 12})
            assert put.status_code == (200 if can_write else 403), role
            scan = client.post("/api/v1/vuln/scan", headers=role_headers)
            assert scan.status_code == (409 if can_write else 403), role
            ignore = client.post("/api/v1/vuln/ignores", headers=role_headers,
                                 json={"advisory": f"CVE-{role}", "reason": "test"})
            assert ignore.status_code == (201 if can_write else 403), role
        assert TestClient(app).get("/api/v1/vuln/summary").status_code == 401
        assert owner.put("/api/v1/vuln/settings", json={}).status_code == 403  # no CSRF
        assert owner.post("/api/v1/vuln/scan").status_code == 403
        assert owner.post("/api/v1/vuln/ignores", json={}).status_code == 403

        bad = owner.put("/api/v1/vuln/settings", headers=headers, json={"interval_hours": 0})
        assert bad.status_code == 422 and bad.json()["error"]["code"] == "invalid_settings"
        assert owner.put("/api/v1/vuln/settings", headers=headers,
                         content=b"{nope").status_code == 422
        missing_proxy = owner.put("/api/v1/vuln/settings", headers=headers,
                                  json={"proxy_id": "abc123"})
        assert missing_proxy.json()["error"]["code"] == "proxy_not_found"
        bad_ignore = owner.post("/api/v1/vuln/ignores", headers=headers, json={"reason": "x"})
        assert bad_ignore.status_code == 422
        assert bad_ignore.json()["error"]["code"] == "invalid_ignore"
        ignores = owner.get("/api/v1/vuln/ignores").json()["items"]
        assert len(ignores) == 3  # owner, admin, operator
        assert owner.delete(f"/api/v1/vuln/ignores/{ignores[0]['id']}").status_code == 403
        viewer, viewer_headers = roles["viewer"]
        assert viewer.delete(f"/api/v1/vuln/ignores/{ignores[0]['id']}",
                             headers=viewer_headers).status_code == 403
        deleted = owner.delete(f"/api/v1/vuln/ignores/{ignores[0]['id']}", headers=headers)
        assert deleted.status_code == 200
        assert owner.delete("/api/v1/vuln/ignores/zz", headers=headers).status_code == 404
        assert owner.post("/api/v1/vuln/scan", headers=headers,
                          json={"refresh_inventory": "yes"}).status_code == 422

        agent.configured = True
        started = owner.post("/api/v1/vuln/scan", headers=headers,
                             json={"refresh_inventory": True})
        assert started.status_code == 202 and started.json()["running"] is True
        deadline = time.time() + 15
        view = owner.get("/api/v1/vuln/images").json()
        while (view["running"] or not view["items"]) and time.time() < deadline:
            time.sleep(0.05)
            view = owner.get("/api/v1/vuln/images").json()
        assert {item["image_id"] for item in view["items"]} == {IMG_DEB, IMG_NODE}
        response = owner.get(f"/api/v1/vuln/images/{IMG_DEB}/findings?severity=critical")
        assert response.status_code == 200
        body = response.json()
        assert body["total"] == 1 and body["items"][0]["id"] == "DEBIAN-CVE-2023-0001"
        assert set(body["items"][0]) >= {"id", "aliases", "package", "installed", "fixed",
                                         "severity", "summary", "ecosystem", "ignored"}
        assert owner.get(f"/api/v1/vuln/images/{IMG_DEB}/findings?severity=bad").status_code == 422
        assert owner.get("/api/v1/vuln/images/sha256:" + "f" * 64 + "/findings").status_code == 404
        summary = owner.get("/api/v1/vuln/summary").json()
        assert summary["counts"]["critical"] == 1 and summary["agent_configured"] is True
        feeds = owner.get("/api/v1/vuln/feeds").json()
        assert {f["ecosystem"] for f in feeds["items"]} == {"Debian", "npm"}
        assert all(f["records"] > 0 for f in feeds["items"])

        services = owner.get("/api/v1/settings/outbound-services").json()["items"]
        assert any(e["kind"] == "vuln_feed" and e["id"] == "osv" for e in services)
        direct = owner.put("/api/v1/settings/outbound-services/vuln_feed/osv",
                           headers=headers, json={"proxy_id": None})
        assert direct.status_code == 200, direct.text
        assert viewer.put("/api/v1/settings/outbound-services/vuln_feed/osv",
                          headers=viewer_headers, json={"proxy_id": None}).status_code == 403
