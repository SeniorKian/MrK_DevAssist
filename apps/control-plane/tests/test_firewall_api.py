"""Firewall module (control plane): engine, safety, API, RBAC/CSRF, dry-run vs enforce."""

from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path

import httpx
import pytest
from alembic.script import ScriptDirectory
from fastapi.testclient import TestClient
from mrk_control_plane.agent import signing
from mrk_control_plane.config import Settings
from mrk_control_plane.database import Database
from mrk_control_plane.firewall.addresses import parse_network
from mrk_control_plane.main import create_app
from mrk_control_plane.models import FirewallBlock
from mrk_control_plane.modules import firewall, firewall_client
from mrk_control_plane.modules.firewall_engine import (
    DEFAULT_SETTINGS,
    Detector,
    FirewallError,
    RuleSpec,
    load_settings,
    merge_settings,
    refusal,
    validate_rule,
)
from sqlalchemy import inspect, select

from .helpers import login_owner
from .test_firewall import KEY, FakeRunner, helper_app

KEY_TEXT = signing.encode_key(KEY)
ADMIN_IP = "198.51.100.20"
SSH_FAIL = "Nov  8 10:00:00 h sshd[1]: Failed password for root from {ip} port 22 ssh2\n"


# ----- pure engine -----------------------------------------------------------------


def test_detector_threshold_window_and_reset() -> None:
    rule = RuleSpec("r", "R", frozenset({"ssh_failed_password"}), 3, 60, 600)
    detector = Detector()

    def sig(ts: float, ip: str = "203.0.113.1", kind: str = "ssh_failed_password"):
        return {"kind": kind, "ip": ip, "ts": ts, "source": "sshd"}

    assert detector.observe([rule], [sig(0), sig(10), sig(100)], now=100) == []  # window
    assert detector.observe([rule], [sig(110, kind="http_404")], now=110) == []  # other kind
    hits = detector.observe([rule], [sig(110), sig(115), sig(120, ip="203.0.113.2")], now=120)
    assert [(h.ip, h.count) for h in hits] == [("203.0.113.1", 3)]
    # The window resets after a hit.
    assert detector.observe([rule], [sig(121), sig(122)], now=122) == []
    assert len(detector.observe([rule], [sig(123)], now=123)) == 1
    detector.prune(10_000, 60)
    assert detector.windows == {}


def test_settings_validation_and_rule_validation() -> None:
    settings = load_settings(None)
    assert settings == DEFAULT_SETTINGS and settings["mode"] == "dry_run"
    updated = merge_settings(settings, {"allowlist": ["192.0.2.9", {"cidr": "192.0.2.9"}],
                                        "sources": {"traefik": {"enabled": True}}})
    assert [e["cidr"] for e in updated["allowlist"]] == ["192.0.2.9/32"]
    assert updated["sources"]["traefik"]["path"] == "/host/log/traefik/access.log"
    bad = [
        {"mode": "on"}, {"unknown": 1}, {"max_blocks": 0}, {"allowlist": ["nope"]},
        {"allowlist": ["0.0.0.0/0"]}, {"sources": {"sshd": {"path": "/etc/shadow"}}},
        {"sources": {"sshd": {"path": "/host/log/../x"}}}, {"sources": {"mrk": {"path": "x"}}},
        {"default_ban_seconds": 10}, {"sensitive_paths": ["nope"]}, {"notify": "yes"},
        {"default_ban_seconds": 90000, "max_ban_seconds": 3600},
    ]
    for patch in bad:
        with pytest.raises(FirewallError):
            merge_settings(settings, patch)
    # Stored garbage falls back to defaults per key.
    assert load_settings({"mode": "bogus", "max_blocks": 5})["mode"] == "dry_run"
    assert validate_rule({"name": "x", "signal_kinds": ["http_404"], "threshold": 2,
                          "window_seconds": 60})["signal_kinds"] == ["http_404"]
    for rule in ({"name": "x"}, {"name": "x", "signal_kinds": ["nope"], "threshold": 1,
                                 "window_seconds": 60},
                 {"name": "", "signal_kinds": ["http_404"], "threshold": 1, "window_seconds": 60},
                 {"name": "x", "signal_kinds": ["http_404"], "threshold": 0,
                  "window_seconds": 60}):
        with pytest.raises(FirewallError):
            validate_rule(rule)


def test_refusal_order_and_allowlist_precedence() -> None:
    settings = merge_settings(load_settings(None), {"allowlist": ["192.0.2.0/24"]})
    requester = parse_network(ADMIN_IP).network_address

    def code(text: str, **kwargs):
        result = refusal(parse_network(text), settings=settings, **kwargs)
        return result[0] if result else None

    assert code("203.0.113.5") is None
    assert code("127.0.0.1") == "loopback"
    assert code("10.0.0.0/8") == "prefix_too_broad"
    assert code("10.1.2.3") == "private_range"
    assert code("172.17.0.1", local_addresses=["172.17.0.1"]) == "host_address"
    assert code("203.0.113.0/24", local_addresses=["203.0.113.4"]) == "host_address"
    assert code("198.51.100.0/24", requester=requester) == "requester_ip"
    assert code("192.0.2.7") == "allowlisted"
    # A wider block that only partly overlaps the allowlist is allowed: allow sets are
    # evaluated first in nft, so the allowlisted part keeps working.
    assert code("192.0.0.0/16") is None
    private_ok = merge_settings(settings, {"allow_private_blocks": True,
                                           "allowlist_private": False})
    assert refusal(parse_network("10.1.2.3"), settings=private_ok) is None


def test_migration_on_fresh_sqlite(tmp_path: Path) -> None:
    database = Database(tmp_path)
    database.initialize()
    tables = set(inspect(database.engine).get_table_names())
    assert {"firewall_rules", "firewall_blocks", "firewall_decisions"} <= tables
    script = ScriptDirectory(str(Path(firewall.__file__).parents[1] / "migrations"))
    assert len(script.get_heads()) == 1
    revision = script.get_revision("20261108_0009")
    assert revision is not None and revision.down_revision == "20261108_0008"
    assert script.get_revision("20261108_0008") is not None
    database.dispose()


# ----- API -------------------------------------------------------------------------


@pytest.fixture
def helper(tmp_path: Path, monkeypatch):
    runner = FakeRunner()
    state = {"online": True, "runner": runner, "app": helper_app(tmp_path / "fw", runner),
             "log": tmp_path / "fw" / "log" / "system" / "auth.log"}

    class Switchable(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            if not state["online"]:
                raise httpx.ConnectError("refused", request=request)
            return await httpx.ASGITransport(app=state["app"]).handle_async_request(request)

    monkeypatch.setattr(firewall_client, "TRANSPORT_FACTORY", lambda _url: Switchable())
    monkeypatch.delenv("MRK_FIREWALL_URL", raising=False)
    monkeypatch.delenv("MRK_FIREWALL_KEY_FILE", raising=False)
    return state


def make_client(tmp_path: Path) -> tuple[TestClient, object]:
    app = create_app(Settings.for_test(tmp_path / "cp"))
    return TestClient(app, client=(ADMIN_IP, 50000)), app


def pair(client: TestClient, headers: dict[str, str]) -> dict:
    response = client.put("/api/v1/firewall/config", headers=headers, json={"key": KEY_TEXT})
    assert response.status_code == 200, response.text
    return response.json()


def tick(client: TestClient) -> None:
    assert firewall.ACTIVE_SERVICE is not None
    client.portal.call(firewall.ACTIVE_SERVICE.tick)
    client.portal.call(asyncio.sleep, 0.01)  # let event handlers run


def test_pairing_status_and_rbac(tmp_path: Path, helper) -> None:
    client, _app = make_client(tmp_path)
    with client:
        assert client.get("/api/v1/firewall/status").status_code == 401
        csrf = str(login_owner(client)["csrf_token"])
        headers = {"X-CSRF-Token": csrf}
        status = client.get("/api/v1/firewall/status").json()
        assert status["configured"] is False and status["mode"] == "dry_run"
        assert client.post("/api/v1/firewall/test", headers=headers).status_code == 409
        assert client.put("/api/v1/firewall/config", json={"key": KEY_TEXT}).status_code == 403
        for url in ("ftp://x:1", "unix:relative.sock", "http://u:p@h:1", "http://h:1/p"):
            assert client.put("/api/v1/firewall/config", headers=headers,
                              json={"url": url, "key": KEY_TEXT}).status_code == 422, url
        assert client.put("/api/v1/firewall/config", headers=headers, json={}).json()[
            "error"]["code"] == "firewall_key_required"
        paired = pair(client, headers)
        assert paired["configured"] is True and paired["url"] == (
            "unix:/run/mrk-firewall/firewall.sock")
        assert paired["reachable"] is True and paired["helper"]["version"]
        assert paired["in_sync"] is True
        stored = (tmp_path / "cp" / "control-plane" / "firewall-helper.json").read_text()
        assert KEY_TEXT not in stored
        assert client.post("/api/v1/firewall/test", headers=headers).json()["ok"] is True
        helper["online"] = False
        offline = client.post("/api/v1/firewall/test", headers=headers).json()
        assert offline["ok"] is False and offline["error_code"] == "firewall_unreachable"
        helper["online"] = True
        # Wrong key on the helper side -> auth failure.
        from mrk_control_plane.firewall.app import FirewallConfig, create_firewall_app

        helper["app"] = create_firewall_app(
            FirewallConfig(key=b"\x07" * 32, state_dir=tmp_path / "other"), runner=FakeRunner())
        assert client.post("/api/v1/firewall/test", headers=headers).json()["error_code"] == (
            "firewall_auth_failed")

        for role in ("operator", "viewer"):
            created = client.post("/api/v1/users", headers=headers, json={
                "username": f"{role}1", "password": "a-long-member-password-123", "role": role})
            assert created.status_code == 201
        client.post("/api/v1/auth/logout", headers=headers)

        def login(name: str) -> dict[str, str]:
            body = client.post("/api/v1/auth/login", json={
                "username": name, "password": "a-long-member-password-123"}).json()
            return {"X-CSRF-Token": str(body["csrf_token"])}

        operator = login("operator1")
        assert client.get("/api/v1/firewall/status").status_code == 200
        assert client.get("/api/v1/firewall/blocks").status_code == 200
        assert client.post("/api/v1/firewall/blocks", headers=operator, json={
            "ip": "203.0.113.5", "reason": "x"}).status_code == 403
        assert client.put("/api/v1/firewall/settings", headers=operator,
                          json={"mode": "off"}).status_code == 403
        client.post("/api/v1/auth/logout", headers=operator)
        login("viewer1")
        for path in ("status", "settings", "blocks", "rules", "events", "preview"):
            assert client.get(f"/api/v1/firewall/{path}").status_code == 403, path
        client.post("/api/v1/auth/logout", headers=operator)

        headers = {"X-CSRF-Token": str(login_owner(client)["csrf_token"])}
        assert client.request("DELETE", "/api/v1/firewall/config", headers=headers,
                              json={"confirmation": "no"}).status_code == 422
        unpaired = client.request("DELETE", "/api/v1/firewall/config", headers=headers,
                                  json={"confirmation": "UNPAIR"})
        assert unpaired.status_code == 200 and unpaired.json()["configured"] is False
        actions = [item["action"] for item in client.get("/api/v1/audit-events").json()["items"]]
        assert "firewall.config.update" in actions and "firewall.unpair" in actions


def test_blocks_safety_modes_and_kill_switch(tmp_path: Path, helper) -> None:
    runner: FakeRunner = helper["runner"]
    client, _app = make_client(tmp_path)
    with client:
        headers = {"X-CSRF-Token": str(login_owner(client)["csrf_token"])}
        pair(client, headers)
        assert runner.table is None  # dry_run: nothing of ours installed

        def block(**body):
            return client.post("/api/v1/firewall/blocks", headers=headers, json=body)

        assert client.post("/api/v1/firewall/blocks", json={"ip": "203.0.113.50",
                                                            "reason": "x"}).status_code == 403
        created = block(ip="203.0.113.50", reason="manual test")
        assert created.status_code == 201, created.text
        first = created.json()
        assert first["simulated"] is False and first["sync"]["applied"] is True
        assert first["expires_at"] - time.time() > 3500  # default ban: always expires
        assert runner.table is None  # still dry_run
        refusals = {
            ADMIN_IP: "requester_ip", "10.1.2.3": "private_range", "127.0.0.1": "loopback",
        }
        for ip, code in refusals.items():
            response = block(ip=ip, reason="x")
            assert response.status_code == 422 and response.json()["error"]["code"] == code
        assert block(cidr="8.0.0.0/8", reason="x").json()["error"]["code"] == "prefix_too_broad"
        assert block(ip="203.0.113.0/24", reason="x").status_code == 422
        assert block(ip="203.0.113.6", cidr="203.0.113.6", reason="x").status_code == 422
        assert block(ip="203.0.113.6", reason="").status_code == 422
        assert block(ip="203.0.113.6", reason="x", duration_seconds=5).status_code == 422
        assert block(ip="203.0.113.50", reason="again").status_code == 409

        allow = client.put("/api/v1/firewall/settings", headers=headers,
                           json={"allowlist": [{"cidr": "192.0.2.0/24", "note": "office"}]})
        assert allow.status_code == 200
        assert block(ip="192.0.2.5", reason="x").json()["error"]["code"] == "allowlisted"

        preview = client.get("/api/v1/firewall/preview").json()
        assert preview["mode"] == "dry_run"
        assert [b["cidr"] for b in preview["would_apply"]["blocks"]] == ["203.0.113.50/32"]
        assert "203.0.113.50" in preview["ruleset"] and "192.0.2.0/24" in preview["ruleset"]

        refused = client.put("/api/v1/firewall/settings", headers=headers,
                             json={"mode": "enforce"})
        assert refused.status_code == 422
        assert refused.json()["error"]["code"] == "confirmation_required"
        enforced = client.put("/api/v1/firewall/settings", headers=headers,
                              json={"mode": "enforce", "confirmation": "ENFORCE"})
        assert enforced.status_code == 200 and enforced.json()["sync"]["applied"] is True
        auto = [e for e in enforced.json()["allowlist"] if e["auto"]]
        assert [e["cidr"] for e in auto] == [f"{ADMIN_IP}/32"]  # requester auto-allowlisted
        assert runner.table is not None
        assert "203.0.113.50 timeout" in runner.table and ADMIN_IP in runner.table

        permanent = block(ip="203.0.113.51", reason="permanent", duration_seconds=None).json()
        assert permanent["expires_at"] is None and "\t\t\t203.0.113.51\n" in runner.table + "\n"
        assert len(client.get("/api/v1/firewall/blocks").json()["items"]) == 2
        removed = client.request("DELETE", f"/api/v1/firewall/blocks/{first['id']}",
                                 headers=headers, json={"reason": "false positive"})
        assert removed.status_code == 200 and "203.0.113.50" not in runner.table
        assert client.request("DELETE", f"/api/v1/firewall/blocks/{first['id']}",
                              headers=headers).status_code == 404

        assert client.post("/api/v1/firewall/blocks/clear", headers=headers,
                           json={"confirmation": "yes"}).status_code == 422
        cleared = client.post("/api/v1/firewall/blocks/clear", headers=headers,
                              json={"confirmation": "UNBLOCK ALL"}).json()
        assert cleared["removed"] == 1 and cleared["sync"]["applied"] is True
        assert "203.0.113.51" not in runner.table
        assert client.get("/api/v1/firewall/status").json()["counts"]["active_blocks"] == 0

        off = client.put("/api/v1/firewall/settings", headers=headers, json={"mode": "off"})
        assert off.status_code == 200 and runner.table is None  # disable = table deleted

        events = client.get("/api/v1/firewall/events").json()["items"]
        actions = {item["action"] for item in events}
        assert {"manual_block", "unblock", "clear", "mode"} <= actions
        assert client.get("/api/v1/firewall/events?action=bogus").status_code == 422
        only = client.get("/api/v1/firewall/events?action=mode&limit=1").json()
        assert len(only["items"]) == 1 and only["next_before_id"] is not None
        audit = [item["action"] for item in client.get("/api/v1/audit-events").json()["items"]]
        for action in ("firewall.block.create", "firewall.block.delete", "firewall.blocks.clear",
                       "firewall.mode.change", "firewall.settings.update"):
            assert action in audit
        assert KEY_TEXT not in json.dumps(audit)


def test_detection_dry_run_then_enforce(tmp_path: Path, helper) -> None:
    runner: FakeRunner = helper["runner"]
    log: Path = helper["log"]
    log.write_text("boot\n")
    client, app = make_client(tmp_path)
    events: list = []
    with client:
        async def collect(event) -> None:
            events.append(event)

        app.state.events.subscribe(collect)
        headers = {"X-CSRF-Token": str(login_owner(client)["csrf_token"])}
        pair(client, headers)
        tick(client)  # first poll: the tailer starts at the end of the file

        def attack(ip: str, count: int = 5) -> None:
            with log.open("a") as handle:
                handle.write(SSH_FAIL.format(ip=ip) * count)

        attack("203.0.113.9")
        tick(client)
        blocks = client.get("/api/v1/firewall/blocks").json()["items"]
        assert [(b["cidr"], b["simulated"], b["origin"]) for b in blocks] == [
            ("203.0.113.9/32", True, "auto")]
        assert runner.table is None
        preview = client.get("/api/v1/firewall/preview").json()
        assert preview["would_apply"]["blocks"] == []
        assert [b["cidr"] for b in preview["simulated"]] == ["203.0.113.9/32"]
        assert [e.type for e in events] == ["firewall.would_block"]

        client.put("/api/v1/firewall/settings", headers=headers,
                   json={"mode": "enforce", "confirmation": "ENFORCE"})
        attack("203.0.113.10")
        attack("10.0.0.5")  # private -> skipped, never blocked
        attack("203.0.113.12", 4)  # below threshold
        tick(client)
        assert "203.0.113.10" in runner.table and "203.0.113.9" not in runner.table
        assert "203.0.113.12" not in runner.table
        blocked = [e for e in events if e.type == "firewall.blocked"]
        assert len(blocked) == 1 and blocked[0].severity == "warning"
        assert blocked[0].dedupe_key == "firewall.blocked:203.0.113.10"
        skipped = client.get("/api/v1/firewall/events?action=skipped").json()["items"]
        assert [(s["ip"], s["reason"]) for s in skipped] == [("10.0.0.5", "private_range")]

        # MRK login failures are read from this control plane's audit log.
        store = app.state.auth_store
        for _ in range(10):
            store.record_audit(None, "auth.login", "session", None, "failure", "203.0.113.11")
        tick(client)
        assert "203.0.113.11" in runner.table
        rule_ids = {b["cidr"]: b["rule_id"] for b in
                    client.get("/api/v1/firewall/blocks").json()["items"]}
        assert rule_ids["203.0.113.11/32"] == "mrk-login"
        assert rule_ids["203.0.113.10/32"] == "ssh-bruteforce"

        # Expiry: the engine retires due blocks and the table follows.
        with app.state.database.session() as db, db.begin():
            row = db.scalar(select(FirewallBlock).where(FirewallBlock.cidr == "203.0.113.10/32"))
            row.expires_at = int(time.time()) - 1
        tick(client)
        assert "203.0.113.10" not in runner.table
        expired = client.get("/api/v1/firewall/events?action=expire").json()["items"]
        assert [e["ip"] for e in expired] == ["203.0.113.10/32"]

        # Helper lost its state (new volume): the next tick re-applies it.
        fresh = FakeRunner()
        helper["runner"] = fresh
        helper["app"] = helper_app(tmp_path / "fw2", fresh)
        tick(client)
        assert fresh.table is not None and "203.0.113.11" in fresh.table
        status = client.get("/api/v1/firewall/status").json()
        assert status["in_sync"] is True
        assert status["sources"]["sshd"]["error"] == "missing"  # new helper: no log yet


def test_rules_crud(tmp_path: Path, helper) -> None:
    client, _app = make_client(tmp_path)
    with client:
        headers = {"X-CSRF-Token": str(login_owner(client)["csrf_token"])}
        rules = client.get("/api/v1/firewall/rules").json()["items"]
        assert {r["id"] for r in rules} == {"ssh-bruteforce", "mrk-login", "http-auth",
                                            "http-404", "http-probe"}
        assert client.post("/api/v1/firewall/rules", json={}).status_code == 403
        body = {"name": "Scanner", "signal_kinds": ["http_404", "http_403"], "threshold": 50,
                "window_seconds": 30}
        assert client.post("/api/v1/firewall/rules", headers=headers,
                           json={**body, "signal_kinds": ["x"]}).status_code == 422
        created = client.post("/api/v1/firewall/rules", headers=headers, json=body)
        assert created.status_code == 201 and created.json()["ban_seconds"] == 3600
        assert client.post("/api/v1/firewall/rules", headers=headers,
                           json=body).status_code == 409
        rule_id = created.json()["id"]
        patched = client.patch(f"/api/v1/firewall/rules/{rule_id}", headers=headers,
                               json={"threshold": 20, "enabled": False})
        assert patched.json()["threshold"] == 20 and patched.json()["enabled"] is False
        assert client.patch("/api/v1/firewall/rules/nope", headers=headers,
                            json={"threshold": 2}).status_code == 404
        builtin = client.request("DELETE", "/api/v1/firewall/rules/ssh-bruteforce",
                                 headers=headers)
        assert builtin.status_code == 409 and builtin.json()["error"]["code"] == "builtin_rule"
        assert client.patch("/api/v1/firewall/rules/ssh-bruteforce", headers=headers,
                            json={"enabled": False}).json()["enabled"] is False
        assert client.request("DELETE", f"/api/v1/firewall/rules/{rule_id}",
                              headers=headers).json() == {"deleted": True, "id": rule_id}
