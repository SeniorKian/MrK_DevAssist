"""SSH port detection (listener banners, sshd_config, ssh.socket), temporary port rules
and the quick firewall actions (parser, placement, preview/apply/undo API)."""

from __future__ import annotations

import socket
import threading
import time
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient
from mrk_control_plane.firewall import importers, netinfo, sshdetect
from mrk_control_plane.firewall.app import FirewallConfig, create_firewall_app
from mrk_control_plane.firewall.nft import DesiredState, render_ruleset
from mrk_control_plane.firewall.ports import CHAIN_INPUT, PortPolicy
from mrk_control_plane.modules import firewall_client
from mrk_control_plane.modules.firewall_engine import FirewallError, parse_requester
from mrk_control_plane.modules.firewall_ports import (
    DEFAULT_PORT_SETTINGS,
    compile_policy,
    lockout_problems,
)
from mrk_control_plane.modules.firewall_ports_api import detected_ssh
from mrk_control_plane.modules.firewall_quick import (
    opens_only,
    parse_commands,
    plan_changes,
    validate_intent,
)
from mrk_control_plane.modules.firewall_quick_api import helper_supports_expiry

from .helpers import login_owner
from .test_firewall import KEY, FakeRunner, signed
from .test_firewall_api import ADMIN_IP, make_client, pair

ANY4 = "0.0.0.0"  # noqa: S104 - a parsed bind address, nothing binds to it

# ----- listener banner detection ------------------------------------------------------


class FakeServer:
    """A loopback TCP server that greets with ``banner`` (or stays silent)."""

    def __init__(self, banner: bytes | None) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self.banner = banner
        self.stop = False
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def serve(self) -> None:
        self.sock.settimeout(0.2)
        while not self.stop:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                continue
            if self.banner:
                try:
                    conn.sendall(self.banner)
                except OSError:
                    pass
            time.sleep(0.05)
            conn.close()

    def close(self) -> None:
        self.stop = True
        self.thread.join(1)
        self.sock.close()


def test_banner_probe_finds_sshd_among_real_listeners() -> None:
    servers = [FakeServer(b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13\r\n"),
               FakeServer(None),  # HTTP-like: waits for the client
               FakeServer(b"SSH-2.0-Go\r\n"),  # e.g. Gitea's built-in SSH in a container
               FakeServer(b"220 mail ESMTP\r\n")]
    try:
        targets = [(server.port, "127.0.0.1") for server in servers]
        started = time.monotonic()
        banners = sshdetect.read_banners(targets, timeout=0.6)
        assert time.monotonic() - started < 2.0  # one select loop for all of them
        found = sshdetect.classify(banners)
        assert found["ports"] == [servers[0].port]
        assert found["other"] == [{"port": servers[2].port, "software": "Go"}]
        assert servers[1].port not in banners
    finally:
        for server in servers:
            server.close()


def test_probe_targets_and_cache() -> None:
    listeners = [(22, ANY4), (22, "::"), (6022, "203.0.113.4"), (631, "127.0.0.1"),
                 (8080, "::")]
    assert sshdetect.probe_targets(listeners) == [
        (22, "127.0.0.1"), (6022, "203.0.113.4"), (8080, "::1")]
    calls: list[list[tuple[int, str]]] = []

    def reader(targets, _timeout):
        calls.append(targets)
        return {6022: "SSH-2.0-OpenSSH_9.6"}

    clock = {"t": 0.0}
    probe = sshdetect.ListenerProbe(reader, clock=lambda: clock["t"])
    assert probe.detect(listeners)["ports"] == [6022]
    clock["t"] = 100
    probe.detect(listeners)
    assert len(calls) == 1  # cached while the listeners stay the same
    probe.detect(listeners + [(2222, ANY4)])
    assert len(calls) == 2  # a new listener -> probe again
    clock["t"] = 1000
    probe.detect(listeners + [(2222, ANY4)])
    assert len(calls) == 3  # and at least every PROBE_MAX_AGE seconds
    assert probe.detect(None) == {"available": False, "ports": [], "other": [], "probed": 0}


def test_proc_net_tcp_listeners(tmp_path: Path) -> None:
    (tmp_path / "tcp").write_text(
        "  sl  local_address rem_address   st\n"
        "   0: 00000000:1786 00000000:0000 0A 0\n"   # 0.0.0.0:6022
        "   1: 0400710B:0050 00000000:0000 0A 0\n"   # 11.113.0.4:80
        "   2: 0100007F:0CEA 0200007F:9C40 01 0\n")  # established: ignored
    (tmp_path / "tcp6").write_text(
        "  sl  local_address\n"
        "   0: 00000000000000000000000000000000:1786 00000000000000000000000000000000:0000 "
        "0A 0\n")
    assert netinfo.tcp_listeners(tmp_path) == [(80, "11.113.0.4"), (6022, ANY4),
                                               (6022, "::")]
    assert netinfo.tcp_listeners(tmp_path / "missing") is None


# ----- sshd_config / ssh.socket / priority --------------------------------------------


def test_sshd_config_include_and_syntax(tmp_path: Path) -> None:
    ssh = tmp_path / "ssh"
    (ssh / "sshd_config.d").mkdir(parents=True)
    (ssh / "extra").mkdir()
    (ssh / "sshd_config").write_text(
        "Include /etc/ssh/sshd_config.d/*.conf\nInclude extra/port.conf\n"
        "Port\t2200\n#Port 1\nMatch User x\n  Port 3\n")
    (ssh / "sshd_config.d" / "10-port.conf").write_text("Port=6022\nPort 6022\n")
    (ssh / "extra" / "port.conf").write_text("ListenAddress [::]:7022\n")
    found = importers.read_sshd_config(tmp_path)
    assert found["readable"] is True and found["ports"] == [6022, 7022, 2200]
    (ssh / "sshd_config").write_text("PermitRootLogin no\n")
    assert importers.read_sshd_config(tmp_path)["ports"] == [22]  # sshd's default
    assert importers.read_sshd_config(tmp_path / "none")["readable"] is False


def test_ssh_socket_listen_streams(tmp_path: Path) -> None:
    assert importers.parse_listen_streams(
        "[Socket]\nListenStream=\nListenStream=0.0.0.0:6022\nListenStream=[::]:6022\n"
        "ListenStream=/run/x.sock\n") == [6022]
    assert importers.parse_listen_streams("[Unit]\nListenStream=1\n") is None
    assert importers.read_ssh_socket(tmp_path)["readable"] is False
    system = tmp_path / "systemd" / "system"
    (system / "ssh.socket.d").mkdir(parents=True)
    (system / "sockets.target.wants").mkdir()
    (system / "sockets.target.wants" / "ssh.socket").write_text("")
    (system / "ssh.socket.d" / "port.conf").write_text("[Socket]\nListenStream=\n"
                                                      "ListenStream=2222\n")
    unit = importers.read_ssh_socket(tmp_path)
    assert unit == {"readable": True, "enabled": True, "explicit": True, "ports": [2222]}
    # A drop-in that only adds keeps the stock 22.
    (system / "ssh.socket.d" / "port.conf").write_text("[Socket]\nListenStream=2222\n")
    assert importers.read_ssh_socket(tmp_path)["ports"] == [22, 2222]


def test_ssh_source_priority(tmp_path: Path) -> None:
    none = {"available": False, "ports": [], "other": [], "probed": 0}
    facts = sshdetect.ssh_facts(tmp_path, none)
    assert (facts["source"], facts["ports"], facts["detected"]) == ("assumed", [22], False)
    assert facts["mounts"] == {"ssh": False, "systemd": False}
    (tmp_path / "ssh").mkdir()
    (tmp_path / "ssh" / "sshd_config").write_text("Port 2200\n")
    assert sshdetect.ssh_facts(tmp_path, none)["source"] == "sshd_config"
    system = tmp_path / "systemd" / "system"
    (system / "ssh.socket.d").mkdir(parents=True)
    (system / "sockets.target.wants").mkdir()
    (system / "sockets.target.wants" / "ssh.socket").write_text("")
    (system / "ssh.socket.d" / "p.conf").write_text("[Socket]\nListenStream=\n"
                                                   "ListenStream=6022\n")
    facts = sshdetect.ssh_facts(tmp_path, none)
    assert (facts["source"], facts["ports"]) == ("ssh_socket", [6022])  # Port is ignored
    live = {"available": True, "ports": [7022], "other": [], "probed": 3}
    facts = sshdetect.ssh_facts(tmp_path, live)
    assert (facts["source"], facts["ports"]) == ("listener", [7022])
    assert facts["sources"]["sshd_config"]["ports"] == [2200]


def test_panel_reads_old_and_new_helper_ssh_facts() -> None:
    assert detected_ssh({"detected": True, "ports": [6022]})["source"] == "sshd_config"
    assert detected_ssh({"detected": False, "ports": [22]})["source"] == "assumed"
    assert detected_ssh(None)["ports"] == [22]
    new = detected_ssh({"detected": True, "ports": [6022], "source": "listener",
                        "sources": {"listener": {"available": True, "ports": [6022],
                                                 "other": [{"port": 2222, "software": "Go"}]}},
                        "mounts": {"ssh": False, "systemd": False}})
    assert new["source"] == "listener" and new["listener"]["other"][0]["port"] == 2222
    assert new["mounts"] == {"ssh": False, "systemd": False}


# ----- temporary rules ------------------------------------------------------------------


def _policy(rules: list[dict], **extra) -> PortPolicy:
    return PortPolicy.from_payload({"enabled": True, "rules": rules, **extra})


def test_expiring_rules_render_until_their_time_and_keep_the_key() -> None:
    policy = _policy([
        {"id": "tmp", "protocol": "tcp", "ports": ["8080"], "sources": None, "scope": "host",
         "expires_at": 2000},
        {"id": "keep", "protocol": "tcp", "ports": ["443"], "sources": None, "scope": "host"},
    ])
    state = DesiredState("dry_run", ports=policy)
    assert 'comment "tmp"' in render_ruleset(state, now=1000, dynamic=False)
    assert 'comment "tmp"' not in render_ruleset(state, now=2000, dynamic=False)
    assert policy.risk_key() == PortPolicy.from_payload(policy.to_payload()).risk_key()
    assert policy.effective_key(2500) == _policy([policy.rules[1].to_payload()]).risk_key()
    assert policy.next_expiry(0) == 2000 and policy.next_expiry(2000) is None
    # Permanent rules keep their old payload (no expires_at key): stored keys stay valid.
    assert "expires_at" not in policy.rules[1].to_payload()
    assert policy.verdict(CHAIN_INPUT, "tcp", 8080, None, now=1500) == "accept"


def test_helper_reloads_when_a_temporary_rule_expires(tmp_path: Path) -> None:
    runner = FakeRunner()
    clock = {"t": 1000.0}
    config = FirewallConfig(key=KEY, state_dir=tmp_path / "s", log_root=tmp_path / "l",
                            proc_net=tmp_path / "p", host_etc=tmp_path / "e",
                            clock=lambda: clock["t"], banner_reader=lambda *_: {})
    app = create_firewall_app(config, runner=runner)
    with TestClient(app) as client:
        helper = app.state.helper
        ports = {"enabled": True, "rules": [
            {"id": "tmp", "protocol": "tcp", "ports": ["8080"], "sources": None,
             "scope": "host", "expires_at": 1100}]}
        response = signed(client, "POST", "/v1/apply", {"mode": "dry_run", "ports": ports,
                                                        "rollback_seconds": 60})
        assert response.status_code == 200, response.text
        assert 'comment "tmp"' in runner.table
        assert helper.expire_rules(now=1050) is False
        assert helper.expire_rules(now=1100) is True
        assert 'comment "tmp"' not in runner.table
        assert helper.pending is not None  # still the same trial; nothing rolled back
        assert helper.expire_rules(now=1200) is False


def test_lockout_check_ignores_temporary_allows_and_requires_admin_ports() -> None:
    admin = parse_requester(ADMIN_IP)
    settings = dict(DEFAULT_PORT_SETTINGS)
    now = int(time.time())
    rules = [
        {"id": "me", "name": "me", "enabled": True, "priority": 10, "created_at": 1,
         "protocol": "tcp", "ports": ["6022"], "scope": "both", "action": "accept",
         "source": {"kind": "cidrs", "cidrs": [f"{ADMIN_IP}/32"]}, "log": False,
         "log_rate": 10, "expires_at": now + 3600},
        {"id": "close", "name": "close", "enabled": True, "priority": 20, "created_at": 1,
         "protocol": "tcp", "ports": ["6022", "22"], "scope": "both", "action": "drop",
         "source": {"kind": "public"}, "log": False, "log_rate": 10},
    ]
    policy, _ = compile_policy(rules, {}, settings, now=now)
    problems = lockout_problems(policy, probes=[admin], ssh_ports=[6022], panel_ports=[],
                                protected=set(), now=now)
    assert problems == [{"code": "lockout_ssh", "address": ADMIN_IP, "ports": [6022],
                         "later": True}]
    # Admin-confirmed ports must all stay open; detected ports need one of them.
    rules[0]["expires_at"] = None
    policy, _ = compile_policy(rules, {}, settings, now=now)
    assert lockout_problems(policy, probes=[admin], ssh_ports=[6022, 22], panel_ports=[],
                            protected=set(), now=now) == []
    assert lockout_problems(policy, probes=[admin], ssh_ports=[6022, 22], panel_ports=[],
                            protected=set(), ssh_require_all=True, now=now) == [
        {"code": "lockout_ssh", "address": ADMIN_IP, "ports": [22]}]


# ----- command parser -------------------------------------------------------------------

LISTS = [{"id": "l1", "name": "IR", "cidrs": ["5.0.0.0/8"]}]


def intents(text: str) -> list[dict]:
    result = parse_commands(text, LISTS)
    assert result.errors == [], result.errors
    return result.intents


def test_parser_english_commands() -> None:
    assert intents("open 8080") == [{
        "kind": "port", "action": "accept", "ports": "8080", "protocol": "tcp",
        "scope": "both", "source": {"kind": "public"}, "exclusive": False,
        "expires_in": None, "note": ""}]
    close, allow, block, geo, mine = intents(
        "close 3306/udp; allow 10.0.0.0/8 -> 5432\nblock 1.2.3.4; allow 443 from IR only;"
        " only me to 22 for 2h # admin")
    assert (close["action"], close["protocol"], close["ports"]) == ("drop", "udp", "3306")
    assert allow["source"] == {"kind": "cidrs", "cidrs": ["10.0.0.0/8"]}
    assert allow["exclusive"] is False and allow["ports"] == "5432"
    assert block == {"kind": "block", "cidr": "1.2.3.4/32", "expires_in": None, "note": ""}
    assert geo["source"] == {"kind": "list", "list_id": "l1"} and geo["exclusive"] is True
    assert mine["source"] == {"kind": "me"} and mine["expires_in"] == 7200
    assert mine["exclusive"] is True and mine["note"] == "admin"
    ranged = intents("open 8000-8100,9000 udp for 30m")[0]
    assert ranged["ports"] == "8000-8100,9000" and ranged["protocol"] == "udp"
    assert ranged["expires_in"] == 1800
    assert intents("deny 22 from 203.0.113.0/24")[0]["source"]["cidrs"] == ["203.0.113.0/24"]
    assert intents("open 80 443 tcp+udp")[0]["ports"] == "80,443"


def test_parser_persian_commands() -> None:
    first, second, third = intents("8080 را باز کن؛ ۳۳۰۶ را ببند\n1.2.3.4 را مسدود کن")
    assert first["action"] == "accept" and first["ports"] == "8080"
    assert second["action"] == "drop" and second["ports"] == "3306"
    assert third["kind"] == "block"
    only = intents("فقط از 10.0.0.0/8 به 5432 برای 1 روز")[0]
    assert only["exclusive"] is True and only["expires_in"] == 86400
    assert only["source"] == {"kind": "cidrs", "cidrs": ["10.0.0.0/8"]}


def test_parser_errors() -> None:
    result = parse_commands("dance 80; open; allow 80 from nowhere; open 80 for ever", LISTS)
    assert [item["error"] for item in result.errors] == [
        "unknown_verb", "need_ports", "unknown_list", "bad_duration"]
    with pytest.raises(FirewallError):
        parse_commands("x" * 5000, LISTS)


# ----- planning ---------------------------------------------------------------------------


def _row(rule_id: str, ports: list[str], action: str, *, priority: int,
         source: dict | None = None, protocol: str = "tcp") -> dict:
    return {"id": rule_id, "name": rule_id, "description": "", "protocol": protocol,
            "ports": ports, "source": source or {"kind": "public"}, "scope": "both",
            "action": action, "enabled": True, "priority": priority, "log": False,
            "log_rate": 10, "origin": "manual", "created_at": 1, "expires_at": None}


def _plan(rules: list[dict], text: str):
    me = parse_requester(ADMIN_IP)
    counter = iter(f"n{index}" for index in range(100))
    validated = [validate_intent(item, lists={"l1": LISTS[0]}, requester=me)
                 for item in parse_commands(text, LISTS).intents]
    return plan_changes(rules, validated, now=1000, new_id=lambda: next(counter))


def test_placement_first_match_wins_the_right_way() -> None:
    blocked = _row("blocked", ["22"], "drop", priority=10,
                   source={"kind": "cidrs", "cidrs": ["203.0.113.9/32"]})
    closed = _row("closed", ["5432"], "drop", priority=20)
    plan = _plan([blocked, closed], "open 22; allow 10.0.0.0/8 -> 5432")
    order = [rule["id"] for rule in plan.rules]
    # "open 22" stays behind the block of 203.0.113.9; the 10/8 allow beats "close 5432".
    assert order == ["blocked", "n0", "n1", "closed"]
    assert plan.priorities == {} and [r["priority"] for r in plan.rules] == [10, 15, 17, 20]

    # "Only" = the allow plus a public drop right behind it; the contradicting public
    # allow goes away.
    opened = _row("opened", ["5432"], "accept", priority=10)
    plan = _plan([opened], "only me to 5432")
    assert [r["id"] for r in plan.removed] == ["opened"]
    assert [(r["id"], r["action"], r["source"]["kind"]) for r in plan.rules] == [
        ("n0", "accept", "cidrs"), ("n1", "drop", "public")]
    assert plan.rules[0]["source"]["cidrs"] == [f"{ADMIN_IP}/32"]
    # With a broader public allow in place, the pair still goes in front of it.
    wide = _row("wide", ["5000-6000"], "accept", priority=10)
    plan = _plan([wide], "only me to 5432")
    assert [r["id"] for r in plan.rules] == ["n0", "n1", "wide"]

    plan = _plan([opened], "close 5432")
    assert [r["id"] for r in plan.removed] == ["opened"] and len(plan.created) == 1
    assert _plan([closed], "close 5432").empty  # already so
    assert _plan([closed], "close 5432").unchanged == [0]
    # No gap left between neighbours -> everything is renumbered in order.
    tight = [_row("a", ["80"], "drop", priority=10), _row("b", ["81"], "drop", priority=11)]
    plan = _plan(tight, "allow 10.0.0.0/8 -> 81")
    assert [r["id"] for r in plan.rules] == ["a", "n0", "b"]
    assert [r["priority"] for r in plan.rules] == [10, 20, 30]
    assert plan.priorities == {"b": 30}


def test_temporary_rules_need_a_new_helper() -> None:
    assert helper_supports_expiry("0.2.0") and helper_supports_expiry("1.0")
    assert not helper_supports_expiry("0.1.9") and not helper_supports_expiry(None)


def test_opens_only() -> None:
    base = _policy([{"id": "d", "protocol": "tcp", "ports": ["25"], "sources": None,
                     "scope": "both", "action": "drop"}])
    more = _policy([{"id": "a", "protocol": "tcp", "ports": ["80"], "sources": None,
                     "scope": "both"}, base.rules[0].to_payload()])
    assert opens_only(base, more, 0) is True
    assert opens_only(more, base, 0) is False
    assert opens_only(base, _policy([]), 0) is True  # removing a deny only opens
    assert opens_only(None, more, 0) is False  # the deny closes something
    assert opens_only(None, _policy([more.rules[0].to_payload()]), 0) is True
    assert opens_only(base, _policy([base.rules[0].to_payload()], input_policy="drop"),
                      0) is False


# ----- API ----------------------------------------------------------------------------------

TCP = ("  sl  local_address rem_address   st\n"
       "   0: 00000000:1786 00000000:0000 0A 0\n"    # 6022 (sshd, not 22!)
       "   1: 00000000:1F90 00000000:0000 0A 0\n"    # 8080
       "   2: 00000000:0CEA 00000000:0000 0A 0\n"    # 3306
       "   3: 00000000:0050 00000000:0000 0A 0\n")   # 80 (the panel in these tests)


@pytest.fixture
def quick_helper(tmp_path: Path, monkeypatch):
    runner = FakeRunner()
    proc = tmp_path / "fw" / "proc"
    proc.mkdir(parents=True)
    (proc / "tcp").write_text(TCP)
    (tmp_path / "fw" / "log").mkdir(parents=True)
    probes: list[list] = []

    def banners(targets, _timeout):
        probes.append(targets)
        return {6022: "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13"}

    config = FirewallConfig(key=KEY, state_dir=tmp_path / "fw" / "state",
                            log_root=tmp_path / "fw" / "log", proc_net=proc,
                            host_etc=tmp_path / "fw" / "etc", banner_reader=banners)
    app = create_firewall_app(config, runner=runner)
    state = {"runner": runner, "app": app, "probes": probes}

    class Transport(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            return await httpx.ASGITransport(app=state["app"]).handle_async_request(request)

    monkeypatch.setattr(firewall_client, "TRANSPORT_FACTORY", lambda _url: Transport())
    monkeypatch.delenv("MRK_FIREWALL_URL", raising=False)
    monkeypatch.delenv("MRK_FIREWALL_KEY_FILE", raising=False)
    return state


def test_quick_api_detects_ssh_previews_applies_and_undoes(tmp_path: Path,
                                                          quick_helper) -> None:
    runner: FakeRunner = quick_helper["runner"]
    helper = quick_helper["app"].state.helper
    client, _app = make_client(tmp_path)
    with client:
        headers = {"X-CSRF-Token": str(login_owner(client)["csrf_token"])}

        def quick(text: str, **extra):
            return client.post("/api/v1/firewall/ports/quick", headers=headers,
                               json={"text": text, **extra})

        assert client.get("/api/v1/firewall/ports/my-ip").json() == {
            "ip": ADMIN_IP, "network": f"{ADMIN_IP}/32", "version": 4}
        assert quick("open 8080", apply=True).json()["error"]["code"] == (
            "firewall_not_configured")
        pair(client, headers)

        # SSH really listens on 6022; the sshd_config mount is missing -> listener wins.
        status = client.get("/api/v1/firewall/ports/status").json()
        assert status["ssh"]["ports"] == [6022] and status["ssh"]["source"] == "listener"
        assert status["ssh"]["detected"]["mounts"]["ssh"] is False
        overview = client.get("/api/v1/firewall/ports/quick/overview").json()
        by_port = {item["port"]: item for item in overview["listening"]}
        assert by_port[6022]["owner"]["kind"] == "ssh" and by_port[80]["panel"] is True
        assert by_port[3306]["owner"]["name"] == "MySQL"
        assert all(item["exposure"] == "open" for item in overview["listening"])
        assert overview["requester"] == ADMIN_IP

        # Opening can't lock anyone out: applied and kept in one click.
        preview = quick("open 8080").json()
        assert preview["problems"] == [] and preview["opens_only"] is True
        assert preview["trial"] is False and len(preview["created"]) == 1
        assert any("8080" in line for line in preview["diff"])
        assert runner.table is None  # a preview writes nothing
        applied = quick("open 8080", apply=True)
        assert applied.status_code == 200, applied.text
        assert applied.json()["kept"] is True and applied.json()["pending"] is False
        assert helper.pending is None and 'tcp dport 8080 accept' in runner.table
        assert quick("open 8080").json()["empty"] is True  # already so

        # Closing the detected SSH port for the admin is refused (override = typed word).
        lockout = quick("close 6022").json()
        assert lockout["problems"][0]["code"] == "lockout_ssh"
        assert lockout["problems"][0]["ports"] == [6022] and lockout["overridable"] is True
        refused = quick("close 6022", apply=True)
        assert refused.status_code == 422 and refused.json()["error"]["code"] == "lockout_ssh"

        # Closing goes on trial; undo while on trial = back to the confirmed rules.
        closed = quick("close 3306", apply=True).json()
        assert closed["pending"] is True and closed["kept"] is False
        assert "tcp dport 3306 counter drop" in runner.table
        rules = client.get("/api/v1/firewall/ports/rules").json()["items"]
        assert any(rule["ports"] == ["3306"] and rule["origin"] == "quick" for rule in rules)
        undone = client.post("/api/v1/firewall/ports/quick/undo", headers=headers,
                             json={"change_id": closed["change_id"]})
        assert undone.status_code == 200, undone.text
        assert undone.json()["status"]["pending"] is None
        assert "3306" not in runner.table and "8080" in runner.table
        rules = client.get("/api/v1/firewall/ports/rules").json()["items"]
        assert [rule["ports"] for rule in rules] == [["8080"]]
        assert client.post("/api/v1/firewall/ports/quick/undo", headers=headers, json={
            "change_id": closed["change_id"]}).json()["error"]["code"] == "nothing_to_undo"

        # "Only me" for a while: two temporary rules, kept after a trial.
        mine = quick("only me to 5432 for 1h", apply=True).json()
        assert mine["pending"] is True
        rules = client.get("/api/v1/firewall/ports/rules").json()["items"]
        temporary = [rule for rule in rules if rule["expires_at"]]
        assert len(temporary) == 2 and all(r["expires_at"] > time.time() + 3000
                                           for r in temporary)
        assert client.post("/api/v1/firewall/ports/confirm", headers=headers,
                           json={}).json()["pending"] is None

        # Undo after it was kept: the draft goes back and is applied again.
        undo = client.post("/api/v1/firewall/ports/quick/undo", headers=headers,
                           json={"change_id": mine["change_id"]})
        assert undo.status_code == 200, undo.text
        assert "5432" not in runner.table

        # Blocking an address uses dynamic defense; undo unblocks.
        blocked = quick("block 203.0.113.9 for 1h", apply=True).json()
        blocks = client.get("/api/v1/firewall/blocks").json()["items"]
        assert [item["cidr"] for item in blocks] == ["203.0.113.9/32"]
        assert quick(f"block {ADMIN_IP}").json()["blocks"][0]["refused"] == "requester_ip"
        client.post("/api/v1/firewall/ports/quick/undo", headers=headers,
                    json={"change_id": blocked["change_id"]})
        assert client.get("/api/v1/firewall/blocks").json()["items"] == []

        # Intents from the shortcut forms, validation errors, history and audit.
        form = client.post("/api/v1/firewall/ports/quick", headers=headers, json={
            "intents": [{"kind": "port", "action": "accept", "ports": "9000-9001",
                         "protocol": "both", "source": {"kind": "me"}, "expires_in": 30}]})
        assert form.status_code == 200 and form.json()["errors"][0]["error"] == (
            "invalid_expiry")
        bad = quick("dance 80").json()
        assert bad["errors"][0]["error"] == "unknown_verb"
        assert quick("dance 80", apply=True).json()["error"]["code"] == "invalid_quick_action"
        history = client.get("/api/v1/firewall/ports/quick/history").json()["items"]
        assert [item["status"] for item in history][:4] == [
            "undone", "undone", "undone", "applied"]
        audit = [item["action"] for item in client.get("/api/v1/audit-events").json()["items"]]
        assert "firewall.ports.quick" in audit and "firewall.ports.quick_undo" in audit
        events = client.get("/api/v1/firewall/events?action=ports_quick").json()["items"]
        assert len(events) >= 4

        # The admin confirms the SSH port by hand; then each confirmed port must stay open.
        client.put("/api/v1/firewall/ports/settings", headers=headers,
                   json={"ssh_ports": [6022, 22]})
        status = client.get("/api/v1/firewall/ports/status").json()
        assert status["ssh"]["source"] == "admin" and status["ssh"]["ports"] == [22, 6022]
        problems = quick("close 22").json()["problems"]
        assert problems and problems[0]["code"] == "lockout_ssh" and problems[0]["ports"] == [22]
        assert len(quick_helper["probes"]) == 1  # the banner probe result is cached


def test_expired_quick_rules_leave_the_draft(tmp_path: Path, quick_helper) -> None:
    client, _app = make_client(tmp_path)
    with client:
        headers = {"X-CSRF-Token": str(login_owner(client)["csrf_token"])}
        pair(client, headers)
        applied = client.post("/api/v1/firewall/ports/quick", headers=headers, json={
            "text": "open 8080 for 2m", "apply": True})
        assert applied.status_code == 200 and applied.json()["kept"] is True
        from mrk_control_plane.modules import firewall

        service = firewall.ACTIVE_SERVICE
        assert service is not None
        removed = service.ports.cleanup_expired(int(time.time()) + 600)
        assert len(removed) == 1
        status = client.get("/api/v1/firewall/ports/status").json()
        assert status["draft"]["rules"] == 0
        events = client.get("/api/v1/firewall/events?action=ports_expire").json()["items"]
        assert len(events) == 1
