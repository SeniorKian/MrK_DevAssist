"""Regression tests for the backend audit fixes (2026-11-08, round 3)."""

from __future__ import annotations

import asyncio
import io
import json
import logging
import os
import socket
import struct
import threading
import time
from collections.abc import Callable
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient
from mrk_control_plane import netresolve, process_control, pypi_router
from mrk_control_plane.auth import AuthStore
from mrk_control_plane.config import Settings
from mrk_control_plane.logging_config import CorrelationIdFilter, JsonFormatter
from mrk_control_plane.main import _csv_cell, create_app
from mrk_control_plane.middleware import correlation_id_context
from mrk_control_plane.models import ApiToken, User
from mrk_control_plane.netresolve import (
    DnsConfig,
    _build_query,
    _parse_answer,
    clear_dns_cache,
    parse_server,
    resolve_custom,
    validate_config,
)
from mrk_control_plane.package_policy import QuarantineCache, valid_package_name
from mrk_control_plane.pypi_router import (
    RouterRuntime,
    RouterSettings,
    Upstream,
    _spool_verified_artifact,
    create_router_app,
)
from mrk_control_plane.secret_store import SecretStore
from mrk_control_plane.upstream_probe import reject_private_destination
from mrk_control_plane.upstream_store import UpstreamStore
from mrk_control_plane.verdaccio_runtime import build_runtime_config

from .helpers import login_owner

# --- DNS stub resolver (H1, L1) ----------------------------------------------


def _question(data: bytes) -> tuple[bytes, int, bytes]:
    end = data.index(b"\x00", 12) + 5
    qtype = struct.unpack("!H", data[end - 4 : end - 2])[0]
    return data[:2], qtype, data[12:end]


def _answer(query: bytes, rdata: bytes | None, flags: int = 0x8180) -> bytes:
    query_id, qtype, question = _question(query)
    header = query_id + struct.pack("!HHHHH", flags, 1, 1 if rdata else 0, 0, 0)
    body = b""
    if rdata:
        body = b"\xc0\x0c" + struct.pack("!HHIH", qtype, 1, 60, len(rdata)) + rdata
    return header + question + body


def _dns_server(handler: Callable[[bytes], bytes | None]) -> tuple[int, threading.Event, list]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    stop = threading.Event()
    seen: list[int] = []

    def serve() -> None:
        sock.settimeout(0.1)
        while not stop.is_set():
            try:
                data, peer = sock.recvfrom(512)
            except TimeoutError:
                continue
            seen.append(_question(data)[1])
            reply = handler(data)
            if reply is not None:
                sock.sendto(reply, peer)
        sock.close()

    threading.Thread(target=serve, daemon=True).start()
    return sock.getsockname()[1], stop, seen


def test_truncated_dns_record_raises_value_error_not_struct_error() -> None:
    query_id, packet = _build_query("example.com", 1)
    header = struct.pack("!HHHHHH", query_id, 0x8180, 1, 1, 0, 0)
    cut = header + packet[12:] + b"\xc0\x0c\x00\x01"  # answer cut mid-record
    with pytest.raises(ValueError):
        _parse_answer(cut, query_id, 1)
    dangling_pointer = header + packet[12:] + b"\xc0"
    with pytest.raises(ValueError):
        _parse_answer(dangling_pointer, query_id, 1)


def test_tc_bit_is_honoured_before_parsing_answers() -> None:
    query_id, packet = _build_query("example.com", 1)
    header = struct.pack("!HHHHHH", query_id, 0x8380, 1, 3, 0, 0)  # TC set, bogus ancount
    addresses, truncated, _ttl = _parse_answer(header + packet[12:], query_id, 1)
    assert addresses == [] and truncated is True


def test_malformed_reply_fails_over_to_next_server() -> None:
    clear_dns_cache()
    # The answer's rdata is cut short: this used to escape as struct.error.
    bad_port, bad_stop, _ = _dns_server(lambda q: _answer(q, b"\x01\x02\x03\x04")[:-2])
    good_port, good_stop, _ = _dns_server(
        lambda q: _answer(q, bytes([93, 184, 216, 34]) if _question(q)[1] == 1 else None)
    )
    try:
        config = validate_config(
            {
                "mode": "custom",
                "servers": [f"127.0.0.1:{bad_port}", f"127.0.0.1:{good_port}"],
                "timeout_seconds": 1,
            }
        )
        assert resolve_custom("failover.example", config) == ["93.184.216.34"]
    finally:
        bad_stop.set()
        good_stop.set()


def test_servfail_fails_over_without_waiting_for_timeout() -> None:
    clear_dns_cache()
    fail_port, fail_stop, _ = _dns_server(lambda q: _answer(q, None, flags=0x8182))
    good_port, good_stop, _ = _dns_server(
        lambda q: _answer(q, bytes([93, 184, 216, 35]) if _question(q)[1] == 1 else None)
    )
    try:
        config = validate_config(
            {
                "mode": "custom",
                "servers": [f"127.0.0.1:{fail_port}", f"127.0.0.1:{good_port}"],
                "timeout_seconds": 3,
            }
        )
        started = time.monotonic()
        assert resolve_custom("servfail.example", config) == ["93.184.216.35"]
        assert time.monotonic() - started < 2.5
    finally:
        fail_stop.set()
        good_stop.set()


def test_aaaa_is_skipped_when_ipv4_is_preferred_and_answers_are_cached() -> None:
    clear_dns_cache()
    port, stop, seen = _dns_server(
        lambda q: _answer(q, bytes([93, 184, 216, 36])) if _question(q)[1] == 1 else None
    )
    try:
        config = validate_config(
            {"mode": "custom", "servers": [f"127.0.0.1:{port}"], "timeout_seconds": 2}
        )
        started = time.monotonic()
        assert resolve_custom("cached.example", config) == ["93.184.216.36"]
        assert resolve_custom("cached.example", config) == ["93.184.216.36"]
        assert time.monotonic() - started < 1.5  # no AAAA timeout was paid
        assert seen == [1]  # one A query, no AAAA, second call served from cache
    finally:
        stop.set()
        clear_dns_cache()


def test_dns_settings_validation_is_strict() -> None:
    with pytest.raises(ValueError):
        parse_server("[2606:4700::1111]junk")
    with pytest.raises(ValueError):
        validate_config({"mode": "system", "prefer_ipv4": "false"})
    with pytest.raises(ValueError):
        netresolve._encode_name(".".join(["a" * 60] * 5))


# --- PyPI router (H2, L4, L5, M8, quarantine) --------------------------------


def test_cancelled_spool_removes_the_partial_file(tmp_path: Path) -> None:
    spool = tmp_path / "spool"

    async def slow_body():
        yield b"partial bytes"
        await asyncio.sleep(30)
        yield b"never"

    async def run() -> None:
        response = httpx.Response(
            200, content=slow_body(), request=httpx.Request("GET", "https://f.example/a.whl")
        )
        async with asyncio.timeout(0.3):
            await _spool_verified_artifact(response, httpx.AsyncClient(), None, 1024, spool)

    with pytest.raises(TimeoutError):
        asyncio.run(run())
    assert list(spool.glob("mrk-pypi-*")) == []


def _router_settings(tmp_path: Path, **overrides) -> RouterSettings:
    values = {
        "upstreams": (
            Upstream("primary", "https://pypi.example/simple/", frozenset({"pypi.example"})),
            Upstream("fallback", "https://fallback.example/simple/", frozenset({"fb.example"})),
        ),
        "offline_file": tmp_path / "offline",
    }
    values.update(overrides)
    return RouterSettings(**values)


def test_missing_artifact_credential_fails_over_instead_of_500(
    tmp_path: Path, monkeypatch
) -> None:
    def missing(_self, _upstream):
        raise KeyError("secret is gone")

    monkeypatch.setattr(RouterRuntime, "authorization_header", missing)
    app = create_router_app(_router_settings(tmp_path))
    with TestClient(app, raise_server_exceptions=False) as client:
        response = client.get("/files/demo/demo-1.0.tar.gz")
    assert response.status_code == 503
    runtime = app.state.runtime
    assert runtime.circuits["primary"].last_error == "credential_error"


def test_corrupt_upstream_config_keeps_last_good_view(tmp_path: Path) -> None:
    config = tmp_path / "upstreams.json"
    config.write_text(
        json.dumps(
            [
                {
                    "id": "a1",
                    "name": "only-private",
                    "ecosystem": "pypi",
                    "url": "https://private.example/simple/",
                    "priority": 1,
                    "enabled": True,
                }
            ]
        ),
        encoding="utf-8",
    )
    runtime = RouterRuntime(_router_settings(tmp_path, config_file=config))
    assert [item.name for item in runtime.upstreams()] == ["only-private"]
    config.write_text("{broken", encoding="utf-8")
    future = time.time() + 5
    os.utime(config, (future, future))
    assert [item.name for item in runtime.upstreams()] == ["only-private"]


def test_circuits_are_keyed_by_upstream_id(tmp_path: Path) -> None:
    runtime = RouterRuntime(_router_settings(tmp_path))
    hosts = frozenset({"a.example"})
    first = Upstream("same", "https://a.example/simple/", hosts, upstream_id="1")
    second = Upstream("same", "https://a.example/simple/", hosts, upstream_id="2")
    runtime.failure(first, "http_503")
    runtime.failure(first, "http_503")
    assert not runtime.available(first)
    assert runtime.available(second)


def test_router_returns_404_for_quarantined_pypi_project(tmp_path: Path, monkeypatch) -> None:
    policy = tmp_path / "control-plane" / "package-policies.json"
    policy.parent.mkdir(parents=True)
    policy.write_text(
        json.dumps({"pypi:evil_pkg": {"quarantined": True, "quarantine_reason": "malware"}}),
        encoding="utf-8",
    )

    async def must_not_fetch(*_args, **_kwargs):
        raise AssertionError("a quarantined project must not be fetched")

    monkeypatch.setattr(pypi_router, "_read_response", must_not_fetch)
    app = create_router_app(_router_settings(tmp_path, data_dir=tmp_path))
    with TestClient(app) as client:
        assert client.get("/simple/Evil.Pkg/").status_code == 404
        assert client.get("/files/evil-pkg/evil_pkg-1.0.tar.gz").status_code == 404


def test_quarantine_cache_keeps_last_good_on_broken_file(tmp_path: Path) -> None:
    policy = tmp_path / "control-plane" / "package-policies.json"
    policy.parent.mkdir(parents=True)
    policy.write_text(json.dumps({"pypi:bad": {"quarantined": True}}), encoding="utf-8")
    cache = QuarantineCache(tmp_path)
    assert cache.is_quarantined_pypi("BAD")
    policy.write_text("{half", encoding="utf-8")
    future = time.time() + 5
    os.utime(policy, (future, future))
    assert cache.is_quarantined_pypi("bad")


# --- Verdaccio runtime (M5, quarantine) ---------------------------------------


def _npm_store(tmp_path: Path) -> UpstreamStore:
    store = UpstreamStore(tmp_path)
    store.ensure_defaults(
        "https://pypi.org/simple/",
        "https://fallback.example/simple/",
        "https://registry.npmjs.org/",
        "https://npm-fallback.example/",
    )
    return store


def test_broken_npm_credential_skips_uplink_instead_of_crashing(tmp_path: Path) -> None:
    store = _npm_store(tmp_path)
    npm = [item for item in store.raw_list() if item["ecosystem"] == "npm"]
    store.update(
        str(npm[0]["id"]),
        {"credential_ref": "deadbeef" * 4, "credential_type": "bearer"},
    )
    config, _environment = build_runtime_config(tmp_path)
    text = config.read_text(encoding="utf-8")
    assert f"mrk_{npm[0]['id']}" not in text
    assert f"mrk_{npm[1]['id']}" in text


def test_quarantined_npm_names_are_denied_before_wildcards(tmp_path: Path) -> None:
    _npm_store(tmp_path)
    policy = tmp_path / "control-plane" / "package-policies.json"
    policy.write_text(
        json.dumps(
            {
                "npm:left-pad": {"quarantined": True},
                "npm:@evil/pkg": {"quarantined": True},
                "npm:bad\nname": {"quarantined": True},
                "npm:released": {"quarantined": False},
            }
        ),
        encoding="utf-8",
    )
    config, _environment = build_runtime_config(tmp_path)
    text = config.read_text(encoding="utf-8")
    assert text.index('"left-pad":') < text.index("'@*/*':")
    assert '"@evil/pkg":' in text
    assert "bad\nname" not in text and "released" not in text
    block = text[text.index('"left-pad":') : text.index("'@*/*':")]
    assert "mrk-quarantine-none" in block and "proxy" not in block


def test_package_name_validation() -> None:
    assert valid_package_name("npm", "@scope/name")
    assert valid_package_name("pypi", "Django_REST.framework")
    assert not valid_package_name("npm", "a" * 300)
    assert not valid_package_name("pypi", "../etc/passwd")


# --- process control (M6) -----------------------------------------------------


def test_reload_best_effort_never_raises(monkeypatch) -> None:
    def broken() -> bool:
        raise RuntimeError("supervisor said no")

    monkeypatch.setattr(process_control, "restart_verdaccio_if_managed", broken)
    assert process_control.reload_verdaccio_best_effort() is False


def test_failed_npm_reload_keeps_change_and_audit(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(
        "mrk_control_plane.main.reload_verdaccio_best_effort", lambda: False
    )
    with TestClient(create_app(Settings.for_test(tmp_path))) as client:
        csrf = str(login_owner(client)["csrf_token"])
        items = client.get("/api/v1/upstreams").json()["items"]
        npm = next(item for item in items if item["ecosystem"] == "npm")
        blocked = client.post(
            f"/api/v1/upstreams/{npm['id']}/block",
            headers={"X-CSRF-Token": csrf},
            json={"reason": "maintenance", "duration_seconds": 600},
        )
        assert blocked.status_code == 200
        actions = [item["action"] for item in client.get("/api/v1/audit-events").json()["items"]]
        assert "upstream.block" in actions and "npm.reload" in actions


# --- auth (M1, M2, M3, M4, L2, L3, csrf_failed) -------------------------------


def _token(client: TestClient, csrf: str, scopes: list[str]) -> str:
    created = client.post(
        "/api/v1/tokens",
        headers={"X-CSRF-Token": csrf},
        json={"name": "ci token", "scopes": scopes, "expires_in_seconds": 3600},
    )
    assert created.status_code == 201
    return str(created.json()["token"])


def test_api_token_cannot_mint_tokens(tmp_path: Path) -> None:
    with TestClient(create_app(Settings.for_test(tmp_path))) as client:
        csrf = str(login_owner(client)["csrf_token"])
        token = _token(client, csrf, ["token:write"])
        bearer = TestClient(client.app)
        minted = bearer.post(
            "/api/v1/tokens",
            headers={"Authorization": f"Bearer {token}"},
            json={"name": "escalated", "scopes": ["*"], "expires_in_seconds": 31536000},
        )
        assert minted.status_code == 403
        assert minted.json()["error"]["code"] == "forbidden"


def test_token_whose_scopes_left_the_role_does_not_authenticate(tmp_path: Path) -> None:
    store = AuthStore(tmp_path)
    user_id = store.create_user("dev-user", "a-long-password-123456", "developer", None)
    _id, token = store.create_api_token(user_id, "narrow", ["cache:read"], 3600)
    with store.db.session() as db, db.begin():
        db.get(User, user_id).role = "viewer"  # role change outside update_user
    assert store.principal_for_api_token(token) is not None  # cache:read still in viewer
    with store.db.session() as db, db.begin():
        db.get(ApiToken, _id).scopes = ["audit:read"]  # viewer no longer has it
    assert store.principal_for_api_token(token) is None


def test_password_check_holds_no_database_connection(tmp_path: Path, monkeypatch) -> None:
    store = AuthStore(tmp_path)
    store.create_user("plain-user", "a-long-password-123456", "viewer", None)
    seen: list[int] = []
    original = store._verify_password

    def spy(password_hash: str, password: str) -> bool:
        seen.append(store.db.engine.pool.checkedout())
        return original(password_hash, password)

    monkeypatch.setattr(store, "_verify_password", spy)
    assert store.authenticate("plain-user", "a-long-password-123456", "1.2.3.4", None)
    assert seen == [0]


def test_concurrent_attempt_recording_is_safe(tmp_path: Path) -> None:
    store = AuthStore(tmp_path, rate_limit_attempts=3, rate_limit_window_seconds=60)
    store._attempts = {f"k{i}": [0.0] for i in range(10050)}
    errors: list[BaseException] = []

    def worker(offset: int) -> None:
        try:
            for index in range(300):
                store._record_attempt(f"new-{offset}-{index}")
                store._rate_limited(f"new-{offset}-{index}")
        except BaseException as exc:  # pragma: no cover - the regression itself
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert errors == []
    for _ in range(3):
        store._record_attempt("limited")
    assert store._rate_limited("limited")


def test_audit_fields_are_clipped_to_column_sizes(tmp_path: Path) -> None:
    store = AuthStore(tmp_path)
    store.record_audit(None, "package.policy", "package", "x" * 400, "success", "1" * 80)
    item = store.list_audit(1)[0]
    assert len(str(item["object_id"])) == 255
    assert len(str(item["source_ip"])) == 64


def test_auth_me_with_bearer_token_and_csrf_error_codes(tmp_path: Path) -> None:
    with TestClient(create_app(Settings.for_test(tmp_path))) as client:
        csrf = str(login_owner(client)["csrf_token"])
        token = _token(client, csrf, ["system:read"])
        bearer = TestClient(client.app)
        me = bearer.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
        assert me.status_code == 200 and me.json()["csrf_token"] is None
        missing_csrf = client.patch("/api/v1/settings/registration", json={"enabled": False})
        assert missing_csrf.status_code == 403
        assert missing_csrf.json()["error"]["code"] == "csrf_failed"
        denied = bearer.get("/api/v1/users", headers={"Authorization": f"Bearer {token}"})
        assert denied.status_code == 403
        assert denied.json()["error"]["code"] == "forbidden"


def test_long_email_logins_pass_validation(tmp_path: Path) -> None:
    with TestClient(create_app(Settings.for_test(tmp_path))) as client:
        response = client.post(
            "/api/v1/auth/login",
            json={"username": ("a" * 80) + "@example.test", "password": "whatever"},
        )
        assert response.status_code == 401  # validated, then rejected as unknown


# --- upstream store and probe (M8, L6) ----------------------------------------


def test_rename_rejects_duplicates_and_blank_names(tmp_path: Path) -> None:
    store = _npm_store(tmp_path)
    pypi = [item for item in store.raw_list() if item["ecosystem"] == "pypi"]
    with pytest.raises(ValueError, match="already exists"):
        store.update(str(pypi[1]["id"]), {"name": str(pypi[0]["name"]).upper()})
    with pytest.raises(ValueError, match="between 2 and 80"):
        store.update(str(pypi[1]["id"]), {"name": "   "})
    renamed = store.update(str(pypi[1]["id"]), {"name": "  Mirror Two  "})
    assert renamed["name"] == "Mirror Two"


@pytest.mark.parametrize(
    "url",
    [
        "https://127.1/",
        "https://2130706433/",
        "https://localhost/",
        "https://registry.internal/",
        "https://intranet/",
    ],
)
def test_local_upstream_hosts_are_rejected(url: str) -> None:
    with pytest.raises(ValueError, match="private and local"):
        UpstreamStore.validate_url(url)


def test_npm_destination_resolving_privately_is_rejected(monkeypatch) -> None:
    monkeypatch.setattr(
        "mrk_control_plane.upstream_probe.resolve_host", lambda *_args: ["10.0.0.5"]
    )
    with pytest.raises(ValueError, match="private"):
        asyncio.run(reject_private_destination("https://npm.corp.example/", DnsConfig()))
    monkeypatch.setattr(
        "mrk_control_plane.upstream_probe.resolve_host",
        lambda *_args: (_ for _ in ()).throw(socket.gaierror("nope")),
    )
    asyncio.run(reject_private_destination("https://not-yet.example/", DnsConfig()))


# --- package policy endpoint (quarantine wiring) ------------------------------


def test_policy_endpoint_validates_names_and_triggers_enforcement(
    tmp_path: Path, monkeypatch
) -> None:
    reloads: list[bool] = []
    monkeypatch.setattr(
        "mrk_control_plane.main.reload_verdaccio_best_effort",
        lambda: reloads.append(True) or True,
    )
    cached = tmp_path / "pypi" / "server" / "+files" / "demo_pkg-1.0.tar.gz"
    cached.parent.mkdir(parents=True)
    cached.write_bytes(b"cached")
    with TestClient(create_app(Settings.for_test(tmp_path))) as client:
        csrf = {"X-CSRF-Token": str(login_owner(client)["csrf_token"])}
        bad = client.put(
            f"/api/v1/packages/npm/{'a' * 300}/policy",
            headers=csrf,
            json={"pinned": True},
        )
        assert bad.status_code == 409
        npm = client.put(
            "/api/v1/packages/npm/left-pad/policy",
            headers=csrf,
            json={"quarantined": True, "quarantine_reason": "compromised"},
        )
        assert npm.status_code == 200 and reloads == [True]
        pypi = client.put(
            "/api/v1/packages/pypi/demo_pkg/policy",
            headers=csrf,
            json={"quarantined": True, "quarantine_reason": "compromised"},
        )
        assert pypi.status_code == 200
        actions = [item["action"] for item in client.get("/api/v1/audit-events").json()["items"]]
        assert "package.quarantine.purge.enqueue" in actions


# --- logging, CSV, config (M7, L7, tunables) ----------------------------------


def test_json_logs_include_extras_and_correlation_id() -> None:
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(JsonFormatter())
    handler.addFilter(CorrelationIdFilter())
    logger = logging.getLogger("mrk-test-extras")
    logger.addHandler(handler)
    logger.propagate = False
    token = correlation_id_context.set("req-123")
    try:
        logger.warning(
            "PyPI upstream failed",
            extra={"upstream": "pypi.org", "code": "dns_error", "note": "token=secret123"},
        )
    finally:
        correlation_id_context.reset(token)
        logger.removeHandler(handler)
    event = json.loads(stream.getvalue())
    assert event["upstream"] == "pypi.org" and event["code"] == "dns_error"
    assert event["correlation_id"] == "req-123"
    assert "secret123" not in event["note"]


def test_csv_cells_guard_tab_and_carriage_return() -> None:
    assert _csv_cell("\t=cmd").startswith("'")
    assert _csv_cell("\r=cmd").startswith("'")
    assert _csv_cell("plain") == "plain"


def test_tunables_are_read_from_environment(monkeypatch) -> None:
    monkeypatch.setenv("MRK_LOGIN_RATE_LIMIT_ATTEMPTS", "9")
    monkeypatch.setenv("MRK_LOGIN_RATE_LIMIT_WINDOW_SECONDS", "120")
    monkeypatch.setenv("MRK_SESSION_PRUNE_AGE_SECONDS", "7200")
    monkeypatch.setenv("MRK_NPM_BLOCK_POLL_SECONDS", "15")
    settings = Settings.from_env()
    assert settings.login_rate_limit_attempts == 9
    assert settings.login_rate_limit_window_seconds == 120
    assert settings.session_prune_age_seconds == 7200
    assert settings.npm_block_poll_seconds == 15
    monkeypatch.setenv("MRK_NPM_BLOCK_POLL_SECONDS", "1")
    with pytest.raises(ValueError):
        Settings.from_env()


def test_secret_store_reference_is_unchanged_by_skip(tmp_path: Path) -> None:
    # Guard for the npm skip path: a valid bearer secret still produces its env var.
    store = _npm_store(tmp_path)
    npm = next(item for item in store.raw_list() if item["ecosystem"] == "npm")
    reference, _ = SecretStore(tmp_path).replace(None, {"token": "npm-token"})
    store.update(str(npm["id"]), {"credential_ref": reference, "credential_type": "bearer"})
    _config, environment = build_runtime_config(tmp_path)
    assert environment[f"MRK_NPM_UPLINK_TOKEN_{str(npm['id']).upper()}"] == "npm-token"


# --- allow_private_upstreams runtime setting ----------------------------------


def test_private_ranges_allowed_only_when_opted_in_and_never_loopback() -> None:
    from mrk_control_plane.netresolve import upstream_address_allowed

    for private in ("10.1.2.3", "172.20.0.9", "192.168.1.5", "100.64.0.7", "fd00::5"):
        assert not upstream_address_allowed(private)
        assert upstream_address_allowed(private, allow_private=True)
    unspecified = ".".join(["0"] * 4)
    forbidden_addresses = (
        "127.0.0.1", "169.254.169.254", "::1", "fe80::1", unspecified, "::ffff:127.0.0.1"
    )
    for forbidden in forbidden_addresses:
        assert not upstream_address_allowed(forbidden, allow_private=True)
    assert upstream_address_allowed("93.184.216.34")


def test_validate_url_honours_allow_private() -> None:
    for url in ("https://nexus.lan/", "https://nexus/", "https://10.0.0.5/", "https://172.16.1.1/"):
        with pytest.raises(ValueError):
            UpstreamStore.validate_url(url)
        assert UpstreamStore.validate_url(url, allow_private=True) == url
    for url in ("https://localhost/", "https://127.1/", "https://169.254.169.254/", "https://a.localhost/"):
        with pytest.raises(ValueError):
            UpstreamStore.validate_url(url, allow_private=True)


def test_reject_private_destination_honours_allow_private(monkeypatch) -> None:
    monkeypatch.setattr(
        "mrk_control_plane.upstream_probe.resolve_host", lambda *_args: ["10.0.0.5"]
    )
    asyncio.run(
        reject_private_destination("https://nexus.corp.example/", DnsConfig(), allow_private=True)
    )
    monkeypatch.setattr(
        "mrk_control_plane.upstream_probe.resolve_host", lambda *_args: ["169.254.169.254"]
    )
    with pytest.raises(ValueError):
        asyncio.run(
            reject_private_destination("https://meta.example/", DnsConfig(), allow_private=True)
        )


def test_router_destination_check_uses_the_runtime_setting(monkeypatch) -> None:
    monkeypatch.setattr(pypi_router, "resolve_host", lambda *_args: ["10.0.0.5"])
    hosts = frozenset({"nexus.lan"})
    with pytest.raises(pypi_router.DestinationRejected):
        asyncio.run(pypi_router._validate_destination("https://nexus.lan/simple/", hosts, False))
    assert asyncio.run(
        pypi_router._validate_destination(
            "https://nexus.lan/simple/", hosts, False, allow_private_ranges=True
        )
    ) == ["10.0.0.5"]
    monkeypatch.setattr(pypi_router, "resolve_host", lambda *_args: ["127.0.0.1"])
    with pytest.raises(pypi_router.DestinationRejected):
        asyncio.run(
            pypi_router._validate_destination(
                "https://nexus.lan/simple/", hosts, False, allow_private_ranges=True
            )
        )


def test_upstream_policy_api_round_trip_audit_and_create(tmp_path: Path) -> None:
    with TestClient(create_app(Settings.for_test(tmp_path))) as client:
        csrf = {"X-CSRF-Token": str(login_owner(client)["csrf_token"])}
        assert client.get("/api/v1/settings/network/upstream-policy").json() == {
            "allow_private_upstreams": False
        }
        body = {
            "name": "Internal",
            "ecosystem": "pypi",
            "url": "https://nexus.lan/simple/",
            "priority": 50,
        }
        assert client.post("/api/v1/upstreams", headers=csrf, json=body).status_code == 409
        no_csrf = client.put(
            "/api/v1/settings/network/upstream-policy", json={"allow_private_upstreams": True}
        )
        assert no_csrf.json()["error"]["code"] == "csrf_failed"
        enabled = client.put(
            "/api/v1/settings/network/upstream-policy",
            headers=csrf,
            json={"allow_private_upstreams": True},
        )
        assert enabled.json() == {"allow_private_upstreams": True}
        assert client.get("/api/v1/settings/network").json()["upstream_policy"] == {
            "allow_private_upstreams": True
        }
        assert client.post("/api/v1/upstreams", headers=csrf, json=body).status_code == 201
        events = client.get("/api/v1/audit-events").json()["items"]
        policy_events = [e for e in events if e["action"] == "settings.network.upstream_policy"]
        assert policy_events[0]["object_id"] == "allow_private_upstreams=true"
        stored = json.loads((tmp_path / "control-plane" / "network.json").read_text("utf-8"))
        assert stored["upstream_policy"] == {"allow_private_upstreams": True}
