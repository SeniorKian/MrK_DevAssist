"""Regression tests for the second round of review fixes (2026-11-08)."""

import asyncio
import json
import socket
import struct
import threading
import time
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient
from mrk_control_plane import pypi_router
from mrk_control_plane.auth import ROLE_PERMISSIONS, AuthStore
from mrk_control_plane.config import Settings
from mrk_control_plane.main import create_app
from mrk_control_plane.netresolve import (
    DnsConfig,
    NetworkSettingsStore,
    parse_server,
    resolve_host,
    validate_config,
)
from mrk_control_plane.pypi_router import (
    RouterRuntime,
    RouterSettings,
    Upstream,
    _fetch_page,
    _public_ip,
)
from mrk_control_plane.tasks import distribution_version, parse_prefetch_specs
from mrk_control_plane.upstream_store import UpstreamStore

from .helpers import login_owner


def _router(tmp_path: Path) -> RouterSettings:
    return RouterSettings(
        upstreams=(
            Upstream("primary", "https://pypi.example/simple/", frozenset({"pypi.example"})),
            Upstream(
                "fallback", "https://fallback.example/simple/", frozenset({"fallback.example"})
            ),
        ),
        offline_file=tmp_path / "offline",
    )


@pytest.mark.parametrize("status", [401, 403])
def test_auth_and_geo_block_errors_fail_over(tmp_path: Path, monkeypatch, status: int) -> None:
    runtime = RouterRuntime(_router(tmp_path))

    async def fake_read(_settings, url, *_args, **_kwargs):
        code = status if "pypi.example" in url else 200
        return httpx.Response(code, text="ok", request=httpx.Request("GET", url))

    monkeypatch.setattr(pypi_router, "_read_response", fake_read)
    upstream, response = asyncio.run(_fetch_page(runtime, "demo/"))
    assert upstream.name == "fallback"
    assert response.status_code == 200
    assert runtime.circuits["primary"].failures == 1


def test_not_found_does_not_fail_over(tmp_path: Path, monkeypatch) -> None:
    runtime = RouterRuntime(_router(tmp_path))

    async def fake_read(_settings, url, *_args, **_kwargs):
        return httpx.Response(404, text="missing", request=httpx.Request("GET", url))

    monkeypatch.setattr(pypi_router, "_read_response", fake_read)
    upstream, response = asyncio.run(_fetch_page(runtime, "demo/"))
    assert upstream.name == "primary"
    assert response.status_code == 404


def test_allowlist_rejection_does_not_open_circuit(tmp_path: Path, monkeypatch) -> None:
    runtime = RouterRuntime(_router(tmp_path))

    async def rejected(*_args, **_kwargs):
        raise pypi_router.DestinationRejected("outside allowlist")

    monkeypatch.setattr(pypi_router, "_read_response", rejected)
    assert asyncio.run(_fetch_page(runtime, "demo/")) is None
    assert all(state.failures == 0 for state in runtime.circuits.values())


def test_cgnat_space_is_not_public() -> None:
    assert not _public_ip("100.64.0.1")
    assert _public_ip("151.101.0.223")


def test_url_host_change_requires_removing_credential(tmp_path: Path) -> None:
    store = UpstreamStore(tmp_path)
    store.ensure_defaults("https://pypi.org/simple/", "https://package-mirror.liara.ir/repository/pypi/simple/")
    item = next(entry for entry in store.raw_list() if entry["name"] == "pypi.org")
    store.update(str(item["id"]), {"credential_ref": "ref", "credential_type": "bearer"})
    with pytest.raises(ValueError, match="credential"):
        store.update(str(item["id"]), {"url": "https://attacker.example/simple/"})
    # Same host, different path is fine.
    store.update(str(item["id"]), {"url": "https://pypi.org/simple/extra/"})


def test_deleted_defaults_are_not_recreated(tmp_path: Path) -> None:
    store = UpstreamStore(tmp_path)
    store.ensure_defaults("https://pypi.org/simple/", "https://package-mirror.liara.ir/repository/pypi/simple/")
    liara = next(entry for entry in store.raw_list() if entry["name"] == "Liara")
    items = [entry for entry in store.raw_list() if entry["id"] != liara["id"]]
    store._write(items)  # noqa: SLF001 - simulate an operator deletion
    store.ensure_defaults("https://pypi.org/simple/", "https://package-mirror.liara.ir/repository/pypi/simple/")
    assert all(entry["name"] != "Liara" for entry in store.raw_list())


def test_viewer_cannot_read_audit() -> None:
    assert "audit:read" not in ROLE_PERMISSIONS["viewer"]


def test_csrf_token_is_stable_across_reloads(tmp_path: Path) -> None:
    with TestClient(create_app(Settings.for_test(tmp_path))) as client:
        first = str(login_owner(client)["csrf_token"])
        second = client.get("/api/v1/auth/me").json()["csrf_token"]
        third = client.get("/api/v1/auth/me").json()["csrf_token"]
        assert first == second == third
        response = client.put(
            "/api/v1/settings/network/dns",
            headers={"X-CSRF-Token": first},
            json={"mode": "system", "servers": []},
        )
        assert response.status_code == 200


def test_attempt_buckets_are_bounded(tmp_path: Path) -> None:
    store = AuthStore(tmp_path)
    old = time.monotonic() - 1000
    store._attempts = {f"k{index}": [old] for index in range(10001)}  # noqa: SLF001
    store._rate_limited("fresh")  # noqa: SLF001
    assert len(store._attempts) < 10  # noqa: SLF001


def test_prune_removes_dead_sessions_and_old_audit(tmp_path: Path) -> None:
    store = AuthStore(tmp_path)
    store.record_audit(None, "test.event", "test", None)
    removed = store.prune(audit_retention_days=0)
    assert removed["sessions"] == 0
    assert store.prune(audit_retention_days=1)["audit_events"] == 0


def test_prefetch_rejects_injection_and_parses_lockfiles() -> None:
    lock = {
        "packages": {
            "": {"name": "app"},
            "node_modules/left-pad": {"version": "1.3.0"},
            "node_modules/a/node_modules/@scope/b": {"version": "2.0.0"},
            "node_modules/https://evil/x.tgz": {"version": "1.0.0"},
            "node_modules/git+ssh://evil": {"version": "1.0.0"},
            "node_modules/bad": {"version": "--registry=http://evil"},
        }
    }
    assert parse_prefetch_specs("npm", json.dumps(lock)) == [
        ("left-pad", "1.3.0"),
        ("@scope/b", "2.0.0"),
    ]
    requirements = "requests==2.32.3\n--pre\n.\n# comment\n-e git+https://x\nflask\n"
    assert parse_prefetch_specs("pypi", requirements) == [
        ("requests", "2.32.3"),
        ("flask", None),
    ]


def test_distribution_version_is_exact() -> None:
    assert distribution_version("demo-1.0-py3-none-any.whl", "demo") == "1.0"
    assert distribution_version("demo-1.0.1.tar.gz", "demo") == "1.0.1"
    assert distribution_version("Demo_Pkg-2.0.zip", "demo-pkg") == "2.0"
    assert distribution_version("other-1.0.tar.gz", "demo") is None


def test_revalidate_refused_in_offline_mode(tmp_path: Path) -> None:
    from mrk_control_plane.catalog import PackageCatalog
    from mrk_control_plane.tasks import TaskManager

    store = UpstreamStore(tmp_path)
    store.ensure_defaults("https://pypi.org/simple/", "https://package-mirror.liara.ir/repository/pypi/simple/")
    store.set_offline("npm", True)
    manager = TaskManager(tmp_path, PackageCatalog(tmp_path))
    with pytest.raises(ValueError, match="offline"):
        asyncio.run(
            manager._execute(  # noqa: SLF001
                "task", "package.revalidate", {"ecosystem": "npm", "name": "left-pad"}
            )
        )


# --- operator DNS settings ---------------------------------------------------


def test_dns_server_parsing_and_validation() -> None:
    assert parse_server("1.1.1.1").label() == "1.1.1.1"
    assert parse_server("9.9.9.9:5353").port == 5353
    assert parse_server("[2606:4700::1111]:53").address == "2606:4700::1111"
    with pytest.raises(ValueError):
        validate_config({"mode": "custom", "servers": []})
    with pytest.raises(ValueError):
        validate_config({"mode": "custom", "servers": ["not-an-ip"]})


def _fake_dns_server(answers: dict[int, bytes]) -> tuple[int, threading.Event]:
    """A tiny UDP DNS server answering A/AAAA for any name."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    stop = threading.Event()

    def serve() -> None:
        sock.settimeout(0.2)
        while not stop.is_set():
            try:
                data, peer = sock.recvfrom(512)
            except TimeoutError:
                continue
            query_id = data[:2]
            question_end = data.index(b"\x00", 12) + 5
            question = data[12:question_end]
            qtype = struct.unpack("!H", data[question_end - 4 : question_end - 2])[0]
            rdata = answers.get(qtype)
            header = query_id + struct.pack("!HHHHH", 0x8180, 1, 1 if rdata else 0, 0, 0)
            answer = b""
            if rdata:
                answer = b"\xc0\x0c" + struct.pack("!HHIH", qtype, 1, 60, len(rdata)) + rdata
            sock.sendto(header + question + answer, peer)
        sock.close()

    threading.Thread(target=serve, daemon=True).start()
    return sock.getsockname()[1], stop


def test_custom_dns_resolves_through_configured_server() -> None:
    port, stop = _fake_dns_server({1: bytes([93, 184, 216, 34])})
    try:
        config = validate_config({"mode": "custom", "servers": [f"127.0.0.1:{port}"]})
        assert resolve_host("pypi.example", 443, config) == ["93.184.216.34"]
    finally:
        stop.set()


def test_network_settings_round_trip_and_fallback(tmp_path: Path) -> None:
    store = NetworkSettingsStore(tmp_path)
    assert store.dns() == DnsConfig()
    store.save_dns(validate_config({"mode": "custom", "servers": ["1.1.1.1"]}))
    assert store.dns().mode == "custom"
    store.path.write_text("{broken", encoding="utf-8")
    time.sleep(0.01)
    assert NetworkSettingsStore(tmp_path).dns().mode == "system"


def test_router_uses_operator_dns_for_destination_checks(tmp_path: Path) -> None:
    port, stop = _fake_dns_server({1: bytes([10, 0, 0, 5])})
    try:
        config = validate_config({"mode": "custom", "servers": [f"127.0.0.1:{port}"]})
        with pytest.raises(pypi_router.DestinationRejected, match="non-public"):
            asyncio.run(
                pypi_router._validate_destination(  # noqa: SLF001
                    "https://pypi.example/simple/", frozenset({"pypi.example"}), False, config
                )
            )
    finally:
        stop.set()


def test_dns_settings_api(tmp_path: Path) -> None:
    port, stop = _fake_dns_server({1: bytes([93, 184, 216, 34])})
    try:
        with TestClient(create_app(Settings.for_test(tmp_path))) as client:
            csrf = str(login_owner(client)["csrf_token"])
            assert client.get("/api/v1/settings/network").json()["dns"]["mode"] == "system"
            bad = client.put(
                "/api/v1/settings/network/dns",
                headers={"X-CSRF-Token": csrf},
                json={"mode": "custom", "servers": []},
            )
            assert bad.status_code == 422
            tested = client.post(
                "/api/v1/settings/network/dns-test",
                headers={"X-CSRF-Token": csrf},
                json={
                    "hostname": "pypi.example",
                    "mode": "custom",
                    "servers": [f"127.0.0.1:{port}"],
                },
            )
            assert tested.json()["addresses"] == ["93.184.216.34"]
            saved = client.put(
                "/api/v1/settings/network/dns",
                headers={"X-CSRF-Token": csrf},
                json={"mode": "custom", "servers": [f"127.0.0.1:{port}"]},
            )
            assert saved.status_code == 200
            assert NetworkSettingsStore(tmp_path).dns().mode == "custom"
    finally:
        stop.set()
