from __future__ import annotations

import asyncio
import json
import socket
import threading
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient
from mrk_control_plane import outbound
from mrk_control_plane.config import Settings
from mrk_control_plane.main import create_app
from mrk_control_plane.modules import notifications_senders as senders
from mrk_control_plane.modules.notifications_engine import NotificationError
from mrk_control_plane.netresolve import DnsConfig, NetworkSettingsStore
from mrk_control_plane.outbound_api import ProxyService
from mrk_control_plane.pypi_router import RouterRuntime, RouterSettings, _fetch_page
from mrk_control_plane.secret_store import SecretStore
from mrk_control_plane.upstream_probe import probe_upstream
from mrk_control_plane.upstream_store import UpstreamStore
from mrk_control_plane.verdaccio_runtime import build_runtime_config

from .helpers import login_owner
from .test_notifications import BOT_TOKEN, make_center, message

PROXY_PASSWORD = "p@ss:w/rd-secret"  # noqa: S105 - test fixture
GLOBAL_IP = "93.184.215.14"


# --- helpers -------------------------------------------------------------------


def service(tmp_path: Path) -> ProxyService:
    return ProxyService(
        NetworkSettingsStore(tmp_path), SecretStore(tmp_path), outbound.OutboundRegistry()
    )


def make_proxy(tmp_path: Path, **overrides: Any) -> outbound.ProxyProfile:
    payload: dict[str, Any] = {
        "name": "tunnel",
        "type": "socks5h",
        "host": "127.0.0.1",
        "port": 1080,
        "username": "alice",
        "password": PROXY_PASSWORD,
    }
    payload.update(overrides)
    return service(tmp_path).create(payload)


class Captured:
    def __init__(self) -> None:
        self.proxies: list[str | None] = []
        self.requests: list[httpx.Request] = []


def capture_clients(
    monkeypatch: pytest.MonkeyPatch, status: int = 200, body: Any = None
) -> Captured:
    """Record the proxy URL of every outbound client and answer with a mock."""
    captured = Captured()

    def handler(request: httpx.Request) -> httpx.Response:
        captured.requests.append(request)
        return httpx.Response(status, json=body if body is not None else {"ok": True})

    def factory(proxy, timeout, transport=None):  # noqa: ANN001
        captured.proxies.append(proxy)
        return httpx.AsyncClient(
            transport=httpx.MockTransport(handler),
            timeout=timeout,
            follow_redirects=False,
            trust_env=False,
        )

    monkeypatch.setattr(outbound, "new_httpx_client", factory)
    return captured


def local_dns(monkeypatch: pytest.MonkeyPatch, answer: list[str] | Exception) -> list[str]:
    calls: list[str] = []

    def resolve(host: str, port: int, _config: object) -> list[str]:
        calls.append(host)
        if isinstance(answer, Exception):
            raise answer
        return list(answer)

    monkeypatch.setattr(outbound, "resolve_host", resolve)
    return calls


def csrf_headers(client: TestClient) -> dict[str, str]:
    return {"X-CSRF-Token": str(login_owner(client)["csrf_token"])}


# --- profiles & resolution -------------------------------------------------------


def test_profile_validation_and_secret_storage(tmp_path: Path) -> None:
    profile = make_proxy(tmp_path)
    raw = (tmp_path / "control-plane" / "network.json").read_text(encoding="utf-8")
    assert PROXY_PASSWORD not in raw
    assert profile.public()["secret_configured"] is True
    assert "secret_ref" not in profile.public() and "password" not in profile.public()

    svc = service(tmp_path)
    for payload, code in [
        ({"name": "x", "type": "ftp", "host": "a.example", "port": 1}, "invalid_proxy_type"),
        ({"name": "x", "type": "http", "host": "a.example", "port": 0}, "invalid_proxy_port"),
        (
            {"name": "x", "type": "http", "host": "169.254.169.254", "port": 80},
            "invalid_proxy_host",
        ),
        ({"name": "x", "type": "http", "host": "bad host", "port": 80}, "invalid_proxy_host"),
        (
            {"name": "x", "type": "http", "host": "a.example", "port": 80, "password": "p"},
            "proxy_password_without_username",
        ),
        (
            {"name": "TUNNEL", "type": "http", "host": "a.example", "port": 80},
            "proxy_name_taken",
        ),
        (
            {"name": "x", "type": "http", "host": "a.example", "port": 80, "no_proxy": ["a b"]},
            "invalid_no_proxy",
        ),
    ]:
        with pytest.raises(outbound.OutboundError) as caught:
            svc.create(payload)
        assert caught.value.code == code

    # Moving the host requires re-entering (or clearing) the stored password.
    with pytest.raises(outbound.OutboundError) as caught:
        svc.update(profile.id, {"host": "proxy.example.net"})
    assert caught.value.code == "proxy_credential_host_change"
    moved = svc.update(profile.id, {"host": "proxy.example.net", "password": ""})
    assert moved.secret_ref is None and moved.username == "alice"
    assert SecretStore(tmp_path)._read()["items"] == {}


def test_reference_resolution_never_falls_back_to_direct(tmp_path: Path) -> None:
    network = NetworkSettingsStore(tmp_path)
    assert outbound.resolve_profile(network, None) is None
    with pytest.raises(outbound.ProxyUnavailable):
        outbound.resolve_profile(network, "default")  # no default configured
    with pytest.raises(outbound.ProxyUnavailable):
        outbound.resolve_profile(network, "abc123")  # unknown id
    profile = make_proxy(tmp_path)
    service(tmp_path).set_default(profile.id)
    assert outbound.resolve_profile(network, "default") == profile
    service(tmp_path).update(profile.id, {"enabled": False})
    with pytest.raises(outbound.ProxyUnavailable) as caught:
        outbound.resolve_profile(network, "default")
    assert caught.value.code == "proxy_unavailable"


def test_route_url_encodes_credentials_and_hides_them_from_repr(tmp_path: Path) -> None:
    profile = make_proxy(tmp_path, username="al ice@corp", host="::1")
    route = outbound.build_route(profile, SecretStore(tmp_path))
    assert route.url == "socks5h://al%20ice%40corp:p%40ss%3Aw%2Frd-secret@[::1]:1080"
    assert route.redacted_url == "socks5h://[::1]:1080"
    assert PROXY_PASSWORD not in repr(route) and "p%40ss" not in repr(route)


def test_no_proxy_patterns() -> None:
    patterns = outbound.validate_no_proxy(["*.corp.example", "pypi.lan", "10.0.0.0/8"])
    assert patterns == (".corp.example", "pypi.lan", "10.0.0.0/8")
    assert outbound.no_proxy_matches(patterns, "a.corp.example")
    assert outbound.no_proxy_matches(patterns, "pypi.lan")
    assert outbound.no_proxy_matches(patterns, "mirror.pypi.lan")
    assert outbound.no_proxy_matches(patterns, "10.1.2.3")
    assert not outbound.no_proxy_matches(patterns, "corp.example.org")
    assert not outbound.no_proxy_matches(patterns, "api.telegram.org")


# --- outbound_client -------------------------------------------------------------


def test_outbound_client_direct_pins_vetted_address(tmp_path: Path, monkeypatch) -> None:
    local_dns(monkeypatch, [GLOBAL_IP])
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(204)

    async def run() -> int:
        async with outbound.outbound_client(
            NetworkSettingsStore(tmp_path),
            SecretStore(tmp_path),
            None,
            timeout=5,
            transport=httpx.MockTransport(handler),
        ) as client:
            response = await client.send("GET", "https://api.telegram.org/x")
            return response.status_code

    assert asyncio.run(run()) == 204
    assert seen[0].url.host == GLOBAL_IP
    assert seen[0].headers["host"] == "api.telegram.org"
    assert seen[0].extensions["sni_hostname"] == "api.telegram.org"


def test_outbound_client_proxy_url_and_no_pinning(tmp_path: Path, monkeypatch) -> None:
    profile = make_proxy(tmp_path, no_proxy=["internal.example"])
    captured = capture_clients(monkeypatch)
    calls = local_dns(monkeypatch, OSError("filtered"))  # local DNS is blocked

    async def run(url: str) -> None:
        async with outbound.outbound_client(
            NetworkSettingsStore(tmp_path), SecretStore(tmp_path), profile.id, timeout=5
        ) as client:
            await client.send("POST", url, content=b"{}")

    asyncio.run(run("https://api.telegram.org/bot1/sendMessage"))
    assert captured.proxies == ["socks5h://alice:p%40ss%3Aw%2Frd-secret@127.0.0.1:1080"]
    assert captured.requests[0].url.host == "api.telegram.org"  # the proxy resolves
    assert calls == ["api.telegram.org"]

    # no_proxy bypasses the proxy (direct, with the full direct policy).
    local_dns(monkeypatch, [GLOBAL_IP])
    asyncio.run(run("https://hooks.internal.example/x"))
    assert captured.proxies[-1] is None
    assert captured.requests[-1].url.host == GLOBAL_IP


def test_socks5_resolves_locally_and_pins(tmp_path: Path, monkeypatch) -> None:
    profile = make_proxy(tmp_path, type="socks5")
    captured = capture_clients(monkeypatch)
    local_dns(monkeypatch, [GLOBAL_IP])

    async def run() -> None:
        async with outbound.outbound_client(
            NetworkSettingsStore(tmp_path), SecretStore(tmp_path), profile.id, timeout=5
        ) as client:
            await client.send("GET", "https://api.telegram.org/")

    asyncio.run(run())
    assert captured.proxies[0] is not None and captured.proxies[0].startswith("socks5://")
    assert captured.requests[0].url.host == GLOBAL_IP
    assert captured.requests[0].headers["host"] == "api.telegram.org"

    local_dns(monkeypatch, OSError("filtered"))
    with pytest.raises(outbound.DnsFailed):
        asyncio.run(run())


def test_disabled_proxy_raises_before_any_connection(tmp_path: Path, monkeypatch) -> None:
    profile = make_proxy(tmp_path, enabled=False)
    captured = capture_clients(monkeypatch)

    async def run() -> None:
        async with outbound.outbound_client(
            NetworkSettingsStore(tmp_path), SecretStore(tmp_path), profile.id, timeout=5
        ) as client:
            await client.send("GET", "https://api.telegram.org/")

    with pytest.raises(outbound.ProxyUnavailable):
        asyncio.run(run())
    assert captured.proxies == []


@pytest.mark.parametrize(
    ("url", "answer", "allowed"),
    [
        ("https://127.0.0.1/", [GLOBAL_IP], False),
        ("https://2130706433/", [GLOBAL_IP], False),
        ("https://localhost/", [GLOBAL_IP], False),
        ("https://metadata/", [GLOBAL_IP], False),
        ("https://intranet.local/", [GLOBAL_IP], False),
        ("https://api.telegram.org/", ["127.0.0.1"], False),
        ("https://api.telegram.org/", ["169.254.169.254"], False),
        # Filtering resolvers answer blocked names with RFC1918 addresses.
        ("https://api.telegram.org/", ["10.10.34.36"], True),
        ("https://api.telegram.org/", OSError("no dns"), True),
        ("https://149.154.167.220/", OSError("no dns"), True),
    ],
)
def test_destination_policy_through_a_proxy(
    tmp_path: Path, monkeypatch, url: str, answer: Any, allowed: bool
) -> None:
    profile = make_proxy(tmp_path, type="http", username=None, password=None)
    captured = capture_clients(monkeypatch)
    local_dns(monkeypatch, answer)

    async def run() -> None:
        async with outbound.outbound_client(
            NetworkSettingsStore(tmp_path), SecretStore(tmp_path), profile.id, timeout=5
        ) as client:
            await client.send("GET", url)

    if allowed:
        asyncio.run(run())
        assert captured.requests
    else:
        with pytest.raises(outbound.DestinationRejected):
            asyncio.run(run())
        assert not captured.requests


# --- notifications -----------------------------------------------------------------


def test_telegram_and_webhook_senders_use_channel_proxy(tmp_path: Path, monkeypatch) -> None:
    profile = make_proxy(tmp_path, type="http", username="bob", password="pw")  # noqa: S106
    captured = capture_clients(monkeypatch, body={"ok": True, "result": {}})
    local_dns(monkeypatch, OSError("filtered"))
    network = NetworkSettingsStore(tmp_path)
    result = asyncio.run(
        senders.send(
            "telegram",
            {"chat_id": "-100123", "proxy_id": profile.id},
            {"bot_token": BOT_TOKEN},
            message(),
            network,
            secret_store=SecretStore(tmp_path),
        )
    )
    assert result.ok, result
    assert captured.proxies == ["http://bob:pw@127.0.0.1:1080"]
    assert captured.requests[0].url.host == "api.telegram.org"
    assert captured.requests[0].url.path == f"/bot{BOT_TOKEN}/sendMessage"

    service(tmp_path).set_default(profile.id)
    hook = asyncio.run(
        senders.send(
            "webhook",
            {"url": "https://hooks.example.com/x", "proxy_id": "default"},
            {},
            message(),
            network,
            secret_store=SecretStore(tmp_path),
        )
    )
    assert hook.ok and captured.requests[-1].url.host == "hooks.example.com"

    service(tmp_path).update(profile.id, {"enabled": False})
    blocked = asyncio.run(
        senders.send(
            "telegram",
            {"chat_id": "-100123", "proxy_id": profile.id},
            {"bot_token": BOT_TOKEN},
            message(),
            network,
            secret_store=SecretStore(tmp_path),
        )
    )
    assert not blocked.ok and blocked.error_code == "proxy_unavailable"
    assert len(captured.requests) == 2  # nothing was sent directly


def test_channel_proxy_validation(tmp_path: Path) -> None:
    center, _clock = make_center(tmp_path)
    http_proxy = make_proxy(tmp_path, name="web", type="http", username=None, password=None)
    socks = make_proxy(tmp_path, name="socks", type="socks5h")
    email = {
        "smtp_host": "smtp.example.com",
        "smtp_port": 587,
        "from_address": "mrk@example.com",
        "to_addresses": ["ops@example.com"],
    }
    with pytest.raises(NotificationError) as caught:
        center.create_channel(
            {"name": "mail", "kind": "email", "config": {**email, "proxy_id": http_proxy.id}}
        )
    assert caught.value.code == "proxy_type_unsupported_for_email"
    with pytest.raises(NotificationError) as caught:
        center.create_channel(
            {"name": "mail", "kind": "email", "config": {**email, "proxy_id": "nope"}}
        )
    assert caught.value.code == "proxy_not_found"
    channel = center.create_channel(
        {"name": "mail", "kind": "email", "config": {**email, "proxy_id": socks.id}}
    )
    assert channel["config"]["proxy_id"] == socks.id
    cleared = center.update_channel(channel["id"], {"config": {"proxy_id": None}})
    assert "proxy_id" not in cleared["config"]


def test_email_goes_through_socks_connector(tmp_path: Path, monkeypatch) -> None:
    profile = make_proxy(tmp_path, type="socks5h")
    local_dns(monkeypatch, OSError("filtered"))
    connects: list[tuple[str, int, str | None]] = []

    def fake_socks_connect(route, host, port, timeout, address=None):  # noqa: ANN001
        assert route.profile.id == profile.id and route.password == PROXY_PASSWORD
        connects.append((host, port, address))
        return object()

    class FakeSMTP:
        def __init__(self, connector, timeout, context=None) -> None:  # noqa: ANN001
            self.connector = connector

        def connect(self, host: str, port: int) -> None:
            self.connector(port, 5)

        def ehlo(self) -> None:
            pass

        def starttls(self, context=None) -> None:  # noqa: ANN001
            pass

        def login(self, username: str, password: str) -> None:
            pass

        def send_message(self, email: Any) -> None:
            pass

        def quit(self) -> None:
            pass

    monkeypatch.setattr(outbound, "socks_connect", fake_socks_connect)
    monkeypatch.setattr(senders, "SMTP_PROXY_FACTORY", {"plain": FakeSMTP, "ssl": FakeSMTP})
    config = {
        "smtp_host": "smtp.example.com",
        "smtp_port": 587,
        "security": "starttls",
        "from_address": "mrk@example.com",
        "to_addresses": ["ops@example.com"],
        "proxy_id": profile.id,
    }
    result = asyncio.run(
        senders.send(
            "email", config, {}, message(), NetworkSettingsStore(tmp_path),
            secret_store=SecretStore(tmp_path),
        )
    )
    assert result.ok, result
    assert connects == [("smtp.example.com", 587, None)]

    web = make_proxy(tmp_path, name="web", type="http", username=None, password=None)
    refused = asyncio.run(
        senders.send(
            "email", {**config, "proxy_id": web.id}, {}, message(),
            NetworkSettingsStore(tmp_path), secret_store=SecretStore(tmp_path),
        )
    )
    assert refused.error_code == "proxy_type_unsupported_for_email" and not refused.retryable


def test_socks_connect_handshake_with_credentials(tmp_path: Path) -> None:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    received: dict[str, bytes] = {}

    def serve() -> None:
        conn, _ = listener.accept()
        with conn:
            received["greeting"] = conn.recv(16)
            conn.sendall(b"\x05\x02")  # username/password
            received["auth"] = conn.recv(512)
            conn.sendall(b"\x01\x00")
            received["connect"] = conn.recv(512)
            conn.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x19")
            received["payload"] = conn.recv(16)

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    profile = make_proxy(tmp_path, port=port, username="alice")
    route = outbound.build_route(profile, SecretStore(tmp_path))
    sock = outbound.socks_connect(route, "smtp.example.com", 25, 5)
    sock.sendall(b"EHLO")
    thread.join(5)
    sock.close()
    listener.close()
    assert received["greeting"] == b"\x05\x01\x02"
    password = PROXY_PASSWORD.encode()
    assert received["auth"] == b"\x01\x05alice" + bytes([len(password)]) + password
    # socks5h: the name, not a locally resolved address, goes to the proxy.
    assert b"smtp.example.com" in received["connect"]
    assert received["payload"] == b"EHLO"


# --- PyPI router & probe --------------------------------------------------------------


def _router_runtime(tmp_path: Path, proxy_id: str) -> RouterRuntime:
    config_file = tmp_path / "control-plane" / "upstreams.json"
    config_file.write_text(
        json.dumps(
            [
                {
                    "id": "abc123",
                    "name": "private",
                    "ecosystem": "pypi",
                    "url": "https://pypi.example/simple/",
                    "priority": 10,
                    "enabled": True,
                    "proxy_id": proxy_id,
                }
            ]
        ),
        encoding="utf-8",
    )
    return RouterRuntime(
        RouterSettings(
            upstreams=(),
            offline_file=tmp_path / "offline",
            config_file=config_file,
            data_dir=tmp_path,
        )
    )


def test_pypi_router_requests_go_through_upstream_proxy(tmp_path: Path, monkeypatch) -> None:
    profile = make_proxy(tmp_path)
    captured = capture_clients(monkeypatch)
    local_dns(monkeypatch, OSError("filtered"))
    runtime = _router_runtime(tmp_path, profile.id)

    fetched = asyncio.run(_fetch_page(runtime, "requests/"))
    assert fetched is not None and fetched[1].status_code == 200
    assert captured.proxies == [outbound.build_route(profile, SecretStore(tmp_path)).url]
    assert str(captured.requests[0].url) == "https://pypi.example/simple/requests/"

    service(tmp_path).update(profile.id, {"enabled": False})
    assert asyncio.run(_fetch_page(runtime, "requests/")) is None
    upstream = runtime.upstreams()[0]
    assert runtime.circuit(upstream).last_error == "proxy_unavailable"
    assert len(captured.requests) == 1


def test_probe_reports_proxy_stages(tmp_path: Path, monkeypatch) -> None:
    captured = capture_clients(monkeypatch)
    local_dns(monkeypatch, OSError("filtered"))

    async def run() -> dict[str, object]:
        server = await asyncio.start_server(lambda _r, w: w.close(), "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        try:
            profile = make_proxy(tmp_path, type="https", port=port)
            route = outbound.build_route(profile, SecretStore(tmp_path))
            return await probe_upstream(
                "https://pypi.org/simple/", 5, None, dns=DnsConfig(), proxy=route
            )
        finally:
            server.close()
            await server.wait_closed()

    result = asyncio.run(run())
    assert result["ok"] is True, result
    assert [stage["name"] for stage in result["stages"]] == ["dns", "proxy", "http"]
    assert result["stages"][0]["detail"] == "resolved by the proxy"
    assert captured.proxies[0] is not None and captured.proxies[0].startswith("https://alice:")
    assert PROXY_PASSWORD not in json.dumps(result)


# --- Verdaccio ---------------------------------------------------------------------------


def test_verdaccio_uplink_https_proxy_and_socks_rejection(tmp_path: Path) -> None:
    upstreams = UpstreamStore(tmp_path)
    upstreams.ensure_defaults(
        "https://pypi.org/simple/", "https://package-mirror.liara.ir/repository/pypi/simple/"
    )
    npm = [item for item in upstreams.raw_list() if item["ecosystem"] == "npm"]
    web = make_proxy(
        tmp_path, name="web", type="http", host="10.0.0.5", port=3128,
        no_proxy=["*.corp.example", "10.0.0.0/8"],
    )
    socks = make_proxy(tmp_path, name="socks", type="socks5h")
    upstreams.update(str(npm[0]["id"]), {"proxy_id": web.id})
    upstreams.update(str(npm[1]["id"]), {"proxy_id": socks.id})

    config_path, _environment = build_runtime_config(tmp_path)
    config = config_path.read_text(encoding="utf-8")
    expected = "http://alice:p%40ss%3Aw%2Frd-secret@10.0.0.5:3128"
    assert f'    https_proxy: "{expected}"' in config
    assert '    no_proxy: ".corp.example"' in config
    assert f"mrk_{npm[0]['id']}:" in config
    # Verdaccio cannot use SOCKS: that uplink is skipped, never connected directly.
    assert f"mrk_{npm[1]['id']}" not in config

    service(tmp_path).update(web.id, {"enabled": False})
    config = build_runtime_config(tmp_path)[0].read_text(encoding="utf-8")
    assert "https_proxy" not in config and f"mrk_{npm[0]['id']}" not in config


# --- API ---------------------------------------------------------------------------------


def test_proxy_api_crud_in_use_guard_and_services(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr("mrk_control_plane.main.reload_verdaccio_best_effort", lambda: True)
    app = create_app(Settings.for_test(tmp_path))
    with TestClient(app) as client:
        headers = csrf_headers(client)
        assert client.post("/api/v1/settings/proxies", json={}).status_code == 403  # no CSRF

        created = client.post(
            "/api/v1/settings/proxies",
            headers=headers,
            json={
                "name": "Office",
                "type": "http",
                "host": "10.0.0.5",
                "port": 3128,
                "username": "alice",
                "password": PROXY_PASSWORD,
                "no_proxy": ["*.corp.example"],
            },
        )
        assert created.status_code == 201, created.text
        proxy = created.json()
        assert proxy["secret_configured"] is True and proxy["used_by"] == []
        assert PROXY_PASSWORD not in created.text and "secret_ref" not in proxy
        proxy_id = proxy["id"]

        duplicate = client.post(
            "/api/v1/settings/proxies",
            headers=headers,
            json={"name": "office", "type": "http", "host": "a.example", "port": 1},
        )
        assert duplicate.status_code == 409
        assert duplicate.json()["error"]["code"] == "proxy_name_taken"
        socks = client.post(
            "/api/v1/settings/proxies",
            headers=headers,
            json={"name": "Tunnel", "type": "socks5h", "host": "127.0.0.1", "port": 1080},
        ).json()

        upstream = client.post(
            "/api/v1/upstreams",
            headers=headers,
            json={
                "name": "Behind proxy",
                "ecosystem": "pypi",
                "url": "https://packages.example.com/simple/",
                "priority": 30,
                "proxy_id": proxy_id,
            },
        )
        assert upstream.status_code == 201, upstream.text
        assert upstream.json()["proxy_id"] == proxy_id
        upstream_id = upstream.json()["id"]

        npm_id = next(
            item["id"]
            for item in client.get("/api/v1/upstreams").json()["items"]
            if item["ecosystem"] == "npm"
        )
        refused = client.patch(
            f"/api/v1/upstreams/{npm_id}", headers=headers, json={"proxy_id": socks["id"]}
        )
        assert refused.status_code == 422
        assert refused.json()["error"]["code"] == "proxy_type_unsupported_for_npm"
        assert client.patch(
            f"/api/v1/upstreams/{npm_id}", headers=headers, json={"proxy_id": proxy_id}
        ).json()["proxy_id"] == proxy_id
        # An npm upstream uses it: switching the profile to SOCKS is refused.
        to_socks = client.patch(
            f"/api/v1/settings/proxies/{proxy_id}", headers=headers, json={"type": "socks5"}
        )
        assert to_socks.json()["error"]["code"] == "proxy_type_unsupported_for_npm"
        unknown = client.patch(
            f"/api/v1/upstreams/{npm_id}", headers=headers, json={"proxy_id": "default"}
        )
        assert unknown.json()["error"]["code"] == "no_default_proxy"

        listed = client.get("/api/v1/settings/proxies").json()
        office = next(item for item in listed["items"] if item["id"] == proxy_id)
        assert {(item["kind"], item["id"]) for item in office["used_by"]} == {
            ("upstream", upstream_id),
            ("upstream", npm_id),
        }

        mismatch = client.request(
            "DELETE", f"/api/v1/settings/proxies/{proxy_id}", headers=headers,
            json={"confirmation": "wrong"},
        )
        assert mismatch.json()["error"]["code"] == "confirmation_mismatch"
        in_use = client.request(
            "DELETE", f"/api/v1/settings/proxies/{proxy_id}", headers=headers,
            json={"confirmation": "Office"},
        )
        assert in_use.status_code == 409
        assert in_use.json()["error"]["code"] == "proxy_in_use"
        assert len(in_use.json()["error"]["used_by"]) == 2

        # Default proxy and the one-tick service table.
        assert client.put(
            "/api/v1/settings/proxies/default", headers=headers, json={"proxy_id": proxy_id}
        ).json() == {"default_proxy_id": proxy_id}
        services = client.get("/api/v1/settings/outbound-services").json()
        assert services["default_proxy_id"] == proxy_id
        entry = next(item for item in services["items"] if item["id"] == npm_id)
        assert entry["kind"] == "upstream" and entry["group"] == "npm"
        assert entry["supported_proxy_types"] == ["http", "https"]
        ticked = client.put(
            f"/api/v1/settings/outbound-services/upstream/{npm_id}",
            headers=headers,
            json={"proxy_id": "default"},
        )
        assert ticked.status_code == 200 and ticked.json()["proxy_id"] == "default"
        clear_default = client.put(
            "/api/v1/settings/proxies/default", headers=headers, json={"proxy_id": None}
        )
        assert clear_default.json()["error"]["code"] == "proxy_in_use"

        for target in (npm_id, upstream_id):
            assert client.put(
                f"/api/v1/settings/outbound-services/upstream/{target}",
                headers=headers,
                json={"proxy_id": None},
            ).json()["proxy_id"] is None
        assert client.request(
            "DELETE", f"/api/v1/settings/proxies/{proxy_id}", headers=headers,
            json={"confirmation": "Office"},
        ).json() == {"deleted": True, "id": proxy_id}
        assert client.get("/api/v1/settings/proxies").json()["default_proxy_id"] is None

        audit = client.get("/api/v1/audit-events").text
        assert "settings.proxy.create" in audit and "settings.proxy.delete" in audit
        assert PROXY_PASSWORD not in audit


def test_proxy_api_rbac_and_test_endpoint(tmp_path: Path, monkeypatch) -> None:
    app = create_app(Settings.for_test(tmp_path))
    with TestClient(app) as client:
        assert client.get("/api/v1/settings/proxies").status_code == 401
        owner = login_owner(client)
        headers = {"X-CSRF-Token": str(owner["csrf_token"])}
        proxy_id = client.post(
            "/api/v1/settings/proxies",
            headers=headers,
            json={"name": "Office", "type": "http", "host": "10.0.0.5", "port": 3128},
        ).json()["id"]
        token = client.post(
            "/api/v1/tokens",
            headers=headers,
            json={"name": "read-only", "scopes": ["upstream:read"], "expires_in_seconds": 3600},
        ).json()["token"]
        bearer = {"Authorization": f"Bearer {token}"}
        reader = TestClient(app)
        assert reader.get("/api/v1/settings/proxies", headers=bearer).status_code == 200
        assert reader.get("/api/v1/settings/outbound-services", headers=bearer).status_code == 200
        assert reader.post(
            "/api/v1/settings/proxies",
            headers=bearer,
            json={"name": "x", "type": "http", "host": "a.example", "port": 1},
        ).status_code == 403
        assert reader.post(
            f"/api/v1/settings/proxies/{proxy_id}/test", headers=bearer, json={}
        ).status_code == 403

        captured = capture_clients(monkeypatch, status=302)
        local_dns(monkeypatch, OSError("filtered"))
        tested = client.post(f"/api/v1/settings/proxies/{proxy_id}/test", headers=headers, json={})
        assert tested.status_code == 200
        assert tested.json()["ok"] is True and tested.json()["status_code"] == 302
        assert str(captured.requests[0].url) == "https://api.telegram.org"
        blocked = client.post(
            f"/api/v1/settings/proxies/{proxy_id}/test",
            headers=headers,
            json={"url": "http://169.254.169.254/latest/meta-data"},
        )
        assert blocked.json() == {
            "ok": False,
            "latency_ms": blocked.json()["latency_ms"],
            "error_code": "destination_not_allowed",
        }
        assert len(captured.requests) == 1
        assert client.post(
            "/api/v1/settings/proxies/missing/test", headers=headers, json={}
        ).status_code == 404
