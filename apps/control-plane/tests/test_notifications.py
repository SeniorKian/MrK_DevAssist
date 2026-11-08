from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import smtplib
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient
from mrk_control_plane.config import Settings
from mrk_control_plane.database import Database
from mrk_control_plane.main import create_app
from mrk_control_plane.module_context import Event
from mrk_control_plane.modules import notifications_senders as senders
from mrk_control_plane.modules.notifications_engine import (
    NotificationCenter,
    held_by_quiet_hours,
    quiet_until,
)
from mrk_control_plane.netresolve import NetworkSettingsStore
from mrk_control_plane.secret_store import SecretStore

from .helpers import login_owner

BOT_TOKEN = "123456789:AAH-super-secret-bot-token_xyz"  # noqa: S105 - test fixture
TELEGRAM_IP = "149.154.167.220"
PUBLIC_IP = "203.0.113.10"  # TEST-NET-3 is not "global"; patched resolver returns a global one
GLOBAL_IP = "93.184.215.14"


class Clock:
    def __init__(self, value: float) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value


def make_center(tmp_path: Path, start: float | None = None) -> tuple[NotificationCenter, Clock]:
    database = Database(tmp_path)
    database.initialize()  # runs every Alembic migration on a fresh SQLite file
    clock = Clock(start if start is not None else time.time())
    center = NotificationCenter(
        database, SecretStore(tmp_path), NetworkSettingsStore(tmp_path), clock=clock
    )
    return center, clock


def fake_resolver(monkeypatch: pytest.MonkeyPatch, address: str = GLOBAL_IP) -> list[str]:
    calls: list[str] = []

    def resolve(host: str, port: int, _config: object) -> list[str]:
        calls.append(f"{host}:{port}")
        return [address]

    monkeypatch.setattr(senders, "resolve_host", resolve)
    return calls


def message(**overrides: Any) -> senders.OutboundMessage:
    values: dict[str, Any] = {
        "event_type": "backup.failed",
        "severity": "error",
        "title": "پشتیبان‌گیری ناموفق بود",
        "message": "disk full",
        "module": "backup",
        "details": {"task_id": "t1"},
        "occurred_at": 1_700_000_000,
        "delivery_id": 7,
    }
    values.update(overrides)
    return senders.OutboundMessage(**values)


def telegram_channel(center: NotificationCenter, **config: Any) -> dict[str, Any]:
    default_rule = bool(config.pop("create_default_rule", False))
    return center.create_channel(
        {
            "name": config.pop("name", "ops telegram"),
            "kind": config.pop("kind", "telegram"),
            "config": {"chat_id": "-1001234567890", **config},
            "secret": {"bot_token": BOT_TOKEN},
            "create_default_rule": default_rule,
        }
    )


# --- senders -------------------------------------------------------------------


def test_telegram_sender_pins_vetted_address(tmp_path: Path, monkeypatch) -> None:
    calls = fake_resolver(monkeypatch, TELEGRAM_IP)
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"ok": True, "result": {}})

    result = asyncio.run(
        senders.send(
            "telegram",
            {"chat_id": "-100123"},
            {"bot_token": BOT_TOKEN},
            message(),
            NetworkSettingsStore(tmp_path),
            httpx.MockTransport(handler),
        )
    )
    assert result.ok and result.error_code is None
    assert calls == ["api.telegram.org:443"]
    request = seen[0]
    assert request.url.host == TELEGRAM_IP
    assert request.url.path == f"/bot{BOT_TOKEN}/sendMessage"
    assert request.headers["host"] == "api.telegram.org"
    assert request.extensions["sni_hostname"] == "api.telegram.org"
    body = json.loads(request.content.decode("utf-8"))
    assert body["chat_id"] == "-100123"
    assert body["text"].startswith("❌ پشتیبان‌گیری ناموفق بود")
    assert "ERROR · backup.failed · backup" in body["text"]


def test_bale_default_and_custom_base_url(tmp_path: Path, monkeypatch) -> None:
    calls = fake_resolver(monkeypatch)
    paths: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        paths.append(request.url.path)
        return httpx.Response(200, json={"ok": True})

    network = NetworkSettingsStore(tmp_path)
    transport = httpx.MockTransport(handler)
    asyncio.run(
        senders.send(
            "bale", {"chat_id": "42"}, {"bot_token": BOT_TOKEN}, message(), network, transport
        )
    )
    asyncio.run(
        senders.send(
            "telegram",
            {"chat_id": "42", "api_base_url": "https://tg-mirror.example.com/proxy"},
            {"bot_token": BOT_TOKEN},
            message(),
            network,
            transport,
        )
    )
    assert calls == ["tapi.bale.ai:443", "tg-mirror.example.com:443"]
    assert paths == [f"/bot{BOT_TOKEN}/sendMessage", f"/proxy/bot{BOT_TOKEN}/sendMessage"]


def test_bot_api_error_classification(tmp_path: Path, monkeypatch) -> None:
    fake_resolver(monkeypatch)
    network = NetworkSettingsStore(tmp_path)

    def run(response: httpx.Response) -> senders.SendResult:
        return asyncio.run(
            senders.send(
                "telegram",
                {"chat_id": "1"},
                {"bot_token": BOT_TOKEN},
                message(),
                network,
                httpx.MockTransport(lambda _request: response),
            )
        )

    unauthorized = run(httpx.Response(401, json={"ok": False}))
    assert (unauthorized.error_code, unauthorized.retryable) == ("http_401", False)
    limited = run(httpx.Response(429, json={"ok": False, "parameters": {"retry_after": 17}}))
    assert (limited.retryable, limited.retry_after) == (True, 17)
    server = run(httpx.Response(502))
    assert (server.error_code, server.retryable) == ("http_502", True)


def test_webhook_signature_and_static_headers(tmp_path: Path, monkeypatch) -> None:
    calls = fake_resolver(monkeypatch)
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(204)

    result = asyncio.run(
        senders.send(
            "webhook",
            {"url": "http://hooks.example.com/mrk?x=1", "headers": {"X-Team": "ops"}},
            {"signing_key": "s3cret-signing-key"},
            message(),
            NetworkSettingsStore(tmp_path),
            httpx.MockTransport(handler),
        )
    )
    assert result.ok
    assert calls == ["hooks.example.com:80"]
    request = seen[0]
    assert request.url.scheme == "http" and request.url.port in (None, 80)
    assert request.url.host == GLOBAL_IP and request.url.query == b"x=1"
    assert request.headers["host"] == "hooks.example.com"
    assert request.headers["x-team"] == "ops"
    expected = hmac.new(b"s3cret-signing-key", request.content, hashlib.sha256).hexdigest()
    assert request.headers["x-mrk-signature"] == f"sha256={expected}"
    payload = json.loads(request.content)
    assert payload["event"] == "backup.failed" and payload["delivery_id"] == 7
    assert payload["title"] == "پشتیبان‌گیری ناموفق بود"


def test_ssrf_destinations_rejected_unless_private_allowed(tmp_path: Path, monkeypatch) -> None:
    network = NetworkSettingsStore(tmp_path)
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200)

    def post(address: str) -> senders.SendResult:
        fake_resolver(monkeypatch, address)
        return asyncio.run(
            senders.send(
                "webhook",
                {"url": "https://hooks.example.com/"},
                {},
                message(),
                network,
                httpx.MockTransport(handler),
            )
        )

    for address in ("127.0.0.1", "169.254.169.254", "10.0.0.5", "::1"):
        result = post(address)
        assert (result.ok, result.error_code, result.retryable) == (
            False,
            "destination_not_allowed",
            False,
        )
    assert requests == []
    network.save_upstream_policy(True)
    assert post("10.0.0.5").ok
    assert post("127.0.0.1").error_code == "destination_not_allowed"
    assert len(requests) == 1


class FakeSMTP:
    instances: list[FakeSMTP] = []
    fail_login = False

    def __init__(self, address: str, timeout: float, context: object = None) -> None:
        self.address = address
        self.timeout = timeout
        self.tls = context is not None
        self.actions: list[str] = []
        self.sent: list[Any] = []
        FakeSMTP.instances.append(self)

    def connect(self, host: str, port: int) -> None:
        self.actions.append(f"connect {host}:{port}")

    def ehlo(self) -> None:
        self.actions.append("ehlo")

    def starttls(self, context: object) -> None:
        self.actions.append("starttls")

    def login(self, username: str, password: str) -> None:
        if FakeSMTP.fail_login:
            raise smtplib.SMTPAuthenticationError(535, b"bad credentials")
        self.actions.append(f"login {username}:{password}")

    def send_message(self, email: Any) -> None:
        self.sent.append(email)

    def quit(self) -> None:
        self.actions.append("quit")

    def close(self) -> None:
        pass


def test_email_sender_starttls_login_and_utf8(tmp_path: Path, monkeypatch) -> None:
    calls = fake_resolver(monkeypatch)
    FakeSMTP.instances.clear()
    FakeSMTP.fail_login = False
    monkeypatch.setattr(senders, "SMTP_FACTORY", {"plain": FakeSMTP, "ssl": FakeSMTP})
    config = {
        "smtp_host": "smtp.example.com",
        "smtp_port": 587,
        "security": "starttls",
        "username": "alerts",
        "from_address": "mrk@example.com",
        "to_addresses": ["ops@example.com", "oncall@example.com"],
    }
    result = asyncio.run(
        senders.send(
            "email", config, {"password": "smtp-pass"}, message(), NetworkSettingsStore(tmp_path)
        )
    )
    assert result.ok
    assert calls == ["smtp.example.com:587"]
    client = FakeSMTP.instances[0]
    assert client.address == GLOBAL_IP
    assert client.actions == [
        "connect smtp.example.com:587",
        "ehlo",
        "starttls",
        "ehlo",
        "login alerts:smtp-pass",
        "quit",
    ]
    email = client.sent[0]
    assert email["Subject"] == "❌ [MRK] پشتیبان‌گیری ناموفق بود"
    assert email["To"] == "ops@example.com, oncall@example.com"
    assert "disk full" in email.get_content()

    FakeSMTP.fail_login = True
    failed = asyncio.run(
        senders.send(
            "email", config, {"password": "smtp-pass"}, message(), NetworkSettingsStore(tmp_path)
        )
    )
    assert (failed.ok, failed.error_code, failed.retryable) == (False, "smtp_auth_failed", False)


def test_smtp_connects_to_pinned_address(monkeypatch) -> None:
    captured: list[tuple[Any, ...]] = []

    def fake_connect(address: tuple[str, int], timeout: float, source: object) -> object:
        captured.append(address)
        return object()

    monkeypatch.setattr(senders.socket, "create_connection", fake_connect)
    client = senders._PinnedSMTP("198.51.100.7", 5)
    client._get_socket("mail.example.com", 25, 5)
    assert captured == [("198.51.100.7", 25)]


def test_secrets_never_logged(tmp_path: Path, monkeypatch, caplog) -> None:
    fake_resolver(monkeypatch)
    senders.install_log_redaction()

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError(f"cannot reach {request.url}", request=request)

    caplog.set_level(logging.DEBUG)
    result = asyncio.run(
        senders.send(
            "telegram",
            {"chat_id": "1"},
            {"bot_token": BOT_TOKEN},
            message(),
            NetworkSettingsStore(tmp_path),
            httpx.MockTransport(handler),
        )
    )
    assert result.error_code == "connect_failed"
    logging.getLogger("httpx").info("HTTP Request: POST https://x/bot%s/sendMessage", BOT_TOKEN)
    assert BOT_TOKEN not in caplog.text
    assert "/bot<redacted>" in caplog.text


# --- routing, dedupe, quiet hours, retry -------------------------------------------


def test_rule_matching_by_pattern_and_severity(tmp_path: Path) -> None:
    center, _clock = make_center(tmp_path)
    backup = telegram_channel(center, name="backup")
    everything = telegram_channel(center, name="everything")
    center.create_rule(
        {"channel_id": backup["id"], "event_pattern": "backup.*", "min_severity": "warning"}
    )
    center.create_rule(
        {"channel_id": everything["id"], "event_pattern": "*", "min_severity": "error"}
    )
    center.create_rule(
        {"channel_id": everything["id"], "event_pattern": "agent.offline", "min_severity": "info"}
    )

    def routed(event_type: str, severity: str) -> list[str]:
        created = center.ingest(
            Event(type=event_type, severity=severity, title=f"{event_type}-{severity}")
        )
        return sorted(item["channel_name"] for item in created)

    assert routed("backup.failed", "error") == ["backup", "everything"]
    assert routed("backup.create.succeeded", "info") == []
    assert routed("backup.slow", "warning") == ["backup"]
    assert routed("agent.offline", "info") == ["everything"]
    assert routed("upstream.down", "critical") == ["everything"]
    # Two matching rules on one channel still create a single delivery.
    assert routed("agent.offline", "critical") == ["everything"]


def test_dedupe_window(tmp_path: Path) -> None:
    center, clock = make_center(tmp_path)
    channel = telegram_channel(center, create_default_rule=True)
    center.create_rule({"channel_id": channel["id"], "event_pattern": "*", "min_severity": "info"})
    event = Event(type="disk.low", severity="warning", title="Disk 91%")
    assert [item["status"] for item in center.ingest(event)] == ["pending"]
    assert [item["status"] for item in center.ingest(event)] == ["suppressed"]
    keyed = Event(type="disk.low", severity="warning", title="Disk 92%", dedupe_key="disk:/")
    assert center.ingest(keyed)[0]["status"] == "pending"
    assert (
        center.ingest(
            Event(type="disk.low", severity="warning", title="Disk 95%", dedupe_key="disk:/")
        )[0]["status"]
        == "suppressed"
    )
    clock.value += 301
    assert center.ingest(event)[0]["status"] == "pending"
    center.put_settings({"dedupe_window_seconds": 0}, None)
    assert center.ingest(event)[0]["status"] == "pending"


TEHRAN_QUIET = {
    "enabled": True,
    "start": "23:00",
    "end": "07:00",
    "timezone": "Asia/Tehran",
    "min_severity_during_quiet": "critical",
}


def ts(text: str) -> float:
    return datetime.fromisoformat(text).timestamp()


def test_quiet_hours_across_midnight_and_timezone() -> None:
    # Tehran is UTC+03:30. 23:30 local on Nov 8 = 20:00 UTC.
    late = ts("2026-11-08T20:00:00+00:00")
    assert quiet_until(late, TEHRAN_QUIET) == ts("2026-11-09T03:30:00+00:00")
    early = ts("2026-11-09T00:00:00+00:00")  # 03:30 local
    assert quiet_until(early, TEHRAN_QUIET) == ts("2026-11-09T03:30:00+00:00")
    assert quiet_until(ts("2026-11-09T03:30:00+00:00"), TEHRAN_QUIET) is None  # 07:00 local
    assert quiet_until(ts("2026-11-08T19:29:00+00:00"), TEHRAN_QUIET) is None  # 22:59 local
    assert quiet_until(late, {**TEHRAN_QUIET, "enabled": False}) is None
    day = {**TEHRAN_QUIET, "start": "09:00", "end": "17:00", "timezone": "UTC"}
    assert quiet_until(ts("2026-11-08T10:00:00+00:00"), day) == ts("2026-11-08T17:00:00+00:00")
    assert quiet_until(ts("2026-11-08T18:00:00+00:00"), day) is None
    assert held_by_quiet_hours(late, "critical", TEHRAN_QUIET) is None
    assert held_by_quiet_hours(late, "error", TEHRAN_QUIET) is not None


def test_quiet_hours_delay_until_end(tmp_path: Path, monkeypatch) -> None:
    sent: list[str] = []

    async def fake_send(kind, config, secret, outbound, network, transport=None):
        sent.append(outbound.title)
        return senders.SendResult(True, None, 3)

    monkeypatch.setattr(senders, "send", fake_send)
    late = ts("2026-11-08T20:00:00+00:00")
    center, clock = make_center(tmp_path, start=late)
    telegram_channel(center, create_default_rule=True)
    center.put_settings({"quiet_hours": TEHRAN_QUIET}, None)
    delayed = center.ingest(Event(type="backup.failed", severity="error", title="late"))[0]
    urgent = center.ingest(Event(type="host.down", severity="critical", title="urgent"))[0]
    assert delayed["status"] == "delayed"
    assert delayed["next_attempt_at"] == int(ts("2026-11-09T03:30:00+00:00"))
    assert urgent["status"] == "pending"
    asyncio.run(center.process_due())
    assert sent == ["urgent"]
    clock.value = ts("2026-11-09T03:30:05+00:00")
    asyncio.run(center.process_due())
    assert sent == ["urgent", "late"]
    statuses = {item["title"]: item["status"] for item in center.list_deliveries(10, None)}
    assert statuses == {"late": "sent", "urgent": "sent"}


def test_retry_backoff_then_failure(tmp_path: Path, monkeypatch) -> None:
    outcomes = [
        senders.SendResult(False, "http_502", 5, True),
        senders.SendResult(False, "http_429", 5, True, retry_after=90),
        senders.SendResult(False, "timeout", 5, True),
    ]

    async def fake_send(*_args, **_kwargs):
        return outcomes.pop(0)

    monkeypatch.setattr(senders, "send", fake_send)
    center, clock = make_center(tmp_path, start=1_800_000_000)
    channel = telegram_channel(center, create_default_rule=True)
    center.put_settings({"max_attempts": 3, "retry_base_seconds": 10}, None)
    center.ingest(Event(type="x.failed", severity="error", title="t"))

    asyncio.run(center.process_due())
    first = center.list_deliveries(1, None)[0]
    assert (first["status"], first["attempts"], first["error_code"]) == ("pending", 1, "http_502")
    assert 1_800_000_000 + 8 <= first["next_attempt_at"] <= 1_800_000_000 + 12
    assert asyncio.run(center.process_due()) == 0  # not due yet

    clock.value = first["next_attempt_at"]
    asyncio.run(center.process_due())
    second = center.list_deliveries(1, None)[0]
    assert second["attempts"] == 2 and second["next_attempt_at"] == int(clock.value) + 90

    clock.value = second["next_attempt_at"]
    asyncio.run(center.process_due())
    final = center.list_deliveries(1, None)[0]
    assert (final["status"], final["attempts"], final["error_code"]) == ("failed", 3, "timeout")
    assert center.get_channel(channel["id"])["last_status"] == "failed"


def test_non_retryable_failure_stops_immediately(tmp_path: Path, monkeypatch) -> None:
    async def fake_send(*_args, **_kwargs):
        return senders.SendResult(False, "destination_not_allowed", 1, False)

    monkeypatch.setattr(senders, "send", fake_send)
    center, _clock = make_center(tmp_path)
    telegram_channel(center, create_default_rule=True)
    center.ingest(Event(type="x", severity="error", title="t"))
    asyncio.run(center.process_due())
    item = center.list_deliveries(1, None)[0]
    assert (item["status"], item["attempts"]) == ("failed", 1)


def test_restart_resumes_pending_and_prunes(tmp_path: Path, monkeypatch) -> None:
    sent: list[int | None] = []

    async def fake_send(kind, config, secret, outbound, network, transport=None):
        assert secret == {"bot_token": BOT_TOKEN}
        sent.append(outbound.delivery_id)
        return senders.SendResult(True, None, 1)

    monkeypatch.setattr(senders, "send", fake_send)
    first, _clock = make_center(tmp_path)
    telegram_channel(first, create_default_rule=True)
    created = first.ingest(Event(type="x", severity="error", title="before restart"))
    first.db.dispose()

    second, clock = make_center(tmp_path)
    asyncio.run(second.process_due())
    assert sent == [created[0]["id"]]
    assert second.list_deliveries(5, "sent")[0]["sent_at"] is not None

    clock.value += 31 * 86400
    assert second.prune() == 1
    assert second.list_deliveries(5, None) == []


def test_dispatcher_lifecycle_sends_published_events(tmp_path: Path, monkeypatch) -> None:
    sent: list[str] = []

    async def fake_send(kind, config, secret, outbound, network, transport=None):
        sent.append(outbound.title)
        return senders.SendResult(True, None, 1)

    monkeypatch.setattr(senders, "send", fake_send)
    center, _clock = make_center(tmp_path)
    telegram_channel(center, create_default_rule=True)

    async def scenario() -> None:
        await center.start()
        await center.handle_event(Event(type="a.b", severity="warning", title="live"))
        for _ in range(100):
            if sent:
                break
            await asyncio.sleep(0.02)
        await center.stop()

    asyncio.run(scenario())
    assert sent == ["live"]


# --- API -----------------------------------------------------------------------------


def _create_user(client: TestClient, csrf: str, username: str, role: str) -> None:
    response = client.post(
        "/api/v1/users",
        headers={"X-CSRF-Token": csrf},
        json={"username": username, "password": f"{username}-password-12345", "role": role},
    )
    assert response.status_code == 201, response.text


def _login(client: TestClient, username: str) -> str:
    client.cookies.clear()
    response = client.post(
        "/api/v1/auth/login",
        json={"username": username, "password": f"{username}-password-12345"},
    )
    assert response.status_code == 200
    return str(response.json()["csrf_token"])


def test_api_crud_secrets_rbac_and_csrf(tmp_path: Path, monkeypatch) -> None:
    sent: list[tuple[str, str]] = []

    async def fake_send(kind, config, secret, outbound, network, transport=None):
        sent.append((kind, outbound.event_type))
        return senders.SendResult(True, None, 12)

    monkeypatch.setattr(senders, "send", fake_send)
    app = create_app(Settings.for_test(tmp_path))
    base = "/api/v1/notifications"
    with TestClient(app) as client:
        assert client.get(f"{base}/channels").status_code == 401
        csrf = str(login_owner(client)["csrf_token"])
        headers = {"X-CSRF-Token": csrf}
        body = {
            "name": "Ops Telegram",
            "kind": "telegram",
            "enabled": True,
            "config": {"chat_id": -1001234567890},
            "secret": {"bot_token": BOT_TOKEN},
            "create_default_rule": True,
        }
        assert client.post(f"{base}/channels", json=body).status_code == 403  # no CSRF
        created = client.post(f"{base}/channels", headers=headers, json=body)
        assert created.status_code == 201, created.text
        channel = created.json()
        assert channel["secret_configured"] is True
        assert channel["config"] == {"chat_id": "-1001234567890"}
        assert BOT_TOKEN not in created.text
        listed = client.get(f"{base}/channels")
        assert BOT_TOKEN not in listed.text and listed.json()["items"][0]["id"] == channel["id"]
        raw_store = (tmp_path / "control-plane" / "upstream-secrets.json").read_text()
        assert BOT_TOKEN not in raw_store
        rules = client.get(f"{base}/rules").json()["items"]
        assert [(r["event_pattern"], r["min_severity"]) for r in rules] == [("*", "warning")]

        duplicate = client.post(f"{base}/channels", headers=headers, json=body)
        assert duplicate.status_code == 409
        for bad, code in (
            ({**body, "name": "a", "kind": "sms"}, "invalid_kind"),
            ({**body, "name": "b", "config": {"chat_id": "x y"}}, "invalid_chat_id"),
            ({**body, "name": "c", "secret": {"bot_token": "bad/../token"}}, "invalid_bot_token"),
            (
                {"name": "d", "kind": "webhook", "config": {"url": "http://127.0.0.1:8080/"}},
                "destination_not_allowed",
            ),
            (
                {"name": "e", "kind": "webhook", "config": {"url": "ftp://x.example.com/"}},
                "invalid_url",
            ),
            (
                {
                    "name": "f",
                    "kind": "webhook",
                    "config": {"url": "https://x.example.com/", "headers": {"Host": "evil"}},
                },
                "invalid_headers",
            ),
            (
                {
                    "name": "g",
                    "kind": "email",
                    "config": {
                        "smtp_host": "smtp.example.com",
                        "smtp_port": 25,
                        "security": "none",
                        "username": "u",
                        "from_address": "a@example.com",
                        "to_addresses": ["b@example.com"],
                    },
                    "secret": {"password": "pw"},
                },
                "insecure_smtp_auth",
            ),
        ):
            response = client.post(f"{base}/channels", headers=headers, json=bad)
            assert response.status_code == 422, (code, response.text)
            assert response.json()["error"]["code"] == code

        # PATCH is partial; the secret survives unless replaced.
        patched = client.patch(
            f"{base}/channels/{channel['id']}",
            headers=headers,
            json={"name": "Ops TG", "config": {"api_base_url": "https://tg.example.com"}},
        )
        assert patched.status_code == 200, patched.text
        assert patched.json()["secret_configured"] is True
        assert patched.json()["config"]["api_base_url"] == "https://tg.example.com"
        assert (
            client.patch(
                f"{base}/channels/{channel['id']}", headers=headers, json={"kind": "bale"}
            ).json()["error"]["code"]
            == "kind_immutable"
        )
        assert client.patch(f"{base}/channels/missing", headers=headers, json={}).status_code == 404

        tested = client.post(f"{base}/channels/{channel['id']}/test", headers=headers)
        assert tested.json() == {"ok": True, "latency_ms": 12}

        # Rules API
        rule = client.post(
            f"{base}/rules",
            headers=headers,
            json={
                "channel_id": channel["id"],
                "event_pattern": "backup.*",
                "min_severity": "error",
            },
        )
        assert rule.status_code == 201
        assert (
            client.post(
                f"{base}/rules",
                headers=headers,
                json={"channel_id": channel["id"], "event_pattern": "a b"},
            ).status_code
            == 422
        )
        assert (
            client.patch(
                f"{base}/rules/{rule.json()['id']}", headers=headers, json={"enabled": False}
            ).json()["enabled"]
            is False
        )
        assert (
            client.delete(f"{base}/rules/{rule.json()['id']}", headers=headers).status_code == 200
        )

        # Settings
        settings = client.get(f"{base}/settings").json()
        assert settings["quiet_hours"]["timezone"] == "Asia/Tehran"
        assert settings["max_attempts"] == 5 and settings["retention_days"] == 30
        bad_tz = client.put(
            f"{base}/settings", headers=headers, json={"quiet_hours": {"timezone": "Mars/Base"}}
        )
        assert bad_tz.json()["error"]["code"] == "invalid_timezone"
        saved = client.put(
            f"{base}/settings",
            headers=headers,
            json={"dedupe_window_seconds": 60, "max_attempts": 3},
        )
        assert saved.json()["dedupe_window_seconds"] == 60

        # Test event goes through the normal rules and the dispatcher.
        queued = client.post(f"{base}/test-event", headers=headers, json={"severity": "error"})
        assert queued.json() == {"queued": 1}
        assert (
            client.post(
                f"{base}/test-event", headers=headers, json={"severity": "loud"}
            ).status_code
            == 422
        )
        for _ in range(100):
            items = client.get(f"{base}/deliveries?status=sent").json()["items"]
            if items:
                break
            time.sleep(0.02)
        assert items[0]["event_type"] == "notification.test"
        assert items[0]["channel_name"] == "Ops TG"
        assert ("telegram", "notification.test") in sent
        assert client.get(f"{base}/deliveries?status=bogus").status_code == 422
        assert client.get(f"{base}/deliveries?limit=0").status_code == 422

        # RBAC: operator reads, viewer cannot.
        _create_user(client, csrf, "operator1", "operator")
        _create_user(client, csrf, "viewer1", "viewer")
        _create_user(client, csrf, "admin1", "admin")
        op_csrf = _login(client, "operator1")
        assert client.get(f"{base}/channels").status_code == 200
        assert (
            client.post(
                f"{base}/test-event", headers={"X-CSRF-Token": op_csrf}, json={}
            ).status_code
            == 403
        )
        _login(client, "viewer1")
        assert client.get(f"{base}/deliveries").status_code == 403
        admin_csrf = _login(client, "admin1")
        assert (
            client.post(
                f"{base}/test-event",
                headers={"X-CSRF-Token": admin_csrf},
                json={"severity": "info"},
            ).status_code
            == 200
        )

        csrf = str(login_owner(client)["csrf_token"])
        headers = {"X-CSRF-Token": csrf}
        wrong = client.request(
            "DELETE",
            f"{base}/channels/{channel['id']}",
            headers=headers,
            json={"confirmation": "nope"},
        )
        assert wrong.status_code == 409
        deleted = client.request(
            "DELETE",
            f"{base}/channels/{channel['id']}",
            headers=headers,
            json={"confirmation": "Ops TG"},
        )
        assert deleted.status_code == 200
        assert client.get(f"{base}/channels").json()["items"] == []
        assert client.get(f"{base}/rules").json()["items"] == []
        history = client.get(f"{base}/deliveries").json()["items"]
        assert history and all(item["channel_id"] is None for item in history)
        assert BOT_TOKEN not in (tmp_path / "control-plane" / "upstream-secrets.json").read_text()

        audit = client.get("/api/v1/audit-events?limit=200")
        actions = {item["action"] for item in audit.json()["items"]}
        assert {
            "notification.channel.create",
            "notification.channel.update",
            "notification.channel.test",
            "notification.channel.delete",
            "notification.settings.update",
            "notification.test_event",
        } <= actions
        assert BOT_TOKEN not in audit.text


def test_task_events_reach_notifications(tmp_path: Path, monkeypatch) -> None:
    """Events published on the shared bus are routed like any other event."""
    sent: list[str] = []

    async def fake_send(kind, config, secret, outbound, network, transport=None):
        sent.append(outbound.event_type)
        return senders.SendResult(True, None, 1)

    monkeypatch.setattr(senders, "send", fake_send)
    app = create_app(Settings.for_test(tmp_path))
    with TestClient(app) as client:
        csrf = str(login_owner(client)["csrf_token"])
        created = client.post(
            "/api/v1/notifications/channels",
            headers={"X-CSRF-Token": csrf},
            json={
                "name": "hook",
                "kind": "webhook",
                "config": {"url": "https://hooks.example.com/x"},
                "create_default_rule": True,
            },
        )
        assert created.status_code == 201
        assert created.json()["secret_configured"] is False
        app.state.events.publish(
            Event(
                type="agent.offline",
                severity="critical",
                title="agent down",
                occurred_at=datetime.now(UTC).timestamp(),
            )
        )
        for _ in range(100):
            if sent:
                break
            time.sleep(0.02)
    assert sent == ["agent.offline"]
