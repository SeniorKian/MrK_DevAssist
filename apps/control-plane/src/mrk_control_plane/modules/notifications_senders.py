"""Channel senders for the notification center (Telegram, Bale, email, webhook).

Every outbound connection goes through ``outbound`` / ``netresolve``: the
destination name is resolved with the operator's DNS settings, every answer must
pass ``upstream_address_allowed`` and the connection is pinned to the vetted IP
so a DNS rebind between check and connect is impossible. A channel may set
``config.proxy_id`` (``"default"`` or a proxy id) to go through an outbound
proxy instead; email supports SOCKS5/SOCKS5h proxies only.

Secrets (bot tokens, SMTP passwords, signing keys) and URLs never appear in
error codes, return values or log records: Telegram-style bot tokens are part
of the request path, so callers only ever see a short ``error_code``.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import html
import json
import logging
import re
import smtplib
import socket
import ssl
import time
from dataclasses import dataclass
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from typing import Any

import httpx

from .. import outbound
from ..netresolve import (
    DnsConfig,
    NetworkSettingsStore,
    resolve_host,
    upstream_address_allowed,
)
from ..secret_store import SecretStore

LOGGER = logging.getLogger(__name__)

DEFAULT_API_BASE = {
    "telegram": "https://api.telegram.org",
    "bale": "https://tapi.bale.ai",
}
SEVERITY_EMOJI = {"info": "ℹ️", "warning": "⚠️", "error": "❌", "critical": "🚨"}
TELEGRAM_TEXT_LIMIT = 4000
_TOKEN_IN_PATH = re.compile(r"/bot[^/\s\"']+")


class _RedactBotTokens(logging.Filter):
    """httpx logs every request URL at INFO; Bot API URLs carry the bot token."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except Exception:  # pragma: no cover - malformed third-party record
            return True
        if "/bot" in message:
            record.msg = _TOKEN_IN_PATH.sub("/bot<redacted>", message)
            record.args = None
        return True


def install_log_redaction() -> None:
    for name in ("httpx", "httpcore"):
        logger = logging.getLogger(name)
        if not any(isinstance(item, _RedactBotTokens) for item in logger.filters):
            logger.addFilter(_RedactBotTokens())


@dataclass(frozen=True, slots=True)
class SendResult:
    ok: bool
    error_code: str | None = None
    latency_ms: int = 0
    retryable: bool = True
    retry_after: int | None = None


@dataclass(frozen=True, slots=True)
class OutboundMessage:
    event_type: str
    severity: str
    title: str
    message: str
    module: str
    details: dict[str, Any]
    occurred_at: int
    delivery_id: int | None = None
    timestamp_label: str = ""

    def text(self) -> str:
        emoji = SEVERITY_EMOJI.get(self.severity, "")
        lines = [f"{emoji} {self.title}".strip()]
        if self.message:
            lines.append(self.message)
        footer = " · ".join(
            item for item in (self.severity.upper(), self.event_type, self.module) if item
        )
        lines.append("")
        lines.append(footer)
        if self.timestamp_label:
            lines.append(self.timestamp_label)
        return "\n".join(lines)

    def webhook_body(self) -> dict[str, Any]:
        return {
            "event": self.event_type,
            "severity": self.severity,
            "title": self.title,
            "message": self.message,
            "module": self.module,
            "details": self.details,
            "occurred_at": self.occurred_at,
            "delivery_id": self.delivery_id,
        }


class DestinationRejected(ValueError):
    """The destination resolves to an address the operator has not allowed."""


def _elapsed_ms(started: float) -> int:
    return int((time.perf_counter() - started) * 1000)


async def vetted_addresses(
    host: str, port: int, network: NetworkSettingsStore, timeout: float
) -> list[str]:
    """Resolve with the operator DNS settings; every answer must be an allowed address."""
    dns: DnsConfig = network.dns()
    allow_private = network.allow_private_upstreams()
    resolved = await asyncio.wait_for(
        asyncio.to_thread(resolve_host, host, port, dns), timeout=timeout
    )
    if not resolved:
        raise OSError("no addresses")
    for item in resolved:
        if not upstream_address_allowed(item, allow_private):
            raise DestinationRejected("destination not allowed")
    return resolved


def _resolve(host: str, port: int, config: DnsConfig) -> list[str]:
    # Late-bound so the module-level resolve_host stays patchable.
    return resolve_host(host, port, config)


def _http_error_code(exc: BaseException) -> str:
    if isinstance(exc, httpx.ProxyError):
        return "proxy_error"
    if isinstance(exc, httpx.TimeoutException | TimeoutError):
        return "timeout"
    if isinstance(exc, httpx.ConnectError):
        cause = exc.__cause__ or exc.__context__
        if isinstance(cause, ssl.SSLError) or "SSL" in type(cause).__name__:
            return "tls_error"
        return "connect_failed"
    if isinstance(exc, httpx.HTTPError):
        return "http_error"
    return "send_failed"


async def post_pinned(
    url: str,
    body: bytes,
    headers: dict[str, str],
    network: NetworkSettingsStore,
    timeout: float,
    transport: httpx.AsyncBaseTransport | None = None,
    *,
    proxy_ref: str | None = None,
    secret_store: SecretStore | None = None,
) -> tuple[httpx.Response | None, str | None, bool]:
    """POST directly (vetted, pinned address) or through the channel's proxy.

    Returns (response, error_code, retryable).
    """
    try:
        async with outbound.outbound_client(
            network,
            secret_store,
            proxy_ref,
            timeout=timeout,
            transport=transport,
            resolver=_resolve,
        ) as client:
            response = await client.send("POST", url, headers=headers, content=body)
            await response.aread()
            return response, None, True
    except outbound.DestinationRejected:
        return None, "destination_not_allowed", False
    except outbound.DnsFailed:
        return None, "dns_failed", True
    except outbound.OutboundError as exc:
        return None, exc.code, True
    except Exception as exc:  # never log: messages can contain the URL
        return None, _http_error_code(exc), True


def _status_result(response: httpx.Response, started: float) -> SendResult:
    status = response.status_code
    if 200 <= status < 300:
        return SendResult(True, None, _elapsed_ms(started))
    retry_after: int | None = None
    if status == 429:
        retry_after = _retry_after(response)
    retryable = status in {408, 425, 429} or status >= 500
    return SendResult(False, f"http_{status}", _elapsed_ms(started), retryable, retry_after)


def _retry_after(response: httpx.Response) -> int | None:
    try:
        payload = response.json()
        value = payload.get("parameters", {}).get("retry_after")
        if isinstance(value, int) and value > 0:
            return min(value, 3600)
    except Exception:  # noqa: S110 - body is optional
        pass
    header = response.headers.get("retry-after", "")
    if header.isdigit():
        return min(int(header), 3600)
    return None


async def send_bot_api(
    kind: str,
    config: dict[str, Any],
    secret: dict[str, str],
    message: OutboundMessage,
    network: NetworkSettingsStore,
    transport: httpx.AsyncBaseTransport | None = None,
    secret_store: SecretStore | None = None,
) -> SendResult:
    started = time.perf_counter()
    token = secret.get("bot_token", "")
    if not token:
        return SendResult(False, "secret_missing", 0, False)
    base = str(config.get("api_base_url") or DEFAULT_API_BASE[kind]).rstrip("/")
    text = message.text()
    if len(text) > TELEGRAM_TEXT_LIMIT:
        text = text[: TELEGRAM_TEXT_LIMIT - 1] + "…"
    payload: dict[str, Any] = {
        "chat_id": config["chat_id"],
        "text": text,
        "disable_web_page_preview": True,
    }
    parse_mode = config.get("parse_mode")
    if parse_mode == "HTML":
        payload["text"] = html.escape(text, quote=False)
        payload["parse_mode"] = "HTML"
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    response, error_code, retryable = await post_pinned(
        f"{base}/bot{token}/sendMessage",
        body,
        {"Content-Type": "application/json; charset=utf-8", "User-Agent": "MRK-Notify/1"},
        network,
        float(config.get("timeout_seconds", 15)),
        transport,
        proxy_ref=config.get("proxy_id") or None,
        secret_store=secret_store,
    )
    if response is None:
        return SendResult(False, error_code, _elapsed_ms(started), retryable)
    result = _status_result(response, started)
    if result.ok:
        try:
            if response.json().get("ok") is not True:
                return SendResult(False, "api_rejected", result.latency_ms, False)
        except ValueError:
            return SendResult(False, "invalid_response", result.latency_ms, True)
    return result


def webhook_signature(signing_key: str, body: bytes) -> str:
    digest = hmac.new(signing_key.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


async def send_webhook(
    config: dict[str, Any],
    secret: dict[str, str],
    message: OutboundMessage,
    network: NetworkSettingsStore,
    transport: httpx.AsyncBaseTransport | None = None,
    secret_store: SecretStore | None = None,
) -> SendResult:
    started = time.perf_counter()
    body = json.dumps(message.webhook_body(), ensure_ascii=False, separators=(",", ":")).encode(
        "utf-8"
    )
    headers = {str(key): str(value) for key, value in (config.get("headers") or {}).items()}
    headers["Content-Type"] = "application/json; charset=utf-8"
    headers["User-Agent"] = "MRK-Notify/1"
    headers["X-MRK-Event"] = message.event_type
    signing_key = secret.get("signing_key")
    if signing_key:
        headers["X-MRK-Signature"] = webhook_signature(signing_key, body)
    response, error_code, retryable = await post_pinned(
        str(config["url"]),
        body,
        headers,
        network,
        float(config.get("timeout_seconds", 15)),
        transport,
        proxy_ref=config.get("proxy_id") or None,
        secret_store=secret_store,
    )
    if response is None:
        return SendResult(False, error_code, _elapsed_ms(started), retryable)
    return _status_result(response, started)


class _PinnedSMTP(smtplib.SMTP):
    def __init__(self, address: str, timeout: float) -> None:
        self._pinned_address = address
        super().__init__(timeout=timeout)

    def _get_socket(self, host: str, port: int, timeout: float) -> socket.socket:
        return socket.create_connection((self._pinned_address, port), timeout, self.source_address)


class _PinnedSMTPSSL(smtplib.SMTP_SSL):
    def __init__(self, address: str, timeout: float, context: ssl.SSLContext) -> None:
        self._pinned_address = address
        super().__init__(timeout=timeout, context=context)

    def _get_socket(self, host: str, port: int, timeout: float) -> socket.socket:
        raw = socket.create_connection((self._pinned_address, port), timeout, self.source_address)
        # Certificate is checked against the configured host name, not the IP.
        return self.context.wrap_socket(raw, server_hostname=self._host)


SMTP_FACTORY: dict[str, Any] = {"plain": _PinnedSMTP, "ssl": _PinnedSMTPSSL}

Connector = Any  # Callable[[int, float], socket.socket]


class _ProxiedSMTP(smtplib.SMTP):
    """SMTP whose TCP stream is opened through a SOCKS5 proxy."""

    def __init__(self, connector: Connector, timeout: float) -> None:
        self._connector = connector
        super().__init__(timeout=timeout)

    def _get_socket(self, host: str, port: int, timeout: float) -> socket.socket:
        return self._connector(port, timeout)


class _ProxiedSMTPSSL(smtplib.SMTP_SSL):
    def __init__(self, connector: Connector, timeout: float, context: ssl.SSLContext) -> None:
        self._connector = connector
        super().__init__(timeout=timeout, context=context)

    def _get_socket(self, host: str, port: int, timeout: float) -> socket.socket:
        return self.context.wrap_socket(self._connector(port, timeout), server_hostname=self._host)


SMTP_PROXY_FACTORY: dict[str, Any] = {"plain": _ProxiedSMTP, "ssl": _ProxiedSMTPSSL}


def _smtp_error_code(exc: BaseException) -> tuple[str, bool]:
    if isinstance(exc, smtplib.SMTPAuthenticationError):
        return "smtp_auth_failed", False
    if isinstance(exc, smtplib.SMTPRecipientsRefused | smtplib.SMTPSenderRefused):
        return "smtp_address_refused", False
    if isinstance(exc, smtplib.SMTPNotSupportedError):
        return "smtp_not_supported", False
    if isinstance(exc, smtplib.SMTPResponseException) and 500 <= exc.smtp_code < 600:
        return "smtp_rejected", False
    if isinstance(exc, smtplib.SMTPException):
        return "smtp_error", True
    if isinstance(exc, ssl.SSLError):
        return "tls_error", True
    if isinstance(exc, TimeoutError | socket.timeout):
        return "timeout", True
    if isinstance(exc, OSError):
        return "connect_failed", True
    return "send_failed", True


def _smtp_send_blocking(
    address: str,
    config: dict[str, Any],
    password: str | None,
    email: EmailMessage,
    timeout: float,
    connector: Connector | None = None,
) -> None:
    host = str(config["smtp_host"])
    port = int(config["smtp_port"])
    security = str(config.get("security", "starttls"))
    context = ssl.create_default_context()
    if connector is not None:
        if security == "tls":
            client = SMTP_PROXY_FACTORY["ssl"](connector, timeout, context)
        else:
            client = SMTP_PROXY_FACTORY["plain"](connector, timeout)
    elif security == "tls":
        client = SMTP_FACTORY["ssl"](address, timeout, context)
    else:
        client = SMTP_FACTORY["plain"](address, timeout)
    try:
        client.connect(host, port)
        client.ehlo()
        if security == "starttls":
            client.starttls(context=context)
            client.ehlo()
        username = config.get("username")
        if username and password:
            client.login(str(username), password)
        client.send_message(email)
    finally:
        try:
            client.quit()
        except Exception:  # noqa: S110 - connection may already be gone
            client.close()


def build_email(config: dict[str, Any], message: OutboundMessage) -> EmailMessage:
    email = EmailMessage()
    emoji = SEVERITY_EMOJI.get(message.severity, "")
    email["Subject"] = f"{emoji} [MRK] {message.title}".strip()
    email["From"] = str(config["from_address"])
    email["To"] = ", ".join(str(item) for item in config["to_addresses"])
    email["Date"] = formatdate(localtime=False)
    email["Message-ID"] = make_msgid(domain="mrk.local")
    email.set_content(message.text(), charset="utf-8")
    return email


async def send_email(
    config: dict[str, Any],
    secret: dict[str, str],
    message: OutboundMessage,
    network: NetworkSettingsStore,
    secret_store: SecretStore | None = None,
) -> SendResult:
    started = time.perf_counter()
    timeout = float(config.get("timeout_seconds", 15))
    host = str(config["smtp_host"])
    port = int(config["smtp_port"])
    route: outbound.ProxyRoute | None = None
    proxy_ref = config.get("proxy_id") or None
    if proxy_ref:
        try:
            route = await asyncio.to_thread(
                outbound.resolve_route, network, secret_store, str(proxy_ref)
            )
        except outbound.OutboundError as exc:
            return SendResult(False, exc.code, _elapsed_ms(started), True)
        if route is not None and route.profile.type not in outbound.SOCKS_PROXY_TYPES:
            return SendResult(
                False, "proxy_type_unsupported_for_email", _elapsed_ms(started), False
            )
        if route is not None and route.bypasses(host):
            route = None
    connector: Connector | None = None
    address: str | None = None
    try:
        if route is None:
            address = (await vetted_addresses(host, port, network, timeout))[0]
        else:
            proxied_route = route
            pinned_address: str | None = None
            if route.pins_locally:
                pinned_address = (
                    await outbound.vetted_addresses(
                        host,
                        port,
                        network.dns(),
                        network.allow_private_upstreams(),
                        timeout,
                        _resolve,
                    )
                )[0]
            else:
                await outbound.check_via_proxy(
                    host,
                    port,
                    network.dns(),
                    network.allow_private_upstreams(),
                    timeout,
                    _resolve,
                )

            def connector(target_port: int, connect_timeout: float) -> socket.socket:
                return outbound.socks_connect(
                    proxied_route, host, target_port, connect_timeout, pinned_address
                )
    except (DestinationRejected, outbound.DestinationRejected):
        return SendResult(False, "destination_not_allowed", _elapsed_ms(started), False)
    except (OSError, ValueError, TimeoutError):
        return SendResult(False, "dns_failed", _elapsed_ms(started), True)
    email = build_email(config, message)
    try:
        await asyncio.wait_for(
            asyncio.to_thread(
                _smtp_send_blocking,
                address or "",
                config,
                secret.get("password"),
                email,
                timeout,
                connector,
            ),
            timeout=timeout * 4,
        )
    except Exception as exc:  # error text may echo server banners; keep codes only
        code, retryable = _smtp_error_code(exc)
        return SendResult(False, code, _elapsed_ms(started), retryable)
    return SendResult(True, None, _elapsed_ms(started))


async def send(
    kind: str,
    config: dict[str, Any],
    secret: dict[str, str],
    message: OutboundMessage,
    network: NetworkSettingsStore,
    transport: httpx.AsyncBaseTransport | None = None,
    secret_store: SecretStore | None = None,
) -> SendResult:
    """``secret_store`` is needed only when the channel uses a proxy with a password."""
    try:
        if kind in DEFAULT_API_BASE:
            return await send_bot_api(
                kind, config, secret, message, network, transport, secret_store
            )
        if kind == "webhook":
            return await send_webhook(config, secret, message, network, transport, secret_store)
        if kind == "email":
            return await send_email(config, secret, message, network, secret_store)
    except Exception as exc:
        LOGGER.warning(
            "notification sender crashed", extra={"kind": kind, "error": type(exc).__name__}
        )
        return SendResult(False, "send_failed", 0, True)
    return SendResult(False, "unsupported_kind", 0, False)
