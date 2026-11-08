"""Notification center core: validation, persistence, routing and the dispatcher.

Database work always happens in short ``asyncio.to_thread`` sessions that are
closed before any network I/O, because PGlite serves the whole control plane
through a single connection.
"""

from __future__ import annotations

import asyncio
import fnmatch
import hashlib
import ipaddress
import logging
import random
import re
import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta, tzinfo
from datetime import time as dtime
from typing import Any
from urllib.parse import urlsplit
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import httpx
from sqlalchemy import delete, func, select

from .. import outbound
from ..database import Database
from ..models import NotificationChannel, NotificationDelivery, NotificationRule, SystemSetting
from ..module_context import SEVERITIES, Event
from ..netresolve import NetworkSettingsStore, upstream_address_allowed
from ..secret_store import SecretStore
from . import notifications_senders as senders

LOGGER = logging.getLogger(__name__)

SETTINGS_KEY = "notifications"
KINDS = ("telegram", "bale", "email", "webhook")
DELIVERY_STATUSES = ("pending", "sent", "failed", "suppressed", "delayed")
ACTIVE_STATUSES = ("pending", "delayed")
DEFAULT_SETTINGS: dict[str, Any] = {
    "quiet_hours": {
        "enabled": False,
        "start": "23:00",
        "end": "07:00",
        "timezone": "Asia/Tehran",
        "min_severity_during_quiet": "critical",
    },
    "dedupe_window_seconds": 300,
    "max_attempts": 5,
    "retention_days": 30,
    "retry_base_seconds": 30,
    "retry_max_seconds": 3600,
}

_NAME = re.compile(r"^[^\x00-\x1f\x7f]{1,80}$")
_PATTERN = re.compile(r"^[A-Za-z0-9_.*?\-\[\]!]{1,120}$")
_CHAT_ID = re.compile(r"^(-?\d{1,20}|@[A-Za-z0-9_]{4,64})$")
_BOT_TOKEN = re.compile(r"^\d{1,20}:[A-Za-z0-9_-]{8,200}$")
_EMAIL = re.compile(r"^[^@\s<>,;\"()\[\]\\]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,63}$")
_HOSTNAME = re.compile(
    r"^(?=.{1,253}$)([A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)"
    r"(\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$"
)
_HEADER_NAME = re.compile(r"^[A-Za-z0-9-]{1,64}$")
_HHMM = re.compile(r"^([01]\d|2[0-3]):([0-5]\d)$")
_FORBIDDEN_HEADERS = {
    "host",
    "content-length",
    "content-type",
    "transfer-encoding",
    "connection",
    "x-mrk-signature",
    "x-mrk-event",
    "user-agent",
    "upgrade",
    "te",
    "trailer",
    "proxy-authorization",
    "keep-alive",
    "expect",
}


class NotificationError(Exception):
    def __init__(self, code: str, message: str, status_code: int = 422) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code


def severity_rank(value: str) -> int:
    return SEVERITIES.index(value)


def _now() -> int:
    return int(time.time())


# --- validation ----------------------------------------------------------------


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise NotificationError(code, message)


def validate_name(value: Any) -> str:
    _require(isinstance(value, str), "invalid_name", "name must be text")
    name = value.strip()
    _require(bool(_NAME.match(name)), "invalid_name", "name must be 1-80 printable characters")
    return name


def validate_severity(value: Any, code: str = "invalid_severity") -> str:
    _require(value in SEVERITIES, code, f"severity must be one of {', '.join(SEVERITIES)}")
    return str(value)


def validate_pattern(value: Any) -> str:
    _require(isinstance(value, str), "invalid_event_pattern", "event_pattern must be text")
    pattern = value.strip()
    _require(
        bool(_PATTERN.match(pattern)),
        "invalid_event_pattern",
        "event_pattern may use letters, digits, '.', '_', '-' and the wildcards * ? [ ]",
    )
    return pattern


def _validate_timeout(config: dict[str, Any], out: dict[str, Any]) -> None:
    if config.get("timeout_seconds") is None:
        return
    value = config["timeout_seconds"]
    _require(
        isinstance(value, int | float) and not isinstance(value, bool) and 2 <= value <= 60,
        "invalid_timeout",
        "timeout_seconds must be between 2 and 60",
    )
    out["timeout_seconds"] = value


def _host_literal_allowed(host: str) -> bool:
    lowered = host.lower().rstrip(".")
    if lowered == "localhost" or lowered.endswith(".localhost"):
        return False
    try:
        ipaddress.ip_address(lowered)
    except ValueError:
        return True
    # An IP literal is checked now; names are checked on every send.
    return upstream_address_allowed(lowered, allow_private=True)


def validate_url(value: Any, *, schemes: tuple[str, ...], code: str) -> str:
    _require(isinstance(value, str) and 0 < len(value) <= 2000, code, "URL is required")
    url = value.strip()
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError:
        raise NotificationError(code, "URL is not valid") from None
    _require(parsed.scheme in schemes, code, f"URL scheme must be {' or '.join(schemes)}")
    _require(bool(parsed.hostname), code, "URL needs a host")
    _require(
        parsed.username is None and parsed.password is None, code, "URL must not embed credentials"
    )
    _require(port is None or 0 < port < 65536, code, "URL port is out of range")
    _require(not any(ch in url for ch in "\r\n\t "), code, "URL must not contain whitespace")
    if not _host_literal_allowed(parsed.hostname or ""):
        raise NotificationError("destination_not_allowed", "URL host is a local address")
    return url


def validate_config(kind: str, config: Any) -> dict[str, Any]:
    _require(isinstance(config, dict), "invalid_config", "config must be an object")
    out: dict[str, Any] = {}
    if kind in ("telegram", "bale"):
        chat_id = config.get("chat_id")
        if isinstance(chat_id, int) and not isinstance(chat_id, bool):
            chat_id = str(chat_id)
        _require(
            isinstance(chat_id, str) and bool(_CHAT_ID.match(chat_id.strip())),
            "invalid_chat_id",
            "chat_id must be a numeric id or @channel name",
        )
        out["chat_id"] = chat_id.strip()
        if config.get("api_base_url"):
            out["api_base_url"] = validate_url(
                config["api_base_url"], schemes=("https",), code="invalid_api_base_url"
            ).rstrip("/")
            parsed = urlsplit(out["api_base_url"])
            _require(
                not parsed.query and not parsed.fragment,
                "invalid_api_base_url",
                "api_base_url must not have a query or fragment",
            )
        if config.get("parse_mode") is not None:
            _require(config["parse_mode"] == "HTML", "invalid_parse_mode", "parse_mode may be HTML")
            out["parse_mode"] = "HTML"
    elif kind == "email":
        host = config.get("smtp_host")
        _require(
            isinstance(host, str) and bool(_HOSTNAME.match(host.strip())),
            "invalid_smtp_host",
            "smtp_host must be a host name or IP address",
        )
        host = host.strip()
        if not _host_literal_allowed(host):
            raise NotificationError("destination_not_allowed", "smtp_host is a local address")
        out["smtp_host"] = host
        port = config.get("smtp_port", 587)
        _require(
            isinstance(port, int) and not isinstance(port, bool) and 0 < port < 65536,
            "invalid_smtp_port",
            "smtp_port must be 1-65535",
        )
        out["smtp_port"] = port
        security = config.get("security", "starttls")
        _require(
            security in ("starttls", "tls", "none"),
            "invalid_smtp_security",
            "security must be starttls, tls or none",
        )
        out["security"] = security
        username = config.get("username")
        if username:
            _require(
                isinstance(username, str) and len(username) <= 254 and "\n" not in username,
                "invalid_smtp_username",
                "username is not valid",
            )
            out["username"] = username.strip()
        sender = config.get("from_address")
        _require(
            isinstance(sender, str) and bool(_EMAIL.match(sender.strip())),
            "invalid_from_address",
            "from_address must be an email address",
        )
        out["from_address"] = sender.strip()
        recipients = config.get("to_addresses")
        _require(
            isinstance(recipients, list) and 0 < len(recipients) <= 20,
            "invalid_to_addresses",
            "to_addresses must list 1-20 email addresses",
        )
        cleaned = []
        for item in recipients:
            _require(
                isinstance(item, str) and bool(_EMAIL.match(item.strip())),
                "invalid_to_addresses",
                "to_addresses contains an invalid address",
            )
            cleaned.append(item.strip())
        out["to_addresses"] = list(dict.fromkeys(cleaned))
    elif kind == "webhook":
        out["url"] = validate_url(config.get("url"), schemes=("https", "http"), code="invalid_url")
        headers = config.get("headers") or {}
        _require(
            isinstance(headers, dict) and len(headers) <= 20,
            "invalid_headers",
            "headers must be an object with at most 20 entries",
        )
        clean_headers: dict[str, str] = {}
        for key, value in headers.items():
            _require(
                isinstance(key, str)
                and bool(_HEADER_NAME.match(key))
                and key.lower() not in _FORBIDDEN_HEADERS,
                "invalid_headers",
                "header name is not allowed",
            )
            _require(
                isinstance(value, str)
                and len(value) <= 1024
                and not any(ch in value for ch in "\r\n\x00"),
                "invalid_headers",
                "header value is not valid",
            )
            clean_headers[key] = value
        if clean_headers:
            out["headers"] = clean_headers
    else:
        raise NotificationError("invalid_kind", f"kind must be one of {', '.join(KINDS)}")
    _validate_timeout(config, out)
    if config.get("proxy_id") is not None:
        try:
            reference = outbound.validate_reference(config["proxy_id"])
        except outbound.OutboundError as exc:
            raise NotificationError(exc.code, exc.message) from None
        if reference is not None:
            out["proxy_id"] = reference
    return out


def proxy_types_for(kind: str) -> frozenset[str]:
    """Email is raw SMTP over TCP: only SOCKS proxies can carry it."""
    return outbound.SOCKS_PROXY_TYPES if kind == "email" else outbound.ALL_PROXY_TYPES


def check_channel_proxy(network: NetworkSettingsStore, kind: str, config: dict[str, Any]) -> None:
    try:
        outbound.check_reference(
            network,
            config.get("proxy_id"),
            proxy_types_for(kind),
            "proxy_type_unsupported_for_email",
        )
    except outbound.OutboundError as exc:
        raise NotificationError(exc.code, exc.message) from None


def validate_secret(
    kind: str, config: dict[str, Any], secret: Any, existing: bool
) -> dict[str, str] | None:
    """Return the cleaned secret, ``{}`` to clear it, or None to keep the existing one."""
    if secret is None:
        if kind in ("telegram", "bale"):
            _require(existing, "secret_required", "bot_token is required")
        if kind == "email" and config.get("username"):
            _require(existing, "secret_required", "password is required with a username")
        return None
    _require(isinstance(secret, dict), "invalid_secret", "secret must be an object")
    if kind in ("telegram", "bale"):
        token = secret.get("bot_token")
        _require(
            isinstance(token, str) and bool(_BOT_TOKEN.match(token.strip())),
            "invalid_bot_token",
            "bot_token must look like 123456:ABC...",
        )
        return {"bot_token": token.strip()}
    if kind == "email":
        password = secret.get("password")
        if not password:
            _require(
                not config.get("username"),
                "secret_required",
                "password is required with a username",
            )
            return {}
        _require(
            isinstance(password, str) and len(password) <= 1024,
            "invalid_password",
            "password is not valid",
        )
        return {"password": password}
    if kind == "webhook":
        key = secret.get("signing_key")
        if not key:
            return {}
        _require(
            isinstance(key, str) and 8 <= len(key) <= 512,
            "invalid_signing_key",
            "signing_key must be 8-512 characters",
        )
        return {"signing_key": key}
    return {}


def _check_email_security(config: dict[str, Any], has_password: bool) -> None:
    if config.get("security") == "none" and (config.get("username") or has_password):
        raise NotificationError("insecure_smtp_auth", "SMTP login needs security starttls or tls")


def _zone(name: str) -> tzinfo:
    if name.upper() == "UTC":
        return UTC
    return ZoneInfo(name)


def validate_settings(payload: Any, current: dict[str, Any]) -> dict[str, Any]:
    _require(isinstance(payload, dict), "invalid_settings", "settings must be an object")
    merged = {**current, "quiet_hours": dict(current["quiet_hours"])}
    if "quiet_hours" in payload:
        quiet = payload["quiet_hours"]
        _require(isinstance(quiet, dict), "invalid_quiet_hours", "quiet_hours must be an object")
        merged["quiet_hours"].update(quiet)
    quiet = merged["quiet_hours"]
    _require(
        isinstance(quiet.get("enabled"), bool),
        "invalid_quiet_hours",
        "quiet_hours.enabled must be a boolean",
    )
    for key in ("start", "end"):
        _require(
            isinstance(quiet.get(key), str) and bool(_HHMM.match(quiet[key])),
            "invalid_quiet_hours",
            f"quiet_hours.{key} must be HH:MM",
        )
    try:
        _zone(str(quiet.get("timezone")))
    except (ZoneInfoNotFoundError, ValueError, TypeError):
        raise NotificationError("invalid_timezone", "unknown time zone") from None
    validate_severity(quiet.get("min_severity_during_quiet"), "invalid_quiet_hours")
    merged["quiet_hours"] = {
        key: quiet[key]
        for key in ("enabled", "start", "end", "timezone", "min_severity_during_quiet")
    }
    limits = {
        "dedupe_window_seconds": (0, 86400),
        "max_attempts": (1, 20),
        "retention_days": (1, 3650),
        "retry_base_seconds": (1, 3600),
        "retry_max_seconds": (1, 86400),
    }
    for key, (low, high) in limits.items():
        if key in payload:
            value = payload[key]
            _require(
                isinstance(value, int) and not isinstance(value, bool) and low <= value <= high,
                f"invalid_{key}",
                f"{key} must be an integer between {low} and {high}",
            )
            merged[key] = value
    _require(
        merged["retry_max_seconds"] >= merged["retry_base_seconds"],
        "invalid_retry_max_seconds",
        "retry_max_seconds must be at least retry_base_seconds",
    )
    return merged


# --- quiet hours -----------------------------------------------------------------


def quiet_until(now: float, quiet: dict[str, Any]) -> int | None:
    """If ``now`` falls inside quiet hours, return the epoch second they end."""
    if not quiet.get("enabled"):
        return None
    start_h, start_m = (int(part) for part in str(quiet["start"]).split(":"))
    end_h, end_m = (int(part) for part in str(quiet["end"]).split(":"))
    start, end = dtime(start_h, start_m), dtime(end_h, end_m)
    if start == end:
        return None
    try:
        zone = _zone(str(quiet.get("timezone", "UTC")))
    except (ZoneInfoNotFoundError, ValueError):
        LOGGER.warning("quiet hours time zone unavailable; using UTC")
        zone = UTC
    local = datetime.fromtimestamp(now, zone)
    current = local.time().replace(second=0, microsecond=0)
    if start < end:
        inside = start <= current < end
        end_date = local.date()
    else:  # window crosses midnight
        inside = current >= start or current < end
        end_date = local.date() + timedelta(days=1) if current >= start else local.date()
    if not inside:
        return None
    ends = datetime.combine(end_date, end, tzinfo=zone)
    return max(int(ends.timestamp()), int(now) + 1)


def held_by_quiet_hours(now: float, severity: str, quiet: dict[str, Any]) -> int | None:
    until = quiet_until(now, quiet)
    if until is None:
        return None
    if severity_rank(severity) >= severity_rank(quiet["min_severity_during_quiet"]):
        return None
    return until


def dedupe_hash(event: Event) -> str:
    basis = f"key:{event.dedupe_key}" if event.dedupe_key else f"tt:{event.type}\x00{event.title}"
    return hashlib.sha256(basis.encode("utf-8")).hexdigest()


# --- public serializers ------------------------------------------------------------


def channel_public(item: NotificationChannel) -> dict[str, Any]:
    return {
        "id": item.id,
        "name": item.name,
        "kind": item.kind,
        "enabled": item.enabled,
        "config": dict(item.config or {}),
        "secret_configured": item.secret_ref is not None,
        "created_at": item.created_at,
        "updated_at": item.updated_at,
        "last_delivery_at": item.last_delivery_at,
        "last_status": item.last_status,
    }


def rule_public(item: NotificationRule) -> dict[str, Any]:
    return {
        "id": item.id,
        "channel_id": item.channel_id,
        "event_pattern": item.event_pattern,
        "min_severity": item.min_severity,
        "enabled": item.enabled,
    }


def delivery_public(item: NotificationDelivery) -> dict[str, Any]:
    return {
        "id": item.id,
        "event_type": item.event_type,
        "severity": item.severity,
        "title": item.title,
        "channel_id": item.channel_id,
        "channel_name": item.channel_name,
        "status": item.status,
        "attempts": item.attempts,
        "error_code": item.error_code,
        "created_at": item.created_at,
        "sent_at": item.sent_at,
        "next_attempt_at": item.next_attempt_at,
    }


@dataclass(slots=True)
class _Work:
    delivery_id: int
    attempts: int
    severity: str
    channel_id: str | None
    kind: str | None
    enabled: bool
    config: dict[str, Any]
    secret_ref: str | None
    message: senders.OutboundMessage


class NotificationCenter:
    def __init__(
        self,
        database: Database,
        secret_store: SecretStore,
        network: NetworkSettingsStore,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.db = database
        self.secrets = secret_store
        self.network = network
        self.clock = clock
        self.transport: httpx.AsyncBaseTransport | None = None
        self.batch_size = 20
        self._wake = asyncio.Event()
        self._task: asyncio.Task[None] | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._last_prune = 0.0

    # ---- settings ----

    def get_settings(self) -> dict[str, Any]:
        with self.db.session() as db:
            row = db.get(SystemSetting, SETTINGS_KEY)
            stored = dict(row.value) if row is not None and isinstance(row.value, dict) else {}
        merged = {**DEFAULT_SETTINGS, **stored}
        merged["quiet_hours"] = {
            **DEFAULT_SETTINGS["quiet_hours"],
            **(stored.get("quiet_hours") or {}),
        }
        return merged

    def put_settings(self, payload: Any, actor_user_id: int | None) -> dict[str, Any]:
        merged = validate_settings(payload, self.get_settings())
        with self.db.session() as db, db.begin():
            row = db.get(SystemSetting, SETTINGS_KEY)
            if row is None:
                row = SystemSetting(key=SETTINGS_KEY, value=merged, updated_at=_now())
                db.add(row)
            row.value = merged
            row.updated_at = _now()
            row.updated_by_user_id = actor_user_id
        self.wake()
        return merged

    # ---- channels ----

    def list_channels(self) -> list[dict[str, Any]]:
        with self.db.session() as db:
            rows = db.scalars(
                select(NotificationChannel).order_by(
                    NotificationChannel.created_at, NotificationChannel.name
                )
            )
            return [channel_public(item) for item in rows]

    def get_channel(self, channel_id: str) -> dict[str, Any]:
        with self.db.session() as db:
            item = db.get(NotificationChannel, channel_id)
            if item is None:
                raise KeyError(channel_id)
            return channel_public(item)

    def _name_taken(self, db: Any, name: str, exclude: str | None = None) -> bool:
        query = select(NotificationChannel.id).where(
            func.lower(NotificationChannel.name) == name.lower()
        )
        if exclude:
            query = query.where(NotificationChannel.id != exclude)
        return db.scalar(query) is not None

    def create_channel(self, payload: Any) -> dict[str, Any]:
        _require(isinstance(payload, dict), "invalid_request", "body must be an object")
        name = validate_name(payload.get("name"))
        kind = payload.get("kind")
        _require(kind in KINDS, "invalid_kind", f"kind must be one of {', '.join(KINDS)}")
        enabled = payload.get("enabled", True)
        _require(isinstance(enabled, bool), "invalid_enabled", "enabled must be a boolean")
        config = validate_config(kind, payload.get("config", {}))
        check_channel_proxy(self.network, kind, config)
        secret = validate_secret(kind, config, payload.get("secret"), existing=False)
        if kind == "email":
            _check_email_security(config, bool(secret))
        default_rule = payload.get("create_default_rule", False)
        _require(
            isinstance(default_rule, bool),
            "invalid_request",
            "create_default_rule must be a boolean",
        )
        with self.db.session() as db:
            if self._name_taken(db, name):
                raise NotificationError(
                    "channel_name_taken", "a channel with this name exists", 409
                )
        secret_ref = self.secrets.replace(None, secret)[0] if secret else None
        now = _now()
        channel = NotificationChannel(
            id=secrets.token_hex(16),
            name=name,
            kind=kind,
            enabled=enabled,
            config=config,
            secret_ref=secret_ref,
            created_at=now,
            updated_at=now,
        )
        try:
            with self.db.session() as db, db.begin():
                db.add(channel)
                if default_rule:
                    db.flush()
                    db.add(
                        NotificationRule(
                            id=secrets.token_hex(16),
                            channel_id=channel.id,
                            event_pattern="*",
                            min_severity="warning",
                            enabled=True,
                            created_at=now,
                            updated_at=now,
                        )
                    )
        except Exception:
            if secret_ref:
                self.secrets.delete(secret_ref)
            raise
        return channel_public(channel)

    def update_channel(self, channel_id: str, payload: Any) -> dict[str, Any]:
        _require(isinstance(payload, dict), "invalid_request", "body must be an object")
        with self.db.session() as db:
            current = db.get(NotificationChannel, channel_id)
            if current is None:
                raise KeyError(channel_id)
            kind, config, secret_ref = current.kind, dict(current.config or {}), current.secret_ref
            name, enabled = current.name, current.enabled
        if "kind" in payload and payload["kind"] != kind:
            raise NotificationError("kind_immutable", "a channel's kind cannot change")
        if "name" in payload:
            name = validate_name(payload["name"])
        if "enabled" in payload:
            _require(
                isinstance(payload["enabled"], bool), "invalid_enabled", "enabled must be a boolean"
            )
            enabled = payload["enabled"]
        if "config" in payload:
            changes = payload["config"]
            _require(isinstance(changes, dict), "invalid_config", "config must be an object")
            for key, value in changes.items():
                if value is None:
                    config.pop(key, None)
                else:
                    config[key] = value
        config = validate_config(kind, config)
        if "config" in payload and "proxy_id" in payload["config"]:
            check_channel_proxy(self.network, kind, config)
        secret = validate_secret(
            kind, config, payload.get("secret"), existing=secret_ref is not None
        )
        if kind == "email":
            has_password = bool(secret) if secret is not None else secret_ref is not None
            _check_email_security(config, has_password)
        with self.db.session() as db:
            if self._name_taken(db, name, exclude=channel_id):
                raise NotificationError(
                    "channel_name_taken", "a channel with this name exists", 409
                )
        old_ref_to_delete: str | None = None
        if secret is not None:
            if secret:
                secret_ref = self.secrets.replace(secret_ref, secret)[0]
            elif secret_ref:
                old_ref_to_delete, secret_ref = secret_ref, None
        with self.db.session() as db, db.begin():
            item = db.get(NotificationChannel, channel_id)
            if item is None:
                raise KeyError(channel_id)
            item.name = name
            item.enabled = enabled
            item.config = config
            item.secret_ref = secret_ref
            item.updated_at = _now()
            result = channel_public(item)
        if old_ref_to_delete:
            self.secrets.delete(old_ref_to_delete)
        self.wake()
        return result

    def delete_channel(self, channel_id: str, confirmation: Any) -> dict[str, Any]:
        with self.db.session() as db, db.begin():
            item = db.get(NotificationChannel, channel_id)
            if item is None:
                raise KeyError(channel_id)
            if not isinstance(confirmation, str) or confirmation.strip() != item.name:
                raise NotificationError("confirmation_mismatch", "type the exact channel name", 409)
            result = channel_public(item)
            secret_ref = item.secret_ref
            db.execute(delete(NotificationRule).where(NotificationRule.channel_id == channel_id))
            # Keep delivery history; pending work for this channel is abandoned.
            for delivery in db.scalars(
                select(NotificationDelivery).where(
                    NotificationDelivery.channel_id == channel_id,
                    NotificationDelivery.status.in_(ACTIVE_STATUSES),
                )
            ):
                delivery.status = "failed"
                delivery.error_code = "channel_deleted"
                delivery.next_attempt_at = None
            db.flush()
            db.delete(item)
        if secret_ref:
            self.secrets.delete(secret_ref)
        return result

    def mark_channel(self, channel_id: str, status: str) -> None:
        with self.db.session() as db, db.begin():
            item = db.get(NotificationChannel, channel_id)
            if item is not None:
                item.last_delivery_at = int(self.clock())
                item.last_status = status

    def channel_for_send(self, channel_id: str) -> tuple[str, dict[str, Any], dict[str, str]]:
        with self.db.session() as db:
            item = db.get(NotificationChannel, channel_id)
            if item is None:
                raise KeyError(channel_id)
            kind, config, ref = item.kind, dict(item.config or {}), item.secret_ref
        return kind, config, self._secret(ref)

    def _proxy_kwargs(self, config: dict[str, Any]) -> dict[str, Any]:
        # Only proxied channels need the store (it decrypts the proxy password).
        return {"secret_store": self.secrets} if config.get("proxy_id") else {}

    def _secret(self, ref: str | None) -> dict[str, str]:
        if not ref:
            return {}
        try:
            return self.secrets.get(ref)
        except (KeyError, ValueError):
            return {}

    # ---- rules ----

    def list_rules(self) -> list[dict[str, Any]]:
        with self.db.session() as db:
            rows = db.scalars(
                select(NotificationRule).order_by(NotificationRule.created_at, NotificationRule.id)
            )
            return [rule_public(item) for item in rows]

    def create_rule(self, payload: Any) -> dict[str, Any]:
        _require(isinstance(payload, dict), "invalid_request", "body must be an object")
        channel_id = payload.get("channel_id")
        _require(isinstance(channel_id, str), "invalid_channel_id", "channel_id is required")
        pattern = validate_pattern(payload.get("event_pattern", "*"))
        min_severity = validate_severity(payload.get("min_severity", "warning"))
        enabled = payload.get("enabled", True)
        _require(isinstance(enabled, bool), "invalid_enabled", "enabled must be a boolean")
        now = _now()
        with self.db.session() as db, db.begin():
            if db.get(NotificationChannel, channel_id) is None:
                raise NotificationError("invalid_channel_id", "channel does not exist")
            rule = NotificationRule(
                id=secrets.token_hex(16),
                channel_id=channel_id,
                event_pattern=pattern,
                min_severity=min_severity,
                enabled=enabled,
                created_at=now,
                updated_at=now,
            )
            db.add(rule)
            return rule_public(rule)

    def update_rule(self, rule_id: str, payload: Any) -> dict[str, Any]:
        _require(isinstance(payload, dict), "invalid_request", "body must be an object")
        with self.db.session() as db, db.begin():
            rule = db.get(NotificationRule, rule_id)
            if rule is None:
                raise KeyError(rule_id)
            if "channel_id" in payload:
                channel_id = payload["channel_id"]
                _require(
                    isinstance(channel_id, str)
                    and db.get(NotificationChannel, channel_id) is not None,
                    "invalid_channel_id",
                    "channel does not exist",
                )
                rule.channel_id = channel_id
            if "event_pattern" in payload:
                rule.event_pattern = validate_pattern(payload["event_pattern"])
            if "min_severity" in payload:
                rule.min_severity = validate_severity(payload["min_severity"])
            if "enabled" in payload:
                _require(
                    isinstance(payload["enabled"], bool),
                    "invalid_enabled",
                    "enabled must be a boolean",
                )
                rule.enabled = payload["enabled"]
            rule.updated_at = _now()
            return rule_public(rule)

    def delete_rule(self, rule_id: str) -> dict[str, Any]:
        with self.db.session() as db, db.begin():
            rule = db.get(NotificationRule, rule_id)
            if rule is None:
                raise KeyError(rule_id)
            result = rule_public(rule)
            db.delete(rule)
            return result

    # ---- deliveries ----

    def list_deliveries(self, limit: int, status: str | None) -> list[dict[str, Any]]:
        with self.db.session() as db:
            query = (
                select(NotificationDelivery).order_by(NotificationDelivery.id.desc()).limit(limit)
            )
            if status:
                query = query.where(NotificationDelivery.status == status)
            return [delivery_public(item) for item in db.scalars(query)]

    def ingest(self, event: Event) -> list[dict[str, Any]]:
        """Route an event to channels and persist one delivery row per channel."""
        settings = self.get_settings()
        now = int(self.clock())
        hold = held_by_quiet_hours(now, event.severity, settings["quiet_hours"])
        digest = dedupe_hash(event)
        window = int(settings["dedupe_window_seconds"])
        created: list[dict[str, Any]] = []
        with self.db.session() as db, db.begin():
            rows = db.execute(
                select(NotificationRule, NotificationChannel)
                .join(NotificationChannel, NotificationRule.channel_id == NotificationChannel.id)
                .where(NotificationRule.enabled.is_(True), NotificationChannel.enabled.is_(True))
            ).all()
            matched: dict[str, NotificationChannel] = {}
            for rule, channel in rows:
                if severity_rank(event.severity) < severity_rank(rule.min_severity):
                    continue
                if not fnmatch.fnmatchcase(event.type, rule.event_pattern):
                    continue
                matched.setdefault(channel.id, channel)
            for channel in matched.values():
                status, next_at = "pending", now
                if (
                    window > 0
                    and db.scalar(
                        select(NotificationDelivery.id)
                        .where(
                            NotificationDelivery.channel_id == channel.id,
                            NotificationDelivery.dedupe_hash == digest,
                            NotificationDelivery.created_at >= now - window,
                            NotificationDelivery.status.in_(("pending", "delayed", "sent")),
                        )
                        .limit(1)
                    )
                    is not None
                ):
                    status, next_at = "suppressed", None
                elif hold is not None:
                    status, next_at = "delayed", hold
                delivery = NotificationDelivery(
                    channel_id=channel.id,
                    channel_name=channel.name,
                    event_type=event.type[:120],
                    severity=event.severity,
                    module=(event.module or "core")[:64],
                    title=event.title[:300],
                    message=event.message[:4000],
                    details=dict(event.details or {}),
                    dedupe_hash=digest,
                    status=status,
                    attempts=0,
                    error_code="duplicate" if status == "suppressed" else None,
                    occurred_at=int(event.occurred_at),
                    created_at=now,
                    next_attempt_at=next_at,
                )
                db.add(delivery)
                db.flush()
                created.append(delivery_public(delivery))
        if any(item["status"] == "pending" for item in created):
            self.wake()
        return created

    async def handle_event(self, event: Event) -> None:
        await asyncio.to_thread(self.ingest, event)

    def _timestamp_label(self, occurred_at: int, quiet: dict[str, Any]) -> str:
        try:
            zone = _zone(str(quiet.get("timezone", "UTC")))
            label = str(quiet.get("timezone", "UTC"))
        except (ZoneInfoNotFoundError, ValueError):
            zone, label = UTC, "UTC"
        return f"{datetime.fromtimestamp(occurred_at, zone):%Y-%m-%d %H:%M} ({label})"

    def _due(self, now: int) -> list[_Work]:
        quiet = self.get_settings()["quiet_hours"]
        with self.db.session() as db:
            rows = db.execute(
                select(NotificationDelivery, NotificationChannel)
                .outerjoin(
                    NotificationChannel, NotificationDelivery.channel_id == NotificationChannel.id
                )
                .where(
                    NotificationDelivery.status.in_(ACTIVE_STATUSES),
                    NotificationDelivery.next_attempt_at <= now,
                )
                .order_by(NotificationDelivery.next_attempt_at, NotificationDelivery.id)
                .limit(self.batch_size)
            ).all()
            work = []
            for delivery, channel in rows:
                work.append(
                    _Work(
                        delivery_id=delivery.id,
                        attempts=delivery.attempts,
                        severity=delivery.severity,
                        channel_id=channel.id if channel else None,
                        kind=channel.kind if channel else None,
                        enabled=bool(channel and channel.enabled),
                        config=dict(channel.config or {}) if channel else {},
                        secret_ref=channel.secret_ref if channel else None,
                        message=senders.OutboundMessage(
                            event_type=delivery.event_type,
                            severity=delivery.severity,
                            title=delivery.title,
                            message=delivery.message,
                            module=delivery.module,
                            details=dict(delivery.details or {}),
                            occurred_at=delivery.occurred_at,
                            delivery_id=delivery.id,
                            timestamp_label=self._timestamp_label(delivery.occurred_at, quiet),
                        ),
                    )
                )
        return work

    def _record(
        self,
        delivery_id: int,
        *,
        status: str,
        error_code: str | None,
        next_attempt_at: int | None,
        attempted: bool,
    ) -> None:
        now = int(self.clock())
        with self.db.session() as db, db.begin():
            item = db.get(NotificationDelivery, delivery_id)
            if item is None:
                return
            if attempted:
                item.attempts += 1
            item.status = status
            item.error_code = error_code
            item.next_attempt_at = next_attempt_at
            if status == "sent":
                item.sent_at = now

    def _next_due(self) -> int | None:
        with self.db.session() as db:
            return db.scalar(
                select(func.min(NotificationDelivery.next_attempt_at)).where(
                    NotificationDelivery.status.in_(ACTIVE_STATUSES)
                )
            )

    def prune(self) -> int:
        retention = int(self.get_settings()["retention_days"])
        cutoff = int(self.clock()) - retention * 86400
        with self.db.session() as db, db.begin():
            result = db.execute(
                delete(NotificationDelivery).where(NotificationDelivery.created_at < cutoff)
            )
            return int(result.rowcount or 0)

    def backoff(self, attempts: int, settings: dict[str, Any], retry_after: int | None) -> int:
        if retry_after:
            return retry_after
        base = int(settings["retry_base_seconds"])
        ceiling = int(settings["retry_max_seconds"])
        delay = min(base * (2 ** max(attempts - 1, 0)), ceiling)
        return max(1, int(delay * random.uniform(0.8, 1.2)))  # noqa: S311 - jitter only

    async def process_due(self) -> int:
        """Send every due delivery once. Returns how many rows were handled."""
        now = int(self.clock())
        work = await asyncio.to_thread(self._due, now)
        if not work:
            return 0
        settings = await asyncio.to_thread(self.get_settings)
        for item in work:
            if item.channel_id is None or item.kind is None:
                await asyncio.to_thread(
                    self._record,
                    item.delivery_id,
                    status="failed",
                    error_code="channel_deleted",
                    next_attempt_at=None,
                    attempted=False,
                )
                continue
            if not item.enabled:
                await asyncio.to_thread(
                    self._record,
                    item.delivery_id,
                    status="suppressed",
                    error_code="channel_disabled",
                    next_attempt_at=None,
                    attempted=False,
                )
                continue
            hold = held_by_quiet_hours(self.clock(), item.severity, settings["quiet_hours"])
            if hold is not None:
                await asyncio.to_thread(
                    self._record,
                    item.delivery_id,
                    status="delayed",
                    error_code=None,
                    next_attempt_at=hold,
                    attempted=False,
                )
                continue
            secret = await asyncio.to_thread(self._secret, item.secret_ref)
            result = await senders.send(
                item.kind,
                item.config,
                secret,
                item.message,
                self.network,
                self.transport,
                **self._proxy_kwargs(item.config),
            )
            attempts = item.attempts + 1
            if result.ok:
                status, next_at = "sent", None
            elif result.retryable and attempts < int(settings["max_attempts"]):
                status = "pending"
                next_at = int(self.clock()) + self.backoff(attempts, settings, result.retry_after)
            else:
                status, next_at = "failed", None
            if not result.ok:
                LOGGER.info(
                    "notification delivery attempt failed",
                    extra={
                        "channel_id": item.channel_id,
                        "delivery_id": item.delivery_id,
                        "error_code": result.error_code,
                        "attempt": attempts,
                    },
                )
            await asyncio.to_thread(
                self._record,
                item.delivery_id,
                status=status,
                error_code=result.error_code,
                next_attempt_at=next_at,
                attempted=True,
            )
            await asyncio.to_thread(
                self.mark_channel, item.channel_id, "sent" if result.ok else "failed"
            )
        return len(work)

    async def test_channel(self, channel_id: str) -> senders.SendResult:
        kind, config, secret = await asyncio.to_thread(self.channel_for_send, channel_id)
        quiet = (await asyncio.to_thread(self.get_settings))["quiet_hours"]
        now = int(self.clock())
        message = senders.OutboundMessage(
            event_type="notification.test",
            severity="info",
            title="MRK test notification · پیام آزمایشی MRK",
            message=(
                "If you can read this, the channel works. / "
                "اگر این پیام را می‌بینید، کانال کار می‌کند."
            ),
            module="notifications",
            details={"test": True},
            occurred_at=now,
            timestamp_label=self._timestamp_label(now, quiet),
        )
        result = await senders.send(
            kind, config, secret, message, self.network, self.transport,
            **self._proxy_kwargs(config),
        )
        await asyncio.to_thread(self.mark_channel, channel_id, "sent" if result.ok else "failed")
        return result

    # ---- lifecycle ----

    def wake(self) -> None:
        loop = self._loop
        if loop is None or loop.is_closed():
            return
        try:
            running = asyncio.get_running_loop()
        except RuntimeError:
            running = None
        if running is loop:
            self._wake.set()
        else:
            loop.call_soon_threadsafe(self._wake.set)

    async def run(self) -> None:
        while True:
            # Cleared before the work so a wake() during processing is not lost.
            self._wake.clear()
            try:
                if time.monotonic() - self._last_prune > 3600:
                    self._last_prune = time.monotonic()
                    await asyncio.to_thread(self.prune)
                handled = await self.process_due()
                if handled >= self.batch_size:
                    continue
                next_due = await asyncio.to_thread(self._next_due)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                LOGGER.warning(
                    "notification dispatcher iteration failed",
                    extra={"error": type(exc).__name__},
                )
                next_due = None
            wait = 60.0
            if next_due is not None:
                wait = min(max(next_due - self.clock(), 0.05), 60.0)
            try:
                await asyncio.wait_for(self._wake.wait(), timeout=wait)
            except TimeoutError:
                pass

    async def start(self) -> None:
        senders.install_log_redaction()
        self._loop = asyncio.get_running_loop()
        self._wake = asyncio.Event()
        self._task = asyncio.create_task(self.run(), name="mrk-notifications")

    async def stop(self) -> None:
        task, self._task = self._task, None
        if task is not None:
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):  # noqa: S110
                pass
        self._loop = None
