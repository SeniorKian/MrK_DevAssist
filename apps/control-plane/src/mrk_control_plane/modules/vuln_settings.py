"""Settings validation for the vulnerability scanner (docs/32 §4, docs/27 §11)."""

from __future__ import annotations

import copy
import re
import time
from typing import Any
from urllib.parse import urlsplit

from .. import outbound
from .vuln_osv import DEFAULT_FEED_BASE, SUPPORTED_FEEDS, feed_for

NOTIFY_LEVELS = ("critical", "high", "medium", "low")
DEFAULT_SETTINGS: dict[str, Any] = {
    "enabled": True,
    "interval_hours": 24,
    # Feeds downloaded even when no scanned image needs them (e.g. "npm").
    "ecosystems_extra": [],
    # OSV bulk-export base: <base>/<Ecosystem>/all.zip. A local mirror works too.
    "feed_base_url": DEFAULT_FEED_BASE,
    "severities_to_notify": ["critical", "high"],
    "include_stopped": False,
    # Outbound: null = direct, "default" = default proxy, or a proxy id.
    "proxy_id": None,
    # Download cap per feed zip (MiB); uncompressed content is capped at 8x.
    "feed_max_mb": 1024,
}
_KEYS = frozenset(DEFAULT_SETTINGS)
MAX_IGNORES = 500
_PATTERN = re.compile(r"^[^\x00-\x1f\x7f]{1,200}$")


class SettingsError(ValueError):
    def __init__(self, message: str, code: str = "invalid_settings") -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def _bool(payload: dict[str, Any], key: str) -> bool:
    value = payload[key]
    if not isinstance(value, bool):
        raise SettingsError(f"{key} must be a boolean")
    return value


def _int(payload: dict[str, Any], key: str, low: int, high: int) -> int:
    value = payload[key]
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise SettingsError(f"{key} must be an integer between {low} and {high}")
    return value


def validate_base_url(value: object) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > 300:
        raise SettingsError("feed_base_url must be an http(s) URL")
    text = value.strip().rstrip("/")
    parts = urlsplit(text)
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        raise SettingsError("feed_base_url must be an http(s) URL")
    if parts.username or parts.password or "@" in parts.netloc:
        raise SettingsError("feed_base_url must not contain credentials")
    if parts.query or parts.fragment or any(ch.isspace() for ch in text):
        raise SettingsError("feed_base_url must not contain a query or fragment")
    try:
        parts.port  # noqa: B018 - validates the port
    except ValueError as exc:
        raise SettingsError("feed_base_url port is invalid") from exc
    return text


def validate_settings(
    payload: Any, base: dict[str, Any] | None = None, network: Any = None
) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise SettingsError("settings must be a JSON object")
    unknown = set(payload) - _KEYS
    if unknown:
        raise SettingsError(f"unknown settings: {', '.join(sorted(unknown))}")
    merged = copy.deepcopy(base if base is not None else DEFAULT_SETTINGS)
    for key, value in DEFAULT_SETTINGS.items():
        merged.setdefault(key, copy.deepcopy(value))
    merged.update(copy.deepcopy(payload))
    result: dict[str, Any] = {
        "enabled": _bool(merged, "enabled"),
        "include_stopped": _bool(merged, "include_stopped"),
        "interval_hours": _int(merged, "interval_hours", 1, 720),
        "feed_max_mb": _int(merged, "feed_max_mb", 16, 4096),
        "feed_base_url": validate_base_url(merged["feed_base_url"]),
    }
    extra = merged["ecosystems_extra"]
    if not isinstance(extra, list) or len(extra) > len(SUPPORTED_FEEDS):
        raise SettingsError("ecosystems_extra must be a list of ecosystem names")
    feeds: list[str] = []
    for item in extra:
        feed = feed_for(item) if isinstance(item, str) else None
        if feed not in SUPPORTED_FEEDS:
            raise SettingsError(
                f"unsupported ecosystem {str(item)[:40]!r}; supported: {', '.join(SUPPORTED_FEEDS)}"
            )
        if feed not in feeds:
            feeds.append(feed)
    result["ecosystems_extra"] = feeds
    levels = merged["severities_to_notify"]
    if not isinstance(levels, list) or any(level not in NOTIFY_LEVELS for level in levels):
        raise SettingsError(f"severities_to_notify must be a subset of {list(NOTIFY_LEVELS)}")
    result["severities_to_notify"] = [level for level in NOTIFY_LEVELS if level in levels]
    try:
        if network is None:
            result["proxy_id"] = outbound.validate_reference(merged["proxy_id"])
        else:
            result["proxy_id"] = outbound.check_reference(
                network, merged["proxy_id"], outbound.ALL_PROXY_TYPES, "proxy_type_unsupported"
            )
    except outbound.OutboundError as exc:
        raise SettingsError(exc.message, exc.code) from None
    return result


def _pattern(payload: dict[str, Any], key: str, limit: int) -> str | None:
    value = payload.get(key)
    if value is None or (isinstance(value, str) and not value.strip()):
        return None
    if not isinstance(value, str) or len(value) > limit or not _PATTERN.fullmatch(value):
        raise SettingsError(f"{key} must be a pattern of at most {limit} characters",
                            "invalid_ignore")
    return value.strip()


def validate_ignore(payload: Any, now: float | None = None) -> dict[str, Any]:
    """{advisory?, package?, image?, reason, expires_at?} -> normalized rule fields."""
    if not isinstance(payload, dict):
        raise SettingsError("ignore rule must be a JSON object", "invalid_ignore")
    unknown = set(payload) - {"advisory", "package", "image", "reason", "expires_at"}
    if unknown:
        raise SettingsError(f"unknown fields: {', '.join(sorted(unknown))}", "invalid_ignore")
    advisory = _pattern(payload, "advisory", 128)
    package = _pattern(payload, "package", 200)
    image = _pattern(payload, "image", 255)
    if advisory is None and package is None:
        raise SettingsError("give an advisory id/pattern or a package pattern", "invalid_ignore")
    reason = payload.get("reason")
    if not isinstance(reason, str) or not reason.strip() or len(reason) > 500:
        raise SettingsError("reason is required (1-500 characters)", "invalid_ignore")
    expires_at = payload.get("expires_at")
    current = time.time() if now is None else now
    if expires_at is not None:
        if (
            isinstance(expires_at, bool)
            or not isinstance(expires_at, int | float)
            or expires_at <= current
            or expires_at > current + 5 * 366 * 86400
        ):
            raise SettingsError(
                "expires_at must be a future unix time (at most 5 years ahead)", "invalid_ignore"
            )
        expires_at = int(expires_at)
    return {
        "advisory": advisory,
        "package": package,
        "image": image,
        "reason": reason.strip(),
        "expires_at": expires_at,
    }
