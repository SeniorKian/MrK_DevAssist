"""Settings of the services/domains module (docs/35), stored in ``system_settings``.

Value precedence for every key: panel value > environment variable (where one is
listed in ``ENV_DEFAULTS``) > built-in default. Nothing is forced: every sync and
routing behaviour has its own switch.
"""

from __future__ import annotations

import copy
import ipaddress
import os
import re
import time
from typing import Any

from ..database import Database
from ..models import SystemSetting

SETTINGS_KEY = "services.settings"
STATE_KEY = "services.state"
ROUTING_MODES = ("auto", "dokploy_api", "traefik_file", "manual")
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
MIDDLEWARE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}(@[a-z]{1,16})?$")
TARGET_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,62}$")

DEFAULT_SETTINGS: dict[str, Any] = {
    "routing_mode": "auto",
    "traefik_file_enabled": False,
    "cert_resolver": "letsencrypt",
    "entrypoint_web": "web",
    "entrypoint_websecure": "websecure",
    "redirect_middleware": "redirect-to-https@file",
    "target_host": "",
    "self_container": "",
    "dokploy_network": "dokploy-network",
    "verify_interval_seconds": 21600,
    "tls_expiry_warning_days": 14,
    "server_public_ips": [],
    "conflict_check_budget": 20,
    "sync_panel_trusted_hosts": True,
    "sync_pypi_outside_url": True,
    "sync_pypi_restart": True,
    "sync_s3_endpoint": True,
    "auto_restart": True,
    "restart_base_delay_seconds": 30,
    "restart_max_delay_seconds": 900,
}

ENV_DEFAULTS: dict[str, str] = {
    "routing_mode": "MRK_DOMAINS_ROUTING_MODE",
    "traefik_file_enabled": "MRK_DOMAINS_TRAEFIK_FILE_ENABLED",
    "cert_resolver": "MRK_DOMAINS_CERT_RESOLVER",
    "target_host": "MRK_DOMAINS_TARGET_HOST",
    "verify_interval_seconds": "MRK_DOMAINS_VERIFY_INTERVAL_SECONDS",
    "server_public_ips": "MRK_SERVER_PUBLIC_IPS",
    "auto_restart": "MRK_SERVICES_AUTO_RESTART",
}


class SettingsError(ValueError):
    def __init__(self, code: str, message: str, status_code: int = 422) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code


def _bool(value: Any, key: str) -> bool:
    if not isinstance(value, bool):
        raise SettingsError("invalid_settings", f"{key} must be true or false")
    return value


def _int(value: Any, key: str, low: int, high: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise SettingsError("invalid_settings", f"{key} must be a whole number {low}..{high}")
    return value


def _pattern(value: Any, key: str, pattern: re.Pattern[str], allow_empty: bool = False) -> str:
    if allow_empty and value in ("", None):
        return ""
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise SettingsError("invalid_settings", f"{key} has an invalid format")
    return value


def _ips(value: Any) -> list[str]:
    if isinstance(value, str):
        value = [item for item in value.split(",") if item.strip()]
    if not isinstance(value, list) or len(value) > 32:
        raise SettingsError("invalid_settings", "server_public_ips must be a list of IPs")
    result: list[str] = []
    for item in value:
        try:
            text = str(ipaddress.ip_address(str(item).strip()))
        except ValueError:
            raise SettingsError(
                "invalid_settings", f"{str(item)[:60]!r} is not an IP address"
            ) from None
        if text not in result:
            result.append(text)
    return result


def validate(payload: Any, current: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise SettingsError("invalid_settings", "settings must be a JSON object")
    unknown = set(payload) - set(DEFAULT_SETTINGS)
    if unknown:
        raise SettingsError("invalid_settings", f"unknown setting(s): {', '.join(sorted(unknown))}")
    merged = dict(current)
    for key, value in payload.items():
        if key == "routing_mode":
            if value not in ROUTING_MODES:
                raise SettingsError("invalid_settings", "routing_mode is not a known mode")
            merged[key] = value
        elif key in {
            "traefik_file_enabled",
            "sync_panel_trusted_hosts",
            "sync_pypi_outside_url",
            "sync_pypi_restart",
            "sync_s3_endpoint",
            "auto_restart",
        }:
            merged[key] = _bool(value, key)
        elif key in {"cert_resolver", "entrypoint_web", "entrypoint_websecure", "dokploy_network"}:
            merged[key] = _pattern(value, key, NAME_RE)
        elif key == "redirect_middleware":
            merged[key] = _pattern(value, key, MIDDLEWARE_RE, allow_empty=True)
        elif key in {"target_host", "self_container"}:
            merged[key] = _pattern(value, key, TARGET_RE, allow_empty=True)
        elif key == "verify_interval_seconds":
            merged[key] = _int(value, key, 0, 7 * 86400)
            if 0 < merged[key] < 300:
                raise SettingsError("invalid_settings", "verify interval must be 0 or >= 300")
        elif key == "tls_expiry_warning_days":
            merged[key] = _int(value, key, 1, 90)
        elif key == "conflict_check_budget":
            merged[key] = _int(value, key, 0, 200)
        elif key == "server_public_ips":
            merged[key] = _ips(value)
        elif key == "restart_base_delay_seconds":
            merged[key] = _int(value, key, 5, 3600)
        elif key == "restart_max_delay_seconds":
            merged[key] = _int(value, key, 60, 86400)
    if merged.get("restart_max_delay_seconds", 900) < merged.get("restart_base_delay_seconds", 30):
        raise SettingsError(
            "invalid_settings", "the longest wait must not be shorter than the first wait"
        )
    return merged


def _env_value(key: str) -> Any:
    name = ENV_DEFAULTS.get(key)
    raw = os.getenv(name, "").strip() if name else ""
    if not raw:
        return None
    default = DEFAULT_SETTINGS[key]
    try:
        if isinstance(default, bool):
            return raw.lower() in {"1", "true", "yes", "on"}
        if isinstance(default, int):
            return int(raw)
        if isinstance(default, list):
            return [item.strip() for item in raw.split(",") if item.strip()]
    except ValueError:
        return None
    return raw


class SettingsStore:
    def __init__(self, database: Database) -> None:
        self.database = database

    def _stored(self, key: str) -> dict[str, Any]:
        with self.database.session() as db:
            row = db.get(SystemSetting, key)
            return dict(row.value) if row is not None and isinstance(row.value, dict) else {}

    def _put(self, key: str, value: dict[str, Any], actor: int | None) -> None:
        now = int(time.time())
        with self.database.session() as db, db.begin():
            row = db.get(SystemSetting, key)
            if row is None:
                db.add(
                    SystemSetting(key=key, value=value, updated_at=now, updated_by_user_id=actor)
                )
            else:
                row.value = value
                row.updated_at = now
                row.updated_by_user_id = actor

    def get_settings(self) -> dict[str, Any]:
        effective = copy.deepcopy(DEFAULT_SETTINGS)
        for key in DEFAULT_SETTINGS:
            env = _env_value(key)
            if env is None:
                continue
            try:
                effective.update(validate({key: env}, effective))
            except SettingsError:
                continue
        stored = self._stored(SETTINGS_KEY)
        for key, value in stored.items():
            if key in DEFAULT_SETTINGS:
                try:
                    effective.update(validate({key: value}, effective))
                except SettingsError:
                    continue
        return effective

    def put_settings(self, payload: Any, actor_user_id: int | None) -> dict[str, Any]:
        merged = validate(payload, self.get_settings())
        stored = self._stored(SETTINGS_KEY)
        stored.update({key: merged[key] for key in payload})
        self._put(SETTINGS_KEY, stored, actor_user_id)
        return self.get_settings()

    # Internal state (not a setting): values MRK wrote on its own, e.g. S3 endpoint.
    def state(self) -> dict[str, Any]:
        return self._stored(STATE_KEY)

    def save_state(self, value: dict[str, Any]) -> None:
        self._put(STATE_KEY, value, None)
