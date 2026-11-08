"""Settings registry: one typed, described entry for every tunable of MRK.

The registry is descriptive (docs/33 §4.3, docs/27 §1.6). Each entry says where a
value lives and how to change it:

* ``runtime``  – owned by a module's settings store; read and written through that
  module (its own validator still runs). Applies without a restart.
* ``startup``  – an ``MRK_*`` environment variable. The panel may write it to
  ``data_dir/control-plane/settings-overrides.json`` (mode 0600) when the entry is
  ``overridable``; an explicit environment variable always wins
  (``locked_by_env``). Needs a restart of the listed processes.
* ``build``    – image build argument / build metadata, read-only.
* ``constant`` – still hard-coded; shown read-only so Advanced mode is honest.

Entries live in ``settings_registry_entries_*.py``; the HTTP API is in
``settings_registry_api.py``.
"""

from __future__ import annotations

import ipaddress
import json
import math
import os
import re
import secrets
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from . import config

TYPES = frozenset(
    {
        "bool", "int", "float", "string", "enum", "list", "duration", "bytes", "secret",
        "cidr_list", "url", "path", "time", "timezone", "map", "ref",
    }
)
SOURCES = ("runtime", "startup", "build", "constant")
DANGERS = ("none", "low", "medium", "high", "critical")
STARTUP_WRITE_PERMISSION = "settings:write"  # owner only (no built-in role grants it)
STARTUP_READ_PERMISSION = "system:read"

# Why a startup value cannot be written from the panel (UI shows the matching text).
ENV_ONLY_REASONS: dict[str, tuple[str, str]] = {
    "bootstrap": (
        "این مقدار جای فایل تنظیمات را مشخص می‌کند؛ فقط از Compose تغییر می‌کند.",
        "Locates the settings file itself; change it in Compose only.",
    ),
    "secret": (
        "رمز است و در فایل تنظیمات پنل نوشته نمی‌شود؛ آن را با Compose یا secret بدهید.",
        "A secret is never written to the panel's settings file; use Compose or a secret.",
    ),
    "compose": (
        "مربوط به خود Compose یا Docker است؛ در فایل Compose عوض کنید.",
        "Belongs to Compose/Docker itself; change it in the compose file.",
    ),
    "other_container": (
        "این تنظیم مال یک کانتینر جداست (Agent یا فایروال)؛ در Compose همان کانتینر عوض کنید.",
        "Belongs to a separate container (agent or firewall helper); set it in its Compose.",
    ),
    "shell_script": (
        "اسکریپت شروع devpi فقط متغیر محیطی را می‌خواند؛ در Compose عوض کنید.",
        "The devpi start script reads only the environment; change it in Compose.",
    ),
    "separate_process": (
        "یک ابزار جدا (healthcheck، restore یا CLI) آن را می‌خواند که فایل پنل را نمی‌بیند.",
        "Read by a separate tool (healthcheck, restore, CLI) that does not see the panel file.",
    ),
    "path": (
        "مسیر داخل کانتینر است؛ تغییر اشتباه آن داده را گم می‌کند. فقط از Compose.",
        "A path inside the container; a wrong value loses data. Compose only.",
    ),
    "lockout": (
        "تغییر اشتباه آن پنل را از دسترس خارج می‌کند؛ فقط از Compose.",
        "A wrong value makes the panel unreachable; Compose only.",
    ),
    "build": (
        "هنگام ساخت image خوانده می‌شود.",
        "Read when the image is built.",
    ),
    "managed_elsewhere": (
        "از صفحه خودش تنظیم می‌شود (اتصال با کلید).",
        "Configured from its own page (pairing with a key).",
    ),
}


class SettingError(Exception):
    def __init__(self, code: str, message: str, status_code: int = 422) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code


@dataclass(frozen=True, slots=True)
class SettingSpec:
    key: str
    group: str
    type: str
    default: Any
    label_fa: str
    label_en: str
    description_fa: str
    description_en: str
    source: str = "startup"
    env: str | None = None
    min: float | None = None
    max: float | None = None
    step: float | None = None
    enum: tuple[str, ...] | None = None
    unit: str | None = None
    restart_required: bool = False
    danger: str = "low"
    read_permission: str = STARTUP_READ_PERMISSION
    write_permission: str | None = None
    depends_on: tuple[dict[str, Any], ...] = ()
    secret: bool = False
    overridable: bool = False
    env_only_reason: str | None = None
    processes: tuple[str, ...] = ()
    module: str | None = None
    path: tuple[str, ...] = ()
    edit_in: str | None = None
    item_type: str | None = None  # element type of list values ("int", "cidr", ...)
    nullable: bool = False
    max_items: int | None = None
    validator: str | None = None  # name of an extra check in VALIDATORS

    @property
    def editable(self) -> bool:
        if self.source == "runtime":
            return self.write_permission is not None and self.edit_in is None
        if self.source == "startup":
            return self.overridable and self.write_permission is not None
        return False

    def schema(self) -> dict[str, Any]:
        reason = ENV_ONLY_REASONS.get(self.env_only_reason or "")
        return {
            "key": self.key,
            "group": self.group,
            "type": self.type,
            "item_type": self.item_type,
            "default": None if self.secret else self.default,
            "min": self.min,
            "max": self.max,
            "step": self.step,
            "enum": list(self.enum) if self.enum else None,
            "unit": self.unit,
            "nullable": self.nullable,
            "max_items": self.max_items,
            "source": self.source,
            "env": self.env,
            "restart_required": self.restart_required,
            "processes": list(self.processes),
            "danger": self.danger,
            "requires": self.write_permission,
            "read_permission": self.read_permission,
            "depends_on": list(self.depends_on),
            "secret": self.secret,
            "overridable": self.overridable,
            "env_only_reason": self.env_only_reason,
            "env_only_note": (
                {"fa": reason[0], "en": reason[1]} if reason and not self.editable else None
            ),
            "edit_in": self.edit_in,
            "label": {"fa": self.label_fa, "en": self.label_en},
            "description": {"fa": self.description_fa, "en": self.description_en},
            # Flat aliases (task contract): description_fa / description_en.
            "description_fa": self.description_fa,
            "description_en": self.description_en,
        }


@dataclass(frozen=True, slots=True)
class Group:
    id: str
    name_fa: str
    name_en: str
    nav: str


GROUPS: tuple[Group, ...] = (
    Group("system", "سامانه و اجرا", "System & runtime", "about"),
    Group("people.security", "ورود و امنیت حساب‌ها", "Sign-in & security", "people/security"),
    Group("packages.npm", "مخزن npm", "npm registry", "packages/sources"),
    Group("packages.pypi", "مخزن PyPI", "PyPI registry", "packages/sources"),
    Group(
        "packages.sources", "منابع، حافظه و نگهداری", "Sources, cache & upkeep", "packages/sources"
    ),
    Group("security.network", "اینترنت، DNS و پروکسی", "Internet, DNS & proxy", "security/network"),
    Group("server.overview", "سرور، Agent و لاگ", "Server, agent & logs", "server/overview"),
    Group("server.resources", "مصرف منابع سرور", "Server resource use", "server/resources"),
    Group("server.apps", "برنامه‌های Dokploy", "Dokploy apps", "server/apps"),
    Group("server.updates", "نسخه تازه برنامه‌ها", "Image updates", "server/updates"),
    Group("server.databases", "دیتابیس‌ها", "Databases", "server/databases"),
    Group("files.space", "فضای فایل (S3)", "File space (S3)", "files/space"),
    Group("files.backups", "پشتیبان برنامه‌ها", "App backups", "files/backups"),
    Group("security.firewall", "فایروال", "Firewall", "security/firewall"),
    Group("security.vuln", "آسیب‌پذیری‌ها", "Vulnerabilities", "security/vuln"),
    Group("alerts", "اعلان‌ها", "Alerts", "alerts/rules"),
)
GROUP_IDS = tuple(group.id for group in GROUPS)


@dataclass(slots=True)
class Registry:
    specs: dict[str, SettingSpec] = field(default_factory=dict)

    def add(self, *items: SettingSpec) -> None:
        for item in items:
            _check_spec(item)
            if item.key in self.specs:
                raise ValueError(f"duplicate setting key {item.key}")
            self.specs[item.key] = item

    def get(self, key: str) -> SettingSpec:
        try:
            return self.specs[key]
        except KeyError:
            raise SettingError("unknown_setting", f"unknown setting {key}", 404) from None

    def by_env(self) -> dict[str, SettingSpec]:
        return {spec.env: spec for spec in self.specs.values() if spec.env}

    def startup(self) -> list[SettingSpec]:
        return [spec for spec in self.specs.values() if spec.source == "startup" and spec.env]


def _check_spec(spec: SettingSpec) -> None:
    if spec.type not in TYPES:
        raise ValueError(f"{spec.key}: unknown type {spec.type}")
    if spec.source not in SOURCES:
        raise ValueError(f"{spec.key}: unknown source {spec.source}")
    if spec.group not in GROUP_IDS:
        raise ValueError(f"{spec.key}: unknown group {spec.group}")
    if spec.danger not in DANGERS:
        raise ValueError(f"{spec.key}: unknown danger {spec.danger}")
    if spec.type == "enum" and not spec.enum:
        raise ValueError(f"{spec.key}: enum without values")
    if spec.source == "runtime" and not spec.module:
        raise ValueError(f"{spec.key}: runtime setting without a module")
    if spec.source == "startup" and not spec.env:
        raise ValueError(f"{spec.key}: startup setting without an env name")
    if spec.overridable and (spec.secret or spec.env in config.BOOTSTRAP_ENV_NAMES):
        raise ValueError(f"{spec.key}: secrets and bootstrap names cannot be overridable")
    if not (spec.label_fa and spec.label_en and spec.description_fa and spec.description_en):
        raise ValueError(f"{spec.key}: missing label or description")


# ---- typed values ---------------------------------------------------------------

_TRUE = {"1", "true", "yes", "on"}
_FALSE = {"0", "false", "no", "off"}
_HHMM = re.compile(r"^([01]\d|2[0-3]):[0-5]\d$")


def _fail(spec: SettingSpec, message: str) -> SettingError:
    return SettingError("invalid_setting_value", f"{spec.key}: {message}")


def _number(spec: SettingSpec, value: Any, *, integer: bool) -> int | float:
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise _fail(spec, "must be a number")
    if isinstance(value, float) and not math.isfinite(value):
        raise _fail(spec, "must be a finite number")
    if integer:
        if isinstance(value, float):
            if not value.is_integer():
                raise _fail(spec, "must be a whole number")
            value = int(value)
    else:
        value = float(value)
    if spec.min is not None and value < spec.min:
        raise _fail(spec, f"must be at least {_fmt(spec.min)}")
    if spec.max is not None and value > spec.max:
        raise _fail(spec, f"must be at most {_fmt(spec.max)}")
    return value


def _fmt(value: float) -> str:
    return str(int(value)) if float(value).is_integer() else str(value)


def _url(spec: SettingSpec, value: Any) -> str:
    if not isinstance(value, str) or len(value) > 2048 or any(ch.isspace() for ch in value):
        raise _fail(spec, "must be an http(s) URL")
    parts = urlsplit(value.strip())
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        raise _fail(spec, "must be an http(s) URL")
    if parts.username or parts.password:
        raise _fail(spec, "must not contain credentials")
    return value.strip()


def _list_item(spec: SettingSpec, item: Any) -> Any:
    kind = spec.item_type or "string"
    if kind == "int":
        return _number(spec, item, integer=True)
    if not isinstance(item, str) or not item.strip() or len(item) > 512:
        raise _fail(spec, "items must be non-empty strings")
    text = item.strip()
    if any(ord(ch) < 32 for ch in text):
        raise _fail(spec, "items must not contain control characters")
    if kind == "cidr":
        try:
            ipaddress.ip_network(text, strict=False)
        except ValueError:
            raise _fail(spec, f"{text[:60]!r} is not an IP address or CIDR") from None
    if kind in {"string", "cidr"} and spec.source == "startup" and "," in text:
        raise _fail(spec, "items must not contain commas")
    if spec.enum and text not in spec.enum:
        raise _fail(spec, f"{text[:60]!r} is not one of {', '.join(spec.enum)}")
    return text


def coerce(spec: SettingSpec, value: Any) -> Any:
    """Validate a JSON value against the spec and return its canonical form."""
    if value is None:
        if spec.nullable:
            return None
        raise _fail(spec, "a value is required")
    kind = spec.type
    if kind == "bool":
        if not isinstance(value, bool):
            raise _fail(spec, "must be true or false")
        result: Any = value
    elif kind in {"int", "duration", "bytes"}:
        result = _number(spec, value, integer=True)
    elif kind == "float":
        result = _number(spec, value, integer=False)
    elif kind == "enum":
        if not isinstance(value, str) or value not in (spec.enum or ()):
            raise _fail(spec, f"must be one of {', '.join(spec.enum or ())}")
        result = value
    elif kind in {"list", "cidr_list"}:
        if isinstance(value, str):
            value = [part for part in value.split(",") if part.strip()]
        if not isinstance(value, list):
            raise _fail(spec, "must be a list")
        if spec.max_items is not None and len(value) > spec.max_items:
            raise _fail(spec, f"at most {spec.max_items} items")
        if kind == "cidr_list" and spec.item_type is None:
            spec = _with_item(spec, "cidr")
        items: list[Any] = []
        for item in value:
            normalized = _list_item(spec, item)
            if normalized not in items:
                items.append(normalized)
        result = items
    elif kind == "url":
        result = _url(spec, value)
    elif kind == "time":
        if not isinstance(value, str) or not _HHMM.match(value):
            raise _fail(spec, "must be HH:MM")
        result = value
    elif kind == "timezone":
        try:
            ZoneInfo(str(value))
        except (ZoneInfoNotFoundError, ValueError):
            raise _fail(spec, "unknown time zone") from None
        result = str(value)
    elif kind == "map":
        if not isinstance(value, dict):
            raise _fail(spec, "must be an object")
        result = value
    else:  # string, path, ref, secret
        if not isinstance(value, str) or len(value) > 4096:
            raise _fail(spec, "must be text of at most 4096 characters")
        if any(ord(ch) < 32 for ch in value):
            raise _fail(spec, "must not contain control characters")
        if kind == "path" and value.strip() and not value.strip().startswith("/"):
            raise _fail(spec, "must be an absolute path")
        if spec.enum and value not in spec.enum:
            raise _fail(spec, f"must be one of {', '.join(spec.enum)}")
        result = value.strip() if kind != "secret" else value
    check = VALIDATORS.get(spec.validator or "")
    if check is not None:
        check(spec, result)
    return result


def _with_item(spec: SettingSpec, item_type: str) -> SettingSpec:
    from dataclasses import replace

    return replace(spec, item_type=item_type)


def _loopback(spec: SettingSpec, value: Any) -> None:
    try:
        if ipaddress.ip_address(str(value)).is_loopback:
            return
    except ValueError:
        pass
    raise _fail(spec, "must be a loopback IP address (127.0.0.1 or ::1)")


def _keeps_local_host(spec: SettingSpec, value: Any) -> None:
    hosts = set(value or ())
    if not hosts & {"localhost", "127.0.0.1"}:
        raise _fail(spec, "must keep localhost or 127.0.0.1 (the container healthcheck uses it)")


def _no_wildcard(spec: SettingSpec, value: Any) -> None:
    if "*" in (value or ()):
        raise _fail(spec, "wildcards are not allowed")


def _trusted_hosts(spec: SettingSpec, value: Any) -> None:
    _no_wildcard(spec, value)
    _keeps_local_host(spec, value)


def _host_port(spec: SettingSpec, value: Any) -> None:
    host, sep, port = str(value).rpartition(":")
    if not sep or not host or not port.isdigit() or not 1 <= int(port) <= 65535:
        raise _fail(spec, "must be host:port")


def _regex(spec: SettingSpec, value: Any) -> None:
    try:
        re.compile(str(value))
    except re.error:
        raise _fail(spec, "is not a valid regular expression") from None


VALIDATORS = {
    "loopback": _loopback,
    "keeps_local_host": _keeps_local_host,
    "no_wildcard": _no_wildcard,
    "trusted_hosts": _trusted_hosts,
    "host_port": _host_port,
    "regex": _regex,
}


def to_env_text(spec: SettingSpec, value: Any) -> str:
    """Serialize a canonical value the way an operator would write it in Compose."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, list):
        return ",".join(str(item) for item in value)
    if isinstance(value, float) and value.is_integer() and spec.type != "float":
        return str(int(value))
    return "" if value is None else str(value)


def from_env_text(spec: SettingSpec, text: str | None) -> Any:
    """Parse an environment string for display; unparsable text is shown as is."""
    if text is None:
        return spec.default
    raw = text.strip()
    kind = spec.type
    try:
        if kind == "bool":
            if raw.lower() in _TRUE:
                return True
            if raw.lower() in _FALSE:
                return False
            return raw
        if kind in {"int", "duration", "bytes"}:
            return int(float(raw)) if raw else spec.default
        if kind == "float":
            return float(raw) if raw else spec.default
    except ValueError:
        return raw
    if kind in {"list", "cidr_list"}:
        items = [part.strip() for part in raw.split(",") if part.strip()]
        if spec.item_type == "int":
            try:
                return [int(item) for item in items]
            except ValueError:
                return items
        return items
    return raw


# ---- startup overrides file -------------------------------------------------------


class OverridesFile:
    """``settings-overrides.json``: {"version": 1, "values": {...}, "updated_at", "updated_by"}."""

    def __init__(self, data_dir: Path) -> None:
        self.path = config.overrides_path(data_dir)

    def values(self) -> dict[str, str]:
        return config.load_overrides(self.path)

    def write(self, values: dict[str, str], actor_user_id: int | None) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        payload = {
            "version": 1,
            "values": dict(sorted(values.items())),
            "updated_at": int(time.time()),
            "updated_by": actor_user_id,
        }
        temporary = self.path.with_name(f".{self.path.name}.{secrets.token_hex(4)}.tmp")
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, indent=2) + "\n")
        os.replace(temporary, self.path)
        try:
            self.path.chmod(0o600)
        except OSError:
            pass


def resolve_startup(
    spec: SettingSpec, overrides: dict[str, str]
) -> tuple[str | None, str]:
    """(text, effective_source) for a startup spec: env | override | default."""
    assert spec.env is not None
    if spec.env.endswith("*"):
        prefix = spec.env[:-1]
        present = any(
            name.startswith(prefix) and config.explicit_env(name) is not None
            for name in os.environ
        )
        return ("configured" if present else None), ("env" if present else "default")
    default = None if spec.default is None else to_env_text(spec, spec.default)
    text, source = config.resolve_env(spec.env, default, overrides=overrides)
    if source == "image":
        source = "default"
    return text, source


def load_registry() -> Registry:
    from . import settings_registry_entries_runtime, settings_registry_entries_startup

    registry = Registry()
    registry.add(*settings_registry_entries_startup.ENTRIES)
    registry.add(*settings_registry_entries_runtime.ENTRIES)
    return registry


_REGISTRY: Registry | None = None


def registry() -> Registry:
    global _REGISTRY
    if _REGISTRY is None:
        _REGISTRY = load_registry()
    return _REGISTRY
