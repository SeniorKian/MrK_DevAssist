"""Settings validation for image update tracking (docs/31 §5, docs/27 §10).

Everything is operator-configurable; PUT merges into the current settings.
"""

from __future__ import annotations

import copy
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from .. import outbound
from .updates_refs import DOCKER_HUB, DOCKER_HUB_API, normalize_registry

DEFAULT_SETTINGS: dict[str, Any] = {
    "enabled": True,
    "interval_hours": 12,
    "ignore": [],
    "include_stopped": False,
    "notify": True,
    # Outbound: null = direct, "default" = default proxy, or a proxy id.
    "proxy_id": None,
    # Per logical registry or endpoint host: overrides proxy_id.
    "registry_proxies": {},
    # Logical registry -> ordered mirror endpoints, e.g.
    # {"docker.io": ["docker.arvancloud.ir"]}. Each endpoint is host[:port], or an
    # http(s) URL with an optional path prefix (https://registry.example.com/ghcr.io).
    "mirrors": {},
    # After every mirror failed, also try the origin registry.
    "mirror_fallback": True,
    # Registries spoken to over plain HTTP (local/LAN registries).
    "insecure_registries": [],
    # Registries without Docker-Content-Digest on HEAD may be GET-hashed instead
    # (never against registry-1.docker.io, where a GET costs pull quota).
    "allow_get_fallback": True,
    "timeout_seconds": 15,
    "concurrency": 4,
}

_KEYS = frozenset(DEFAULT_SETTINGS)
_HOST = re.compile(
    r"^(?:localhost|[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*"
    r"|\[[0-9a-f:.]+\])(?::[0-9]{1,5})?$"
)
_PREFIX = re.compile(r"^[a-z0-9._-]+(?:/[a-z0-9._-]+)*$")
MAX_IGNORE = 100
MAX_REGISTRIES = 32
MAX_MIRRORS = 5


class SettingsError(ValueError):
    def __init__(self, message: str, code: str = "invalid_settings") -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True, slots=True)
class Endpoint:
    """Where manifests are asked for: scheme://netloc/v2/<prefix/><repo>/manifests/<tag>."""

    scheme: str
    netloc: str
    prefix: str = ""
    mirror: bool = False

    @property
    def host(self) -> str:
        return self.netloc

    @property
    def label(self) -> str:
        base = self.netloc if self.scheme == "https" else f"{self.scheme}://{self.netloc}"
        return f"{base}/{self.prefix}" if self.prefix else base

    def repository(self, repository: str) -> str:
        return f"{self.prefix}/{repository}" if self.prefix else repository

    def manifest_url(self, repository: str, reference: str) -> str:
        return f"{self.scheme}://{self.netloc}/v2/{self.repository(repository)}/manifests/{reference}"


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


def validate_registry_key(value: object) -> str:
    if not isinstance(value, str):
        raise SettingsError("registry names must be strings")
    host = normalize_registry(value)
    if not _HOST.fullmatch(host) or len(host) > 255:
        raise SettingsError(f"invalid registry host: {value[:80]!r}")
    return host


def parse_endpoint(value: object) -> str:
    """Validate and normalise one mirror endpoint to its stored text form."""
    if not isinstance(value, str) or not value.strip() or len(value) > 300:
        raise SettingsError("mirror endpoints must be non-empty strings")
    text = value.strip().rstrip("/")
    if "://" not in text:
        text = f"https://{text}"
    parts = urlsplit(text)
    if parts.scheme not in {"http", "https"}:
        raise SettingsError("mirror endpoints must use http or https")
    if parts.username or parts.password or "@" in parts.netloc:
        raise SettingsError("mirror endpoints must not contain credentials")
    if parts.query or parts.fragment:
        raise SettingsError("mirror endpoints must not contain a query or fragment")
    netloc = parts.netloc.lower()
    try:
        port = parts.port
    except ValueError as exc:
        raise SettingsError("mirror endpoint port is invalid") from exc
    if not _HOST.fullmatch(netloc) or (port is not None and not 0 < port < 65536):
        raise SettingsError(f"invalid mirror host: {value[:80]!r}")
    prefix = parts.path.strip("/").lower()
    if prefix and (not _PREFIX.fullmatch(prefix) or ".." in prefix.split("/")):
        raise SettingsError("invalid mirror path prefix")
    if prefix.startswith("v2"):
        raise SettingsError("give the mirror base URL without /v2")
    stored = netloc if parts.scheme == "https" else f"http://{netloc}"
    return f"{stored}/{prefix}" if prefix else stored


def endpoint_from_text(text: str, *, mirror: bool) -> Endpoint:
    full = text if "://" in text else f"https://{text}"
    parts = urlsplit(full)
    return Endpoint(parts.scheme, parts.netloc, parts.path.strip("/"), mirror)


def origin_endpoint(registry: str, settings: dict[str, Any]) -> Endpoint:
    netloc = DOCKER_HUB_API if registry == DOCKER_HUB else registry
    scheme = "http" if registry in settings.get("insecure_registries", []) else "https"
    return Endpoint(scheme, netloc)


def endpoints_for(registry: str, settings: dict[str, Any]) -> list[Endpoint]:
    mirrors = [
        endpoint_from_text(item, mirror=True) for item in settings["mirrors"].get(registry, [])
    ]
    if not mirrors or settings["mirror_fallback"]:
        mirrors.append(origin_endpoint(registry, settings))
    return mirrors


def proxy_for(registry: str, endpoint: Endpoint, settings: dict[str, Any]) -> str | None:
    overrides = settings["registry_proxies"]
    for key in (endpoint.netloc, registry):
        if key in overrides:
            return overrides[key]
    return settings["proxy_id"]


def validate_settings(
    payload: Any,
    base: dict[str, Any] | None = None,
    network: Any = None,
) -> dict[str, Any]:
    """Merge ``payload`` into ``base`` (defaults) and validate the whole result.

    ``network`` (NetworkSettingsStore) enables proxy existence checks on save.
    """
    if not isinstance(payload, dict):
        raise SettingsError("settings must be a JSON object")
    unknown = set(payload) - _KEYS
    if unknown:
        raise SettingsError(f"unknown settings: {', '.join(sorted(unknown))}")
    merged = copy.deepcopy(base if base is not None else DEFAULT_SETTINGS)
    for key, value in DEFAULT_SETTINGS.items():
        merged.setdefault(key, copy.deepcopy(value))
    merged.update(copy.deepcopy(payload))
    result: dict[str, Any] = {}
    for key in ("enabled", "include_stopped", "notify", "mirror_fallback", "allow_get_fallback"):
        result[key] = _bool(merged, key)
    result["interval_hours"] = _int(merged, "interval_hours", 1, 720)
    result["timeout_seconds"] = _int(merged, "timeout_seconds", 3, 120)
    result["concurrency"] = _int(merged, "concurrency", 1, 16)

    ignore = merged["ignore"]
    if not isinstance(ignore, list) or len(ignore) > MAX_IGNORE:
        raise SettingsError(f"ignore must be a list of at most {MAX_IGNORE} patterns")
    patterns: list[str] = []
    for item in ignore:
        if not isinstance(item, str) or not item.strip() or len(item) > 200:
            raise SettingsError("ignore patterns must be 1-200 character strings")
        if any(ord(ch) < 32 for ch in item):
            raise SettingsError("ignore patterns must not contain control characters")
        if item.strip() not in patterns:
            patterns.append(item.strip())
    result["ignore"] = patterns

    insecure = merged["insecure_registries"]
    if not isinstance(insecure, list) or len(insecure) > MAX_REGISTRIES:
        raise SettingsError("insecure_registries must be a list of registry hosts")
    result["insecure_registries"] = sorted({validate_registry_key(item) for item in insecure})
    if DOCKER_HUB in result["insecure_registries"]:
        raise SettingsError("docker.io cannot be an insecure registry")

    mirrors = merged["mirrors"]
    if not isinstance(mirrors, dict) or len(mirrors) > MAX_REGISTRIES:
        raise SettingsError("mirrors must map registry hosts to endpoint lists")
    normalized_mirrors: dict[str, list[str]] = {}
    for registry, endpoints in mirrors.items():
        key = validate_registry_key(registry)
        if isinstance(endpoints, str):
            endpoints = [endpoints]
        if not isinstance(endpoints, list) or len(endpoints) > MAX_MIRRORS:
            raise SettingsError(f"each registry takes at most {MAX_MIRRORS} mirror endpoints")
        values: list[str] = []
        for endpoint in endpoints:
            text = parse_endpoint(endpoint)
            if text not in values:
                values.append(text)
        if values:
            normalized_mirrors[key] = values
    result["mirrors"] = normalized_mirrors

    result["proxy_id"] = _reference(merged["proxy_id"], network)
    overrides = merged["registry_proxies"]
    if not isinstance(overrides, dict) or len(overrides) > MAX_REGISTRIES * 2:
        raise SettingsError("registry_proxies must map registry hosts to proxy references")
    result["registry_proxies"] = {
        validate_registry_key(key): _reference(value, network) for key, value in overrides.items()
    }
    return result


def _reference(value: object, network: Any) -> str | None:
    try:
        if network is None:
            return outbound.validate_reference(value)
        return outbound.check_reference(
            network, value, outbound.ALL_PROXY_TYPES, "proxy_type_unsupported"
        )
    except outbound.OutboundError as exc:
        raise SettingsError(exc.message, exc.code) from None
