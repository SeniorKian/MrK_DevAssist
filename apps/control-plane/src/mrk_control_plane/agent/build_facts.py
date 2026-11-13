"""Read-only facts for the build-mirror health page (docs/48).

Two fixed files below the read-only host root, size-capped, parsed and reduced to
whitelisted fields (never raw contents):

* ``/etc/docker/daemon.json`` - only ``registry-mirrors``;
* ``/etc/devassist/build-mirror.json`` - the marker ``devassist-build-mirror.sh`` writes.

Docker's own view (``/info`` mirrors, the ``mrk-mirror`` builder container) is added
by the route in ``app.py``.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .dns_facts import _read_text, resolve_in_root

MARKER_PATH = "etc/devassist/build-mirror.json"
DAEMON_PATH = "etc/docker/daemon.json"
BUILDER_CONTAINER = "buildx_buildkit_mrk-mirror0"
MAX_ITEMS = 16
_TEXT = re.compile(r"^[A-Za-z0-9 ._:/@+=,-]{0,200}$")
MARKER_FIELDS = {
    "version": str, "applied_at": int, "registry": str, "npm_url": str, "pypi_url": str,
    "buildkit_file": str, "daemon_mirror": bool,
    "daemon_reloaded": bool, "restart_needed": bool, "test": str, "test_detail": str,
    "docker_version": str,
}


def _url(value: Any) -> str | None:
    if not isinstance(value, str) or len(value) > 300:
        return None
    parts = urlsplit(value.strip())
    if parts.scheme not in {"http", "https"} or not parts.hostname or parts.username:
        return None
    return value.strip().rstrip("/")


def _read_json(root: Path, relative: str) -> tuple[str, Any]:
    """("missing"|"invalid"|"ok", payload)."""
    path = resolve_in_root(root, relative)
    if path is None:
        return "missing", None
    text, truncated = _read_text(path)
    if text is None:
        return "missing", None
    if truncated:
        return "invalid", None
    try:
        return "ok", json.loads(text) if text.strip() else {}
    except ValueError:
        return "invalid", None


def daemon_mirrors(root: Path) -> dict[str, Any]:
    state, payload = _read_json(root, DAEMON_PATH)
    if state != "ok" or not isinstance(payload, dict):
        return {"present": state != "missing", "valid": False if state != "missing" else None,
                "mirrors": []}
    raw = payload.get("registry-mirrors")
    items = raw[:MAX_ITEMS] if isinstance(raw, list) else []
    return {"present": True, "valid": True,
            "mirrors": [url for url in (_url(item) for item in items) if url]}


def marker(root: Path) -> dict[str, Any] | None:
    state, payload = _read_json(root, MARKER_PATH)
    if state == "missing":
        return None
    if state != "ok" or not isinstance(payload, dict):
        return {"valid": False}
    out: dict[str, Any] = {"valid": True}
    for key, kind in MARKER_FIELDS.items():
        value = payload.get(key)
        if kind is bool and isinstance(value, bool):
            out[key] = value
        elif kind is int and isinstance(value, int) and not isinstance(value, bool):
            out[key] = value
        elif kind is str and isinstance(value, str) and _TEXT.fullmatch(value):
            out[key] = value
    return out


def collect(root: Path | None) -> dict[str, Any]:
    if root is None:
        return {"host_root": False, "daemon": None, "marker": None}
    return {"host_root": True, "daemon": daemon_mirrors(root), "marker": marker(root)}


def live_mirrors(info: dict[str, Any]) -> list[str]:
    registry = info.get("RegistryConfig") if isinstance(info, dict) else None
    raw = registry.get("Mirrors") if isinstance(registry, dict) else None
    items = raw[:MAX_ITEMS] if isinstance(raw, list) else []
    return [url for url in (_url(item) for item in items) if url]


def builder_state(containers: list[dict[str, Any]]) -> str:
    """"running", "stopped" or "absent" for the mrk-mirror builder's container."""
    for item in containers:
        names = item.get("Names") if isinstance(item, dict) else None
        if isinstance(names, list) and f"/{BUILDER_CONTAINER}" in names:
            return "running" if item.get("State") == "running" else "stopped"
    return "absent"
