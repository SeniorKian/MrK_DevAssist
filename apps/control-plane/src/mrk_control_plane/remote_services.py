"""npm and PyPI registries in their own containers (docs/44).

The panel image runs without Verdaccio and devpi. When the add-service wizard
connects one of them, this file records where it runs and turns the matching
panel features on, without a restart:

- ``npm``: Verdaccio in ``mrk-npm``. The panel shares its data volume
  (``/data/npm``), writes Verdaccio's config there (``config/generated.yaml``)
  and the container's runner restarts Verdaccio when that file changes.
- ``pypi``: devpi in ``mrk-pypi``. The panel shares ``/data/pypi`` and keeps the
  PyPI upstream router itself (it needs the panel's upstreams, secrets, proxies
  and quarantine); devpi uses it as its mirror over ``mrk-net``.

State: ``<data>/control-plane/remote-services.json``
``{"npm": {"host": "mrk-npm", "port": 4873}, "pypi": {...}}``.
"""

from __future__ import annotations

import json
import logging
import os
import re
import secrets
from pathlib import Path
from typing import Any

LOGGER = logging.getLogger(__name__)
STATE_FILE = "remote-services.json"
SERVICES = {"npm": ("npm_enabled", "npm_health_host", "npm_health_port"),
            "pypi": ("pypi_enabled", "pypi_health_host", "pypi_health_port")}
DEFAULTS = {"npm": ("mrk-npm", 4873), "pypi": ("mrk-pypi", 3141)}
_HOST = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
                   r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$")

_DATA_DIR: Path | None = None


def _path(data_dir: Path) -> Path:
    return data_dir / "control-plane" / STATE_FILE


def validate_target(host: str, port: int) -> tuple[str, int]:
    host = host.strip().lower()
    if not _HOST.match(host):
        raise ValueError("host must be a plain host name or IPv4 address")
    if not 1 <= int(port) <= 65535:
        raise ValueError("port must be between 1 and 65535")
    return host, int(port)


def load(data_dir: Path) -> dict[str, dict[str, Any]]:
    try:
        payload = json.loads(_path(data_dir).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    result: dict[str, dict[str, Any]] = {}
    if not isinstance(payload, dict):
        return result
    for name in SERVICES:
        entry = payload.get(name)
        if not isinstance(entry, dict):
            continue
        try:
            host, port = validate_target(str(entry.get("host", "")), int(entry.get("port", 0)))
        except (TypeError, ValueError):
            continue
        result[name] = {"host": host, "port": port}
    return result


def is_remote(service: str, data_dir: Path | None = None) -> bool:
    root = data_dir or _DATA_DIR
    return root is not None and service in load(root)


def _apply_one(settings: Any, service: str, host: str, port: int) -> None:
    enabled, host_field, port_field = SERVICES[service]
    # Settings is frozen: it is the one object every module reads, so switching
    # these three fields in place turns the feature on everywhere at once.
    object.__setattr__(settings, enabled, True)
    object.__setattr__(settings, host_field, host)
    object.__setattr__(settings, port_field, port)


def apply(settings: Any) -> None:
    """At startup: turn on what the wizard connected earlier."""
    global _DATA_DIR
    _DATA_DIR = Path(settings.data_dir)
    for service, entry in load(_DATA_DIR).items():
        _apply_one(settings, service, entry["host"], entry["port"])


def connect(settings: Any, service: str, host: str, port: int) -> None:
    global _DATA_DIR
    host, port = validate_target(host, port)
    data_dir = Path(settings.data_dir)
    _DATA_DIR = data_dir
    state = {name: entry for name, entry in load(data_dir).items()}
    state[service] = {"host": host, "port": port}
    path = _path(data_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{STATE_FILE}.{secrets.token_hex(4)}.tmp")
    temporary.write_bytes((json.dumps(state, sort_keys=True) + "\n").encode("utf-8"))
    temporary.chmod(0o600)
    os.replace(temporary, path)
    _apply_one(settings, service, host, port)


# ----------------------------------------------------------------------------- npm config

ENV_FILE = "generated.env.json"


def write_npm_config(data_dir: Path) -> Path:
    """Render Verdaccio's config into the shared npm volume (the runner reloads it).

    Upstream tokens are passed to Verdaccio as environment variables that the
    YAML references; only those extra variables go to ``generated.env.json``
    (mode 0600, next to the YAML in the same private folder).
    """
    from .verdaccio_runtime import build_runtime_config

    base = dict(os.environ)
    env_path = data_dir / "npm" / "config" / ENV_FILE
    changes = {"config": False, "env": False}

    def write_environment(environment: dict[str, str], config_changed: bool) -> None:
        # Runs before the YAML is replaced: the runner restarts Verdaccio when the
        # YAML changes, so the environment file must already be current by then.
        changes["config"] = config_changed
        extra = {key: value for key, value in environment.items() if base.get(key) != value}
        env_payload = json.dumps(extra, sort_keys=True).encode("utf-8")
        try:
            changes["env"] = env_path.read_bytes() != env_payload
        except OSError:
            changes["env"] = True
        if changes["env"]:
            temporary = env_path.with_name(f".{ENV_FILE}.{secrets.token_hex(4)}.tmp")
            descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(env_payload)
            os.replace(temporary, env_path)
        else:
            env_path.chmod(0o600)

    target, _environment = build_runtime_config(
        data_dir, container=True, before_replace=write_environment
    )
    # The runner watches only the YAML mtime. Touch it when token-only changes
    # alter the companion environment file, but leave it alone when both files
    # are identical so repeated connection probes do not restart Verdaccio.
    if changes["env"] and not changes["config"]:
        os.utime(target)
    return target


def refresh_npm() -> bool:
    """Apply panel changes to a separate Verdaccio. False when npm is not separate."""
    if _DATA_DIR is None or not is_remote("npm"):
        return False
    write_npm_config(_DATA_DIR)
    return True
