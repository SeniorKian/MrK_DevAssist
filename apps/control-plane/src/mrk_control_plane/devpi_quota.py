"""Pre-upload size quota for «My space» PyPI indexes (docs/43 §0.1).

devpi has no "before upload" hook, so this module adds a Pyramid tween at the
ingress of devpi-server. ``mrk-devpi-server`` (``run``) starts devpi-server with
this plugin registered explicitly, so the check cannot be skipped by a missing
entry point. The control plane writes the limits to ``quotas.json``::

    {"indexes": {"<slug>/dev": <bytes or null>}}

For a POST upload to a listed index the tween refuses the request before devpi
reads the body when ``stored files + Content-Length (+ uploads in flight)`` would
exceed the limit: HTTP 413 with the reason ``quota_exceeded`` (twine and
``devpi upload`` print it). A ``push`` from another index into a size-limited
index is refused, because its size is not known up front.
"""

from __future__ import annotations

import json
import logging
import os
import re
import sys
import threading
from collections.abc import Callable
from pathlib import Path
from typing import Any

LOGGER = logging.getLogger(__name__)
_INDEX_PATH = re.compile(r"^/([A-Za-z0-9][A-Za-z0-9._-]*)/([A-Za-z0-9][A-Za-z0-9._-]*)/?$")
_LOCK = threading.Lock()
_IN_FLIGHT: dict[str, int] = {}
_CACHE: dict[str, Any] = {"key": None, "limits": {}}

try:  # devpi-server (pluggy) is only installed next to devpi.
    from pluggy import HookimplMarker

    hookimpl: Callable[..., Any] = HookimplMarker("devpiserver")
except ImportError:  # pragma: no cover - the control plane alone does not need it
    def hookimpl(function: Any = None, **_kwargs: Any) -> Any:
        return function if function is not None else (lambda inner: inner)


def quota_file() -> Path:
    explicit = os.getenv("MRK_PYPI_QUOTA_FILE")
    if explicit:
        return Path(explicit)
    return Path(os.getenv("MRK_DATA_DIR", "/data")) / "pypi" / "quotas.json"


def load_limits(path: Path) -> dict[str, int | None]:
    """Index → byte limit; re-read only when the file changes."""
    try:
        stat = path.stat()
    except OSError:
        return {}
    key = (stat.st_mtime_ns, stat.st_size)
    if _CACHE["key"] == key:
        return _CACHE["limits"]
    try:
        payload = json.loads(path.read_text("utf-8"))
        raw = payload.get("indexes") if isinstance(payload, dict) else None
    except (OSError, ValueError):
        # The control plane writes it atomically, so this is damage: keep the last good
        # limits, or fail closed (every authenticated upload refused) when there are none.
        LOGGER.error("unreadable PyPI quota file %s", path)
        return _CACHE["limits"] if _CACHE["key"] is not None else {"*": 0}
    limits: dict[str, int | None] = {}
    for name, value in (raw or {}).items():
        if isinstance(name, str) and (value is None or (isinstance(value, int) and value >= 0)):
            limits[name] = value
    _CACHE.update(key=key, limits=limits)
    return limits


def dir_bytes(path: Path) -> int:
    total = 0
    for root, _dirs, files in os.walk(path):
        for name in files:
            try:
                total += (Path(root) / name).stat().st_size
            except OSError:
                continue
    return total


def check(index: str, limit: int, used: int, incoming: int) -> str | None:
    """The refusal message, or None when the upload fits."""
    if used + incoming <= limit:
        return None
    return (f"quota_exceeded: this upload ({incoming} bytes) would put index {index} over "
            f"its storage limit ({used} of {limit} bytes used). Delete old versions in "
            "My space, or ask for a larger plan.")


def _refuse(status: int, reason: str) -> Any:
    from pyramid.response import Response

    body = json.dumps({"type": "error", "code": "quota_exceeded", "message": reason})
    # The reason phrase is what twine shows; keep it on one short line.
    phrase = reason.split(".", 1)[0][:200]
    return Response(body=body.encode(), status=f"{status} {phrase}",
                    content_type="application/json", charset="utf-8")


def quota_tween_factory(handler: Callable[[Any], Any], registry: Any) -> Callable[[Any], Any]:
    server_path = Path(registry["xom"].config.server_path)

    def tween(request: Any) -> Any:
        if request.method not in ("POST", "PUSH"):
            return handler(request)
        match = _INDEX_PATH.fullmatch(request.path)
        if match is None:
            return handler(request)
        index = f"{match.group(1)}/{match.group(2)}"
        limits = load_limits(quota_file())
        limit = limits[index] if index in limits else limits.get("*")
        if limit is None:
            return handler(request)
        # devpi itself answers 401/403 to anonymous callers; never leak usage to them.
        if not (request.headers.get("Authorization") or request.headers.get("X-Devpi-Auth")):
            return handler(request)
        content_type = (request.content_type or "").lower()
        if request.method == "PUSH" or content_type == "application/json":
            return _refuse(413, "quota_exceeded: pushing between indexes is not available "
                                f"for the size-limited index {index}. Upload the files instead.")
        if request.content_length is None:
            return _refuse(411, "quota_exceeded: the upload has no Content-Length, so its "
                                "size cannot be checked against the storage limit")
        incoming = int(request.content_length)
        used = dir_bytes(server_path / "+files" / match.group(1) / match.group(2))
        with _LOCK:
            pending = _IN_FLIGHT.get(index, 0)
            refusal = check(index, limit, used + pending, incoming)
            if refusal is None:
                _IN_FLIGHT[index] = pending + incoming
        if refusal is not None:
            return _refuse(413, refusal)
        try:
            return handler(request)
        finally:
            with _LOCK:
                left = _IN_FLIGHT.get(index, 0) - incoming
                if left > 0:
                    _IN_FLIGHT[index] = left
                else:
                    _IN_FLIGHT.pop(index, None)

    return tween


@hookimpl
def devpiserver_pyramid_configure(config: Any, pyramid_config: Any) -> None:  # noqa: ARG001
    from pyramid.tweens import INGRESS

    pyramid_config.add_tween("mrk_control_plane.devpi_quota.quota_tween_factory",
                             under=INGRESS)


def run(argv: list[str] | None = None) -> int:
    """``mrk-devpi-server``: devpi-server with the quota plugin always registered."""
    from devpi_server.config import get_pluginmanager
    from devpi_server.main import CommandRunner, _main

    pluginmanager = get_pluginmanager()
    if not pluginmanager.is_registered(sys.modules[__name__]):
        pluginmanager.register(sys.modules[__name__], name="mrk-quota")
    with CommandRunner(pluginmanager=pluginmanager) as runner:
        runner.return_code = _main(pluginmanager, argv=argv if argv is not None else sys.argv)
    return int(runner.return_code or 0)


if __name__ == "__main__":
    sys.exit(run())
