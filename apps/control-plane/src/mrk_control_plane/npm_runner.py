"""``mrk-npm-runner``: Verdaccio in its own container (image mrk-npm, docs/44).

The panel writes Verdaccio's config into the shared npm volume
(``/data/npm/config/generated.yaml`` plus ``generated.env.json`` for upstream
tokens). This runner waits for that config, starts Verdaccio with it and
restarts Verdaccio whenever the panel writes a new one: that is how upstream,
user and quota changes made in the panel take effect.
"""

from __future__ import annotations

import json
import logging
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

from .logging_config import configure_logging

LOGGER = logging.getLogger("mrk_control_plane.npm_runner")
VERDACCIO = "/opt/verdaccio/node_modules/.bin/verdaccio"
POLL_SECONDS = 2.0
# Let the panel finish writing the environment file before a restart.
SETTLE_SECONDS = 1.0


def config_path() -> Path:
    root = Path(os.getenv("MRK_NPM_DIR", "/data/npm"))
    return root / "config" / "generated.yaml"


def _mtime(path: Path) -> int | None:
    try:
        return path.stat().st_mtime_ns
    except OSError:
        return None


def child_environment(config: Path) -> dict[str, str]:
    environment = dict(os.environ)
    try:
        extra = json.loads((config.with_name("generated.env.json")).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        extra = {}
    if isinstance(extra, dict):
        environment.update({str(k): str(v) for k, v in extra.items() if str(k).isupper()})
    environment.setdefault("HOME", "/tmp")  # noqa: S108 - private tmpfs
    environment["XDG_CONFIG_HOME"] = str(config.parent)
    environment.setdefault("NODE_ENV", "production")
    return environment


def start(config: Path) -> subprocess.Popen[bytes]:
    LOGGER.info("starting Verdaccio", extra={"config": str(config)})
    return subprocess.Popen(  # noqa: S603 - fixed binary, config written by the panel
        [VERDACCIO, "--config", str(config)], env=child_environment(config)
    )


def stop(child: subprocess.Popen[bytes] | None, timeout: float = 10.0) -> None:
    if child is None or child.poll() is not None:
        return
    child.terminate()
    try:
        child.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        child.kill()
        child.wait()


def run() -> None:
    configure_logging(os.getenv("MRK_LOG_LEVEL", "INFO").strip().upper() or "INFO")
    config = config_path()
    stopping = {"now": False}

    def on_signal(_signum: int, _frame: object) -> None:
        stopping["now"] = True

    signal.signal(signal.SIGTERM, on_signal)
    signal.signal(signal.SIGINT, on_signal)

    waited = False
    while _mtime(config) is None and not stopping["now"]:
        if not waited:
            LOGGER.warning(
                "waiting for the panel to write the npm config; connect this service in "
                "the panel (My services -> Add a service)", extra={"config": str(config)}
            )
            waited = True
        time.sleep(POLL_SECONDS)
    if stopping["now"]:
        return

    seen = _mtime(config)
    child = start(config)
    while not stopping["now"]:
        time.sleep(POLL_SECONDS)
        current = _mtime(config)
        if current is not None and current != seen:
            time.sleep(SETTLE_SECONDS)
            seen = _mtime(config)
            LOGGER.info("npm config changed; restarting Verdaccio")
            stop(child)
            child = start(config)
            continue
        if child.poll() is not None:
            LOGGER.error("Verdaccio exited; restarting", extra={"code": child.returncode})
            time.sleep(POLL_SECONDS)
            child = start(config)
    stop(child)
    sys.exit(0)


if __name__ == "__main__":  # pragma: no cover
    run()
