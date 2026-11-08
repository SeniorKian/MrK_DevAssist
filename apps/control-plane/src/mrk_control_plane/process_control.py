from __future__ import annotations

import logging
import os
import subprocess
from pathlib import Path

LOGGER = logging.getLogger(__name__)


def restart_verdaccio_if_managed() -> bool:
    """Restart Verdaccio under supervisor. Raises RuntimeError on any failure."""
    socket_path = Path(
        os.getenv(
            "MRK_SUPERVISOR_SOCKET",
            "/tmp/mrk-supervisor.sock",  # noqa: S108 - 0600 socket on private tmpfs
        )
    ).resolve()
    if not socket_path.is_socket():
        return False
    try:
        completed = subprocess.run(  # noqa: S603 - fixed binary and fixed program allowlist
            [
                "/usr/local/bin/supervisorctl",
                "-s",
                f"unix://{socket_path.as_posix()}",
                "restart",
                "verdaccio",
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=45,
            env={"PATH": os.getenv("PATH", "/usr/local/bin:/usr/bin:/bin")},
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError("Verdaccio reload could not be requested") from exc
    if completed.returncode != 0:
        raise RuntimeError("Verdaccio rejected the runtime configuration reload")
    return True


def reload_verdaccio_best_effort() -> bool:
    """Reload Verdaccio; log and return False instead of raising.

    Callers have already saved the change, so a failed reload must not turn
    the request into a 500 (and skip its audit record).
    """
    try:
        restart_verdaccio_if_managed()
    except RuntimeError:
        LOGGER.exception("Verdaccio reload failed; the saved change applies on next start")
        return False
    return True
