from __future__ import annotations

import logging
import os
import subprocess
from pathlib import Path

LOGGER = logging.getLogger(__name__)


def restart_verdaccio_if_managed() -> bool:
    """Restart Verdaccio under supervisor. Raises RuntimeError on any failure."""
    if os.getenv("MRK_NPM_ENABLED", "").strip().lower() in {"0", "false", "no", "off"}:
        # The panel-only image has no Verdaccio to restart (docs/44).
        return False
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


# ---- generic, allowlisted supervisor control (docs/35 §3, "my services") ----

# Programs the panel may inspect. Only CONTROLLABLE ones may be started/stopped;
# pglite and control-plane are never stopped from the panel (the panel would
# kill itself or its database).
STATUS_PROGRAMS = frozenset(
    {"verdaccio", "devpi", "devpi-configure", "pypi-router", "s3-engine", "pglite", "control-plane"}
)
CONTROLLABLE_PROGRAMS = frozenset({"verdaccio", "devpi", "pypi-router", "s3-engine"})
SUPERVISOR_ACTIONS = frozenset({"start", "stop", "restart"})
SUPERVISORCTL = "/usr/local/bin/supervisorctl"
# supervisorctl status states (supervisor/states.py ProcessStates).
_STATES = frozenset(
    {"STOPPED", "STARTING", "RUNNING", "BACKOFF", "STOPPING", "EXITED", "FATAL", "UNKNOWN"}
)


class SupervisorError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def supervisor_socket() -> Path:
    return Path(
        os.getenv(
            "MRK_SUPERVISOR_SOCKET",
            "/tmp/mrk-supervisor.sock",  # noqa: S108 - 0600 socket on private tmpfs
        )
    ).resolve()


def supervisor_available() -> bool:
    try:
        return supervisor_socket().is_socket() and Path(SUPERVISORCTL).is_file()
    except OSError:
        return False


def _supervisorctl(args: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
    socket_path = supervisor_socket()
    try:
        return subprocess.run(  # noqa: S603 - fixed binary, allowlisted program names only
            [SUPERVISORCTL, "-s", f"unix://{socket_path.as_posix()}", *args],
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
            env={"PATH": os.getenv("PATH", "/usr/local/bin:/usr/bin:/bin")},
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise SupervisorError("supervisor_unavailable", "supervisorctl could not run") from exc


def parse_status(output: str) -> dict[str, dict[str, str]]:
    """Parse ``supervisorctl status`` lines: ``name  STATE  description``."""
    result: dict[str, dict[str, str]] = {}
    for line in output.splitlines():
        parts = line.split(None, 2)
        if len(parts) < 2 or parts[1] not in _STATES:
            continue
        name = parts[0].split(":", 1)[-1]
        if name in STATUS_PROGRAMS:
            result[name] = {
                "state": parts[1],
                "description": (parts[2] if len(parts) > 2 else "")[:200],
            }
    return result


def program_status(names: list[str] | tuple[str, ...]) -> dict[str, dict[str, str]] | None:
    """State per allowlisted program, or None when supervisor is not reachable."""
    wanted = [name for name in names if name in STATUS_PROGRAMS]
    if not wanted or not supervisor_available():
        return None
    completed = _supervisorctl(["status", *wanted], timeout=10)
    # status exits non-zero when any program is not RUNNING; the output still holds.
    parsed = parse_status(completed.stdout or "")
    return parsed or None


def program_action(name: str, action: str) -> None:
    """Start/stop/restart one controllable program. Raises SupervisorError."""
    if name not in CONTROLLABLE_PROGRAMS or action not in SUPERVISOR_ACTIONS:
        raise SupervisorError("program_not_controllable", "this program cannot be controlled")
    if not supervisor_available():
        raise SupervisorError("supervisor_unavailable", "process supervisor is not reachable")
    completed = _supervisorctl([action, name], timeout=60)
    output = f"{completed.stdout}\n{completed.stderr}"
    if completed.returncode != 0 and not (
        (action == "start" and "ALREADY_STARTED" in output)
        or (action == "stop" and "NOT_RUNNING" in output)
    ):
        raise SupervisorError("supervisor_action_failed", f"supervisor could not {action} {name}")
