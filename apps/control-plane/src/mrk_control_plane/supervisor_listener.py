"""Supervisor event listener that stops the container when an essential service goes FATAL.

Supervisor gives up on a program after its start retries, but supervisord itself
keeps running, so Docker never notices the dead service. For the essential
programs (database and panel, ``MRK_FATAL_ESSENTIAL``) this listener asks
supervisord to shut down; the container then exits and the platform's restart
policy (Docker, Dokploy, ...) restarts it with its own backoff.

Non-essential programs (npm, PyPI, S3) are left FATAL on purpose: the panel's
service watchdog (modules/services_watchdog.py) retries them with a growing
delay and notifies the operator, so one broken registry never takes the panel
down in a restart loop. ``MRK_FATAL_ESSENTIAL=*`` restores the old behaviour.

stdout is the supervisor protocol channel, so diagnostics go to stderr only.
"""

from __future__ import annotations

import os
import signal
import sys
from typing import TextIO


def parse_tokens(line: str) -> dict[str, str]:
    return dict(item.split(":", 1) for item in line.split() if ":" in item)


DEFAULT_ESSENTIAL = frozenset({"pglite", "control-plane"})


def essential_programs(raw: str | None) -> frozenset[str] | None:
    """Programs whose FATAL stops the container; None means every program."""
    if raw is None or not raw.strip():
        return DEFAULT_ESSENTIAL
    items = {item.strip() for item in raw.split(",") if item.strip()}
    if "*" in items:
        return None
    return frozenset(items)


def should_stop(
    headers: dict[str, str],
    payload: dict[str, str],
    ignored: set[str],
    essential: frozenset[str] | None = DEFAULT_ESSENTIAL,
) -> bool:
    name = payload.get("processname")
    return (
        headers.get("eventname") == "PROCESS_STATE_FATAL"
        and name not in ignored
        and (essential is None or name in essential)
    )


def run(stdin: TextIO, stdout: TextIO, stderr: TextIO) -> None:
    ignored = {
        item.strip()
        for item in os.getenv("MRK_FATAL_IGNORE", "").split(",")
        if item.strip()
    }
    essential = essential_programs(os.getenv("MRK_FATAL_ESSENTIAL"))
    while True:
        stdout.write("READY\n")
        stdout.flush()
        header_line = stdin.readline()
        if not header_line:
            return
        headers = parse_tokens(header_line)
        payload_line = stdin.read(int(headers.get("len", "0")))
        payload = parse_tokens(payload_line.split("\n", 1)[0])
        if headers.get("eventname") == "PROCESS_STATE_FATAL" and not should_stop(
            headers, payload, ignored, essential
        ):
            stderr.write(
                f"mrk: program {payload.get('processname')} is FATAL; "
                "the panel's service watchdog will retry it\n"
            )
            stderr.flush()
        if should_stop(headers, payload, ignored, essential):
            stderr.write(
                f"mrk: program {payload.get('processname')} is FATAL; stopping supervisord\n"
            )
            stderr.flush()
            # The entrypoint reads this marker to exit non-zero, so `on-failure`
            # restart policies also restart the container.
            try:
                with open(os.getenv("MRK_FATAL_MARKER", "/tmp/mrk-fatal"), "w") as marker:  # noqa: S108
                    marker.write(str(payload.get("processname")))
            except OSError:
                pass
            os.kill(os.getppid(), signal.SIGTERM)
        stdout.write("RESULT 2\nOK")
        stdout.flush()


def main() -> None:
    run(sys.stdin, sys.stdout, sys.stderr)


if __name__ == "__main__":
    main()
