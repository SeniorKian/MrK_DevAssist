"""Supervisor event listener that stops the container when a service goes FATAL.

Supervisor gives up on a program after its start retries, but supervisord itself
keeps running, so Docker never notices the dead service. This listener asks
supervisord to shut down instead; the container then exits and the platform's
restart policy (Docker, Dokploy, ...) restarts it with its own backoff.

stdout is the supervisor protocol channel, so diagnostics go to stderr only.
"""

from __future__ import annotations

import os
import signal
import sys
from typing import TextIO


def parse_tokens(line: str) -> dict[str, str]:
    return dict(item.split(":", 1) for item in line.split() if ":" in item)


def should_stop(headers: dict[str, str], payload: dict[str, str], ignored: set[str]) -> bool:
    return (
        headers.get("eventname") == "PROCESS_STATE_FATAL"
        and payload.get("processname") not in ignored
    )


def run(stdin: TextIO, stdout: TextIO, stderr: TextIO) -> None:
    ignored = {
        item.strip()
        for item in os.getenv("MRK_FATAL_IGNORE", "").split(",")
        if item.strip()
    }
    while True:
        stdout.write("READY\n")
        stdout.flush()
        header_line = stdin.readline()
        if not header_line:
            return
        headers = parse_tokens(header_line)
        payload_line = stdin.read(int(headers.get("len", "0")))
        payload = parse_tokens(payload_line.split("\n", 1)[0])
        if should_stop(headers, payload, ignored):
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
