"""Run supervisord for the native (systemd) install of Pishkar.

``deploy/appliance/supervisord.conf`` is shared with the container unchanged. It
sends every program's output to ``/dev/fd/1`` and ``/dev/fd/2``. In a container
those are pipes; under systemd they are journald sockets, and Linux cannot reopen
a socket through ``/dev/fd`` (ENXIO), so supervisord would fail to start its
programs. This wrapper gives supervisord a pipe, copies everything to its own
stdout (the journal), forwards stop signals unchanged, and exits with status 1
when the FATAL listener stopped supervisord, like ``deploy/appliance/entrypoint.py``.
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import threading
from pathlib import Path

SUPERVISORD = "/usr/local/bin/supervisord"
CONFIG = "/opt/mrk/supervisord.conf"
FATAL_MARKER = Path("/tmp/mrk-fatal")  # noqa: S108 - private tmpfs, written by the listener
DRAIN_SECONDS = 2.0


def _write_all(data: bytes) -> None:
    view = memoryview(data)
    while view:
        try:
            written = os.write(1, view)
        except OSError:
            return  # journal gone; keep draining so the children never block
        view = view[written:]


def _relay(read_end: int) -> None:
    while True:
        try:
            chunk = os.read(read_end, 65536)
        except OSError:
            return
        if not chunk:
            return
        _write_all(chunk)


def main() -> int:
    FATAL_MARKER.unlink(missing_ok=True)
    read_end, write_end = os.pipe()
    child = subprocess.Popen(  # noqa: S603 - fixed binary and arguments, no shell
        [SUPERVISORD, "-c", CONFIG],
        stdin=subprocess.DEVNULL,
        stdout=write_end,
        stderr=write_end,
    )
    os.close(write_end)
    relay = threading.Thread(target=_relay, args=(read_end,), daemon=True)
    relay.start()

    def forward(signum: int, _frame: object) -> None:
        if child.poll() is None:
            child.send_signal(signum)

    for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP, signal.SIGQUIT, signal.SIGUSR2):
        signal.signal(signum, forward)

    code = child.wait()
    # An orphan may still hold the pipe; never wait for it forever.
    relay.join(DRAIN_SECONDS)
    if FATAL_MARKER.exists():
        reason = FATAL_MARKER.read_text(encoding="utf-8", errors="replace").strip()
        print(f"pishkar: stopped because a service went FATAL: {reason}", file=sys.stderr)
        return 1
    return code


if __name__ == "__main__":
    sys.exit(main())
