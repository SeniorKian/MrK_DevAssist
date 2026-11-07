from __future__ import annotations

import os
import subprocess
from pathlib import Path


def restart_verdaccio_if_managed() -> bool:
    socket_path = Path(
        os.getenv(
            "MRK_SUPERVISOR_SOCKET",
            "/tmp/mrk-supervisor.sock",  # noqa: S108 - 0600 socket on private tmpfs
        )
    ).resolve()
    if not socket_path.is_socket():
        return False
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
    if completed.returncode != 0:
        raise RuntimeError("Verdaccio rejected the runtime configuration reload")
    return True
