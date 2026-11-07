"""Prepare the mounted data volume, drop privileges, and start the appliance.

Docker creates bind and named-volume mount points as root on some runtimes.  The
appliance only needs root long enough to create its fixed directory layout.  It
then permanently drops to the unprivileged ``mrk`` uid/gid before Supervisor or
any network-facing process is started.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

APP_UID = 10001
APP_GID = 10001
DATA_ROOT = Path("/data")
DATA_DIRECTORIES = (
    "database",
    "npm",
    "npm/config",
    "npm/storage",
    "pypi",
    "pypi/server",
    "pypi/auth",
    "control-plane",
    "router",
)


def _ensure_real_directory(path: Path, *, may_change_owner: bool) -> None:
    """Create and own one directory without following a volume-provided symlink."""

    try:
        mode = path.lstat().st_mode
    except FileNotFoundError:
        path.mkdir(mode=0o750)
        mode = path.lstat().st_mode

    if not stat.S_ISDIR(mode):
        raise RuntimeError(f"refusing non-directory appliance data path: {path}")

    if may_change_owner:
        os.chown(path, APP_UID, APP_GID, follow_symlinks=False)
    path.chmod(0o750, follow_symlinks=False)


def main() -> None:
    effective_uid = os.geteuid()
    if effective_uid not in {0, APP_UID}:
        raise RuntimeError(f"appliance must start as root or uid {APP_UID}, got {effective_uid}")

    may_change_owner = effective_uid == 0
    _ensure_real_directory(DATA_ROOT, may_change_owner=may_change_owner)
    for relative_path in DATA_DIRECTORIES:
        _ensure_real_directory(
            DATA_ROOT / relative_path,
            may_change_owner=may_change_owner,
        )

    if may_change_owner:
        os.setgroups([])
        os.setgid(APP_GID)
        os.setuid(APP_UID)
    os.umask(0o027)
    os.execv(  # noqa: S606 - direct exec preserves PID 1 and never invokes a shell
        "/usr/local/bin/supervisord",
        ("supervisord", "-c", "/opt/mrk/supervisord.conf"),
    )


if __name__ == "__main__":
    main()
