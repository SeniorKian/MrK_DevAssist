"""Read-only facts about host folders a service stack will bind-mount.

The agent sees the host's root file system read-only (``/host/root``). Before a stack
is deployed the panel asks whether each chosen folder exists, who owns it and how much
room is left, so a container that runs as uid 10001 is not handed a root-owned folder
that Docker would create on its own. Nothing is created or changed here.
"""

from __future__ import annotations

import os
import shutil
import stat
from pathlib import Path, PurePosixPath
from typing import Any

MAX_PATHS = 16
MAX_PATH_LENGTH = 400
# Never reported: host secrets and kernel interfaces are not storage locations.
_REFUSED_PREFIXES = ("/proc", "/sys", "/dev", "/run/secrets", "/etc/shadow", "/etc/gshadow")


def valid_host_path(path: str) -> bool:
    if not path or len(path) > MAX_PATH_LENGTH or "\x00" in path or not path.startswith("/"):
        return False
    pure = PurePosixPath(path)
    if any(part in {"..", "."} for part in pure.parts):
        return False
    text = pure.as_posix()
    return not any(text == prefix or text.startswith(prefix + "/") for prefix in _REFUSED_PREFIXES)


def _host(root: Path, path: str) -> Path:
    return root / path.lstrip("/")


def check(root: Path | None, path: str) -> dict[str, Any]:
    """{path, valid, exists, is_dir, uid, gid, mode, free_bytes, nearest_parent}."""
    result: dict[str, Any] = {"path": path, "valid": valid_host_path(path), "exists": False,
                              "is_dir": False, "uid": None, "gid": None, "mode": None,
                              "free_bytes": None, "nearest_parent": None}
    if root is None or not result["valid"]:
        return result
    target = _host(root, path)
    try:
        info = os.lstat(target)
    except OSError:
        info = None
    if info is not None and not stat.S_ISLNK(info.st_mode):
        result.update(exists=True, is_dir=stat.S_ISDIR(info.st_mode), uid=info.st_uid,
                      gid=info.st_gid, mode=oct(stat.S_IMODE(info.st_mode)))
    elif info is not None:
        result.update(exists=True, is_dir=False)  # a symlink: reported, never followed
    # Room left where the folder is (or will be created).
    probe = PurePosixPath(path)
    while True:
        candidate = _host(root, probe.as_posix())
        try:
            free = shutil.disk_usage(candidate).free
        except OSError:
            if probe.as_posix() == "/":
                break
            probe = probe.parent
            continue
        result["free_bytes"] = int(free)
        if not result["exists"]:
            result["nearest_parent"] = probe.as_posix()
        break
    return result


def check_all(root: Path | None, paths: list[str]) -> dict[str, Any]:
    unique = list(dict.fromkeys(paths))[:MAX_PATHS]
    return {"host_root": root is not None, "items": [check(root, path) for path in unique]}
