"""Read-only package-database files from containers (Gate 19 S8, docs/32 §4).

The vulnerability scanner needs the package inventory of each image. The agent
fetches a **fixed** list of package-database / lockfile paths with Docker's
``GET /containers/{id}/archive?path=...`` (a tar stream; the container is not
touched and nothing runs inside it), decodes the tar here and returns only the
regular files' bytes, each capped in size. Paths are never supplied by the
caller: the allowlist in ``docker_client`` accepts exactly ``PACKAGE_DB_PATHS``.

Symlinks are not followed (``/etc/os-release`` is usually a link to
``/usr/lib/os-release``, which is in the list on its own). The BerkeleyDB RPM
database (``/var/lib/rpm/Packages``) is only probed for presence so the
control plane can report "unsupported"; its content is never transferred.
"""

from __future__ import annotations

import base64
import io
import tarfile
from dataclasses import dataclass
from typing import Any

APP_DIRS = ("/app", "/usr/src/app", "/srv", "/opt/app", "/home/node/app", "/code")
APP_FILES = (
    "package-lock.json",
    "node_modules/.package-lock.json",
    "requirements.txt",
    "poetry.lock",
    "Pipfile.lock",
)
OS_PATHS = (
    "/etc/os-release",
    "/usr/lib/os-release",
    "/var/lib/dpkg/status",
    "/var/lib/dpkg/status.d",
    "/lib/apk/db/installed",
    "/var/lib/rpm/rpmdb.sqlite",
    "/usr/lib/sysimage/rpm/rpmdb.sqlite",
    "/var/lib/rpm/Packages",
)
PACKAGE_DB_PATHS: tuple[str, ...] = OS_PATHS + tuple(
    f"{directory}/{name}" for directory in APP_DIRS for name in APP_FILES
)
# Presence only: content is never read past the first tar header.
PRESENCE_ONLY = frozenset({"/var/lib/rpm/Packages"})

DEFAULT_FILE_CAP = 8 * 1024 * 1024
PATH_CAPS = {
    "/var/lib/rpm/rpmdb.sqlite": 40 * 1024 * 1024,
    "/usr/lib/sysimage/rpm/rpmdb.sqlite": 40 * 1024 * 1024,
    "/var/lib/dpkg/status.d": 16 * 1024 * 1024,
    "/var/lib/rpm/Packages": 4096,
}
TOTAL_CAP = 40 * 1024 * 1024
MAX_DIR_ENTRIES = 2000


def path_cap(path: str) -> int:
    return PATH_CAPS.get(path, DEFAULT_FILE_CAP)


def tar_cap(path: str) -> int:
    """The tar stream carries headers/padding on top of the file bytes."""
    return path_cap(path) + 64 * 1024


class TarTooLarge(Exception):
    pass


@dataclass(slots=True)
class FileEntry:
    name: str
    data: bytes

    def public(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "size": len(self.data),
            "data_b64": base64.b64encode(self.data).decode("ascii"),
        }


def decode_archive(raw: bytes, path: str) -> tuple[list[FileEntry], str | None]:
    """Regular files from a Docker archive tar. Returns (entries, note).

    ``note`` is ``"symlink"`` when the path itself is a symbolic link (nothing
    is returned then) and ``"present"`` for presence-only paths.
    """
    if path in PRESENCE_ONLY:
        return [], "present"
    entries: list[FileEntry] = []
    cap = path_cap(path)
    total = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
            members = 0
            for member in archive:
                members += 1
                if members > MAX_DIR_ENTRIES + 1:
                    break
                name = member.name.strip("/")
                parts = name.split("/")
                if any(part in {"", ".", ".."} for part in parts) or len(parts) > 2:
                    continue  # only the path itself and its direct children
                if member.issym() or member.islnk():
                    if len(parts) == 1:
                        return [], "symlink"
                    continue
                if not member.isreg():
                    continue
                if member.size > cap or total + member.size > cap:
                    raise TarTooLarge()
                handle = archive.extractfile(member)
                if handle is None:
                    continue
                data = handle.read(cap + 1)
                if len(data) > cap:
                    raise TarTooLarge()
                total += len(data)
                entries.append(FileEntry(name, data))
    except tarfile.TarError:
        return [], "invalid_archive"
    return entries, None
