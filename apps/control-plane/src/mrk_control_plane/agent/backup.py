"""Gate 18 backup sources served by the agent (docs/31 §4).

Two read-only sources, both streamed to the Control Plane in a tiny framing so
the receiver always knows whether the stream finished cleanly::

    frame := kind(1) | u32be length | payload
    kind  := b"D" (data bytes) | b"E" (end: JSON status, always last)

A stream without a final ``E`` frame (agent crash, timeout, cut connection) is a
failed backup. The ``E`` payload never contains credentials or tool output.

* **Volumes** are read from the read-only host mount (``/host/volumes`` =
  ``/var/lib/docker/volumes``) and written as an uncompressed PAX tar. Symlinks
  are stored as links and never followed; directories and files are opened
  relative to their parent descriptor with ``O_NOFOLLOW`` so a container that
  swaps a directory for a symlink mid-walk cannot make the agent read outside
  the volume. FIFOs, sockets and device nodes are skipped (and counted).
* **Databases** are dumped with ``docker exec`` using one of the fixed argv
  templates below. The caller only names the engine and (optionally) a database
  name; credentials are read from the container's own environment here, passed
  to the exec as environment variables (never argv), and never returned.
"""

from __future__ import annotations

import json
import os
import re
import stat
import struct
import tarfile
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, BinaryIO

FRAME_DATA = b"D"
FRAME_END = b"E"
MAX_FRAME_BYTES = 1024 * 1024
DEFAULT_VOLUMES_ROOT = "/host/volumes"
DOCKER_VOLUMES_DIR = "/var/lib/docker/volumes"

VOLUME_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,254}$")
DATABASE_NAME = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_$-]{0,63}$")
DB_USER = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.@-]{0,62}$")
ENGINES = ("postgres", "mysql", "mariadb", "mongo", "redis")
# Which dump engine may be used for a detected image family.
COMPATIBLE_ENGINES: dict[str, frozenset[str]] = {
    "postgres": frozenset({"postgres"}),
    "mysql": frozenset({"mysql"}),
    "mariadb": frozenset({"mariadb", "mysql"}),
    "mongo": frozenset({"mongo"}),
    "redis": frozenset({"redis"}),
}

# --- fixed exec templates -------------------------------------------------------
# Shell scripts are constants; every variable part arrives through the exec's
# environment and is expanded by the container's shell, never interpolated here.
MONGO_SCRIPT_AUTH = (
    'printf \'%s\\n\' "$MRK_DB_PASSWORD" | mongodump --archive '
    '--username="$MRK_DB_USER" --authenticationDatabase=admin'
)
MONGO_SCRIPT_AUTH_DB = MONGO_SCRIPT_AUTH + ' --db="$MRK_DB_NAME"'
MONGO_SCRIPT_NOAUTH = "mongodump --archive"
MONGO_SCRIPT_NOAUTH_DB = MONGO_SCRIPT_NOAUTH + ' --db="$MRK_DB_NAME"'
MONGO_SCRIPTS = frozenset(
    {MONGO_SCRIPT_AUTH, MONGO_SCRIPT_AUTH_DB, MONGO_SCRIPT_NOAUTH, MONGO_SCRIPT_NOAUTH_DB}
)
MYSQL_FLAGS = ("--single-transaction", "--routines", "--events", "--triggers", "--hex-blob")
EXEC_ENV_NAMES = frozenset(
    {"PGPASSWORD", "MYSQL_PWD", "MRK_DB_USER", "MRK_DB_PASSWORD", "MRK_DB_NAME", "REDISCLI_AUTH"}
)


class BackupSourceError(Exception):
    def __init__(self, code: str, status_code: int = 422) -> None:
        super().__init__(code)
        self.code = code
        self.status_code = status_code


def frame(kind: bytes, payload: bytes) -> bytes:
    return kind + struct.pack(">I", len(payload)) + payload


def end_frame(status: dict[str, Any]) -> bytes:
    return frame(FRAME_END, json.dumps(status, separators=(",", ":")).encode("utf-8"))


def data_frames(chunk: bytes) -> Iterator[bytes]:
    for offset in range(0, len(chunk), MAX_FRAME_BYTES):
        yield frame(FRAME_DATA, chunk[offset : offset + MAX_FRAME_BYTES])


# --- image heuristics -----------------------------------------------------------


def detect_engine(image: object) -> str | None:
    """Guess the database family from an image reference (``postgres:16``, ``bitnami/mysql``)."""
    if not isinstance(image, str) or not image:
        return None
    name = image.split("@", 1)[0]
    last = name.rsplit("/", 1)[-1]
    repository = last.split(":", 1)[0].lower()
    if "postgres" in repository or "postgis" in repository or repository == "timescaledb":
        return "postgres"
    if "mariadb" in repository:
        return "mariadb"
    if "mysql" in repository or "percona" in repository:
        return "mysql"
    if "mongo" in repository:
        return "mongo"
    if "redis" in repository or "valkey" in repository or "keydb" in repository:
        return "redis"
    return None


# --- dump specs -----------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class DumpSpec:
    argv: list[str]
    env: list[str]
    secrets: tuple[str, ...] = ()
    payload_name: str = "dump"

    def redact(self, text: str) -> str:
        for secret in self.secrets:
            if secret:
                text = text.replace(secret, "***")
        return text


def container_env(inspected: dict[str, Any]) -> dict[str, str]:
    config = inspected.get("Config")
    raw = config.get("Env") if isinstance(config, dict) else None
    result: dict[str, str] = {}
    for item in raw or []:
        if isinstance(item, str) and "=" in item:
            key, _, value = item.partition("=")
            result[key] = value
    return result


def _container_cmd(inspected: dict[str, Any]) -> list[str]:
    config = inspected.get("Config")
    parts: list[str] = []
    for key in ("Entrypoint", "Cmd"):
        value = config.get(key) if isinstance(config, dict) else None
        if isinstance(value, list):
            parts.extend(item for item in value if isinstance(item, str))
    args = inspected.get("Args")
    if isinstance(args, list) and not parts:
        parts.extend(item for item in args if isinstance(item, str))
    return parts


def _redis_password(env: dict[str, str], cmd: list[str]) -> str | None:
    for key in ("REDIS_PASSWORD", "REDIS_PASS"):
        if env.get(key):
            return env[key]
    for index, item in enumerate(cmd):
        if item == "--requirepass" and index + 1 < len(cmd):
            return cmd[index + 1] or None
        if item.startswith("--requirepass="):
            return item.partition("=")[2] or None
        # `sh -c "redis-server --requirepass secret"` style commands.
        match = re.search(r"--requirepass[ =](\"[^\"]*\"|'[^']*'|\S+)", item)
        if match and index > 0:
            value = match.group(1).strip("'\"")
            if value and "$" not in value:
                return value
    return None


def _no_newline(value: str) -> str:
    if "\n" in value or "\r" in value or "\x00" in value:
        raise BackupSourceError("credentials_unsupported")
    return value


def build_dump_spec(engine: str, database: str | None, inspected: dict[str, Any]) -> DumpSpec:
    """Return the fixed exec for ``engine``. Raises BackupSourceError (stable codes)."""
    if engine not in ENGINES:
        raise BackupSourceError("invalid_engine")
    if database is not None and not DATABASE_NAME.fullmatch(database):
        raise BackupSourceError("invalid_database")
    env = container_env(inspected)
    if engine == "postgres":
        user = env.get("POSTGRES_USER") or "postgres"
        dbname = database or env.get("POSTGRES_DB") or user
        if not DB_USER.fullmatch(user) or not DATABASE_NAME.fullmatch(dbname):
            raise BackupSourceError("credentials_unsupported")
        exec_env: list[str] = []
        secrets: tuple[str, ...] = ()
        password = env.get("POSTGRES_PASSWORD")
        if password:
            exec_env.append(f"PGPASSWORD={_no_newline(password)}")
            secrets = (password,)
        argv = [
            "pg_dump", "--format=custom", "--no-password", "--username", user, "--dbname", dbname,
        ]
        return DumpSpec(argv, exec_env, secrets, f"{dbname}.pgdump")
    if engine in {"mysql", "mariadb"}:
        binary = "mysqldump" if engine == "mysql" else "mariadb-dump"
        user, password = "root", None
        root_password = env.get("MYSQL_ROOT_PASSWORD") or env.get("MARIADB_ROOT_PASSWORD")
        empty_root = any(
            env.get(key, "").lower() in {"1", "yes", "true"}
            for key in ("MYSQL_ALLOW_EMPTY_PASSWORD", "MARIADB_ALLOW_EMPTY_ROOT_PASSWORD")
        )
        default_db = None
        if root_password:
            password = root_password
        elif not empty_root:
            user = env.get("MYSQL_USER") or env.get("MARIADB_USER") or ""
            password = env.get("MYSQL_PASSWORD") or env.get("MARIADB_PASSWORD")
            default_db = env.get("MYSQL_DATABASE") or env.get("MARIADB_DATABASE")
            if not user or not password:
                raise BackupSourceError("credentials_unavailable")
        if not DB_USER.fullmatch(user):
            raise BackupSourceError("credentials_unsupported")
        dbname = database or default_db
        if dbname is not None and not DATABASE_NAME.fullmatch(dbname):
            raise BackupSourceError("credentials_unsupported")
        argv = [binary, *MYSQL_FLAGS, f"--user={user}"]
        argv += ["--databases", dbname] if dbname else ["--all-databases"]
        exec_env = [f"MYSQL_PWD={_no_newline(password)}"] if password else []
        return DumpSpec(
            argv, exec_env, (password,) if password else (), f"{dbname or 'all-databases'}.sql"
        )
    if engine == "mongo":
        user = env.get("MONGO_INITDB_ROOT_USERNAME") or ""
        password = env.get("MONGO_INITDB_ROOT_PASSWORD") or ""
        exec_env = []
        if user and password:
            script = MONGO_SCRIPT_AUTH_DB if database else MONGO_SCRIPT_AUTH
            exec_env += [
                f"MRK_DB_USER={_no_newline(user)}",
                f"MRK_DB_PASSWORD={_no_newline(password)}",
            ]
            secrets = (password,)
        else:
            script = MONGO_SCRIPT_NOAUTH_DB if database else MONGO_SCRIPT_NOAUTH
            secrets = ()
        if database:
            exec_env.append(f"MRK_DB_NAME={database}")
        payload = f"{database or 'all'}.mongo.archive"
        return DumpSpec(["sh", "-c", script], exec_env, secrets, payload)
    password = _redis_password(env, _container_cmd(inspected))
    exec_env = [f"REDISCLI_AUTH={_no_newline(password)}"] if password else []
    return DumpSpec(
        ["redis-cli", "--rdb", "-"], exec_env, (password,) if password else (), "dump.rdb"
    )


# --- exec allowlist (checked again by docker_client before anything is sent) -----

_EXEC_TEMPLATES: tuple[tuple[object, ...], ...] = (
    ("pg_dump", "--format=custom", "--no-password", "--username", DB_USER, "--dbname",
     DATABASE_NAME),
    *(
        (binary, *MYSQL_FLAGS, re.compile(r"^--user=[A-Za-z0-9_][A-Za-z0-9_.@-]{0,62}$"), *tail)
        for binary in ("mysqldump", "mariadb-dump")
        for tail in (("--all-databases",), ("--databases", DATABASE_NAME))
    ),
    *(("sh", "-c", script) for script in sorted(MONGO_SCRIPTS)),
    ("redis-cli", "--rdb", "-"),
)


def exec_spec_allowed(argv: object, env: object) -> bool:
    """True only for argv equal to a fixed template and env limited to known names."""
    if not isinstance(argv, list) or not all(isinstance(item, str) for item in argv):
        return False
    if not isinstance(env, list) or not all(isinstance(item, str) for item in env):
        return False
    for item in env:
        name, separator, _value = item.partition("=")
        if not separator or name not in EXEC_ENV_NAMES:
            return False
    for template in _EXEC_TEMPLATES:
        if len(template) != len(argv):
            continue
        if all(
            (part.fullmatch(value) is not None)
            if isinstance(part, re.Pattern)
            else part == value
            for part, value in zip(template, argv, strict=True)
        ):
            return True
    return False


# --- docker exec multiplexed stream ---------------------------------------------


class ExecDemuxer:
    """Split Docker's ``[stream,0,0,0,u32 size]`` frames into stdout bytes + stderr tail."""

    def __init__(self, stderr_limit: int = 4096) -> None:
        self._buffer = bytearray()
        self.stderr_tail = bytearray()
        self.stderr_limit = stderr_limit

    def feed(self, chunk: bytes) -> bytes:
        self._buffer.extend(chunk)
        out = bytearray()
        while len(self._buffer) >= 8:
            stream_type = self._buffer[0]
            size = struct.unpack(">I", self._buffer[4:8])[0]
            if len(self._buffer) < 8 + size:
                break
            payload = bytes(self._buffer[8 : 8 + size])
            del self._buffer[: 8 + size]
            if stream_type in (0, 1):
                out.extend(payload)
            elif stream_type == 2:
                self.stderr_tail.extend(payload)
                if len(self.stderr_tail) > self.stderr_limit:
                    del self.stderr_tail[: len(self.stderr_tail) - self.stderr_limit]
        return bytes(out)

    @property
    def pending(self) -> int:
        return len(self._buffer)


# --- volume tar -------------------------------------------------------------------


class StopRequested(Exception):
    pass


@dataclass(slots=True)
class TarStats:
    files: int = 0
    directories: int = 0
    symlinks: int = 0
    skipped_special: int = 0
    unreadable: int = 0
    changed: int = 0
    bytes: int = 0

    def public(self) -> dict[str, int]:
        return {
            "files": self.files,
            "directories": self.directories,
            "symlinks": self.symlinks,
            "skipped_special": self.skipped_special,
            "unreadable": self.unreadable,
            "changed": self.changed,
        }


class VolumeFs:
    """Filesystem primitives for the walk. Directory handles are opaque.

    On POSIX every lookup is relative to the parent directory descriptor with
    ``O_NOFOLLOW``; elsewhere (development on Windows) paths are used with
    ``lstat`` checks, which is enough for tests but not race-free.
    """

    def __init__(self) -> None:
        self.fd_mode = (
            os.open in os.supports_dir_fd
            and os.scandir in os.supports_fd
            and hasattr(os, "O_NOFOLLOW")
            and hasattr(os, "O_DIRECTORY")
        )

    def open_root(self, path: Path) -> Any:
        st = os.lstat(path)
        if not stat.S_ISDIR(st.st_mode):
            raise BackupSourceError("volume_unsupported")
        if self.fd_mode:
            return os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        return str(path)

    def close_dir(self, handle: Any) -> None:
        if self.fd_mode:
            os.close(handle)

    def list(self, handle: Any) -> list[str]:
        with os.scandir(handle) as entries:
            return sorted(entry.name for entry in entries)

    def lstat(self, parent: Any, name: str) -> os.stat_result:
        if self.fd_mode:
            return os.stat(name, dir_fd=parent, follow_symlinks=False)
        return os.lstat(os.path.join(parent, name))

    def open_dir(self, parent: Any, name: str) -> Any:
        if self.fd_mode:
            return os.open(
                name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent
            )
        path = os.path.join(parent, name)
        if not stat.S_ISDIR(os.lstat(path).st_mode):
            raise NotADirectoryError(path)
        return path

    def open_file(self, parent: Any, name: str) -> tuple[BinaryIO, os.stat_result]:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        flags |= getattr(os, "O_BINARY", 0)
        if self.fd_mode:
            descriptor = os.open(name, flags, dir_fd=parent)
        else:
            path = os.path.join(parent, name)
            if stat.S_ISLNK(os.lstat(path).st_mode):
                raise OSError("symlink")
            descriptor = os.open(path, flags)
        try:
            st = os.fstat(descriptor)
        except OSError:
            os.close(descriptor)
            raise
        return os.fdopen(descriptor, "rb", buffering=0), st

    def readlink(self, parent: Any, name: str) -> str:
        if self.fd_mode:
            return os.readlink(name, dir_fd=parent)
        return os.readlink(os.path.join(parent, name))


class _ExactReader:
    """Feed exactly ``size`` bytes to tarfile even if the file changed meanwhile."""

    def __init__(self, handle: BinaryIO, size: int, stats: TarStats) -> None:
        self.handle = handle
        self.remaining = size
        self.stats = stats
        self.short = False

    def read(self, size: int = -1) -> bytes:
        if self.remaining <= 0:
            return b""
        wanted = self.remaining if size < 0 else min(size, self.remaining)
        data = b"" if self.short else self.handle.read(wanted)
        if len(data) < wanted:
            if not self.short:
                self.short = True
                self.stats.changed += 1
            data += b"\0" * (wanted - len(data))
        self.remaining -= len(data)
        return data


def _tarinfo(name: str, st: os.stat_result) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.mode = stat.S_IMODE(st.st_mode)
    info.uid = int(getattr(st, "st_uid", 0) or 0)
    info.gid = int(getattr(st, "st_gid", 0) or 0)
    info.mtime = int(st.st_mtime)
    info.uname = ""
    info.gname = ""
    return info


def write_volume_tar(
    root: Path,
    output: Any,
    should_stop: Callable[[], bool] = lambda: False,
    fs: VolumeFs | None = None,
) -> TarStats:
    """Write ``root`` (a volume's ``_data``) as a PAX tar into ``output.write``."""
    fs = fs or VolumeFs()
    stats = TarStats()
    try:
        root_handle = fs.open_root(root)
    except PermissionError as exc:
        raise BackupSourceError("volume_unreadable", 403) from exc
    except FileNotFoundError as exc:
        raise BackupSourceError("not_found", 404) from exc
    try:
        with tarfile.open(fileobj=output, mode="w|", format=tarfile.PAX_FORMAT) as archive:
            stack: list[tuple[Any, str]] = [(root_handle, "")]
            opened: list[Any] = []
            try:
                while stack:
                    handle, prefix = stack.pop()
                    try:
                        names = fs.list(handle)
                    except PermissionError:
                        stats.unreadable += 1
                        continue
                    for name in names:
                        if should_stop():
                            raise StopRequested()
                        relative = f"{prefix}{name}"
                        try:
                            st = fs.lstat(handle, name)
                        except FileNotFoundError:
                            continue
                        except PermissionError:
                            stats.unreadable += 1
                            continue
                        mode = st.st_mode
                        if stat.S_ISDIR(mode):
                            try:
                                child = fs.open_dir(handle, name)
                            except (PermissionError, NotADirectoryError, OSError):
                                stats.unreadable += 1
                                continue
                            opened.append(child)
                            info = _tarinfo(relative, st)
                            info.type = tarfile.DIRTYPE
                            archive.addfile(info)
                            stats.directories += 1
                            stack.append((child, relative + "/"))
                        elif stat.S_ISLNK(mode):
                            try:
                                target = fs.readlink(handle, name)
                            except OSError:
                                stats.unreadable += 1
                                continue
                            info = _tarinfo(relative, st)
                            info.type = tarfile.SYMTYPE
                            info.linkname = target
                            archive.addfile(info)
                            stats.symlinks += 1
                        elif stat.S_ISREG(mode):
                            try:
                                handle_file, fst = fs.open_file(handle, name)
                            except PermissionError:
                                stats.unreadable += 1
                                continue
                            except OSError:
                                # ELOOP (swapped for a symlink), vanished, ...
                                stats.changed += 1
                                continue
                            with handle_file:
                                if not stat.S_ISREG(fst.st_mode):
                                    stats.skipped_special += 1
                                    continue
                                info = _tarinfo(relative, fst)
                                info.size = fst.st_size
                                archive.addfile(
                                    info,
                                    _ExactReader(handle_file, fst.st_size, stats),  # type: ignore[arg-type]
                                )
                            stats.files += 1
                            stats.bytes += fst.st_size
                        else:
                            stats.skipped_special += 1
            finally:
                for child in opened:
                    try:
                        fs.close_dir(child)
                    except OSError:
                        pass
    finally:
        try:
            fs.close_dir(root_handle)
        except OSError:
            pass
    return stats


@dataclass(slots=True)
class ChunkWriter:
    """``write()`` target for tarfile that hands fixed-size chunks to ``emit``."""

    emit: Callable[[bytes], None]
    chunk_size: int = 256 * 1024
    buffer: bytearray = field(default_factory=bytearray)
    total: int = 0

    def write(self, data: bytes) -> int:
        self.buffer.extend(data)
        self.total += len(data)
        while len(self.buffer) >= self.chunk_size:
            self.emit(bytes(self.buffer[: self.chunk_size]))
            del self.buffer[: self.chunk_size]
        return len(data)

    def flush(self) -> None:
        return None

    def close(self) -> None:
        if self.buffer:
            self.emit(bytes(self.buffer))
            self.buffer.clear()


def volume_data_path(volumes_root: Path, name: str) -> Path:
    if not VOLUME_NAME.fullmatch(name) or ".." in name:
        raise BackupSourceError("invalid_volume")
    volume_dir = volumes_root / name
    try:
        st = os.lstat(volume_dir)
    except FileNotFoundError as exc:
        raise BackupSourceError("not_found", 404) from exc
    except PermissionError as exc:
        raise BackupSourceError("volume_unreadable", 403) from exc
    if not stat.S_ISDIR(st.st_mode):
        raise BackupSourceError("volume_unsupported")
    return volume_dir / "_data"
