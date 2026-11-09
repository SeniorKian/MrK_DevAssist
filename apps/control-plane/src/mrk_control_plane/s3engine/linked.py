"""Linked-folder buckets: objects are real files under ``link_path`` (docs/30 §3.2).

Safety rules:

* keys map to path components; empty, ``.``, ``..``, NUL, over-long and reserved
  (``.mrk``, ``.mrk-tmp-*``) segments are refused;
* on POSIX every lookup walks component by component with
  ``os.open(..., O_NOFOLLOW | O_DIRECTORY, dir_fd=parent)``; symlinks are invisible
  in listings and denied on access, special files (fifo, socket, device) are never
  listed or opened, and nested mounts (other ``st_dev``) are not crossed;
* writes go to ``<dir>/.mrk-tmp-<uuid>`` in the destination directory, then fsync
  and an atomic rename; ``ro`` buckets reject every mutation with AccessDenied.

On platforms without ``dir_fd`` support (Windows development machines) the same
checks run path-based with ``lstat`` (reparse points are refused), which is not
race-free; production images are Linux.
"""

from __future__ import annotations

import asyncio
import errno
import hashlib
import logging
import mimetypes
import os
import stat
import time
import uuid
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from .errors import S3Error
from .index import BucketIndex, ObjectRecord, PartRecord, UploadRecord
from .listing import Entry
from .settings import EngineSettings
from .snapshot import BucketConfig
from .storage import (
    EMPTY_MD5,
    BaseBucket,
    ObjectInfo,
    PendingWrite,
    fsync_file,
)

LOGGER = logging.getLogger("mrk.s3.linked")
POSIX_SAFE = (
    os.name != "nt"
    and hasattr(os, "O_NOFOLLOW")
    and hasattr(os, "O_DIRECTORY")
    and os.open in os.supports_dir_fd
    and os.scandir in os.supports_fd
)
_O_BINARY = getattr(os, "O_BINARY", 0)
_REPARSE = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
_WINDOWS_BAD = set('\\:*?"<>|')
HIDDEN_NAMES = frozenset({".mrk", "lost+found"})
NAME_MAX = 255
PATH_MAX = 4096
COPY_BLOCK = 1024 * 1024


def is_hidden(name: str) -> bool:
    return name in HIDDEN_NAMES or name.startswith((".mrk-tmp-", ".mrk-probe"))


def key_parts(key: str) -> tuple[list[str], bool]:
    """Split a key into path components; raise for keys a filesystem cannot hold."""
    is_dir = key.endswith("/")
    body = key[:-1] if is_dir else key
    if len(key.encode("utf-8")) > PATH_MAX:
        raise S3Error("KeyTooLongError", "The key is too long for a linked folder (PATH_MAX).")
    if not body:
        raise S3Error(
            "InvalidArgument", "This key cannot be stored in a linked folder.", ArgumentName="key"
        )
    parts = body.split("/")
    for segment in parts:
        if segment in {"", ".", ".."} or "\x00" in segment:
            raise S3Error(
                "InvalidArgument",
                "Linked folders do not support empty, '.' or '..' path segments.",
                ArgumentName="key",
            )
        if len(segment.encode("utf-8")) > NAME_MAX:
            raise S3Error("KeyTooLongError", "A path segment is longer than 255 bytes (NAME_MAX).")
        if is_hidden(segment):
            raise S3Error(
                "InvalidArgument",
                "The .mrk prefix is reserved in linked folders.",
                ArgumentName="key",
            )
        if os.name == "nt" and (
            any(ch in _WINDOWS_BAD for ch in segment) or segment.endswith((".", " "))
        ):
            raise S3Error(
                "InvalidArgument", "This key is not a valid file name here.", ArgumentName="key"
            )
    return parts, is_dir


class DirHandle:
    __slots__ = ("fd", "path")

    def __init__(self, fd: int | None, path: str) -> None:
        self.fd = fd
        self.path = path

    def close(self) -> None:
        if self.fd is not None:
            try:
                os.close(self.fd)
            except OSError:
                pass
            self.fd = None

    def __enter__(self) -> DirHandle:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()


class SafeRoot:
    """No-follow, no-escape filesystem access below one directory."""

    def __init__(self, root: Path, *, one_filesystem: bool = True, dir_mode: int = 0o755) -> None:
        self.root = Path(os.path.realpath(root))
        self.one_filesystem = one_filesystem
        self.dir_mode = dir_mode
        self.root_dev = os.stat(self.root).st_dev

    # ------------------------------------------------------------------ directories
    def open_dir(self, parts: list[str], *, create: bool = False) -> DirHandle:
        if POSIX_SAFE:
            return self._open_dir_posix(parts, create)
        return self._open_dir_portable(parts, create)

    def _open_dir_posix(self, parts: list[str], create: bool) -> DirHandle:
        fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        path = str(self.root)
        try:
            for segment in parts:
                try:
                    child = os.open(
                        segment, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd
                    )
                except FileNotFoundError:
                    if not create:
                        raise
                    try:
                        os.mkdir(segment, self.dir_mode, dir_fd=fd)
                    except FileExistsError:
                        pass
                    child = os.open(
                        segment, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd
                    )
                except OSError as exc:
                    if exc.errno in {errno.ELOOP, errno.EMLINK}:
                        raise PermissionError(errno.EACCES, "symlinks are not allowed") from exc
                    raise
                if self.one_filesystem and os.fstat(child).st_dev != self.root_dev:
                    os.close(child)
                    raise PermissionError(errno.EXDEV, "nested mounts are not crossed")
                os.close(fd)
                fd = child
                path = f"{path}/{segment}"
        except BaseException:
            os.close(fd)
            raise
        return DirHandle(fd, path)

    def _check_portable(self, path: Path) -> os.stat_result:
        info = os.lstat(path)
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & _REPARSE:
            raise PermissionError(errno.EACCES, "symlinks are not allowed")
        return info

    def _open_dir_portable(self, parts: list[str], create: bool) -> DirHandle:
        current = self.root
        for segment in parts:
            current = current / segment
            try:
                info = self._check_portable(current)
            except FileNotFoundError:
                if not create:
                    raise
                os.makedirs(current, exist_ok=True)
                info = self._check_portable(current)
            if not stat.S_ISDIR(info.st_mode):
                raise NotADirectoryError(errno.ENOTDIR, "not a directory", str(current))
            if self.one_filesystem and info.st_dev != self.root_dev:
                raise PermissionError(errno.EXDEV, "nested mounts are not crossed")
        resolved = Path(os.path.realpath(current))
        if resolved != self.root and not resolved.is_relative_to(self.root):
            raise PermissionError(errno.EACCES, "path escapes the linked folder")
        return DirHandle(None, str(current))

    # ------------------------------------------------------------------ entries
    def lstat(self, handle: DirHandle, name: str) -> os.stat_result:
        if handle.fd is not None:
            return os.stat(name, dir_fd=handle.fd, follow_symlinks=False)
        return os.lstat(os.path.join(handle.path, name))

    def scandir(self, handle: DirHandle) -> list[tuple[str, os.stat_result]]:
        result: list[tuple[str, os.stat_result]] = []
        target: Any = handle.fd if handle.fd is not None else handle.path
        if handle.fd is not None:
            # scandir(fd) consumes the descriptor position; use a duplicate.
            target = os.dup(handle.fd)
        try:
            with os.scandir(target) as entries:
                for entry in entries:
                    try:
                        if handle.fd is None:
                            # Windows DirEntry.stat() leaves st_ino/st_dev at zero.
                            info = os.lstat(os.path.join(handle.path, entry.name))
                        else:
                            info = entry.stat(follow_symlinks=False)
                        result.append((entry.name, info))
                    except OSError:
                        continue
        finally:
            if handle.fd is not None and isinstance(target, int):
                try:
                    os.close(target)
                except OSError:
                    pass
        return result

    def open_read(self, handle: DirHandle, name: str) -> tuple[int, os.stat_result]:
        if handle.fd is not None:
            flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0)
            try:
                fd = os.open(name, flags, dir_fd=handle.fd)
            except OSError as exc:
                if exc.errno in {errno.ELOOP, errno.EMLINK}:
                    raise PermissionError(errno.EACCES, "symlinks are not allowed") from exc
                raise
        else:
            path = os.path.join(handle.path, name)
            self._check_portable(Path(path))
            fd = os.open(path, os.O_RDONLY | _O_BINARY)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            os.close(fd)
            raise PermissionError(errno.EACCES, "not a regular file")
        if self.one_filesystem and info.st_dev != self.root_dev:
            os.close(fd)
            raise PermissionError(errno.EXDEV, "nested mounts are not crossed")
        return fd, info

    def create_temp(self, handle: DirHandle, mode: int = 0o644) -> tuple[str, int]:
        name = f".mrk-tmp-{uuid.uuid4().hex}"
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | _O_BINARY | getattr(os, "O_NOFOLLOW", 0)
        if handle.fd is not None:
            fd = os.open(name, flags, mode, dir_fd=handle.fd)
        else:
            fd = os.open(os.path.join(handle.path, name), flags, mode)
        return name, fd

    def replace(self, handle: DirHandle, source: str, target: str) -> None:
        if handle.fd is not None:
            os.replace(source, target, src_dir_fd=handle.fd, dst_dir_fd=handle.fd)
        else:
            os.replace(os.path.join(handle.path, source), os.path.join(handle.path, target))

    def unlink(self, handle: DirHandle, name: str) -> None:
        if handle.fd is not None:
            os.unlink(name, dir_fd=handle.fd)
        else:
            os.unlink(os.path.join(handle.path, name))

    def rmdir(self, handle: DirHandle, name: str) -> None:
        if handle.fd is not None:
            os.rmdir(name, dir_fd=handle.fd)
        else:
            os.rmdir(os.path.join(handle.path, name))


def synthetic_etag(info: os.stat_result) -> str:
    raw = f"{info.st_ino}:{info.st_size}:{info.st_mtime_ns}".encode("ascii")
    return hashlib.sha256(raw).hexdigest()[:32]


class LinkedBucket(BaseBucket):
    kind = "linked"

    def __init__(self, settings: EngineSettings, config: BucketConfig, index: BucketIndex) -> None:
        super().__init__(settings, config, index)
        assert config.link_path is not None
        self.link_path = config.link_path
        self._safe: SafeRoot | None = None
        self.hash_queue: dict[str, None] = {}
        self._usage: tuple[float, tuple[int, int]] | None = None

    @property
    def safe(self) -> SafeRoot:
        if self._safe is None:
            try:
                self._safe = SafeRoot(self.link_path)
            except OSError as exc:
                raise S3Error(
                    "ServiceUnavailable", "The linked folder is not mounted.", 503
                ) from exc
        return self._safe

    def storage_path(self) -> Path:
        return self.safe.root

    def ensure(self) -> None:
        _ = self.safe

    # ------------------------------------------------------------------ metadata
    def _sidecar_valid(self, record: ObjectRecord | None, info: os.stat_result) -> bool:
        return (
            record is not None
            and record.size == info.st_size
            and record.mtime_ns == info.st_mtime_ns
            and record.inode == info.st_ino
        )

    def _file_info(
        self, key: str, info: os.stat_result, record: ObjectRecord | None = None
    ) -> ObjectInfo:
        if record is None:
            record = self.index.get(key)
        valid = self._sidecar_valid(record, info)
        if valid and record is not None and record.etag:
            etag, meta = record.etag, dict(record.meta)
        else:
            etag = synthetic_etag(info)
            meta = dict(record.meta) if valid and record is not None else {}
            valid = False
        if "content_type" not in meta:
            guessed, _ = mimetypes.guess_type(key.rsplit("/", 1)[-1])
            meta["content_type"] = guessed or "binary/octet-stream"
        result = ObjectInfo(
            key=key,
            size=info.st_size,
            etag=etag,
            last_modified_ns=info.st_mtime_ns,
            meta=meta,
            validated=valid,
        )
        if (
            not valid
            and info.st_size <= self.settings.hash_max_file_bytes
            and len(self.hash_queue) < 10000
        ):
            self.hash_queue[key] = None
        return result

    def head(self, key: str) -> ObjectInfo | None:
        try:
            parts, is_dir = key_parts(key)
        except S3Error:
            return None
        try:
            if is_dir:
                with self.safe.open_dir(parts) as handle:
                    info = os.fstat(handle.fd) if handle.fd is not None else os.stat(handle.path)
                return ObjectInfo(
                    key,
                    0,
                    EMPTY_MD5,
                    info.st_mtime_ns,
                    {"content_type": "application/x-directory"},
                    is_dir=True,
                )
            with self.safe.open_dir(parts[:-1]) as handle:
                info = self.safe.lstat(handle, parts[-1])
        except (OSError, ValueError):
            return None
        if not stat.S_ISREG(info.st_mode):
            return None
        if self.safe.one_filesystem and info.st_dev != self.safe.root_dev:
            return None
        return self._file_info(key, info)

    def open_object(self, info: ObjectInfo) -> list[tuple[int, int]]:
        if info.is_dir:
            return []
        parts, _ = key_parts(info.key)
        try:
            with self.safe.open_dir(parts[:-1]) as handle:
                fd, current = self.safe.open_read(handle, parts[-1])
        except FileNotFoundError as exc:
            raise S3Error("NoSuchKey", Key=info.key) from exc
        except OSError as exc:
            raise S3Error("AccessDenied", "The file cannot be read.") from exc
        if current.st_size != info.size or current.st_mtime_ns != info.last_modified_ns:
            os.close(fd)
            raise S3Error(
                "InternalError", "The file changed while it was being opened; retry.", 503
            )
        return [(fd, info.size)]

    # ------------------------------------------------------------------ writes
    def _parent(self, parts: list[str]) -> DirHandle:
        try:
            return self.safe.open_dir(parts[:-1], create=True)
        except NotADirectoryError as exc:
            raise S3Error(
                "InvalidArgument", "Path conflict: a parent of this key is a file."
            ) from exc
        except FileExistsError as exc:
            raise S3Error(
                "InvalidArgument", "Path conflict: a parent of this key is a file."
            ) from exc
        except PermissionError as exc:
            raise S3Error("AccessDenied", "The linked folder refused this path.") from exc

    def _check_target(self, handle: DirHandle, name: str) -> None:
        try:
            info = self.safe.lstat(handle, name)
        except FileNotFoundError:
            return
        if stat.S_ISDIR(info.st_mode):
            raise S3Error(
                "InvalidArgument", "Path conflict: this key is a directory in the linked folder."
            )
        if not stat.S_ISREG(info.st_mode):
            raise S3Error("AccessDenied", "The target is not a regular file.")

    def make_dir_marker(self, key: str) -> ObjectInfo:
        self.check_writable()
        parts, _ = key_parts(key)
        try:
            with self.safe.open_dir(parts, create=True):
                pass
        except NotADirectoryError as exc:
            raise S3Error(
                "InvalidArgument", "Path conflict: a file exists at this folder path."
            ) from exc
        except PermissionError as exc:
            raise S3Error("AccessDenied", "The linked folder refused this path.") from exc
        info = self.head(key)
        assert info is not None
        return info

    def new_temp(self, key: str) -> PendingWrite:
        self.check_writable()
        parts, is_dir = key_parts(key)
        if is_dir:
            raise S3Error("InvalidArgument", "Folder keys cannot carry data.")
        handle = self._parent(parts)
        try:
            self._check_target(handle, parts[-1])
            name, fd = self.safe.create_temp(handle)
        except BaseException:
            handle.close()
            raise
        pending = PendingWrite(
            os.path.join(handle.path, name), fd, final_dir=handle.path, final_name=parts[-1]
        )
        pending.extra.update(handle=handle, temp=name, parts=parts)
        return pending

    def discard(self, pending: PendingWrite) -> None:
        pending.close()
        handle: DirHandle = pending.extra["handle"]
        try:
            self.safe.unlink(handle, pending.extra["temp"])
        except OSError:
            pass
        handle.close()

    def commit_object(
        self, pending: PendingWrite, key: str, etag: str, meta: dict[str, Any]
    ) -> ObjectInfo:
        handle: DirHandle = pending.extra["handle"]
        try:
            fsync_file(pending.fd, self.settings.fsync_policy)
            pending.close()
            self._check_target(handle, pending.extra["parts"][-1])
            self.safe.replace(handle, pending.extra["temp"], pending.extra["parts"][-1])
            info = self.safe.lstat(handle, pending.extra["parts"][-1])
        except BaseException:
            try:
                self.safe.unlink(handle, pending.extra["temp"])
            except OSError:
                pass
            raise
        finally:
            handle.close()
        record = ObjectRecord(
            key=key,
            size=info.st_size,
            etag=etag,
            last_modified_ns=info.st_mtime_ns,
            meta=meta,
            layout=[],
            mtime_ns=info.st_mtime_ns,
            inode=info.st_ino,
            dev=info.st_dev,
        )
        self.index.put(record, count_stats=False)
        self._usage = None
        self.hash_queue.pop(key, None)
        return self._file_info(key, info, record)

    def set_object_meta(
        self, key: str, meta: dict[str, Any], version_id: str | None = None
    ) -> bool:
        """Tags live in the sidecar row, which stays valid while the file is unchanged."""
        if version_id not in (None, "null"):
            return False
        try:
            parts, is_dir = key_parts(key)
            if is_dir:
                return False
            with self.safe.open_dir(parts[:-1]) as handle:
                info = self.safe.lstat(handle, parts[-1])
        except (OSError, ValueError, S3Error):
            return False
        if not stat.S_ISREG(info.st_mode):
            return False
        record = self.index.get(key)
        etag = record.etag if record is not None and self._sidecar_valid(record, info) else ""
        self.index.put(
            ObjectRecord(
                key=key,
                size=info.st_size,
                etag=etag,
                last_modified_ns=info.st_mtime_ns,
                meta=meta,
                layout=[],
                mtime_ns=info.st_mtime_ns,
                inode=info.st_ino,
                dev=info.st_dev,
            ),
            count_stats=False,
        )
        return True

    def delete(self, key: str) -> bool:
        self.check_writable()
        try:
            parts, is_dir = key_parts(key)
        except S3Error:
            return False
        removed = False
        try:
            if is_dir:
                with self.safe.open_dir(parts[:-1]) as handle:
                    try:
                        self.safe.rmdir(handle, parts[-1])
                        removed = True
                    except OSError:
                        return False
            else:
                with self.safe.open_dir(parts[:-1]) as handle:
                    info = self.safe.lstat(handle, parts[-1])
                    if not stat.S_ISREG(info.st_mode):
                        return False
                    self.safe.unlink(handle, parts[-1])
                    removed = True
        except (OSError, ValueError):
            return removed
        self.index.delete(key, count_stats=False)
        self._usage = None
        self._prune(parts[:-1])
        return removed

    def _prune(self, parts: list[str]) -> None:
        while parts:
            try:
                with self.safe.open_dir(parts[:-1]) as handle:
                    self.safe.rmdir(handle, parts[-1])
            except OSError:
                return
            parts = parts[:-1]

    # ------------------------------------------------------------------ multipart
    def part_dir(self, upload_id: str) -> Path:
        return self.safe.root / ".mrk" / "uploads" / upload_id

    def part_temp(self, upload_id: str) -> PendingWrite:
        self.check_writable()
        try:
            with self.safe.open_dir([".mrk", "uploads", upload_id], create=True):
                pass
        except OSError as exc:
            raise S3Error(
                "AccessDenied", "Cannot stage multipart parts in this linked folder."
            ) from exc
        return super().part_temp(upload_id)

    def complete_upload(
        self, upload: UploadRecord, parts: list[PartRecord], etag: str, meta: dict[str, Any]
    ) -> ObjectInfo:
        self.check_writable()
        key_list, is_dir = key_parts(upload.key)
        if is_dir:
            raise S3Error("InvalidArgument", "Folder keys cannot carry data.")
        handle = self._parent(key_list)
        try:
            self._check_target(handle, key_list[-1])
            temp, fd = self.safe.create_temp(handle)
            try:
                for part in parts:
                    with open(self._absolute(part.path), "rb") as source:
                        while block := source.read(COPY_BLOCK):
                            view = memoryview(block)
                            while view:
                                view = view[os.write(fd, view) :]
                fsync_file(fd, self.settings.fsync_policy)
            finally:
                os.close(fd)
            self.safe.replace(handle, temp, key_list[-1])
            info = self.safe.lstat(handle, key_list[-1])
        except BaseException:
            try:
                self.safe.unlink(handle, temp)  # type: ignore[possibly-undefined]
            except (OSError, UnboundLocalError):
                pass
            raise
        finally:
            handle.close()
        self.index.finish_upload(upload.upload_id, None, keep_paths=set())
        record = ObjectRecord(
            key=upload.key,
            size=info.st_size,
            etag=etag,
            last_modified_ns=info.st_mtime_ns,
            meta=meta,
            layout=[],
            mtime_ns=info.st_mtime_ns,
            inode=info.st_ino,
            dev=info.st_dev,
        )
        self.index.put(record, count_stats=False)
        self._usage = None
        return self._file_info(upload.key, info, record)

    # ------------------------------------------------------------------ listing
    def iter_entries(self, prefix: str, delimiter: str):
        collapse = delimiter == "/"

        def source(start: str, inclusive: bool) -> Iterator[Entry]:
            yield from self._walk([], "", prefix, start, inclusive, collapse)

        return source

    def _visible(
        self, entries: list[tuple[str, os.stat_result]]
    ) -> list[tuple[str, str, bool, os.stat_result]]:
        items: list[tuple[str, str, bool, os.stat_result]] = []
        for name, info in entries:
            if is_hidden(name):
                continue
            try:
                name.encode("utf-8")
            except UnicodeEncodeError:
                continue  # not valid UTF-8 on disk: not addressable as a key
            mode = info.st_mode
            if stat.S_ISLNK(mode) or getattr(info, "st_file_attributes", 0) & _REPARSE:
                continue
            if stat.S_ISDIR(mode):
                if self.safe.one_filesystem and info.st_dev != self.safe.root_dev:
                    continue
                items.append((name + "/", name, True, info))
            elif stat.S_ISREG(mode):
                items.append((name, name, False, info))
        items.sort(key=lambda item: item[0])
        return items

    def _walk(
        self,
        parts: list[str],
        dir_key: str,
        prefix: str,
        start: str,
        inclusive: bool,
        collapse: bool,
    ) -> Iterator[Entry]:
        try:
            with self.safe.open_dir(parts) as handle:
                entries = self.safe.scandir(handle)
        except (OSError, S3Error):
            return
        items = self._visible(entries)
        if not items and dir_key:
            if dir_key.startswith(prefix) and (dir_key > start or (inclusive and dir_key == start)):
                yield Entry(dir_key, ("dir", parts, None))
            return
        for sort_name, name, is_dir, info in items:
            key = dir_key + sort_name
            if is_dir:
                if not (key.startswith(prefix) or prefix.startswith(key)):
                    continue
                if key < start and not start.startswith(key):
                    continue
                if (
                    collapse
                    and key.startswith(prefix)
                    and key.find("/", len(prefix)) == len(key) - 1
                ):
                    if key > start or (inclusive and key == start):
                        yield Entry(key, ("dir", parts + [name], info), collapsed=True)
                    continue
                yield from self._walk(parts + [name], key, prefix, start, inclusive, collapse)
            else:
                if not key.startswith(prefix):
                    continue
                if key < start or (key == start and not inclusive):
                    continue
                yield Entry(key, ("file", parts, info))

    def entry_info(self, entry: Entry) -> ObjectInfo:
        kind, _parts, info = entry.payload
        if kind == "dir":
            mtime = info.st_mtime_ns if info is not None else time.time_ns()
            return ObjectInfo(entry.key, 0, EMPTY_MD5, mtime, {}, is_dir=True)
        return self._file_info(entry.key, info)

    def usage(self) -> tuple[int, int]:
        cached = self._usage
        if cached and cached[0] > time.monotonic():
            return cached[1]
        objects = 0
        total = 0
        for entry in self._walk([], "", "", "", True, False):
            kind, _parts, info = entry.payload
            if kind == "file":
                objects += 1
                total += info.st_size
        self._usage = (time.monotonic() + 30, (objects, total))
        return objects, total

    def is_empty(self) -> bool:
        return True  # detaching a linked folder never deletes files

    def reconcile(self) -> dict[str, int]:
        keys: set[str] = set()
        objects = 0
        total = 0
        for entry in self._walk([], "", "", "", True, False):
            kind, _parts, info = entry.payload
            if kind == "file":
                keys.add(entry.key)
                objects += 1
                total += info.st_size
        removed = self.index.delete_keys_not_in(keys)
        self.index.set_stats(objects, total)
        self._usage = (time.monotonic() + 30, (objects, total))
        return {"objects": objects, "bytes": total, "pruned": removed}

    async def hash_one(self, key: str, rate_bytes: int) -> bool:
        """Compute and cache the real MD5 of an externally written file (lazy ETag)."""
        info = self.head(key)
        if info is None or info.validated or info.is_dir:
            return False
        try:
            opened = self.open_object(info)
        except S3Error:
            return False
        fd = opened[0][0]
        digest = hashlib.md5(usedforsecurity=False)
        try:
            while True:
                block = await asyncio.to_thread(os.read, fd, COPY_BLOCK)
                if not block:
                    break
                digest.update(block)
                if rate_bytes:
                    await asyncio.sleep(len(block) / rate_bytes)
            current = os.fstat(fd)
        finally:
            os.close(fd)
        if current.st_size != info.size or current.st_mtime_ns != info.last_modified_ns:
            return False
        self.store_md5(key, current, digest.hexdigest())
        return True

    def store_md5(self, key: str, info: os.stat_result, md5_hex: str) -> None:
        record = self.index.get(key)
        meta = dict(record.meta) if record is not None and self._sidecar_valid(record, info) else {}
        self.index.put(
            ObjectRecord(
                key=key,
                size=info.st_size,
                etag=md5_hex,
                last_modified_ns=info.st_mtime_ns,
                meta=meta,
                layout=[],
                mtime_ns=info.st_mtime_ns,
                inode=info.st_ino,
                dev=info.st_dev,
            ),
            count_stats=False,
        )
        self.hash_queue.pop(key, None)

    def gc(self, now_ns: int) -> dict[str, int]:
        result = super().gc(now_ns)
        cutoff = time.time() - 24 * 3600
        for entry in self._walk_temp([]):
            parts, name = entry
            try:
                with self.safe.open_dir(parts) as handle:
                    info = self.safe.lstat(handle, name)
                    if stat.S_ISREG(info.st_mode) and info.st_mtime < cutoff:
                        self.safe.unlink(handle, name)
                        result["tmp"] += 1
            except OSError:
                continue
        uploads = self.safe.root / ".mrk" / "uploads"
        try:
            live = {upload.upload_id for upload in self.index.list_uploads()}
            if uploads.is_dir() and not uploads.is_symlink():
                for item in uploads.iterdir():
                    if item.name not in live and item.is_dir() and not item.is_symlink():
                        if not any(item.iterdir()):
                            item.rmdir()
        except OSError:
            pass
        return result

    def _walk_temp(self, parts: list[str]) -> Iterator[tuple[list[str], str]]:
        try:
            with self.safe.open_dir(parts) as handle:
                entries = self.safe.scandir(handle)
        except OSError:
            return
        for name, info in entries:
            if name.startswith(".mrk-tmp-") and stat.S_ISREG(info.st_mode):
                yield parts, name
            elif (
                stat.S_ISDIR(info.st_mode)
                and not is_hidden(name)
                and not (self.safe.one_filesystem and info.st_dev != self.safe.root_dev)
            ):
                yield from self._walk_temp(parts + [name])
