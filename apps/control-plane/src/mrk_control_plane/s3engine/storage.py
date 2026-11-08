"""Bucket storage: write pipeline, managed buckets and shared multipart state (docs/30 §3)."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import logging
import os
import secrets
import shutil
import time
import uuid
from collections.abc import AsyncIterator, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import checksums
from .errors import S3Error
from .index import BucketIndex, ObjectRecord, PartRecord, UploadRecord
from .listing import Entry
from .settings import EngineSettings
from .snapshot import BucketConfig

LOGGER = logging.getLogger("mrk.s3.storage")
WRITE_BLOCK = 1024 * 1024
READ_BLOCK = 1024 * 1024
EMPTY_MD5 = hashlib.md5(b"", usedforsecurity=False).hexdigest()
_O_BINARY = getattr(os, "O_BINARY", 0)


@dataclass(slots=True)
class ObjectInfo:
    key: str
    size: int
    etag: str  # unquoted
    last_modified_ns: int
    meta: dict[str, Any] = field(default_factory=dict)
    segments: list[tuple[str, int]] = field(default_factory=list)  # absolute paths (managed)
    is_dir: bool = False
    validated: bool = True  # linked: metadata/etag still matches the file

    @property
    def parts_count(self) -> int | None:
        value = self.meta.get("parts_count")
        return int(value) if value else None


class BodyHasher:
    """MD5 always, plus the requested flexible checksums and an optional SHA-256."""

    def __init__(self, algorithms: set[str], *, sha256: bool = False) -> None:
        self.md5 = hashlib.md5(usedforsecurity=False)
        self.algorithms = {name: checksums.new_hasher(name) for name in sorted(algorithms)}
        self.sha256 = hashlib.sha256() if sha256 else None

    def update(self, block: bytes) -> None:
        self.md5.update(block)
        for hasher in self.algorithms.values():
            hasher.update(block)
        if self.sha256 is not None:
            self.sha256.update(block)

    def digests(self) -> dict[str, bytes]:
        return {name: hasher.digest() for name, hasher in self.algorithms.items()}

    def checksum_values(self) -> dict[str, str]:
        return {name: checksums.b64(digest) for name, digest in self.digests().items()}


@dataclass(slots=True)
class PendingWrite:
    path: str  # absolute path of the temp file
    fd: int
    final_dir: str | None = None
    final_name: str | None = None
    written: int = 0
    closed: bool = False
    extra: dict[str, Any] = field(default_factory=dict)

    def close(self) -> None:
        if not self.closed:
            self.closed = True
            os.close(self.fd)

    def abort(self) -> None:
        self.close()
        try:
            os.unlink(self.path)
        except OSError:
            pass


def _process_block(fd: int, hasher: BodyHasher, block: bytes) -> None:
    hasher.update(block)
    view = memoryview(block)
    while view:
        written = os.write(fd, view)
        view = view[written:]


async def write_stream(
    source: AsyncIterator[bytes],
    pending: PendingWrite,
    hasher: BodyHasher,
    *,
    size_limit: int | None = None,
    quota_limit: int | None = None,
) -> int:
    """Stream ``source`` into the temp file, hashing on a worker thread in 1 MiB blocks."""
    buffer = bytearray()
    total = 0
    async for piece in source:
        if not piece:
            continue
        total += len(piece)
        if size_limit is not None and total > size_limit:
            raise S3Error("EntityTooLarge", MaxSizeAllowed=str(size_limit))
        if quota_limit is not None and total > quota_limit:
            raise S3Error("QuotaExceeded")
        buffer += piece
        if len(buffer) >= WRITE_BLOCK:
            block = bytes(buffer)
            buffer.clear()
            await asyncio.to_thread(_process_block, pending.fd, hasher, block)
    if buffer:
        await asyncio.to_thread(_process_block, pending.fd, hasher, bytes(buffer))
    pending.written = total
    return total


def fsync_file(fd: int, policy: str) -> None:
    if policy != "none":
        os.fsync(fd)


def fsync_dir(path: str, policy: str) -> None:
    if policy != "strict" or os.name == "nt":
        return
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def new_upload_id() -> str:
    return base64.urlsafe_b64encode(secrets.token_bytes(24)).decode("ascii").rstrip("=")


def multipart_etag(md5_hexes: list[str]) -> str:
    digest = hashlib.md5(
        b"".join(bytes.fromhex(h) for h in md5_hexes), usedforsecurity=False
    ).hexdigest()
    return f"{digest}-{len(md5_hexes)}"


class BaseBucket:
    """State shared by managed and linked buckets."""

    kind = "base"

    def __init__(self, settings: EngineSettings, config: BucketConfig, index: BucketIndex) -> None:
        self.settings = settings
        self.config = config
        self.index = index
        self.name = config.name
        self.key_locks: dict[str, asyncio.Lock] = {}

    # Hooks implemented by subclasses ------------------------------------------------
    def ensure(self) -> None:
        raise NotImplementedError

    def head(self, key: str) -> ObjectInfo | None:
        raise NotImplementedError

    def iter_entries(self, prefix: str, delimiter: str) -> Any:
        raise NotImplementedError

    def usage(self) -> tuple[int, int]:
        raise NotImplementedError

    def storage_path(self) -> Path:
        raise NotImplementedError

    def lock_for(self, key: str) -> asyncio.Lock:
        lock = self.key_locks.get(key)
        if lock is None:
            if len(self.key_locks) > 4096:
                for name in [name for name, item in self.key_locks.items() if not item.locked()]:
                    self.key_locks.pop(name, None)
            lock = self.key_locks[key] = asyncio.Lock()
        return lock

    def check_writable(self) -> None:
        if self.config.read_only:
            raise S3Error("AccessDenied", "The bucket is read-only (linked folder).")

    # Multipart ---------------------------------------------------------------------
    def create_upload(self, key: str, meta: dict[str, Any], initiator: str) -> UploadRecord:
        self.check_writable()
        upload = UploadRecord(new_upload_id(), key, time.time_ns(), meta, initiator)
        self.index.create_upload(upload)
        return upload

    def get_upload(self, upload_id: str, key: str) -> UploadRecord:
        upload = self.index.get_upload(upload_id)
        if upload is None or upload.key != key:
            raise S3Error("NoSuchUpload", UploadId=upload_id)
        return upload

    def part_dir(self, upload_id: str) -> Path:
        raise NotImplementedError

    def part_temp(self, upload_id: str) -> PendingWrite:
        directory = self.part_dir(upload_id)
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / f".tmp-{uuid.uuid4().hex}"
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | _O_BINARY, 0o600)
        return PendingWrite(str(path), fd)

    def commit_part(
        self,
        pending: PendingWrite,
        upload: UploadRecord,
        number: int,
        md5_hex: str,
        values: dict[str, str],
    ) -> PartRecord:
        fsync_file(pending.fd, self.settings.fsync_policy)
        pending.close()
        final = self.part_dir(upload.upload_id) / f"{number}.{uuid.uuid4().hex}"
        os.replace(pending.path, final)
        part = PartRecord(
            upload.upload_id,
            number,
            pending.written,
            md5_hex,
            values,
            self._relative(final),
            time.time_ns(),
        )
        try:
            old = self.index.put_part(part)
        except KeyError:
            os.unlink(final)
            raise S3Error("NoSuchUpload", UploadId=upload.upload_id) from None
        if old is not None:
            self.index.trash_add([old.path])
        return part

    def abort_upload(self, upload_id: str) -> None:
        self.index.finish_upload(upload_id, None, keep_paths=set())
        self._remove_part_dir(upload_id)

    def _remove_part_dir(self, upload_id: str) -> None:
        directory = self.part_dir(upload_id)
        # Part files are queued in the trash; the GC removes the directory later.
        try:
            if directory.is_dir() and not any(directory.iterdir()):
                directory.rmdir()
        except OSError:
            pass

    def _relative(self, path: Path) -> str:
        return path.relative_to(self.storage_path()).as_posix()

    def _absolute(self, relative: str) -> Path:
        candidate = (self.storage_path() / relative).resolve()
        base = self.storage_path().resolve()
        if not candidate.is_relative_to(base):
            raise ValueError("path escapes bucket storage")
        return candidate

    # GC ----------------------------------------------------------------------------
    def gc(self, now_ns: int) -> dict[str, int]:
        result = {"trash": 0, "uploads": 0, "tmp": 0}
        due = self.index.trash_due(now_ns - self.settings.trash_grace_seconds * 1_000_000_000)
        done: list[str] = []
        for relative in due:
            try:
                os.unlink(self._absolute(relative))
                done.append(relative)
            except FileNotFoundError:
                done.append(relative)
            except (OSError, ValueError):
                if os.name != "nt":
                    LOGGER.warning("could not delete trashed file", extra={"bucket": self.name})
        if done:
            self.index.trash_done(done)
        result["trash"] = len(done)
        ttl_ns = self.settings.multipart_upload_ttl_days * 86400 * 1_000_000_000
        for upload_id in self.index.stale_uploads(now_ns - ttl_ns):
            self.abort_upload(upload_id)
            result["uploads"] += 1
        return result


class ManagedBucket(BaseBucket):
    kind = "managed"

    def __init__(self, settings: EngineSettings, config: BucketConfig, index: BucketIndex) -> None:
        super().__init__(settings, config, index)
        self.root = settings.buckets_dir / config.name

    def storage_path(self) -> Path:
        return self.root

    def ensure(self) -> None:
        for name in ("objects", "parts", ".tmp"):
            (self.root / name).mkdir(parents=True, exist_ok=True)

    def usage(self) -> tuple[int, int]:
        return self.index.stats()

    def part_dir(self, upload_id: str) -> Path:
        return self.root / "parts" / upload_id

    def new_temp(self, key: str) -> PendingWrite:
        directory = self.root / ".tmp"
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / f"{uuid.uuid4().hex}.part"
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | _O_BINARY, 0o600)
        return PendingWrite(str(path), fd)

    def _new_object_path(self) -> Path:
        name = uuid.uuid4().hex
        directory = self.root / "objects" / name[:2] / name[2:4]
        directory.mkdir(parents=True, exist_ok=True)
        return directory / name

    def _info(self, record: ObjectRecord) -> ObjectInfo:
        return ObjectInfo(
            key=record.key,
            size=record.size,
            etag=record.etag,
            last_modified_ns=record.last_modified_ns,
            meta=record.meta,
            segments=[(str(self.root / item[0]), int(item[1])) for item in record.layout],
            is_dir=False,
        )

    def head(self, key: str) -> ObjectInfo | None:
        record = self.index.get(key)
        return self._info(record) if record else None

    def commit_object(
        self, pending: PendingWrite, key: str, etag: str, meta: dict[str, Any]
    ) -> ObjectInfo:
        fsync_file(pending.fd, self.settings.fsync_policy)
        pending.close()
        final = self._new_object_path()
        os.replace(pending.path, final)
        fsync_dir(str(final.parent), self.settings.fsync_policy)
        record = ObjectRecord(
            key=key,
            size=pending.written,
            etag=etag,
            last_modified_ns=time.time_ns(),
            meta=meta,
            layout=[[self._relative(final), pending.written]],
        )
        self.index.put(record)
        return self._info(record)

    def link_copy(self, source: ObjectInfo, key: str, meta: dict[str, Any]) -> ObjectInfo | None:
        """Copy within the managed store by hard-linking content files (no data copy)."""
        layout: list[list[Any]] = []
        created: list[Path] = []
        try:
            for path, size in source.segments:
                target = self._new_object_path()
                os.link(path, target)
                created.append(target)
                layout.append([self._relative(target), size])
        except OSError:
            for path in created:
                try:
                    path.unlink()
                except OSError:
                    pass
            return None
        record = ObjectRecord(
            key=key,
            size=source.size,
            etag=source.etag,
            last_modified_ns=time.time_ns(),
            meta=meta,
            layout=layout,
        )
        self.index.put(record)
        return self._info(record)

    def delete(self, key: str) -> bool:
        self.check_writable()
        return self.index.delete(key) is not None

    def complete_upload(
        self, upload: UploadRecord, parts: list[PartRecord], etag: str, meta: dict[str, Any]
    ) -> ObjectInfo:
        layout: list[list[Any]] = []
        for part in parts:
            source = self._absolute(part.path)
            target = self._new_object_path()
            os.replace(source, target)
            layout.append([self._relative(target), part.size])
        record = ObjectRecord(
            key=upload.key,
            size=sum(part.size for part in parts),
            etag=etag,
            last_modified_ns=time.time_ns(),
            meta=meta,
            layout=layout,
        )
        self.index.finish_upload(upload.upload_id, record, keep_paths={part.path for part in parts})
        self._remove_part_dir(upload.upload_id)
        return self._info(record)

    def iter_entries(self, prefix: str, delimiter: str):
        def source(start: str, inclusive: bool) -> Iterator[Entry]:
            for record in self.index.iter_objects(start, inclusive=inclusive, prefix=prefix):
                yield Entry(record.key, self._info(record))

        return source

    def is_empty(self) -> bool:
        return not self.index.has_objects() and not self.index.has_uploads()

    def gc(self, now_ns: int) -> dict[str, int]:
        result = super().gc(now_ns)
        cutoff = time.time() - self.settings.tmp_ttl_seconds
        tmp_dir = self.root / ".tmp"
        if tmp_dir.is_dir():
            for item in tmp_dir.iterdir():
                try:
                    if item.stat().st_mtime < cutoff:
                        item.unlink()
                        result["tmp"] += 1
                except OSError:
                    continue
        parts_dir = self.root / "parts"
        if parts_dir.is_dir():
            live = {upload.upload_id for upload in self.index.list_uploads()}
            for item in parts_dir.iterdir():
                if item.name not in live:
                    shutil.rmtree(item, ignore_errors=True)
        return result

    def orphan_sweep(self, min_age_seconds: int = 3600) -> int:
        """Delete content files no index row references (crash between rename and commit)."""
        referenced = self.index.all_layout_paths()
        trashed = set(self.index.trash_due(time.time_ns() + 10**18, limit=10**9))
        cutoff = time.time() - min_age_seconds
        removed = 0
        objects = self.root / "objects"
        if not objects.is_dir():
            return 0
        for path in objects.rglob("*"):
            if not path.is_file():
                continue
            relative = self._relative(path)
            if relative in referenced or relative in trashed:
                continue
            try:
                if path.stat().st_mtime < cutoff:
                    path.unlink()
                    removed += 1
            except OSError:
                continue
        return removed


def open_segments(segments: list[tuple[str, int]]) -> list[tuple[int, int]]:
    """Open every content file up front so a concurrent delete cannot cut a GET short."""
    opened: list[tuple[int, int]] = []
    try:
        for path, size in segments:
            opened.append((os.open(path, os.O_RDONLY | _O_BINARY), size))
    except OSError:
        for fd, _ in opened:
            os.close(fd)
        raise
    return opened


def _pread(fd: int, size: int, offset: int) -> bytes:
    if hasattr(os, "pread"):
        return os.pread(fd, size, offset)
    os.lseek(fd, offset, os.SEEK_SET)
    return os.read(fd, size)


async def stream_fds(opened: list[tuple[int, int]], start: int, end: int) -> AsyncIterator[bytes]:
    """Yield bytes ``start..end`` (inclusive) across the opened segment files."""
    try:
        offset = 0
        for fd, size in opened:
            seg_start, seg_end = offset, offset + size - 1
            offset += size
            if size == 0 or seg_end < start or seg_start > end:
                continue
            position = max(start, seg_start) - seg_start
            last = min(end, seg_end) - seg_start
            while position <= last:
                count = min(READ_BLOCK, last - position + 1)
                data = await asyncio.to_thread(_pread, fd, count, position)
                if not data:
                    raise S3Error("InternalError", "Object data is shorter than its index entry.")
                position += len(data)
                yield data
    finally:
        for fd, _ in opened:
            try:
                os.close(fd)
            except OSError:
                pass
