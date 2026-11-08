"""Encrypted appliance backups.

Format 2 (``MRKBKP2``) is a chunked AEAD stream so archives of any size can be
written and validated in one pass without a decrypted temporary copy::

    "MRKBKP2\\0" | u32 header_len | header JSON
    record*      : u8 last | u32 ct_len | AES-256-GCM(ciphertext || tag)

* ``K = HKDF-SHA256(scrypt(passphrase, salt), salt=file_id, info="mrk-backup-v2")``
* ``nonce_i = nonce_prefix(7) || u32be(i) || last(1)``
* ``aad_i   = SHA-256(header_bytes) || u64be(i)``

Data records (``last=0``) carry the tar.gz stream. The single final record
(``last=1``) is a JSON trailer ``{manifest_sha256, plaintext_bytes, record_count}``;
a missing final record, a record after it or trailing bytes are rejected, so
truncation and reordering are detected. Format 1 (single GCM stream) remains
readable.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import io
import json
import os
import secrets
import shutil
import sqlite3
import struct
import tarfile
import time
from collections.abc import Callable
from pathlib import Path, PurePosixPath
from typing import BinaryIO

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from sqlalchemy import MetaData, inspect, select

from .database import Database

MAGIC = b"MRKBKP1\0"
MAGIC_V2 = b"MRKBKP2\0"
MAX_HEADER_BYTES = 64 * 1024
MAX_MEMBERS = 2_000_000
MAX_MANIFEST_BYTES = 512 * 1024 * 1024
RESTORE_PLAN_TTL_SECONDS = 3600
CHUNK_SIZE = 4 * 1024 * 1024
# Format 1 parameters (kept for reading old backups).
KDF_N = 2**15
KDF_R = 8
KDF_P = 1
# Format 2 parameters: 128 MiB scrypt.
KDF_N_V2 = 2**17
KDF_BOUNDS = {"n": (2**14, 2**20), "r": (8, 16), "p": (1, 4)}
HKDF_INFO = b"mrk-backup-v2"
CIPHER_V1 = "AES-256-GCM"
CIPHER_V2 = "AES-256-GCM-STREAM"
DATA_ROOTS = ("control-plane", "logs", "npm", "pypi")
PROFILES: dict[str, tuple[str, ...]] = {
    # Rebuildable package caches are left out; the npm/PyPI engine state that
    # is not a cache (Verdaccio users, devpi credentials) stays consistent
    # because the whole ``pypi`` tree is either kept or replaced together.
    "config": ("control-plane", "logs", "npm/auth", "npm/config"),
    "full": DATA_ROOTS,
}
EXCLUDED_CONTROL_PLANE = frozenset(
    {
        "control-plane/control-plane.sqlite3",
        "control-plane/tasks.sqlite3",
        "control-plane/integrity-ledger.sqlite3",
        "control-plane/database-logical.json",
    }
)
FREE_SPACE_CHECK_BYTES = 256 * 1024 * 1024
PUBLIC_HEADER_FIELDS = (
    "format",
    "backup_id",
    "created_at",
    "app_version",
    "cipher",
    "kdf",
    "profile",
    "roots",
    "estimated_bytes",
)


class BackupError(ValueError):
    """A backup failure with a stable error code (ValueError for API compatibility)."""

    def __init__(self, error_code: str, message: str) -> None:
        super().__init__(message)
        self.error_code = error_code


class BackupCancelled(Exception):
    error_code = "cancelled"


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        return default


class _HashingReader:
    def __init__(self, source: BinaryIO) -> None:
        self.source = source
        self.digest = hashlib.sha256()

    def read(self, size: int = -1) -> bytes:
        value = self.source.read(size)
        self.digest.update(value)
        return value


def _derive_key(
    passphrase: str, salt: bytes, n: int = KDF_N, r: int = KDF_R, p: int = KDF_P
) -> bytes:
    if not 16 <= len(passphrase) <= 1024:
        raise ValueError("passphrase must be between 16 and 1024 characters")
    return Scrypt(salt=salt, length=32, n=n, r=r, p=p).derive(passphrase.encode("utf-8"))


def _kdf_params(header: dict[str, object]) -> tuple[int, int, int]:
    kdf = header.get("kdf")
    if not isinstance(kdf, dict) or kdf.get("name") != "scrypt":
        raise BackupError("unsupported_kdf", "unsupported key derivation")
    values: list[int] = []
    for name in ("n", "r", "p"):
        value = kdf.get(name)
        low, high = KDF_BOUNDS[name]
        if not isinstance(value, int) or not low <= value <= high:
            raise BackupError("unsupported_kdf", "key derivation parameters out of bounds")
        values.append(value)
    if values[0] & (values[0] - 1):
        raise BackupError("unsupported_kdf", "scrypt n must be a power of two")
    return values[0], values[1], values[2]


def _b64(header: dict[str, object], field: str, length: int) -> bytes:
    try:
        value = base64.b64decode(str(header[field]), validate=True)
    except (KeyError, ValueError) as exc:
        raise BackupError("invalid_header", f"backup header field {field} is invalid") from exc
    if len(value) != length:
        raise BackupError("invalid_header", f"backup header field {field} is invalid")
    return value


def _stream_key(passphrase: str, header: dict[str, object]) -> bytes:
    n, r, p = _kdf_params(header)
    master = _derive_key(passphrase, _b64(header, "salt", 16), n, r, p)
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=_b64(header, "file_id", 16),
        info=HKDF_INFO,
    ).derive(master)


def _safe_member(name: str) -> PurePosixPath:
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts or not path.parts or "\\" in name:
        raise ValueError("unsafe archive path")
    return path


class _EncryptingWriter:
    """File-like sink for ``tarfile`` that emits authenticated chunk records."""

    def __init__(
        self,
        output: BinaryIO,
        key: bytes,
        header_bytes: bytes,
        nonce_prefix: bytes,
        should_stop: Callable[[], bool] | None = None,
    ) -> None:
        self.output = output
        self.aead = AESGCM(key)
        self.header_digest = hashlib.sha256(header_bytes).digest()
        self.nonce_prefix = nonce_prefix
        self.should_stop = should_stop
        self.buffer = bytearray()
        self.index = 0
        self.plaintext_bytes = 0

    def write(self, data: bytes) -> int:
        self.buffer.extend(data)
        while len(self.buffer) >= CHUNK_SIZE:
            chunk = bytes(self.buffer[:CHUNK_SIZE])
            del self.buffer[:CHUNK_SIZE]
            self._emit(chunk, last=False)
        return len(data)

    def flush(self) -> None:
        return None

    def _emit(self, plaintext: bytes, last: bool) -> None:
        if self.should_stop is not None and self.should_stop():
            raise BackupCancelled()
        if self.index >= 2**32:
            raise BackupError("too_large", "backup exceeds the record limit")
        flag = 1 if last else 0
        nonce = self.nonce_prefix + struct.pack(">IB", self.index, flag)
        aad = self.header_digest + struct.pack(">Q", self.index)
        sealed = self.aead.encrypt(nonce, plaintext, aad)
        self.output.write(struct.pack(">BI", flag, len(sealed)))
        self.output.write(sealed)
        if not last:
            self.plaintext_bytes += len(plaintext)
        self.index += 1

    def finish(self, trailer: dict[str, object]) -> None:
        if self.buffer:
            self._emit(bytes(self.buffer), last=False)
            self.buffer.clear()
        record_count = self.index
        payload = {
            **trailer,
            "plaintext_bytes": self.plaintext_bytes,
            "record_count": record_count,
        }
        self._emit(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8"),
            last=True,
        )


class _DecryptingReader:
    """File-like source that verifies every record before releasing plaintext."""

    def __init__(
        self, source: BinaryIO, key: bytes, header_bytes: bytes, nonce_prefix: bytes
    ) -> None:
        self.source = source
        self.aead = AESGCM(key)
        self.header_digest = hashlib.sha256(header_bytes).digest()
        self.nonce_prefix = nonce_prefix
        self.buffer = bytearray()
        self.index = 0
        self.plaintext_bytes = 0
        self.trailer: dict[str, object] | None = None

    def _exact(self, size: int) -> bytes:
        value = self.source.read(size)
        if len(value) != size:
            raise BackupError("truncated", "backup is truncated")
        return value

    def _next_record(self) -> None:
        prefix = self.source.read(5)
        if not prefix:
            raise BackupError("truncated", "backup is truncated (final record missing)")
        if len(prefix) != 5:
            raise BackupError("truncated", "backup is truncated")
        flag, length = struct.unpack(">BI", prefix)
        if flag not in {0, 1} or not 16 <= length <= CHUNK_SIZE + 16:
            raise BackupError("corrupt", "backup record header is invalid")
        if self.index >= 2**32:
            raise BackupError("corrupt", "backup has too many records")
        sealed = self._exact(length)
        nonce = self.nonce_prefix + struct.pack(">IB", self.index, flag)
        aad = self.header_digest + struct.pack(">Q", self.index)
        try:
            plaintext = self.aead.decrypt(nonce, sealed, aad)
        except InvalidTag as exc:
            raise BackupError("authentication_failed", "backup authentication failed") from exc
        if flag == 1:
            trailer = json.loads(plaintext)
            if (
                not isinstance(trailer, dict)
                or trailer.get("record_count") != self.index
                or trailer.get("plaintext_bytes") != self.plaintext_bytes
                or not isinstance(trailer.get("manifest_sha256"), str)
            ):
                raise BackupError("corrupt", "backup trailer is inconsistent")
            if self.source.read(1):
                raise BackupError("corrupt", "backup has trailing data")
            self.trailer = trailer
        else:
            self.plaintext_bytes += len(plaintext)
            self.buffer.extend(plaintext)
        self.index += 1

    def read(self, size: int = -1) -> bytes:
        while self.trailer is None and (size < 0 or len(self.buffer) < size):
            self._next_record()
        if size < 0:
            size = len(self.buffer)
        value = bytes(self.buffer[:size])
        del self.buffer[:size]
        return value

    def drain(self) -> dict[str, object]:
        while self.trailer is None:
            self._next_record()
            self.buffer.clear()
        return self.trailer


MemberSink = Callable[[str, BinaryIO], tuple[str, int]]


def _hash_member(_name: str, payload: BinaryIO) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    while chunk := payload.read(1024 * 1024):
        digest.update(chunk)
        size += len(chunk)
    return digest.hexdigest(), size


class BackupManager:
    def __init__(
        self, data_dir: Path, version: str, database: Database | None = None
    ) -> None:
        self.data_dir = data_dir
        self.version = version
        self.database = database
        self.backup_dir = data_dir / "backups" / "encrypted"
        self.work_dir = data_dir / "tmp" / "backup-work"
        self.restore_plan_dir = data_dir / "control-plane" / "restore-plans"
        self.backup_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.work_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.restore_plan_dir.mkdir(parents=True, exist_ok=True, mode=0o700)

    def cleanup_stale(self, max_age_seconds: int = 86400) -> int:
        """Remove temporaries left by a killed backup/validate (call when idle)."""
        removed = 0
        cutoff = time.time() - max_age_seconds
        for path in list(self.backup_dir.glob(".*.tmp")) + list(self.work_dir.iterdir()):
            try:
                if path.lstat().st_mtime > cutoff:
                    continue
                if path.is_dir() and not path.is_symlink():
                    shutil.rmtree(path, ignore_errors=True)
                else:
                    path.unlink()
                removed += 1
            except OSError:
                continue
        return removed

    # -- sources ----------------------------------------------------------
    def _snapshot_sqlite(self, source: Path, destination: Path) -> None:
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with (
            contextlib.closing(sqlite3.connect(source)) as source_db,
            contextlib.closing(sqlite3.connect(destination)) as target,
        ):
            source_db.backup(target)

    @staticmethod
    def _included(relative: str, profile: str) -> bool:
        return any(
            relative == root or relative.startswith(f"{root}/") for root in PROFILES[profile]
        )

    @staticmethod
    def _may_contain(relative: str, profile: str) -> bool:
        return any(
            relative == root
            or relative.startswith(f"{root}/")
            or root.startswith(f"{relative}/")
            for root in PROFILES[profile]
        )

    def _source_files(self, profile: str = "full") -> list[tuple[Path, str]]:
        if profile not in PROFILES:
            raise BackupError("unknown_profile", "unknown backup profile")
        files: list[tuple[Path, str]] = []
        root = str(self.data_dir)
        for directory, dirnames, filenames in os.walk(root):
            relative_dir = os.path.relpath(directory, root).replace("\\", "/")
            relative_dir = "" if relative_dir == "." else relative_dir
            kept: list[str] = []
            for name in dirnames:
                relative = f"{relative_dir}/{name}" if relative_dir else name
                if relative in {
                    "control-plane/restore-plans",
                    "control-plane/restore-receipts",
                } or not self._may_contain(relative, profile):
                    continue
                if os.path.islink(os.path.join(directory, name)):
                    raise BackupError("symlink", f"symlink is not allowed: {relative}")
                kept.append(name)
            dirnames[:] = kept
            for name in filenames:
                relative = f"{relative_dir}/{name}" if relative_dir else name
                if not self._included(relative, profile):
                    continue
                path = Path(directory, name)
                if path.is_symlink():
                    raise BackupError("symlink", f"symlink is not allowed: {relative}")
                if not path.is_file():
                    continue
                if name.endswith(("-wal", "-shm", "-journal")):
                    continue
                if relative.startswith("control-plane/runtime-heartbeat"):
                    continue
                if relative in EXCLUDED_CONTROL_PLANE:
                    continue
                files.append((path, relative))
        files.sort(key=lambda item: item[1])
        return files

    def _snapshot_logical_database(self, destination: Path) -> None:
        if self.database is None:
            return
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        payload: dict[str, object] = {
            "format": 1,
            "dialect": self.database.dialect,
            "tables": {},
        }
        with self.database.engine.connect() as connection, connection.begin():
            inspector = inspect(connection)
            metadata = MetaData()
            for table_name in sorted(inspector.get_table_names()):
                table = metadata.tables.get(table_name)
                if table is None:
                    metadata.reflect(
                        bind=connection,
                        only=[table_name],
                        resolve_fks=False,
                    )
                    table = metadata.tables[table_name]
                rows = [dict(row) for row in connection.execute(select(table)).mappings()]
                payload["tables"][table_name] = rows  # type: ignore[index]
        destination.write_text(
            json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
            encoding="utf-8",
        )
        destination.chmod(0o600)

    def _snapshots(self, work: Path) -> list[tuple[Path, str]]:
        snapshots: list[tuple[Path, str]] = []
        if self.database is not None and not self.database.is_embedded_sqlite:
            snapshot = work / "database" / "logical.json"
            self._snapshot_logical_database(snapshot)
            snapshots.append((snapshot, "control-plane/database-logical.json"))
        else:
            for relative in (
                "control-plane/control-plane.sqlite3",
                "control-plane/tasks.sqlite3",
            ):
                source = self.data_dir / relative
                if source.is_file():
                    snapshot = work / "sqlite" / Path(relative).name
                    self._snapshot_sqlite(source, snapshot)
                    snapshots.append((snapshot, relative))
        return snapshots

    # -- create -----------------------------------------------------------
    def create(
        self,
        passphrase: str,
        profile: str = "config",
        should_stop: Callable[[], bool] | None = None,
    ) -> dict[str, object]:
        if profile not in PROFILES:
            raise BackupError("unknown_profile", "unknown backup profile")
        if not 16 <= len(passphrase) <= 1024:
            raise ValueError("passphrase must be between 16 and 1024 characters")
        timestamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        backup_id = f"mrk-{timestamp}-{secrets.token_hex(4)}"
        target = self.backup_dir / f"{backup_id}.mrkbak"
        temporary = target.with_name(f".{target.name}.tmp")
        work = self.work_dir / secrets.token_hex(12)
        work.mkdir(mode=0o700)
        try:
            sources = self._source_files(profile) + self._snapshots(work)
            estimated = sum(source.stat().st_size for source, _relative in sources)
            reserve = max(_env_int("MRK_BACKUP_MIN_FREE_BYTES", 1024**3), 0)
            free = shutil.disk_usage(self.backup_dir).free
            if free < int(estimated * 1.05) + reserve:
                raise BackupError(
                    "insufficient_space",
                    f"insufficient free space for backup ({estimated} bytes needed)",
                )
            created_at = int(time.time())
            header = {
                "format": 2,
                "backup_id": backup_id,
                "created_at": created_at,
                "app_version": self.version,
                "cipher": CIPHER_V2,
                "chunk_size": CHUNK_SIZE,
                "kdf": {"name": "scrypt", "n": KDF_N_V2, "r": KDF_R, "p": KDF_P},
                "salt": base64.b64encode(os.urandom(16)).decode("ascii"),
                "file_id": base64.b64encode(os.urandom(16)).decode("ascii"),
                "nonce_prefix": base64.b64encode(os.urandom(7)).decode("ascii"),
                "profile": profile,
                "roots": list(PROFILES[profile]),
                "estimated_bytes": estimated,
            }
            header_bytes = json.dumps(header, sort_keys=True, separators=(",", ":")).encode(
                "utf-8"
            )
            key = _stream_key(passphrase, header)
            entries: list[dict[str, object]] = []
            with temporary.open("xb") as output:
                output.write(MAGIC_V2)
                output.write(struct.pack(">I", len(header_bytes)))
                output.write(header_bytes)
                writer = _EncryptingWriter(
                    output, key, header_bytes, _b64(header, "nonce_prefix", 7), should_stop
                )
                with tarfile.open(
                    fileobj=writer,  # type: ignore[arg-type]
                    mode="w|gz",
                    format=tarfile.PAX_FORMAT,
                    compresslevel=6,
                ) as archive:
                    for source, relative in sources:
                        if should_stop is not None and should_stop():
                            raise BackupCancelled()
                        stat = source.stat()
                        info = tarfile.TarInfo(relative)
                        info.size = stat.st_size
                        info.mtime = int(stat.st_mtime)
                        info.mode = 0o600
                        with source.open("rb") as raw:
                            reader = _HashingReader(raw)
                            archive.addfile(info, reader)  # type: ignore[arg-type]
                        entries.append(
                            {
                                "path": relative,
                                "size": stat.st_size,
                                "sha256": reader.digest.hexdigest(),
                            }
                        )
                    manifest = {
                        "format": 1,
                        "created_at": created_at,
                        "app_version": self.version,
                        "profile": profile,
                        "entries": entries,
                    }
                    encoded = json.dumps(
                        manifest, ensure_ascii=False, sort_keys=True, separators=(",", ":")
                    ).encode("utf-8")
                    info = tarfile.TarInfo("manifest.json")
                    info.size = len(encoded)
                    info.mtime = created_at
                    info.mode = 0o600
                    archive.addfile(info, io.BytesIO(encoded))
                manifest_sha256 = hashlib.sha256(encoded).hexdigest()
                writer.finish({"manifest_sha256": manifest_sha256})
                output.flush()
                os.fsync(output.fileno())
            temporary.chmod(0o600)
            temporary.replace(target)
            return {
                **{key_name: header[key_name] for key_name in PUBLIC_HEADER_FIELDS},
                "manifest_sha256": manifest_sha256,
                "filename": target.name,
                "size_bytes": target.stat().st_size,
                "entry_count": len(entries),
            }
        except BaseException:
            with contextlib.suppress(OSError):
                temporary.unlink()
            raise
        finally:
            shutil.rmtree(work, ignore_errors=True)

    # -- retention --------------------------------------------------------
    def prune(
        self, retain_count: int | None = None, retain_days: int | None = None
    ) -> list[str]:
        """Delete old backups; the newest valid backup is always kept."""
        count = (
            _env_int("MRK_BACKUP_RETAIN_COUNT", 7) if retain_count is None else retain_count
        )
        days = _env_int("MRK_BACKUP_RETAIN_DAYS", 30) if retain_days is None else retain_days
        valid = [item for item in self.list() if not item.get("invalid")]
        valid.sort(key=lambda item: int(item.get("created_at") or 0), reverse=True)
        cutoff = int(time.time()) - max(days, 0) * 86400
        deleted: list[str] = []
        for index, item in enumerate(valid):
            if index == 0:
                continue
            too_many = count > 0 and index >= count
            too_old = days > 0 and int(item.get("created_at") or 0) < cutoff
            if too_many or too_old:
                path = self.backup_dir / str(item["filename"])
                try:
                    path.unlink()
                except OSError:
                    continue
                deleted.append(str(item["filename"]))
        return deleted

    # -- reading ----------------------------------------------------------
    def _read_header(self, source: BinaryIO) -> tuple[dict[str, object], bytes]:
        magic = source.read(len(MAGIC))
        if magic not in {MAGIC, MAGIC_V2}:
            raise ValueError("unknown backup format")
        encoded_length = source.read(4)
        if len(encoded_length) != 4:
            raise ValueError("truncated backup header")
        header_length = struct.unpack(">I", encoded_length)[0]
        if not 1 <= header_length <= MAX_HEADER_BYTES:
            raise ValueError("invalid backup header length")
        header_bytes = source.read(header_length)
        if len(header_bytes) != header_length:
            raise ValueError("truncated backup header")
        header = json.loads(header_bytes)
        if not isinstance(header, dict) or not isinstance(header.get("backup_id"), str):
            raise ValueError("unsupported backup format")
        if magic == MAGIC:
            if header.get("format") != 1 or header.get("cipher") != CIPHER_V1:
                raise ValueError("unsupported backup format")
            header.setdefault("profile", "full")
            header.setdefault("roots", list(DATA_ROOTS))
        else:
            if (
                header.get("format") != 2
                or header.get("cipher") != CIPHER_V2
                or header.get("chunk_size") != CHUNK_SIZE
                or header.get("profile") not in PROFILES
                or header.get("roots") != list(PROFILES[str(header.get("profile"))])
                or not isinstance(header.get("estimated_bytes"), int)
            ):
                raise ValueError("unsupported backup format")
        return header, header_bytes

    def list(self) -> list[dict[str, object]]:
        result: list[dict[str, object]] = []
        for path in sorted(self.backup_dir.glob("*.mrkbak"), reverse=True):
            if path.name.startswith("."):
                continue
            try:
                with path.open("rb") as source:
                    header, _header_bytes = self._read_header(source)
                result.append(
                    {
                        **{key: header.get(key) for key in PUBLIC_HEADER_FIELDS},
                        "filename": path.name,
                        "size_bytes": path.stat().st_size,
                    }
                )
            except (OSError, ValueError):
                with contextlib.suppress(OSError):
                    result.append(
                        {"filename": path.name, "size_bytes": path.stat().st_size, "invalid": True}
                    )
        return result

    def _decrypt_v1(
        self, source: BinaryIO, header: dict[str, object], header_bytes: bytes,
        passphrase: str, destination: Path,
    ) -> None:
        salt = base64.b64decode(str(header["salt"]), validate=True)
        nonce = base64.b64decode(str(header["nonce"]), validate=True)
        n, r, p = _kdf_params(header)
        key = _derive_key(passphrase, salt, n, r, p)
        source.seek(0, os.SEEK_END)
        end = source.tell()
        encrypted_start = len(MAGIC) + 4 + len(header_bytes)
        if end - encrypted_start <= 16:
            raise ValueError("truncated encrypted payload")
        source.seek(end - 16)
        tag = source.read(16)
        source.seek(encrypted_start)
        decryptor = Cipher(algorithms.AES(key), modes.GCM(nonce, tag)).decryptor()
        decryptor.authenticate_additional_data(header_bytes)
        remaining = end - encrypted_start - 16
        with destination.open("wb") as output:
            while remaining:
                chunk = source.read(min(1024 * 1024, remaining))
                if not chunk:
                    raise ValueError("truncated encrypted payload")
                remaining -= len(chunk)
                output.write(decryptor.update(chunk))
            try:
                output.write(decryptor.finalize())
            except InvalidTag as exc:
                raise BackupError(
                    "authentication_failed", "backup authentication failed"
                ) from exc

    def _resolve_source(self, filename: str) -> Path:
        if (
            len(filename) > 128
            or Path(filename).name != filename
            or not filename.endswith(".mrkbak")
            or filename.startswith(".")
        ):
            raise ValueError("invalid backup filename")
        source = self.backup_dir / filename
        if not source.is_file() or source.is_symlink():
            raise FileNotFoundError(filename)
        return source

    def resolve_download(self, reference: str) -> tuple[Path, str, int]:
        """Locate an encrypted archive by filename or header ``backup_id``.

        Returns (path, filename, size). The file is served as-is: it is already
        AES-256-GCM encrypted and is never decrypted server-side. Only archives
        whose public header parses are downloadable.
        """
        if not reference or len(reference) > 128:
            raise ValueError("invalid backup reference")
        if reference.endswith(".mrkbak"):
            source = self._resolve_source(reference)
            with source.open("rb") as handle:
                self._read_header(handle)
            return source, source.name, source.stat().st_size
        for path in sorted(self.backup_dir.glob("*.mrkbak"), reverse=True):
            if path.name.startswith(".") or path.is_symlink() or not path.is_file():
                continue
            try:
                with path.open("rb") as handle:
                    header, _header_bytes = self._read_header(handle)
            except (OSError, ValueError):
                continue
            if header.get("backup_id") == reference:
                return path, path.name, path.stat().st_size
        raise FileNotFoundError(reference)

    def _read_archive(
        self, filename: str, passphrase: str, sink: MemberSink
    ) -> tuple[dict[str, object], dict[str, dict[str, object]]]:
        """Decrypt, authenticate and walk the archive once; returns (header, manifest entries).

        ``sink`` consumes each member stream and returns its (sha256, size).
        Any failure raises ValueError (or BackupError) before the result is used.
        """
        source_path = self._resolve_source(filename)
        work = self.work_dir / secrets.token_hex(12)
        work.mkdir(mode=0o700)
        try:
            with source_path.open("rb") as source:
                header, header_bytes = self._read_header(source)
                reader: _DecryptingReader | None = None
                if header["format"] == 1:
                    archive_path = work / "payload.tar.gz"
                    self._decrypt_v1(source, header, header_bytes, passphrase, archive_path)
                    stream: BinaryIO = archive_path.open("rb")
                    expected_manifest = str(header["manifest_sha256"])
                else:
                    reader = _DecryptingReader(
                        source,
                        _stream_key(passphrase, header),
                        header_bytes,
                        _b64(header, "nonce_prefix", 7),
                    )
                    stream = reader  # type: ignore[assignment]
                    expected_manifest = ""
                try:
                    manifest_bytes, actual = self._walk_members(stream, sink)
                finally:
                    if reader is None:
                        stream.close()
                if reader is not None:
                    expected_manifest = str(reader.drain()["manifest_sha256"])
            if hashlib.sha256(manifest_bytes).hexdigest() != expected_manifest:
                raise ValueError("manifest checksum mismatch")
            manifest = json.loads(manifest_bytes)
            entries = manifest.get("entries") if isinstance(manifest, dict) else None
            if not isinstance(entries, list):
                raise ValueError("manifest entries are invalid")
            expected: dict[str, dict[str, object]] = {}
            for entry in entries:
                if not isinstance(entry, dict) or not isinstance(entry.get("path"), str):
                    raise ValueError("manifest entries are invalid")
                expected[entry["path"]] = entry
            if set(expected) != set(actual):
                raise ValueError("manifest entries mismatch")
            for name, entry in expected.items():
                digest, size = actual[name]
                if size != int(entry.get("size", -1)) or digest != entry.get("sha256"):
                    raise ValueError("archive entry checksum mismatch")
            roots = header["roots"]
            for name in expected:
                if not any(name == root or name.startswith(f"{root}/") for root in roots):  # type: ignore[union-attr]
                    raise ValueError("archive entry outside the backup profile")
            return header, expected
        except InvalidTag as exc:
            raise BackupError("authentication_failed", "backup authentication failed") from exc
        except (tarfile.TarError, KeyError, TypeError, EOFError) as exc:
            raise BackupError("corrupt", "backup archive is corrupt") from exc
        finally:
            shutil.rmtree(work, ignore_errors=True)

    @staticmethod
    def _walk_members(
        stream: BinaryIO, sink: MemberSink
    ) -> tuple[bytes, dict[str, tuple[str, int]]]:
        actual: dict[str, tuple[str, int]] = {}
        manifest_bytes: bytes | None = None
        count = 0
        with tarfile.open(fileobj=stream, mode="r|gz") as archive:
            for member in archive:
                count += 1
                if count > MAX_MEMBERS:
                    raise ValueError("archive has too many members")
                _safe_member(member.name)
                if not member.isfile():
                    raise ValueError("unsupported archive member")
                if manifest_bytes is not None:
                    raise ValueError("manifest must be the last archive member")
                if member.name in actual:
                    raise ValueError("duplicate archive member")
                payload = archive.extractfile(member)
                if payload is None:
                    raise ValueError("archive entry is unreadable")
                if member.name == "manifest.json":
                    if member.size > MAX_MANIFEST_BYTES:
                        raise ValueError("manifest is too large")
                    manifest_bytes = payload.read()
                    continue
                actual[member.name] = sink(member.name, payload)  # type: ignore[arg-type]
        if manifest_bytes is None:
            raise ValueError("manifest is missing")
        return manifest_bytes, actual

    def validate(self, filename: str, passphrase: str) -> dict[str, object]:
        header, expected = self._read_archive(filename, passphrase, _hash_member)
        return {
            "valid": True,
            "backup_id": header["backup_id"],
            "filename": filename,
            "format": header["format"],
            "profile": header["profile"],
            "roots": header["roots"],
            "entry_count": len(expected),
            "uncompressed_bytes": sum(int(entry["size"]) for entry in expected.values()),
            "confirmation": f"RESTORE {header['backup_id']}",
            "isolated_only": True,
        }

    def create_restore_plan(
        self,
        filename: str,
        passphrase: str,
        confirmation: str,
        actor_user_id: int,
    ) -> dict[str, object]:
        validated = self.validate(filename, passphrase)
        expected = str(validated["confirmation"])
        if not secrets.compare_digest(confirmation.strip(), expected):
            raise ValueError("restore confirmation does not match")
        now = int(time.time())
        plan_id = secrets.token_hex(16)
        plan = {
            "format": 1,
            "plan_id": plan_id,
            "backup_id": validated["backup_id"],
            "filename": filename,
            "profile": validated["profile"],
            "roots": validated["roots"],
            "created_at": now,
            "expires_at": now + RESTORE_PLAN_TTL_SECONDS,
            "created_by_user_id": actor_user_id,
            "apply_confirmation": f"APPLY {validated['backup_id']}",
        }
        target = self.restore_plan_dir / f"{plan_id}.json"
        temporary = target.with_suffix(".tmp")
        temporary.write_text(
            json.dumps(plan, sort_keys=True, separators=(",", ":")),
            encoding="utf-8",
        )
        temporary.chmod(0o600)
        temporary.replace(target)
        return plan

    def extract_validated(
        self, filename: str, passphrase: str, destination: Path
    ) -> dict[str, object]:
        source = self._resolve_source(filename)
        with source.open("rb") as handle:
            header, _header_bytes = self._read_header(handle)
        destination.mkdir(parents=True, exist_ok=False, mode=0o700)
        estimated = int(header.get("estimated_bytes") or 0)
        if estimated and estimated > int(shutil.disk_usage(destination).free * 0.9):
            shutil.rmtree(destination, ignore_errors=True)
            raise BackupError("insufficient_space", "insufficient free space for restore staging")
        limit = int(estimated * 1.1) + 64 * 1024 * 1024 if estimated else None
        state = {"written": 0, "since_check": 0}

        def write_member(name: str, payload: BinaryIO) -> tuple[str, int]:
            relative = _safe_member(name)
            target = destination.joinpath(*relative.parts)
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            digest = hashlib.sha256()
            size = 0
            with target.open("xb") as output:
                while chunk := payload.read(1024 * 1024):
                    digest.update(chunk)
                    size += len(chunk)
                    state["written"] += len(chunk)
                    state["since_check"] += len(chunk)
                    if limit is not None and state["written"] > limit:
                        raise BackupError("corrupt", "archive exceeds its declared size")
                    if state["since_check"] >= FREE_SPACE_CHECK_BYTES:
                        state["since_check"] = 0
                        if shutil.disk_usage(destination).free < FREE_SPACE_CHECK_BYTES:
                            raise BackupError(
                                "insufficient_space",
                                "insufficient free space for restore staging",
                            )
                    output.write(chunk)
                output.flush()
                os.fsync(output.fileno())
            target.chmod(0o600)
            return digest.hexdigest(), size

        try:
            header, expected = self._read_archive(filename, passphrase, write_member)
        except BaseException:
            shutil.rmtree(destination, ignore_errors=True)
            raise
        return {
            "backup_id": header["backup_id"],
            "filename": filename,
            "format": header["format"],
            "profile": header["profile"],
            "roots": list(header["roots"]),  # type: ignore[call-overload]
            "entry_count": len(expected),
            "uncompressed_bytes": sum(int(entry["size"]) for entry in expected.values()),
        }
