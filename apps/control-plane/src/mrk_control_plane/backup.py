from __future__ import annotations

import base64
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
from pathlib import Path, PurePosixPath
from typing import BinaryIO

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from sqlalchemy import MetaData, inspect, select

from .database import Database

MAGIC = b"MRKBKP1\0"
MAX_HEADER_BYTES = 64 * 1024
MAX_MEMBERS = 2_000_000
RESTORE_PLAN_TTL_SECONDS = 3600
KDF_N = 2**15
KDF_R = 8
KDF_P = 1


class _HashingReader:
    def __init__(self, source: BinaryIO) -> None:
        self.source = source
        self.digest = hashlib.sha256()

    def read(self, size: int = -1) -> bytes:
        value = self.source.read(size)
        self.digest.update(value)
        return value


def _derive_key(passphrase: str, salt: bytes) -> bytes:
    if not 16 <= len(passphrase) <= 1024:
        raise ValueError("passphrase must be between 16 and 1024 characters")
    return Scrypt(salt=salt, length=32, n=KDF_N, r=KDF_R, p=KDF_P).derive(
        passphrase.encode("utf-8")
    )


def _safe_member(name: str) -> PurePosixPath:
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts or not path.parts:
        raise ValueError("unsafe archive path")
    return path


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

    def _snapshot_sqlite(self, source: Path, destination: Path) -> None:
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with sqlite3.connect(source) as source_db, sqlite3.connect(destination) as target:
            source_db.backup(target)

    def _source_files(self) -> list[tuple[Path, str]]:
        files: list[tuple[Path, str]] = []
        for path in self.data_dir.rglob("*"):
            relative = path.relative_to(self.data_dir)
            if not relative.parts or relative.parts[0] in {"backups", "tmp"}:
                continue
            if relative.parts[:2] == ("database", "pglite"):
                # Live PGlite files are not crash-consistent when copied. A
                # transactional logical snapshot is added to the archive below.
                continue
            if (
                relative.parts[0] == "control-plane"
                and relative.name.startswith("runtime-heartbeat")
            ):
                continue
            if relative.parts[:2] in {
                ("control-plane", "restore-plans"),
                ("control-plane", "restore-receipts"),
            }:
                continue
            if path.is_symlink():
                raise ValueError(f"symlink is not allowed: {relative.as_posix()}")
            if not path.is_file():
                continue
            if path.name.endswith(("-wal", "-shm")):
                continue
            if relative.as_posix() in {
                "control-plane/control-plane.sqlite3",
                "control-plane/tasks.sqlite3",
            }:
                continue
            files.append((path, relative.as_posix()))
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

    def _build_archive(self, work: Path) -> tuple[Path, dict[str, object]]:
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

        archive_path = work / "payload.tar.gz"
        entries: list[dict[str, object]] = []
        sources = self._source_files() + snapshots
        with tarfile.open(archive_path, mode="w:gz", format=tarfile.PAX_FORMAT) as archive:
            for source, relative in sources:
                stat = source.stat()
                info = tarfile.TarInfo(relative)
                info.size = stat.st_size
                info.mtime = int(stat.st_mtime)
                info.mode = 0o600
                with source.open("rb") as raw:
                    reader = _HashingReader(raw)
                    archive.addfile(info, reader)
                    digest = reader.digest.hexdigest()
                entries.append(
                    {"path": relative, "size": stat.st_size, "sha256": digest}
                )
            manifest = {
                "format": 1,
                "created_at": int(time.time()),
                "app_version": self.version,
                "entries": entries,
            }
            encoded = json.dumps(
                manifest, ensure_ascii=False, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
            info = tarfile.TarInfo("manifest.json")
            info.size = len(encoded)
            info.mtime = int(time.time())
            info.mode = 0o600
            archive.addfile(info, io.BytesIO(encoded))
        manifest["manifest_sha256"] = hashlib.sha256(encoded).hexdigest()
        return archive_path, manifest

    def create(self, passphrase: str) -> dict[str, object]:
        salt = os.urandom(16)
        nonce = os.urandom(12)
        key = _derive_key(passphrase, salt)
        work = self.work_dir / secrets.token_hex(12)
        work.mkdir(mode=0o700)
        try:
            archive_path, manifest = self._build_archive(work)
            timestamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
            backup_id = f"mrk-{timestamp}-{secrets.token_hex(4)}"
            target = self.backup_dir / f"{backup_id}.mrkbak"
            temporary = target.with_name(f".{target.name}.tmp")
            header = {
                "format": 1,
                "backup_id": backup_id,
                "created_at": manifest["created_at"],
                "app_version": self.version,
                "cipher": "AES-256-GCM",
                "kdf": {"name": "scrypt", "n": KDF_N, "r": KDF_R, "p": KDF_P},
                "salt": base64.b64encode(salt).decode("ascii"),
                "nonce": base64.b64encode(nonce).decode("ascii"),
                "manifest_sha256": manifest["manifest_sha256"],
            }
            header_bytes = json.dumps(
                header, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
            encryptor = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
            encryptor.authenticate_additional_data(header_bytes)
            with archive_path.open("rb") as source, temporary.open("wb") as output:
                output.write(MAGIC)
                output.write(struct.pack(">I", len(header_bytes)))
                output.write(header_bytes)
                while chunk := source.read(1024 * 1024):
                    output.write(encryptor.update(chunk))
                output.write(encryptor.finalize())
                output.write(encryptor.tag)
                output.flush()
                os.fsync(output.fileno())
            temporary.chmod(0o600)
            temporary.replace(target)
            return {
                **header,
                "filename": target.name,
                "size_bytes": target.stat().st_size,
                "entry_count": len(manifest["entries"]),
            }
        finally:
            key = b"\0" * len(key)
            shutil.rmtree(work, ignore_errors=True)

    def _read_header(self, source: BinaryIO) -> tuple[dict[str, object], bytes]:
        if source.read(len(MAGIC)) != MAGIC:
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
        if header.get("format") != 1 or header.get("cipher") != "AES-256-GCM":
            raise ValueError("unsupported backup format")
        return header, header_bytes

    def list(self) -> list[dict[str, object]]:
        result: list[dict[str, object]] = []
        for path in sorted(self.backup_dir.glob("*.mrkbak"), reverse=True):
            try:
                with path.open("rb") as source:
                    header, _header_bytes = self._read_header(source)
                result.append(
                    {**header, "filename": path.name, "size_bytes": path.stat().st_size}
                )
            except (OSError, ValueError, json.JSONDecodeError):
                result.append(
                    {"filename": path.name, "size_bytes": path.stat().st_size, "invalid": True}
                )
        return result

    def _decrypt(self, path: Path, passphrase: str, destination: Path) -> dict[str, object]:
        with path.open("rb") as source:
            header, header_bytes = self._read_header(source)
            salt = base64.b64decode(str(header["salt"]), validate=True)
            nonce = base64.b64decode(str(header["nonce"]), validate=True)
            key = _derive_key(passphrase, salt)
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
            try:
                with destination.open("wb") as output:
                    while remaining:
                        chunk = source.read(min(1024 * 1024, remaining))
                        if not chunk:
                            raise ValueError("truncated encrypted payload")
                        remaining -= len(chunk)
                        output.write(decryptor.update(chunk))
                    output.write(decryptor.finalize())
            finally:
                key = b"\0" * len(key)
        return header

    def validate(self, filename: str, passphrase: str) -> dict[str, object]:
        if Path(filename).name != filename or not filename.endswith(".mrkbak"):
            raise ValueError("invalid backup filename")
        source = self.backup_dir / filename
        if not source.is_file() or source.is_symlink():
            raise FileNotFoundError(filename)
        work = self.work_dir / secrets.token_hex(12)
        work.mkdir(mode=0o700)
        archive_path = work / "validated.tar.gz"
        try:
            header = self._decrypt(source, passphrase, archive_path)
            with tarfile.open(archive_path, mode="r:gz") as archive:
                members = archive.getmembers()
                if len(members) > MAX_MEMBERS:
                    raise ValueError("archive has too many members")
                for member in members:
                    _safe_member(member.name)
                    if not member.isfile():
                        raise ValueError("unsupported archive member")
                manifest_member = archive.getmember("manifest.json")
                manifest_file = archive.extractfile(manifest_member)
                if manifest_file is None:
                    raise ValueError("manifest is missing")
                manifest_bytes = manifest_file.read()
                if hashlib.sha256(manifest_bytes).hexdigest() != header["manifest_sha256"]:
                    raise ValueError("manifest checksum mismatch")
                manifest = json.loads(manifest_bytes)
                expected = {entry["path"]: entry for entry in manifest["entries"]}
                actual_members = {
                    member.name: member
                    for member in members
                    if member.name != "manifest.json"
                }
                if set(expected) != set(actual_members):
                    raise ValueError("manifest entries mismatch")
                total_bytes = 0
                for name, entry in expected.items():
                    payload = archive.extractfile(actual_members[name])
                    if payload is None:
                        raise ValueError("archive entry is unreadable")
                    digest = hashlib.sha256()
                    size = 0
                    while chunk := payload.read(1024 * 1024):
                        digest.update(chunk)
                        size += len(chunk)
                    if size != int(entry["size"]) or digest.hexdigest() != entry["sha256"]:
                        raise ValueError("archive entry checksum mismatch")
                    total_bytes += size
            return {
                "valid": True,
                "backup_id": header["backup_id"],
                "filename": filename,
                "entry_count": len(expected),
                "uncompressed_bytes": total_bytes,
                "confirmation": f"RESTORE {header['backup_id']}",
                "isolated_only": True,
            }
        except InvalidTag as exc:
            raise ValueError("backup authentication failed") from exc
        finally:
            shutil.rmtree(work, ignore_errors=True)

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
        if Path(filename).name != filename or not filename.endswith(".mrkbak"):
            raise ValueError("invalid backup filename")
        source = self.backup_dir / filename
        if not source.is_file() or source.is_symlink():
            raise FileNotFoundError(filename)
        destination.mkdir(parents=True, exist_ok=False, mode=0o700)
        work = self.work_dir / secrets.token_hex(12)
        work.mkdir(mode=0o700)
        archive_path = work / "restore.tar.gz"
        try:
            header = self._decrypt(source, passphrase, archive_path)
            with tarfile.open(archive_path, mode="r:gz") as archive:
                members = archive.getmembers()
                if len(members) > MAX_MEMBERS:
                    raise ValueError("archive has too many members")
                for member in members:
                    _safe_member(member.name)
                    if not member.isfile():
                        raise ValueError("unsupported archive member")
                manifest_member = archive.getmember("manifest.json")
                manifest_file = archive.extractfile(manifest_member)
                if manifest_file is None:
                    raise ValueError("manifest is missing")
                manifest_bytes = manifest_file.read()
                if hashlib.sha256(manifest_bytes).hexdigest() != header["manifest_sha256"]:
                    raise ValueError("manifest checksum mismatch")
                manifest = json.loads(manifest_bytes)
                expected = {entry["path"]: entry for entry in manifest["entries"]}
                actual = {
                    member.name: member
                    for member in members
                    if member.name != "manifest.json"
                }
                if set(expected) != set(actual):
                    raise ValueError("manifest entries mismatch")
                required_bytes = sum(int(entry["size"]) for entry in expected.values())
                if required_bytes > int(shutil.disk_usage(destination.parent).free * 0.9):
                    raise ValueError("insufficient free space for restore staging")
                for name, entry in expected.items():
                    relative = _safe_member(name)
                    target = destination.joinpath(*relative.parts)
                    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                    payload = archive.extractfile(actual[name])
                    if payload is None:
                        raise ValueError("archive entry is unreadable")
                    digest = hashlib.sha256()
                    size = 0
                    with target.open("xb") as output:
                        while chunk := payload.read(1024 * 1024):
                            digest.update(chunk)
                            size += len(chunk)
                            output.write(chunk)
                        output.flush()
                        os.fsync(output.fileno())
                    target.chmod(0o600)
                    if size != int(entry["size"]) or digest.hexdigest() != entry["sha256"]:
                        raise ValueError("archive entry checksum mismatch")
            return {
                "backup_id": header["backup_id"],
                "filename": filename,
                "entry_count": len(expected),
                "uncompressed_bytes": required_bytes,
            }
        except Exception:
            shutil.rmtree(destination, ignore_errors=True)
            raise
        finally:
            shutil.rmtree(work, ignore_errors=True)
