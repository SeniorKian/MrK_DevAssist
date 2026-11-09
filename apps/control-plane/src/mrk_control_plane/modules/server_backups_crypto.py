"""Streaming MRKBKP2 encryption for server backups + the ``mrk-backup-decrypt`` tool.

Server backup artifacts use exactly the appliance backup format of ``backup.py``
(``MRKBKP2``: header, AES-256-GCM records, authenticated JSON trailer) with a
different header ``kind`` (``server-backup``). Each job has its own random
passphrase in the SecretStore; the header records only its reference
(``key_ref``), never the secret. Because the passphrase is 256 random bits the
scrypt cost is the format minimum class (n=2^15) instead of the appliance 2^17.

Decrypt offline::

    python -m mrk_control_plane.modules.server_backups_crypto ARTIFACT.mrkbak \\
        -o dump.sql.gz --passphrase-file key.txt        # key from "Export key" in the panel
    python -m mrk_control_plane.modules.server_backups_crypto ARTIFACT.mrkbak \\
        -o - --data-dir /data | gunzip > dump.sql       # inside the appliance container

``--decompress`` gunzips gzip payloads on the fly; ``--info`` prints the public header.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import secrets
import struct
import sys
import time
import zlib
from pathlib import Path
from typing import Any, BinaryIO

from ..backup import (
    CHUNK_SIZE,
    CIPHER_V2,
    KDF_P,
    KDF_R,
    MAGIC_V2,
    MAX_HEADER_BYTES,
    BackupError,
    _b64,
    _DecryptingReader,
    _EncryptingWriter,
    _stream_key,
)

HEADER_KIND = "server-backup"
KDF_N_SERVER = 2**15
PASSPHRASE_BYTES = 32
PUBLIC_FIELDS = (
    "format", "kind", "backup_id", "created_at", "cipher", "compression", "payload_name",
    "source", "job_id", "key_ref",
)


def new_passphrase() -> str:
    return secrets.token_urlsafe(PASSPHRASE_BYTES)


class _Collector:
    def __init__(self) -> None:
        self.buffer = bytearray()

    def write(self, data: bytes) -> int:
        self.buffer.extend(data)
        return len(data)

    def flush(self) -> None:
        return None


class StreamEncryptor:
    """Incremental encryptor: feed plaintext, get ciphertext bytes to upload.

    Memory is bounded by one record (4 MiB plaintext) plus what the caller has
    not yet taken from ``update``/``finish``.
    """

    def __init__(
        self,
        passphrase: str,
        *,
        backup_id: str,
        source: dict[str, Any],
        payload_name: str,
        compression: str,
        job_id: str,
        key_ref: str,
        created_at: int | None = None,
    ) -> None:
        if compression not in {"gzip", "none"}:
            raise ValueError("unknown compression")
        self.header: dict[str, Any] = {
            "format": 2,
            "kind": HEADER_KIND,
            "backup_id": backup_id,
            "created_at": int(created_at if created_at is not None else time.time()),
            "cipher": CIPHER_V2,
            "chunk_size": CHUNK_SIZE,
            "kdf": {"name": "scrypt", "n": KDF_N_SERVER, "r": KDF_R, "p": KDF_P},
            "salt": base64.b64encode(os.urandom(16)).decode("ascii"),
            "file_id": base64.b64encode(os.urandom(16)).decode("ascii"),
            "nonce_prefix": base64.b64encode(os.urandom(7)).decode("ascii"),
            "compression": compression,
            "payload_name": payload_name + (".gz" if compression == "gzip" else ""),
            "source": source,
            "job_id": job_id,
            "key_ref": key_ref,
        }
        header_bytes = json.dumps(self.header, sort_keys=True, separators=(",", ":")).encode()
        key = _stream_key(passphrase, self.header)
        self._out = _Collector()
        self._out.write(MAGIC_V2 + struct.pack(">I", len(header_bytes)) + header_bytes)
        self._writer = _EncryptingWriter(
            self._out,  # type: ignore[arg-type]
            key,
            header_bytes,
            _b64(self.header, "nonce_prefix", 7),
        )
        self._compressor = (
            zlib.compressobj(6, zlib.DEFLATED, 31) if compression == "gzip" else None
        )
        self.source_digest = hashlib.sha256()
        self.payload_digest = hashlib.sha256()
        self.artifact_digest = hashlib.sha256()
        self.source_bytes = 0
        self.artifact_bytes = 0
        self.finished = False

    def _payload(self, data: bytes) -> None:
        if data:
            self.payload_digest.update(data)
            self._writer.write(data)

    def _drain(self) -> bytes:
        data = bytes(self._out.buffer)
        self._out.buffer.clear()
        self.artifact_digest.update(data)
        self.artifact_bytes += len(data)
        return data

    def update(self, data: bytes) -> bytes:
        self.source_digest.update(data)
        self.source_bytes += len(data)
        self._payload(self._compressor.compress(data) if self._compressor else data)
        return self._drain()

    def finish(self) -> bytes:
        if self._compressor is not None:
            self._payload(self._compressor.flush())
        self._writer.finish(
            {
                "manifest_sha256": self.payload_digest.hexdigest(),
                "source_sha256": self.source_digest.hexdigest(),
                "source_bytes": self.source_bytes,
            }
        )
        self.finished = True
        return self._drain()


def read_header(source: BinaryIO) -> tuple[dict[str, Any], bytes]:
    if source.read(len(MAGIC_V2)) != MAGIC_V2:
        raise BackupError("unknown_format", "not an MRKBKP2 file")
    encoded = source.read(4)
    if len(encoded) != 4:
        raise BackupError("truncated", "truncated header")
    length = struct.unpack(">I", encoded)[0]
    if not 1 <= length <= MAX_HEADER_BYTES:
        raise BackupError("invalid_header", "invalid header length")
    header_bytes = source.read(length)
    if len(header_bytes) != length:
        raise BackupError("truncated", "truncated header")
    try:
        header = json.loads(header_bytes)
    except ValueError as exc:
        raise BackupError("invalid_header", "header is not JSON") from exc
    if (
        not isinstance(header, dict)
        or header.get("format") != 2
        or header.get("kind") != HEADER_KIND
        or header.get("cipher") != CIPHER_V2
        or header.get("chunk_size") != CHUNK_SIZE
        or header.get("compression") not in {"gzip", "none"}
    ):
        raise BackupError("unsupported_format", "not a server backup artifact")
    return header, header_bytes


def decrypt_stream(
    source: BinaryIO, output: BinaryIO, passphrase: str, *, decompress: bool = False
) -> dict[str, Any]:
    """Verify and decrypt an artifact into ``output``. Returns header + trailer.

    Output written before an authentication failure must be discarded by the
    caller (the CLI deletes a partial output file).
    """
    header, header_bytes = read_header(source)
    reader = _DecryptingReader(
        source, _stream_key(passphrase, header), header_bytes, _b64(header, "nonce_prefix", 7)
    )
    digest = hashlib.sha256()
    inflater = zlib.decompressobj(31) if decompress and header["compression"] == "gzip" else None
    while True:
        chunk = reader.read(1024 * 1024)
        if not chunk:
            break
        digest.update(chunk)
        output.write(inflater.decompress(chunk) if inflater else chunk)
    trailer = reader.drain()
    if inflater is not None:
        output.write(inflater.flush())
    if trailer.get("manifest_sha256") != digest.hexdigest():
        raise BackupError("checksum_mismatch", "payload checksum mismatch")
    return {**{key: header.get(key) for key in PUBLIC_FIELDS}, "trailer": trailer}


def _passphrase(args: argparse.Namespace, header: dict[str, Any]) -> str:
    if args.passphrase_file:
        text = Path(args.passphrase_file).read_text(encoding="utf-8").strip()
        if not text:
            raise SystemExit("passphrase file is empty")
        return text
    if args.data_dir:
        from ..secret_store import SecretStore

        reference = header.get("key_ref")
        if not isinstance(reference, str):
            raise SystemExit("artifact has no key reference")
        return SecretStore(Path(args.data_dir)).get(reference)["passphrase"]
    env = os.getenv("MRK_BACKUP_PASSPHRASE", "").strip()
    if env:
        return env
    raise SystemExit("give --passphrase-file, --data-dir or MRK_BACKUP_PASSPHRASE")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="mrk-backup-decrypt", description="Verify and decrypt an Pishkar server backup"
    )
    parser.add_argument("artifact")
    parser.add_argument("-o", "--output", help="output file or - for stdout")
    parser.add_argument("--passphrase-file")
    parser.add_argument("--data-dir", help="appliance data dir (reads the job key)")
    parser.add_argument("--decompress", action="store_true", help="gunzip gzip payloads")
    parser.add_argument("--info", action="store_true", help="print the public header only")
    args = parser.parse_args(argv)
    with open(args.artifact, "rb") as source:
        header, _ = read_header(source)
        if args.info:
            print(json.dumps({key: header.get(key) for key in PUBLIC_FIELDS}, indent=2))
            return 0
        passphrase = _passphrase(args, header)
        source.seek(0)
        if not args.output:
            parser.error("--output is required")
        if args.output == "-":
            result = decrypt_stream(source, sys.stdout.buffer, passphrase,
                                    decompress=args.decompress)
        else:
            target = Path(args.output)
            partial = target.with_name(f".{target.name}.partial")
            try:
                with partial.open("xb") as output:
                    result = decrypt_stream(source, output, passphrase,
                                            decompress=args.decompress)
                partial.replace(target)
            except BaseException:
                partial.unlink(missing_ok=True)
                raise
    print(json.dumps({"ok": True, "payload_name": result["payload_name"],
                      "sha256": result["trailer"]["manifest_sha256"]}), file=sys.stderr)
    return 0


def run() -> None:  # console-script entry point
    try:
        raise SystemExit(main())
    except BackupError as exc:
        print(f"error: {exc.error_code}: {exc}", file=sys.stderr)
        raise SystemExit(2) from None


if __name__ == "__main__":  # pragma: no cover
    run()
