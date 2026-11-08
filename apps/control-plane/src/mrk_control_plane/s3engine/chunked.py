"""Incremental ``Content-Encoding: aws-chunked`` decoder (docs/30 §2.2).

Supports ``STREAMING-AWS4-HMAC-SHA256-PAYLOAD`` (signed chunks),
``STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER`` (signed chunks + signed trailer) and
``STREAMING-UNSIGNED-PAYLOAD-TRAILER`` (plain chunks + trailer). Chunk payloads are
yielded as they arrive (never buffered whole); signatures are checked at the end of
each chunk, and callers only commit after the whole stream decoded cleanly.
"""

from __future__ import annotations

import hashlib
import hmac
import re
from collections.abc import AsyncIterator

from .. import s3sigv4
from .errors import S3Error

_HEX = re.compile(rb"^[0-9a-fA-F]{1,16}$")
_SIG = re.compile(rb"^[0-9a-f]{64}$")
MAX_LINE = 4096
MAX_TRAILER = 4096


class AwsChunkedDecoder:
    def __init__(
        self,
        source: AsyncIterator[bytes],
        *,
        mode: str,
        verified: s3sigv4.VerifiedRequest | None,
        declared_trailers: set[str],
        decoded_length: int | None,
        max_chunk_bytes: int,
    ) -> None:
        if mode not in s3sigv4.STREAMING_MODES:
            raise ValueError(mode)
        self._source = source
        self.signed = mode in {s3sigv4.STREAMING_SIGNED, s3sigv4.STREAMING_SIGNED_TRAILER}
        self.has_trailer = mode in {
            s3sigv4.STREAMING_SIGNED_TRAILER,
            s3sigv4.STREAMING_UNSIGNED_TRAILER,
        }
        if self.signed and verified is None:
            raise S3Error("AccessDenied", "Signed streaming payloads require SigV4 header auth.")
        self._verified = verified
        self._previous = verified.signature if verified else ""
        self._declared = declared_trailers
        self._decoded_length = decoded_length
        self._max_chunk = max_chunk_bytes
        self._buffer = bytearray()
        self._eof = False
        self.trailers: dict[str, str] = {}
        self.total = 0

    async def _fill(self) -> bool:
        if self._eof:
            return False
        try:
            data = await anext(self._source)
        except StopAsyncIteration:
            self._eof = True
            return False
        self._buffer += data
        return True

    async def _line(self, limit: int = MAX_LINE) -> bytes | None:
        while True:
            index = self._buffer.find(b"\r\n")
            if index >= 0:
                line = bytes(self._buffer[:index])
                del self._buffer[: index + 2]
                return line
            if len(self._buffer) > limit:
                raise S3Error("InvalidArgument", "aws-chunked line is too long.")
            if not await self._fill():
                if self._buffer:
                    line = bytes(self._buffer)
                    self._buffer.clear()
                    return line
                return None

    def _verify_chunk(self, chunk_sig: bytes, digest: str) -> None:
        assert self._verified is not None
        expected = s3sigv4.chunk_signature(
            self._verified.signing_key,
            self._verified.amz_date,
            self._verified.credential.scope,
            self._previous,
            digest,
        )
        if not hmac.compare_digest(expected.encode("ascii"), chunk_sig):
            raise S3Error("SignatureDoesNotMatch", "The chunk signature does not match.")
        self._previous = expected

    def _parse_header(self, line: bytes) -> tuple[int, bytes]:
        size_part, _, extension = line.partition(b";")
        size_part = size_part.strip(b" ")
        if not _HEX.match(size_part):
            raise S3Error("IncompleteBody", "Malformed aws-chunked chunk size.")
        size = int(size_part, 16)
        if size > self._max_chunk:
            raise S3Error("InvalidChunkSizeError", "The aws-chunked chunk is too large.")
        signature = b""
        if self.signed:
            name, _, value = extension.partition(b"=")
            if name.strip() != b"chunk-signature" or not _SIG.match(value.strip()):
                raise S3Error("SignatureDoesNotMatch", "Missing or malformed chunk-signature.")
            signature = value.strip()
        elif extension:
            raise S3Error("InvalidArgument", "Unexpected aws-chunked chunk extension.")
        return size, signature

    async def __aiter__(self) -> AsyncIterator[bytes]:  # noqa: C901 - one state machine
        while True:
            line = await self._line()
            if line is None:
                raise S3Error("IncompleteBody", "The aws-chunked body ended early.")
            size, chunk_sig = self._parse_header(line)
            if size == 0:
                if self.signed:
                    self._verify_chunk(chunk_sig, s3sigv4.EMPTY_SHA256)
                break
            digest = hashlib.sha256() if self.signed else None
            remaining = size
            while remaining:
                if not self._buffer and not await self._fill():
                    raise S3Error("IncompleteBody", "The aws-chunked body ended inside a chunk.")
                piece = bytes(self._buffer[:remaining])
                del self._buffer[: len(piece)]
                remaining -= len(piece)
                self.total += len(piece)
                if self._decoded_length is not None and self.total > self._decoded_length:
                    raise S3Error("IncompleteBody", "More data than x-amz-decoded-content-length.")
                if digest is not None:
                    digest.update(piece)
                yield piece
            while len(self._buffer) < 2:
                if not await self._fill():
                    raise S3Error("IncompleteBody", "Missing CRLF after aws-chunked chunk.")
            if self._buffer[:2] != b"\r\n":
                raise S3Error("IncompleteBody", "Missing CRLF after aws-chunked chunk.")
            del self._buffer[:2]
            if digest is not None:
                self._verify_chunk(chunk_sig, digest.hexdigest())
        if self.has_trailer:
            await self._read_trailers()
        else:
            # Optional final CRLF after the last chunk.
            await self._line()
        if self._decoded_length is not None and self.total != self._decoded_length:
            raise S3Error(
                "IncompleteBody", "Body length does not match x-amz-decoded-content-length."
            )

    async def _read_trailers(self) -> None:
        consumed = 0
        trailer_signature: bytes | None = None
        ordered: list[tuple[str, str]] = []
        while True:
            line = await self._line(MAX_TRAILER)
            if line is None or line == b"":
                break
            consumed += len(line) + 2
            if consumed > MAX_TRAILER:
                raise S3Error("InvalidArgument", "The aws-chunked trailer is too large.")
            name, sep, value = line.partition(b":")
            if not sep:
                raise S3Error("IncompleteBody", "Malformed aws-chunked trailer.")
            key = name.strip().decode("ascii", "replace").lower()
            text = value.strip().decode("ascii", "replace")
            if key == "x-amz-trailer-signature":
                trailer_signature = text.encode("ascii", "replace")
                continue
            if key not in self._declared:
                raise S3Error(
                    "InvalidArgument", f"Trailer {key} was not declared in x-amz-trailer."
                )
            self.trailers[key] = text
            ordered.append((key, text))
        if self.signed:
            assert self._verified is not None
            expected = s3sigv4.trailer_signature(
                self._verified.signing_key,
                self._verified.amz_date,
                self._verified.credential.scope,
                self._previous,
                ordered,
            )
            if trailer_signature is None or not hmac.compare_digest(
                expected.encode("ascii"), trailer_signature
            ):
                raise S3Error("SignatureDoesNotMatch", "The trailer signature does not match.")
        missing = self._declared - set(self.trailers)
        if missing:
            raise S3Error(
                "InvalidRequest", f"Declared trailer missing: {', '.join(sorted(missing))}"
            )
