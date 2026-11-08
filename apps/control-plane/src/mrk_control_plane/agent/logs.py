"""Decode ``GET /containers/{id}/logs`` output into ``{ts, stream, text}`` lines.

Without a TTY Docker multiplexes stdout/stderr into frames with an 8-byte header
``[stream, 0, 0, 0, size (uint32 big-endian)]``; with a TTY the body is the raw
terminal output (reported as ``stdout``).
"""

from __future__ import annotations

import re
from typing import Any

MAX_LINE_BYTES = 16 * 1024
_STREAMS = {0: "stdout", 1: "stdout", 2: "stderr"}
_TIMESTAMP = re.compile(
    rb"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})) "
)


class LogDecoder:
    def __init__(self, tty: bool, *, timestamps: bool = True) -> None:
        self.tty = tty
        self.timestamps = timestamps
        self._frame = bytearray()
        self._buffers: dict[str, bytearray] = {"stdout": bytearray(), "stderr": bytearray()}

    def feed(self, chunk: bytes) -> list[dict[str, Any]]:
        lines: list[dict[str, Any]] = []
        if self.tty:
            self._append("stdout", chunk, lines)
            return lines
        self._frame.extend(chunk)
        while len(self._frame) >= 8:
            stream = _STREAMS.get(self._frame[0], "stdout")
            size = int.from_bytes(self._frame[4:8], "big")
            if len(self._frame) < 8 + size:
                break
            payload = bytes(self._frame[8 : 8 + size])
            del self._frame[: 8 + size]
            self._append(stream, payload, lines)
        return lines

    def flush(self) -> list[dict[str, Any]]:
        lines: list[dict[str, Any]] = []
        if self._frame and not self.tty:
            # A truncated frame at the end of the body: keep what arrived.
            payload = bytes(self._frame[8:])
            stream = _STREAMS.get(self._frame[0], "stdout")
            self._frame.clear()
            self._append(stream, payload, lines)
        for stream, buffer in self._buffers.items():
            if buffer:
                lines.append(self._line(stream, bytes(buffer)))
                buffer.clear()
        return lines

    def _append(self, stream: str, data: bytes, lines: list[dict[str, Any]]) -> None:
        buffer = self._buffers[stream]
        buffer.extend(data)
        while True:
            index = buffer.find(b"\n")
            if index < 0:
                break
            lines.append(self._line(stream, bytes(buffer[:index])))
            del buffer[: index + 1]
        while len(buffer) > MAX_LINE_BYTES:
            lines.append(self._line(stream, bytes(buffer[:MAX_LINE_BYTES])))
            del buffer[:MAX_LINE_BYTES]

    def _line(self, stream: str, raw: bytes) -> dict[str, Any]:
        ts = None
        match = _TIMESTAMP.match(raw)
        if match:
            raw = raw[match.end() :]
            if self.timestamps:
                ts = match.group(1).decode("ascii")
        text = raw.decode("utf-8", errors="replace").rstrip("\r")
        return {"ts": ts, "stream": stream, "text": text}


def line_size(line: dict[str, Any]) -> int:
    return len(line["text"].encode("utf-8")) + len(line["ts"] or "") + 32
