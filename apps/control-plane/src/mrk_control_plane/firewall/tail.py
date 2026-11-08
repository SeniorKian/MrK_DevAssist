"""Poll-based file tailing with rotation handling and no long-lived file handles.

Each ``read()`` stats the path, reads what was appended since the last call (bounded)
and closes the file again, so the helper holds no descriptors between polls and
rotation by rename works on every platform:

* inode/device changed -> rotated: the rest of the old file is drained from
  ``<path>.1`` when that file still has the old inode, then the new file is read
  from offset 0;
* size shrank below the offset -> truncated in place (copytruncate): restart at 0;
* first sight of a file -> start at its end (history is never re-judged).
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

MAX_LINE_BYTES = 16 * 1024
DEFAULT_MAX_BYTES = 2 * 1024 * 1024


@dataclass(slots=True)
class TailResult:
    lines: list[str] = field(default_factory=list)
    rotated: bool = False
    truncated: bool = False
    more: bool = False
    error: str | None = None


class FileTailer:
    def __init__(self, path: Path, *, start_at_end: bool = True) -> None:
        self.path = path
        self.start_at_end = start_at_end
        self.identity: tuple[int, int] | None = None
        self.offset = 0
        self.partial = b""

    def _consume(self, data: bytes, out: list[str]) -> None:
        buffer = self.partial + data
        parts = buffer.split(b"\n")
        self.partial = parts.pop()
        if len(self.partial) > MAX_LINE_BYTES:
            self.partial = b""  # an over-long line is dropped, never buffered forever
        for raw in parts:
            if raw and len(raw) <= MAX_LINE_BYTES:
                out.append(raw.rstrip(b"\r").decode("utf-8", errors="replace"))

    def _read_from(self, path: Path, offset: int, limit: int) -> bytes:
        with path.open("rb") as handle:
            handle.seek(offset)
            return handle.read(limit)

    def _drain_rotated(self, budget: int, out: list[str]) -> int:
        rotated = self.path.with_name(self.path.name + ".1")
        try:
            stat = rotated.stat()
        except OSError:
            return 0
        if self.identity != (stat.st_ino, stat.st_dev) or stat.st_size <= self.offset:
            return 0
        data = self._read_from(rotated, self.offset, min(budget, stat.st_size - self.offset))
        self._consume(data, out)
        return len(data)

    def read(self, max_bytes: int = DEFAULT_MAX_BYTES) -> TailResult:
        result = TailResult()
        try:
            stat = self.path.stat()
        except FileNotFoundError:
            result.error = "missing"
            return result
        except OSError:
            result.error = "unreadable"
            return result
        if not os.path.isfile(self.path):
            result.error = "not_a_file"
            return result
        identity = (stat.st_ino, stat.st_dev)
        if self.identity is None:
            self.identity = identity
            self.offset = stat.st_size if self.start_at_end else 0
            self.partial = b""
            if self.start_at_end:
                return result
        budget = max_bytes
        try:
            if identity != self.identity:
                result.rotated = True
                budget -= self._drain_rotated(budget, result.lines)
                if self.partial:
                    self._consume(b"\n", result.lines)
                self.identity = identity
                self.offset = 0
            elif stat.st_size < self.offset:
                result.truncated = True
                self.offset = 0
                self.partial = b""
            if stat.st_size > self.offset and budget > 0:
                data = self._read_from(self.path, self.offset, min(budget, stat.st_size -
                                                                    self.offset))
                self.offset += len(data)
                self._consume(data, result.lines)
            result.more = stat.st_size > self.offset
        except PermissionError:
            result.error = "unreadable"
        except OSError:
            result.error = "read_failed"
        return result
