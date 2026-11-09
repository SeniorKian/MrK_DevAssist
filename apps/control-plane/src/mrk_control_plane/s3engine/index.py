# ruff: noqa: E501, S608 - SQL text is built only from module constants
"""Per-bucket SQLite (WAL) object index owned by the engine (docs/30 §3.1).

One file per bucket in ``/data/modules/s3/meta/<bucket>.sqlite``:

* managed buckets: the authoritative object rows (``layout`` = content files),
* linked buckets: a sidecar cache (metadata, real MD5) valid only while
  ``(size, mtime_ns, inode)`` still match the file,
* multipart uploads/parts, deferred deletes (``trash``) and usage counters.

Keys are TEXT with SQLite's default BINARY collation, i.e. UTF-8 byte order, which
is the S3 listing order.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

SCHEMA = """
CREATE TABLE IF NOT EXISTS objects (
  key TEXT PRIMARY KEY,
  size INTEGER NOT NULL,
  etag TEXT NOT NULL,
  last_modified_ns INTEGER NOT NULL,
  meta TEXT NOT NULL,
  layout TEXT NOT NULL,
  mtime_ns INTEGER,
  inode TEXT,
  dev TEXT
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS uploads (
  upload_id TEXT PRIMARY KEY,
  key TEXT NOT NULL,
  initiated_ns INTEGER NOT NULL,
  meta TEXT NOT NULL,
  initiator TEXT NOT NULL
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS uploads_by_key ON uploads(key, upload_id);
CREATE TABLE IF NOT EXISTS parts (
  upload_id TEXT NOT NULL,
  part_number INTEGER NOT NULL,
  size INTEGER NOT NULL,
  etag TEXT NOT NULL,
  checksums TEXT NOT NULL,
  path TEXT NOT NULL,
  last_modified_ns INTEGER NOT NULL,
  PRIMARY KEY (upload_id, part_number)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS trash (
  path TEXT PRIMARY KEY,
  queued_ns INTEGER NOT NULL
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS stats (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  objects INTEGER NOT NULL,
  bytes INTEGER NOT NULL
);
INSERT OR IGNORE INTO stats (id, objects, bytes) VALUES (1, 0, 0);
CREATE TABLE IF NOT EXISTS settings (
  name TEXT PRIMARY KEY,
  value TEXT NOT NULL
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS versions (
  key TEXT NOT NULL,
  version_id TEXT NOT NULL,
  seq INTEGER NOT NULL,
  size INTEGER NOT NULL,
  etag TEXT NOT NULL,
  last_modified_ns INTEGER NOT NULL,
  meta TEXT NOT NULL,
  layout TEXT NOT NULL,
  delete_marker INTEGER NOT NULL,
  noncurrent_ns INTEGER NOT NULL,
  PRIMARY KEY (key, version_id)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS versions_by_seq ON versions(key, seq);
"""
# Schema history (additive only, ``CREATE ... IF NOT EXISTS``, so older index files
# keep working and are upgraded in place on open):
#   1 = objects/uploads/parts/trash/stats
#   2 = + settings (bucket tagging, lifecycle, versioning state) and versions
#       (noncurrent object versions and delete markers; the current version of a
#       key always stays in ``objects``)
SCHEMA_VERSION = 2

PAGE = 500
VERSIONING_STATES = ("Enabled", "Suspended")
_BASE62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
_SEQ_LOCK = threading.Lock()
_LAST_SEQ = 0


def next_seq() -> int:
    """Strictly increasing nanosecond counter (orders versions of one key)."""
    global _LAST_SEQ
    with _SEQ_LOCK:
        _LAST_SEQ = max(time.time_ns(), _LAST_SEQ + 1)
        return _LAST_SEQ


def _base62(number: int, width: int) -> str:
    chars = []
    while number:
        number, rest = divmod(number, 62)
        chars.append(_BASE62[rest])
    return "".join(reversed(chars)).rjust(width, "0")[-width:]


def new_version_id() -> str:
    """32-char base62 id: 12 time-ordered characters + 20 random ones."""
    return _base62(next_seq(), 12) + _base62(int.from_bytes(os.urandom(16), "big"), 20)


def version_of(meta: dict[str, Any]) -> str:
    return str(meta.get("version_id") or "null")


@dataclass(slots=True)
class VersionRecord:
    key: str
    version_id: str
    seq: int
    size: int
    etag: str
    last_modified_ns: int
    meta: dict[str, Any]
    layout: list[list[Any]]
    delete_marker: bool
    is_latest: bool
    noncurrent_ns: int = 0


@dataclass(slots=True)
class ObjectRecord:
    key: str
    size: int
    etag: str
    last_modified_ns: int
    meta: dict[str, Any] = field(default_factory=dict)
    layout: list[list[Any]] = field(default_factory=list)  # [[relative path, size], ...]
    mtime_ns: int | None = None
    inode: int | None = None
    dev: int | None = None


@dataclass(slots=True)
class UploadRecord:
    upload_id: str
    key: str
    initiated_ns: int
    meta: dict[str, Any]
    initiator: str


@dataclass(slots=True)
class PartRecord:
    upload_id: str
    part_number: int
    size: int
    etag: str
    checksums: dict[str, str]
    path: str
    last_modified_ns: int


def _object(row: tuple[Any, ...]) -> ObjectRecord:
    return ObjectRecord(
        key=row[0],
        size=row[1],
        etag=row[2],
        last_modified_ns=row[3],
        meta=json.loads(row[4]) if row[4] else {},
        layout=json.loads(row[5]) if row[5] else [],
        mtime_ns=row[6],
        inode=int(row[7]) if row[7] is not None else None,
        dev=int(row[8]) if row[8] is not None else None,
    )


def _text(value: int | None) -> str | None:
    # Inode/device numbers can exceed SQLite's int64 (e.g. ReFS 128-bit file ids).
    return None if value is None else str(value)


_OBJECT_COLUMNS = "key, size, etag, last_modified_ns, meta, layout, mtime_ns, inode, dev"


def prefix_upper_bound(prefix: str) -> str | None:
    """Smallest string greater than every string starting with ``prefix``."""
    chars = list(prefix)
    while chars:
        last = ord(chars[-1])
        if last < 0x10FFFF:
            # Skip the surrogate block, which UTF-8 strings never contain.
            nxt = last + 1 if last + 1 != 0xD800 else 0xE000
            chars[-1] = chr(nxt)
            return "".join(chars)
        chars.pop()
    return None


class BucketIndex:
    def __init__(self, path: Path, *, synchronous: str = "NORMAL") -> None:
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(
            path, check_same_thread=False, isolation_level=None, timeout=30
        )
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute(f"PRAGMA synchronous={synchronous}")
        self._conn.execute("PRAGMA foreign_keys=OFF")
        self._conn.executescript(SCHEMA)
        if self._conn.execute("PRAGMA user_version").fetchone()[0] < SCHEMA_VERSION:
            self._conn.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
        self._settings: dict[str, str | None] = {}

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # ------------------------------------------------------------------ objects

    def get(self, key: str) -> ObjectRecord | None:
        with self._lock:
            row = self._conn.execute(
                f"SELECT {_OBJECT_COLUMNS} FROM objects WHERE key = ?", (key,)
            ).fetchone()
        return _object(row) if row else None

    # ------------------------------------------------------------------ settings

    def get_setting(self, name: str) -> str | None:
        with self._lock:
            if name not in self._settings:
                row = self._conn.execute(
                    "SELECT value FROM settings WHERE name = ?", (name,)
                ).fetchone()
                self._settings[name] = row[0] if row else None
            return self._settings[name]

    def set_setting(self, name: str, value: str | None) -> None:
        with self._lock:
            if value is None:
                self._conn.execute("DELETE FROM settings WHERE name = ?", (name,))
            else:
                self._conn.execute(
                    "INSERT OR REPLACE INTO settings (name, value) VALUES (?, ?)", (name, value)
                )
            self._settings[name] = value

    # ------------------------------------------------------------------ write helpers

    @staticmethod
    def _insert_object(cur: sqlite3.Cursor, record: ObjectRecord) -> None:
        cur.execute(
            "INSERT OR REPLACE INTO objects (key, size, etag, last_modified_ns, meta, layout, mtime_ns, inode, dev)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                record.key,
                record.size,
                record.etag,
                record.last_modified_ns,
                json.dumps(record.meta, separators=(",", ":")),
                json.dumps(record.layout, separators=(",", ":")),
                record.mtime_ns,
                _text(record.inode),
                _text(record.dev),
            ),
        )

    @staticmethod
    def _trash(cur: sqlite3.Cursor, layout: list[list[Any]], now: int, keep: set[str]) -> None:
        for item in layout:
            if item[0] not in keep:
                cur.execute(
                    "INSERT OR REPLACE INTO trash (path, queued_ns) VALUES (?, ?)", (item[0], now)
                )

    def _drop_version(self, cur: sqlite3.Cursor, key: str, version_id: str, now: int) -> int:
        """Remove one noncurrent version/marker row; returns the bytes it freed."""
        row = cur.execute(
            "SELECT size, layout, delete_marker FROM versions WHERE key = ? AND version_id = ?",
            (key, version_id),
        ).fetchone()
        if row is None:
            return 0
        cur.execute("DELETE FROM versions WHERE key = ? AND version_id = ?", (key, version_id))
        if row[2]:
            return 0
        self._trash(cur, json.loads(row[1] or "[]"), now, set())
        return int(row[0])

    def _archive(self, cur: sqlite3.Cursor, old: ObjectRecord, now: int) -> int:
        """Move the current version into ``versions`` (noncurrent); returns freed bytes."""
        vid = version_of(old.meta)
        freed = self._drop_version(cur, old.key, vid, now)
        cur.execute(
            "INSERT INTO versions (key, version_id, seq, size, etag, last_modified_ns, meta, layout,"
            " delete_marker, noncurrent_ns) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?)",
            (
                old.key,
                vid,
                int(old.meta.get("vseq") or old.last_modified_ns),
                old.size,
                old.etag,
                old.last_modified_ns,
                json.dumps(old.meta, separators=(",", ":")),
                json.dumps(old.layout, separators=(",", ":")),
                now,
            ),
        )
        return freed

    def _publish(
        self,
        cur: sqlite3.Cursor,
        record: ObjectRecord,
        *,
        versioning: str,
        count_stats: bool,
        now: int,
    ) -> ObjectRecord | None:
        meta = dict(record.meta)
        meta.pop("version_id", None)
        meta.pop("vseq", None)
        if versioning in VERSIONING_STATES:
            if versioning == "Enabled":
                meta["version_id"] = new_version_id()
            meta["vseq"] = next_seq()
        record.meta = meta
        row = cur.execute(
            f"SELECT {_OBJECT_COLUMNS} FROM objects WHERE key = ?", (record.key,)
        ).fetchone()
        old = _object(row) if row else None
        self._insert_object(cur, record)
        delta_objects = 0 if old else 1
        delta_bytes = record.size
        if versioning in VERSIONING_STATES:
            cur.execute(
                "UPDATE versions SET noncurrent_ns = ? WHERE key = ? AND noncurrent_ns = 0",
                (now, record.key),
            )
        if old is not None:
            if versioning == "Enabled" or (
                versioning == "Suspended" and version_of(old.meta) != "null"
            ):
                delta_bytes -= self._archive(cur, old, now)
            else:
                self._trash(cur, old.layout, now, {item[0] for item in record.layout})
                delta_bytes -= old.size
        if versioning == "Suspended":
            delta_bytes -= self._drop_version(cur, record.key, "null", now)
        if count_stats:
            cur.execute(
                "UPDATE stats SET objects = objects + ?, bytes = bytes + ? WHERE id = 1",
                (delta_objects, delta_bytes),
            )
        return old

    def put(
        self, record: ObjectRecord, *, count_stats: bool = True, versioning: str = ""
    ) -> ObjectRecord | None:
        """Insert or replace; the replaced record's files go to the trash queue.

        With ``versioning`` Enabled/Suspended the replaced version is kept as a
        noncurrent version instead (unless both are the ``null`` version).
        """
        now = time.time_ns()
        with self._lock:
            cur = self._conn.cursor()
            cur.execute("BEGIN IMMEDIATE")
            try:
                old = self._publish(
                    cur, record, versioning=versioning, count_stats=count_stats, now=now
                )
                cur.execute("COMMIT")
            except BaseException:
                cur.execute("ROLLBACK")
                raise
        return old

    def update_meta(self, key: str, meta: dict[str, Any], version_id: str | None = None) -> bool:
        """Replace an object's (or one version's) metadata without touching its data."""
        text = json.dumps(meta, separators=(",", ":"))
        with self._lock:
            if version_id is not None:
                current = self._conn.execute(
                    "SELECT meta FROM objects WHERE key = ?", (key,)
                ).fetchone()
                if current is None or version_of(json.loads(current[0] or "{}")) != version_id:
                    cur = self._conn.execute(
                        "UPDATE versions SET meta = ? WHERE key = ? AND version_id = ? AND delete_marker = 0",
                        (text, key, version_id),
                    )
                    return cur.rowcount > 0
            cur = self._conn.execute("UPDATE objects SET meta = ? WHERE key = ?", (text, key))
            return cur.rowcount > 0

    # ------------------------------------------------------------------ versions

    @staticmethod
    def _version_row(row: tuple[Any, ...]) -> VersionRecord:
        return VersionRecord(
            key=row[0],
            version_id=row[1],
            seq=row[2],
            size=row[3],
            etag=row[4],
            last_modified_ns=row[5],
            meta=json.loads(row[6]) if row[6] else {},
            layout=json.loads(row[7]) if row[7] else [],
            delete_marker=bool(row[8]),
            is_latest=row[9] == 0,
            noncurrent_ns=row[9],
        )

    @staticmethod
    def _current_version(record: ObjectRecord) -> VersionRecord:
        return VersionRecord(
            key=record.key,
            version_id=version_of(record.meta),
            seq=int(record.meta.get("vseq") or record.last_modified_ns),
            size=record.size,
            etag=record.etag,
            last_modified_ns=record.last_modified_ns,
            meta=record.meta,
            layout=record.layout,
            delete_marker=False,
            is_latest=True,
        )

    _VERSION_COLUMNS = "key, version_id, seq, size, etag, last_modified_ns, meta, layout, delete_marker, noncurrent_ns"

    def versions_for(self, key: str) -> list[VersionRecord]:
        """Every version of ``key``, newest first (the current object, if any, leads)."""
        with self._lock:
            row = self._conn.execute(
                f"SELECT {_OBJECT_COLUMNS} FROM objects WHERE key = ?", (key,)
            ).fetchone()
            rows = self._conn.execute(
                f"SELECT {self._VERSION_COLUMNS} FROM versions WHERE key = ? ORDER BY seq DESC, version_id DESC",
                (key,),
            ).fetchall()
        result = [self._current_version(_object(row))] if row else []
        result.extend(self._version_row(item) for item in rows)
        return result

    def get_version(self, key: str, version_id: str) -> VersionRecord | None:
        with self._lock:
            row = self._conn.execute(
                f"SELECT {_OBJECT_COLUMNS} FROM objects WHERE key = ?", (key,)
            ).fetchone()
            if row is not None:
                current = _object(row)
                if version_of(current.meta) == version_id:
                    return self._current_version(current)
            found = self._conn.execute(
                f"SELECT {self._VERSION_COLUMNS} FROM versions WHERE key = ? AND version_id = ?",
                (key, version_id),
            ).fetchone()
        return self._version_row(found) if found else None

    def latest_marker(self, key: str) -> VersionRecord | None:
        with self._lock:
            row = self._conn.execute(
                f"SELECT {self._VERSION_COLUMNS} FROM versions WHERE key = ? AND noncurrent_ns = 0 AND delete_marker = 1",
                (key,),
            ).fetchone()
        return self._version_row(row) if row else None

    def version_keys(self, start: str, *, inclusive: bool, prefix: str, limit: int) -> list[str]:
        """Distinct keys (current or noncurrent) in key order after ``start``."""
        upper = prefix_upper_bound(prefix) if prefix else None
        lower, lower_inclusive = start, inclusive
        if prefix and prefix > lower:
            lower, lower_inclusive = prefix, True
        op = ">=" if lower_inclusive else ">"
        bound = " AND key < ?" if upper is not None else ""
        params: list[Any] = [lower] + ([upper] if upper is not None else [])
        sql = (
            f"SELECT key FROM objects WHERE key {op} ?{bound}"
            f" UNION SELECT key FROM versions WHERE key {op} ?{bound} ORDER BY key LIMIT ?"
        )
        with self._lock:
            rows = self._conn.execute(sql, [*params, *params, limit]).fetchall()
        return [row[0] for row in rows]

    def has_versions(self) -> bool:
        with self._lock:
            return self._conn.execute("SELECT 1 FROM versions LIMIT 1").fetchone() is not None

    def delete_marker(self, key: str, versioning: str) -> str:
        """Versioned DELETE without a version id: add a delete marker; returns its id."""
        now = time.time_ns()
        vid = new_version_id() if versioning == "Enabled" else "null"
        with self._lock:
            cur = self._conn.cursor()
            cur.execute("BEGIN IMMEDIATE")
            try:
                row = cur.execute(
                    f"SELECT {_OBJECT_COLUMNS} FROM objects WHERE key = ?", (key,)
                ).fetchone()
                old = _object(row) if row else None
                delta_objects = delta_bytes = 0
                cur.execute(
                    "UPDATE versions SET noncurrent_ns = ? WHERE key = ? AND noncurrent_ns = 0",
                    (now, key),
                )
                if old is not None:
                    cur.execute("DELETE FROM objects WHERE key = ?", (key,))
                    delta_objects = -1
                    if versioning == "Enabled" or version_of(old.meta) != "null":
                        delta_bytes -= self._archive(cur, old, now)
                    else:
                        self._trash(cur, old.layout, now, set())
                        delta_bytes -= old.size
                delta_bytes -= self._drop_version(cur, key, vid, now)
                cur.execute(
                    "INSERT INTO versions (key, version_id, seq, size, etag, last_modified_ns, meta, layout,"
                    " delete_marker, noncurrent_ns) VALUES (?, ?, ?, 0, '', ?, '{}', '[]', 1, 0)",
                    (key, vid, next_seq(), now),
                )
                cur.execute(
                    "UPDATE stats SET objects = objects + ?, bytes = bytes + ? WHERE id = 1",
                    (delta_objects, delta_bytes),
                )
                cur.execute("COMMIT")
            except BaseException:
                cur.execute("ROLLBACK")
                raise
        return vid

    def _promote(self, cur: sqlite3.Cursor, key: str) -> int:
        """After the latest version was removed, make the newest remaining one current."""
        row = cur.execute(
            f"SELECT {self._VERSION_COLUMNS} FROM versions WHERE key = ? ORDER BY seq DESC, version_id DESC LIMIT 1",
            (key,),
        ).fetchone()
        if row is None:
            return 0
        newest = self._version_row(row)
        if newest.delete_marker:
            cur.execute(
                "UPDATE versions SET noncurrent_ns = 0 WHERE key = ? AND version_id = ?",
                (key, newest.version_id),
            )
            return 0
        cur.execute(
            "DELETE FROM versions WHERE key = ? AND version_id = ?", (key, newest.version_id)
        )
        self._insert_object(
            cur,
            ObjectRecord(
                key=key,
                size=newest.size,
                etag=newest.etag,
                last_modified_ns=newest.last_modified_ns,
                meta=newest.meta,
                layout=newest.layout,
            ),
        )
        return 1

    def delete_version(self, key: str, version_id: str) -> VersionRecord | None:
        """Permanently remove one version (or delete marker); returns what was removed."""
        now = time.time_ns()
        with self._lock:
            cur = self._conn.cursor()
            cur.execute("BEGIN IMMEDIATE")
            try:
                row = cur.execute(
                    f"SELECT {_OBJECT_COLUMNS} FROM objects WHERE key = ?", (key,)
                ).fetchone()
                current = _object(row) if row else None
                delta_objects = delta_bytes = 0
                removed: VersionRecord | None = None
                if current is not None and version_of(current.meta) == version_id:
                    removed = self._current_version(current)
                    cur.execute("DELETE FROM objects WHERE key = ?", (key,))
                    self._trash(cur, current.layout, now, set())
                    delta_objects, delta_bytes = -1, -current.size
                    delta_objects += self._promote(cur, key)
                else:
                    found = cur.execute(
                        f"SELECT {self._VERSION_COLUMNS} FROM versions WHERE key = ? AND version_id = ?",
                        (key, version_id),
                    ).fetchone()
                    if found is not None:
                        removed = self._version_row(found)
                        delta_bytes -= self._drop_version(cur, key, version_id, now)
                        if removed.is_latest and current is None:
                            delta_objects += self._promote(cur, key)
                cur.execute(
                    "UPDATE stats SET objects = objects + ?, bytes = bytes + ? WHERE id = 1",
                    (delta_objects, delta_bytes),
                )
                cur.execute("COMMIT")
            except BaseException:
                cur.execute("ROLLBACK")
                raise
        return removed

    def delete(self, key: str, *, count_stats: bool = True) -> ObjectRecord | None:
        now = time.time_ns()
        with self._lock:
            cur = self._conn.cursor()
            cur.execute("BEGIN IMMEDIATE")
            try:
                row = cur.execute(
                    f"SELECT {_OBJECT_COLUMNS} FROM objects WHERE key = ?", (key,)
                ).fetchone()
                if row is None:
                    cur.execute("COMMIT")
                    return None
                old = _object(row)
                cur.execute("DELETE FROM objects WHERE key = ?", (key,))
                for item in old.layout:
                    cur.execute(
                        "INSERT OR REPLACE INTO trash (path, queued_ns) VALUES (?, ?)",
                        (item[0], now),
                    )
                if count_stats:
                    cur.execute(
                        "UPDATE stats SET objects = objects - 1, bytes = bytes - ? WHERE id = 1",
                        (old.size,),
                    )
                cur.execute("COMMIT")
            except BaseException:
                cur.execute("ROLLBACK")
                raise
        return old

    def iter_objects(
        self, start: str = "", *, inclusive: bool = False, prefix: str = ""
    ) -> Iterator[ObjectRecord]:
        """Objects in key order with ``key > start`` (or ``>=``), restricted to ``prefix``."""
        upper = prefix_upper_bound(prefix) if prefix else None
        lower = start
        lower_inclusive = inclusive
        if prefix and prefix > lower:
            lower, lower_inclusive = prefix, True
        while True:
            op = ">=" if lower_inclusive else ">"
            sql = f"SELECT {_OBJECT_COLUMNS} FROM objects WHERE key {op} ?"
            params: list[Any] = [lower]
            if upper is not None:
                sql += " AND key < ?"
                params.append(upper)
            sql += " ORDER BY key LIMIT ?"
            params.append(PAGE)
            with self._lock:
                rows = self._conn.execute(sql, params).fetchall()
            for row in rows:
                yield _object(row)
            if len(rows) < PAGE:
                return
            lower, lower_inclusive = rows[-1][0], False

    def stats(self) -> tuple[int, int]:
        with self._lock:
            row = self._conn.execute("SELECT objects, bytes FROM stats WHERE id = 1").fetchone()
        return (int(row[0]), int(row[1])) if row else (0, 0)

    def recompute_stats(self) -> tuple[int, int]:
        with self._lock:
            row = self._conn.execute(
                "SELECT count(*), coalesce(sum(size), 0)"
                " + (SELECT coalesce(sum(size), 0) FROM versions) FROM objects"
            ).fetchone()
            self._conn.execute(
                "UPDATE stats SET objects = ?, bytes = ? WHERE id = 1", (row[0], row[1])
            )
        return int(row[0]), int(row[1])

    def has_objects(self) -> bool:
        with self._lock:
            if self._conn.execute("SELECT 1 FROM objects LIMIT 1").fetchone() is not None:
                return True
            return self._conn.execute("SELECT 1 FROM versions LIMIT 1").fetchone() is not None

    def all_layout_paths(self) -> set[str]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT layout FROM objects UNION ALL SELECT layout FROM versions"
            ).fetchall()
        paths: set[str] = set()
        for (layout,) in rows:
            for item in json.loads(layout or "[]"):
                paths.add(item[0])
        return paths

    def delete_keys_not_in(self, keys: set[str]) -> int:
        """Prune sidecar rows (linked buckets) whose files no longer exist."""
        removed = 0
        with self._lock:
            rows = [row[0] for row in self._conn.execute("SELECT key FROM objects").fetchall()]
            for key in rows:
                if key not in keys:
                    self._conn.execute("DELETE FROM objects WHERE key = ?", (key,))
                    removed += 1
        return removed

    def set_stats(self, objects: int, total: int) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE stats SET objects = ?, bytes = ? WHERE id = 1", (objects, total)
            )

    # ------------------------------------------------------------------ trash

    def trash_due(self, older_than_ns: int, limit: int = 1000) -> list[str]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT path FROM trash WHERE queued_ns <= ? LIMIT ?", (older_than_ns, limit)
            ).fetchall()
        return [row[0] for row in rows]

    def trash_done(self, paths: list[str]) -> None:
        with self._lock:
            self._conn.executemany("DELETE FROM trash WHERE path = ?", [(p,) for p in paths])

    def trash_add(self, paths: list[str]) -> None:
        now = time.time_ns()
        with self._lock:
            self._conn.executemany(
                "INSERT OR REPLACE INTO trash (path, queued_ns) VALUES (?, ?)",
                [(p, now) for p in paths],
            )

    # ------------------------------------------------------------------ uploads

    def create_upload(self, upload: UploadRecord) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO uploads (upload_id, key, initiated_ns, meta, initiator) VALUES (?, ?, ?, ?, ?)",
                (
                    upload.upload_id,
                    upload.key,
                    upload.initiated_ns,
                    json.dumps(upload.meta),
                    upload.initiator,
                ),
            )

    def get_upload(self, upload_id: str) -> UploadRecord | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT upload_id, key, initiated_ns, meta, initiator FROM uploads WHERE upload_id = ?",
                (upload_id,),
            ).fetchone()
        if row is None:
            return None
        return UploadRecord(row[0], row[1], row[2], json.loads(row[3]), row[4])

    def list_uploads(self) -> list[UploadRecord]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT upload_id, key, initiated_ns, meta, initiator FROM uploads ORDER BY key, initiated_ns, upload_id"
            ).fetchall()
        return [UploadRecord(r[0], r[1], r[2], json.loads(r[3]), r[4]) for r in rows]

    def has_uploads(self) -> bool:
        with self._lock:
            return self._conn.execute("SELECT 1 FROM uploads LIMIT 1").fetchone() is not None

    def put_part(self, part: PartRecord) -> PartRecord | None:
        with self._lock:
            cur = self._conn.cursor()
            cur.execute("BEGIN IMMEDIATE")
            try:
                row = cur.execute(
                    "SELECT upload_id, part_number, size, etag, checksums, path, last_modified_ns FROM parts"
                    " WHERE upload_id = ? AND part_number = ?",
                    (part.upload_id, part.part_number),
                ).fetchone()
                exists = cur.execute(
                    "SELECT 1 FROM uploads WHERE upload_id = ?", (part.upload_id,)
                ).fetchone()
                if exists is None:
                    cur.execute("ROLLBACK")
                    raise KeyError(part.upload_id)
                cur.execute(
                    "INSERT OR REPLACE INTO parts (upload_id, part_number, size, etag, checksums, path, last_modified_ns)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        part.upload_id,
                        part.part_number,
                        part.size,
                        part.etag,
                        json.dumps(part.checksums),
                        part.path,
                        part.last_modified_ns,
                    ),
                )
                cur.execute("COMMIT")
            except KeyError:
                raise
            except BaseException:
                cur.execute("ROLLBACK")
                raise
        if row is None:
            return None
        return PartRecord(row[0], row[1], row[2], row[3], json.loads(row[4]), row[5], row[6])

    def list_parts(self, upload_id: str) -> list[PartRecord]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT upload_id, part_number, size, etag, checksums, path, last_modified_ns FROM parts"
                " WHERE upload_id = ? ORDER BY part_number",
                (upload_id,),
            ).fetchall()
        return [PartRecord(r[0], r[1], r[2], r[3], json.loads(r[4]), r[5], r[6]) for r in rows]

    def uploads_bytes(self) -> int:
        with self._lock:
            row = self._conn.execute("SELECT coalesce(sum(size), 0) FROM parts").fetchone()
        return int(row[0])

    def finish_upload(
        self,
        upload_id: str,
        record: ObjectRecord | None,
        *,
        keep_paths: set[str],
        versioning: str = "",
    ) -> ObjectRecord | None:
        """Atomically drop the upload (and parts) and, if given, publish ``record``.

        Part files not in ``keep_paths`` are queued for deletion.
        """
        now = time.time_ns()
        with self._lock:
            cur = self._conn.cursor()
            cur.execute("BEGIN IMMEDIATE")
            try:
                parts = cur.execute(
                    "SELECT path FROM parts WHERE upload_id = ?", (upload_id,)
                ).fetchall()
                cur.execute("DELETE FROM parts WHERE upload_id = ?", (upload_id,))
                cur.execute("DELETE FROM uploads WHERE upload_id = ?", (upload_id,))
                for (path,) in parts:
                    if path not in keep_paths:
                        cur.execute(
                            "INSERT OR REPLACE INTO trash (path, queued_ns) VALUES (?, ?)",
                            (path, now),
                        )
                old: ObjectRecord | None = None
                if record is not None:
                    old = self._publish(
                        cur, record, versioning=versioning, count_stats=True, now=now
                    )
                cur.execute("COMMIT")
            except BaseException:
                cur.execute("ROLLBACK")
                raise
        return old

    def stale_uploads(self, older_than_ns: int) -> list[str]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT upload_id FROM uploads WHERE initiated_ns < ?", (older_than_ns,)
            ).fetchall()
        return [row[0] for row in rows]
