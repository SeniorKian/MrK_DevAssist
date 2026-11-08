"""Local OSV.dev index for the vulnerability scanner (Gate 19 S8).

OSV publishes one bulk export per ecosystem:
``<base>/<Ecosystem>/all.zip`` (default base
``https://osv-vulnerabilities.storage.googleapis.com``), one JSON record per zip
member. Release-specific ecosystems ("Debian:12", "Alpine:v3.20",
"Ubuntu:22.04:LTS") live inside the top-level export, so the feed for
``Debian:12`` is ``Debian/all.zip`` and records are indexed by their full
``affected[].package.ecosystem``.

Downloads stream to a temporary file (size cap), then the zip is read member by
member (per-member and total uncompressed caps) into a SQLite index at
``data_dir/modules/vuln/osv.sqlite`` — never PGlite, never the whole feed in
memory. Refreshes are conditional (``If-None-Match`` / ``If-Modified-Since``);
a 304 only updates ``checked_at``. Each import replaces that feed's rows in one
transaction, so readers always see a complete feed.
"""

from __future__ import annotations

import contextlib
import json
import logging
import math
import os
import re
import sqlite3
import tempfile
import threading
import time
import zipfile
import zlib
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import quote

from .vuln_inventory import normalize_pypi

LOGGER = logging.getLogger(__name__)
DEFAULT_FEED_BASE = "https://osv-vulnerabilities.storage.googleapis.com"
# Feeds this scanner can evaluate (version ordering implemented).
SUPPORTED_FEEDS = (
    "Debian", "Ubuntu", "Alpine", "Wolfi", "Chainguard", "AlmaLinux", "Rocky Linux",
    "npm", "PyPI",
)
SEVERITIES = ("critical", "high", "medium", "low", "unknown")
SEVERITY_RANK = {name: index for index, name in enumerate(reversed(SEVERITIES))}
MAX_MEMBER_BYTES = 4 * 1024 * 1024
MAX_SUMMARY = 300
BATCH = 500

_SCHEMA = """
CREATE TABLE IF NOT EXISTS feeds (
    feed TEXT PRIMARY KEY, url TEXT, etag TEXT, last_modified TEXT,
    updated_at REAL, checked_at REAL, records INTEGER DEFAULT 0, size INTEGER DEFAULT 0,
    status TEXT, error TEXT
);
CREATE TABLE IF NOT EXISTS advisories (
    feed TEXT NOT NULL, id TEXT NOT NULL, summary TEXT, severity TEXT, score REAL,
    aliases TEXT, modified TEXT, PRIMARY KEY (feed, id)
);
CREATE TABLE IF NOT EXISTS affected (
    feed TEXT NOT NULL, id TEXT NOT NULL, ecosystem TEXT NOT NULL, name TEXT NOT NULL,
    data BLOB NOT NULL
);
CREATE INDEX IF NOT EXISTS affected_lookup ON affected (ecosystem, name);
CREATE INDEX IF NOT EXISTS affected_feed ON affected (feed);
"""


def feed_for(ecosystem: str) -> str:
    return ecosystem.split(":", 1)[0]


def feed_url(base: str, feed: str) -> str:
    return f"{base.rstrip('/')}/{quote(feed, safe='')}/all.zip"


# ----- severity ---------------------------------------------------------------------------

_V3_WEIGHTS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
}


def _roundup(value: float) -> float:
    integer = round(value * 100000)
    if integer % 10000 == 0:
        return integer / 100000.0
    return (math.floor(integer / 10000) + 1) / 10.0


def _vector(text: str) -> dict[str, str]:
    metrics: dict[str, str] = {}
    for part in text.split("/"):
        key, sep, value = part.partition(":")
        if sep:
            metrics[key] = value
    return metrics


def cvss3_score(vector: str) -> float | None:
    """CVSS v3.0/v3.1 base score from a vector string."""
    if not vector.startswith("CVSS:3"):
        return None
    m = _vector(vector)
    try:
        scope_changed = m["S"] == "C"
        av = _V3_WEIGHTS["AV"][m["AV"]]
        ac = _V3_WEIGHTS["AC"][m["AC"]]
        ui = _V3_WEIGHTS["UI"][m["UI"]]
        pr = {"N": 0.85, "L": 0.68 if scope_changed else 0.62,
              "H": 0.5 if scope_changed else 0.27}[m["PR"]]
        c, i, a = (_V3_WEIGHTS["C"][m[key]] for key in ("C", "I", "A"))
    except KeyError:
        return None
    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    exploitability = 8.22 * av * ac * pr * ui
    if impact <= 0:
        return 0.0
    if scope_changed:
        return _roundup(min(1.08 * (impact + exploitability), 10))
    return _roundup(min(impact + exploitability, 10))


def cvss2_score(vector: str) -> float | None:
    m = _vector(vector.removeprefix("(").removesuffix(")"))
    try:
        av = {"L": 0.395, "A": 0.646, "N": 1.0}[m["AV"]]
        ac = {"H": 0.35, "M": 0.61, "L": 0.71}[m["AC"]]
        au = {"M": 0.45, "S": 0.56, "N": 0.704}[m["Au"]]
        c, i, a = ({"N": 0.0, "P": 0.275, "C": 0.660}[m[key]] for key in ("C", "I", "A"))
    except KeyError:
        return None
    impact = 10.41 * (1 - (1 - c) * (1 - i) * (1 - a))
    exploitability = 20 * av * ac * au
    factor = 0 if impact == 0 else 1.176
    return round(((0.6 * impact) + (0.4 * exploitability) - 1.5) * factor, 1)


def score_severity(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


_TEXT_SEVERITY = {
    "critical": "critical", "high": "high", "important": "high", "moderate": "medium",
    "medium": "medium", "low": "low", "negligible": "low", "unimportant": "low",
}


def record_severity(record: dict[str, Any]) -> tuple[str, float | None]:
    """(severity, score) from OSV ``severity`` vectors or database-specific labels."""
    entries = [item for item in record.get("severity") or [] if isinstance(item, dict)]
    for item in record.get("affected") or []:
        if isinstance(item, dict):
            entries.extend(e for e in item.get("severity") or [] if isinstance(e, dict))
    v2: float | None = None
    text: str | None = None
    for item in entries:
        kind, score = item.get("type"), str(item.get("score") or "")
        if kind == "CVSS_V3":
            value = cvss3_score(score)
            if value is not None:
                return score_severity(value), value
        elif kind == "CVSS_V2" and v2 is None:
            v2 = cvss2_score(score)
        elif kind == "Ubuntu" and text is None:
            text = _TEXT_SEVERITY.get(score.lower())
    specific = record.get("database_specific")
    if isinstance(specific, dict) and isinstance(specific.get("severity"), str):
        text = _TEXT_SEVERITY.get(specific["severity"].lower()) or text
    if text is None:
        for item in record.get("affected") or []:
            extra = item.get("database_specific") if isinstance(item, dict) else None
            for key in ("severity", "urgency"):
                value = extra.get(key) if isinstance(extra, dict) else None
                if isinstance(value, str) and value.lower().rstrip("*") in _TEXT_SEVERITY:
                    text = _TEXT_SEVERITY[value.lower().rstrip("*")]
                    break
            if text:
                break
    if text:
        return text, None
    if v2 is not None:
        return score_severity(v2), v2
    return "unknown", None


# ----- store ---------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Match:
    id: str
    entry: dict[str, Any]
    summary: str
    severity: str
    score: float | None
    aliases: list[str]


class FeedImportError(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class OsvStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = threading.Lock()
        self._ready = False

    @contextlib.contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.path, timeout=30.0)
        try:
            if not self._ready:
                with self._lock:
                    connection.execute("PRAGMA journal_mode=WAL")
                    connection.executescript(_SCHEMA)
                    self._ready = True
            yield connection
        finally:
            connection.close()

    # -- feed metadata
    def feeds(self) -> dict[str, dict[str, Any]]:
        with self.connect() as db:
            rows = db.execute(
                "SELECT feed, url, etag, last_modified, updated_at, checked_at, records, size, "
                "status, error FROM feeds"
            ).fetchall()
        keys = ("feed", "url", "etag", "last_modified", "updated_at", "checked_at", "records",
                "size", "status", "error")
        return {row[0]: dict(zip(keys, row, strict=True)) for row in rows}

    def mark(self, feed: str, **values: Any) -> None:
        with self.connect() as db:
            db.execute("INSERT OR IGNORE INTO feeds (feed) VALUES (?)", (feed,))
            if values:
                columns = ", ".join(f"{key} = ?" for key in values)
                db.execute(
                    f"UPDATE feeds SET {columns} WHERE feed = ?",  # noqa: S608 - fixed keys
                    (*values.values(), feed),
                )
            db.commit()

    # -- import
    def import_zip(
        self,
        feed: str,
        zip_path: Path,
        *,
        max_total_bytes: int,
        meta: dict[str, Any] | None = None,
    ) -> int:
        """Replace ``feed``'s rows with the records in ``zip_path``. Returns record count."""
        try:
            archive = zipfile.ZipFile(zip_path)
        except (zipfile.BadZipFile, OSError) as exc:
            raise FeedImportError("feed_invalid_zip") from exc
        records = 0
        total = 0
        with archive, self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                db.execute("DELETE FROM advisories WHERE feed = ?", (feed,))
                db.execute("DELETE FROM affected WHERE feed = ?", (feed,))
                advisories: list[tuple[Any, ...]] = []
                affected: list[tuple[Any, ...]] = []
                for info in archive.infolist():
                    if info.is_dir() or not info.filename.endswith(".json"):
                        continue
                    if info.file_size > MAX_MEMBER_BYTES:
                        continue
                    total += info.file_size
                    if total > max_total_bytes:
                        raise FeedImportError("feed_too_large")
                    with archive.open(info) as handle:
                        raw = handle.read(MAX_MEMBER_BYTES + 1)
                    if len(raw) > MAX_MEMBER_BYTES:
                        continue
                    try:
                        record = json.loads(raw)
                    except ValueError:
                        continue
                    rows = self._rows(feed, record)
                    if rows is None:
                        continue
                    advisory, entries = rows
                    advisories.append(advisory)
                    affected.extend(entries)
                    records += 1
                    if len(advisories) >= BATCH:
                        self._flush(db, advisories, affected)
                if advisories or affected:
                    self._flush(db, advisories, affected)
                values = {
                    "records": records,
                    "updated_at": time.time(),
                    "checked_at": time.time(),
                    "size": zip_path.stat().st_size,
                    "status": "ok",
                    "error": None,
                    **(meta or {}),
                }
                db.execute("INSERT OR IGNORE INTO feeds (feed) VALUES (?)", (feed,))
                columns = ", ".join(f"{key} = ?" for key in values)
                db.execute(
                    f"UPDATE feeds SET {columns} WHERE feed = ?",  # noqa: S608 - fixed keys
                    (*values.values(), feed),
                )
                db.commit()
            except BaseException:
                db.rollback()
                raise
        return records

    @staticmethod
    def _flush(
        db: sqlite3.Connection, advisories: list[tuple[Any, ...]], affected: list[tuple[Any, ...]]
    ) -> None:
        db.executemany(
            "INSERT OR REPLACE INTO advisories (feed, id, summary, severity, score, aliases, "
            "modified) VALUES (?, ?, ?, ?, ?, ?, ?)",
            advisories,
        )
        db.executemany(
            "INSERT INTO affected (feed, id, ecosystem, name, data) VALUES (?, ?, ?, ?, ?)",
            affected,
        )
        advisories.clear()
        affected.clear()

    @staticmethod
    def _rows(
        feed: str, record: Any
    ) -> tuple[tuple[Any, ...], list[tuple[Any, ...]]] | None:
        if not isinstance(record, dict) or record.get("withdrawn"):
            return None
        advisory_id = record.get("id")
        if not isinstance(advisory_id, str) or not advisory_id or len(advisory_id) > 128:
            return None
        entries: list[tuple[Any, ...]] = []
        for item in record.get("affected") or []:
            if not isinstance(item, dict) or not isinstance(item.get("package"), dict):
                continue
            ecosystem = item["package"].get("ecosystem")
            name = item["package"].get("name")
            if not isinstance(ecosystem, str) or not isinstance(name, str) or not name:
                continue
            if feed_for(ecosystem) != feed:
                continue
            ranges = [
                {"type": r.get("type"), "events": r.get("events")}
                for r in item.get("ranges") or []
                if isinstance(r, dict) and r.get("type") in {"ECOSYSTEM", "SEMVER"}
            ]
            versions = [v for v in item.get("versions") or [] if isinstance(v, str)]
            if not ranges and not versions:
                continue
            data = zlib.compress(
                json.dumps({"ranges": ranges, "versions": versions}, separators=(",", ":"))
                .encode("utf-8")
            )
            key = normalize_pypi(name) if feed == "PyPI" else name
            entries.append((feed, advisory_id, ecosystem, key, data))
        if not entries:
            return None
        severity, score = record_severity(record)
        aliases = sorted(
            {a for a in [*(record.get("aliases") or []), *(record.get("upstream") or [])]
             if isinstance(a, str) and len(a) <= 64}
        )[:20]
        summary = record.get("summary") or record.get("details") or ""
        summary = re.sub(r"\s+", " ", str(summary)).strip()[:MAX_SUMMARY]
        return (
            (feed, advisory_id, summary, severity, score, json.dumps(aliases),
             str(record.get("modified") or "")[:40]),
            entries,
        )

    # -- lookup
    def lookup(self, ecosystem: str, names: list[str]) -> dict[str, list[Match]]:
        """Advisories per package name for one ecosystem."""
        result: dict[str, list[Match]] = {}
        if not names:
            return result
        with self.connect() as db:
            for start in range(0, len(names), 400):
                chunk = names[start : start + 400]
                marks = ",".join("?" for _ in chunk)
                sql = (
                    "SELECT a.name, a.id, a.data, v.summary, v.severity, v.score, v.aliases "
                    "FROM affected a JOIN advisories v ON v.feed = a.feed AND v.id = a.id "
                    "WHERE a.ecosystem = ? AND a.name IN (" + marks + ")"  # noqa: S608
                )
                rows = db.execute(
                    sql,
                    (ecosystem, *chunk),
                ).fetchall()
                for name, advisory_id, data, summary, severity, score, aliases in rows:
                    try:
                        entry = json.loads(zlib.decompress(data))
                        alias_list = json.loads(aliases or "[]")
                    except (zlib.error, ValueError):
                        continue
                    result.setdefault(name, []).append(
                        Match(advisory_id, entry, summary or "", severity or "unknown", score,
                              alias_list)
                    )
        return result

    def has_feed(self, feed: str) -> bool:
        info = self.feeds().get(feed)
        return bool(info and info.get("updated_at"))


def temp_download_path(directory: Path) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    handle, name = tempfile.mkstemp(prefix=".feed-", suffix=".zip", dir=directory)
    os.close(handle)
    return Path(name)
