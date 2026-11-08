"""Scan results, inventory cache and notification dedupe for the vulnerability scanner.

Lives in ``data_dir/modules/vuln/results.sqlite`` (re-derivable by rescanning, so
it stays off PGlite and out of backups). User decisions — ignore rules — are in
the control-plane database (``vuln_ignores``, migration 20261108_0008) so they are
backed up and restored with everything else.
"""

from __future__ import annotations

import contextlib
import fnmatch
import json
import sqlite3
import threading
import time
import zlib
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .vuln_osv import SEVERITIES, SEVERITY_RANK

_SCHEMA = """
CREATE TABLE IF NOT EXISTS images (
    image_id TEXT PRIMARY KEY, payload TEXT NOT NULL, inventory BLOB, inventory_at REAL,
    present INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS findings (
    image_id TEXT NOT NULL, advisory_id TEXT NOT NULL, package TEXT NOT NULL,
    installed TEXT NOT NULL, fixed TEXT, severity TEXT NOT NULL, score REAL, summary TEXT,
    ecosystem TEXT, aliases TEXT, binaries TEXT, location TEXT, first_seen REAL,
    PRIMARY KEY (image_id, advisory_id, package, installed)
);
CREATE INDEX IF NOT EXISTS findings_image ON findings (image_id);
CREATE TABLE IF NOT EXISTS notified (
    image_id TEXT NOT NULL, advisory_id TEXT NOT NULL, notified_at REAL NOT NULL,
    PRIMARY KEY (image_id, advisory_id)
);
"""
_FINDING_COLUMNS = (
    "advisory_id", "package", "installed", "fixed", "severity", "score", "summary",
    "ecosystem", "aliases", "binaries", "location", "first_seen",
)


@dataclass(frozen=True, slots=True)
class IgnoreRule:
    id: str
    advisory: str | None
    package: str | None
    image: str | None
    reason: str
    expires_at: int | None

    def active(self, now: float) -> bool:
        return self.expires_at is None or self.expires_at > now

    def matches(self, finding: dict[str, Any], image: str | None) -> bool:
        if self.advisory is not None:
            names = [finding["id"], *finding.get("aliases", [])]
            if not any(fnmatch.fnmatchcase(name, self.advisory) for name in names):
                return False
        if self.package is not None:
            names = [finding["package"], *finding.get("binaries", [])]
            if not any(fnmatch.fnmatchcase(name, self.package) for name in names):
                return False
        if self.image is not None and not fnmatch.fnmatchcase(image or "", self.image):
            return False
        return True


def first_match(
    rules: list[IgnoreRule], finding: dict[str, Any], image: str | None
) -> IgnoreRule | None:
    for rule in rules:
        if rule.matches(finding, image):
            return rule
    return None


def empty_counts() -> dict[str, int]:
    return dict.fromkeys(SEVERITIES, 0)


def sort_findings(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(
        items,
        key=lambda f: (-SEVERITY_RANK.get(f["severity"], 0), -(f.get("score") or 0), f["id"],
                       f["package"]),
    )


class ResultStore:
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

    # ----- inventory cache
    def cached_inventory(self, image_id: str) -> tuple[dict[str, Any], float] | None:
        with self.connect() as db:
            row = db.execute(
                "SELECT inventory, inventory_at FROM images WHERE image_id = ?", (image_id,)
            ).fetchone()
        if not row or row[0] is None:
            return None
        try:
            return json.loads(zlib.decompress(row[0])), float(row[1] or 0)
        except (zlib.error, ValueError):
            return None

    # ----- write one scan
    def save_scan(
        self,
        images: list[tuple[dict[str, Any], dict[str, Any] | None, float | None]],
        findings: dict[str, list[dict[str, Any]]],
        now: float,
    ) -> None:
        """Replace results. ``images``: (payload, inventory or None, inventory_at)."""
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                first_seen = {
                    (row[0], row[1], row[2], row[3]): row[4]
                    for row in db.execute(
                        "SELECT image_id, advisory_id, package, installed, first_seen "
                        "FROM findings"
                    )
                }
                db.execute("UPDATE images SET present = 0")
                db.execute("DELETE FROM findings")
                for payload, inventory, inventory_at in images:
                    image_id = payload["image_id"]
                    blob = (
                        zlib.compress(json.dumps(inventory, separators=(",", ":")).encode())
                        if inventory is not None
                        else None
                    )
                    db.execute(
                        "INSERT INTO images (image_id, payload, inventory, inventory_at, present) "
                        "VALUES (?, ?, ?, ?, 1) ON CONFLICT(image_id) DO UPDATE SET "
                        "payload = excluded.payload, present = 1, "
                        "inventory = COALESCE(excluded.inventory, images.inventory), "
                        "inventory_at = COALESCE(excluded.inventory_at, images.inventory_at)",
                        (image_id, json.dumps(payload), blob, inventory_at),
                    )
                    rows = []
                    for item in findings.get(image_id, []):
                        key = (image_id, item["id"], item["package"], item["installed"])
                        rows.append(
                            (
                                image_id, item["id"], item["package"], item["installed"],
                                item.get("fixed"), item["severity"], item.get("score"),
                                item.get("summary"), item.get("ecosystem"),
                                json.dumps(item.get("aliases", [])),
                                json.dumps(item.get("binaries", [])), item.get("location"),
                                first_seen.get(key, now),
                            )
                        )
                    db.executemany(
                        "INSERT OR IGNORE INTO findings (image_id, advisory_id, package, "
                        "installed, fixed, severity, score, summary, ecosystem, aliases, "
                        "binaries, location, first_seen) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        rows,
                    )
                # Images that no longer run: forget them (and their dedupe state).
                db.execute(
                    "DELETE FROM notified WHERE image_id IN "
                    "(SELECT image_id FROM images WHERE present = 0)"
                )
                db.execute("DELETE FROM images WHERE present = 0")
                db.commit()
            except BaseException:
                db.rollback()
                raise

    # ----- reads
    def images(self) -> list[dict[str, Any]]:
        with self.connect() as db:
            rows = db.execute("SELECT payload FROM images ORDER BY image_id").fetchall()
        return [json.loads(row[0]) for row in rows]

    def image(self, image_id: str) -> dict[str, Any] | None:
        with self.connect() as db:
            row = db.execute(
                "SELECT payload FROM images WHERE image_id = ?", (image_id,)
            ).fetchone()
        return json.loads(row[0]) if row else None

    def findings(self, image_id: str | None = None) -> dict[str, list[dict[str, Any]]]:
        query = f"SELECT image_id, {', '.join(_FINDING_COLUMNS)} FROM findings"  # noqa: S608
        args: tuple[Any, ...] = ()
        if image_id is not None:
            query += " WHERE image_id = ?"
            args = (image_id,)
        result: dict[str, list[dict[str, Any]]] = {}
        with self.connect() as db:
            for row in db.execute(query, args):
                values = dict(zip(_FINDING_COLUMNS, row[1:], strict=True))
                result.setdefault(row[0], []).append(
                    {
                        "id": values["advisory_id"],
                        "aliases": json.loads(values["aliases"] or "[]"),
                        "package": values["package"],
                        "binaries": json.loads(values["binaries"] or "[]"),
                        "installed": values["installed"],
                        "fixed": values["fixed"],
                        "severity": values["severity"],
                        "score": values["score"],
                        "summary": values["summary"] or "",
                        "ecosystem": values["ecosystem"],
                        "location": values["location"],
                        "first_seen": values["first_seen"],
                    }
                )
        return result

    # ----- notification dedupe
    def notified(self) -> set[tuple[str, str]]:
        with self.connect() as db:
            return {
                (row[0], row[1])
                for row in db.execute("SELECT image_id, advisory_id FROM notified")
            }

    def mark_notified(self, pairs: list[tuple[str, str]], now: float | None = None) -> None:
        if not pairs:
            return
        stamp = time.time() if now is None else now
        with self.connect() as db:
            db.executemany(
                "INSERT OR IGNORE INTO notified (image_id, advisory_id, notified_at) "
                "VALUES (?, ?, ?)",
                [(image, advisory, stamp) for image, advisory in pairs],
            )
            db.commit()
