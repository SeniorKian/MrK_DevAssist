"""Database access for the monitoring module (sync; call via asyncio.to_thread).

Every function opens one short session and never performs network I/O, so the
single PGlite connection is held only for the write or read itself.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import delete, func, insert, select

from ..database import Database
from ..models import MetricHour, MetricMinute
from .monitoring_math import METRIC_FIELDS, rollup_rows

MetricModel = type[MetricMinute] | type[MetricHour]
ROW_FIELDS = ("kind", "scope", "ts", "samples", "protected", *METRIC_FIELDS)
MAX_ROLLUP_HOURS = 48


def _as_dict(row: Any) -> dict[str, Any]:
    return {name: getattr(row, name) for name in ROW_FIELDS}


def insert_rows(database: Database, model: MetricModel, rows: list[dict[str, Any]]) -> int:
    """Insert one batch (a single executemany statement)."""
    if not rows:
        return 0
    clean = [{name: row.get(name) for name in ROW_FIELDS} for row in rows]
    with database.session() as db, db.begin():
        db.execute(insert(model), clean)
    return len(clean)


def rollup_hour(database: Database, hour_ts: int) -> int:
    """(Re)build the hour rows for [hour_ts, hour_ts + 3600). Idempotent."""
    with database.session() as db, db.begin():
        minutes = db.scalars(
            select(MetricMinute).where(
                MetricMinute.ts >= hour_ts, MetricMinute.ts < hour_ts + 3600
            )
        ).all()
        rows = rollup_rows((_as_dict(row) for row in minutes), hour_ts)
        db.execute(delete(MetricHour).where(MetricHour.ts == hour_ts))
        if rows:
            db.execute(insert(MetricHour), rows)
    return len(rows)


def rollup_pending(database: Database, now: float, max_hours: int = MAX_ROLLUP_HOURS) -> list[int]:
    """Roll up every complete hour after the newest hour row (bounded lookback)."""
    current_hour = int(now // 3600) * 3600
    with database.session() as db:
        last_hour = db.scalar(select(func.max(MetricHour.ts)))
        first_minute = db.scalar(
            select(func.min(MetricMinute.ts)).where(
                MetricMinute.ts >= current_hour - max_hours * 3600
            )
        )
    if first_minute is None:
        return []
    start = int(first_minute // 3600) * 3600
    if last_hour is not None:
        start = max(start, int(last_hour) + 3600)
    done: list[int] = []
    for hour_ts in range(start, current_hour, 3600):
        if rollup_hour(database, hour_ts):
            done.append(hour_ts)
    return done


def prune(
    database: Database, now: float, minute_retention_days: int, hour_retention_days: int
) -> tuple[int, int]:
    with database.session() as db, db.begin():
        minutes = db.execute(
            delete(MetricMinute).where(MetricMinute.ts < now - minute_retention_days * 86400)
        ).rowcount
        hours = db.execute(
            delete(MetricHour).where(MetricHour.ts < now - hour_retention_days * 86400)
        ).rowcount
    return int(minutes or 0), int(hours or 0)


def series(
    database: Database,
    model: MetricModel,
    kind: str,
    since: float,
    scopes: list[str] | None = None,
) -> list[dict[str, Any]]:
    statement = select(model).where(model.kind == kind, model.ts >= since)
    if scopes is not None:
        statement = statement.where(model.scope.in_(scopes))
    with database.session() as db:
        rows = db.scalars(statement.order_by(model.ts, model.scope)).all()
        return [_as_dict(row) for row in rows]


def latest_containers(database: Database, since: float) -> list[dict[str, Any]]:
    """Container rows of the newest stored minute (within the lookback)."""
    with database.session() as db:
        newest = db.scalar(
            select(func.max(MetricMinute.ts)).where(
                MetricMinute.kind == "container", MetricMinute.ts >= since
            )
        )
        if newest is None:
            return []
        rows = db.scalars(
            select(MetricMinute).where(
                MetricMinute.kind == "container", MetricMinute.ts == newest
            )
        ).all()
        return [_as_dict(row) for row in rows]
