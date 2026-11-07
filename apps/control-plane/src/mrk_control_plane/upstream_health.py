from __future__ import annotations

import time

from sqlalchemy import delete, select

from .database import Database
from .models import UpstreamHealthCheck


class UpstreamHealthStore:
    def __init__(self, database: Database, retention_per_upstream: int = 500) -> None:
        self.database = database
        self.retention_per_upstream = retention_per_upstream

    @staticmethod
    def _serialize(item: UpstreamHealthCheck) -> dict[str, object]:
        return {
            "id": item.id,
            "upstream_id": item.upstream_id,
            "ecosystem": item.ecosystem,
            "upstream_name": item.upstream_name,
            "ok": item.ok,
            "stages": item.stages,
            "total_latency_ms": item.total_latency_ms,
            "checked_at": item.checked_at,
        }

    def record(
        self,
        upstream_id: str,
        ecosystem: str,
        upstream_name: str,
        result: dict[str, object],
        actor_user_id: int,
    ) -> dict[str, object]:
        stages = result.get("stages")
        if not isinstance(stages, list):
            raise ValueError("probe result is missing stage data")
        safe_stages = [dict(stage) for stage in stages if isinstance(stage, dict)]
        total_latency_ms = round(
            sum(float(stage.get("latency_ms", 0)) for stage in safe_stages)
        )
        with self.database.session_factory.begin() as db:
            item = UpstreamHealthCheck(
                upstream_id=upstream_id,
                ecosystem=ecosystem,
                upstream_name=upstream_name,
                ok=bool(result.get("ok")),
                stages=safe_stages,
                total_latency_ms=total_latency_ms,
                actor_user_id=actor_user_id,
                checked_at=int(time.time()),
            )
            db.add(item)
            db.flush()
            stale_ids = list(
                db.scalars(
                    select(UpstreamHealthCheck.id)
                    .where(UpstreamHealthCheck.upstream_id == upstream_id)
                    .order_by(UpstreamHealthCheck.id.desc())
                    .offset(self.retention_per_upstream)
                )
            )
            if stale_ids:
                db.execute(
                    delete(UpstreamHealthCheck).where(
                        UpstreamHealthCheck.id.in_(stale_ids)
                    )
                )
            return self._serialize(item)

    def list(self, upstream_id: str, limit: int = 100) -> list[dict[str, object]]:
        bounded_limit = min(max(limit, 1), 500)
        with self.database.session_factory() as db:
            items = db.scalars(
                select(UpstreamHealthCheck)
                .where(UpstreamHealthCheck.upstream_id == upstream_id)
                .order_by(UpstreamHealthCheck.checked_at.desc(), UpstreamHealthCheck.id.desc())
                .limit(bounded_limit)
            ).all()
            return [self._serialize(item) for item in items]
