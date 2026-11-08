"""Database access for the firewall module: rules, blocks and decision history."""

from __future__ import annotations

import secrets
import time
from typing import Any

from sqlalchemy import delete, func, or_, select

from ..database import Database
from ..firewall.addresses import AddressError, IPAddress, contains, parse_ip, parse_network
from ..models import AuditEvent, FirewallBlock, FirewallDecision, FirewallRule
from .firewall_engine import BUILTIN_RULES, FirewallError, RuleSpec

DECISION_ACTIONS = (
    "block", "would_block", "skipped", "manual_block", "unblock", "expire", "clear", "mode",
)
MAX_REASON = 500


def _now() -> int:
    return int(time.time())


def rule_public(row: FirewallRule) -> dict[str, Any]:
    return {
        "id": row.id, "name": row.name, "signal_kinds": list(row.signal_kinds or []),
        "threshold": row.threshold, "window_seconds": row.window_seconds,
        "ban_seconds": row.ban_seconds, "enabled": row.enabled, "builtin": row.builtin,
        "created_at": row.created_at, "updated_at": row.updated_at,
    }


def block_public(row: FirewallBlock) -> dict[str, Any]:
    return {
        "id": row.id, "cidr": row.cidr, "origin": row.origin, "rule_id": row.rule_id,
        "reason": row.reason, "simulated": row.simulated,
        "created_by_user_id": row.created_by_user_id, "created_at": row.created_at,
        "expires_at": row.expires_at, "removed_at": row.removed_at,
        "removed_reason": row.removed_reason,
    }


def decision_public(row: FirewallDecision) -> dict[str, Any]:
    return {
        "id": row.id, "occurred_at": row.occurred_at, "action": row.action, "ip": row.ip,
        "rule_id": row.rule_id, "mode": row.mode, "reason": row.reason,
        "actor_user_id": row.actor_user_id, "details": row.details or {},
    }


def _active(now: int):
    return (FirewallBlock.removed_at.is_(None),
            or_(FirewallBlock.expires_at.is_(None), FirewallBlock.expires_at > now))


class FirewallStore:
    def __init__(self, database: Database) -> None:
        self.db = database

    # ----- rules ---------------------------------------------------------------
    def seed_rules(self) -> None:
        now = _now()
        with self.db.session() as db, db.begin():
            existing = set(db.scalars(select(FirewallRule.id)).all())
            names = set(db.scalars(select(FirewallRule.name)).all())
            for spec in BUILTIN_RULES:
                if spec["id"] in existing or spec["name"] in names:
                    continue
                db.add(FirewallRule(**spec, enabled=True, builtin=True, created_at=now,
                                    updated_at=now))

    def list_rules(self) -> list[dict[str, Any]]:
        with self.db.session() as db:
            rows = db.scalars(select(FirewallRule).order_by(FirewallRule.builtin.desc(),
                                                            FirewallRule.name)).all()
            return [rule_public(row) for row in rows]

    def rule_specs(self) -> list[RuleSpec]:
        return [
            RuleSpec(item["id"], item["name"], frozenset(item["signal_kinds"]),
                     item["threshold"], item["window_seconds"], item["ban_seconds"])
            for item in self.list_rules() if item["enabled"]
        ]

    def create_rule(self, values: dict[str, Any], default_ban: int) -> dict[str, Any]:
        now = _now()
        with self.db.session() as db, db.begin():
            if db.scalar(select(FirewallRule.id).where(FirewallRule.name == values["name"])):
                raise FirewallError("rule_name_taken", "a rule with this name exists", 409)
            row = FirewallRule(
                id=secrets.token_hex(8), name=values["name"],
                signal_kinds=values["signal_kinds"], threshold=values["threshold"],
                window_seconds=values["window_seconds"],
                ban_seconds=values.get("ban_seconds", default_ban),
                enabled=values.get("enabled", True), builtin=False, created_at=now,
                updated_at=now,
            )
            db.add(row)
            db.flush()
            return rule_public(row)

    def update_rule(self, rule_id: str, values: dict[str, Any]) -> dict[str, Any]:
        with self.db.session() as db, db.begin():
            row = db.get(FirewallRule, rule_id)
            if row is None:
                raise KeyError(rule_id)
            if "name" in values and values["name"] != row.name and db.scalar(
                select(FirewallRule.id).where(FirewallRule.name == values["name"])
            ):
                raise FirewallError("rule_name_taken", "a rule with this name exists", 409)
            for key, value in values.items():
                setattr(row, key, value)
            row.updated_at = _now()
            db.flush()
            return rule_public(row)

    def delete_rule(self, rule_id: str) -> None:
        with self.db.session() as db, db.begin():
            row = db.get(FirewallRule, rule_id)
            if row is None:
                raise KeyError(rule_id)
            if row.builtin:
                raise FirewallError("builtin_rule", "built-in rules can be disabled, not deleted",
                                    409)
            db.delete(row)

    # ----- blocks --------------------------------------------------------------
    def active_blocks(self, now: int | None = None, *, include_simulated: bool = True
                      ) -> list[dict[str, Any]]:
        stamp = _now() if now is None else now
        with self.db.session() as db:
            query = select(FirewallBlock).where(*_active(stamp))
            if not include_simulated:
                query = query.where(FirewallBlock.simulated.is_(False))
            rows = db.scalars(query.order_by(FirewallBlock.created_at.desc())).all()
            return [block_public(row) for row in rows]

    def count_active(self, now: int | None = None) -> dict[str, int]:
        stamp = _now() if now is None else now
        with self.db.session() as db:
            rows = db.execute(
                select(FirewallBlock.simulated, func.count()).where(*_active(stamp))
                .group_by(FirewallBlock.simulated)
            ).all()
        counts = {"enforced": 0, "simulated": 0}
        for simulated, number in rows:
            counts["simulated" if simulated else "enforced"] += int(number)
        return counts

    def covering_block(self, target: IPAddress, now: int | None = None
                       ) -> dict[str, Any] | None:
        for item in self.active_blocks(now):
            try:
                if contains(parse_network(item["cidr"]), target):
                    return item
            except AddressError:
                continue
        return None

    def add_block(self, *, cidr: str, origin: str, reason: str, simulated: bool,
                  expires_at: int | None, rule_id: str | None = None,
                  user_id: int | None = None) -> dict[str, Any]:
        with self.db.session() as db, db.begin():
            row = FirewallBlock(
                id=secrets.token_hex(8), cidr=cidr, origin=origin, rule_id=rule_id,
                reason=reason[:MAX_REASON], simulated=simulated, created_by_user_id=user_id,
                created_at=_now(), expires_at=expires_at,
            )
            db.add(row)
            db.flush()
            return block_public(row)

    def remove_block(self, block_id: str, reason: str) -> dict[str, Any]:
        now = _now()
        with self.db.session() as db, db.begin():
            row = db.get(FirewallBlock, block_id)
            if row is None or row.removed_at is not None or (
                row.expires_at is not None and row.expires_at <= now
            ):
                raise KeyError(block_id)
            row.removed_at = now
            row.removed_reason = reason
            db.flush()
            return block_public(row)

    def remove_all(self, reason: str) -> list[dict[str, Any]]:
        now = _now()
        with self.db.session() as db, db.begin():
            rows = db.scalars(select(FirewallBlock).where(*_active(now))).all()
            for row in rows:
                row.removed_at = now
                row.removed_reason = reason
            db.flush()
            return [block_public(row) for row in rows]

    def expire(self, now: int | None = None) -> list[dict[str, Any]]:
        stamp = _now() if now is None else now
        with self.db.session() as db, db.begin():
            rows = db.scalars(select(FirewallBlock).where(
                FirewallBlock.removed_at.is_(None), FirewallBlock.expires_at.is_not(None),
                FirewallBlock.expires_at <= stamp,
            )).all()
            for row in rows:
                row.removed_at = stamp
                row.removed_reason = "expired"
            db.flush()
            return [block_public(row) for row in rows]

    # ----- decisions -----------------------------------------------------------
    def record(self, action: str, *, mode: str, ip: str | None = None,
               rule_id: str | None = None, reason: str = "", user_id: int | None = None,
               details: dict[str, Any] | None = None) -> None:
        with self.db.session() as db, db.begin():
            db.add(FirewallDecision(
                occurred_at=_now(), action=action, ip=ip, rule_id=rule_id, mode=mode,
                reason=reason[:MAX_REASON], actor_user_id=user_id, details=details or {},
            ))

    def list_decisions(self, *, ip: str | None = None, action: str | None = None,
                       since: int | None = None, before_id: int | None = None,
                       limit: int = 100) -> list[dict[str, Any]]:
        with self.db.session() as db:
            query = select(FirewallDecision)
            if ip:
                query = query.where(FirewallDecision.ip == ip)
            if action:
                query = query.where(FirewallDecision.action == action)
            if since is not None:
                query = query.where(FirewallDecision.occurred_at >= since)
            if before_id is not None:
                query = query.where(FirewallDecision.id < before_id)
            rows = db.scalars(query.order_by(FirewallDecision.id.desc()).limit(limit)).all()
            return [decision_public(row) for row in rows]

    def count_decisions_since(self, since: int) -> int:
        with self.db.session() as db:
            return int(db.scalar(select(func.count()).select_from(FirewallDecision).where(
                FirewallDecision.occurred_at >= since)) or 0)

    def prune(self, retention_days: int, now: int | None = None) -> int:
        cutoff = (_now() if now is None else now) - retention_days * 86400
        with self.db.session() as db, db.begin():
            result = db.execute(delete(FirewallDecision).where(
                FirewallDecision.occurred_at < cutoff))
            db.execute(delete(FirewallBlock).where(FirewallBlock.removed_at.is_not(None),
                                                   FirewallBlock.removed_at < cutoff))
            return int(result.rowcount or 0)

    # ----- MRK login failures (consumed from this control plane's audit log) ---
    def last_audit_id(self) -> int:
        with self.db.session() as db:
            return int(db.scalar(select(func.max(AuditEvent.id))) or 0)

    def login_failures_after(self, audit_id: int, limit: int = 5000
                             ) -> tuple[int, list[dict[str, Any]]]:
        with self.db.session() as db:
            rows = db.execute(
                select(AuditEvent.id, AuditEvent.source_ip, AuditEvent.occurred_at,
                       AuditEvent.result)
                .where(AuditEvent.id > audit_id, AuditEvent.action == "auth.login",
                       AuditEvent.result.in_(("failure", "rate_limited")))
                .order_by(AuditEvent.id).limit(limit)
            ).all()
            newest = int(db.scalar(select(func.max(AuditEvent.id))) or audit_id)
        signals = []
        for row in rows:
            address = parse_ip(row.source_ip)
            if address is not None:
                signals.append({"source": "mrk", "kind": "mrk_login_failure",
                                "ip": str(address), "ts": float(row.occurred_at),
                                "detail": row.result})
        last = int(rows[-1].id) if len(rows) == limit else newest
        return last, signals
