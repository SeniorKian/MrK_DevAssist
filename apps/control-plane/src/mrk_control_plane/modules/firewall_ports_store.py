"""Database access for the port policy draft: port rules and named source lists (docs/45)."""

from __future__ import annotations

import secrets
import time
from typing import Any

from sqlalchemy import select

from ..database import Database
from ..models import FirewallPortRule, FirewallSourceList
from .firewall_engine import FirewallError
from .firewall_ports import MAX_LISTS, MAX_RULES


def _now() -> int:
    return int(time.time())


def port_rule_public(row: FirewallPortRule) -> dict[str, Any]:
    source: dict[str, Any] = {"kind": row.source_kind}
    if row.source_kind == "cidrs":
        source["cidrs"] = list(row.source_cidrs or [])
    elif row.source_kind == "list":
        source["list_id"] = row.source_list_id
    return {
        "id": row.id, "name": row.name, "description": row.description,
        "protocol": row.protocol, "ports": list(row.ports or []), "source": source,
        "scope": row.scope, "action": row.action, "enabled": row.enabled,
        "priority": row.priority, "log": row.log, "log_rate": row.log_rate,
        "origin": row.origin, "created_by_user_id": row.created_by_user_id,
        "created_at": row.created_at, "updated_at": row.updated_at,
    }


def source_list_public(row: FirewallSourceList) -> dict[str, Any]:
    return {"id": row.id, "name": row.name, "note": row.note, "cidrs": list(row.cidrs or []),
            "created_at": row.created_at, "updated_at": row.updated_at}


_COLUMNS = ("name", "description", "protocol", "ports", "source_kind", "source_cidrs",
            "source_list_id", "scope", "action", "enabled", "priority", "log", "log_rate")


class PortStore:
    def __init__(self, database: Database) -> None:
        self.db = database

    # ----- rules -----------------------------------------------------------------
    def list_rules(self) -> list[dict[str, Any]]:
        with self.db.session() as db:
            rows = db.scalars(select(FirewallPortRule).order_by(
                FirewallPortRule.priority, FirewallPortRule.created_at, FirewallPortRule.id)).all()
            return [port_rule_public(row) for row in rows]

    def _check_list(self, db: Any, values: dict[str, Any]) -> None:
        list_id = values.get("source_list_id")
        if list_id is not None and db.get(FirewallSourceList, list_id) is None:
            raise FirewallError("source_list_not_found", "the named address list does not exist")

    def create_rule(self, values: dict[str, Any], *, origin: str = "manual",
                    user_id: int | None = None, unique_name: bool = False) -> dict[str, Any]:
        now = _now()
        with self.db.session() as db, db.begin():
            count = len(db.scalars(select(FirewallPortRule.id)).all())
            if count >= MAX_RULES:
                raise FirewallError("too_many_port_rules", f"at most {MAX_RULES} port rules",
                                    409)
            name = values["name"]
            taken = set(db.scalars(select(FirewallPortRule.name)).all())
            if name in taken:
                if not unique_name:
                    raise FirewallError("port_rule_name_taken",
                                        "a port rule with this name exists", 409)
                base, index = name[:74], 2
                while f"{base} ({index})" in taken:
                    index += 1
                name = f"{base} ({index})"
            self._check_list(db, values)
            if "priority" not in values:
                last = db.scalar(select(FirewallPortRule.priority).order_by(
                    FirewallPortRule.priority.desc()).limit(1))
                values = {**values, "priority": (last or 0) + 10}
            row = FirewallPortRule(
                id=secrets.token_hex(8), name=name,
                description=values.get("description", ""), protocol=values["protocol"],
                ports=values["ports"], source_kind=values.get("source_kind", "public"),
                source_cidrs=values.get("source_cidrs", []),
                source_list_id=values.get("source_list_id"), scope=values["scope"],
                action=values.get("action", "accept"), enabled=values.get("enabled", True),
                priority=values["priority"], log=values.get("log", False),
                log_rate=values.get("log_rate", 10), origin=origin,
                created_by_user_id=user_id, created_at=now, updated_at=now,
            )
            db.add(row)
            db.flush()
            return port_rule_public(row)

    def update_rule(self, rule_id: str, values: dict[str, Any]) -> dict[str, Any]:
        with self.db.session() as db, db.begin():
            row = db.get(FirewallPortRule, rule_id)
            if row is None:
                raise KeyError(rule_id)
            if "name" in values and values["name"] != row.name and db.scalar(
                select(FirewallPortRule.id).where(FirewallPortRule.name == values["name"])
            ):
                raise FirewallError("port_rule_name_taken", "a port rule with this name exists",
                                    409)
            self._check_list(db, values)
            for key in _COLUMNS:
                if key in values:
                    setattr(row, key, values[key])
            row.updated_at = _now()
            db.flush()
            return port_rule_public(row)

    def get_rule(self, rule_id: str) -> dict[str, Any]:
        with self.db.session() as db:
            row = db.get(FirewallPortRule, rule_id)
            if row is None:
                raise KeyError(rule_id)
            return port_rule_public(row)

    def delete_rule(self, rule_id: str) -> dict[str, Any]:
        with self.db.session() as db, db.begin():
            row = db.get(FirewallPortRule, rule_id)
            if row is None:
                raise KeyError(rule_id)
            item = port_rule_public(row)
            db.delete(row)
            return item

    # ----- named source lists ------------------------------------------------------
    def list_lists(self) -> list[dict[str, Any]]:
        with self.db.session() as db:
            rows = db.scalars(select(FirewallSourceList).order_by(FirewallSourceList.name)).all()
            return [source_list_public(row) for row in rows]

    def create_list(self, values: dict[str, Any]) -> dict[str, Any]:
        now = _now()
        with self.db.session() as db, db.begin():
            if len(db.scalars(select(FirewallSourceList.id)).all()) >= MAX_LISTS:
                raise FirewallError("too_many_source_lists", f"at most {MAX_LISTS} lists", 409)
            if db.scalar(select(FirewallSourceList.id).where(
                    FirewallSourceList.name == values["name"])):
                raise FirewallError("source_list_name_taken", "a list with this name exists",
                                    409)
            row = FirewallSourceList(id=secrets.token_hex(8), name=values["name"],
                                     note=values.get("note", ""), cidrs=values["cidrs"],
                                     created_at=now, updated_at=now)
            db.add(row)
            db.flush()
            return source_list_public(row)

    def update_list(self, list_id: str, values: dict[str, Any]) -> dict[str, Any]:
        with self.db.session() as db, db.begin():
            row = db.get(FirewallSourceList, list_id)
            if row is None:
                raise KeyError(list_id)
            if "name" in values and values["name"] != row.name and db.scalar(
                select(FirewallSourceList.id).where(FirewallSourceList.name == values["name"])
            ):
                raise FirewallError("source_list_name_taken", "a list with this name exists",
                                    409)
            for key in ("name", "note", "cidrs"):
                if key in values:
                    setattr(row, key, values[key])
            row.updated_at = _now()
            db.flush()
            return source_list_public(row)

    def delete_list(self, list_id: str) -> None:
        with self.db.session() as db, db.begin():
            row = db.get(FirewallSourceList, list_id)
            if row is None:
                raise KeyError(list_id)
            if db.scalar(select(FirewallPortRule.id).where(
                    FirewallPortRule.source_list_id == list_id).limit(1)):
                raise FirewallError("source_list_in_use", "port rules still use this list", 409)
            db.delete(row)
