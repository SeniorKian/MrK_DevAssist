"""«My space» service layer: workspaces, plans, ownership and isolation (docs/43).

Every ``/api/v1/my`` route goes through this module, never through its own checks:

* :meth:`TenancyStore.resolve` turns the signed-in principal (session, workspace API
  token or an admin's «view as» grant) into a :class:`WorkspaceContext` — the
  workspace, the caller's role in it and the effective ``my.*`` scopes.
* :meth:`WorkspaceContext.need` checks a scope (403), the suspended state (423) and a
  plan feature (403); :func:`check_quota` checks a numeric quota (409).
* :meth:`TenancyStore.owned` / :meth:`TenancyStore.require_owned` answer «does this
  workspace own that resource»; a foreign or unknown id is always 404 ``not_found``.
* :meth:`TenancyStore.claim` records ownership and counts the quota in one database
  transaction under a per-workspace lock, so two parallel creates cannot both pass.

Resource ids come only from the URL path; request bodies are never trusted to name a
resource. With ``tenancy.enabled`` off every ``/my`` route answers 404.
"""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import re
import secrets
import threading
import time
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any, Final

from sqlalchemy import delete, func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session as OrmSession

from .auth import MY_TOKEN_SCOPES, AuthStore, Principal
from .database import Database
from .models import (
    ApiToken,
    ImpersonationSession,
    ResourceOwner,
    SystemSetting,
    TenancyPlan,
    TenancySignup,
    User,
    Workspace,
    WorkspaceInvite,
    WorkspaceMember,
)

SETTINGS_KEY: Final = "tenancy.settings"
SIGNUP_MODES: Final = ("off", "approval", "open")
DEFAULT_SETTINGS: Final[dict[str, Any]] = {
    "enabled": False,
    "signup": "off",
    "default_plan_id": "basic",
    "verify_domains": True,
    "admin_area_local_only": False,
}
FEATURES: Final = (
    "dns", "dns_dnssec", "dns_templates", "s3", "s3_public_links", "s3_bucket_domains",
    "npm", "pypi", "teams", "api_tokens",
)
NUMERIC_QUOTAS: Final = (
    "workspaces_team", "members", "dns_zones", "dns_records_per_zone", "s3_buckets",
    "s3_bytes", "s3_objects", "s3_keys", "s3_bucket_domains", "npm_bytes", "pypi_bytes",
    "api_tokens",
)
QUOTA_KEYS: Final = (*NUMERIC_QUOTAS, "dns_record_types")
# Record types a plan may allow; SOA is managed by the engine, PTR only for reverse zones.
PLAN_RECORD_TYPES: Final = ("A", "AAAA", "CNAME", "MX", "TXT", "SRV", "NS", "PTR", "CAA")
RESOURCE_KINDS: Final = (
    "dns_zone", "s3_bucket", "s3_identity", "bucket_domain", "npm_scope", "pypi_index",
    "api_token",
)
ROLES: Final = ("viewer", "member", "admin", "owner")
RANK: Final[dict[str, int]] = {role: index for index, role in enumerate(ROLES, start=1)}
READ_SCOPES: Final = frozenset({"my.dns:read", "my.s3:read", "my.packages:read"})
WRITE_SCOPES: Final = frozenset({"my.dns:write", "my.s3:write", "my.packages:write"})
ROLE_SCOPES: Final[dict[str, frozenset[str]]] = {
    "viewer": READ_SCOPES,
    "member": READ_SCOPES | WRITE_SCOPES,
    "admin": READ_SCOPES | WRITE_SCOPES | {"my.workspace:admin"},
    "owner": READ_SCOPES | WRITE_SCOPES | {"my.workspace:admin", "my.workspace:owner"},
}
VIEW_AS_SECONDS: Final = 30 * 60
INVITE_SECONDS: Final = 7 * 86400
TOKEN_DEFAULT_SECONDS: Final = 90 * 86400
TOKEN_MIN_SECONDS: Final = 900
TOKEN_MAX_SECONDS: Final = 365 * 86400
MAX_IP_ALLOW: Final = 16
GIB: Final = 1024**3
_SLUG = re.compile(r"^[a-z0-9](?:[a-z0-9-]{1,30}[a-z0-9])$")
_PLAN_ID = re.compile(r"^[a-z0-9][a-z0-9_-]{1,31}$")
# Slugs become an npm scope, a devpi user/index and a bucket-name prefix.
RESERVED_SLUGS: Final = frozenset({
    "root", "admin", "administrator", "api", "www", "mrk", "pishkar", "system", "npm",
    "pypi", "s3", "dns", "panel", "my", "support", "help", "billing", "security", "types",
    "babel", "angular", "vue", "react", "nestjs", "aws-sdk", "google-cloud", "azure",
    "mail", "smtp", "ftp", "localhost", "internal", "public", "default", "dev", "test",
})


def _all(value: bool) -> dict[str, bool]:
    return dict.fromkeys(FEATURES, value)


BUILTIN_PLANS: Final[dict[str, dict[str, Any]]] = {
    "basic": {
        "name_fa": "پایه", "name_en": "Basic",
        "description": "دامنه و فضای فایل کوچک برای شروع.",
        "default": True,
        "features": {**_all(False), "dns": True, "dns_templates": True, "s3": True,
                     "api_tokens": True},
        "quotas": {
            "workspaces_team": 0, "members": 1, "dns_zones": 3, "dns_records_per_zone": 50,
            "dns_record_types": ["A", "AAAA", "CNAME", "MX", "TXT", "SRV", "CAA"],
            "s3_buckets": 2, "s3_bytes": 5 * GIB, "s3_objects": 50_000, "s3_keys": 4,
            "s3_bucket_domains": 0, "npm_bytes": 0, "pypi_bytes": 0, "api_tokens": 5,
        },
    },
    "pro": {
        "name_fa": "حرفه‌ای", "name_en": "Pro",
        "description": "همه امکانات با سقف‌های بیشتر و فضای تیمی.",
        "default": False,
        "features": _all(True),
        "quotas": {
            "workspaces_team": 3, "members": 10, "dns_zones": 20, "dns_records_per_zone": 500,
            "dns_record_types": ["A", "AAAA", "CNAME", "MX", "TXT", "SRV", "NS", "CAA"],
            "s3_buckets": 10, "s3_bytes": 100 * GIB, "s3_objects": 1_000_000, "s3_keys": 20,
            "s3_bucket_domains": 5, "npm_bytes": 5 * GIB, "pypi_bytes": 5 * GIB,
            "api_tokens": 20,
        },
    },
    "unlimited": {
        "name_fa": "بدون محدودیت", "name_en": "Unlimited",
        "description": "همه امکانات بدون سقف.",
        "default": False,
        "features": _all(True),
        "quotas": {**dict.fromkeys(NUMERIC_QUOTAS), "dns_record_types": list(PLAN_RECORD_TYPES)},
    },
}


class TenancyError(Exception):
    """A «my space» failure with a stable code (rendered by the module's ``fail``)."""

    def __init__(
        self,
        code: str,
        status_code: int,
        message: str,
        *,
        fields: list[dict[str, Any]] | None = None,
        **extra: Any,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.status_code = status_code
        self.message = message
        self.fields = fields
        self.extra = extra


def not_found() -> TenancyError:
    return TenancyError("not_found", 404, "Not found")


def _invalid(field_name: str, reason: str, message: str, **params: Any) -> TenancyError:
    entry: dict[str, Any] = {"field": field_name, "reason_code": reason}
    if params:
        entry["params"] = params
    return TenancyError("invalid_request", 422, message, fields=[entry])


def _now() -> int:
    return int(time.time())


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def check_quota(limits: dict[str, Any], name: str, used: int, adding: int = 1) -> None:
    """Raise ``quota_exceeded`` (409) when ``used + adding`` passes the limit."""
    limit = limits["quotas"].get(name)
    if limit is not None and used + adding > int(limit):
        raise TenancyError(
            "quota_exceeded", 409, f"The {name} limit of your plan is reached",
            quota=name, limit=int(limit), used=int(used),
        )


def effective_limits(plan: dict[str, Any] | None, overrides: dict[str, Any] | None
                     ) -> dict[str, Any]:
    """Plan features + quotas with the workspace's ``quota_overrides`` on top."""
    plan = plan or {"features": {}, "quotas": {}}
    features = {name: bool((plan.get("features") or {}).get(name)) for name in FEATURES}
    stored = dict(plan.get("quotas") or {})
    quotas: dict[str, Any] = {name: stored.get(name, 0) for name in NUMERIC_QUOTAS}
    quotas["dns_record_types"] = list(stored.get("dns_record_types") or [])
    for key, value in (overrides or {}).items():
        if key in QUOTA_KEYS:
            quotas[key] = value
    return {"features": features, "quotas": quotas}


def names_overlap(first: str, second: str) -> bool:
    """True when the names are equal or one is inside the other (``a.b`` / ``b``)."""
    first, second = first.lower().rstrip("."), second.lower().rstrip(".")
    return first == second or first.endswith("." + second) or second.endswith("." + first)


def validate_plan_body(payload: Any, *, creating: bool) -> dict[str, Any]:
    """Strict plan body: known keys only, booleans for features, null/int>=0 quotas."""
    if not isinstance(payload, dict):
        raise _invalid("body", "invalid_type", "The plan must be an object")
    allowed = {"id", "name_fa", "name_en", "description", "default", "features", "quotas"}
    unknown = sorted(set(payload) - allowed)
    if unknown:
        raise TenancyError("invalid_request", 422, "Unknown fields", fields=[
            {"field": key, "reason_code": "unknown_field"} for key in unknown[:10]])
    out: dict[str, Any] = {}
    if creating and payload.get("id") not in (None, ""):
        if not isinstance(payload["id"], str) or not _PLAN_ID.fullmatch(payload["id"]):
            raise _invalid("id", "invalid_format", "Use 2-32 lowercase letters, digits, - or _")
        out["id"] = payload["id"]
    for key in ("name_fa", "name_en"):
        if key in payload or creating:
            value = payload.get(key)
            if not isinstance(value, str) or not 1 <= len(value.strip()) <= 100:
                raise _invalid(key, "required", "A name of 1-100 characters is required")
            out[key] = " ".join(value.split())
    if "description" in payload:
        value = payload["description"]
        if value is None:
            value = ""
        if not isinstance(value, str) or len(value) > 1000:
            raise _invalid("description", "too_long", "At most 1000 characters")
        out["description"] = value.strip()
    if "default" in payload:
        if not isinstance(payload["default"], bool):
            raise _invalid("default", "invalid_type", "default must be true or false")
        out["default"] = payload["default"]
    if "features" in payload or creating:
        raw = payload.get("features") or {}
        if not isinstance(raw, dict):
            raise _invalid("features", "invalid_type", "features must be an object")
        bad = sorted(set(raw) - set(FEATURES))
        if bad:
            raise _invalid(f"features.{bad[0]}", "unknown_field", "Unknown feature")
        for key, value in raw.items():
            if not isinstance(value, bool):
                raise _invalid(f"features.{key}", "invalid_type", "Use true or false")
        out["features"] = {name: bool(raw.get(name, False)) for name in FEATURES}
    if "quotas" in payload or creating:
        raw = payload.get("quotas") or {}
        out["quotas"] = quota_values(raw, "quotas", fill=True)
    return out


def quota_values(raw: Any, prefix: str, *, fill: bool) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise _invalid(prefix, "invalid_type", "quotas must be an object")
    bad = sorted(set(raw) - set(QUOTA_KEYS))
    if bad:
        raise _invalid(f"{prefix}.{bad[0]}", "unknown_field", "Unknown quota")
    out: dict[str, Any] = {}
    for key in NUMERIC_QUOTAS:
        if key not in raw:
            if fill:
                out[key] = 0
            continue
        value = raw[key]
        if value is not None and (
            isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 2**62
        ):
            raise _invalid(f"{prefix}.{key}", "out_of_range", "Use empty (no limit) or 0 or more")
        out[key] = value
    if "dns_record_types" in raw or fill:
        types = raw.get("dns_record_types", [])
        if types is None:
            types = list(PLAN_RECORD_TYPES)
        if not isinstance(types, list) or any(
            not isinstance(item, str) or item.upper() not in PLAN_RECORD_TYPES for item in types
        ):
            raise _invalid(f"{prefix}.dns_record_types", "invalid_choice", "Unknown record type",
                           choices=list(PLAN_RECORD_TYPES))
        out["dns_record_types"] = sorted({item.upper() for item in types})
    return out


def validate_settings(payload: Any, current: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise _invalid("body", "invalid_type", "Settings must be an object")
    unknown = sorted(set(payload) - set(DEFAULT_SETTINGS))
    if unknown:
        raise _invalid(unknown[0], "unknown_field", "Unknown setting")
    merged = {**current}
    for key, value in payload.items():
        if key == "signup":
            if value not in SIGNUP_MODES:
                raise _invalid(key, "invalid_choice", "Choose off, approval or open",
                               choices=list(SIGNUP_MODES))
        elif key == "default_plan_id":
            if not isinstance(value, str) or not _PLAN_ID.fullmatch(value):
                raise _invalid(key, "invalid_format", "Unknown plan")
        elif not isinstance(value, bool):
            raise _invalid(key, "invalid_type", "Use true or false")
        merged[key] = value
    return merged


def validate_slug(value: Any, field_name: str = "slug") -> str:
    if not isinstance(value, str) or not _SLUG.fullmatch(value) or "--" in value:
        raise _invalid(field_name, "invalid_format",
                       "Use 3-32 lowercase letters, digits and single dashes")
    if value in RESERVED_SLUGS:
        raise TenancyError("slug_unavailable", 409, "This name is reserved",
                           fields=[{"field": field_name, "reason_code": "reserved"}])
    return value


def _slug_base(text: str) -> str:
    base = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    base = re.sub(r"-{2,}", "-", base)[:28].strip("-")
    if len(base) < 3:
        base = f"ws-{base}".strip("-") if base else "space"
    if base in RESERVED_SLUGS:
        base = f"{base}-space"
    return base


def _name(value: Any, field_name: str = "name") -> str:
    if not isinstance(value, str) or not 2 <= len(" ".join(value.split())) <= 100:
        raise _invalid(field_name, "too_short", "A name of 2-100 characters is required",
                       min_length=2, max_length=100)
    return " ".join(value.split())


@dataclass(slots=True)
class WorkspaceContext:
    """Who is acting in which workspace, with what (resolved per request)."""

    principal: Principal
    workspace_id: str
    slug: str
    name: str
    kind: str
    status: str
    role: str
    scopes: frozenset[str]
    limits: dict[str, Any]
    plan_id: str
    via_token: bool = False
    view_as: dict[str, Any] | None = None
    on_behalf_of: int | None = None
    owner_user_id: int | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def user_id(self) -> int:
        return self.principal.user_id

    def can(self, scope: str) -> bool:
        return scope in self.scopes

    def need(self, scope: str, *, feature: str | None = None) -> None:
        """Scope (403) → suspended for writes (423) → plan feature (403)."""
        if scope not in self.scopes:
            raise TenancyError("forbidden", 403, "Your role here does not allow this",
                               required=scope)
        if self.status == "suspended" and not scope.endswith(":read"):
            raise TenancyError("workspace_suspended", 423,
                               "This workspace is suspended; it is read-only")
        if feature is not None:
            self.feature(feature)

    def feature(self, name: str) -> None:
        if not self.limits["features"].get(name):
            raise TenancyError("feature_disabled", 403, "Your plan does not include this",
                               feature=name)

    def need_session(self) -> None:
        """Membership, tokens and the workspace itself: a person, not a key or «view as»."""
        if self.via_token or self.view_as is not None:
            raise TenancyError("forbidden", 403, "Sign in yourself to do this",
                               required="session")


def _plan_item(row: TenancyPlan, workspaces: int = 0) -> dict[str, Any]:
    limits = effective_limits({"features": row.features, "quotas": row.quotas}, None)
    return {
        "id": row.id, "name_fa": row.name_fa, "name_en": row.name_en,
        "description": row.description or "", "default": bool(row.is_default),
        "builtin": bool(row.builtin), "features": limits["features"],
        "quotas": limits["quotas"], "workspaces": workspaces,
        "created_at": row.created_at, "updated_at": row.updated_at,
    }


class TenancyStore:
    """Database side of «my space»; every method is synchronous (call via to_thread)."""

    def __init__(self, database: Database, auth_store: AuthStore) -> None:
        self.db = database
        self.auth = auth_store
        self._lock = threading.RLock()
        self._ws_locks: dict[str, threading.Lock] = {}
        self._async_locks: dict[str, asyncio.Lock] = {}
        self._settings: tuple[float, dict[str, Any]] | None = None
        self._plans_ready = False

    # ------------------------------------------------------------------ locks
    def ws_lock(self, workspace_id: str) -> threading.Lock:
        with self._lock:
            return self._ws_locks.setdefault(workspace_id, threading.Lock())

    def alock(self, workspace_id: str) -> asyncio.Lock:
        """Serialises check-then-create flows that also call an engine."""
        with self._lock:
            return self._async_locks.setdefault(workspace_id, asyncio.Lock())

    # ------------------------------------------------------------------ settings
    def get_settings(self, *, cached: bool = False) -> dict[str, Any]:
        if cached and self._settings is not None and time.monotonic() - self._settings[0] < 2.0:
            return dict(self._settings[1])
        with self.db.session() as db:
            row = db.get(SystemSetting, SETTINGS_KEY)
            stored = dict(row.value) if row is not None and isinstance(row.value, dict) else {}
        value = {**DEFAULT_SETTINGS, **{k: v for k, v in stored.items() if k in DEFAULT_SETTINGS}}
        self._settings = (time.monotonic(), value)
        return dict(value)

    def enabled(self) -> bool:
        return bool(self.get_settings(cached=True)["enabled"])

    def admin_area_allowed(self, client_ip: str | None) -> bool:
        settings = self.get_settings(cached=True)
        if not settings["enabled"] or not settings["admin_area_local_only"]:
            return True
        return local_address(client_ip)

    def put_settings(self, payload: Any, actor_user_id: int | None) -> dict[str, Any]:
        merged = validate_settings(payload, self.get_settings())
        self.ensure_builtin_plans()
        with self.db.session() as db, db.begin():
            if db.get(TenancyPlan, merged["default_plan_id"]) is None:
                raise _invalid("default_plan_id", "not_found", "Unknown plan")
            row = db.get(SystemSetting, SETTINGS_KEY)
            if row is None:
                row = SystemSetting(key=SETTINGS_KEY, value=merged, updated_at=_now())
                db.add(row)
            row.value = merged
            row.updated_at = _now()
            row.updated_by_user_id = actor_user_id
            self.auth._audit_db(db, actor_user_id, "tenancy.settings.update", "system_setting",
                                ",".join(sorted(payload)) if isinstance(payload, dict) else None,
                                "success")
        self._settings = None
        return merged

    # ------------------------------------------------------------------ plans
    def ensure_builtin_plans(self) -> None:
        if self._plans_ready:
            return
        with self.db.session() as db, db.begin():
            existing = set(db.scalars(select(TenancyPlan.id)))
            for plan_id, spec in BUILTIN_PLANS.items():
                if plan_id in existing:
                    continue
                now = _now()
                db.add(TenancyPlan(
                    id=plan_id, name_fa=spec["name_fa"], name_en=spec["name_en"],
                    description=spec["description"],
                    is_default=bool(spec["default"]) and not existing, builtin=True,
                    features=dict(spec["features"]), quotas=dict(spec["quotas"]),
                    created_at=now, updated_at=now,
                ))
        self._plans_ready = True

    def _plan_counts(self, db: OrmSession) -> dict[str, int]:
        return dict(db.execute(
            select(Workspace.plan_id, func.count()).group_by(Workspace.plan_id)).all())

    def list_plans(self) -> list[dict[str, Any]]:
        self.ensure_builtin_plans()
        with self.db.session() as db:
            counts = self._plan_counts(db)
            rows = db.scalars(select(TenancyPlan).order_by(TenancyPlan.created_at,
                                                           TenancyPlan.id)).all()
            return [_plan_item(row, int(counts.get(row.id, 0))) for row in rows]

    def get_plan(self, plan_id: str) -> dict[str, Any]:
        self.ensure_builtin_plans()
        with self.db.session() as db:
            row = db.get(TenancyPlan, plan_id)
            if row is None:
                raise not_found()
            return _plan_item(row, int(self._plan_counts(db).get(row.id, 0)))

    def _set_default(self, db: OrmSession, plan_id: str) -> None:
        db.execute(update(TenancyPlan).where(TenancyPlan.id != plan_id).values(is_default=False))

    def create_plan(self, payload: Any, actor_user_id: int) -> dict[str, Any]:
        self.ensure_builtin_plans()
        body = validate_plan_body(payload, creating=True)
        plan_id = body.get("id") or f"plan-{secrets.token_hex(4)}"
        now = _now()
        try:
            with self.db.session() as db, db.begin():
                if db.get(TenancyPlan, plan_id) is not None:
                    raise TenancyError("plan_exists", 409, "A plan with this id exists",
                                       fields=[{"field": "id", "reason_code": "duplicate"}])
                row = TenancyPlan(
                    id=plan_id, name_fa=body["name_fa"], name_en=body["name_en"],
                    description=body.get("description", ""), is_default=body.get("default", False),
                    builtin=False, features=body["features"], quotas=body["quotas"],
                    created_at=now, updated_at=now,
                )
                db.add(row)
                db.flush()
                if row.is_default:
                    self._set_default(db, plan_id)
                self.auth._audit_db(db, actor_user_id, "tenancy.plan.create", "tenancy_plan",
                                    plan_id, "success")
                return _plan_item(row)
        except IntegrityError:
            raise TenancyError("plan_exists", 409, "A plan with this id exists") from None

    def update_plan(self, plan_id: str, payload: Any, actor_user_id: int) -> dict[str, Any]:
        self.ensure_builtin_plans()
        body = validate_plan_body(payload, creating=False)
        with self.db.session() as db, db.begin():
            row = db.get(TenancyPlan, plan_id)
            if row is None:
                raise not_found()
            for key in ("name_fa", "name_en", "description"):
                if key in body:
                    setattr(row, key, body[key])
            if "features" in body:
                row.features = {**(row.features or {}), **{
                    key: value for key, value in body["features"].items()
                    if key in (payload.get("features") or {})}}
            if "quotas" in body:
                given = set(payload.get("quotas") or {})
                row.quotas = {**(row.quotas or {}),
                              **{key: value for key, value in body["quotas"].items()
                                 if key in given}}
            if body.get("default") is True:
                row.is_default = True
                self._set_default(db, plan_id)
            elif body.get("default") is False and row.is_default:
                raise TenancyError("plan_default", 409,
                                   "Choose another default plan first")
            row.updated_at = _now()
            self.auth._audit_db(db, actor_user_id, "tenancy.plan.update", "tenancy_plan",
                                plan_id, "success")
            return _plan_item(row, int(self._plan_counts(db).get(plan_id, 0)))

    def delete_plan(self, plan_id: str, actor_user_id: int) -> dict[str, Any]:
        self.ensure_builtin_plans()
        with self.db.session() as db, db.begin():
            row = db.get(TenancyPlan, plan_id)
            if row is None:
                raise not_found()
            used = int(self._plan_counts(db).get(plan_id, 0))
            if used:
                raise TenancyError("plan_in_use", 409, "Workspaces still use this plan",
                                   workspaces=used)
            if row.builtin:
                raise TenancyError("plan_builtin", 409, "Built-in plans cannot be deleted")
            if row.is_default or self.get_settings()["default_plan_id"] == plan_id:
                raise TenancyError("plan_default", 409, "Choose another default plan first")
            db.delete(row)
            self.auth._audit_db(db, actor_user_id, "tenancy.plan.delete", "tenancy_plan",
                                plan_id, "success")
        return {"deleted": plan_id}

    def _default_plan_id(self, db: OrmSession) -> str:
        wanted = self.get_settings(cached=True)["default_plan_id"]
        if db.get(TenancyPlan, wanted) is not None:
            return str(wanted)
        row = db.scalar(select(TenancyPlan.id).where(TenancyPlan.is_default.is_(True)))
        return str(row or "basic")

    # ------------------------------------------------------------------ workspaces
    def _unique_slug(self, db: OrmSession, base: str) -> str:
        candidate = base
        while db.scalar(select(Workspace.id).where(Workspace.slug == candidate)) is not None:
            candidate = f"{base[:25]}-{secrets.token_hex(2)}"
        return candidate

    def _new_workspace(self, db: OrmSession, *, slug: str, name: str, kind: str,
                       plan_id: str, owner_id: int) -> Workspace:
        now = _now()
        row = Workspace(
            id=f"ws_{secrets.token_hex(6)}", slug=slug, name=name, kind=kind, plan_id=plan_id,
            quota_overrides={}, status="active", created_by_user_id=owner_id,
            created_at=now, updated_at=now,
        )
        db.add(row)
        db.flush()
        db.add(WorkspaceMember(workspace_id=row.id, user_id=owner_id, role="owner",
                               created_at=now))
        db.flush()
        return row

    def personal_workspace_id(self, db: OrmSession, user_id: int) -> str | None:
        return db.scalar(
            select(Workspace.id)
            .join(WorkspaceMember, WorkspaceMember.workspace_id == Workspace.id)
            .where(WorkspaceMember.user_id == user_id, WorkspaceMember.role == "owner",
                   Workspace.kind == "personal")
            .order_by(Workspace.created_at)
        )

    def ensure_personal(self, user_id: int, plan_id: str | None = None) -> str:
        self.ensure_builtin_plans()
        with self._lock, self.db.session() as db, db.begin():
            found = self.personal_workspace_id(db, user_id)
            if found is not None:
                return found
            user = db.get(User, user_id)
            if user is None:
                raise not_found()
            chosen = plan_id if plan_id and db.get(TenancyPlan, plan_id) is not None \
                else self._default_plan_id(db)
            slug = self._unique_slug(db, _slug_base(user.username))
            row = self._new_workspace(db, slug=slug, name=user.display_name or user.username,
                                      kind="personal", plan_id=chosen, owner_id=user_id)
            self.auth._audit_db(db, user_id, "tenancy.workspace.create", "workspace", row.id,
                                "success", workspace_id=row.id)
            return row.id

    def _limits(self, db: OrmSession, row: Workspace) -> dict[str, Any]:
        plan = db.get(TenancyPlan, row.plan_id)
        return effective_limits(
            {"features": plan.features, "quotas": plan.quotas} if plan is not None else None,
            row.quota_overrides,
        )

    def limits_for(self, workspace_id: str) -> dict[str, Any]:
        with self.db.session() as db:
            row = db.get(Workspace, workspace_id)
            if row is None:
                raise not_found()
            return self._limits(db, row)

    def create_team(self, ctx_user_id: int, name: Any, slug: Any) -> str:
        """A team workspace owned by the caller (feature/quota from their personal space)."""
        normalized = _name(name)
        personal = self.ensure_personal(ctx_user_id)
        with self.ws_lock(personal), self.db.session() as db, db.begin():
            base = db.get(Workspace, personal, with_for_update=True)
            assert base is not None
            limits = self._limits(db, base)
            if not limits["features"].get("teams"):
                raise TenancyError("feature_disabled", 403, "Your plan does not include teams",
                                   feature="teams")
            owned = db.scalar(
                select(func.count()).select_from(Workspace)
                .join(WorkspaceMember, WorkspaceMember.workspace_id == Workspace.id)
                .where(WorkspaceMember.user_id == ctx_user_id, WorkspaceMember.role == "owner",
                       Workspace.kind == "team")
            ) or 0
            check_quota(limits, "workspaces_team", int(owned))
            if slug in (None, ""):
                chosen = self._unique_slug(db, _slug_base(normalized))
            else:
                chosen = validate_slug(slug)
                if db.scalar(select(Workspace.id).where(Workspace.slug == chosen)) is not None:
                    raise TenancyError("slug_unavailable", 409, "This name is taken",
                                       fields=[{"field": "slug", "reason_code": "duplicate"}])
            row = self._new_workspace(db, slug=chosen, name=normalized, kind="team",
                                      plan_id=base.plan_id, owner_id=ctx_user_id)
            self.auth._audit_db(db, ctx_user_id, "tenancy.workspace.create", "workspace",
                                row.id, "success", workspace_id=row.id)
            return row.id

    def rename(self, workspace_id: str, name: Any, actor: int, on_behalf_of: int | None = None
               ) -> None:
        normalized = _name(name)
        with self.db.session() as db, db.begin():
            row = db.get(Workspace, workspace_id)
            if row is None:
                raise not_found()
            row.name = normalized
            row.updated_at = _now()
            self.auth._audit_db(db, actor, "tenancy.workspace.update", "workspace",
                                workspace_id, "success", workspace_id=workspace_id,
                                on_behalf_of=on_behalf_of)

    def workspace_row(self, workspace_id: str) -> dict[str, Any]:
        with self.db.session() as db:
            row = db.get(Workspace, workspace_id)
            if row is None:
                raise not_found()
            return self._ws_dict(db, row)

    def _ws_dict(self, db: OrmSession, row: Workspace) -> dict[str, Any]:
        plan = db.get(TenancyPlan, row.plan_id)
        owner = db.execute(
            select(User.id, User.username, User.display_name)
            .join(WorkspaceMember, WorkspaceMember.user_id == User.id)
            .where(WorkspaceMember.workspace_id == row.id, WorkspaceMember.role == "owner")
            .order_by(WorkspaceMember.created_at)
        ).first()
        members = db.scalar(select(func.count()).select_from(WorkspaceMember)
                            .where(WorkspaceMember.workspace_id == row.id)) or 0
        return {
            "id": row.id, "slug": row.slug, "name": row.name, "kind": row.kind,
            "status": row.status, "plan_id": row.plan_id,
            "plan": {"id": row.plan_id,
                     "name_fa": plan.name_fa if plan else row.plan_id,
                     "name_en": plan.name_en if plan else row.plan_id},
            "quota_overrides": dict(row.quota_overrides or {}),
            "limits": self._limits(db, row),
            "owner": {"id": owner[0], "username": owner[1], "display_name": owner[2]}
            if owner else None,
            "members_count": int(members),
            "created_at": row.created_at, "updated_at": row.updated_at,
        }

    def memberships(self, user_id: int) -> list[dict[str, Any]]:
        with self.db.session() as db:
            rows = db.execute(
                select(Workspace, WorkspaceMember.role)
                .join(WorkspaceMember, WorkspaceMember.workspace_id == Workspace.id)
                .where(WorkspaceMember.user_id == user_id)
                .order_by(Workspace.kind.desc(), Workspace.created_at)
            ).all()
            return [{**self._ws_dict(db, row), "role": role} for row, role in rows]

    def list_workspaces(self, query: str | None, status: str | None) -> list[dict[str, Any]]:
        with self.db.session() as db:
            stmt = select(Workspace).order_by(Workspace.created_at)
            if status:
                stmt = stmt.where(Workspace.status == status)
            rows = db.scalars(stmt).all()
            items = [self._ws_dict(db, row) for row in rows]
        if query:
            needle = query.strip().lower()
            items = [item for item in items if needle in item["slug"]
                     or needle in item["name"].lower()
                     or (item["owner"] and needle in str(item["owner"]["username"]).lower())]
        return items

    def admin_update(self, workspace_id: str, payload: Any, actor: int) -> dict[str, Any]:
        if not isinstance(payload, dict):
            raise _invalid("body", "invalid_type", "The request must be an object")
        unknown = sorted(set(payload) - {"plan_id", "quota_overrides", "status", "name"})
        if unknown:
            raise _invalid(unknown[0], "unknown_field", "Unknown field")
        with self.db.session() as db, db.begin():
            row = db.get(Workspace, workspace_id)
            if row is None:
                raise not_found()
            if "plan_id" in payload:
                if not isinstance(payload["plan_id"], str) or db.get(
                        TenancyPlan, payload["plan_id"]) is None:
                    raise _invalid("plan_id", "not_found", "Unknown plan")
                row.plan_id = payload["plan_id"]
            if "quota_overrides" in payload:
                raw = payload["quota_overrides"] or {}
                values = quota_values(raw, "quota_overrides", fill=False)
                current = dict(row.quota_overrides or {})
                for key in raw:
                    if raw[key] is None and key != "dns_record_types":
                        # null = «no exception»; an explicit unlimited is not expressible
                        # here on purpose (pick the unlimited plan instead).
                        current.pop(key, None)
                    else:
                        current[key] = values[key]
                row.quota_overrides = current
            if "status" in payload:
                if payload["status"] not in ("active", "suspended"):
                    raise _invalid("status", "invalid_choice", "active or suspended",
                                   choices=["active", "suspended"])
                row.status = payload["status"]
            if "name" in payload:
                row.name = _name(payload["name"])
            row.updated_at = _now()
            self.auth._audit_db(db, actor, "tenancy.workspace.admin_update", "workspace",
                                f"{workspace_id}:{','.join(sorted(payload))}", "success",
                                workspace_id=workspace_id)
            return self._ws_dict(db, row)

    def delete_workspace_row(self, workspace_id: str, actor: int,
                             on_behalf_of: int | None = None) -> None:
        with self.db.session() as db, db.begin():
            row = db.get(Workspace, workspace_id)
            if row is None:
                raise not_found()
            db.execute(update(ApiToken).where(ApiToken.workspace_id == workspace_id,
                                              ApiToken.revoked_at.is_(None))
                       .values(revoked_at=_now()))
            db.execute(delete(ResourceOwner).where(ResourceOwner.workspace_id == workspace_id))
            db.delete(row)
            self.auth._audit_db(db, actor, "tenancy.workspace.delete", "workspace",
                                workspace_id, "success", workspace_id=workspace_id,
                                on_behalf_of=on_behalf_of)

    # ------------------------------------------------------------------ context
    def resolve(
        self,
        principal: Principal,
        *,
        requested: str | None,
        view_as_token: str | None,
        client_ip: str | None,
    ) -> WorkspaceContext:
        """The workspace context of one request (see module docstring)."""
        if not self.enabled():
            raise TenancyError("tenancy_disabled", 404, "My space is not turned on")
        requested = requested.strip() if isinstance(requested, str) and requested.strip() \
            else None
        view_as: dict[str, Any] | None = None
        via_token = False
        if view_as_token:
            if principal.token_id is not None:
                raise TenancyError("forbidden", 403, "«View as» needs a signed-in admin",
                                   required="session")
            view_as = self._view_as(view_as_token, principal)
            if requested is not None and requested != view_as["workspace_id"]:
                raise not_found()
            workspace_id = view_as["workspace_id"]
        elif principal.workspace_id is not None:
            via_token = True
            if principal.token_ip_allow and not _ip_allowed(client_ip, principal.token_ip_allow):
                raise TenancyError("forbidden", 403, "This key may not be used from here",
                                   required="ip_allow")
            if requested is not None and requested != principal.workspace_id:
                raise not_found()
            workspace_id = principal.workspace_id
        else:
            if principal.token_id is not None:
                # A server-management key never reaches «my space».
                raise TenancyError("forbidden", 403, "Use a «my space» key", required="my_token")
            workspace_id = requested or self.ensure_personal(principal.user_id)
        with self.db.session() as db:
            row = db.get(Workspace, workspace_id)
            if row is None:
                raise not_found()
            owner_id = db.scalar(
                select(WorkspaceMember.user_id)
                .where(WorkspaceMember.workspace_id == row.id, WorkspaceMember.role == "owner")
                .order_by(WorkspaceMember.created_at))
            if view_as is not None:
                role = "admin" if view_as["write"] else "viewer"
            else:
                role = db.scalar(select(WorkspaceMember.role).where(
                    WorkspaceMember.workspace_id == row.id,
                    WorkspaceMember.user_id == principal.user_id))
                if role is None:
                    raise not_found()
            scopes = ROLE_SCOPES[role]
            if via_token:
                scopes = scopes & principal.permissions & MY_TOKEN_SCOPES
            return WorkspaceContext(
                principal=principal, workspace_id=row.id, slug=row.slug, name=row.name,
                kind=row.kind, status=row.status, role=role, scopes=frozenset(scopes),
                limits=self._limits(db, row), plan_id=row.plan_id, via_token=via_token,
                view_as=view_as, on_behalf_of=owner_id if view_as is not None else None,
                owner_user_id=owner_id,
            )

    # ------------------------------------------------------------------ ownership
    def owner_of(self, kind: str, resource_id: str) -> str | None:
        with self.db.session() as db:
            row = db.get(ResourceOwner, (kind, resource_id))
            return row.workspace_id if row is not None else None

    def owned(self, kind: str, workspace_id: str) -> list[dict[str, Any]]:
        with self.db.session() as db:
            rows = db.scalars(select(ResourceOwner).where(
                ResourceOwner.kind == kind, ResourceOwner.workspace_id == workspace_id)
                .order_by(ResourceOwner.created_at, ResourceOwner.resource_id)).all()
            return [_owner_item(row) for row in rows]

    def require_owned(self, ctx: WorkspaceContext, kind: str, resource_id: str
                      ) -> dict[str, Any]:
        """The ownership row of a resource of ``ctx``'s workspace, else 404."""
        with self.db.session() as db:
            row = db.get(ResourceOwner, (kind, resource_id))
            if row is None or row.workspace_id != ctx.workspace_id:
                raise not_found()
            return _owner_item(row)

    def count_owned(self, db: OrmSession, kind: str, workspace_id: str) -> int:
        return int(db.scalar(select(func.count()).select_from(ResourceOwner).where(
            ResourceOwner.kind == kind, ResourceOwner.workspace_id == workspace_id)) or 0)

    def claim(
        self,
        ctx: WorkspaceContext,
        kind: str,
        resource_id: str,
        *,
        quota: str | None = None,
        meta: dict[str, Any] | None = None,
    ) -> None:
        """Record ownership, counting ``quota`` in the same transaction (409 when taken)."""
        with self.ws_lock(ctx.workspace_id), self.db.session() as db, db.begin():
            workspace = db.get(Workspace, ctx.workspace_id, with_for_update=True)
            if workspace is None:
                raise not_found()
            if quota is not None:
                check_quota(self._limits(db, workspace), quota,
                            self.count_owned(db, kind, ctx.workspace_id))
            if db.get(ResourceOwner, (kind, resource_id)) is not None:
                raise TenancyError("resource_taken", 409, "This name is already in use")
            db.add(ResourceOwner(kind=kind, resource_id=resource_id,
                                 workspace_id=ctx.workspace_id, created_by=ctx.user_id,
                                 created_at=_now(), meta=dict(meta or {})))
            db.flush()

    def release(self, kind: str, resource_id: str) -> None:
        with self.db.session() as db, db.begin():
            db.execute(delete(ResourceOwner).where(ResourceOwner.kind == kind,
                                                   ResourceOwner.resource_id == resource_id))

    def transfer_reservation(self, kind: str, reserved_id: str, final_id: str) -> None:
        """Rename a placeholder ownership row once the real id is known."""
        with self.db.session() as db, db.begin():
            row = db.get(ResourceOwner, (kind, reserved_id))
            if row is None:
                raise not_found()
            db.add(ResourceOwner(kind=kind, resource_id=final_id,
                                 workspace_id=row.workspace_id, created_by=row.created_by,
                                 created_at=row.created_at, meta=dict(row.meta or {})))
            db.delete(row)

    def set_meta(self, kind: str, resource_id: str, changes: dict[str, Any]) -> dict[str, Any]:
        with self.db.session() as db, db.begin():
            row = db.get(ResourceOwner, (kind, resource_id))
            if row is None:
                raise not_found()
            row.meta = {**(row.meta or {}), **changes}
            return _owner_item(row)

    def all_owned(self, kinds: Iterable[str]) -> list[dict[str, Any]]:
        with self.db.session() as db:
            rows = db.scalars(select(ResourceOwner).where(ResourceOwner.kind.in_(list(kinds))))
            return [_owner_item(row) for row in rows]

    def list_ownership(self, kind: str | None, workspace_id: str | None) -> list[dict[str, Any]]:
        with self.db.session() as db:
            stmt = select(ResourceOwner, Workspace.slug).join(
                Workspace, Workspace.id == ResourceOwner.workspace_id)
            if kind:
                stmt = stmt.where(ResourceOwner.kind == kind)
            if workspace_id:
                stmt = stmt.where(ResourceOwner.workspace_id == workspace_id)
            rows = db.execute(stmt.order_by(ResourceOwner.kind, ResourceOwner.resource_id)
                              .limit(5000)).all()
            return [{**_owner_item(row), "workspace_slug": slug} for row, slug in rows]

    def transfer(self, kind: Any, resource_id: Any, workspace_id: Any, actor: int
                 ) -> dict[str, Any]:
        if kind not in RESOURCE_KINDS:
            raise _invalid("kind", "invalid_choice", "Unknown resource kind",
                           choices=list(RESOURCE_KINDS))
        if kind == "api_token":
            raise TenancyError("not_transferable", 409, "Keys cannot change workspace")
        if not isinstance(resource_id, str) or not 1 <= len(resource_id) <= 255:
            raise _invalid("resource_id", "required", "Name the resource")
        with self.db.session() as db, db.begin():
            if workspace_id is not None:
                if not isinstance(workspace_id, str) or db.get(Workspace, workspace_id) is None:
                    raise _invalid("workspace_id", "not_found", "Unknown workspace")
            row = db.get(ResourceOwner, (kind, resource_id))
            before = row.workspace_id if row is not None else None
            if workspace_id is None:
                if row is not None:
                    db.delete(row)
            elif row is None:
                db.add(ResourceOwner(kind=kind, resource_id=resource_id,
                                     workspace_id=workspace_id, created_by=actor,
                                     created_at=_now(),
                                     meta={"status": "active", "transferred": True}))
            else:
                row.workspace_id = workspace_id
            self.auth._audit_db(db, actor, "tenancy.ownership.transfer", kind,
                                f"{resource_id}:{before or 'system'}->{workspace_id or 'system'}",
                                "success", workspace_id=workspace_id or before)
        return {"kind": kind, "resource_id": resource_id, "workspace_id": workspace_id}

    # ------------------------------------------------------------------ members
    def list_members(self, workspace_id: str) -> list[dict[str, Any]]:
        with self.db.session() as db:
            rows = db.execute(
                select(WorkspaceMember, User)
                .join(User, User.id == WorkspaceMember.user_id)
                .where(WorkspaceMember.workspace_id == workspace_id)
                .order_by(WorkspaceMember.created_at)
            ).all()
            return [_member_item(member, user) for member, user in rows]

    @staticmethod
    def _check_grant(actor_role: str, role: Any, current: str | None = None) -> str:
        if role not in ROLES:
            raise _invalid("role", "invalid_choice", "Unknown role", choices=list(ROLES))
        if RANK[actor_role] < RANK["admin"]:
            raise TenancyError("forbidden", 403, "Only workspace admins manage members",
                               required="my.workspace:admin")
        escalation = TenancyError(
            "permission_escalation", 403, "You cannot give a role equal to or above your own",
            fields=[{"field": "role", "reason_code": "exceeds_own_role"}])
        if actor_role != "owner":
            if RANK[role] >= RANK[actor_role]:
                raise escalation
            if current is not None and RANK[current] >= RANK[actor_role]:
                raise escalation
        return str(role)

    def _team(self, db: OrmSession, workspace_id: str) -> Workspace:
        row = db.get(Workspace, workspace_id, with_for_update=True)
        if row is None:
            raise not_found()
        if row.kind != "team":
            raise TenancyError("personal_workspace", 409,
                               "A personal workspace has no other members")
        return row

    def add_member(self, ctx: WorkspaceContext, who: Any, role: Any) -> dict[str, Any]:
        granted = self._check_grant(ctx.role, role)
        if not isinstance(who, str) or not who.strip():
            raise _invalid("user", "required", "Name the user")
        needle = who.strip().lower()
        with self.ws_lock(ctx.workspace_id), self.db.session() as db, db.begin():
            workspace = self._team(db, ctx.workspace_id)
            user = db.scalar(select(User).where((User.username == needle)
                                                | (User.email == needle)))
            if user is None or not user.enabled:
                raise TenancyError("user_not_found", 404, "No such user")
            if db.get(WorkspaceMember, (ctx.workspace_id, user.id)) is not None:
                raise TenancyError("already_member", 409, "Already a member")
            count = db.scalar(select(func.count()).select_from(WorkspaceMember).where(
                WorkspaceMember.workspace_id == ctx.workspace_id)) or 0
            check_quota(self._limits(db, workspace), "members", int(count))
            member = WorkspaceMember(workspace_id=ctx.workspace_id, user_id=user.id,
                                     role=granted, created_at=_now())
            db.add(member)
            db.flush()
            self.auth._audit_db(db, ctx.user_id, "tenancy.member.add", "workspace_member",
                                f"{user.id}:{granted}", "success",
                                workspace_id=ctx.workspace_id)
            return _member_item(member, user)

    def change_member(self, ctx: WorkspaceContext, user_id: int, role: Any) -> dict[str, Any]:
        with self.ws_lock(ctx.workspace_id), self.db.session() as db, db.begin():
            self._team(db, ctx.workspace_id)
            member = db.get(WorkspaceMember, (ctx.workspace_id, user_id))
            if member is None:
                raise not_found()
            if user_id == ctx.user_id:
                raise TenancyError("permission_escalation", 403, "You cannot change your own role",
                                   fields=[{"field": "role", "reason_code": "own_role"}])
            granted = self._check_grant(ctx.role, role, member.role)
            if member.role == "owner" and granted != "owner":
                self._keep_an_owner(db, ctx.workspace_id)
            member.role = granted
            user = db.get(User, user_id)
            self.auth._audit_db(db, ctx.user_id, "tenancy.member.role", "workspace_member",
                                f"{user_id}:{granted}", "success", workspace_id=ctx.workspace_id)
            return _member_item(member, user)

    @staticmethod
    def _keep_an_owner(db: OrmSession, workspace_id: str) -> None:
        owners = db.scalar(select(func.count()).select_from(WorkspaceMember).where(
            WorkspaceMember.workspace_id == workspace_id, WorkspaceMember.role == "owner")) or 0
        if owners <= 1:
            raise TenancyError("last_owner", 409, "A workspace needs at least one owner")

    def remove_member(self, ctx: WorkspaceContext, user_id: int) -> None:
        with self.ws_lock(ctx.workspace_id), self.db.session() as db, db.begin():
            self._team(db, ctx.workspace_id)
            member = db.get(WorkspaceMember, (ctx.workspace_id, user_id))
            if member is None:
                raise not_found()
            if user_id != ctx.user_id:
                self._check_grant(ctx.role, "viewer", member.role)
            if member.role == "owner":
                self._keep_an_owner(db, ctx.workspace_id)
            db.delete(member)
            db.execute(update(ApiToken).where(
                ApiToken.workspace_id == ctx.workspace_id, ApiToken.user_id == user_id,
                ApiToken.revoked_at.is_(None)).values(revoked_at=_now()))
            self.auth._audit_db(db, ctx.user_id, "tenancy.member.remove", "workspace_member",
                                str(user_id), "success", workspace_id=ctx.workspace_id)

    # ------------------------------------------------------------------ invites
    def list_invites(self, workspace_id: str) -> list[dict[str, Any]]:
        now = _now()
        with self.db.session() as db:
            rows = db.scalars(select(WorkspaceInvite).where(
                WorkspaceInvite.workspace_id == workspace_id,
                WorkspaceInvite.accepted_at.is_(None), WorkspaceInvite.revoked_at.is_(None),
                WorkspaceInvite.expires_at > now).order_by(WorkspaceInvite.created_at)).all()
            return [{"id": row.id, "email": row.email, "role": row.role,
                     "created_at": row.created_at, "expires_at": row.expires_at}
                    for row in rows]

    def create_invite(self, ctx: WorkspaceContext, email: Any, role: Any) -> dict[str, Any]:
        granted = self._check_grant(ctx.role, role)
        normalized = AuthStore.validate_email(email) if isinstance(email, str) else None
        if normalized is None:
            raise _invalid("email", "required", "An email address is required")
        token = secrets.token_urlsafe(32)
        now = _now()
        with self.ws_lock(ctx.workspace_id), self.db.session() as db, db.begin():
            workspace = self._team(db, ctx.workspace_id)
            count = db.scalar(select(func.count()).select_from(WorkspaceMember).where(
                WorkspaceMember.workspace_id == ctx.workspace_id)) or 0
            check_quota(self._limits(db, workspace), "members", int(count))
            row = WorkspaceInvite(
                id=f"inv_{secrets.token_hex(8)}", workspace_id=ctx.workspace_id,
                email=normalized, role=granted, token_hash=_digest(token),
                created_by=ctx.user_id, created_at=now, expires_at=now + INVITE_SECONDS,
            )
            db.add(row)
            self.auth._audit_db(db, ctx.user_id, "tenancy.invite.create", "workspace_invite",
                                row.id, "success", workspace_id=ctx.workspace_id)
        return {"id": row.id, "email": normalized, "role": granted, "token": token,
                "expires_at": row.expires_at}

    def revoke_invite(self, ctx: WorkspaceContext, invite_id: str) -> None:
        with self.db.session() as db, db.begin():
            row = db.get(WorkspaceInvite, invite_id)
            if row is None or row.workspace_id != ctx.workspace_id or row.revoked_at is not None \
                    or row.accepted_at is not None:
                raise not_found()
            row.revoked_at = _now()
            self.auth._audit_db(db, ctx.user_id, "tenancy.invite.revoke", "workspace_invite",
                                invite_id, "success", workspace_id=ctx.workspace_id)

    def accept_invite(self, principal: Principal, token: Any) -> dict[str, Any]:
        if not isinstance(token, str) or not 10 <= len(token) <= 200:
            raise not_found()
        now = _now()
        with self.db.session() as db, db.begin():
            row = db.scalar(select(WorkspaceInvite).where(
                WorkspaceInvite.token_hash == _digest(token)))
            if row is None or row.revoked_at is not None or row.accepted_at is not None \
                    or row.expires_at <= now:
                raise not_found()
            if not principal.email or principal.email.lower() != row.email.lower():
                raise not_found()
            workspace = db.get(Workspace, row.workspace_id, with_for_update=True)
            if workspace is None:
                raise not_found()
            if db.get(WorkspaceMember, (row.workspace_id, principal.user_id)) is not None:
                raise TenancyError("already_member", 409, "Already a member")
            count = db.scalar(select(func.count()).select_from(WorkspaceMember).where(
                WorkspaceMember.workspace_id == row.workspace_id)) or 0
            check_quota(self._limits(db, workspace), "members", int(count))
            db.add(WorkspaceMember(workspace_id=row.workspace_id, user_id=principal.user_id,
                                   role=row.role, created_at=now))
            row.accepted_at = now
            self.auth._audit_db(db, principal.user_id, "tenancy.invite.accept",
                                "workspace_invite", row.id, "success",
                                workspace_id=row.workspace_id)
            return {"workspace_id": row.workspace_id, "role": row.role}

    # ------------------------------------------------------------------ API tokens
    def list_tokens(self, ctx: WorkspaceContext) -> list[dict[str, Any]]:
        with self.db.session() as db:
            stmt = select(ApiToken, User.username).join(User, User.id == ApiToken.user_id).where(
                ApiToken.workspace_id == ctx.workspace_id, ApiToken.revoked_at.is_(None))
            if not ctx.can("my.workspace:admin"):
                stmt = stmt.where(ApiToken.user_id == ctx.user_id)
            rows = db.execute(stmt.order_by(ApiToken.id.desc())).all()
            return [_token_item(row, username) for row, username in rows]

    def create_token(self, ctx: WorkspaceContext, payload: Any) -> dict[str, Any]:
        if not isinstance(payload, dict):
            raise _invalid("body", "invalid_type", "The request must be an object")
        unknown = sorted(set(payload) - {"name", "scopes", "expires_in_seconds", "ip_allow",
                                         "workspace_id"})
        if unknown:
            raise _invalid(unknown[0], "unknown_field", "Unknown field")
        if payload.get("workspace_id") not in (None, ctx.workspace_id):
            # The workspace comes from the context only; a body naming another is refused.
            raise not_found()
        name = payload.get("name")
        if not isinstance(name, str) or not 3 <= len(name.strip()) <= 80:
            raise _invalid("name", "too_short", "A name of 3-80 characters is required",
                           min_length=3, max_length=80)
        scopes = payload.get("scopes")
        if not isinstance(scopes, list) or not scopes or not all(
                isinstance(item, str) for item in scopes):
            raise _invalid("scopes", "required", "Choose at least one permission")
        unknown_scopes = sorted(set(scopes) - MY_TOKEN_SCOPES)
        if unknown_scopes:
            raise TenancyError("invalid_request", 422, "Unknown permission", fields=[
                {"field": "scopes", "reason_code": "unknown_permission",
                 "params": {"permission": item}} for item in unknown_scopes[:10]])
        exceeding = sorted(set(scopes) - ctx.scopes)
        if exceeding:
            raise TenancyError("permission_escalation", 403,
                               "A key cannot do more than you can", permissions=exceeding,
                               fields=[{"field": "scopes", "reason_code": "exceeds_own_role",
                                        "params": {"permissions": exceeding}}])
        expires = payload.get("expires_in_seconds", TOKEN_DEFAULT_SECONDS)
        if isinstance(expires, bool) or not isinstance(expires, int) or not (
                TOKEN_MIN_SECONDS <= expires <= TOKEN_MAX_SECONDS):
            raise _invalid("expires_in_seconds", "out_of_range",
                           "Between 15 minutes and 365 days",
                           min=TOKEN_MIN_SECONDS, max=TOKEN_MAX_SECONDS)
        ip_allow = _ip_list(payload.get("ip_allow"))
        token = f"mrk_{secrets.token_urlsafe(32)}"
        now = _now()
        with self.ws_lock(ctx.workspace_id), self.db.session() as db, db.begin():
            workspace = db.get(Workspace, ctx.workspace_id, with_for_update=True)
            if workspace is None:
                raise not_found()
            active = db.scalar(select(func.count()).select_from(ApiToken).where(
                ApiToken.workspace_id == ctx.workspace_id, ApiToken.revoked_at.is_(None),
                ApiToken.expires_at > now)) or 0
            check_quota(self._limits(db, workspace), "api_tokens", int(active))
            row = ApiToken(
                user_id=ctx.user_id, name=name.strip(), token_hash=_digest(token),
                scopes=sorted(set(scopes)), created_at=now, expires_at=now + expires,
                workspace_id=ctx.workspace_id, ip_allow=ip_allow or None,
            )
            db.add(row)
            db.flush()
            self.auth._audit_db(db, ctx.user_id, "tenancy.token.create", "api_token",
                                str(row.id), "success", workspace_id=ctx.workspace_id)
            return {**_token_item(row, ctx.principal.username), "token": token}

    def revoke_token(self, ctx: WorkspaceContext, token_id: int) -> None:
        with self.db.session() as db, db.begin():
            row = db.get(ApiToken, token_id)
            if row is None or row.workspace_id != ctx.workspace_id or row.revoked_at is not None:
                raise not_found()
            if row.user_id != ctx.user_id and not ctx.can("my.workspace:admin"):
                raise not_found()
            row.revoked_at = _now()
            self.auth._audit_db(db, ctx.user_id, "tenancy.token.revoke", "api_token",
                                str(token_id), "success", workspace_id=ctx.workspace_id)

    def active_tokens(self, workspace_id: str) -> int:
        with self.db.session() as db:
            return int(db.scalar(select(func.count()).select_from(ApiToken).where(
                ApiToken.workspace_id == workspace_id, ApiToken.revoked_at.is_(None),
                ApiToken.expires_at > _now())) or 0)

    # ------------------------------------------------------------------ view as
    def start_view_as(self, admin: Principal, workspace_id: str, write: bool) -> dict[str, Any]:
        token = secrets.token_urlsafe(32)
        now = _now()
        with self.db.session() as db, db.begin():
            row = db.get(Workspace, workspace_id)
            if row is None:
                raise not_found()
            db.add(ImpersonationSession(
                token_hash=_digest(token), admin_user_id=admin.user_id,
                workspace_id=workspace_id, write=write, created_at=now,
                expires_at=now + VIEW_AS_SECONDS))
            owner = db.scalar(select(WorkspaceMember.user_id).where(
                WorkspaceMember.workspace_id == workspace_id, WorkspaceMember.role == "owner")
                .order_by(WorkspaceMember.created_at))
            self.auth._audit_db(db, admin.user_id, "tenancy.view_as.start", "workspace",
                                f"{workspace_id}:{'write' if write else 'read'}", "success",
                                workspace_id=workspace_id, on_behalf_of=owner)
            return {"token": token, "expires_at": now + VIEW_AS_SECONDS, "write": write,
                    "workspace": {"id": row.id, "slug": row.slug, "name": row.name}}

    def _view_as(self, token: str, principal: Principal) -> dict[str, Any]:
        invalid = TenancyError("view_as_invalid", 403, "The «view as» session has ended")
        with self.db.session() as db:
            row = db.scalar(select(ImpersonationSession).where(
                ImpersonationSession.token_hash == _digest(token)))
            if row is None or row.revoked_at is not None or row.expires_at <= _now() \
                    or row.admin_user_id != principal.user_id:
                raise invalid
        # Re-checked every request: losing the permission ends the session at once.
        if not principal.allows("tenancy:admin") or (
                row.write and not principal.allows("tenancy:impersonate_write")):
            raise invalid
        return {"workspace_id": row.workspace_id, "write": bool(row.write),
                "expires_at": row.expires_at, "admin_user_id": row.admin_user_id}

    def end_view_as(self, principal: Principal, token: str | None) -> bool:
        if not token:
            return False
        with self.db.session() as db, db.begin():
            row = db.scalar(select(ImpersonationSession).where(
                ImpersonationSession.token_hash == _digest(token)))
            if row is None or row.admin_user_id != principal.user_id or row.revoked_at:
                return False
            row.revoked_at = _now()
            self.auth._audit_db(db, principal.user_id, "tenancy.view_as.end", "workspace",
                                row.workspace_id, "success", workspace_id=row.workspace_id)
            return True

    # ------------------------------------------------------------------ sign-ups
    def record_signup(self, user_id: int) -> None:
        with self.db.session() as db, db.begin():
            db.add(TenancySignup(id=f"su_{secrets.token_hex(8)}", user_id=user_id,
                                 status="pending", created_at=_now()))

    def list_signups(self, status: str | None) -> list[dict[str, Any]]:
        with self.db.session() as db:
            stmt = select(TenancySignup, User).join(User, User.id == TenancySignup.user_id)
            if status:
                stmt = stmt.where(TenancySignup.status == status)
            rows = db.execute(stmt.order_by(TenancySignup.created_at)).all()
            return [{"id": row.id, "status": row.status, "created_at": row.created_at,
                     "decided_at": row.decided_at,
                     "user": {"id": user.id, "username": user.username,
                              "display_name": user.display_name, "email": user.email}}
                    for row, user in rows]

    def decide_signup(self, signup_id: str, approve: bool, actor: int,
                      plan_id: Any = None) -> dict[str, Any]:
        if plan_id is not None and not isinstance(plan_id, str):
            raise _invalid("plan_id", "invalid_type", "Unknown plan")
        with self.db.session() as db, db.begin():
            row = db.get(TenancySignup, signup_id)
            if row is None or row.status != "pending":
                raise not_found()
            if plan_id is not None and db.get(TenancyPlan, plan_id) is None:
                raise _invalid("plan_id", "not_found", "Unknown plan")
            user = db.get(User, row.user_id)
            row.decided_at = _now()
            row.decided_by = actor
            user_id = row.user_id
            if approve:
                row.status = "approved"
                if user is not None:
                    user.enabled = True
                    user.updated_at = _now()
            else:
                row.status = "rejected"
            self.auth._audit_db(db, actor, f"tenancy.signup.{'approve' if approve else 'reject'}",
                                "user", str(user_id), "success")
            if not approve and user is not None:
                db.delete(user)
        if not approve:
            return {"status": "rejected"}
        return {"status": "approved", "workspace_id": self.ensure_personal(user_id, plan_id)}

    # ------------------------------------------------------------------ usage
    def db_usage(self, workspace_id: str) -> dict[str, int]:
        with self.db.session() as db:
            counts = dict(db.execute(
                select(ResourceOwner.kind, func.count())
                .where(ResourceOwner.workspace_id == workspace_id)
                .group_by(ResourceOwner.kind)).all())
            members = db.scalar(select(func.count()).select_from(WorkspaceMember).where(
                WorkspaceMember.workspace_id == workspace_id)) or 0
            row = db.get(Workspace, workspace_id)
            teams = 0
            if row is not None and row.kind == "personal":
                owner = db.scalar(select(WorkspaceMember.user_id).where(
                    WorkspaceMember.workspace_id == workspace_id,
                    WorkspaceMember.role == "owner"))
                teams = db.scalar(
                    select(func.count()).select_from(Workspace)
                    .join(WorkspaceMember, WorkspaceMember.workspace_id == Workspace.id)
                    .where(WorkspaceMember.user_id == owner, WorkspaceMember.role == "owner",
                           Workspace.kind == "team")) or 0
        return {
            "members": int(members), "workspaces_team": int(teams),
            "dns_zones": int(counts.get("dns_zone", 0)),
            "s3_buckets": int(counts.get("s3_bucket", 0)),
            "s3_keys": int(counts.get("s3_identity", 0)),
            "s3_bucket_domains": int(counts.get("bucket_domain", 0)),
            "api_tokens": self.active_tokens(workspace_id),
        }

    def audit(self, ctx: WorkspaceContext, action: str, object_type: str,
              object_id: str | None, result: str = "success",
              source_ip: str | None = None, request_id: str | None = None) -> None:
        self.auth.record_audit(
            ctx.user_id, action, object_type,
            None if object_id is None else object_id[:255], result, source_ip, request_id,
            workspace_id=ctx.workspace_id, on_behalf_of=ctx.on_behalf_of,
        )

    def activity(self, workspace_id: str, before_id: int | None, limit: int
                 ) -> list[dict[str, Any]]:
        items = self.auth.list_audit(limit, before_id=before_id, workspace_id=workspace_id,
                                     max_limit=200)
        ids = {item["actor_user_id"] for item in items if item["actor_user_id"] is not None}
        with self.db.session() as db:
            names = dict(db.execute(select(User.id, User.username).where(User.id.in_(ids))).all()) \
                if ids else {}
        return [{
            "id": item["id"], "actor_user_id": item["actor_user_id"],
            "actor_username": names.get(item["actor_user_id"]),
            "on_behalf_of": item["on_behalf_of"], "action": item["action"],
            "object_type": item["object_type"], "object_id": item["object_id"],
            "result": item["result"], "occurred_at": item["occurred_at"],
        } for item in items]


def _owner_item(row: ResourceOwner) -> dict[str, Any]:
    return {"kind": row.kind, "resource_id": row.resource_id, "workspace_id": row.workspace_id,
            "created_by": row.created_by, "created_at": row.created_at,
            "meta": dict(row.meta or {})}


def _member_item(member: WorkspaceMember, user: User | None) -> dict[str, Any]:
    return {"user_id": member.user_id, "role": member.role, "created_at": member.created_at,
            "username": user.username if user else None,
            "display_name": user.display_name if user else None,
            "email": user.email if user else None}


def _token_item(row: ApiToken, username: str | None) -> dict[str, Any]:
    return {"id": row.id, "name": row.name, "scopes": list(row.scopes),
            "workspace_id": row.workspace_id, "created_by": username,
            "expires_at": row.expires_at, "ip_allow": list(row.ip_allow or []),
            "last_used_at": row.last_used_at, "created_at": row.created_at}


def _ip_list(raw: Any) -> list[str]:
    if raw in (None, []):
        return []
    if not isinstance(raw, list) or len(raw) > MAX_IP_ALLOW:
        raise _invalid("ip_allow", "invalid_type", f"A list of up to {MAX_IP_ALLOW} addresses",
                       max_items=MAX_IP_ALLOW)
    out: list[str] = []
    for index, item in enumerate(raw):
        try:
            out.append(str(ipaddress.ip_network(str(item).strip(), strict=False)))
        except ValueError:
            raise _invalid(f"ip_allow.{index}", "invalid_format", "Not an IP or CIDR") from None
    return sorted(set(out))


def _ip_allowed(client_ip: str | None, networks: tuple[str, ...]) -> bool:
    if not client_ip:
        return False
    try:
        address = ipaddress.ip_address(client_ip)
    except ValueError:
        return False
    for item in networks:
        try:
            if address in ipaddress.ip_network(item, strict=False):
                return True
        except ValueError:
            continue
    return False


def local_address(client_ip: str | None) -> bool:
    """Loopback or private (RFC 1918, ULA, link-local): «admin area local only»."""
    if not client_ip:
        return False
    try:
        address = ipaddress.ip_address(client_ip)
    except ValueError:
        return client_ip == "localhost"
    return address.is_loopback or address.is_private or address.is_link_local
