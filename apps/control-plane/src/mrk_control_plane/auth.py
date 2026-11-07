from __future__ import annotations

import hashlib
import re
import secrets
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from sqlalchemy import func, or_, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session as OrmSession

from .database import Database
from .models import ApiToken, AuditEvent, SystemSetting, User
from .models import Session as LoginSession

ROLE_PERMISSIONS: Final[dict[str, frozenset[str]]] = {
    "owner": frozenset({"*"}),
    "admin": frozenset(
        {
            "system:read", "upstream:read", "upstream:write", "upstream:operate",
            "cache:read", "cache:write", "task:read", "task:write", "audit:read",
            "user:read", "user:write", "token:read", "token:write", "backup:read",
            "backup:write",
        }
    ),
    "operator": frozenset(
        {
            "system:read", "upstream:read", "upstream:operate", "cache:read",
            "cache:write", "task:read", "task:write", "audit:read", "backup:read",
        }
    ),
    "developer": frozenset(
        {"system:read", "upstream:read", "cache:read", "task:read", "token:read", "token:write"}
    ),
    "viewer": frozenset(
        {"system:read", "upstream:read", "cache:read", "task:read", "audit:read"}
    ),
}


@dataclass(frozen=True, slots=True)
class Principal:
    user_id: int
    username: str
    role: str
    permissions: frozenset[str]
    session_id: int | None
    csrf_hash: str
    token_id: int | None = None
    display_name: str | None = None
    email: str | None = None

    def allows(self, permission: str) -> bool:
        return "*" in self.permissions or permission in self.permissions


class AuthStore:
    def __init__(
        self,
        data_dir: Path,
        session_ttl_seconds: int = 28800,
        database: Database | None = None,
    ) -> None:
        self.root = data_dir / "control-plane"
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.session_ttl_seconds = session_ttl_seconds
        self.hasher = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2)
        self._dummy_password_hash = self.hasher.hash(secrets.token_urlsafe(32))
        self._lock = threading.RLock()
        self._attempts: dict[str, list[float]] = {}
        self.db = database or Database(data_dir)
        self.db.initialize()

    @staticmethod
    def _digest(value: str) -> str:
        return hashlib.sha256(value.encode("utf-8")).hexdigest()

    @staticmethod
    def validate_username(username: str) -> str:
        normalized = username.strip().lower()
        if not 3 <= len(normalized) <= 64 or not all(
            item.isalnum() or item in "._-" for item in normalized
        ):
            raise ValueError("username must be 3-64 safe characters")
        return normalized

    @staticmethod
    def validate_password(password: str) -> None:
        if len(password) < 14 or len(password) > 256:
            raise ValueError("password must be between 14 and 256 characters")

    @staticmethod
    def validate_display_name(display_name: str) -> str:
        normalized = " ".join(display_name.strip().split())
        if not 2 <= len(normalized) <= 100:
            raise ValueError("display name must be between 2 and 100 characters")
        return normalized

    @staticmethod
    def validate_email(email: str) -> str:
        normalized = email.strip().lower()
        if len(normalized) > 254 or re.fullmatch(
            r"[^@\s]{1,64}@[^@\s]{1,189}", normalized
        ) is None:
            raise ValueError("invalid email")
        return normalized

    def has_users(self) -> bool:
        with self.db.session() as db:
            return db.scalar(select(User.id).limit(1)) is not None

    def setup_owner(
        self,
        display_name: str,
        email: str,
        password: str,
        source_ip: str | None,
        request_id: str | None,
    ) -> str:
        key = f"setup:{source_ip or '-'}"
        with self._lock:
            if self.has_users():
                raise ValueError("instance is already initialized")
            if self._rate_limited(key):
                raise ValueError("setup is rate limited")
            normalized_name = self.validate_display_name(display_name)
            normalized_email = self.validate_email(email)
            self.validate_password(password)
            local_part = re.sub(r"[^a-z0-9._-]+", "-", normalized_email.split("@", 1)[0])
            username = local_part.strip("-._")[:48]
            if len(username) < 3:
                username = "owner"
            now = int(time.time())
            try:
                with self.db.session() as db, db.begin():
                    if db.scalar(select(User.id).limit(1)) is not None:
                        raise ValueError("instance is already initialized")
                    db.add(
                        SystemSetting(
                            key="instance_initialized",
                            value={"initialized": True},
                            updated_at=now,
                            updated_by_user_id=None,
                        )
                    )
                    owner = User(
                        username=username,
                        password_hash=self.hasher.hash(password),
                        role="owner",
                        enabled=True,
                        display_name=normalized_name,
                        email=normalized_email,
                        identity_provider="local",
                        mfa_enabled=False,
                        created_at=now,
                        updated_at=now,
                    )
                    db.add(owner)
                    db.flush()
                    self._audit_db(
                        db,
                        owner.id,
                        "auth.setup",
                        "instance",
                        "owner",
                        "success",
                        source_ip,
                        request_id,
                    )
            except IntegrityError as exc:
                raise ValueError("instance is already initialized") from exc
            self._attempts.pop(key, None)
            return normalized_email

    def public_registration_enabled(self) -> bool:
        with self.db.session() as db:
            setting = db.get(SystemSetting, "public_registration")
            return bool(setting and setting.value.get("enabled") is True)

    def set_public_registration(self, enabled: bool, actor_user_id: int) -> bool:
        now = int(time.time())
        with self.db.session() as db, db.begin():
            setting = db.get(SystemSetting, "public_registration")
            if setting is None:
                setting = SystemSetting(
                    key="public_registration",
                    value={"enabled": enabled, "default_role": "viewer"},
                    updated_at=now,
                    updated_by_user_id=actor_user_id,
                )
                db.add(setting)
            else:
                setting.value = {"enabled": enabled, "default_role": "viewer"}
                setting.updated_at = now
                setting.updated_by_user_id = actor_user_id
            self._audit_db(
                db,
                actor_user_id,
                "registration.policy.update",
                "system_setting",
                "public_registration",
                "success",
            )
        return enabled

    def register_public_user(
        self,
        display_name: str,
        email: str,
        password: str,
        source_ip: str | None,
        request_id: str | None,
    ) -> str:
        key = f"register:{source_ip or '-'}"
        with self._lock:
            if not self.public_registration_enabled():
                raise ValueError("public registration is disabled")
            if self._rate_limited(key):
                raise ValueError("registration is rate limited")
            normalized_name = self.validate_display_name(display_name)
            normalized_email = self.validate_email(email)
            local_part = re.sub(
                r"[^a-z0-9._-]+", "-", normalized_email.split("@", 1)[0]
            )
            username = local_part.strip("-._")[:42]
            if len(username) < 3:
                username = "user"
            username = f"{username}-{secrets.token_hex(3)}"
            try:
                user_id = self.create_user(
                    username,
                    password,
                    "viewer",
                    actor_user_id=None,
                    display_name=normalized_name,
                    email=normalized_email,
                )
            except ValueError:
                self._attempts.setdefault(key, []).append(time.monotonic())
                raise
            self.record_audit(
                user_id,
                "auth.register",
                "user",
                str(user_id),
                "success",
                source_ip,
                request_id,
            )
            self._attempts.pop(key, None)
            return normalized_email

    def create_user(
        self,
        username: str,
        password: str,
        role: str,
        actor_user_id: int | None,
        display_name: str | None = None,
        email: str | None = None,
    ) -> int:
        normalized = self.validate_username(username)
        self.validate_password(password)
        normalized_name = self.validate_display_name(display_name) if display_name else None
        normalized_email = self.validate_email(email) if email else None
        if role not in ROLE_PERMISSIONS:
            raise ValueError("unknown role")
        now = int(time.time())
        try:
            with self.db.session() as db, db.begin():
                user = User(
                    username=normalized,
                    password_hash=self.hasher.hash(password),
                    role=role,
                    enabled=True,
                    display_name=normalized_name,
                    email=normalized_email,
                    identity_provider="local",
                    mfa_enabled=False,
                    created_at=now,
                    updated_at=now,
                )
                db.add(user)
                db.flush()
                self._audit_db(
                    db, actor_user_id, "user.create", "user", str(user.id), "success"
                )
                return int(user.id)
        except IntegrityError as exc:
            raise ValueError("username or email already exists") from exc

    def _rate_limited(self, key: str) -> bool:
        now = time.monotonic()
        recent = [item for item in self._attempts.get(key, []) if item > now - 300]
        self._attempts[key] = recent
        return len(recent) >= 5

    @staticmethod
    def _principal(
        user: User,
        session_id: int | None,
        csrf_hash: str,
        token_id: int | None = None,
        permissions: frozenset[str] | None = None,
    ) -> Principal:
        return Principal(
            int(user.id), user.username, user.role, permissions or ROLE_PERMISSIONS[user.role],
            session_id, csrf_hash, token_id, user.display_name, user.email,
        )

    def authenticate(
        self, username: str, password: str, source_ip: str | None, request_id: str | None
    ) -> tuple[str, str, Principal] | None:
        normalized = username.strip().lower()
        key = f"{source_ip or '-'}:{normalized}"
        if self._rate_limited(key):
            self.record_audit(
                None, "auth.login", "session", None, "rate_limited", source_ip, request_id
            )
            return None
        with self.db.session() as db, db.begin():
            user = db.scalar(
                select(User).where(or_(User.username == normalized, User.email == normalized))
            )
            valid = False
            if user is not None and user.enabled:
                try:
                    valid = self.hasher.verify(user.password_hash, password)
                except (VerifyMismatchError, InvalidHashError):
                    valid = False
            else:
                try:
                    self.hasher.verify(self._dummy_password_hash, password)
                except (VerifyMismatchError, InvalidHashError):
                    pass
            if not valid or user is None:
                self._attempts.setdefault(key, []).append(time.monotonic())
                self._audit_db(
                    db, None, "auth.login", "session", None, "failure", source_ip, request_id
                )
                return None
            self._attempts.pop(key, None)
            now = int(time.time())
            user.last_login_at = now
            user.updated_at = now
            token = secrets.token_urlsafe(32)
            csrf = secrets.token_urlsafe(24)
            login_session = LoginSession(
                user_id=user.id,
                token_hash=self._digest(token),
                csrf_hash=self._digest(csrf),
                created_at=now,
                expires_at=now + self.session_ttl_seconds,
            )
            db.add(login_session)
            db.flush()
            self._audit_db(
                db, user.id, "auth.login", "session", str(login_session.id), "success",
                source_ip, request_id,
            )
            return token, csrf, self._principal(
                user, int(login_session.id), login_session.csrf_hash
            )

    def principal_for_token(self, token: str | None) -> Principal | None:
        if not token:
            return None
        now = int(time.time())
        with self.db.session() as db:
            row = db.execute(
                select(LoginSession, User)
                .join(User, User.id == LoginSession.user_id)
                .where(
                    LoginSession.token_hash == self._digest(token),
                    LoginSession.revoked_at.is_(None), LoginSession.expires_at > now,
                )
            ).first()
            if row is None:
                return None
            login_session, user = row
            if not user.enabled or user.role not in ROLE_PERMISSIONS:
                return None
            return self._principal(user, int(login_session.id), login_session.csrf_hash)

    def verify_csrf(self, principal: Principal, token: str | None) -> bool:
        return bool(token) and secrets.compare_digest(principal.csrf_hash, self._digest(token))

    def issue_csrf(self, principal: Principal) -> str:
        if principal.session_id is None:
            raise ValueError("CSRF tokens are only available for browser sessions")
        csrf = secrets.token_urlsafe(24)
        with self.db.session() as db, db.begin():
            db.execute(
                update(LoginSession)
                .where(LoginSession.id == principal.session_id, LoginSession.revoked_at.is_(None))
                .values(csrf_hash=self._digest(csrf))
            )
        return csrf

    def principal_for_api_token(self, token: str | None) -> Principal | None:
        if not token or not token.startswith("mrk_"):
            return None
        now = int(time.time())
        with self.db.session() as db, db.begin():
            row = db.execute(
                select(ApiToken, User)
                .join(User, User.id == ApiToken.user_id)
                .where(
                    ApiToken.token_hash == self._digest(token), ApiToken.revoked_at.is_(None),
                    ApiToken.expires_at > now,
                )
            ).first()
            if row is None:
                return None
            api_token, user = row
            if not user.enabled or user.role not in ROLE_PERMISSIONS:
                return None
            api_token.last_used_at = now
            requested = frozenset(api_token.scopes)
            role_permissions = ROLE_PERMISSIONS[user.role]
            permissions = requested if "*" in role_permissions else requested & role_permissions
            return self._principal(user, None, "", int(api_token.id), permissions)

    def update_user(
        self, user_id: int, role: str | None, enabled: bool | None, actor_user_id: int
    ) -> None:
        if role is not None and role not in ROLE_PERMISSIONS:
            raise ValueError("unknown role")
        now = int(time.time())
        with self.db.session() as db, db.begin():
            user = db.get(User, user_id)
            if user is None:
                raise ValueError("user not found")
            next_role = role if role is not None else user.role
            next_enabled = enabled if enabled is not None else user.enabled
            if user.role == "owner" and (next_role != "owner" or not next_enabled):
                owners = db.scalar(
                    select(func.count()).select_from(User).where(
                        User.role == "owner", User.enabled.is_(True)
                    )
                )
                if int(owners or 0) <= 1:
                    raise ValueError("the last enabled owner cannot be changed")
            user.role = next_role
            user.enabled = next_enabled
            user.updated_at = now
            db.execute(
                update(LoginSession)
                .where(LoginSession.user_id == user_id, LoginSession.revoked_at.is_(None))
                .values(revoked_at=now)
            )
            db.execute(
                update(ApiToken)
                .where(ApiToken.user_id == user_id, ApiToken.revoked_at.is_(None))
                .values(revoked_at=now)
            )
            self._audit_db(db, actor_user_id, "user.update", "user", str(user_id), "success")

    def create_api_token(
        self, user_id: int, name: str, scopes: list[str], expires_in_seconds: int
    ) -> tuple[int, str]:
        normalized_name = name.strip()
        if not 3 <= len(normalized_name) <= 80:
            raise ValueError("token name must be between 3 and 80 characters")
        if not 900 <= expires_in_seconds <= 31536000:
            raise ValueError("token expiry must be between 15 minutes and 365 days")
        if not scopes:
            raise ValueError("at least one scope is required")
        with self.db.session() as db, db.begin():
            user = db.get(User, user_id)
            if user is None or user.role not in ROLE_PERMISSIONS:
                raise ValueError("user not found")
            role_permissions = ROLE_PERMISSIONS[user.role]
            if "*" not in role_permissions and not set(scopes).issubset(role_permissions):
                raise ValueError("token scope exceeds role permissions")
            token = f"mrk_{secrets.token_urlsafe(32)}"
            now = int(time.time())
            api_token = ApiToken(
                user_id=user_id, name=normalized_name, token_hash=self._digest(token),
                scopes=sorted(set(scopes)), created_at=now,
                expires_at=now + expires_in_seconds,
            )
            db.add(api_token)
            db.flush()
            self._audit_db(
                db, user_id, "token.create", "api_token", str(api_token.id), "success"
            )
            return int(api_token.id), token

    def list_api_tokens(self, user_id: int) -> list[dict[str, object]]:
        with self.db.session() as db:
            rows = db.scalars(
                select(ApiToken).where(ApiToken.user_id == user_id).order_by(ApiToken.id.desc())
            ).all()
            return [
                {
                    "id": row.id, "name": row.name, "scopes": list(row.scopes),
                    "created_at": row.created_at, "expires_at": row.expires_at,
                    "last_used_at": row.last_used_at, "revoked_at": row.revoked_at,
                }
                for row in rows
            ]

    def revoke_api_token(self, token_id: int, user_id: int) -> bool:
        now = int(time.time())
        with self.db.session() as db, db.begin():
            result = db.execute(
                update(ApiToken)
                .where(
                    ApiToken.id == token_id, ApiToken.user_id == user_id,
                    ApiToken.revoked_at.is_(None),
                )
                .values(revoked_at=now)
            )
            changed = bool(result.rowcount)
            if changed:
                self._audit_db(
                    db, user_id, "token.revoke", "api_token", str(token_id), "success"
                )
            return changed

    def revoke_session(self, session_id: int, actor_user_id: int, request_id: str | None) -> None:
        now = int(time.time())
        with self.db.session() as db, db.begin():
            db.execute(
                update(LoginSession)
                .where(LoginSession.id == session_id)
                .values(revoked_at=now)
            )
            self._audit_db(
                db, actor_user_id, "auth.logout", "session", str(session_id), "success",
                request_id=request_id,
            )

    def rotate_session(self, principal: Principal) -> tuple[str, str]:
        token = secrets.token_urlsafe(32)
        csrf = secrets.token_urlsafe(24)
        now = int(time.time())
        with self.db.session() as db, db.begin():
            db.execute(
                update(LoginSession)
                .where(LoginSession.id == principal.session_id, LoginSession.revoked_at.is_(None))
                .values(
                    token_hash=self._digest(token), csrf_hash=self._digest(csrf),
                    expires_at=now + self.session_ttl_seconds,
                )
            )
            self._audit_db(
                db, principal.user_id, "auth.refresh", "session",
                str(principal.session_id), "success",
            )
        return token, csrf

    def list_users(self) -> list[dict[str, object]]:
        with self.db.session() as db:
            rows = db.scalars(select(User).order_by(User.username)).all()
            return [
                {
                    "id": row.id, "username": row.username, "display_name": row.display_name,
                    "email": row.email, "role": row.role, "enabled": row.enabled,
                    "identity_provider": row.identity_provider, "mfa_enabled": row.mfa_enabled,
                    "created_at": row.created_at, "last_login_at": row.last_login_at,
                }
                for row in rows
            ]

    def list_audit(self, limit: int = 100) -> list[dict[str, object]]:
        with self.db.session() as db:
            rows = db.scalars(
                select(AuditEvent).order_by(AuditEvent.id.desc()).limit(min(max(limit, 1), 500))
            ).all()
            return [
                {
                    "id": row.id, "actor_user_id": row.actor_user_id, "action": row.action,
                    "object_type": row.object_type, "object_id": row.object_id,
                    "result": row.result, "source_ip": row.source_ip,
                    "request_id": row.request_id, "occurred_at": row.occurred_at,
                }
                for row in rows
            ]

    def record_audit(
        self,
        actor_user_id: int | None,
        action: str,
        object_type: str,
        object_id: str | None,
        result: str = "success",
        source_ip: str | None = None,
        request_id: str | None = None,
    ) -> None:
        with self.db.session() as db, db.begin():
            self._audit_db(
                db, actor_user_id, action, object_type, object_id, result, source_ip, request_id
            )

    @staticmethod
    def _audit_db(
        db: OrmSession,
        actor_user_id: int | None,
        action: str,
        object_type: str,
        object_id: str | None,
        result: str,
        source_ip: str | None = None,
        request_id: str | None = None,
    ) -> None:
        db.add(
            AuditEvent(
                actor_user_id=actor_user_id, action=action, object_type=object_type,
                object_id=object_id, result=result, source_ip=source_ip,
                request_id=request_id, occurred_at=int(time.time()),
            )
        )
