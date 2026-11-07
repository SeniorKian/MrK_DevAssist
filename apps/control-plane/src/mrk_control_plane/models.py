from __future__ import annotations

from typing import Any

from sqlalchemy import JSON, Boolean, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    display_name: Mapped[str | None] = mapped_column(String(100))
    email: Mapped[str | None] = mapped_column(String(254), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(Text)
    role: Mapped[str] = mapped_column(String(32), index=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    identity_provider: Mapped[str] = mapped_column(String(32), default="local")
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[int] = mapped_column(Integer)
    updated_at: Mapped[int] = mapped_column(Integer)
    last_login_at: Mapped[int | None] = mapped_column(Integer)

    sessions: Mapped[list[Session]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )
    api_tokens: Mapped[list[ApiToken]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )


class Session(Base):
    __tablename__ = "sessions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    csrf_hash: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[int] = mapped_column(Integer)
    expires_at: Mapped[int] = mapped_column(Integer, index=True)
    revoked_at: Mapped[int | None] = mapped_column(Integer)

    user: Mapped[User] = relationship(back_populates="sessions")


class AuditEvent(Base):
    __tablename__ = "audit_events"
    __table_args__ = (Index("audit_occurred_at_idx", "occurred_at"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    actor_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), index=True
    )
    action: Mapped[str] = mapped_column(String(120), index=True)
    object_type: Mapped[str] = mapped_column(String(80))
    object_id: Mapped[str | None] = mapped_column(String(255))
    result: Mapped[str] = mapped_column(String(32))
    source_ip: Mapped[str | None] = mapped_column(String(64))
    request_id: Mapped[str | None] = mapped_column(String(128), index=True)
    occurred_at: Mapped[int] = mapped_column(Integer, index=True)


class ApiToken(Base):
    __tablename__ = "api_tokens"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    name: Mapped[str] = mapped_column(String(80))
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    scopes: Mapped[list[str]] = mapped_column(JSON)
    created_at: Mapped[int] = mapped_column(Integer)
    expires_at: Mapped[int] = mapped_column(Integer, index=True)
    last_used_at: Mapped[int | None] = mapped_column(Integer)
    revoked_at: Mapped[int | None] = mapped_column(Integer)

    user: Mapped[User] = relationship(back_populates="api_tokens")


class Task(Base):
    __tablename__ = "tasks"
    __table_args__ = (Index("tasks_created_idx", "created_at"),)

    id: Mapped[str] = mapped_column(String(48), primary_key=True)
    kind: Mapped[str] = mapped_column(String(80), index=True)
    state: Mapped[str] = mapped_column(String(32), index=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON)
    actor_user_id: Mapped[int] = mapped_column(Integer, index=True)
    progress: Mapped[int] = mapped_column(Integer, default=0)
    result: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    error_code: Mapped[str | None] = mapped_column(String(120))
    created_at: Mapped[int] = mapped_column(Integer)
    started_at: Mapped[int | None] = mapped_column(Integer)
    finished_at: Mapped[int | None] = mapped_column(Integer)
    cancel_requested: Mapped[bool] = mapped_column(Boolean, default=False)
    retry_of: Mapped[str | None] = mapped_column(String(48), index=True)


class ServiceModule(Base):
    """Installed control-plane module metadata for future DNS/uptime/server features."""

    __tablename__ = "service_modules"

    key: Mapped[str] = mapped_column(String(80), primary_key=True)
    display_name: Mapped[str] = mapped_column(String(120))
    schema_version: Mapped[int] = mapped_column(Integer, default=1)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    settings: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[int] = mapped_column(Integer)
    updated_at: Mapped[int] = mapped_column(Integer)


class SystemSetting(Base):
    __tablename__ = "system_settings"

    key: Mapped[str] = mapped_column(String(120), primary_key=True)
    value: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    updated_at: Mapped[int] = mapped_column(Integer)
    updated_by_user_id: Mapped[int | None] = mapped_column(Integer)


class UpstreamHealthCheck(Base):
    __tablename__ = "upstream_health_checks"
    __table_args__ = (
        Index("upstream_health_timeline_idx", "upstream_id", "checked_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    upstream_id: Mapped[str] = mapped_column(String(64), index=True)
    ecosystem: Mapped[str] = mapped_column(String(16), index=True)
    upstream_name: Mapped[str] = mapped_column(String(80))
    ok: Mapped[bool] = mapped_column(Boolean, index=True)
    stages: Mapped[list[dict[str, Any]]] = mapped_column(JSON)
    total_latency_ms: Mapped[int] = mapped_column(Integer)
    actor_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), index=True
    )
    checked_at: Mapped[int] = mapped_column(Integer, index=True)
