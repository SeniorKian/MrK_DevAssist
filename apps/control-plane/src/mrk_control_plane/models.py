from __future__ import annotations

from typing import Any

from sqlalchemy import JSON, BigInteger, Boolean, Float, ForeignKey, Index, Integer, String, Text
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


class NotificationChannel(Base):
    """A delivery target (Telegram, Bale, email, webhook). Secrets live in SecretStore."""

    __tablename__ = "notification_channels"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    name: Mapped[str] = mapped_column(String(80), unique=True)
    kind: Mapped[str] = mapped_column(String(16), index=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    config: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    secret_ref: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[int] = mapped_column(Integer)
    updated_at: Mapped[int] = mapped_column(Integer)
    last_delivery_at: Mapped[int | None] = mapped_column(Integer)
    last_status: Mapped[str | None] = mapped_column(String(16))


class NotificationRule(Base):
    __tablename__ = "notification_rules"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    channel_id: Mapped[str] = mapped_column(
        ForeignKey("notification_channels.id", ondelete="CASCADE"), index=True
    )
    event_pattern: Mapped[str] = mapped_column(String(120))
    min_severity: Mapped[str] = mapped_column(String(16))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[int] = mapped_column(Integer)
    updated_at: Mapped[int] = mapped_column(Integer)


class NotificationDelivery(Base):
    """One event routed to one channel; persisted so restarts resume pending work."""

    __tablename__ = "notification_deliveries"
    __table_args__ = (
        Index("notification_deliveries_due_idx", "status", "next_attempt_at"),
        Index("notification_deliveries_dedupe_idx", "channel_id", "dedupe_hash", "created_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    channel_id: Mapped[str | None] = mapped_column(
        ForeignKey("notification_channels.id", ondelete="SET NULL")
    )
    channel_name: Mapped[str] = mapped_column(String(80))
    event_type: Mapped[str] = mapped_column(String(120))
    severity: Mapped[str] = mapped_column(String(16))
    module: Mapped[str] = mapped_column(String(64))
    title: Mapped[str] = mapped_column(String(300))
    message: Mapped[str] = mapped_column(Text, default="")
    details: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    dedupe_hash: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(16))
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    error_code: Mapped[str | None] = mapped_column(String(80))
    occurred_at: Mapped[int] = mapped_column(Integer)
    created_at: Mapped[int] = mapped_column(Integer, index=True)
    next_attempt_at: Mapped[int | None] = mapped_column(Integer)
    sent_at: Mapped[int | None] = mapped_column(Integer)


class _MetricColumns:
    """Shared columns for minute and hour resource metrics (Gate 17 monitoring).

    kind is "host" or "container"; scope is "host" or the container name (names
    survive container re-creation, ids do not). Every metric is nullable because
    the agent may not report it (no cgroup, first sample, counter reset).
    """

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    kind: Mapped[str] = mapped_column(String(16))
    scope: Mapped[str] = mapped_column(String(128))
    ts: Mapped[int] = mapped_column(Integer)
    samples: Mapped[int] = mapped_column(Integer, default=0)
    protected: Mapped[bool] = mapped_column(Boolean, default=False)
    cpu_percent: Mapped[float | None] = mapped_column(Float)
    cpu_max_percent: Mapped[float | None] = mapped_column(Float)
    mem_bytes: Mapped[int | None] = mapped_column(BigInteger)
    mem_limit_bytes: Mapped[int | None] = mapped_column(BigInteger)
    mem_percent: Mapped[float | None] = mapped_column(Float)
    disk_percent: Mapped[float | None] = mapped_column(Float)
    load1: Mapped[float | None] = mapped_column(Float)
    net_rx_bps: Mapped[float | None] = mapped_column(Float)
    net_tx_bps: Mapped[float | None] = mapped_column(Float)
    io_read_bps: Mapped[float | None] = mapped_column(Float)
    io_write_bps: Mapped[float | None] = mapped_column(Float)


class MetricMinute(_MetricColumns, Base):
    __tablename__ = "metric_minutes"
    __table_args__ = (
        Index("metric_minutes_scope_ts_idx", "scope", "ts"),
        Index("metric_minutes_kind_ts_idx", "kind", "ts"),
        Index("metric_minutes_ts_idx", "ts"),
    )


class MetricHour(_MetricColumns, Base):
    __tablename__ = "metric_hours"
    __table_args__ = (
        Index("metric_hours_scope_ts_idx", "scope", "ts"),
        Index("metric_hours_kind_ts_idx", "kind", "ts"),
        Index("metric_hours_ts_idx", "ts"),
    )


class S3Bucket(Base):
    """Gate 18 S3 bucket registry; the engine receives it through the config snapshot."""

    __tablename__ = "s3_buckets"

    name: Mapped[str] = mapped_column(String(63), primary_key=True)
    mode: Mapped[str] = mapped_column(String(16))
    link_path: Mapped[str | None] = mapped_column(String(4096))
    link_mode: Mapped[str] = mapped_column(String(8), default="rw")
    public_read: Mapped[bool] = mapped_column(Boolean, default=False)
    quota_bytes: Mapped[int | None] = mapped_column(BigInteger)
    created_by_user_id: Mapped[int | None] = mapped_column(Integer)
    created_at: Mapped[int] = mapped_column(Integer)
    updated_at: Mapped[int] = mapped_column(Integer)


class S3Identity(Base):
    """An S3 API identity (separate from panel users). Policy is the effective document."""

    __tablename__ = "s3_identities"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    name: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    policy_template: Mapped[str] = mapped_column(String(32))
    buckets: Mapped[list[str]] = mapped_column(JSON, default=list)
    policy: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_by_user_id: Mapped[int | None] = mapped_column(Integer)
    created_at: Mapped[int] = mapped_column(Integer)
    updated_at: Mapped[int] = mapped_column(Integer)

    keys: Mapped[list[S3AccessKey]] = relationship(
        back_populates="identity", cascade="all, delete-orphan", order_by="S3AccessKey.created_at"
    )


class S3AccessKey(Base):
    """Access key metadata; the secret lives only in SecretStore under ``secret_ref``."""

    __tablename__ = "s3_access_keys"

    access_key_id: Mapped[str] = mapped_column(String(20), primary_key=True)
    identity_id: Mapped[str] = mapped_column(
        ForeignKey("s3_identities.id", ondelete="CASCADE"), index=True
    )
    secret_ref: Mapped[str] = mapped_column(String(64))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[int] = mapped_column(Integer)
    last_used_at: Mapped[int | None] = mapped_column(Integer)

    identity: Mapped[S3Identity] = relationship(back_populates="keys")


class ServerBackupDestination(Base):
    """Where server backup artifacts go (Gate 18 S6). Secrets live in SecretStore."""

    __tablename__ = "server_backup_destinations"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    name: Mapped[str] = mapped_column(String(80), unique=True, index=True)
    kind: Mapped[str] = mapped_column(String(16))
    config: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    secret_ref: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[int] = mapped_column(Integer)
    updated_at: Mapped[int] = mapped_column(Integer)


class ServerBackupJob(Base):
    __tablename__ = "server_backup_jobs"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    name: Mapped[str] = mapped_column(String(80), unique=True, index=True)
    source: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    destination_id: Mapped[str] = mapped_column(
        ForeignKey("server_backup_destinations.id", ondelete="RESTRICT"), index=True
    )
    schedule: Mapped[str] = mapped_column(String(120))
    retention: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    key_ref: Mapped[str] = mapped_column(String(64))
    next_run_at: Mapped[int | None] = mapped_column(Integer)
    created_at: Mapped[int] = mapped_column(Integer)
    updated_at: Mapped[int] = mapped_column(Integer)


class ServerBackupRun(Base):
    __tablename__ = "server_backup_runs"
    __table_args__ = (Index("server_backup_runs_job_started_idx", "job_id", "started_at"),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    job_id: Mapped[str] = mapped_column(
        ForeignKey("server_backup_jobs.id", ondelete="CASCADE"), index=True
    )
    destination_id: Mapped[str] = mapped_column(String(32))
    trigger: Mapped[str] = mapped_column(String(16))
    state: Mapped[str] = mapped_column(String(16), index=True)
    started_at: Mapped[int] = mapped_column(Integer)
    finished_at: Mapped[int | None] = mapped_column(Integer)
    bytes: Mapped[int | None] = mapped_column(BigInteger)
    source_bytes: Mapped[int | None] = mapped_column(BigInteger)
    sha256: Mapped[str | None] = mapped_column(String(64))
    object_key: Mapped[str | None] = mapped_column(String(1024))
    error_code: Mapped[str | None] = mapped_column(String(80))
    details: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)


class FirewallRule(Base):
    """A threshold rule: N signals of the given kinds from one IP inside a window (S7)."""

    __tablename__ = "firewall_rules"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    name: Mapped[str] = mapped_column(String(80), unique=True, index=True)
    signal_kinds: Mapped[list[str]] = mapped_column(JSON, default=list)
    threshold: Mapped[int] = mapped_column(Integer)
    window_seconds: Mapped[int] = mapped_column(Integer)
    ban_seconds: Mapped[int] = mapped_column(Integer)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    builtin: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[int] = mapped_column(Integer)
    updated_at: Mapped[int] = mapped_column(Integer)


class FirewallBlock(Base):
    """A desired block. Active = removed_at is NULL and not expired; simulated = dry-run."""

    __tablename__ = "firewall_blocks"
    __table_args__ = (Index("firewall_blocks_active_idx", "removed_at", "expires_at"),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    cidr: Mapped[str] = mapped_column(String(64), index=True)
    origin: Mapped[str] = mapped_column(String(16))
    rule_id: Mapped[str | None] = mapped_column(String(32))
    reason: Mapped[str] = mapped_column(String(500), default="")
    simulated: Mapped[bool] = mapped_column(Boolean, default=False)
    created_by_user_id: Mapped[int | None] = mapped_column(Integer)
    created_at: Mapped[int] = mapped_column(Integer)
    expires_at: Mapped[int | None] = mapped_column(Integer)
    removed_at: Mapped[int | None] = mapped_column(Integer)
    removed_reason: Mapped[str | None] = mapped_column(String(32))


class FirewallDecision(Base):
    """Decision history (block, would_block, skipped, unblock, expire, clear, mode)."""

    __tablename__ = "firewall_decisions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    occurred_at: Mapped[int] = mapped_column(Integer, index=True)
    action: Mapped[str] = mapped_column(String(24), index=True)
    ip: Mapped[str | None] = mapped_column(String(64), index=True)
    rule_id: Mapped[str | None] = mapped_column(String(32))
    mode: Mapped[str] = mapped_column(String(16))
    reason: Mapped[str] = mapped_column(String(500), default="")
    actor_user_id: Mapped[int | None] = mapped_column(Integer)
    details: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)


class VulnIgnore(Base):
    """Vulnerability scanner ignore rule (Gate 19 S8). Patterns are fnmatch globs."""

    __tablename__ = "vuln_ignores"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    advisory: Mapped[str | None] = mapped_column(String(128))
    package: Mapped[str | None] = mapped_column(String(200))
    image: Mapped[str | None] = mapped_column(String(255))
    reason: Mapped[str] = mapped_column(String(500))
    expires_at: Mapped[int | None] = mapped_column(Integer, index=True)
    created_at: Mapped[int] = mapped_column(Integer)
    created_by: Mapped[int | None] = mapped_column(Integer)


class DbAdminConnection(Base):
    """A saved database connection for the dbadmin module (Gate 19 S9).

    The password lives only in SecretStore under ``secret_ref`` (write-only API).
    """

    __tablename__ = "dbadmin_connections"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    name: Mapped[str] = mapped_column(String(80), unique=True, index=True)
    engine: Mapped[str] = mapped_column(String(16))
    host: Mapped[str] = mapped_column(String(255))
    port: Mapped[int] = mapped_column(Integer)
    database: Mapped[str | None] = mapped_column(String(128))
    username: Mapped[str | None] = mapped_column(String(128))
    tls_mode: Mapped[str] = mapped_column(String(16), default="disable")
    options: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    secret_ref: Mapped[str | None] = mapped_column(String(64))
    created_by_user_id: Mapped[int | None] = mapped_column(Integer)
    created_at: Mapped[int] = mapped_column(Integer)
    updated_at: Mapped[int] = mapped_column(Integer)
    last_tested_at: Mapped[int | None] = mapped_column(Integer)
    last_test_ok: Mapped[bool | None] = mapped_column(Boolean)


class CustomRole(Base):
    """An owner-defined role (docs/33 §5.3). Users reference it as ``custom:<id>``.

    Built-in roles stay in code (auth.ROLE_PERMISSIONS) and are immutable; a
    custom role never holds ``*``.
    """

    __tablename__ = "custom_roles"

    id: Mapped[str] = mapped_column(String(24), primary_key=True)
    name: Mapped[str] = mapped_column(String(80), unique=True, index=True)
    description: Mapped[str] = mapped_column(String(500), default="")
    permissions: Mapped[list[str]] = mapped_column(JSON, default=list)
    created_by_user_id: Mapped[int | None] = mapped_column(Integer)
    updated_by_user_id: Mapped[int | None] = mapped_column(Integer)
    created_at: Mapped[int] = mapped_column(Integer)
    updated_at: Mapped[int] = mapped_column(Integer)


class UserPasswordState(Base):
    """Per-user password lifecycle flags (``must_change_password`` after an invite)."""

    __tablename__ = "user_password_states"

    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), primary_key=True
    )
    must_change_password: Mapped[bool] = mapped_column(Boolean, default=False)
    reason: Mapped[str | None] = mapped_column(String(32))
    set_at: Mapped[int | None] = mapped_column(Integer)
    changed_at: Mapped[int | None] = mapped_column(Integer)


class UserInvite(Base):
    """Single-use invite link; only the SHA-256 of the token is stored."""

    __tablename__ = "user_invites"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    created_by_user_id: Mapped[int | None] = mapped_column(Integer)
    created_at: Mapped[int] = mapped_column(Integer)
    expires_at: Mapped[int] = mapped_column(Integer, index=True)
    used_at: Mapped[int | None] = mapped_column(Integer)
    revoked_at: Mapped[int | None] = mapped_column(Integer)
