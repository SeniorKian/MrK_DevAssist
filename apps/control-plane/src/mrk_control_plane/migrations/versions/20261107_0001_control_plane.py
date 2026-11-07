"""Create the modular control-plane schema."""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "20261107_0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("username", sa.String(64), nullable=False),
        sa.Column("display_name", sa.String(100)),
        sa.Column("email", sa.String(254)),
        sa.Column("password_hash", sa.Text(), nullable=False),
        sa.Column("role", sa.String(32), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("identity_provider", sa.String(32), nullable=False),
        sa.Column("mfa_enabled", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.Integer(), nullable=False),
        sa.Column("updated_at", sa.Integer(), nullable=False),
        sa.Column("last_login_at", sa.Integer()),
        sa.UniqueConstraint("username"),
        sa.UniqueConstraint("email"),
    )
    op.create_index("ix_users_username", "users", ["username"])
    op.create_index("ix_users_email", "users", ["email"])
    op.create_index("ix_users_role", "users", ["role"])
    op.create_table(
        "sessions",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "user_id",
            sa.Integer(),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("token_hash", sa.String(64), nullable=False, unique=True),
        sa.Column("csrf_hash", sa.String(64), nullable=False),
        sa.Column("created_at", sa.Integer(), nullable=False),
        sa.Column("expires_at", sa.Integer(), nullable=False),
        sa.Column("revoked_at", sa.Integer()),
    )
    op.create_index("ix_sessions_user_id", "sessions", ["user_id"])
    op.create_index("ix_sessions_token_hash", "sessions", ["token_hash"])
    op.create_index("ix_sessions_expires_at", "sessions", ["expires_at"])
    op.create_table(
        "audit_events",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("actor_user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL")),
        sa.Column("action", sa.String(120), nullable=False),
        sa.Column("object_type", sa.String(80), nullable=False),
        sa.Column("object_id", sa.String(255)),
        sa.Column("result", sa.String(32), nullable=False),
        sa.Column("source_ip", sa.String(64)),
        sa.Column("request_id", sa.String(128)),
        sa.Column("occurred_at", sa.Integer(), nullable=False),
    )
    op.create_index("ix_audit_events_actor_user_id", "audit_events", ["actor_user_id"])
    op.create_index("ix_audit_events_action", "audit_events", ["action"])
    op.create_index("ix_audit_events_request_id", "audit_events", ["request_id"])
    op.create_index("ix_audit_events_occurred_at", "audit_events", ["occurred_at"])
    op.create_index("audit_occurred_at_idx", "audit_events", ["occurred_at"])
    op.create_table(
        "api_tokens",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "user_id",
            sa.Integer(),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("name", sa.String(80), nullable=False),
        sa.Column("token_hash", sa.String(64), nullable=False, unique=True),
        sa.Column("scopes", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.Integer(), nullable=False),
        sa.Column("expires_at", sa.Integer(), nullable=False),
        sa.Column("last_used_at", sa.Integer()),
        sa.Column("revoked_at", sa.Integer()),
    )
    op.create_index("ix_api_tokens_user_id", "api_tokens", ["user_id"])
    op.create_index("ix_api_tokens_token_hash", "api_tokens", ["token_hash"])
    op.create_index("ix_api_tokens_expires_at", "api_tokens", ["expires_at"])
    op.create_table(
        "tasks",
        sa.Column("id", sa.String(48), primary_key=True),
        sa.Column("kind", sa.String(80), nullable=False),
        sa.Column("state", sa.String(32), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("actor_user_id", sa.Integer(), nullable=False),
        sa.Column("progress", sa.Integer(), nullable=False),
        sa.Column("result", sa.JSON()),
        sa.Column("error_code", sa.String(120)),
        sa.Column("created_at", sa.Integer(), nullable=False),
        sa.Column("started_at", sa.Integer()),
        sa.Column("finished_at", sa.Integer()),
        sa.Column("cancel_requested", sa.Boolean(), nullable=False),
        sa.Column("retry_of", sa.String(48)),
    )
    op.create_index("ix_tasks_kind", "tasks", ["kind"])
    op.create_index("ix_tasks_state", "tasks", ["state"])
    op.create_index("ix_tasks_actor_user_id", "tasks", ["actor_user_id"])
    op.create_index("ix_tasks_retry_of", "tasks", ["retry_of"])
    op.create_index("tasks_created_idx", "tasks", ["created_at"])
    op.create_table(
        "service_modules",
        sa.Column("key", sa.String(80), primary_key=True),
        sa.Column("display_name", sa.String(120), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("settings", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.Integer(), nullable=False),
        sa.Column("updated_at", sa.Integer(), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("service_modules")
    op.drop_table("tasks")
    op.drop_table("api_tokens")
    op.drop_table("audit_events")
    op.drop_table("sessions")
    op.drop_table("users")
