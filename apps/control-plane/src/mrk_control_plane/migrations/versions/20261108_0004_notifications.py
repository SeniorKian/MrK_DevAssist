"""Notification center: channels, routing rules and the persisted delivery queue."""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "20261108_0004"
down_revision = "20261107_0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "notification_channels",
        sa.Column("id", sa.String(32), primary_key=True),
        sa.Column("name", sa.String(80), nullable=False, unique=True),
        sa.Column("kind", sa.String(16), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("config", sa.JSON(), nullable=False),
        sa.Column("secret_ref", sa.String(64)),
        sa.Column("created_at", sa.Integer(), nullable=False),
        sa.Column("updated_at", sa.Integer(), nullable=False),
        sa.Column("last_delivery_at", sa.Integer()),
        sa.Column("last_status", sa.String(16)),
    )
    op.create_index("ix_notification_channels_kind", "notification_channels", ["kind"])
    op.create_table(
        "notification_rules",
        sa.Column("id", sa.String(32), primary_key=True),
        sa.Column(
            "channel_id",
            sa.String(32),
            sa.ForeignKey("notification_channels.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("event_pattern", sa.String(120), nullable=False),
        sa.Column("min_severity", sa.String(16), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.Integer(), nullable=False),
        sa.Column("updated_at", sa.Integer(), nullable=False),
    )
    op.create_index("ix_notification_rules_channel_id", "notification_rules", ["channel_id"])
    op.create_table(
        "notification_deliveries",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "channel_id",
            sa.String(32),
            sa.ForeignKey("notification_channels.id", ondelete="SET NULL"),
        ),
        sa.Column("channel_name", sa.String(80), nullable=False),
        sa.Column("event_type", sa.String(120), nullable=False),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("module", sa.String(64), nullable=False),
        sa.Column("title", sa.String(300), nullable=False),
        sa.Column("message", sa.Text(), nullable=False),
        sa.Column("details", sa.JSON(), nullable=False),
        sa.Column("dedupe_hash", sa.String(64), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("error_code", sa.String(80)),
        sa.Column("occurred_at", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.Integer(), nullable=False),
        sa.Column("next_attempt_at", sa.Integer()),
        sa.Column("sent_at", sa.Integer()),
    )
    op.create_index(
        "ix_notification_deliveries_created_at",
        "notification_deliveries",
        ["created_at"],
    )
    op.create_index(
        "notification_deliveries_due_idx",
        "notification_deliveries",
        ["status", "next_attempt_at"],
    )
    op.create_index(
        "notification_deliveries_dedupe_idx",
        "notification_deliveries",
        ["channel_id", "dedupe_hash", "created_at"],
    )


def downgrade() -> None:
    op.drop_table("notification_deliveries")
    op.drop_table("notification_rules")
    op.drop_table("notification_channels")
