"""Firewall & anti-attack: rules, blocks and decision history (Gate 19 S7)."""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "20261108_0009"
down_revision = "20261108_0008"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "firewall_rules",
        sa.Column("id", sa.String(32), primary_key=True),
        sa.Column("name", sa.String(80), nullable=False),
        sa.Column("signal_kinds", sa.JSON(), nullable=False),
        sa.Column("threshold", sa.Integer(), nullable=False),
        sa.Column("window_seconds", sa.Integer(), nullable=False),
        sa.Column("ban_seconds", sa.Integer(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("builtin", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.Integer(), nullable=False),
        sa.Column("updated_at", sa.Integer(), nullable=False),
    )
    op.create_index("ix_firewall_rules_name", "firewall_rules", ["name"], unique=True)
    op.create_table(
        "firewall_blocks",
        sa.Column("id", sa.String(32), primary_key=True),
        sa.Column("cidr", sa.String(64), nullable=False),
        sa.Column("origin", sa.String(16), nullable=False),
        sa.Column("rule_id", sa.String(32)),
        sa.Column("reason", sa.String(500), nullable=False),
        sa.Column("simulated", sa.Boolean(), nullable=False),
        sa.Column("created_by_user_id", sa.Integer()),
        sa.Column("created_at", sa.Integer(), nullable=False),
        sa.Column("expires_at", sa.Integer()),
        sa.Column("removed_at", sa.Integer()),
        sa.Column("removed_reason", sa.String(32)),
    )
    op.create_index("ix_firewall_blocks_cidr", "firewall_blocks", ["cidr"])
    op.create_index(
        "firewall_blocks_active_idx", "firewall_blocks", ["removed_at", "expires_at"]
    )
    op.create_table(
        "firewall_decisions",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("occurred_at", sa.Integer(), nullable=False),
        sa.Column("action", sa.String(24), nullable=False),
        sa.Column("ip", sa.String(64)),
        sa.Column("rule_id", sa.String(32)),
        sa.Column("mode", sa.String(16), nullable=False),
        sa.Column("reason", sa.String(500), nullable=False),
        sa.Column("actor_user_id", sa.Integer()),
        sa.Column("details", sa.JSON(), nullable=False),
    )
    op.create_index("ix_firewall_decisions_occurred_at", "firewall_decisions", ["occurred_at"])
    op.create_index("ix_firewall_decisions_action", "firewall_decisions", ["action"])
    op.create_index("ix_firewall_decisions_ip", "firewall_decisions", ["ip"])


def downgrade() -> None:
    op.drop_table("firewall_decisions")
    op.drop_table("firewall_blocks")
    op.drop_table("firewall_rules")
