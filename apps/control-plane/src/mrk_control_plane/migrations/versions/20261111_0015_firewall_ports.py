"""Firewall port policy: port rules and named source lists (docs/45)."""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "20261111_0015"
down_revision = "20261109_0014"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "firewall_source_lists",
        sa.Column("id", sa.String(32), primary_key=True),
        sa.Column("name", sa.String(80), nullable=False),
        sa.Column("note", sa.String(500), nullable=False, server_default=""),
        sa.Column("cidrs", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.Integer(), nullable=False),
        sa.Column("updated_at", sa.Integer(), nullable=False),
    )
    op.create_index("ix_firewall_source_lists_name", "firewall_source_lists", ["name"],
                    unique=True)
    op.create_table(
        "firewall_port_rules",
        sa.Column("id", sa.String(32), primary_key=True),
        sa.Column("name", sa.String(80), nullable=False),
        sa.Column("description", sa.String(500), nullable=False, server_default=""),
        sa.Column("protocol", sa.String(8), nullable=False),
        sa.Column("ports", sa.JSON(), nullable=False),
        sa.Column("source_kind", sa.String(8), nullable=False),
        sa.Column("source_cidrs", sa.JSON(), nullable=False),
        sa.Column("source_list_id", sa.String(32)),
        sa.Column("scope", sa.String(8), nullable=False),
        sa.Column("action", sa.String(8), nullable=False, server_default="accept"),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("priority", sa.Integer(), nullable=False),
        sa.Column("log", sa.Boolean(), nullable=False),
        sa.Column("log_rate", sa.Integer(), nullable=False),
        sa.Column("origin", sa.String(16), nullable=False, server_default="manual"),
        sa.Column("created_by_user_id", sa.Integer()),
        sa.Column("created_at", sa.Integer(), nullable=False),
        sa.Column("updated_at", sa.Integer(), nullable=False),
    )
    op.create_index("ix_firewall_port_rules_name", "firewall_port_rules", ["name"], unique=True)
    op.create_index("ix_firewall_port_rules_source_list_id", "firewall_port_rules",
                    ["source_list_id"])


def downgrade() -> None:
    op.drop_table("firewall_port_rules")
    op.drop_table("firewall_source_lists")
