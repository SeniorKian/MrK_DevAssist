"""Persist the per-upstream connection health timeline."""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "20261107_0003"
down_revision = "20261107_0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "upstream_health_checks",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("upstream_id", sa.String(64), nullable=False),
        sa.Column("ecosystem", sa.String(16), nullable=False),
        sa.Column("upstream_name", sa.String(80), nullable=False),
        sa.Column("ok", sa.Boolean(), nullable=False),
        sa.Column("stages", sa.JSON(), nullable=False),
        sa.Column("total_latency_ms", sa.Integer(), nullable=False),
        sa.Column(
            "actor_user_id",
            sa.Integer(),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
        ),
        sa.Column("checked_at", sa.Integer(), nullable=False),
    )
    op.create_index(
        "ix_upstream_health_checks_upstream_id",
        "upstream_health_checks",
        ["upstream_id"],
    )
    op.create_index(
        "ix_upstream_health_checks_ecosystem",
        "upstream_health_checks",
        ["ecosystem"],
    )
    op.create_index(
        "ix_upstream_health_checks_ok", "upstream_health_checks", ["ok"]
    )
    op.create_index(
        "ix_upstream_health_checks_actor_user_id",
        "upstream_health_checks",
        ["actor_user_id"],
    )
    op.create_index(
        "ix_upstream_health_checks_checked_at",
        "upstream_health_checks",
        ["checked_at"],
    )
    op.create_index(
        "upstream_health_timeline_idx",
        "upstream_health_checks",
        ["upstream_id", "checked_at"],
    )


def downgrade() -> None:
    op.drop_table("upstream_health_checks")
