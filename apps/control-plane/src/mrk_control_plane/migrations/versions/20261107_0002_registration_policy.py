"""Add administrator-controlled public registration policy."""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "20261107_0002"
down_revision = "20261107_0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "system_settings",
        sa.Column("key", sa.String(120), primary_key=True),
        sa.Column("value", sa.JSON(), nullable=False),
        sa.Column("updated_at", sa.Integer(), nullable=False),
        sa.Column("updated_by_user_id", sa.Integer()),
    )


def downgrade() -> None:
    op.drop_table("system_settings")
