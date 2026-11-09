"""User-made DNS domain templates (docs/41 §5)."""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "20261109_0013"
down_revision = "20261108_0012"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "dns_templates",
        sa.Column("id", sa.String(32), primary_key=True),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("description", sa.Text(), nullable=False, server_default=""),
        sa.Column("body", sa.JSON(), nullable=False),
        sa.Column("copied_from", sa.String(32)),
        sa.Column("created_at", sa.Integer(), nullable=False),
        sa.Column("updated_at", sa.Integer(), nullable=False),
        sa.Column("created_by_user_id", sa.Integer()),
        sa.Column("updated_by_user_id", sa.Integer()),
    )


def downgrade() -> None:
    op.drop_table("dns_templates")
