"""Database admin connections (Gate 19 S9)."""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "20261108_0010"
down_revision = "20261108_0009"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "dbadmin_connections",
        sa.Column("id", sa.String(32), primary_key=True),
        sa.Column("name", sa.String(80), nullable=False),
        sa.Column("engine", sa.String(16), nullable=False),
        sa.Column("host", sa.String(255), nullable=False),
        sa.Column("port", sa.Integer(), nullable=False),
        sa.Column("database", sa.String(128)),
        sa.Column("username", sa.String(128)),
        sa.Column("tls_mode", sa.String(16), nullable=False),
        sa.Column("options", sa.JSON(), nullable=False),
        sa.Column("secret_ref", sa.String(64)),
        sa.Column("created_by_user_id", sa.Integer()),
        sa.Column("created_at", sa.Integer(), nullable=False),
        sa.Column("updated_at", sa.Integer(), nullable=False),
        sa.Column("last_tested_at", sa.Integer()),
        sa.Column("last_test_ok", sa.Boolean()),
    )
    op.create_index(
        "ix_dbadmin_connections_name", "dbadmin_connections", ["name"], unique=True
    )


def downgrade() -> None:
    op.drop_table("dbadmin_connections")
