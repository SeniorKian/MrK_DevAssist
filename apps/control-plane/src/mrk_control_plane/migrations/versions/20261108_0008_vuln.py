"""Vulnerability scanner ignore rules (Gate 19 S8).

Scan results and the OSV index live in data_dir/modules/vuln/*.sqlite (re-derivable);
only user decisions are stored here so they are backed up with the database.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "20261108_0008"
down_revision = "20261108_0007"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "vuln_ignores",
        sa.Column("id", sa.String(32), primary_key=True),
        sa.Column("advisory", sa.String(128)),
        sa.Column("package", sa.String(200)),
        sa.Column("image", sa.String(255)),
        sa.Column("reason", sa.String(500), nullable=False),
        sa.Column("expires_at", sa.Integer()),
        sa.Column("created_at", sa.Integer(), nullable=False),
        sa.Column("created_by", sa.Integer()),
    )
    op.create_index("ix_vuln_ignores_expires_at", "vuln_ignores", ["expires_at"])


def downgrade() -> None:
    op.drop_index("ix_vuln_ignores_expires_at", table_name="vuln_ignores")
    op.drop_table("vuln_ignores")
