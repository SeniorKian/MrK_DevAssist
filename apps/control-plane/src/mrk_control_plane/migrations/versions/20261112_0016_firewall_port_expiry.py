"""Firewall port rules: optional expiry for temporary rules (quick actions, docs/45)."""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "20261112_0016"
down_revision = "20261111_0015"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("firewall_port_rules", sa.Column("expires_at", sa.Integer(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("firewall_port_rules") as batch:
        batch.drop_column("expires_at")
