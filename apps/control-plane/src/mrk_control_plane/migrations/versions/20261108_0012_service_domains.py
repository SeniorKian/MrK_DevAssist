"""Public domains per MRK service (docs/35 §3)."""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "20261108_0012"
down_revision = "20261108_0011"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "service_domains",
        sa.Column("id", sa.String(24), primary_key=True),
        sa.Column("service_id", sa.String(32), nullable=False),
        sa.Column("host", sa.String(253), nullable=False),
        sa.Column("is_primary", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("https", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("mode", sa.String(32), nullable=False),
        sa.Column("dokploy_domain_id", sa.String(64)),
        sa.Column("health", sa.JSON()),
        sa.Column("created_at", sa.Integer(), nullable=False),
        sa.Column("updated_at", sa.Integer(), nullable=False),
        sa.Column("created_by_user_id", sa.Integer()),
    )
    op.create_index("ix_service_domains_host", "service_domains", ["host"], unique=True)
    op.create_index("ix_service_domains_service_id", "service_domains", ["service_id"])


def downgrade() -> None:
    op.drop_index("ix_service_domains_service_id", table_name="service_domains")
    op.drop_index("ix_service_domains_host", table_name="service_domains")
    op.drop_table("service_domains")
