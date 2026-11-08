"""S3 module: bucket registry, identities and access-key metadata (Gate 18)."""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "20261108_0006"
down_revision = "20261108_0005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "s3_buckets",
        sa.Column("name", sa.String(63), primary_key=True),
        sa.Column("mode", sa.String(16), nullable=False),
        sa.Column("link_path", sa.String(4096)),
        sa.Column("link_mode", sa.String(8), nullable=False),
        sa.Column("public_read", sa.Boolean(), nullable=False),
        sa.Column("quota_bytes", sa.BigInteger()),
        sa.Column("created_by_user_id", sa.Integer()),
        sa.Column("created_at", sa.Integer(), nullable=False),
        sa.Column("updated_at", sa.Integer(), nullable=False),
    )
    op.create_table(
        "s3_identities",
        sa.Column("id", sa.String(32), primary_key=True),
        sa.Column("name", sa.String(64), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("policy_template", sa.String(32), nullable=False),
        sa.Column("buckets", sa.JSON(), nullable=False),
        sa.Column("policy", sa.JSON(), nullable=False),
        sa.Column("created_by_user_id", sa.Integer()),
        sa.Column("created_at", sa.Integer(), nullable=False),
        sa.Column("updated_at", sa.Integer(), nullable=False),
    )
    op.create_index("ix_s3_identities_name", "s3_identities", ["name"], unique=True)
    op.create_table(
        "s3_access_keys",
        sa.Column("access_key_id", sa.String(20), primary_key=True),
        sa.Column(
            "identity_id",
            sa.String(32),
            sa.ForeignKey("s3_identities.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("secret_ref", sa.String(64), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.Integer(), nullable=False),
        sa.Column("last_used_at", sa.Integer()),
    )
    op.create_index("ix_s3_access_keys_identity_id", "s3_access_keys", ["identity_id"])


def downgrade() -> None:
    op.drop_table("s3_access_keys")
    op.drop_index("ix_s3_identities_name", table_name="s3_identities")
    op.drop_table("s3_identities")
    op.drop_table("s3_buckets")
