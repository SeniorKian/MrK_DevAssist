"""Custom roles, invites and must-change-password state (docs/33 §5, Phase 2 BE2/BE7)."""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "20261108_0011"
down_revision = "20261108_0010"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "custom_roles",
        sa.Column("id", sa.String(24), primary_key=True),
        sa.Column("name", sa.String(80), nullable=False),
        sa.Column("description", sa.String(500), nullable=False, server_default=""),
        sa.Column("permissions", sa.JSON(), nullable=False),
        sa.Column("created_by_user_id", sa.Integer()),
        sa.Column("updated_by_user_id", sa.Integer()),
        sa.Column("created_at", sa.Integer(), nullable=False),
        sa.Column("updated_at", sa.Integer(), nullable=False),
    )
    op.create_index("ix_custom_roles_name", "custom_roles", ["name"], unique=True)
    op.create_table(
        "user_password_states",
        sa.Column(
            "user_id",
            sa.Integer(),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column(
            "must_change_password", sa.Boolean(), nullable=False, server_default=sa.false()
        ),
        sa.Column("reason", sa.String(32)),
        sa.Column("set_at", sa.Integer()),
        sa.Column("changed_at", sa.Integer()),
    )
    op.create_table(
        "user_invites",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column(
            "user_id",
            sa.Integer(),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("token_hash", sa.String(64), nullable=False),
        sa.Column("created_by_user_id", sa.Integer()),
        sa.Column("created_at", sa.Integer(), nullable=False),
        sa.Column("expires_at", sa.Integer(), nullable=False),
        sa.Column("used_at", sa.Integer()),
        sa.Column("revoked_at", sa.Integer()),
    )
    op.create_index("ix_user_invites_user_id", "user_invites", ["user_id"])
    op.create_index("ix_user_invites_token_hash", "user_invites", ["token_hash"], unique=True)
    op.create_index("ix_user_invites_expires_at", "user_invites", ["expires_at"])


def downgrade() -> None:
    op.drop_table("user_invites")
    op.drop_table("user_password_states")
    op.drop_index("ix_custom_roles_name", table_name="custom_roles")
    op.drop_table("custom_roles")
