"""Sign-in security: sliding sessions, two-step sign-in (TOTP) and SSO identities."""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "20261112_0017"
down_revision = "20261112_0016"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Older rows keep NULLs: they use the configured idle window and maximum age.
    op.add_column("sessions", sa.Column("last_seen_at", sa.Integer(), nullable=True))
    op.add_column("sessions", sa.Column("idle_seconds", sa.Integer(), nullable=True))
    op.add_column("sessions", sa.Column("absolute_expires_at", sa.Integer(), nullable=True))
    op.add_column("sessions", sa.Column("remember", sa.Boolean(), nullable=True))
    op.add_column("sessions", sa.Column("auth_method", sa.String(16), nullable=True))
    op.add_column("sessions", sa.Column("source_ip", sa.String(64), nullable=True))
    op.add_column("sessions", sa.Column("user_agent", sa.String(200), nullable=True))
    op.create_table(
        "user_mfa",
        sa.Column(
            "user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("secret_ref", sa.String(64), nullable=True),
        sa.Column("pending_ref", sa.String(64), nullable=True),
        sa.Column("pending_created_at", sa.Integer(), nullable=True),
        sa.Column("enabled_at", sa.Integer(), nullable=True),
        sa.Column("last_step", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("recovery_hashes", sa.JSON(), nullable=False),
        sa.Column("recovery_generated_at", sa.Integer(), nullable=True),
        sa.Column("updated_at", sa.Integer(), nullable=False),
    )
    op.create_table(
        "user_identities",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("issuer", sa.String(255), nullable=False),
        sa.Column("subject", sa.String(255), nullable=False),
        sa.Column("email", sa.String(254), nullable=True),
        sa.Column("created_at", sa.Integer(), nullable=False),
        sa.Column("last_login_at", sa.Integer(), nullable=True),
        sa.UniqueConstraint("issuer", "subject", name="uq_user_identities_issuer_subject"),
    )
    op.create_index("ix_user_identities_user_id", "user_identities", ["user_id"])


def downgrade() -> None:
    op.drop_table("user_identities")
    op.drop_table("user_mfa")
    with op.batch_alter_table("sessions") as batch:
        for name in (
            "user_agent", "source_ip", "auth_method", "remember", "absolute_expires_at",
            "idle_seconds", "last_seen_at",
        ):
            batch.drop_column(name)
