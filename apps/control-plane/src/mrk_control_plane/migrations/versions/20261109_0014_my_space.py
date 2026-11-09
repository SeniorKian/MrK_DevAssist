"""My space: plans, workspaces, memberships, resource ownership (docs/43)."""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "20261109_0014"
down_revision = "20261109_0013"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "tenancy_plans",
        sa.Column("id", sa.String(32), primary_key=True),
        sa.Column("name_fa", sa.String(100), nullable=False),
        sa.Column("name_en", sa.String(100), nullable=False),
        sa.Column("description", sa.Text(), nullable=False, server_default=""),
        sa.Column("is_default", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("builtin", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("features", sa.JSON(), nullable=False),
        sa.Column("quotas", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.Integer(), nullable=False),
        sa.Column("updated_at", sa.Integer(), nullable=False),
    )
    op.create_table(
        "workspaces",
        sa.Column("id", sa.String(16), primary_key=True),
        sa.Column("slug", sa.String(40), nullable=False, unique=True),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("kind", sa.String(16), nullable=False),
        sa.Column("plan_id", sa.String(32), nullable=False),
        sa.Column("quota_overrides", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default="active"),
        sa.Column("created_by_user_id", sa.Integer()),
        sa.Column("created_at", sa.Integer(), nullable=False),
        sa.Column("updated_at", sa.Integer(), nullable=False),
    )
    op.create_index("ix_workspaces_slug", "workspaces", ["slug"])
    op.create_index("ix_workspaces_plan_id", "workspaces", ["plan_id"])
    op.create_table(
        "workspace_members",
        sa.Column(
            "workspace_id", sa.String(16),
            sa.ForeignKey("workspaces.id", ondelete="CASCADE"), primary_key=True,
        ),
        sa.Column(
            "user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("role", sa.String(16), nullable=False),
        sa.Column("created_at", sa.Integer(), nullable=False),
    )
    op.create_index("ix_workspace_members_user_id", "workspace_members", ["user_id"])
    op.create_table(
        "resource_owners",
        sa.Column("kind", sa.String(24), primary_key=True),
        sa.Column("resource_id", sa.String(255), primary_key=True),
        sa.Column(
            "workspace_id", sa.String(16),
            sa.ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False,
        ),
        sa.Column("created_by", sa.Integer()),
        sa.Column("created_at", sa.Integer(), nullable=False),
        sa.Column("meta", sa.JSON(), nullable=False),
    )
    op.create_index("ix_resource_owners_workspace_id", "resource_owners", ["workspace_id"])
    op.create_table(
        "workspace_invites",
        sa.Column("id", sa.String(24), primary_key=True),
        sa.Column(
            "workspace_id", sa.String(16),
            sa.ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False,
        ),
        sa.Column("email", sa.String(254), nullable=False),
        sa.Column("role", sa.String(16), nullable=False),
        sa.Column("token_hash", sa.String(64), nullable=False, unique=True),
        sa.Column("created_by", sa.Integer()),
        sa.Column("created_at", sa.Integer(), nullable=False),
        sa.Column("expires_at", sa.Integer(), nullable=False),
        sa.Column("accepted_at", sa.Integer()),
        sa.Column("revoked_at", sa.Integer()),
    )
    op.create_index("ix_workspace_invites_workspace_id", "workspace_invites", ["workspace_id"])
    op.create_index("ix_workspace_invites_token_hash", "workspace_invites", ["token_hash"])
    op.create_table(
        "tenancy_signups",
        sa.Column("id", sa.String(24), primary_key=True),
        sa.Column(
            "user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False, unique=True,
        ),
        sa.Column("status", sa.String(16), nullable=False, server_default="pending"),
        sa.Column("created_at", sa.Integer(), nullable=False),
        sa.Column("decided_at", sa.Integer()),
        sa.Column("decided_by", sa.Integer()),
    )
    op.create_index("ix_tenancy_signups_user_id", "tenancy_signups", ["user_id"])
    op.create_index("ix_tenancy_signups_status", "tenancy_signups", ["status"])
    op.create_table(
        "impersonation_sessions",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("token_hash", sa.String(64), nullable=False, unique=True),
        sa.Column(
            "admin_user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "workspace_id", sa.String(16),
            sa.ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False,
        ),
        sa.Column("write", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("created_at", sa.Integer(), nullable=False),
        sa.Column("expires_at", sa.Integer(), nullable=False),
        sa.Column("revoked_at", sa.Integer()),
    )
    op.create_index(
        "ix_impersonation_sessions_token_hash", "impersonation_sessions", ["token_hash"]
    )
    op.create_index(
        "ix_impersonation_sessions_admin_user_id", "impersonation_sessions", ["admin_user_id"]
    )
    op.create_index(
        "ix_impersonation_sessions_workspace_id", "impersonation_sessions", ["workspace_id"]
    )
    op.add_column("audit_events", sa.Column("workspace_id", sa.String(16)))
    op.add_column("audit_events", sa.Column("on_behalf_of", sa.Integer()))
    op.create_index("ix_audit_events_workspace_id", "audit_events", ["workspace_id"])
    op.add_column("api_tokens", sa.Column("workspace_id", sa.String(16)))
    op.add_column("api_tokens", sa.Column("ip_allow", sa.JSON()))
    op.create_index("ix_api_tokens_workspace_id", "api_tokens", ["workspace_id"])


def downgrade() -> None:
    op.drop_index("ix_api_tokens_workspace_id", "api_tokens")
    op.drop_column("api_tokens", "ip_allow")
    op.drop_column("api_tokens", "workspace_id")
    op.drop_index("ix_audit_events_workspace_id", "audit_events")
    op.drop_column("audit_events", "on_behalf_of")
    op.drop_column("audit_events", "workspace_id")
    for table in (
        "impersonation_sessions", "tenancy_signups", "workspace_invites", "resource_owners",
        "workspace_members", "workspaces", "tenancy_plans",
    ):
        op.drop_table(table)
