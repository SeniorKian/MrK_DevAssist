"""Server & database backups: destinations, jobs and run history (Gate 18 S6)."""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "20261108_0007"
down_revision = "20261108_0006"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "server_backup_destinations",
        sa.Column("id", sa.String(32), primary_key=True),
        sa.Column("name", sa.String(80), nullable=False),
        sa.Column("kind", sa.String(16), nullable=False),
        sa.Column("config", sa.JSON(), nullable=False),
        sa.Column("secret_ref", sa.String(64)),
        sa.Column("created_at", sa.Integer(), nullable=False),
        sa.Column("updated_at", sa.Integer(), nullable=False),
    )
    op.create_index(
        "ix_server_backup_destinations_name", "server_backup_destinations", ["name"], unique=True
    )
    op.create_table(
        "server_backup_jobs",
        sa.Column("id", sa.String(32), primary_key=True),
        sa.Column("name", sa.String(80), nullable=False),
        sa.Column("source", sa.JSON(), nullable=False),
        sa.Column(
            "destination_id",
            sa.String(32),
            sa.ForeignKey("server_backup_destinations.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("schedule", sa.String(120), nullable=False),
        sa.Column("retention", sa.JSON(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("key_ref", sa.String(64), nullable=False),
        sa.Column("next_run_at", sa.Integer()),
        sa.Column("created_at", sa.Integer(), nullable=False),
        sa.Column("updated_at", sa.Integer(), nullable=False),
    )
    op.create_index("ix_server_backup_jobs_name", "server_backup_jobs", ["name"], unique=True)
    op.create_index(
        "ix_server_backup_jobs_destination_id", "server_backup_jobs", ["destination_id"]
    )
    op.create_table(
        "server_backup_runs",
        sa.Column("id", sa.String(32), primary_key=True),
        sa.Column(
            "job_id",
            sa.String(32),
            sa.ForeignKey("server_backup_jobs.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("destination_id", sa.String(32), nullable=False),
        sa.Column("trigger", sa.String(16), nullable=False),
        sa.Column("state", sa.String(16), nullable=False),
        sa.Column("started_at", sa.Integer(), nullable=False),
        sa.Column("finished_at", sa.Integer()),
        sa.Column("bytes", sa.BigInteger()),
        sa.Column("source_bytes", sa.BigInteger()),
        sa.Column("sha256", sa.String(64)),
        sa.Column("object_key", sa.String(1024)),
        sa.Column("error_code", sa.String(80)),
        sa.Column("details", sa.JSON(), nullable=False),
    )
    op.create_index("ix_server_backup_runs_job_id", "server_backup_runs", ["job_id"])
    op.create_index("ix_server_backup_runs_state", "server_backup_runs", ["state"])
    op.create_index(
        "server_backup_runs_job_started_idx", "server_backup_runs", ["job_id", "started_at"]
    )


def downgrade() -> None:
    op.drop_table("server_backup_runs")
    op.drop_table("server_backup_jobs")
    op.drop_table("server_backup_destinations")
