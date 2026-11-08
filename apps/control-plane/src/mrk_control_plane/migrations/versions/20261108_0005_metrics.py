"""Resource monitoring: minute and hour metric rollups (Gate 17)."""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "20261108_0005"
down_revision = "20261108_0004"
branch_labels = None
depends_on = None


def _columns() -> list[sa.Column]:
    return [
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("kind", sa.String(16), nullable=False),
        sa.Column("scope", sa.String(128), nullable=False),
        sa.Column("ts", sa.Integer(), nullable=False),
        sa.Column("samples", sa.Integer(), nullable=False),
        sa.Column("protected", sa.Boolean(), nullable=False),
        sa.Column("cpu_percent", sa.Float()),
        sa.Column("cpu_max_percent", sa.Float()),
        sa.Column("mem_bytes", sa.BigInteger()),
        sa.Column("mem_limit_bytes", sa.BigInteger()),
        sa.Column("mem_percent", sa.Float()),
        sa.Column("disk_percent", sa.Float()),
        sa.Column("load1", sa.Float()),
        sa.Column("net_rx_bps", sa.Float()),
        sa.Column("net_tx_bps", sa.Float()),
        sa.Column("io_read_bps", sa.Float()),
        sa.Column("io_write_bps", sa.Float()),
    ]


def upgrade() -> None:
    for table, prefix in (("metric_minutes", "metric_minutes"), ("metric_hours", "metric_hours")):
        op.create_table(table, *_columns())
        op.create_index(f"{prefix}_scope_ts_idx", table, ["scope", "ts"])
        op.create_index(f"{prefix}_kind_ts_idx", table, ["kind", "ts"])
        op.create_index(f"{prefix}_ts_idx", table, ["ts"])


def downgrade() -> None:
    op.drop_table("metric_hours")
    op.drop_table("metric_minutes")
