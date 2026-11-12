"""track sensor-enforced IP blocks on approved response records

Revision ID: 012
Revises: 011
Create Date: 2026-11-12
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "012"
down_revision: str | None = "011"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

TABLE = "response_simulations"


def upgrade() -> None:
    op.add_column(TABLE, sa.Column("sensor_id", postgresql.UUID(as_uuid=True), nullable=True))
    op.add_column(TABLE, sa.Column("duration_minutes", sa.Integer(), nullable=True))
    op.add_column(TABLE, sa.Column("enforcement_status", sa.String(length=32), nullable=True))
    op.add_column(
        TABLE,
        sa.Column("enforcement_detail", sa.String(length=255), nullable=False, server_default=""),
    )
    op.add_column(TABLE, sa.Column("enforced_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column(TABLE, sa.Column("block_until", sa.DateTime(timezone=True), nullable=True))
    op.add_column(TABLE, sa.Column("removed_at", sa.DateTime(timezone=True), nullable=True))
    op.create_index("ix_response_simulations_sensor_id", TABLE, ["sensor_id"])
    op.create_index("ix_response_simulations_enforcement_status", TABLE, ["enforcement_status"])


def downgrade() -> None:
    op.drop_index("ix_response_simulations_enforcement_status", table_name=TABLE)
    op.drop_index("ix_response_simulations_sensor_id", table_name=TABLE)
    for column in (
        "removed_at",
        "block_until",
        "enforced_at",
        "enforcement_detail",
        "enforcement_status",
        "duration_minutes",
        "sensor_id",
    ):
        op.drop_column(TABLE, column)
