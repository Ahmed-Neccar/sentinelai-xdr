"""add one-to-one sensor credential registrations

Revision ID: 004
Revises: 003
Create Date: 2026-10-23
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "004"
down_revision: str | None = "003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "sensor_registrations",
        sa.Column("sensor_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "credential_user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "data_source_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("data_sources.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("status", sa.String(32), nullable=False, server_default="active"),
        sa.Column("enrolled_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("credential_user_id", name="uq_sensor_registrations_credential_user_id"),
        sa.UniqueConstraint("data_source_id", name="uq_sensor_registrations_data_source_id"),
    )
    op.create_index("ix_sensor_registrations_status", "sensor_registrations", ["status"])


def downgrade() -> None:
    op.drop_index("ix_sensor_registrations_status", table_name="sensor_registrations")
    op.drop_table("sensor_registrations")
