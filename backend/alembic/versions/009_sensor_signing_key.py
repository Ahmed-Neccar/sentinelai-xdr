"""pin cryptographic identities to registered host sensors

Revision ID: 009
Revises: 008
Create Date: 2026-10-24
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "009"
down_revision: str | None = "008"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("sensor_registrations", sa.Column("public_key", sa.Text(), nullable=True))
    op.add_column(
        "sensor_registrations",
        sa.Column("last_request_counter", sa.Integer(), nullable=False, server_default="0"),
    )


def downgrade() -> None:
    op.drop_column("sensor_registrations", "last_request_counter")
    op.drop_column("sensor_registrations", "public_key")
