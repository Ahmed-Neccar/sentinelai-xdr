"""track live sensor heartbeats

Revision ID: 002
Revises: 001
Create Date: 2026-10-22
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "002"
down_revision: str | None = "001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("ingestion_jobs", sa.Column("last_heartbeat_at", sa.DateTime(timezone=True)))


def downgrade() -> None:
    op.drop_column("ingestion_jobs", "last_heartbeat_at")
