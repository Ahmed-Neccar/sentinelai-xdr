"""record when a response action was handed to its sensor, and why one failed

Revision ID: 019
Revises: 018
Create Date: 2026-11-15
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "019"
down_revision: str | None = "018"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "response_simulations",
        sa.Column("dispatched_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column("response_simulations", sa.Column("failure_code", sa.String(32), nullable=True))


def downgrade() -> None:
    op.drop_column("response_simulations", "failure_code")
    op.drop_column("response_simulations", "dispatched_at")
