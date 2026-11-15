"""remember which session, address and browser each refresh token belongs to

Revision ID: 018
Revises: 017
Create Date: 2026-11-15
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "018"
down_revision: str | None = "017"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "refresh_tokens", sa.Column("session_id", postgresql.UUID(as_uuid=True), nullable=True)
    )
    op.add_column("refresh_tokens", sa.Column("ip_address", sa.String(64), nullable=True))
    op.add_column("refresh_tokens", sa.Column("user_agent", sa.String(300), nullable=True))
    # Sessions that exist today become one session per token.
    op.execute("UPDATE refresh_tokens SET session_id = id WHERE session_id IS NULL")
    op.create_index("ix_refresh_tokens_session_id", "refresh_tokens", ["session_id"])


def downgrade() -> None:
    op.drop_index("ix_refresh_tokens_session_id", table_name="refresh_tokens")
    op.drop_column("refresh_tokens", "user_agent")
    op.drop_column("refresh_tokens", "ip_address")
    op.drop_column("refresh_tokens", "session_id")
