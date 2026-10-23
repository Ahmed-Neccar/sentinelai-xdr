"""add organization MFA policy and TOTP enrollment fields

Revision ID: 006
Revises: 005
Create Date: 2026-10-23
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "006"
down_revision: str | None = "005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "organizations",
        sa.Column("mfa_required", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.add_column("users", sa.Column("mfa_secret_encrypted", sa.Text(), nullable=True))
    op.add_column("users", sa.Column("mfa_pending_secret_encrypted", sa.Text(), nullable=True))
    op.add_column(
        "users", sa.Column("mfa_enabled_at", sa.DateTime(timezone=True), nullable=True)
    )
    op.add_column(
        "users",
        sa.Column(
            "mfa_recovery_code_hashes",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
    )
    op.add_column("users", sa.Column("mfa_last_counter", sa.Integer(), nullable=True))
    op.add_column("users", sa.Column("mfa_challenge_id", sa.String(36), nullable=True))


def downgrade() -> None:
    op.drop_column("users", "mfa_challenge_id")
    op.drop_column("users", "mfa_last_counter")
    op.drop_column("users", "mfa_recovery_code_hashes")
    op.drop_column("users", "mfa_enabled_at")
    op.drop_column("users", "mfa_pending_secret_encrypted")
    op.drop_column("users", "mfa_secret_encrypted")
    op.drop_column("organizations", "mfa_required")
