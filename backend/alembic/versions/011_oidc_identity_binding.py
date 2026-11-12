"""bind SSO accounts to the identity provider's immutable subject

Revision ID: 011
Revises: 010
Create Date: 2026-11-12
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "011"
down_revision: str | None = "010"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("users", sa.Column("oidc_issuer", sa.String(length=512), nullable=True))
    op.add_column("users", sa.Column("oidc_subject", sa.String(length=255), nullable=True))
    # NULLs are distinct, so accounts that never used SSO do not collide.
    op.create_unique_constraint(
        "uq_users_org_oidc_identity", "users", ["organization_id", "oidc_issuer", "oidc_subject"]
    )


def downgrade() -> None:
    op.drop_constraint("uq_users_org_oidc_identity", "users", type_="unique")
    op.drop_column("users", "oidc_subject")
    op.drop_column("users", "oidc_issuer")
