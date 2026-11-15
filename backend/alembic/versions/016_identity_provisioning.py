"""single sign-on role mapping, automatic provisioning settings and SCIM tokens

Revision ID: 016
Revises: 015
Create Date: 2026-11-15
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "016"
down_revision: str | None = "015"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_ORG_DEFAULT = sa.text("NULLIF(current_setting('app.current_organization_id', true), '')::uuid")
_ORG_MATCH = "organization_id = NULLIF(current_setting('app.current_organization_id', true), '')::uuid"


def _secure(table: str) -> None:
    op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
    op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
    op.execute(
        f"CREATE POLICY tenant_isolation ON {table} USING ({_ORG_MATCH}) WITH CHECK ({_ORG_MATCH})"
    )


def upgrade() -> None:
    uuid = postgresql.UUID(as_uuid=True)
    timestamp = sa.DateTime(timezone=True)
    op.add_column(
        "organizations",
        sa.Column("sso_auto_provision", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.add_column(
        "organizations",
        sa.Column("sso_sync_roles", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.add_column("organizations", sa.Column("default_role", sa.String(64), nullable=True))
    op.add_column("users", sa.Column("scim_external_id", sa.String(255), nullable=True))

    op.create_table(
        "sso_role_mappings",
        sa.Column("id", uuid, primary_key=True),
        sa.Column("organization_id", uuid, nullable=False, server_default=_ORG_DEFAULT),
        sa.Column("claim_value", sa.String(255), nullable=False),
        sa.Column("role_name", sa.String(64), nullable=False),
        sa.Column("created_at", timestamp, nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.UniqueConstraint(
            "organization_id", "claim_value", "role_name", name="uq_sso_role_mappings_value"
        ),
    )
    op.create_index(
        "ix_sso_role_mappings_organization_id", "sso_role_mappings", ["organization_id"]
    )
    _secure("sso_role_mappings")

    op.create_table(
        "scim_tokens",
        sa.Column("id", uuid, primary_key=True),
        sa.Column("organization_id", uuid, nullable=False, server_default=_ORG_DEFAULT),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("token_hash", sa.String(128), nullable=False, unique=True),
        sa.Column("revoked", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("last_used_at", timestamp),
        sa.Column("created_at", timestamp, nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
    )
    op.create_index("ix_scim_tokens_organization_id", "scim_tokens", ["organization_id"])
    _secure("scim_tokens")


def downgrade() -> None:
    op.drop_table("scim_tokens")
    op.drop_table("sso_role_mappings")
    op.drop_column("users", "scim_external_id")
    op.drop_column("organizations", "default_role")
    op.drop_column("organizations", "sso_sync_roles")
    op.drop_column("organizations", "sso_auto_provision")
