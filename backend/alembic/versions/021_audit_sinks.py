"""destinations that receive a copy of the audit log as it grows

Revision ID: 021
Revises: 020
Create Date: 2026-11-15
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "021"
down_revision: str | None = "020"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_ORG_DEFAULT = sa.text("NULLIF(current_setting('app.current_organization_id', true), '')::uuid")
_ORG_MATCH = "organization_id = NULLIF(current_setting('app.current_organization_id', true), '')::uuid"


def upgrade() -> None:
    uuid = postgresql.UUID(as_uuid=True)
    timestamp = sa.DateTime(timezone=True)
    op.create_table(
        "audit_sinks",
        sa.Column("id", uuid, primary_key=True),
        sa.Column("organization_id", uuid, nullable=False, server_default=_ORG_DEFAULT),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("target_encrypted", sa.Text(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("last_seq", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("last_success_at", timestamp),
        sa.Column("last_error", sa.Text()),
        sa.Column("failures", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("next_attempt_at", timestamp),
        sa.Column("created_at", timestamp, nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.UniqueConstraint("organization_id", "name", name="uq_audit_sinks_org_name"),
    )
    op.create_index("ix_audit_sinks_organization_id", "audit_sinks", ["organization_id"])
    op.execute("ALTER TABLE audit_sinks ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE audit_sinks FORCE ROW LEVEL SECURITY")
    op.execute(
        f"CREATE POLICY tenant_isolation ON audit_sinks USING ({_ORG_MATCH}) "
        f"WITH CHECK ({_ORG_MATCH})"
    )


def downgrade() -> None:
    op.drop_table("audit_sinks")
