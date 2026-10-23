"""add tenant-scoped encrypted cloud connector records

Revision ID: 008
Revises: 007
Create Date: 2026-10-23
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "008"
down_revision: str | None = "007"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "cloud_connectors",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False,
                  server_default=sa.text("NULLIF(current_setting('app.current_organization_id', true), '')::uuid")),
        sa.Column("data_source_id", postgresql.UUID(as_uuid=True), nullable=False, unique=True),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("provider", sa.String(32), nullable=False),
        sa.Column("config", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("credentials_encrypted", sa.Text(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("cursor", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("status", sa.String(32), nullable=False, server_default="idle"),
        sa.Column("last_poll_started_at", sa.DateTime(timezone=True)),
        sa.Column("last_success_at", sa.DateTime(timezone=True)),
        sa.Column("last_error", sa.Text()),
        sa.Column("created_by", postgresql.UUID(as_uuid=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["data_source_id"], ["data_sources.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["organization_id", "data_source_id"], ["data_sources.organization_id", "data_sources.id"], ondelete="CASCADE", name="fk_cloud_connectors_data_source_org"),
        sa.UniqueConstraint("organization_id", "name", name="uq_cloud_connectors_org_name"),
        sa.UniqueConstraint("organization_id", "id", name="uq_cloud_connectors_org_id"),
    )
    op.create_index("ix_cloud_connectors_organization_id", "cloud_connectors", ["organization_id"])
    op.create_index("ix_cloud_connectors_provider", "cloud_connectors", ["provider"])
    op.execute(
        "ALTER TABLE cloud_connectors ADD CONSTRAINT fk_cloud_connectors_created_by_org "
        "FOREIGN KEY (organization_id, created_by) REFERENCES users (organization_id, id) "
        "ON DELETE SET NULL (created_by)"
    )
    op.execute("ALTER TABLE cloud_connectors ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE cloud_connectors FORCE ROW LEVEL SECURITY")
    op.execute(
        "CREATE POLICY tenant_isolation ON cloud_connectors "
        "USING (organization_id = NULLIF(current_setting('app.current_organization_id', true), '')::uuid) "
        "WITH CHECK (organization_id = NULLIF(current_setting('app.current_organization_id', true), '')::uuid)"
    )


def downgrade() -> None:
    op.drop_table("cloud_connectors")
