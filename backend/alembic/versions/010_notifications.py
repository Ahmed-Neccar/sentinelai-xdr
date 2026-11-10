"""add tenant-scoped alert notification channels and delivery outbox

Revision ID: 010
Revises: 009
Create Date: 2026-11-10
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "010"
down_revision: str | None = "009"
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
    op.create_table(
        "notification_channels",
        sa.Column("id", uuid, primary_key=True),
        sa.Column("organization_id", uuid, nullable=False, server_default=_ORG_DEFAULT),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("kind", sa.String(32), nullable=False),
        sa.Column("target_encrypted", sa.Text(), nullable=False),
        sa.Column("min_severity", sa.String(32), nullable=False, server_default="high"),
        sa.Column("include_summary", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("last_success_at", timestamp),
        sa.Column("last_error", sa.Text()),
        sa.Column("created_by", uuid),
        sa.Column("created_at", timestamp, nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", timestamp, nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"], ondelete="SET NULL"),
        sa.UniqueConstraint("organization_id", "name", name="uq_notification_channels_org_name"),
        sa.UniqueConstraint("organization_id", "id", name="uq_notification_channels_org_id"),
    )
    op.create_index(
        "ix_notification_channels_organization_id", "notification_channels", ["organization_id"]
    )
    _secure("notification_channels")

    op.create_table(
        "notification_deliveries",
        sa.Column("id", uuid, primary_key=True),
        sa.Column("organization_id", uuid, nullable=False, server_default=_ORG_DEFAULT),
        sa.Column("channel_id", uuid, nullable=False),
        sa.Column("detection_id", uuid),
        sa.Column("kind", sa.String(32), nullable=False),
        sa.Column("status", sa.String(32), nullable=False, server_default="pending"),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("next_attempt_at", timestamp, nullable=False, server_default=sa.func.now()),
        sa.Column("last_error", sa.Text()),
        sa.Column("created_at", timestamp, nullable=False, server_default=sa.func.now()),
        sa.Column("sent_at", timestamp),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["organization_id", "channel_id"],
            ["notification_channels.organization_id", "notification_channels.id"],
            ondelete="CASCADE",
            name="fk_notification_deliveries_channel_org",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "detection_id"],
            ["detections.organization_id", "detections.id"],
            ondelete="CASCADE",
            name="fk_notification_deliveries_detection_org",
        ),
        sa.UniqueConstraint(
            "organization_id",
            "channel_id",
            "detection_id",
            name="uq_notification_deliveries_org_channel_detection",
        ),
    )
    op.create_index(
        "ix_notification_deliveries_organization_id",
        "notification_deliveries",
        ["organization_id"],
    )
    op.create_index(
        "ix_notification_deliveries_channel_id", "notification_deliveries", ["channel_id"]
    )
    op.create_index("ix_notification_deliveries_status", "notification_deliveries", ["status"])
    _secure("notification_deliveries")


def downgrade() -> None:
    op.drop_table("notification_deliveries")
    op.drop_table("notification_channels")
