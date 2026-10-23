"""introduce organization data isolation

Revision ID: 005
Revises: 004
Create Date: 2026-10-23
"""

from collections.abc import Sequence
from uuid import UUID

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "005"
down_revision: str | None = "004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

DEFAULT_ORGANIZATION_ID = UUID("00000000-0000-4000-8000-000000000001")
TENANT_TABLES = (
    "users",
    "user_roles",
    "refresh_tokens",
    "data_sources",
    "sensor_registrations",
    "ingestion_jobs",
    "security_events",
    "detection_rules",
    "detection_rule_versions",
    "detections",
    "detection_evidence",
    "cases",
    "response_simulations",
    "case_detections",
    "case_comments",
    "case_status_history",
    "model_versions",
    "model_evaluations",
    "audit_logs",
    "system_settings",
)


def upgrade() -> None:
    op.create_table(
        "organizations",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("slug", sa.String(80), nullable=False, unique=True),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.execute(
        sa.text(
            "INSERT INTO organizations (id, slug, name) "
            "VALUES (:id, 'default', 'SentinelAI Workspace')"
        ).bindparams(id=DEFAULT_ORGANIZATION_ID)
    )

    for table in TENANT_TABLES:
        op.add_column(
            table,
            sa.Column(
                "organization_id",
                postgresql.UUID(as_uuid=True),
                nullable=True,
            ),
        )
        op.execute(
            sa.text(f"UPDATE {table} SET organization_id = :organization_id")
            .bindparams(organization_id=DEFAULT_ORGANIZATION_ID)
        )
        op.alter_column(table, "organization_id", nullable=False)
        op.create_foreign_key(
            f"fk_{table}_organization_id_organizations",
            table,
            "organizations",
            ["organization_id"],
            ["id"],
            ondelete="CASCADE",
        )
        op.create_index(f"ix_{table}_organization_id", table, ["organization_id"])
        op.alter_column(
            table,
            "organization_id",
            server_default=sa.text(
                "NULLIF(current_setting('app.current_organization_id', true), '')::uuid"
            ),
        )

    scoped_unique_constraints = (
        ("users", "users_email_key", "uq_users_org_email", ["organization_id", "email"]),
        ("data_sources", "data_sources_name_key", "uq_data_sources_org_name", ["organization_id", "name"]),
        ("ingestion_jobs", "ingestion_jobs_idempotency_key_key", "uq_ingestion_jobs_org_idempotency", ["organization_id", "idempotency_key"]),
        ("security_events", "security_events_dedup_key_key", "uq_security_events_org_dedup", ["organization_id", "dedup_key"]),
        ("detection_rules", "detection_rules_rule_id_key", "uq_detection_rules_org_rule_id", ["organization_id", "rule_id"]),
        ("detections", "detections_fingerprint_key", "uq_detections_org_fingerprint", ["organization_id", "fingerprint"]),
        ("response_simulations", "response_simulations_idempotency_key_key", "uq_responses_org_idempotency", ["organization_id", "idempotency_key"]),
    )
    for table, old_name, new_name, columns in scoped_unique_constraints:
        op.drop_constraint(old_name, table, type_="unique")
        op.create_unique_constraint(new_name, table, columns)

    op.drop_constraint("system_settings_pkey", "system_settings", type_="primary")
    op.create_primary_key(
        "system_settings_pkey", "system_settings", ["organization_id", "key"]
    )

    for table in TENANT_TABLES:
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"CREATE POLICY tenant_isolation ON {table} "
            "USING (organization_id = NULLIF(current_setting('app.current_organization_id', true), '')::uuid) "
            "WITH CHECK (organization_id = NULLIF(current_setting('app.current_organization_id', true), '')::uuid)"
        )


def downgrade() -> None:
    for table in reversed(TENANT_TABLES):
        op.execute(f"DROP POLICY tenant_isolation ON {table}")
        op.execute(f"ALTER TABLE {table} NO FORCE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY")

    op.drop_constraint("system_settings_pkey", "system_settings", type_="primary")
    op.create_primary_key("system_settings_pkey", "system_settings", ["key"])

    scoped_unique_constraints = (
        ("users", "uq_users_org_email", "users_email_key", ["email"]),
        ("data_sources", "uq_data_sources_org_name", "data_sources_name_key", ["name"]),
        ("ingestion_jobs", "uq_ingestion_jobs_org_idempotency", "ingestion_jobs_idempotency_key_key", ["idempotency_key"]),
        ("security_events", "uq_security_events_org_dedup", "security_events_dedup_key_key", ["dedup_key"]),
        ("detection_rules", "uq_detection_rules_org_rule_id", "detection_rules_rule_id_key", ["rule_id"]),
        ("detections", "uq_detections_org_fingerprint", "detections_fingerprint_key", ["fingerprint"]),
        ("response_simulations", "uq_responses_org_idempotency", "response_simulations_idempotency_key_key", ["idempotency_key"]),
    )
    for table, old_name, new_name, columns in scoped_unique_constraints:
        op.drop_constraint(old_name, table, type_="unique")
        op.create_unique_constraint(new_name, table, columns)

    for table in reversed(TENANT_TABLES):
        op.drop_index(f"ix_{table}_organization_id", table_name=table)
        op.drop_constraint(
            f"fk_{table}_organization_id_organizations", table, type_="foreignkey"
        )
        op.drop_column(table, "organization_id")
    op.drop_table("organizations")
