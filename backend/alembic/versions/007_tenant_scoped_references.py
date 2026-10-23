"""enforce tenant-scoped references and refreshable detection evidence

Revision ID: 007
Revises: 006
Create Date: 2026-10-23
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "007"
down_revision: str | None = "006"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


# Each reference is additionally constrained by organization_id. The existing
# single-column FKs remain for ORM relationship loading and their delete rules.
REFERENCES = (
    ("user_roles", "user_id", "users", "CASCADE"),
    ("refresh_tokens", "user_id", "users", "CASCADE"),
    ("sensor_registrations", "credential_user_id", "users", "CASCADE"),
    ("sensor_registrations", "data_source_id", "data_sources", "CASCADE"),
    ("ingestion_jobs", "data_source_id", "data_sources", "SET NULL"),
    ("ingestion_jobs", "created_by", "users", None),
    ("security_events", "data_source_id", "data_sources", "SET NULL"),
    ("security_events", "ingestion_job_id", "ingestion_jobs", "SET NULL"),
    ("detection_rule_versions", "rule_pk", "detection_rules", "CASCADE"),
    ("detection_evidence", "detection_id", "detections", "CASCADE"),
    ("detection_evidence", "event_id", "security_events", "CASCADE"),
    ("cases", "assigned_to", "users", None),
    ("response_simulations", "case_id", "cases", "CASCADE"),
    ("response_simulations", "requested_by", "users", "SET NULL"),
    ("response_simulations", "approved_by", "users", "SET NULL"),
    ("response_simulations", "simulated_by", "users", "SET NULL"),
    ("response_simulations", "rejected_by", "users", "SET NULL"),
    ("case_detections", "case_id", "cases", "CASCADE"),
    ("case_detections", "detection_id", "detections", "CASCADE"),
    ("case_comments", "case_id", "cases", "CASCADE"),
    ("case_comments", "author_id", "users", None),
    ("case_status_history", "case_id", "cases", "CASCADE"),
    ("case_status_history", "actor_id", "users", None),
    ("model_evaluations", "model_version_id", "model_versions", "CASCADE"),
    ("audit_logs", "actor_id", "users", None),
)

PARENT_TABLES = (
    "users",
    "data_sources",
    "ingestion_jobs",
    "security_events",
    "detection_rules",
    "detections",
    "cases",
    "model_versions",
)


def _constraint_name(table: str, column: str) -> str:
    return f"fk_{table}_{column}_org"


def upgrade() -> None:
    # Fail safely if old data already contains a cross-tenant reference. Do not
    # silently delete or reassign company data during a schema migration.
    for table, column, parent, _ in REFERENCES:
        op.execute(
            sa.text(
                f"""DO $$ BEGIN
                IF EXISTS (
                    SELECT 1 FROM {table} child
                    JOIN {parent} parent ON parent.id = child.{column}
                    WHERE child.{column} IS NOT NULL
                      AND child.organization_id <> parent.organization_id
                ) THEN
                    RAISE EXCEPTION 'cross-tenant reference found: {table}.{column}';
                END IF;
                END $$;"""  # noqa: S608 -- identifiers come from the constant REFERENCES list
            )
        )

    for table in PARENT_TABLES:
        op.create_unique_constraint(f"uq_{table}_org_id", table, ["organization_id", "id"])

    # Earlier versions could create repeated links when a detector retried.
    op.execute(
        sa.text(
            """DELETE FROM detection_evidence older USING detection_evidence newer
            WHERE older.organization_id = newer.organization_id
              AND older.detection_id = newer.detection_id
              AND older.event_id = newer.event_id
              AND older.id > newer.id"""
        )
    )
    op.create_unique_constraint(
        "uq_detection_evidence_org_detection_event",
        "detection_evidence",
        ["organization_id", "detection_id", "event_id"],
    )

    for table, column, parent, ondelete in REFERENCES:
        name = _constraint_name(table, column)
        if ondelete == "SET NULL":
            # PostgreSQL 15+ column lists preserve organization_id while nulling
            # the optional reference. The project uses PostgreSQL 16.
            op.execute(
                sa.text(
                    f"ALTER TABLE {table} ADD CONSTRAINT {name} "
                    f"FOREIGN KEY (organization_id, {column}) "
                    f"REFERENCES {parent} (organization_id, id) "
                    f"ON DELETE SET NULL ({column})"
                )
            )
        else:
            op.create_foreign_key(
                name,
                table,
                parent,
                ["organization_id", column],
                ["organization_id", "id"],
                ondelete=ondelete,
            )


def downgrade() -> None:
    for table, column, _, _ in reversed(REFERENCES):
        op.drop_constraint(_constraint_name(table, column), table, type_="foreignkey")
    op.drop_constraint(
        "uq_detection_evidence_org_detection_event", "detection_evidence", type_="unique"
    )
    for table in reversed(PARENT_TABLES):
        op.drop_constraint(f"uq_{table}_org_id", table, type_="unique")
