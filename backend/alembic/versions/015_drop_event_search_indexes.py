"""drop the trigram indexes added in 014: row-level security prevents their use

Revision ID: 015
Revises: 014
Create Date: 2026-11-14

The application role queries `security_events` under a forced row-level security policy.
PostgreSQL only lets an index serve a condition ahead of that policy when the operator is
"leakproof", and the pattern-matching operators behind `ILIKE '%text%'` are not. Measured on
a 180,000-row table as the application role: the planner ignored both indexes (604 ms), while
the same query as a superuser used them (5 ms). The indexes therefore cost write time on every
inserted event and helped no query, so they are removed. The pg_trgm extension is left in place.
"""

from collections.abc import Sequence

from alembic import op

revision: str = "015"
down_revision: str | None = "014"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_security_events_event_type_trgm")
    op.execute("DROP INDEX IF EXISTS ix_security_events_host_id_trgm")


def downgrade() -> None:
    # 014's downgrade is a no-op for indexes that no longer exist; nothing to restore.
    pass
