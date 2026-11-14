"""trigram indexes so the Events text search does not scan every row

Revision ID: 014
Revises: 013
Create Date: 2026-11-14

`GET /events?q=` matches `event_type` and `host_id` with ILIKE '%text%', which a normal index
cannot serve. pg_trgm indexes can. The extension is "trusted" in PostgreSQL 13+, so the
migration role can create it; if it cannot (a managed database without the extension), the
indexes are skipped and the search keeps working, only slowly.
"""

from collections.abc import Sequence

from alembic import op

revision: str = "014"
down_revision: str | None = "013"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        """
        DO $$
        BEGIN
            CREATE EXTENSION IF NOT EXISTS pg_trgm;
            CREATE INDEX IF NOT EXISTS ix_security_events_event_type_trgm
                ON security_events USING gin (event_type gin_trgm_ops);
            CREATE INDEX IF NOT EXISTS ix_security_events_host_id_trgm
                ON security_events USING gin (host_id gin_trgm_ops);
        EXCEPTION WHEN OTHERS THEN
            RAISE NOTICE 'trigram search indexes skipped: %', SQLERRM;
        END
        $$;
        """
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_security_events_event_type_trgm")
    op.execute("DROP INDEX IF EXISTS ix_security_events_host_id_trgm")
