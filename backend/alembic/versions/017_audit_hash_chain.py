"""chain audit log rows with hashes so edits and removals in the middle can be detected

Each organization's audit rows form a chain: a row's hash covers its own fields and the hash of
the row before it. A trigger computes it on insert (so every writer is covered), and a second
trigger refuses updates. Rows can still be deleted, because retention removes old history, but
a deletion in the middle breaks the chain and is reported by the integrity check.

Revision ID: 017
Revises: 016
Create Date: 2026-11-15
"""

from collections.abc import Sequence

from alembic import op

revision: str = "017"
down_revision: str | None = "016"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_HASH_FUNCTION = """
CREATE OR REPLACE FUNCTION audit_row_hash(
    prev text, id uuid, actor uuid, action text, target_type text, target_id text,
    ip text, details jsonb, created timestamptz
) RETURNS text LANGUAGE sql IMMUTABLE AS $$
    SELECT encode(sha256(convert_to(concat_ws('|',
        coalesce(prev, ''), id::text, coalesce(actor::text, ''), action, target_type,
        coalesce(target_id, ''), coalesce(ip, ''), details::text,
        to_char(created AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US')
    ), 'UTF8')), 'hex')
$$
"""

_CHAIN_TRIGGER = """
CREATE OR REPLACE FUNCTION audit_chain() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE previous text;
BEGIN
    PERFORM pg_advisory_xact_lock(hashtext(NEW.organization_id::text));
    SELECT row_hash INTO previous FROM audit_logs
        WHERE organization_id = NEW.organization_id ORDER BY seq DESC LIMIT 1;
    NEW.prev_hash := previous;
    NEW.row_hash := audit_row_hash(previous, NEW.id, NEW.actor_id, NEW.action, NEW.target_type,
        NEW.target_id, NEW.ip_address, NEW.details, NEW.created_at);
    RETURN NEW;
END $$
"""

_NO_UPDATE = """
CREATE OR REPLACE FUNCTION audit_no_update() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'audit log rows cannot be changed';
END $$
"""

_BACKFILL = """
DO $$
DECLARE o record; r record; previous text;
BEGIN
    -- Row-level security applies to the migration role too, so work one organization at a time.
    FOR o IN SELECT id FROM organizations LOOP
        PERFORM set_config('app.current_organization_id', o.id::text, true);
        previous := NULL;
        FOR r IN SELECT * FROM audit_logs ORDER BY seq LOOP
            UPDATE audit_logs SET prev_hash = previous,
                row_hash = audit_row_hash(previous, r.id, r.actor_id, r.action, r.target_type,
                    r.target_id, r.ip_address, r.details, r.created_at)
            WHERE id = r.id RETURNING row_hash INTO previous;
        END LOOP;
    END LOOP;
    PERFORM set_config('app.current_organization_id', '', true);
END $$
"""


def upgrade() -> None:
    # Existing rows are numbered in whatever order the table is read; the chain only needs one
    # consistent order, and rows written from now on follow the sequence.
    op.execute("CREATE SEQUENCE audit_logs_seq_seq")
    op.execute(
        "ALTER TABLE audit_logs ADD COLUMN seq bigint NOT NULL "
        "DEFAULT nextval('audit_logs_seq_seq')"
    )
    op.execute("ALTER SEQUENCE audit_logs_seq_seq OWNED BY audit_logs.seq")
    op.execute("CREATE UNIQUE INDEX uq_audit_logs_seq ON audit_logs (seq)")
    op.execute("ALTER TABLE audit_logs ADD COLUMN prev_hash text")
    op.execute("ALTER TABLE audit_logs ADD COLUMN row_hash text")
    op.execute(_HASH_FUNCTION)
    op.execute(_BACKFILL)
    op.execute(_CHAIN_TRIGGER)
    op.execute(
        "CREATE TRIGGER audit_chain BEFORE INSERT ON audit_logs "
        "FOR EACH ROW EXECUTE FUNCTION audit_chain()"
    )
    op.execute(_NO_UPDATE)
    op.execute(
        "CREATE TRIGGER audit_no_update BEFORE UPDATE ON audit_logs "
        "FOR EACH ROW EXECUTE FUNCTION audit_no_update()"
    )


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS audit_no_update ON audit_logs")
    op.execute("DROP TRIGGER IF EXISTS audit_chain ON audit_logs")
    op.execute("DROP FUNCTION IF EXISTS audit_no_update()")
    op.execute("DROP FUNCTION IF EXISTS audit_chain()")
    op.execute(
        "DROP FUNCTION IF EXISTS audit_row_hash("
        "text, uuid, uuid, text, text, text, text, jsonb, timestamptz)"
    )
    op.execute("DROP INDEX IF EXISTS uq_audit_logs_seq")
    op.execute("ALTER TABLE audit_logs DROP COLUMN row_hash")
    op.execute("ALTER TABLE audit_logs DROP COLUMN prev_hash")
    op.execute("ALTER TABLE audit_logs DROP COLUMN seq")
