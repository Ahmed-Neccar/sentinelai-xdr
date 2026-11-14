import os

import pytest
from app.db.session import SessionLocal
from sqlalchemy import text

pytestmark = pytest.mark.skipif(
    not os.environ.get("MFA_TEST_DATABASE_URL"),
    reason="Index check requires a migrated PostgreSQL test database",
)


def test_trigram_indexes_exist_after_migration() -> None:
    with SessionLocal() as db:
        names = set(
            db.scalars(
                text("select indexname from pg_indexes where tablename = 'security_events'")
            )
        )
    assert {"ix_security_events_event_type_trgm", "ix_security_events_host_id_trgm"} <= names
