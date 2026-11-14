"""File ingestion inserts in bulk and still counts duplicates correctly (needs PostgreSQL)."""

import json
import os
from uuid import uuid4

import pytest
from app.db.session import SessionLocal, set_organization_context
from app.ingestion.service import INSERT_BATCH_ROWS, process_ingestion_job
from app.models import DataSource, IngestionJob, Organization, SecurityEvent
from sqlalchemy import delete, func, select

pytestmark = pytest.mark.skipif(
    not os.environ.get("MFA_TEST_DATABASE_URL"),
    reason="Bulk ingestion test requires a migrated PostgreSQL test database",
)


def _record(i: int, dedup: str | None) -> dict:
    return {
        "event_time": "2026-11-14T10:00:00Z",
        "event_type": "auth.failure",
        "src_ip": f"10.0.{i // 250}.{i % 250 + 1}",
        "host_id": f"host-{i % 7}",
        "dedup_key": dedup,
    }


def _run(organization_id, tmp_path, name: str, records: list[dict]) -> dict:
    path = tmp_path / name
    path.write_text(json.dumps(records), encoding="utf-8")
    with SessionLocal() as db:
        set_organization_context(db, organization_id)
        source = db.scalar(select(DataSource).where(DataSource.name == "bulk-test"))
        if source is None:
            source = DataSource(name="bulk-test", source_type="file")
            db.add(source)
            db.flush()
        job = IngestionJob(
            data_source_id=source.id,
            original_filename=name,
            stored_path=str(path),
            adapter="generic_json",
        )
        db.add(job)
        db.commit()
        job_id = job.id
    process_ingestion_job(job_id, organization_id)
    with SessionLocal() as db:
        set_organization_context(db, organization_id)
        finished = db.get(IngestionJob, job_id)
        assert finished.status == "completed", finished.error
        return dict(finished.stats)


def test_bulk_insert_counts_new_rows_and_duplicates(tmp_path) -> None:
    organization_id = uuid4()
    with SessionLocal() as db:
        db.add(Organization(id=organization_id, slug=f"bulk-{organization_id.hex}", name="Bulk"))
        db.commit()
    try:
        # More rows than one batch, some without a dedup key, some repeated inside the file.
        total = INSERT_BATCH_ROWS + 120
        first = [_record(i, f"k-{i}" if i % 3 else None) for i in range(total)]
        first += [_record(1, "k-1"), _record(2, "k-2"), _record(7, "k-7")]
        stats = _run(organization_id, tmp_path, "first.json", first)
        assert stats["accepted"] == total
        assert stats["duplicates"] == 3
        assert stats["quarantined"] == 0

        # The same file again: only the rows without a key are new.
        stats = _run(organization_id, tmp_path, "second.json", first)
        keyless = len([r for r in first if r["dedup_key"] is None])
        assert stats["accepted"] == keyless
        assert stats["duplicates"] == len(first) - keyless

        with SessionLocal() as db:
            set_organization_context(db, organization_id)
            stored = db.scalar(select(func.count()).select_from(SecurityEvent))
            assert stored == total + keyless
    finally:
        with SessionLocal() as db:
            set_organization_context(db, organization_id)
            db.execute(delete(Organization).where(Organization.id == organization_id))
            db.commit()
