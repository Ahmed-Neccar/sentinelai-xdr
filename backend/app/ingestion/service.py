from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.session import set_organization_context
from app.detection.run import run_detection_for_job
from app.ingestion.parsers import ADAPTERS, RowError, load_records, validate_normalized_event
from app.models import DataSource, IngestionJob, SecurityEvent

INSERT_BATCH_ROWS = 500


def insert_events(db: Session, rows: list[dict]) -> int:
    """Insert event rows in one statement and return how many were new.

    A row whose dedup key already exists for the organization is skipped by the database
    (`ON CONFLICT DO NOTHING`), which also covers duplicates inside the batch itself. One
    statement per few hundred rows replaces a lookup and a savepoint for every row.
    """
    if not rows:
        return 0
    statement = (
        pg_insert(SecurityEvent)
        .values(rows)
        .on_conflict_do_nothing(
            index_elements=[SecurityEvent.organization_id, SecurityEvent.dedup_key]
        )
        .returning(SecurityEvent.id)
    )
    return len(db.execute(statement).all())


def safe_filename(name: str) -> str:
    base = Path(name).name
    if not base or base in {".", ".."}:
        return "upload.bin"
    return base.replace("\x00", "")[:200]


def process_ingestion_job(
    job_id: str | UUID, organization_id: str | UUID | None = None, session_factory=None
) -> None:
    from app.db.session import SessionLocal
    from app.models import Organization

    factory = session_factory or SessionLocal
    db: Session = factory()
    try:
        if organization_id is None:
            organization = db.scalar(
                select(Organization).where(
                    Organization.slug == settings.default_organization_slug
                )
            )
            if organization is None:
                return
            organization_id = organization.id
        set_organization_context(db, UUID(str(organization_id)))
        job = db.get(IngestionJob, UUID(str(job_id)))
        if job is None:
            return
        job.status = "running"
        job.started_at = datetime.now(UTC)
        db.commit()
        path = Path(job.stored_path or "")
        content = path.read_bytes() if path.exists() else b"[]"
        adapter = job.adapter if job.adapter in ADAPTERS else "generic_json"
        normalizer = ADAPTERS[adapter]
        try:
            records = load_records(
                content, job.original_filename, adapter, settings.max_upload_rows
            )
        except (ValueError, OSError) as exc:
            job.status = "failed"
            job.error = str(exc)
            job.completed_at = datetime.now(UTC)
            job.stats = {"accepted": 0, "quarantined": 0, "duplicates": 0}
            db.commit()
            return
        accepted = 0
        quarantined: list[dict] = []
        duplicates = 0
        detections = 0
        pending: list[dict] = []
        for index, raw in enumerate(records, start=1):
            if not isinstance(raw, dict):
                quarantined.append({"row": index, "error": "Row is not an object"})
                continue
            try:
                normalized = validate_normalized_event(normalizer(raw, index), index)
            except RowError as exc:
                quarantined.append({"row": exc.row_number, "error": exc.message})
                continue
            pending.append(
                {
                    "id": uuid4(),
                    "event_time": normalized["event_time"],
                    "data_source_id": job.data_source_id,
                    "ingestion_job_id": job.id,
                    "event_type": normalized["event_type"],
                    "src_ip": normalized.get("src_ip"),
                    "dst_ip": normalized.get("dst_ip"),
                    "src_port": normalized.get("src_port"),
                    "dst_port": normalized.get("dst_port"),
                    "host_id": normalized.get("host_id"),
                    "severity": normalized.get("severity") or "informational",
                    "attributes": normalized.get("attributes") or {},
                    "raw_payload": normalized.get("raw_payload") or {},
                    "schema_version": normalized.get("schema_version") or 1,
                    "dedup_key": normalized.get("dedup_key"),
                }
            )
            if len(pending) >= INSERT_BATCH_ROWS:
                inserted = insert_events(db, pending)
                accepted += inserted
                duplicates += len(pending) - inserted
                pending = []
        inserted = insert_events(db, pending)
        accepted += inserted
        duplicates += len(pending) - inserted
        try:
            detections = run_detection_for_job(db, job.id)
        except Exception as exc:  # noqa: BLE001 — persist job failure, do not crash worker silently
            job.status = "failed"
            job.error = f"Detection processing failed: {exc.__class__.__name__}"
            job.completed_at = datetime.now(UTC)
            job.stats = {
                "accepted": accepted,
                "quarantined": len(quarantined),
                "duplicates": duplicates,
                "quarantine_samples": quarantined[:50],
            }
            db.commit()
            return
        if job.data_source_id:
            source = db.get(DataSource, job.data_source_id)
            if source:
                source.last_seen_at = datetime.now(UTC)
                source.last_error = (
                    None if not quarantined else f"{len(quarantined)} rows quarantined"
                )
        job.status = "completed"
        job.completed_at = datetime.now(UTC)
        job.error = None
        job.stats = {
            "accepted": accepted,
            "quarantined": len(quarantined),
            "duplicates": duplicates,
            "detections_created": detections,
            "quarantine_samples": quarantined[:50],
        }
        db.commit()
    except Exception:
        db.rollback()
        job = db.get(IngestionJob, UUID(str(job_id)))
        if job:
            job.status = "failed"
            job.error = "Job failed unexpectedly"
            job.completed_at = datetime.now(UTC)
            db.commit()
        raise
    finally:
        db.close()
