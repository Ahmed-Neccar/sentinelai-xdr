import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

from sqlalchemy import and_, delete, or_, select, tuple_

from app.core.config import settings
from app.db.session import SessionLocal, set_organization_context
from app.ingestion.service import process_ingestion_job
from app.models import (
    AuditLog,
    CloudConnector,
    IngestionJob,
    Organization,
    SecurityEvent,
    SystemSetting,
)
from app.workers.celery_app import celery_app


def safe_upload_path(upload_root: Path, stored_path: str | None) -> Path | None:
    """Return an upload file path only when its parent remains inside upload_root.

    Resolve parent directories to reject symlink escapes, but do not resolve the
    final component because cleanup must unlink a symlink itself, not its target.
    """
    if not stored_path:
        return None
    try:
        root = upload_root.resolve()
        candidate = Path(os.path.abspath(stored_path))
        path = candidate.parent.resolve() / candidate.name
        relative = path.relative_to(root)
    except (OSError, ValueError):
        return None
    if not relative.parts or path == root:
        return None
    return path


@celery_app.task(bind=True, name="app.workers.tasks.process_ingestion_job_task", max_retries=3)
def process_ingestion_job_task(self, job_id: str, organization_id: str | None = None) -> None:
    try:
        process_ingestion_job(job_id, organization_id)
    except Exception as exc:
        raise self.retry(exc=exc) from exc


@celery_app.task(bind=True, name="app.workers.tasks.poll_cloud_connector_task", max_retries=2)
def poll_cloud_connector_task(
    self, connector_id: str, organization_id: str
) -> dict[str, str | int]:
    from app.connectors.cloud import poll_cloud_events
    from app.connectors.secrets import decrypt_credentials

    org_id = UUID(organization_id)
    connector_uuid = UUID(connector_id)
    with SessionLocal() as db:
        set_organization_context(db, org_id)
        connector = db.scalar(
            select(CloudConnector).where(CloudConnector.id == connector_uuid).with_for_update()
        )
        if connector is None or not connector.enabled:
            return {"status": "skipped", "events": 0}
        if connector.status == "polling":
            return {"status": "skipped", "events": 0}
        connector.status = "polling"
        connector.last_poll_started_at = datetime.now(UTC)
        connector.last_error = None
        db.commit()
        provider = connector.provider
        config = dict(connector.config or {})
        encrypted_credentials = connector.credentials_encrypted
        source_id = connector.data_source_id
        prior_cursor = dict(connector.cursor or {})

    now = datetime.now(UTC)
    cursor_text = prior_cursor.get("since")
    if cursor_text:
        try:
            since = datetime.fromisoformat(str(cursor_text).replace("Z", "+00:00"))
            if since.tzinfo is None:
                raise ValueError
            since = since.astimezone(UTC) - timedelta(minutes=1)
        except ValueError:
            since = now - timedelta(minutes=15)
    else:
        since = now - timedelta(minutes=15)

    try:
        credentials = decrypt_credentials(encrypted_credentials)
        events, next_cursor, truncated = poll_cloud_events(
            provider, config, credentials, since, now
        )
        with SessionLocal() as db:
            set_organization_context(db, org_id)
            current_connector = db.get(CloudConnector, connector_uuid)
            if current_connector is None or not current_connector.enabled:
                return {"status": "revoked", "events": 0}
        accepted = 0
        if events:
            encoded = json.dumps(events, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
            if len(encoded) > settings.max_upload_bytes:
                raise ValueError("Cloud event page exceeds the configured ingestion limit")
            cloud_root = Path(settings.upload_dir).resolve() / "cloud-connectors"
            cloud_root.mkdir(parents=True, exist_ok=True)
            job_id = UUID(os.urandom(16).hex())
            event_path = cloud_root / f"{job_id}.json"
            with event_path.open("xb") as stream:
                stream.write(encoded)
            with SessionLocal() as db:
                set_organization_context(db, org_id)
                job = IngestionJob(
                    id=job_id,
                    data_source_id=source_id,
                    status="queued",
                    original_filename=f"cloud-connector-{provider}.json",
                    stored_path=str(event_path),
                    adapter=provider,
                    stats={},
                )
                db.add(job)
                db.commit()
            process_ingestion_job(str(job_id), str(org_id))
            with SessionLocal() as db:
                set_organization_context(db, org_id)
                ingested_job = db.get(IngestionJob, job_id)
                if ingested_job is None or ingested_job.status != "completed":
                    raise RuntimeError("Cloud event ingestion did not complete")
                accepted = int((ingested_job.stats or {}).get("accepted", 0))

        with SessionLocal() as db:
            set_organization_context(db, org_id)
            connector = db.get(CloudConnector, connector_uuid)
            if connector is None:
                return {"status": "missing", "events": accepted}
            if not connector.enabled or connector.status == "revoked":
                return {"status": "revoked", "events": accepted}
            connector.cursor = {"since": next_cursor.isoformat()}
            connector.last_success_at = now
            connector.status = "partial" if truncated else "healthy"
            connector.last_error = (
                "Poll page limit reached; next poll resumes from the oldest returned event"
                if truncated
                else None
            )
            db.add(
                AuditLog(
                    action="cloud_connector.poll_completed",
                    target_type="cloud_connector",
                    target_id=str(connector.id),
                    details={
                        "provider": provider,
                        "events_received": len(events),
                        "events_accepted": accepted,
                        "truncated": truncated,
                    },
                )
            )
            db.commit()
        return {"status": "partial" if truncated else "healthy", "events": accepted}
    except Exception as exc:  # noqa: BLE001 — preserve connector health without persisting provider response bodies
        with SessionLocal() as db:
            set_organization_context(db, org_id)
            connector = db.get(CloudConnector, connector_uuid)
            if connector is not None and connector.enabled and connector.status != "revoked":
                connector.status = "error"
                connector.last_error = "Provider poll or event ingestion failed"
                db.add(
                    AuditLog(
                        action="cloud_connector.poll_failed",
                        target_type="cloud_connector",
                        target_id=str(connector.id),
                        details={"provider": provider, "error_type": type(exc).__name__},
                    )
                )
                db.commit()
        raise self.retry(exc=exc, countdown=30) from exc


@celery_app.task(name="app.workers.tasks.poll_due_cloud_connectors_task")
def poll_due_cloud_connectors_task() -> dict[str, int]:
    """Queue due connectors every five minutes without crossing tenant scopes."""
    with SessionLocal() as catalog_db:
        organization_ids = list(catalog_db.scalars(select(Organization.id)))
    queued = 0
    cutoff = datetime.now(UTC) - timedelta(minutes=5)
    lease_cutoff = datetime.now(UTC) - timedelta(minutes=15)
    for organization_id in organization_ids:
        with SessionLocal() as db:
            set_organization_context(db, organization_id)
            rows = db.scalars(
                select(CloudConnector)
                .where(
                    CloudConnector.enabled.is_(True),
                    or_(
                        and_(
                            CloudConnector.status.not_in(("queued", "polling")),
                            (CloudConnector.last_poll_started_at.is_(None))
                            | (CloudConnector.last_poll_started_at < cutoff),
                        ),
                        and_(
                            CloudConnector.status.in_(("queued", "polling")),
                            CloudConnector.last_poll_started_at < lease_cutoff,
                        ),
                    ),
                )
                .with_for_update(skip_locked=True)
                .limit(20)
            ).all()
            ids = [row.id for row in rows]
            for row in rows:
                row.status = "queued"
                row.last_poll_started_at = datetime.now(UTC)
            db.commit()
        for connector_id in ids:
            try:
                poll_cloud_connector_task.delay(str(connector_id), str(organization_id))
                queued += 1
            except Exception:  # noqa: BLE001 — convert broker failure into safe source health
                with SessionLocal() as db:
                    set_organization_context(db, organization_id)
                    connector = db.get(CloudConnector, connector_id)
                    if connector is not None and connector.status == "queued":
                        connector.status = "error"
                        connector.last_error = "Poll could not be queued"
                        db.commit()
    return {"connectors_queued": queued, "organizations_checked": len(organization_ids)}


@celery_app.task(name="app.workers.tasks.deliver_notifications_task")
def deliver_notifications_task() -> dict[str, int]:
    """Send due alert notifications for every organization within its own scope."""
    from app.notifications.service import deliver_pending, purge_delivery_history

    with SessionLocal() as catalog_db:
        organization_ids = list(catalog_db.scalars(select(Organization.id)))
    totals = {"sent": 0, "retry": 0, "failed": 0, "dropped": 0, "purged": 0}
    for organization_id in organization_ids:
        with SessionLocal() as db:
            set_organization_context(db, organization_id)
            for key, value in deliver_pending(db).items():
                totals[key] += value
            totals["purged"] += purge_delivery_history(db)
    return totals


@celery_app.task(name="app.workers.tasks.sweep_response_actions_task")
def sweep_response_actions_task() -> dict[str, int]:
    """Close response actions that ran out of time, for every organization."""
    from app.response.lifecycle import sweep_stale_actions

    with SessionLocal() as catalog_db:
        organization_ids = list(catalog_db.scalars(select(Organization.id)))
    totals = {"cancelled": 0, "failed": 0, "expired": 0}
    for organization_id in organization_ids:
        with SessionLocal() as db:
            set_organization_context(db, organization_id)
            for key, value in sweep_stale_actions(db, datetime.now(UTC)).items():
                totals[key] += value
            db.commit()
    return totals


@celery_app.task(name="app.workers.tasks.push_audit_sinks_task")
def push_audit_sinks_task() -> dict[str, int]:
    """Send new audit rows to every organization's outside collectors."""
    from app.audit.sink import push_all

    with SessionLocal() as catalog_db:
        organization_ids = list(catalog_db.scalars(select(Organization.id)))
    sent = 0
    for organization_id in organization_ids:
        with SessionLocal() as db:
            set_organization_context(db, organization_id)
            sent += push_all(db)
            db.commit()
    return {"rows_sent": sent}


@celery_app.task(name="app.workers.tasks.check_system_health_task")
def check_system_health_task() -> dict[str, int]:
    """Queue alerts for silent sensors and failing cloud connectors, per organization."""
    from app.notifications.health import queue_health_alerts

    with SessionLocal() as catalog_db:
        organization_ids = list(catalog_db.scalars(select(Organization.id)))
    reported = 0
    for organization_id in organization_ids:
        with SessionLocal() as db:
            set_organization_context(db, organization_id)
            reported += queue_health_alerts(db)
    return {"problems_reported": reported, "organizations_checked": len(organization_ids)}


@celery_app.task(name="app.workers.tasks.cleanup_expired_events_task")
def cleanup_expired_events_task(batch_size: int = 1000) -> dict[str, int]:
    """Purge expired telemetry in bounded, tenant-scoped transactions.

    Detection snapshots, cases, and audit logs are intentionally retained. The
    event FK cascades only remove the corresponding DetectionEvidence links.
    """
    if not 1 <= batch_size <= 10_000:
        raise ValueError("batch_size must be between 1 and 10000")

    with SessionLocal() as catalog_db:
        organization_ids = list(catalog_db.scalars(select(Organization.id)))

    deleted_total = 0
    upload_files_deleted = 0
    upload_references_cleared = 0
    failed_organizations = 0
    for organization_id in organization_ids:
        try:
            with SessionLocal() as db:
                set_organization_context(db, organization_id)
                setting = db.scalar(select(SystemSetting).where(SystemSetting.key == "retention"))
                setting_value = setting.value if setting is not None else {}
                retention_days = (setting_value or {}).get("days", settings.retention_days)
                if type(retention_days) is not int or not 1 <= retention_days <= 3650:
                    raise ValueError("Stored retention_days is outside the supported range")
                cutoff = datetime.now(UTC) - timedelta(days=retention_days)

                while True:
                    expired_ids = (
                        select(SecurityEvent.id)
                        .where(SecurityEvent.ingested_at < cutoff)
                        .order_by(SecurityEvent.ingested_at)
                        .limit(batch_size)
                    )
                    deleted_ids = list(
                        db.scalars(
                            delete(SecurityEvent)
                            .where(SecurityEvent.id.in_(expired_ids))
                            .returning(SecurityEvent.id)
                        )
                    )
                    if not deleted_ids:
                        break
                    deleted_total += len(deleted_ids)
                    db.add(
                        AuditLog(
                            action="retention.events_deleted",
                            target_type="security_event_batch",
                            details={
                                "records_deleted": len(deleted_ids),
                                "retention_days": retention_days,
                                "cutoff": cutoff.isoformat(),
                                "basis": "ingested_at",
                            },
                        )
                    )
                    db.commit()

                upload_setting = db.scalar(
                    select(SystemSetting).where(SystemSetting.key == "upload_retention")
                )
                upload_setting_value = upload_setting.value if upload_setting is not None else {}
                upload_retention_days = (upload_setting_value or {}).get(
                    "days", settings.upload_retention_days
                )
                if type(upload_retention_days) is not int or not 1 <= upload_retention_days <= 3650:
                    raise ValueError("Stored upload_retention_days is outside the supported range")
                upload_cutoff = datetime.now(UTC) - timedelta(days=upload_retention_days)
                upload_root = Path(settings.upload_dir).resolve()
                cursor: tuple[datetime, UUID] | None = None
                while True:
                    jobs_query = select(IngestionJob).where(
                        IngestionJob.status.in_(("completed", "failed")),
                        IngestionJob.stored_path.is_not(None),
                        IngestionJob.created_at < upload_cutoff,
                    )
                    if cursor is not None:
                        jobs_query = jobs_query.where(
                            tuple_(IngestionJob.created_at, IngestionJob.id) > cursor
                        )
                    jobs = list(
                        db.scalars(
                            jobs_query.order_by(IngestionJob.created_at, IngestionJob.id).limit(
                                batch_size
                            )
                        )
                    )
                    if not jobs:
                        break
                    cursor = (jobs[-1].created_at, jobs[-1].id)
                    removed = 0
                    cleared = 0
                    for job in jobs:
                        path = safe_upload_path(upload_root, job.stored_path)
                        if path is None:
                            continue
                        try:
                            existed = path.is_file() or path.is_symlink()
                            path.unlink(missing_ok=True)
                        except OSError:
                            continue
                        job.stored_path = None
                        cleared += 1
                        removed += int(existed)
                    if cleared:
                        db.add(
                            AuditLog(
                                action="retention.uploads_deleted",
                                target_type="ingestion_job_batch",
                                details={
                                    "files_deleted": removed,
                                    "job_references_cleared": cleared,
                                    "retention_days": upload_retention_days,
                                    "cutoff": upload_cutoff.isoformat(),
                                    "basis": "job_created_at",
                                },
                            )
                        )
                        db.commit()
                        upload_files_deleted += removed
                        upload_references_cleared += cleared
        except Exception:
            failed_organizations += 1

    if failed_organizations:
        raise RuntimeError(
            f"Retention cleanup failed for {failed_organizations} organization(s); "
            f"{deleted_total} event(s) were deleted before the failure"
        )
    return {
        "organizations_processed": len(organization_ids),
        "events_deleted": deleted_total,
        "upload_files_deleted": upload_files_deleted,
        "upload_references_cleared": upload_references_cleared,
    }
