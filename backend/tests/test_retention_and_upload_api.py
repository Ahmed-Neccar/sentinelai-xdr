import json
from datetime import UTC, datetime, timedelta

from app.models import AuditLog, IngestionJob, SecurityEvent, SystemSetting
from app.workers.tasks import cleanup_expired_events_task
from sqlalchemy import func, select


def _event(label: str, age_days: int) -> SecurityEvent:
    when = datetime.now(UTC) - timedelta(days=age_days)
    return SecurityEvent(
        event_time=when,
        ingested_at=when,
        event_type="auth.failure",
        host_id=label,
        dedup_key=f"retention-{label}",
    )


def _count(tenant) -> int:
    with tenant.session() as db:
        return db.scalar(select(func.count()).select_from(SecurityEvent)) or 0


def test_retention_deletes_only_expired_events_of_the_organization(tenant) -> None:
    with tenant.session() as db:
        db.add(SystemSetting(key="retention", value={"days": 10}))
        db.add_all(
            [_event("old-1", 30), _event("old-2", 11), _event("new-1", 9), _event("new-2", 0)]
        )
        db.commit()

    cleanup_expired_events_task()

    with tenant.session() as db:
        hosts = set(db.scalars(select(SecurityEvent.host_id)))
        assert hosts == {"new-1", "new-2"}
        audit = db.scalars(
            select(AuditLog).where(AuditLog.action == "retention.events_deleted")
        ).all()
        assert sum(row.details["records_deleted"] for row in audit) == 2
        assert all(row.details["retention_days"] == 10 for row in audit)


def test_retention_uses_the_default_when_no_setting_exists_and_keeps_recent_data(tenant) -> None:
    with tenant.session() as db:
        db.add_all([_event("fresh", 1), _event("ancient", 4000)])
        db.commit()
    cleanup_expired_events_task()
    with tenant.session() as db:
        assert set(db.scalars(select(SecurityEvent.host_id))) == {"fresh"}


def test_cleanup_rejects_a_bad_batch_size() -> None:
    import pytest

    for value in (0, 10_001):
        with pytest.raises(ValueError):
            cleanup_expired_events_task(batch_size=value)


def test_upload_validation_and_processing(tenant, tmp_path, monkeypatch) -> None:
    from app.core.config import settings

    monkeypatch.setattr(settings, "upload_dir", str(tmp_path))
    client, h = tenant.client, tenant.headers
    rows = [
        {"event_time": "2026-11-14T10:00:00Z", "event_type": "auth.failure", "src_ip": "10.0.0.1"},
        {"event_time": "2026-11-14T10:00:01Z", "event_type": "auth.success", "src_ip": "10.0.0.1"},
        {"event_type": "missing-time"},
    ]
    files = {"file": ("events.json", json.dumps(rows), "application/json")}
    uploaded = client.post("/api/v1/ingest/upload", headers=h["analyst"], files=files)
    assert uploaded.status_code == 202, uploaded.text
    job_id = uploaded.json()["id"]

    # The inline runner has processed the file by the time the response returns.
    job = client.get(f"/api/v1/ingest/jobs/{job_id}", headers=h["analyst"]).json()
    assert job["status"] == "completed", job
    assert job["stats"]["accepted"] == 2 and job["stats"]["quarantined"] == 1
    quarantine = client.get(f"/api/v1/ingest/jobs/{job_id}/quarantine", headers=h["analyst"]).json()
    assert len(quarantine["items"]) == 1
    assert client.get("/api/v1/ingest/jobs", headers=h["analyst"]).json()["total"] == 1
    assert _count(tenant) == 2

    # Idempotency keys return the existing job instead of a second one.
    first = client.post(
        "/api/v1/ingest/upload",
        headers={**h["analyst"], "Idempotency-Key": "upload-key-0001"},
        files={"file": ("again.json", json.dumps(rows[:1]), "application/json")},
    )
    second = client.post(
        "/api/v1/ingest/upload",
        headers={**h["analyst"], "Idempotency-Key": "upload-key-0001"},
        files={"file": ("again.json", json.dumps(rows[:1]), "application/json")},
    )
    assert first.json()["id"] == second.json()["id"]

    # Rejections.
    bad_type = client.post(
        "/api/v1/ingest/upload",
        headers=h["analyst"],
        files={"file": ("events.exe", "x", "application/octet-stream")},
    )
    assert bad_type.status_code == 400
    bad_adapter = client.post(
        "/api/v1/ingest/upload",
        headers=h["analyst"],
        data={"adapter": "nonsense"},
        files={"file": ("events.json", "[]", "application/json")},
    )
    assert bad_adapter.status_code == 400
    unknown_source = client.post(
        "/api/v1/ingest/upload",
        headers=h["analyst"],
        data={"data_source_id": "00000000-0000-0000-0000-000000000000"},
        files={"file": ("events.json", "[]", "application/json")},
    )
    assert unknown_source.status_code == 400
    assert (
        client.post(
            "/api/v1/ingest/upload", headers=h["auditor"], files={"file": ("e.json", "[]", "x/y")}
        ).status_code
        == 403
    )
    assert (
        client.get(
            "/api/v1/ingest/jobs/00000000-0000-0000-0000-000000000000", headers=h["analyst"]
        ).status_code
        == 404
    )


def test_oversized_upload_is_refused(tenant, tmp_path, monkeypatch) -> None:
    from app.core.config import settings

    monkeypatch.setattr(settings, "upload_dir", str(tmp_path))
    monkeypatch.setattr(settings, "max_upload_bytes", 100)
    response = tenant.client.post(
        "/api/v1/ingest/upload",
        headers=tenant.headers["analyst"],
        files={"file": ("big.json", "[" + " " * 500 + "]", "application/json")},
    )
    assert response.status_code == 413
    with tenant.session() as db:
        assert db.scalar(select(func.count()).select_from(IngestionJob)) == 0
