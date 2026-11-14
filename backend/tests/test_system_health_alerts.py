"""Silent sensor and failing connector alerts, against a real database (skipped without one)."""

import os
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from app.connectors.secrets import encrypt_credentials
from app.db.session import SessionLocal, set_organization_context
from app.models import (
    CloudConnector,
    DataSource,
    IngestionJob,
    NotificationChannel,
    NotificationDelivery,
    Organization,
)
from app.notifications.health import queue_health_alerts
from app.notifications.service import deliver_pending
from sqlalchemy import delete, select

pytestmark = pytest.mark.skipif(
    not os.environ.get("MFA_TEST_DATABASE_URL"),
    reason="Health alert test requires a migrated PostgreSQL test database",
)


def _slug(organization_id) -> str:
    return f"health-{organization_id.hex}"


def _live_job(
    name: str, heartbeat_age: timedelta, now: datetime, status: str = "running"
) -> IngestionJob:
    return IngestionJob(
        status=status,
        original_filename=f"live-capture:{name}",
        last_heartbeat_at=now - heartbeat_age,
    )


def test_silent_sensors_and_failing_connectors_are_reported_once() -> None:
    organization_id = uuid4()
    now = datetime.now(UTC)
    with SessionLocal() as db:
        db.add(Organization(id=organization_id, slug=_slug(organization_id), name="Health"))
        db.commit()
    try:
        with SessionLocal() as db:
            set_organization_context(db, organization_id)
            channel = NotificationChannel(
                name="ops",
                kind="slack",
                target_encrypted=encrypt_credentials({"url": "https://hooks.example.com/x"}),
                min_severity="high",
                include_summary=True,
                enabled=True,
            )
            db.add(channel)
            source = DataSource(name="azure-1", source_type="cloud")
            db.add(source)
            db.flush()
            db.add_all(
                [
                    _live_job("silent-pc", timedelta(minutes=20), now),
                    _live_job("healthy-pc", timedelta(seconds=10), now),
                    _live_job("stopped-pc", timedelta(minutes=20), now, status="completed"),
                    _live_job("abandoned-pc", timedelta(days=3), now),
                ]
            )
            db.add(
                CloudConnector(
                    data_source_id=source.id,
                    name="azure-prod",
                    provider="azure_activity",
                    credentials_encrypted="x",
                    status="error",
                    last_error="Authentication failed",
                    last_poll_started_at=now,
                )
            )
            db.commit()

            assert queue_health_alerts(db, now) == 2
            rows = db.scalars(select(NotificationDelivery)).all()
            assert len(rows) == 2 and {row.kind for row in rows} == {"system"}
            text = " ".join(str(row.payload) for row in rows)
            assert "silent-pc" in text and "azure-prod" in text
            for other in ("healthy-pc", "stopped-pc", "abandoned-pc"):
                assert other not in text

            # The same problems are not queued again straight away, only after the repeat window.
            assert queue_health_alerts(db, now + timedelta(minutes=2)) == 0
            # Seven hours on, the two problems repeat, and the sensor that was healthy has
            # now been silent for hours as well.
            assert queue_health_alerts(db, now + timedelta(hours=7)) == 3

            sent: list[dict] = []
            counts = deliver_pending(db, sender=lambda kind, target, message: sent.append(message))
            assert counts["sent"] >= 5 and sent
            assert all(m["type"] == "system.health" and "health_key" not in m for m in sent)
    finally:
        with SessionLocal() as db:
            set_organization_context(db, organization_id)
            db.execute(delete(Organization).where(Organization.id == organization_id))
            db.commit()


def test_no_channel_means_no_alerts() -> None:
    organization_id = uuid4()
    now = datetime.now(UTC)
    with SessionLocal() as db:
        db.add(Organization(id=organization_id, slug=_slug(organization_id), name="Health"))
        db.commit()
    try:
        with SessionLocal() as db:
            set_organization_context(db, organization_id)
            db.add(_live_job("silent-pc", timedelta(minutes=20), now))
            db.commit()
            assert queue_health_alerts(db, now) == 0
    finally:
        with SessionLocal() as db:
            set_organization_context(db, organization_id)
            db.execute(delete(Organization).where(Organization.id == organization_id))
            db.commit()
