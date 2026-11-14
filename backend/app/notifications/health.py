"""System-health alerts: a sensor that stopped reporting, a cloud connector that is failing.

Detections are only one thing an operator needs to hear about. These messages go through the
same outbox and channels as response notifications. One message per problem is queued, and the
same problem is repeated at most every REPEAT_AFTER while it lasts.
"""

from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import CloudConnector, IngestionJob, NotificationChannel, NotificationDelivery
from app.notifications.delivery import build_message

SENSOR_SILENT_AFTER = timedelta(minutes=5)
# A live session that stopped long ago is an abandoned record, not a news item.
SENSOR_ABANDONED_AFTER = timedelta(hours=24)
CONNECTOR_STALE_AFTER = timedelta(minutes=30)
REPEAT_AFTER = timedelta(hours=6)


def _already_reported(db: Session, key: str, now: datetime) -> bool:
    return (
        db.scalar(
            select(NotificationDelivery.id)
            .where(
                NotificationDelivery.kind == "system",
                NotificationDelivery.payload["health_key"].astext == key,
                NotificationDelivery.created_at > now - REPEAT_AFTER,
            )
            .limit(1)
        )
        is not None
    )


def _queue(
    db: Session,
    channels: list[NotificationChannel],
    key: str,
    title: str,
    summary: str,
    now: datetime,
) -> None:
    message: dict[str, Any] = build_message(
        event_type="system.health",
        title=title,
        severity="high",
        created_at=now.isoformat(timespec="seconds"),
        summary=summary,
    )
    message["note"] = (
        "A health alert about this SentinelAI installation; "
        "check the Sensors or Cloud connectors page."
    )
    message["health_key"] = key
    for channel in channels:
        db.add(NotificationDelivery(channel_id=channel.id, kind="system", payload=message))


def silent_sensors(db: Session, now: datetime) -> list[IngestionJob]:
    """Live sessions still marked running whose heartbeat stopped a few minutes ago."""
    return list(
        db.scalars(
            select(IngestionJob).where(
                IngestionJob.original_filename.like("live-capture:%"),
                IngestionJob.status == "running",
                IngestionJob.last_heartbeat_at < now - SENSOR_SILENT_AFTER,
                IngestionJob.last_heartbeat_at > now - SENSOR_ABANDONED_AFTER,
            )
        )
    )


def failing_connectors(db: Session, now: datetime) -> list[CloudConnector]:
    rows = db.scalars(
        select(CloudConnector).where(
            CloudConnector.enabled.is_(True), CloudConnector.last_poll_started_at.is_not(None)
        )
    )
    failing = []
    for connector in rows:
        reference = connector.last_success_at or connector.created_at
        if connector.status == "error" or (reference and now - reference > CONNECTOR_STALE_AFTER):
            failing.append(connector)
    return failing


def queue_health_alerts(db: Session, now: datetime | None = None) -> int:
    """Queue alerts for the session's organization; returns how many problems were reported."""
    current = now or datetime.now(UTC)
    channels = list(
        db.scalars(select(NotificationChannel).where(NotificationChannel.enabled.is_(True)))
    )
    if not channels:
        return 0
    reported = 0
    for job in silent_sensors(db, current):
        key = f"sensor:{job.id}"
        if _already_reported(db, key, current):
            continue
        heartbeat = job.last_heartbeat_at or current
        minutes = int((current - heartbeat).total_seconds() // 60)
        name = job.original_filename.removeprefix("live-capture:")
        _queue(
            db,
            channels,
            key,
            "A sensor stopped reporting",
            f"Sensor {name} sent its last heartbeat {minutes} minutes ago.",
            current,
        )
        reported += 1
    for connector in failing_connectors(db, current):
        key = f"connector:{connector.id}"
        if _already_reported(db, key, current):
            continue
        reason = (connector.last_error or "no recent successful poll")[:200]
        _queue(
            db,
            channels,
            key,
            "A cloud connector is failing",
            f"Connector {connector.name} ({connector.provider}): {reason}",
            current,
        )
        reported += 1
    if reported:
        db.commit()
    return reported


SENSOR_ONLINE_WITHIN = timedelta(seconds=30)


def health_snapshot(db: Session, now: datetime | None = None) -> dict[str, Any]:
    """What the Overview page shows about the installation's own health.

    Read-only and tenant-scoped through the session. A sensor is "online" when its running
    session sent a heartbeat in the last 30 seconds and "silent" when it is still marked running
    but has been quiet for the alert threshold (see `silent_sensors`).
    """
    current = now or datetime.now(UTC)
    live = IngestionJob.original_filename.like("live-capture:%")
    online = db.scalar(
        select(func.count())
        .select_from(IngestionJob)
        .where(
            live,
            IngestionJob.status == "running",
            IngestionJob.last_heartbeat_at > current - SENSOR_ONLINE_WITHIN,
        )
    )
    silent = [
        {
            "name": job.original_filename.removeprefix("live-capture:"),
            "last_heartbeat_at": job.last_heartbeat_at,
        }
        for job in silent_sensors(db, current)
    ]
    problem_ids = {connector.id for connector in failing_connectors(db, current)}
    connectors = [
        {
            "name": connector.name,
            "provider": connector.provider,
            "status": connector.status,
            "healthy": connector.enabled and connector.id not in problem_ids,
            "enabled": connector.enabled,
            "last_success_at": connector.last_success_at,
            "last_error": connector.last_error,
        }
        for connector in db.scalars(select(CloudConnector).order_by(CloudConnector.name))
    ]
    channels = db.scalar(
        select(func.count())
        .select_from(NotificationChannel)
        .where(NotificationChannel.enabled.is_(True))
    )
    since = current - timedelta(hours=24)
    delivery: dict[str, int] = {
        status: count
        for status, count in db.execute(
            select(NotificationDelivery.status, func.count())
            .where(NotificationDelivery.created_at > since)
            .group_by(NotificationDelivery.status)
        ).all()
    }
    return {
        "generated_at": current,
        "sensors": {"online": online or 0, "silent": silent},
        "connectors": connectors,
        "notifications": {
            "enabled_channels": channels or 0,
            "pending": delivery.get("pending", 0),
            "failed_24h": delivery.get("failed", 0),
        },
    }
