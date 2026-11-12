"""Queue and deliver alert notifications through a transactional outbox."""

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app.connectors.secrets import decrypt_credentials
from app.models import (
    AuditLog,
    CaseDetection,
    Detection,
    NotificationChannel,
    NotificationDelivery,
)
from app.notifications.delivery import DeliveryError, build_message, send, severity_rank

MAX_ATTEMPTS = 5
PENDING_TTL = timedelta(hours=24)
HISTORY_TTL = timedelta(days=30)
Sender = Callable[[str, dict[str, str], dict[str, Any]], None]


def enqueue_detection_notifications(db: Session, detection: Detection) -> int:
    """Add outbox rows for a new detection in the caller's transaction.

    The rows commit or roll back together with the detection, so a notification
    is never sent for a finding that was not stored.
    """
    channels = db.scalars(
        select(NotificationChannel).where(NotificationChannel.enabled.is_(True))
    ).all()
    queued = 0
    for channel in channels:
        if severity_rank(detection.severity) < severity_rank(channel.min_severity):
            continue
        inserted = db.scalar(
            pg_insert(NotificationDelivery)
            .values(channel_id=channel.id, detection_id=detection.id, kind="detection")
            .on_conflict_do_nothing(
                index_elements=[
                    NotificationDelivery.organization_id,
                    NotificationDelivery.channel_id,
                    NotificationDelivery.detection_id,
                ]
            )
            .returning(NotificationDelivery.id)
        )
        queued += int(inserted is not None)
    return queued


RESPONSE_EVENTS: dict[str, tuple[str, str]] = {
    # event -> (severity shown in the message, title)
    "approval_needed": ("high", "Approval needed: {label} was proposed"),
    "rejected": ("informational", "{label} proposal rejected"),
    "applied": ("medium", "{label} applied by the sensor"),
    "refused": ("high", "{label} refused by the sensor"),
    "failed": ("high", "{label} failed on the sensor"),
    "removed": ("informational", "{label} lifted"),
}


def response_message(
    event: str,
    *,
    case_id: str,
    target: str,
    sensor: str,
    minutes: int | None,
    detail: str = "",
    label: str = "IP block",
) -> dict[str, Any]:
    severity, title = RESPONSE_EVENTS[event]
    title = title.format(label=label if event != "approval_needed" else f"a real {label}")
    summary = f"Target {target} on sensor {sensor}"
    if minutes:
        summary += f" for {minutes} minutes"
    if detail:
        summary += f". {detail}"
    message = build_message(
        event_type=f"response.{event}",
        title=title,
        severity=severity,
        case_id=case_id,
        created_at=datetime.now(UTC).isoformat(timespec="seconds"),
        summary=summary,
    )
    message["note"] = (
        "Open the case in SentinelAI to review. A different administrator must approve."
        if event == "approval_needed"
        else "Recorded in the SentinelAI audit log."
    )
    return message


def enqueue_response_notifications(db: Session, message: dict[str, Any]) -> int:
    """Queue one response-workflow message for every enabled channel.

    Runs in the caller's transaction, like detections. Severity thresholds do
    not apply: these are operational messages about an action people asked for.
    """
    channels = db.scalars(
        select(NotificationChannel).where(NotificationChannel.enabled.is_(True))
    ).all()
    for channel in channels:
        db.add(NotificationDelivery(channel_id=channel.id, kind="response", payload=message))
    return len(channels)


def _message_for(db: Session, delivery: NotificationDelivery, channel: NotificationChannel) -> dict:
    if delivery.kind == "response" and isinstance(delivery.payload, dict):
        message = dict(delivery.payload)
        if not channel.include_summary:
            # The summary names an address and a host; it leaves the
            # installation only for channels that opted in, as for findings.
            message.pop("summary", None)
        return message
    if delivery.kind == "test" or delivery.detection_id is None:
        return build_message(
            event_type="test",
            title=f"Test notification for channel {channel.name}",
            severity="informational",
            created_at=datetime.now(UTC).isoformat(timespec="seconds"),
        )
    detection = db.get(Detection, delivery.detection_id)
    if detection is None:
        raise LookupError("detection no longer exists")
    case_id = db.scalar(
        select(CaseDetection.case_id).where(CaseDetection.detection_id == detection.id).limit(1)
    )
    return build_message(
        event_type="detection",
        title=detection.title,
        severity=detection.severity,
        rule_id=detection.rule_id,
        detector_kind=detection.detector_kind,
        detection_id=str(detection.id),
        case_id=str(case_id) if case_id else None,
        created_at=detection.created_at.isoformat(timespec="seconds")
        if detection.created_at
        else None,
        summary=detection.summary if channel.include_summary else None,
    )


def deliver_pending(
    db: Session, *, limit: int = 20, sender: Sender = send, now: datetime | None = None
) -> dict[str, int]:
    """Send due outbox rows for the session's organization, one transaction each.

    Each row is locked only while it is being sent, so overlapping worker runs
    skip it instead of sending a duplicate.
    """
    counts = {"sent": 0, "retry": 0, "failed": 0, "dropped": 0}
    for _ in range(limit):
        current = now or datetime.now(UTC)
        delivery = db.scalar(
            select(NotificationDelivery)
            .where(
                NotificationDelivery.status == "pending",
                NotificationDelivery.next_attempt_at <= current,
            )
            .order_by(NotificationDelivery.created_at)
            .limit(1)
            .with_for_update(skip_locked=True)
        )
        if delivery is None:
            break
        channel = db.get(NotificationChannel, delivery.channel_id)
        if channel is None or not channel.enabled:
            delivery.status, delivery.last_error = "dropped", "Channel is disabled"
            counts["dropped"] += 1
        elif delivery.created_at and current - delivery.created_at > PENDING_TTL:
            delivery.status, delivery.last_error = "dropped", "Expired before delivery"
            counts["dropped"] += 1
        else:
            try:
                message = _message_for(db, delivery, channel)
                sender(channel.kind, decrypt_credentials(channel.target_encrypted), message)
            except LookupError:
                delivery.status, delivery.last_error = "dropped", "Detection was removed"
                counts["dropped"] += 1
            except Exception as exc:  # noqa: BLE001 — never persist destination details
                reason = str(exc) if isinstance(exc, DeliveryError) else type(exc).__name__
                delivery.attempts += 1
                delivery.last_error = reason[:300]
                channel.last_error = reason[:300]
                if delivery.attempts >= MAX_ATTEMPTS:
                    delivery.status = "failed"
                    counts["failed"] += 1
                    db.add(
                        AuditLog(
                            action="notification.delivery_failed",
                            target_type="notification_channel",
                            target_id=str(channel.id),
                            details={"attempts": delivery.attempts, "kind": delivery.kind},
                        )
                    )
                else:
                    delivery.next_attempt_at = current + timedelta(
                        seconds=30 * 2**delivery.attempts
                    )
                    counts["retry"] += 1
            else:
                delivery.status = "sent"
                delivery.sent_at = current
                delivery.attempts += 1
                delivery.last_error = None
                channel.last_success_at = current
                channel.last_error = None
                counts["sent"] += 1
        db.commit()
    return counts


def purge_delivery_history(db: Session, *, now: datetime | None = None) -> int:
    """Remove finished outbox rows older than the history window."""
    cutoff = (now or datetime.now(UTC)) - HISTORY_TTL
    removed = db.scalars(
        delete(NotificationDelivery)
        .where(
            NotificationDelivery.status != "pending",
            NotificationDelivery.created_at < cutoff,
        )
        .returning(NotificationDelivery.id)
    ).all()
    db.commit()
    return len(removed)
