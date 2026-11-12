"""Tell people about IP-block workflow events through the notification outbox."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import DataSource, ResponseSimulation, SensorRegistration
from app.notifications.service import enqueue_response_notifications, response_message


def sensor_name(db: Session, simulation: ResponseSimulation) -> str:
    if simulation.sensor_id is None:
        return "unknown"
    source = db.scalar(
        select(DataSource)
        .join(SensorRegistration, SensorRegistration.data_source_id == DataSource.id)
        .where(SensorRegistration.sensor_id == simulation.sensor_id)
    )
    if source is None:
        return str(simulation.sensor_id)[:8]
    return str((source.config or {}).get("host_name") or source.name)[:120]


def notify_block_event(
    db: Session, event: str, simulation: ResponseSimulation, detail: str = ""
) -> int:
    """Queue a message in the caller's transaction; never raises into the workflow."""
    try:
        with_duration = event in {"approval_needed", "applied"}
        message = response_message(
            event,
            case_id=str(simulation.case_id),
            target=simulation.target,
            sensor=sensor_name(db, simulation),
            minutes=simulation.duration_minutes if with_duration else None,
            detail=detail[:200],
        )
        with db.begin_nested():
            return enqueue_response_notifications(db, message)
    except Exception:  # noqa: BLE001 - a notification problem must not block a response action
        return 0
