"""Time limits of an executed response action, applied whether or not its sensor is reachable.

Without this, a deadline was only checked when the sensor next contacted the server, so a sensor
that never came back left its action "pending" for ever. The sweep runs every minute for every
organization, and the same function runs for one sensor at each heartbeat.
"""

from datetime import datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.audit.service import write_audit
from app.models import ResponseSimulation
from app.response import ip_block
from app.response.notify import notify_block_event


def sweep_stale_actions(
    db: Session, now: datetime, *, sensor_id: UUID | None = None
) -> dict[str, int]:
    """Close what ran out of time. The caller commits.

    - approved but never handed to a sensor within DELIVERY_WINDOW: cancelled;
    - handed to a sensor that never answered within EXECUTION_TIMEOUT: failed (timeout);
    - proposed and never approved before its own expiry: expired.
    """
    counts = {"cancelled": 0, "failed": 0, "expired": 0}
    query = select(ResponseSimulation).where(
        ResponseSimulation.action_type.in_(list(ip_block.EXECUTED))
    )
    if sensor_id is not None:
        query = query.where(ResponseSimulation.sensor_id == sensor_id)
    rows = db.scalars(
        query.where(
            (ResponseSimulation.status == "proposed")
            | (
                ResponseSimulation.enforcement_status.in_(
                    [ip_block.PENDING, ip_block.DISPATCHED]
                )
            )
        ).with_for_update()
    ).all()
    for row in rows:
        spec = ip_block.EXECUTED[row.action_type]
        if row.status == "proposed":
            if row.expires_at <= now:
                row.status = "expired"
                write_audit(
                    db,
                    actor_id=None,
                    action="response.simulation.expired",
                    target_type="response_simulation",
                    target_id=str(row.id),
                    details={"case_id": str(row.case_id)},
                )
                counts["expired"] += 1
        elif (
            row.enforcement_status == ip_block.PENDING
            and row.approved_at is not None
            and now - row.approved_at > ip_block.DELIVERY_WINDOW
        ):
            # Approved while the sensor was away. Applying it whenever the sensor next
            # starts, perhaps days later, is not what was approved.
            row.enforcement_status = ip_block.CANCELLED
            row.enforcement_detail = "not delivered to the sensor in time"
            row.failure_code = "not_delivered"
            row.removed_at = now
            write_audit(
                db,
                actor_id=None,
                action=f"response.{spec.audit}.delivery_expired",
                target_type="response_simulation",
                target_id=str(row.id),
                details={"target": row.target, "sensor_id": str(row.sensor_id)},
            )
            notify_block_event(db, "failed", row, row.enforcement_detail)
            counts["cancelled"] += 1
        elif (
            row.enforcement_status == ip_block.DISPATCHED
            and row.dispatched_at is not None
            and now - row.dispatched_at > ip_block.EXECUTION_TIMEOUT
        ):
            row.enforcement_status = ip_block.FAILED
            row.enforcement_detail = "the sensor did not report a result in time"
            row.failure_code = "timeout"
            write_audit(
                db,
                actor_id=None,
                action=f"response.{spec.audit}.failed",
                target_type="response_simulation",
                target_id=str(row.id),
                details={
                    "target": row.target,
                    "sensor_id": str(row.sensor_id),
                    "failure_code": "timeout",
                },
            )
            notify_block_event(db, "failed", row, row.enforcement_detail)
            counts["failed"] += 1
    return counts
