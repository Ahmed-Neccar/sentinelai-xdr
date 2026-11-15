"""Push the audit log to an outside collector (a SIEM or a log archive) as it grows.

The chain of hashes (migration 017) makes tampering inside the database visible, but someone
who removes the newest rows leaves no trace. A copy kept elsewhere closes that gap: every batch
carries the hash of its last row, so the receiver can tell later whether anything was removed.

Delivery reuses the alert webhook sender: HTTPS only, a public host name, no redirects, and an
optional HMAC signature. A failing destination is retried with a growing wait; nothing is lost,
because the position reached is only moved forward after a batch was accepted.
"""

from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.connectors.secrets import decrypt_credentials
from app.models import AuditLog, AuditSink
from app.notifications import delivery

BATCH_SIZE = 200
MAX_WAIT = timedelta(minutes=30)
_Sender = Any


def _row(entry: AuditLog) -> dict[str, Any]:
    return {
        "seq": entry.seq,
        "id": str(entry.id),
        "time": entry.created_at.isoformat() if entry.created_at else None,
        "actor_id": str(entry.actor_id) if entry.actor_id else None,
        "action": entry.action,
        "target_type": entry.target_type,
        "target_id": entry.target_id,
        "ip_address": entry.ip_address,
        "details": entry.details,
        "prev_hash": entry.prev_hash,
        "row_hash": entry.row_hash,
    }


def push_pending(
    db: Session, sink: AuditSink, now: datetime, *, sender: _Sender = delivery.send
) -> int:
    """Send the next batch to one destination. Returns how many rows were accepted."""
    if not sink.enabled or (sink.next_attempt_at and sink.next_attempt_at > now):
        return 0
    rows = db.scalars(
        select(AuditLog)
        .where(AuditLog.seq > sink.last_seq)
        .order_by(AuditLog.seq)
        .limit(BATCH_SIZE)
    ).all()
    if not rows:
        return 0
    message = {
        "type": "sentinel.audit",
        "from_seq": rows[0].seq,
        "to_seq": rows[-1].seq,
        "head_hash": rows[-1].row_hash,
        "rows": [_row(entry) for entry in rows],
    }
    try:
        sender("webhook", decrypt_credentials(sink.target_encrypted), message)
    except delivery.DeliveryError as exc:
        sink.failures += 1
        sink.last_error = str(exc)[:500]
        wait = timedelta(seconds=30 * 2 ** min(sink.failures, 6))
        sink.next_attempt_at = now + min(MAX_WAIT, wait)
        return 0
    sink.last_seq = rows[-1].seq
    sink.last_success_at = now
    sink.last_error = None
    sink.failures = 0
    sink.next_attempt_at = None
    return len(rows)


def push_all(db: Session, now: datetime | None = None, *, sender: _Sender = delivery.send) -> int:
    """One pass over every enabled destination of the organization the session is scoped to."""
    now = now or datetime.now(UTC)
    total = 0
    for sink in db.scalars(select(AuditSink).where(AuditSink.enabled.is_(True))):
        total += push_pending(db, sink, now, sender=sender)
    return total
