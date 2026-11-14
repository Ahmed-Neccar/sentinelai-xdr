import threading
import time
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends
from sqlalchemy import func, select

from app.api.deps import DbDep, require_roles
from app.api.v1.events import _event
from app.core.errors import AppError
from app.core.permissions import READ_EVENTS
from app.models import Detection, DetectionEvidence, SecurityEvent
from app.schemas.common import TokenUser

router = APIRouter(prefix="/hosts", tags=["hosts"])
Reader = Annotated[TokenUser, Depends(require_roles(*READ_EVENTS))]


# The inventory aggregates the whole event table, and the panel asks again every five
# seconds. Keeping the answer for a few seconds per organization removes most of that load
# at the cost of data up to HOSTS_CACHE_SECONDS old. The cache is per API process.
HOSTS_CACHE_SECONDS = 10.0
_hosts_cache: dict[UUID, tuple[float, list[dict]]] = {}
_hosts_cache_lock = threading.Lock()


def _cached_hosts(organization_id: UUID, now: float | None = None) -> list[dict] | None:
    current = time.monotonic() if now is None else now
    with _hosts_cache_lock:
        entry = _hosts_cache.get(organization_id)
        if entry is not None and current - entry[0] < HOSTS_CACHE_SECONDS:
            return entry[1]
    return None


def _store_hosts(organization_id: UUID, value: list[dict], now: float | None = None) -> None:
    current = time.monotonic() if now is None else now
    with _hosts_cache_lock:
        if len(_hosts_cache) > 256:
            _hosts_cache.clear()
        _hosts_cache[organization_id] = (current, value)


@router.get("")
def list_hosts(db: DbDep, user: Reader) -> list[dict]:
    """Return a telemetry-derived host summary, not managed-agent health."""
    cached = _cached_hosts(user.organization_id)
    if cached is not None:
        return cached
    result = _build_hosts(db)
    _store_hosts(user.organization_id, result)
    return result


def _build_hosts(db: DbDep) -> list[dict]:
    rows = db.execute(
        select(
            SecurityEvent.host_id,
            func.min(SecurityEvent.event_time).label("first_seen"),
            func.max(SecurityEvent.event_time).label("last_seen"),
            func.count(SecurityEvent.id).label("event_count"),
        )
        .where(SecurityEvent.host_id.is_not(None), SecurityEvent.host_id != "")
        .group_by(SecurityEvent.host_id)
        .order_by(func.max(SecurityEvent.event_time).desc())
        .limit(1000)
    ).all()
    type_rows = db.execute(
        select(SecurityEvent.host_id, SecurityEvent.event_type, func.count(SecurityEvent.id))
        .where(SecurityEvent.host_id.is_not(None), SecurityEvent.host_id != "")
        .group_by(SecurityEvent.host_id, SecurityEvent.event_type)
    ).all()
    event_types: dict[str, dict[str, int]] = {}
    for host_id, event_type, count in type_rows:
        event_types.setdefault(host_id, {})[event_type] = count
    return [
        {
            "host_id": row.host_id,
            "first_seen": row.first_seen,
            "last_seen": row.last_seen,
            "event_count": row.event_count,
            "event_types": event_types.get(row.host_id, {}),
        }
        for row in rows
    ]


@router.get("/{host_id}")
def get_host(host_id: str, db: DbDep, _: Reader) -> dict:
    summary = db.execute(
        select(
            SecurityEvent.host_id,
            func.min(SecurityEvent.event_time).label("first_seen"),
            func.max(SecurityEvent.event_time).label("last_seen"),
            func.count(SecurityEvent.id).label("event_count"),
        )
        .where(SecurityEvent.host_id == host_id)
        .group_by(SecurityEvent.host_id)
    ).first()
    if summary is None:
        raise AppError(404, "not_found", "Host label not found in telemetry")

    type_rows = db.execute(
        select(SecurityEvent.event_type, func.count(SecurityEvent.id))
        .where(SecurityEvent.host_id == host_id)
        .group_by(SecurityEvent.event_type)
    ).all()
    recent_events = db.scalars(
        select(SecurityEvent)
        .where(SecurityEvent.host_id == host_id)
        .order_by(SecurityEvent.event_time.desc())
        .limit(25)
    ).all()
    detections = db.scalars(
        select(Detection)
        .join(DetectionEvidence, DetectionEvidence.detection_id == Detection.id)
        .join(SecurityEvent, SecurityEvent.id == DetectionEvidence.event_id)
        .where(SecurityEvent.host_id == host_id)
        .distinct()
        .order_by(Detection.created_at.desc())
        .limit(25)
    ).all()
    return {
        "host_id": summary.host_id,
        "first_seen": summary.first_seen,
        "last_seen": summary.last_seen,
        "event_count": summary.event_count,
        "event_types": {event_type: count for event_type, count in type_rows},
        "recent_events": [_event(event) for event in recent_events],
        "detections": [
            {
                "id": detection.id,
                "title": detection.title,
                "severity": detection.severity,
                "status": detection.status,
                "created_at": detection.created_at,
            }
            for detection in detections
        ],
        "identity_note": (
            "This device name is reported by telemetry; it is not a verified asset identity "
            "or managed-agent heartbeat."
        ),
    }
