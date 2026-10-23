from datetime import datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select

from app.api.deps import DbDep, require_roles
from app.core.errors import AppError
from app.core.permissions import READ_EVENTS
from app.models import SecurityEvent
from app.schemas.common import Page, TokenUser

router = APIRouter(prefix="/events", tags=["events"])
Reader = Annotated[TokenUser, Depends(require_roles(*READ_EVENTS))]


@router.get("")
def list_events(
    db: DbDep,
    _: Reader,
    page: int = 1,
    page_size: int = 20,
    event_type: str | None = None,
    src_ip: str | None = None,
    dst_ip: str | None = None,
    host_id: str | None = None,
    severity: str | None = None,
    q: str | None = Query(default=None, max_length=200),
    time_from: datetime | None = Query(default=None, alias="from"),
    time_to: datetime | None = Query(default=None, alias="to"),
) -> Page[dict]:
    page_size = min(max(page_size, 1), 100)
    page = max(page, 1)
    stmt = select(SecurityEvent)
    count_stmt = select(func.count()).select_from(SecurityEvent)
    if event_type:
        stmt = stmt.where(SecurityEvent.event_type == event_type)
        count_stmt = count_stmt.where(SecurityEvent.event_type == event_type)
    if src_ip:
        stmt = stmt.where(SecurityEvent.src_ip == src_ip)
        count_stmt = count_stmt.where(SecurityEvent.src_ip == src_ip)
    if dst_ip:
        stmt = stmt.where(SecurityEvent.dst_ip == dst_ip)
        count_stmt = count_stmt.where(SecurityEvent.dst_ip == dst_ip)
    if host_id:
        stmt = stmt.where(SecurityEvent.host_id == host_id)
        count_stmt = count_stmt.where(SecurityEvent.host_id == host_id)
    if severity:
        stmt = stmt.where(SecurityEvent.severity == severity)
        count_stmt = count_stmt.where(SecurityEvent.severity == severity)
    if time_from:
        stmt = stmt.where(SecurityEvent.event_time >= time_from)
        count_stmt = count_stmt.where(SecurityEvent.event_time >= time_from)
    if time_to:
        stmt = stmt.where(SecurityEvent.event_time <= time_to)
        count_stmt = count_stmt.where(SecurityEvent.event_time <= time_to)
    if q:
        like = f"%{q}%"
        stmt = stmt.where(SecurityEvent.event_type.ilike(like) | SecurityEvent.host_id.ilike(like))
        count_stmt = count_stmt.where(
            SecurityEvent.event_type.ilike(like) | SecurityEvent.host_id.ilike(like)
        )
    total = db.scalar(count_stmt) or 0
    rows = db.scalars(
        stmt.order_by(SecurityEvent.event_time.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    ).all()
    return Page(items=[_event(e) for e in rows], page=page, page_size=page_size, total=total)


@router.get("/{event_id}")
def get_event(event_id: UUID, db: DbDep, _: Reader) -> dict:
    event = db.get(SecurityEvent, event_id)
    if event is None:
        raise AppError(404, "not_found", "Event not found")
    return _event(event, include_raw=True)


def _event(event: SecurityEvent, include_raw: bool = False) -> dict:
    payload = {
        "id": event.id,
        "event_time": event.event_time,
        "ingested_at": event.ingested_at,
        "event_type": event.event_type,
        "src_ip": str(event.src_ip) if event.src_ip else None,
        "dst_ip": str(event.dst_ip) if event.dst_ip else None,
        "src_port": event.src_port,
        "dst_port": event.dst_port,
        "host_id": event.host_id,
        "severity": event.severity,
        "attributes": event.attributes,
        "schema_version": event.schema_version,
        "dedup_key": event.dedup_key,
        "data_source_id": event.data_source_id,
        "ingestion_job_id": event.ingestion_job_id,
    }
    if include_raw:
        payload["raw_payload"] = event.raw_payload
    return payload
