"""Administrator settings for sending the audit log to an outside collector."""

from datetime import UTC, datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy import func, select

from app.api.deps import DbDep, client_ip, require_roles
from app.audit import sink as sink_service
from app.audit.service import write_audit
from app.connectors.secrets import decrypt_credentials, encrypt_credentials
from app.core.errors import AppError
from app.core.permissions import ADMIN
from app.models import AuditLog, AuditSink
from app.notifications import delivery
from app.schemas.common import TokenUser

router = APIRouter(prefix="/audit-sinks", tags=["audit"])
AdminUser = Annotated[TokenUser, Depends(require_roles(ADMIN))]


class SinkIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=200)
    url: str = Field(min_length=10, max_length=2048)
    signing_secret: str | None = Field(default=None, min_length=16, max_length=256)
    # Start from the newest row (the default) or replay the whole log into the new destination.
    from_beginning: bool = False

    @model_validator(mode="after")
    def check_url(self) -> "SinkIn":
        try:
            delivery.parse_https_url(self.url)
        except ValueError as exc:
            raise ValueError(str(exc)) from None
        return self


class SinkPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool


def _serialize(item: AuditSink, newest: int) -> dict:
    return {
        "id": item.id,
        "name": item.name,
        "enabled": item.enabled,
        "last_seq": item.last_seq,
        "behind": max(0, newest - item.last_seq),
        "last_success_at": item.last_success_at,
        "last_error": item.last_error,
        "failures": item.failures,
        "created_at": item.created_at,
    }


def _newest(db: DbDep) -> int:
    return db.scalar(select(func.max(AuditLog.seq))) or 0


def _get(db: DbDep, sink_id: UUID) -> AuditSink:
    item = db.get(AuditSink, sink_id)
    if item is None:
        raise AppError(404, "not_found", "Destination not found")
    return item


@router.get("")
def list_sinks(db: DbDep, _: AdminUser) -> list[dict]:
    newest = _newest(db)
    rows = db.scalars(select(AuditSink).order_by(AuditSink.created_at.desc())).all()
    return [_serialize(item, newest) for item in rows]


@router.post("", status_code=201)
def create_sink(payload: SinkIn, db: DbDep, actor: AdminUser, request: Request) -> dict:
    if db.scalar(select(AuditSink).where(AuditSink.name == payload.name)):
        raise AppError(409, "conflict", "A destination with this name already exists")
    target = {"url": payload.url}
    if payload.signing_secret:
        target["signing_secret"] = payload.signing_secret
    newest = _newest(db)
    item = AuditSink(
        name=payload.name.strip(),
        target_encrypted=encrypt_credentials(target),
        last_seq=0 if payload.from_beginning else newest,
    )
    db.add(item)
    db.flush()
    write_audit(
        db,
        actor_id=actor.id,
        action="audit.sink_created",
        target_type="audit_sink",
        target_id=str(item.id),
        ip_address=client_ip(request),
        details={"name": item.name, "from_beginning": payload.from_beginning},
    )
    db.commit()
    return _serialize(item, _newest(db))


@router.patch("/{sink_id}")
def update_sink(
    sink_id: UUID, payload: SinkPatch, db: DbDep, actor: AdminUser, request: Request
) -> dict:
    item = _get(db, sink_id)
    item.enabled = payload.enabled
    if payload.enabled:
        item.next_attempt_at = None
    write_audit(
        db,
        actor_id=actor.id,
        action="audit.sink_updated",
        target_type="audit_sink",
        target_id=str(item.id),
        ip_address=client_ip(request),
        details={"enabled": payload.enabled},
    )
    db.commit()
    return _serialize(item, _newest(db))


@router.delete("/{sink_id}")
def delete_sink(sink_id: UUID, db: DbDep, actor: AdminUser, request: Request) -> dict:
    item = _get(db, sink_id)
    write_audit(
        db,
        actor_id=actor.id,
        action="audit.sink_deleted",
        target_type="audit_sink",
        target_id=str(item.id),
        ip_address=client_ip(request),
        details={"name": item.name},
    )
    db.delete(item)
    db.commit()
    return {"ok": True}


@router.post("/{sink_id}/test")
def test_sink(sink_id: UUID, db: DbDep, actor: AdminUser) -> dict:
    """Send a small message so an administrator can see the destination accepts it."""
    item = _get(db, sink_id)
    message = {
        "type": "sentinel.audit.test",
        "time": datetime.now(UTC).isoformat(timespec="seconds"),
        "note": "A test from SentinelAI. No audit rows are in this message.",
    }
    try:
        delivery.send("webhook", decrypt_credentials(item.target_encrypted), message)
    except delivery.DeliveryError as exc:
        return {"ok": False, "error": str(exc)}
    return {"ok": True}


@router.post("/{sink_id}/push")
def push_now(sink_id: UUID, db: DbDep, actor: AdminUser) -> dict:
    """Send the next batch immediately instead of waiting for the minute timer."""
    item = _get(db, sink_id)
    item.next_attempt_at = None
    sent = sink_service.push_pending(db, item, datetime.now(UTC))
    db.commit()
    return {"sent": sent, **_serialize(item, _newest(db))}
