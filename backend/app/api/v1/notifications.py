from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy import func, select

from app.api.deps import DbDep, client_ip, require_roles
from app.audit.service import write_audit
from app.connectors.secrets import encrypt_credentials
from app.core.errors import AppError
from app.core.permissions import ADMIN, ANALYST
from app.models import NotificationChannel, NotificationDelivery
from app.notifications.delivery import validate_target
from app.schemas.common import TokenUser

router = APIRouter(prefix="/notification-channels", tags=["notifications"])
AdminUser = Annotated[TokenUser, Depends(require_roles(ADMIN))]
Reader = Annotated[TokenUser, Depends(require_roles(ADMIN, ANALYST))]
Severity = Literal["low", "medium", "high", "critical"]


class ChannelInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=200)
    kind: Literal["webhook", "slack", "telegram"]
    target: dict[str, str] = Field(min_length=1, max_length=2)
    min_severity: Severity = "high"
    include_summary: bool = False
    enabled: bool = True

    @model_validator(mode="after")
    def validate_destination(self) -> "ChannelInput":
        validate_target(self.kind, self.target)
        return self


class ChannelUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool | None = None
    min_severity: Severity | None = None
    include_summary: bool | None = None


def _get(db: DbDep, channel_id: UUID) -> NotificationChannel:
    channel = db.get(NotificationChannel, channel_id)
    if channel is None:
        raise AppError(404, "channel_not_found", "Notification channel not found")
    return channel


@router.get("")
def list_channels(db: DbDep, _: Reader) -> list[dict]:
    rows = db.scalars(
        select(NotificationChannel).order_by(NotificationChannel.created_at.desc())
    ).all()
    counts: dict[tuple[UUID, str], int] = {
        (channel_id, status): total
        for channel_id, status, total in db.execute(
            select(
                NotificationDelivery.channel_id,
                NotificationDelivery.status,
                func.count(),
            ).group_by(NotificationDelivery.channel_id, NotificationDelivery.status)
        )
    }
    return [_view(row, counts) for row in rows]


@router.post("", status_code=201)
def create_channel(payload: ChannelInput, db: DbDep, actor: AdminUser, request: Request) -> dict:
    if db.scalar(select(NotificationChannel.id).where(NotificationChannel.name == payload.name)):
        raise AppError(409, "channel_name_exists", "A channel with this name already exists")
    channel = NotificationChannel(
        name=payload.name,
        kind=payload.kind,
        target_encrypted=encrypt_credentials(payload.target),
        min_severity=payload.min_severity,
        include_summary=payload.include_summary,
        enabled=payload.enabled,
        created_by=actor.id,
    )
    db.add(channel)
    db.flush()
    write_audit(
        db,
        actor_id=actor.id,
        action="notification_channel.created",
        target_type="notification_channel",
        target_id=str(channel.id),
        ip_address=client_ip(request),
        details={
            "kind": payload.kind,
            "min_severity": payload.min_severity,
            "include_summary": payload.include_summary,
        },
    )
    db.commit()
    db.refresh(channel)
    return _view(channel, {})


@router.patch("/{channel_id}")
def update_channel(
    channel_id: UUID, payload: ChannelUpdate, db: DbDep, actor: AdminUser, request: Request
) -> dict:
    channel = _get(db, channel_id)
    changes = payload.model_dump(exclude_none=True)
    if not changes:
        raise AppError(400, "no_changes", "No channel changes were supplied")
    for field, value in changes.items():
        setattr(channel, field, value)
    if changes.get("enabled"):
        channel.last_error = None
    write_audit(
        db,
        actor_id=actor.id,
        action="notification_channel.updated",
        target_type="notification_channel",
        target_id=str(channel.id),
        ip_address=client_ip(request),
        details=changes,
    )
    db.commit()
    db.refresh(channel)
    return _view(channel, {})


@router.delete("/{channel_id}", status_code=204)
def delete_channel(channel_id: UUID, db: DbDep, actor: AdminUser, request: Request) -> None:
    channel = _get(db, channel_id)
    write_audit(
        db,
        actor_id=actor.id,
        action="notification_channel.deleted",
        target_type="notification_channel",
        target_id=str(channel.id),
        ip_address=client_ip(request),
        details={"kind": channel.kind},
    )
    db.delete(channel)
    db.commit()


@router.post("/{channel_id}/test", status_code=202)
def queue_test(channel_id: UUID, db: DbDep, actor: AdminUser, request: Request) -> dict:
    channel = _get(db, channel_id)
    if not channel.enabled:
        raise AppError(409, "channel_disabled", "Enable the channel before sending a test")
    pending_tests = db.scalar(
        select(func.count())
        .select_from(NotificationDelivery)
        .where(
            NotificationDelivery.channel_id == channel.id,
            NotificationDelivery.kind == "test",
            NotificationDelivery.status == "pending",
        )
    )
    if pending_tests:
        raise AppError(409, "test_pending", "A test notification is already waiting to be sent")
    db.add(NotificationDelivery(channel_id=channel.id, kind="test"))
    write_audit(
        db,
        actor_id=actor.id,
        action="notification_channel.test_requested",
        target_type="notification_channel",
        target_id=str(channel.id),
        ip_address=client_ip(request),
    )
    db.commit()
    return {"channel_id": channel.id, "status": "queued"}


def _view(channel: NotificationChannel, counts: dict[tuple[UUID, str], int]) -> dict:
    return {
        "id": channel.id,
        "name": channel.name,
        "kind": channel.kind,
        "min_severity": channel.min_severity,
        "include_summary": channel.include_summary,
        "enabled": channel.enabled,
        "last_success_at": channel.last_success_at,
        "last_error": channel.last_error,
        "created_at": channel.created_at,
        "pending": counts.get((channel.id, "pending"), 0),
        "sent": counts.get((channel.id, "sent"), 0),
        "failed": counts.get((channel.id, "failed"), 0),
    }
