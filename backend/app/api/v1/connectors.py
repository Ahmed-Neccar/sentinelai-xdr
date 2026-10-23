from datetime import UTC, datetime
from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from sqlalchemy import select

from app.api.deps import DbDep, client_ip, require_roles
from app.audit.service import write_audit
from app.connectors.secrets import encrypt_credentials
from app.core.errors import AppError
from app.core.permissions import ADMIN, ANALYST
from app.models import CloudConnector, DataSource
from app.schemas.common import TokenUser

router = APIRouter(prefix="/cloud-connectors", tags=["cloud connectors"])
AdminUser = Annotated[TokenUser, Depends(require_roles(ADMIN))]
Reader = Annotated[TokenUser, Depends(require_roles(ADMIN, ANALYST))]


class ConnectorInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=200)
    provider: Literal["aws_cloudtrail", "azure_activity", "entra_signin"]
    config: dict[str, str] = Field(max_length=8)
    credentials: dict[str, str] = Field(min_length=1, max_length=4)
    enabled: bool = True

    @field_validator("credentials")
    @classmethod
    def validate_credential_values(cls, value: dict[str, str]) -> dict[str, str]:
        if any(
            not key or len(key) > 64 or not secret or len(secret) > 4096
            for key, secret in value.items()
        ):
            raise ValueError(
                "Credential fields must be non-empty strings of at most 4096 characters"
            )
        return value

    @model_validator(mode="after")
    def validate_provider_fields(self) -> "ConnectorInput":
        expected_config = {
            "aws_cloudtrail": {"region"},
            "azure_activity": {"tenant_id", "client_id", "subscription_id"},
            "entra_signin": {"tenant_id", "client_id"},
        }[self.provider]
        expected_credentials = {
            "aws_cloudtrail": {"access_key_id", "secret_access_key"},
            "azure_activity": {"client_secret"},
            "entra_signin": {"client_secret"},
        }[self.provider]
        allowed_credentials = expected_credentials
        if self.provider == "aws_cloudtrail":
            allowed_credentials = expected_credentials | {"session_token"}
        if set(self.config) != expected_config or not (
            set(self.credentials) == expected_credentials
            or (self.provider == "aws_cloudtrail" and set(self.credentials) == allowed_credentials)
        ):
            raise ValueError("Configuration or credentials do not match the selected provider")
        if self.provider == "aws_cloudtrail":
            region = self.config["region"]
            if len(region) > 64 or not region.replace("-", "").isalnum():
                raise ValueError("AWS region is invalid")
        else:
            for field in expected_config:
                if not self.config[field] or len(self.config[field]) > 128:
                    raise ValueError(f"{field} is required and must be at most 128 characters")
                if field in {"tenant_id", "client_id", "subscription_id"}:
                    try:
                        UUID(self.config[field])
                    except ValueError as exc:
                        raise ValueError(f"{field} must be a UUID") from exc
        return self


class ConnectorEnable(BaseModel):
    enabled: bool


@router.get("")
def list_connectors(db: DbDep, _: Reader) -> list[dict]:
    rows = db.scalars(select(CloudConnector).order_by(CloudConnector.created_at.desc())).all()
    return [_view(row) for row in rows]


@router.post("", status_code=201)
def create_connector(
    payload: ConnectorInput, db: DbDep, actor: AdminUser, request: Request
) -> dict:
    source_name = f"Cloud: {payload.name}"
    if db.scalar(select(CloudConnector.id).where(CloudConnector.name == payload.name)):
        raise AppError(
            409, "connector_name_exists", "A cloud connector with this name already exists"
        )
    if db.scalar(select(DataSource.id).where(DataSource.name == source_name)):
        raise AppError(409, "source_name_exists", "A data source with this name already exists")
    source = DataSource(
        name=source_name,
        source_type=payload.provider,
        config={"connector_managed": True},
    )
    db.add(source)
    db.flush()
    connector = CloudConnector(
        name=payload.name,
        provider=payload.provider,
        config=payload.config,
        credentials_encrypted=encrypt_credentials(payload.credentials),
        enabled=payload.enabled,
        data_source_id=source.id,
        created_by=actor.id,
    )
    db.add(connector)
    write_audit(
        db,
        actor_id=actor.id,
        action="cloud_connector.created",
        target_type="cloud_connector",
        ip_address=client_ip(request) if request else None,
        details={"provider": payload.provider, "enabled": payload.enabled},
    )
    db.commit()
    db.refresh(connector)
    return _view(connector)


@router.put("/{connector_id}")
def replace_connector(
    connector_id: UUID,
    payload: ConnectorInput,
    db: DbDep,
    actor: AdminUser,
    request: Request,
) -> dict:
    connector = db.get(CloudConnector, connector_id)
    if connector is None:
        raise AppError(404, "connector_not_found", "Cloud connector not found")
    if connector.provider != payload.provider:
        raise AppError(
            400, "provider_change_not_allowed", "Create a new connector to change provider"
        )
    if db.scalar(
        select(CloudConnector.id).where(
            CloudConnector.name == payload.name, CloudConnector.id != connector.id
        )
    ):
        raise AppError(
            409, "connector_name_exists", "A cloud connector with this name already exists"
        )
    source_name = f"Cloud: {payload.name}"
    if db.scalar(
        select(DataSource.id).where(
            DataSource.name == source_name, DataSource.id != connector.data_source_id
        )
    ):
        raise AppError(409, "source_name_exists", "A data source with this name already exists")
    if connector.status in {"queued", "polling"}:
        raise AppError(409, "poll_in_progress", "Pause credential changes until polling completes")
    connector.name = payload.name
    connector.config = payload.config
    connector.credentials_encrypted = encrypt_credentials(payload.credentials)
    connector.enabled = payload.enabled
    connector.status = "idle"
    connector.last_error = None
    source = db.get(DataSource, connector.data_source_id)
    if source is not None:
        source.name = source_name
    write_audit(
        db,
        actor_id=actor.id,
        action="cloud_connector.credentials_rotated",
        target_type="cloud_connector",
        target_id=str(connector.id),
        ip_address=client_ip(request) if request else None,
        details={"provider": payload.provider, "enabled": payload.enabled},
    )
    db.commit()
    db.refresh(connector)
    return _view(connector)


@router.patch("/{connector_id}")
def set_enabled(
    connector_id: UUID,
    payload: ConnectorEnable,
    db: DbDep,
    actor: AdminUser,
    request: Request,
) -> dict:
    connector = db.get(CloudConnector, connector_id)
    if connector is None:
        raise AppError(404, "connector_not_found", "Cloud connector not found")
    if connector.status == "revoked" and payload.enabled:
        raise AppError(409, "connector_revoked", "Replace provider credentials before enabling")
    connector.enabled = payload.enabled
    connector.status = "idle" if payload.enabled else "disabled"
    if not payload.enabled:
        connector.last_error = None
    write_audit(
        db,
        actor_id=actor.id,
        action="cloud_connector.enabled_changed",
        target_type="cloud_connector",
        target_id=str(connector.id),
        ip_address=client_ip(request) if request else None,
        details={"enabled": payload.enabled},
    )
    db.commit()
    db.refresh(connector)
    return _view(connector)


@router.delete("/{connector_id}")
def revoke_connector(
    connector_id: UUID,
    db: DbDep,
    actor: AdminUser,
    request: Request,
) -> dict:
    connector = db.scalar(
        select(CloudConnector).where(CloudConnector.id == connector_id).with_for_update()
    )
    if connector is None:
        raise AppError(404, "connector_not_found", "Cloud connector not found")
    connector.enabled = False
    connector.status = "revoked"
    connector.credentials_encrypted = ""
    connector.last_error = None
    write_audit(
        db,
        actor_id=actor.id,
        action="cloud_connector.revoked",
        target_type="cloud_connector",
        target_id=str(connector.id),
        ip_address=client_ip(request),
        details={"provider": connector.provider},
    )
    db.commit()
    db.refresh(connector)
    return _view(connector)


@router.post("/{connector_id}/poll", status_code=202)
def request_poll(
    connector_id: UUID,
    db: DbDep,
    actor: AdminUser,
    request: Request,
) -> dict:
    connector = db.scalar(
        select(CloudConnector).where(CloudConnector.id == connector_id).with_for_update()
    )
    if connector is None:
        raise AppError(404, "connector_not_found", "Cloud connector not found")
    if not connector.enabled:
        raise AppError(409, "connector_disabled", "Enable the connector before polling")
    if (
        connector.status in {"queued", "polling"}
        and connector.last_poll_started_at is not None
        and (datetime.now(UTC) - connector.last_poll_started_at).total_seconds() > 900
    ):
        connector.status = "error"
        connector.last_error = "Previous poll lease expired; safe to retry"
    if connector.status in {"queued", "polling"}:
        raise AppError(409, "poll_in_progress", "A connector poll is already in progress")
    connector.status = "queued"
    connector.last_poll_started_at = datetime.now(UTC)
    write_audit(
        db,
        actor_id=actor.id,
        action="cloud_connector.poll_requested",
        target_type="cloud_connector",
        target_id=str(connector.id),
        ip_address=client_ip(request) if request else None,
        details={"provider": connector.provider},
    )
    db.commit()
    from app.workers.tasks import poll_cloud_connector_task

    try:
        result = poll_cloud_connector_task.delay(str(connector.id), str(actor.organization_id))
    except Exception as exc:  # noqa: BLE001 — avoid exposing broker internals
        connector = db.get(CloudConnector, connector_id)
        if connector is not None:
            connector.status = "error"
            connector.last_error = "Poll could not be queued"
            db.commit()
        raise AppError(503, "poll_queue_unavailable", "The poll could not be queued") from exc
    return {"connector_id": connector.id, "status": "queued", "task_id": result.id}


def _view(connector: CloudConnector) -> dict:
    return {
        "id": connector.id,
        "name": connector.name,
        "provider": connector.provider,
        "config": connector.config,
        "enabled": connector.enabled,
        "status": connector.status,
        "last_poll_started_at": connector.last_poll_started_at,
        "last_success_at": connector.last_success_at,
        "last_error": connector.last_error,
        "created_at": connector.created_at,
        "credentials_configured": bool(connector.credentials_encrypted)
        and connector.status != "revoked",
    }
