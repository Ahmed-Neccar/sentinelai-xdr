import base64
import binascii
import hashlib
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated
from uuid import UUID, uuid4

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi import APIRouter, Depends, File, Form, Header, Request, UploadFile
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import func, or_, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app.api.deps import DbDep, client_ip, require_roles
from app.audit.service import write_audit
from app.core.config import settings
from app.core.errors import AppError
from app.core.permissions import ADMIN, ANALYST, INGESTION
from app.core.security import hash_password
from app.ingestion.parsers import RowError, normalize_generic, validate_normalized_event
from app.ingestion.service import safe_filename
from app.models import (
    DataSource,
    IngestionJob,
    ResponseSimulation,
    SecurityEvent,
    SensorRegistration,
    User,
)
from app.response import ip_block
from app.response.notify import notify_block_event
from app.schemas.common import Page, TokenUser
from app.workers.dispatch import enqueue_ingestion

router = APIRouter(tags=["ingestion"])
LiveSensorUser = Annotated[TokenUser, Depends(require_roles(ADMIN, ANALYST, INGESTION))]
UploadUser = Annotated[TokenUser, Depends(require_roles(ADMIN, ANALYST))]
AllowedList = Annotated[TokenUser, Depends(require_roles(ADMIN, ANALYST))]
AdminUser = Annotated[TokenUser, Depends(require_roles(ADMIN))]

ALLOWED_EXT = {".json", ".csv", ".log"}
ALLOWED_ADAPTERS = {
    "generic_json",
    "generic_csv",
    "zeek_json",
    "suricata_eve",
    "aws_cloudtrail",
    "azure_activity",
    "entra_signin",
}


class DataSourceIn(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    source_type: str = Field(min_length=1, max_length=64)
    config: dict = Field(default_factory=dict)


class LiveCaptureStart(BaseModel):
    source_name: str = Field(min_length=1, max_length=120)
    sensor_id: str | None = Field(
        default=None,
        min_length=36,
        max_length=36,
        pattern=r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$",
    )
    host_name: str | None = Field(default=None, max_length=255)
    sensor_version: str | None = Field(default=None, max_length=32)
    capabilities: list[str] = Field(default_factory=list, max_length=16)
    sensor_public_key: str | None = Field(default=None, min_length=40, max_length=64)


class LiveCaptureBatch(BaseModel):
    events: list[dict] = Field(min_length=1, max_length=100)


class LiveCaptureDiagnostics(BaseModel):
    model_config = ConfigDict(extra="forbid")

    interface: str | None = Field(default=None, max_length=255)
    events_forwarded: int = Field(default=0, ge=0, le=2_000_000_000)
    event_counts: dict[str, int] = Field(default_factory=dict, max_length=16)
    windows_event_ids_configured: list[int] = Field(default_factory=list, max_length=64)
    windows_event_ids_seen: list[int] = Field(default_factory=list, max_length=64)
    last_event_forwarded_at: datetime | None = None
    windows_collection_state: str = Field(default="disabled", pattern="^(disabled|enabled|error)$")

    @field_validator("event_counts")
    @classmethod
    def validate_counts(cls, value: dict[str, int]) -> dict[str, int]:
        if any(len(key) > 64 or count < 0 or count > 2_000_000_000 for key, count in value.items()):
            raise ValueError("Invalid sensor event counters")
        return value

    @field_validator("windows_event_ids_configured", "windows_event_ids_seen")
    @classmethod
    def validate_event_ids(cls, value: list[int]) -> list[int]:
        if any(event_id < 1 or event_id > 65535 for event_id in value):
            raise ValueError("Windows event IDs must be between 1 and 65535")
        if len(set(value)) != len(value):
            raise ValueError("Windows event IDs must be unique")
        return value


class SensorCredentialRotate(BaseModel):
    password: str = Field(min_length=12, max_length=128)


@router.get("/data-sources")
def list_sources(db: DbDep, _: AllowedList, page: int = 1, page_size: int = 20) -> Page[dict]:
    page_size = min(max(page_size, 1), 100)
    total = db.scalar(select(func.count()).select_from(DataSource)) or 0
    rows = db.scalars(select(DataSource).offset((page - 1) * page_size).limit(page_size)).all()
    return Page(items=[_source(s) for s in rows], page=page, page_size=page_size, total=total)


@router.post("/data-sources", status_code=201)
def create_source(payload: DataSourceIn, db: DbDep, actor: AdminUser, request: Request) -> dict:
    source = DataSource(name=payload.name, source_type=payload.source_type, config=payload.config)
    db.add(source)
    write_audit(
        db,
        actor_id=actor.id,
        action="datasource.create",
        target_type="data_source",
        ip_address=client_ip(request),
    )
    db.commit()
    db.refresh(source)
    return _source(source)


@router.get("/data-sources/{source_id}")
def get_source(source_id: UUID, db: DbDep, _: AllowedList) -> dict:
    source = db.get(DataSource, source_id)
    if source is None:
        raise AppError(404, "not_found", "Data source not found")
    return _source(source)


@router.patch("/data-sources/{source_id}")
def patch_source(source_id: UUID, payload: DataSourceIn, db: DbDep, actor: AdminUser) -> dict:
    source = db.get(DataSource, source_id)
    if source is None:
        raise AppError(404, "not_found", "Data source not found")
    source.name = payload.name
    source.source_type = payload.source_type
    source.config = payload.config
    db.commit()
    db.refresh(source)
    return _source(source)


@router.post("/ingest/upload", status_code=202)
async def upload(
    db: DbDep,
    actor: UploadUser,
    request: Request,
    file: UploadFile = File(...),
    adapter: str = Form("generic_json"),
    data_source_id: UUID | None = Form(default=None),
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
) -> dict:
    if adapter not in ALLOWED_ADAPTERS:
        raise AppError(400, "invalid_adapter", "Unknown adapter")
    filename = safe_filename(file.filename or "upload.json")
    ext = Path(filename).suffix.lower()
    if ext not in ALLOWED_EXT:
        raise AppError(400, "invalid_type", "Allowed extensions: .json, .csv, .log")
    if idempotency_key:
        existing = db.scalar(
            select(IngestionJob).where(IngestionJob.idempotency_key == idempotency_key)
        )
        if existing:
            return _job(existing)
    if data_source_id is not None and db.get(DataSource, data_source_id) is None:
        # RLS hides sources belonging to another organization, so the response
        # deliberately does not reveal whether an inaccessible ID exists.
        raise AppError(400, "invalid_data_source", "Data source not found")
    content = await file.read(settings.max_upload_bytes + 1)
    if len(content) > settings.max_upload_bytes:
        raise AppError(413, "payload_too_large", "File exceeds size limit")
    upload_root = Path(settings.upload_dir).resolve()
    upload_root.mkdir(parents=True, exist_ok=True)
    stored = upload_root / f"{uuid4()}_{filename}"
    if not str(stored).startswith(str(upload_root)):
        raise AppError(400, "invalid_path", "Unsafe filename")
    stored.write_bytes(content)
    job = IngestionJob(
        organization_id=actor.organization_id,
        data_source_id=data_source_id,
        created_by=actor.id,
        original_filename=filename,
        stored_path=str(stored),
        adapter=adapter,
        idempotency_key=idempotency_key,
        status="queued",
        stats={},
    )
    db.add(job)
    write_audit(
        db,
        actor_id=actor.id,
        action="ingest.upload",
        target_type="ingestion_job",
        ip_address=client_ip(request),
        details={"filename": filename, "adapter": adapter},
    )
    db.commit()
    db.refresh(job)
    enqueue_ingestion(job.id, actor.organization_id)
    return _job(job)


@router.post("/ingest/live/start", status_code=201)
async def start_live_capture(
    payload: LiveCaptureStart, db: DbDep, actor: LiveSensorUser, request: Request
) -> dict:
    sensor_only = not _can_manage_all_live_sessions(actor)
    if sensor_only and payload.sensor_id is None:
        raise AppError(
            400, "sensor_id_required", "Sensor credentials must register a stable sensor ID"
        )

    source = db.scalar(select(DataSource).where(DataSource.name == payload.source_name))
    source_config = dict(source.config or {}) if source else {}
    sensor_uuid = UUID(payload.sensor_id) if payload.sensor_id else None
    registration = None
    if sensor_only and sensor_uuid is not None:
        registration = db.scalar(
            select(SensorRegistration).where(
                or_(
                    SensorRegistration.sensor_id == sensor_uuid,
                    SensorRegistration.credential_user_id == actor.id,
                )
            ).with_for_update()
        )
        if registration is not None:
            if registration.status != "active":
                raise AppError(409, "sensor_revoked", "This sensor registration has been revoked")
            if registration.sensor_id != sensor_uuid:
                raise AppError(
                    409,
                    "sensor_credential_bound",
                    "This credential is already registered to another sensor ID",
                )
            if registration.credential_user_id != actor.id:
                raise AppError(
                    409,
                    "sensor_id_already_registered",
                    "This sensor ID is registered to another credential",
                )
            # The display/source name may change across controller versions.
            # A stable sensor registration is authoritative for its data source.
            registered_source = db.get(DataSource, registration.data_source_id)
            if registered_source is None:
                raise AppError(
                    409,
                    "sensor_source_missing",
                    "The data source for this sensor registration no longer exists",
                )
            source = registered_source
            source_config = dict(source.config or {})

    if sensor_only:
        _decode_sensor_public_key(payload.sensor_public_key)
        pinned_key: str | None
        if registration is not None and registration.public_key is not None:
            if registration.public_key != payload.sensor_public_key:
                raise AppError(
                    409,
                    "sensor_key_mismatch",
                    "This sensor key is already bound to another identity",
                )
            pinned_key = registration.public_key
        else:
            pinned_key = payload.sensor_public_key
        request_counter = await _verify_sensor_proof(request, payload.sensor_id or "", pinned_key)
        if registration is not None and request_counter <= registration.last_request_counter:
            raise AppError(409, "sensor_request_replayed", "The sensor request was already used")

    if sensor_only and source is not None:
        bound_user = source_config.get("sensor_credential_user_id")
        bound_sensor = source_config.get("sensor_id")
        owned_session = db.scalar(
            select(IngestionJob.id)
            .where(
                IngestionJob.data_source_id == source.id,
                IngestionJob.created_by == actor.id,
                IngestionJob.original_filename.like("live-capture:%"),
            )
            .limit(1)
        )
        # Preserve existing sessions created by this account, but do not let a
        # newly credentialed sensor silently claim an old/unowned data source.
        if bound_user is not None and bound_user != str(actor.id):
            raise AppError(
                409, "sensor_credential_mismatch", "This sensor is bound to another credential"
            )
        if bound_sensor is not None and bound_sensor != payload.sensor_id:
            raise AppError(
                409, "sensor_id_mismatch", "This credential is already bound to another sensor ID"
            )
        if bound_user is None and owned_session is None:
            raise AppError(
                409,
                "sensor_not_enrolled",
                "This data source has no session owned by this sensor credential",
            )

    if sensor_only and payload.sensor_id:
        sources = db.scalars(
            select(DataSource).where(DataSource.source_type == "host_packet_headers")
        ).all()
        for registered_source in sources:
            registered = registered_source.config or {}
            if (
                registered.get("sensor_id") == payload.sensor_id
                and (source is None or registered_source.id != source.id)
            ):
                raise AppError(
                    409,
                    "sensor_id_already_registered",
                    "This sensor ID is registered under a different data source",
                )
            if (
                registered.get("sensor_credential_user_id") == str(actor.id)
                and registered.get("sensor_id") != payload.sensor_id
            ):
                raise AppError(
                    409,
                    "sensor_credential_bound",
                    "This credential is already enrolled to a different sensor ID",
                )

    if source is not None:
        recent_running = db.scalar(
            select(IngestionJob.id)
            .where(
                IngestionJob.data_source_id == source.id,
                IngestionJob.status == "running",
                IngestionJob.original_filename.like("live-capture:%"),
                IngestionJob.last_heartbeat_at >= datetime.now(UTC) - timedelta(seconds=30),
            )
            .limit(1)
        )
        if recent_running:
            raise AppError(
                409,
                "sensor_session_already_running",
                "This sensor already has a recent live session",
            )

    if source is None:
        source = DataSource(
            name=payload.source_name,
            source_type="host_packet_headers",
            config={
                "capture_mode": "passive",
                "payload_collection": False,
                "sensor_id": payload.sensor_id,
                "host_name": payload.host_name,
                "sensor_version": payload.sensor_version,
                "capabilities": payload.capabilities,
                "sensor_credential_user_id": str(actor.id) if sensor_only else None,
            },
        )
        db.add(source)
        db.flush()
    else:
        source.config = {
            **(source.config or {}),
            "capture_mode": "passive",
            "payload_collection": False,
            "sensor_id": payload.sensor_id,
            "host_name": payload.host_name,
            "sensor_version": payload.sensor_version,
            "capabilities": payload.capabilities,
            "sensor_credential_user_id": source_config.get("sensor_credential_user_id")
            or (str(actor.id) if sensor_only else None),
        }
    if sensor_only and sensor_uuid is not None:
        now = datetime.now(UTC)
        if registration is None:
            inserted = db.scalar(
                pg_insert(SensorRegistration)
                .values(
                    sensor_id=sensor_uuid,
                    public_key=payload.sensor_public_key,
                    last_request_counter=request_counter,
                    credential_user_id=actor.id,
                    data_source_id=source.id,
                    status="active",
                    last_seen_at=now,
                )
                .on_conflict_do_nothing()
                .returning(SensorRegistration.sensor_id)
            )
            if inserted is None:
                raise AppError(
                    409,
                    "sensor_registration_conflict",
                    "The sensor ID, credential, or data source is already registered",
                )
        else:
            registration.last_seen_at = now
            if registration.public_key is None:
                registration.public_key = payload.sensor_public_key
            registration.last_request_counter = request_counter
    job = IngestionJob(
        data_source_id=source.id,
        created_by=actor.id,
        original_filename=f"live-capture:{payload.source_name}",
        adapter="generic_json",
        status="running",
        stats={"accepted": 0, "quarantined": 0, "duplicates": 0, "detections_created": 0},
        last_heartbeat_at=datetime.now(UTC),
    )
    db.add(job)
    db.flush()
    write_audit(
        db,
        actor_id=actor.id,
        action="ingest.live.start",
        target_type="ingestion_job",
        target_id=str(job.id),
        ip_address=client_ip(request),
        details={"source_name": payload.source_name, "payload_collection": False},
    )
    db.commit()
    db.refresh(job)
    return _job(job)


@router.post("/ingest/live/{job_id}/heartbeat")
async def live_capture_heartbeat(
    job_id: UUID,
    payload: LiveCaptureDiagnostics,
    db: DbDep,
    actor: LiveSensorUser,
    request: Request,
) -> dict:
    job = db.get(IngestionJob, job_id)
    if job is None or not job.original_filename.startswith("live-capture:"):
        raise AppError(404, "not_found", "Live capture session not found")
    _assert_live_session_access(job, actor)
    registration = _assert_registered_sensor_session(db, job, actor)
    if registration is not None:
        await _verify_registered_sensor_request(request, registration)
    if job.status != "running":
        raise AppError(409, "capture_not_running", "Live capture session is not running")
    job.last_heartbeat_at = datetime.now(UTC)
    if registration is not None:
        registration.last_seen_at = job.last_heartbeat_at
    if job.data_source_id is not None:
        source = db.get(DataSource, job.data_source_id)
        if source is not None:
            config = dict(source.config or {})
            config["sensor_diagnostics"] = {
                **payload.model_dump(mode="json"),
                "reported_at": job.last_heartbeat_at.isoformat(),
            }
            source.config = config
    response_actions = _pending_response_actions(db, registration, job.last_heartbeat_at)
    db.commit()
    return {
        "job_id": job.id,
        "last_heartbeat_at": job.last_heartbeat_at,
        "diagnostics_recorded": True,
        # Work for this sensor only, delivered in the response to its own
        # signed request; the server never opens a connection to a host.
        "response_actions": response_actions,
    }


class ResponseActionResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    result: str = Field(pattern="^(applied|refused|failed|removed)$")
    detail: str = Field(default="", max_length=200)


@router.post("/ingest/live/{job_id}/actions/{action_id}/result")
async def report_response_action(
    job_id: UUID,
    action_id: UUID,
    payload: ResponseActionResult,
    db: DbDep,
    actor: LiveSensorUser,
    request: Request,
) -> dict:
    job = db.get(IngestionJob, job_id)
    if job is None or not job.original_filename.startswith("live-capture:"):
        raise AppError(404, "not_found", "Live capture session not found")
    _assert_live_session_access(job, actor)
    registration = _assert_registered_sensor_session(db, job, actor)
    if registration is None:
        raise AppError(403, "forbidden", "Only an enrolled sensor can report response actions")
    await _verify_registered_sensor_request(request, registration)
    action = db.scalar(
        select(ResponseSimulation)
        .where(
            ResponseSimulation.id == action_id,
            ResponseSimulation.sensor_id == registration.sensor_id,
            ResponseSimulation.action_type == ip_block.ACTION,
        )
        .with_for_update()
    )
    if action is None:
        raise AppError(404, "not_found", "Response action not found for this sensor")
    status = ip_block.next_status(action.enforcement_status, payload.result)
    if status is None:
        # A repeated or late report: answer without changing anything.
        return {"id": action.id, "enforcement_status": action.enforcement_status, "changed": False}
    now = datetime.now(UTC)
    action.enforcement_status = status
    action.enforcement_detail = payload.detail[:255]
    if status == ip_block.APPLIED:
        action.enforced_at = now
        action.block_until = ip_block.block_until(now, action.duration_minutes or 0)
    elif status == ip_block.REMOVED:
        action.removed_at = now
    write_audit(
        db,
        actor_id=actor.id,
        action=f"response.block.{status}",
        target_type="response_simulation",
        target_id=str(action.id),
        ip_address=client_ip(request),
        details={
            "target": action.target,
            "sensor_id": str(registration.sensor_id),
            "detail": action.enforcement_detail,
        },
    )
    notify_block_event(db, status, action, action.enforcement_detail)
    db.commit()
    return {"id": action.id, "enforcement_status": status, "changed": True}


@router.get("/ingest/live/sessions")
def list_live_capture_sessions(db: DbDep, actor: LiveSensorUser, page_size: int = 50) -> list[dict]:
    page_size = min(max(page_size, 1), 100)
    query = select(IngestionJob).where(IngestionJob.original_filename.like("live-capture:%"))
    if not _can_manage_all_live_sessions(actor):
        query = query.where(IngestionJob.created_by == actor.id)
    rows = db.scalars(query.order_by(IngestionJob.created_at.desc()).limit(page_size)).all()
    source_ids = {job.data_source_id for job in rows if job.data_source_id is not None}
    sources = (
        db.scalars(select(DataSource).where(DataSource.id.in_(source_ids))).all()
        if source_ids
        else []
    )
    sources_by_id = {source.id: source for source in sources}
    registrations = (
        db.scalars(
            select(SensorRegistration).where(SensorRegistration.data_source_id.in_(source_ids))
        ).all()
        if source_ids
        else []
    )
    registrations_by_source = {
        registration.data_source_id: registration for registration in registrations
    }
    now = datetime.now(UTC)
    sessions = []
    for job in rows:
        heartbeat = job.last_heartbeat_at
        if job.status == "completed":
            state = "stopped"
        elif (
            job.status == "running"
            and heartbeat is not None
            and -60 <= (now - heartbeat).total_seconds() <= 30
        ):
            state = "online"
        else:
            state = "stale"
        source = sources_by_id.get(job.data_source_id) if job.data_source_id is not None else None
        source_config = source.config or {} if source else {}
        sessions.append(
            {
                "id": job.id,
                "source_name": job.original_filename.removeprefix("live-capture:"),
                "sensor_id": source_config.get("sensor_id"),
                "host_name": source_config.get("host_name"),
                "sensor_version": source_config.get("sensor_version"),
                "capabilities": source_config.get("capabilities") or [],
                "diagnostics": source_config.get("sensor_diagnostics") or {},
                "registration_status": (
                    registrations_by_source[job.data_source_id].status
                    if job.data_source_id in registrations_by_source
                    else "legacy"
                ),
                "state": state,
                "started_at": job.created_at,
                "last_heartbeat_at": heartbeat,
                "completed_at": job.completed_at,
                "stats": job.stats or {},
            }
        )
    return sessions


@router.get("/ingest/live/sensors")
def list_registered_sensors(db: DbDep, _: AdminUser) -> list[dict]:
    rows = db.execute(
        select(SensorRegistration, User.email, DataSource)
        .join(User, User.id == SensorRegistration.credential_user_id)
        .join(DataSource, DataSource.id == SensorRegistration.data_source_id)
        .order_by(SensorRegistration.enrolled_at.desc())
        .limit(500)
    ).all()
    return [
        {
            "sensor_id": registration.sensor_id,
            "identity_verified": registration.public_key is not None,
            "key_fingerprint": (
                hashlib.sha256(_decode_sensor_public_key(registration.public_key)).hexdigest()[:24]
                if registration.public_key
                else None
            ),
            "credential_email": email,
            "source_name": source.name,
            "status": registration.status,
            "host_name": (source.config or {}).get("host_name"),
            "sensor_version": (source.config or {}).get("sensor_version"),
            "capabilities": (source.config or {}).get("capabilities") or [],
            "diagnostics": (source.config or {}).get("sensor_diagnostics") or {},
            "enrolled_at": registration.enrolled_at,
            "last_seen_at": registration.last_seen_at,
            "revoked_at": registration.revoked_at,
        }
        for registration, email, source in rows
    ]


@router.post("/ingest/live/sensors/{sensor_id}/revoke")
def revoke_sensor(sensor_id: UUID, db: DbDep, actor: AdminUser, request: Request) -> dict:
    registration = db.scalar(
        select(SensorRegistration)
        .where(SensorRegistration.sensor_id == sensor_id)
        .with_for_update()
    )
    if registration is None:
        raise AppError(404, "sensor_not_found", "Registered sensor not found")
    if registration.status == "revoked":
        return {"sensor_id": sensor_id, "status": "revoked"}
    now = datetime.now(UTC)
    registration.status = "revoked"
    registration.revoked_at = now
    user = db.get(User, registration.credential_user_id)
    if user is not None:
        user.is_active = False
        user.token_version += 1
    jobs = db.scalars(
        select(IngestionJob).where(
            IngestionJob.data_source_id == registration.data_source_id,
            IngestionJob.status == "running",
            IngestionJob.original_filename.like("live-capture:%"),
        )
    ).all()
    for job in jobs:
        job.status = "completed"
        job.completed_at = now
    write_audit(
        db,
        actor_id=actor.id,
        action="sensor.registration.revoked",
        target_type="sensor",
        target_id=str(sensor_id),
        ip_address=client_ip(request),
        details={"closed_sessions": len(jobs)},
    )
    db.commit()
    return {"sensor_id": sensor_id, "status": "revoked", "closed_sessions": len(jobs)}


@router.post("/ingest/live/sensors/{sensor_id}/rotate-credential")
def rotate_sensor_credential(
    sensor_id: UUID,
    payload: SensorCredentialRotate,
    db: DbDep,
    actor: AdminUser,
    request: Request,
) -> dict:
    registration = db.scalar(
        select(SensorRegistration)
        .where(SensorRegistration.sensor_id == sensor_id)
        .with_for_update()
    )
    if registration is None:
        raise AppError(404, "sensor_not_found", "Registered sensor not found")
    user = db.get(User, registration.credential_user_id)
    if user is None:
        raise AppError(
            409,
            "sensor_account_missing",
            "The sensor credential account no longer exists",
        )
    user.hashed_password = hash_password(payload.password)
    user.token_version += 1
    user.is_active = True
    registration.status = "active"
    registration.revoked_at = None
    registration.public_key = None
    registration.last_request_counter = 0
    now = datetime.now(UTC)
    jobs = db.scalars(
        select(IngestionJob).where(
            IngestionJob.data_source_id == registration.data_source_id,
            IngestionJob.status == "running",
            IngestionJob.original_filename.like("live-capture:%"),
        )
    ).all()
    for job in jobs:
        job.status = "completed"
        job.completed_at = now
    write_audit(
        db,
        actor_id=actor.id,
        action="sensor.credential.rotated",
        target_type="sensor",
        target_id=str(sensor_id),
        ip_address=client_ip(request),
        details={"closed_sessions": len(jobs)},
    )
    db.commit()
    return {
        "sensor_id": sensor_id,
        "status": "active",
        "credential_email": user.email,
        "restart_required": True,
        "message": (
            "Update SENTINEL_SENSOR_PASSWORD in the host .env file, "
            "then restart the sensor controller."
        ),
    }


@router.post("/ingest/live/{job_id}/events", status_code=202)
async def ingest_live_batch(
    job_id: UUID, payload: LiveCaptureBatch, db: DbDep, actor: LiveSensorUser, request: Request
) -> dict:
    # Import lazily: the ingestion service imports this detector module too.
    from app.detection.run import run_detection_for_job

    job = db.get(IngestionJob, job_id)
    if job is None:
        raise AppError(404, "not_found", "Live capture session not found")
    if job.status != "running" or not job.original_filename.startswith("live-capture:"):
        raise AppError(409, "capture_not_running", "Live capture session is not running")
    _assert_live_session_access(job, actor)
    registration = _assert_registered_sensor_session(db, job, actor)
    if registration is not None:
        await _verify_registered_sensor_request(request, registration)

    accepted = duplicates = 0
    quarantined: list[dict] = []
    batch_keys: set[str] = set()
    for index, raw in enumerate(payload.events, start=1):
        if not isinstance(raw, dict):
            quarantined.append({"row": index, "error": "Event must be a JSON object"})
            continue
        try:
            normalized = validate_normalized_event(normalize_generic(raw, index), index)
        except RowError as exc:
            quarantined.append({"row": index, "error": exc.message})
            continue
        key = normalized.get("dedup_key")
        if key and (
            key in batch_keys
            or db.scalar(select(SecurityEvent.id).where(SecurityEvent.dedup_key == key))
        ):
            duplicates += 1
            continue
        if key:
            batch_keys.add(key)
        db.add(
            SecurityEvent(
                event_time=normalized["event_time"],
                data_source_id=job.data_source_id,
                ingestion_job_id=job.id,
                event_type=normalized["event_type"],
                src_ip=normalized.get("src_ip"),
                dst_ip=normalized.get("dst_ip"),
                src_port=normalized.get("src_port"),
                dst_port=normalized.get("dst_port"),
                host_id=normalized.get("host_id"),
                severity=normalized.get("severity") or "informational",
                attributes=normalized.get("attributes") or {},
                raw_payload=normalized.get("raw_payload") or {},
                schema_version=normalized.get("schema_version") or 1,
                dedup_key=key,
            )
        )
        accepted += 1

    db.flush()
    detections = run_detection_for_job(db, job.id) if accepted else 0
    stats = dict(job.stats or {})
    stats["accepted"] = stats.get("accepted", 0) + accepted
    stats["duplicates"] = stats.get("duplicates", 0) + duplicates
    stats["quarantined"] = stats.get("quarantined", 0) + len(quarantined)
    stats["detections_created"] = stats.get("detections_created", 0) + detections
    samples = list(stats.get("quarantine_samples") or [])
    stats["quarantine_samples"] = (samples + quarantined)[:50]
    job.stats = stats
    job.started_at = job.started_at or datetime.now(UTC)
    job.last_heartbeat_at = datetime.now(UTC)
    if registration is not None:
        registration.last_seen_at = job.last_heartbeat_at
    if job.data_source_id:
        source = db.get(DataSource, job.data_source_id)
        if source:
            source.last_seen_at = datetime.now(UTC)
    db.commit()
    return {
        "job_id": job.id,
        "accepted": accepted,
        "duplicates": duplicates,
        "quarantined": len(quarantined),
        "detections_created": detections,
    }


@router.post("/ingest/live/{job_id}/finish")
async def finish_live_capture(
    job_id: UUID, db: DbDep, actor: LiveSensorUser, request: Request
) -> dict:
    job = db.get(IngestionJob, job_id)
    if job is None:
        raise AppError(404, "not_found", "Live capture session not found")
    _assert_live_session_access(job, actor)
    registration = _assert_registered_sensor_session(db, job, actor)
    if registration is not None:
        await _verify_registered_sensor_request(request, registration)
    if not job.original_filename.startswith("live-capture:"):
        raise AppError(400, "not_live_capture", "This job is not a live capture session")
    if job.status == "running":
        job.status = "completed"
        job.completed_at = datetime.now(UTC)
        write_audit(
            db,
            actor_id=actor.id,
            action="ingest.live.finish",
            target_type="ingestion_job",
            target_id=str(job.id),
            ip_address=client_ip(request),
            details={"stats": job.stats or {}},
        )
        db.commit()
        db.refresh(job)
    return _job(job)


@router.get("/ingest/jobs")
def list_jobs(db: DbDep, _: AllowedList, page: int = 1, page_size: int = 20) -> Page[dict]:
    page_size = min(max(page_size, 1), 100)
    total = db.scalar(select(func.count()).select_from(IngestionJob)) or 0
    rows = db.scalars(
        select(IngestionJob)
        .order_by(IngestionJob.created_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    ).all()
    return Page(items=[_job(j) for j in rows], page=page, page_size=page_size, total=total)


@router.get("/ingest/jobs/{job_id}")
def get_job(job_id: UUID, db: DbDep, _: AllowedList) -> dict:
    job = db.get(IngestionJob, job_id)
    if job is None:
        raise AppError(404, "not_found", "Job not found")
    return _job(job)


@router.get("/ingest/jobs/{job_id}/quarantine")
def job_quarantine(job_id: UUID, db: DbDep, _: AllowedList) -> dict:
    job = db.get(IngestionJob, job_id)
    if job is None:
        raise AppError(404, "not_found", "Job not found")
    return {"job_id": job.id, "items": (job.stats or {}).get("quarantine_samples") or []}


def _can_manage_all_live_sessions(actor: TokenUser) -> bool:
    return ADMIN in actor.roles or ANALYST in actor.roles


def _decode_sensor_public_key(value: str | None) -> bytes:
    if not value:
        raise AppError(
            400, "sensor_key_required", "A sensor signing key is required for enrollment"
        )
    try:
        decoded = base64.b64decode(value, validate=True)
        Ed25519PublicKey.from_public_bytes(decoded)
        return decoded
    except (ValueError, binascii.Error):
        raise AppError(400, "sensor_key_invalid", "The sensor signing key is invalid") from None


async def _verify_registered_sensor_request(
    request: Request, registration: SensorRegistration
) -> None:
    counter = await _verify_sensor_proof(
        request, str(registration.sensor_id), registration.public_key
    )
    if counter <= registration.last_request_counter:
        raise AppError(409, "sensor_request_replayed", "The sensor request was already used")
    registration.last_request_counter = counter


async def _verify_sensor_proof(request: Request, sensor_id: str, public_key: str | None) -> int:
    """Verify a time-bounded Ed25519 signature over the exact HTTP request body."""
    if not public_key:
        raise AppError(
            409,
            "sensor_key_not_enrolled",
            "This sensor has no registered signing key; rotate its credential to enroll it",
        )
    header_sensor_id = request.headers.get("x-sentinel-sensor-id", "")
    timestamp = request.headers.get("x-sentinel-timestamp", "")
    counter_header = request.headers.get("x-sentinel-counter", "")
    signature = request.headers.get("x-sentinel-signature", "")
    try:
        if len(timestamp) != 10 or not timestamp.isascii() or not timestamp.isdigit():
            raise ValueError
        if not counter_header.isascii() or not counter_header.isdigit() or len(counter_header) > 19:
            raise ValueError
        issued_at = int(timestamp)
        counter = int(counter_header)
        if counter > 9_223_372_036_854_775_807:
            raise ValueError
        signature_bytes = base64.b64decode(signature, validate=True)
        key_bytes = _decode_sensor_public_key(public_key)
    except (ValueError, binascii.Error):
        raise AppError(
            401, "sensor_proof_invalid", "The sensor identity proof is invalid"
        ) from None
    if counter < 1 or header_sensor_id != sensor_id or abs(time.time() - issued_at) > 60:
        raise AppError(
            401, "sensor_proof_expired", "The sensor identity proof is missing or expired"
        )
    method = request.method.upper()
    message = (
        f"{sensor_id}\n{counter}\n{timestamp}\n{method}\n{request.url.path}\n".encode()
        + await request.body()
    )
    try:
        Ed25519PublicKey.from_public_bytes(key_bytes).verify(signature_bytes, message)
    except (InvalidSignature, ValueError):
        raise AppError(
            401, "sensor_proof_invalid", "The sensor identity proof is invalid"
        ) from None
    return counter


def _assert_live_session_access(job: IngestionJob, actor: TokenUser) -> None:
    # Ingestion-only credentials may operate only sessions they created.
    if not _can_manage_all_live_sessions(actor) and job.created_by != actor.id:
        raise AppError(404, "not_found", "Live capture session not found")


def _assert_registered_sensor_session(
    db: DbDep, job: IngestionJob, actor: TokenUser
) -> SensorRegistration | None:
    if _can_manage_all_live_sessions(actor):
        return None
    registration = db.scalar(
        select(SensorRegistration)
        .where(
            SensorRegistration.credential_user_id == actor.id,
            SensorRegistration.data_source_id == job.data_source_id,
            SensorRegistration.status == "active",
        )
        .with_for_update()
    )
    if registration is None:
        raise AppError(404, "not_found", "Live capture session not found")
    return registration


def _pending_response_actions(
    db: Session, registration: SensorRegistration | None, now: datetime
) -> list[dict]:
    if registration is None:
        return []
    rows = db.scalars(
        select(ResponseSimulation)
        .where(
            ResponseSimulation.sensor_id == registration.sensor_id,
            ResponseSimulation.action_type == ip_block.ACTION,
            ResponseSimulation.enforcement_status.in_(
                [ip_block.PENDING, ip_block.APPLIED, ip_block.REMOVAL_PENDING]
            ),
        )
        .order_by(ResponseSimulation.created_at)
        .limit(50)
    ).all()
    actions: list[dict] = []
    for row in rows:
        if row.enforcement_status == ip_block.PENDING and row.status == "approved":
            actions.append(
                {
                    "id": str(row.id),
                    "action": "block",
                    "ip": row.target,
                    "minutes": row.duration_minutes or ip_block.DEFAULT_MINUTES,
                }
            )
        elif row.enforcement_status == ip_block.REMOVAL_PENDING or (
            row.enforcement_status == ip_block.APPLIED
            and row.block_until is not None
            and row.block_until <= now
        ):
            actions.append({"id": str(row.id), "action": "unblock", "ip": row.target})
    return actions


def _source(source: DataSource) -> dict:
    return {
        "id": source.id,
        "name": source.name,
        "source_type": source.source_type,
        "status": source.status,
        "last_seen_at": source.last_seen_at,
        "last_error": source.last_error,
        "config": source.config,
        "created_at": source.created_at,
    }


def _job(job: IngestionJob) -> dict:
    return {
        "id": job.id,
        "status": job.status,
        "adapter": job.adapter,
        "original_filename": job.original_filename,
        "stats": job.stats,
        "error": job.error,
        "created_at": job.created_at,
        "started_at": job.started_at,
        "completed_at": job.completed_at,
        "data_source_id": job.data_source_id,
    }
