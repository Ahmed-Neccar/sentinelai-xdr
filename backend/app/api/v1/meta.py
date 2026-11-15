import csv
import io
from datetime import UTC, datetime, timedelta
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field
from sqlalchemy import func, select, text

from app.api.deps import DbDep, require_roles
from app.core.config import settings
from app.core.errors import AppError
from app.core.permissions import ADMIN, ANALYST, AUDITOR, MANAGE_SETTINGS, READ_AUDIT, READ_EVENTS
from app.models import (
    AuditLog,
    Case,
    Detection,
    IngestionJob,
    ModelEvaluation,
    ModelVersion,
    SecurityEvent,
    SystemSetting,
)
from app.schemas.common import Page, TokenUser

router = APIRouter(tags=["meta"])
Reader = Annotated[TokenUser, Depends(require_roles(*READ_EVENTS))]
Auditor = Annotated[TokenUser, Depends(require_roles(*READ_AUDIT))]
Admin = Annotated[TokenUser, Depends(require_roles(*MANAGE_SETTINGS))]


def csv_cell(value: object) -> str:
    text = "" if value is None else str(value)
    if text.startswith(("=", "+", "-", "@")):
        return f"'{text}"
    return text


class SettingsPatch(BaseModel):
    retention_days: int | None = Field(default=None, ge=1, le=3650)
    upload_retention_days: int | None = Field(default=None, ge=1, le=3650)


@router.get("/dashboard/summary")
def dashboard(db: DbDep, _: Reader) -> dict:
    events = db.scalar(select(func.count()).select_from(SecurityEvent)) or 0
    detections = db.scalar(select(func.count()).select_from(Detection)) or 0
    open_cases = (
        db.scalar(
            select(func.count()).select_from(Case).where(Case.status.in_(("new", "investigating")))
        )
        or 0
    )
    sev_rows = db.execute(
        select(Detection.severity, func.count()).group_by(Detection.severity)
    ).all()
    jobs = db.scalars(select(IngestionJob).order_by(IngestionJob.created_at.desc()).limit(8)).all()
    return {
        "generated_at": datetime.now(UTC),
        "event_count": events,
        "detection_count": detections,
        "open_cases": open_cases,
        "severity_distribution": {row[0]: row[1] for row in sev_rows},
        "recent_jobs": [
            {
                "id": j.id,
                "status": j.status,
                "filename": j.original_filename,
                "created_at": j.created_at,
            }
            for j in jobs
        ],
        "disclaimer": (
            "Figures are computed from persisted lab data. They are not live sensor health "
            "from production networks."
        ),
    }


@router.get("/system/health")
def system_health(db: DbDep, _: Reader) -> dict:
    from app.notifications.health import health_snapshot

    return health_snapshot(db)


@router.get("/reports/summary")
def report(db: DbDep, _: Reader, format: str = "json"):
    summary = dashboard(db, _)
    summary["limitations"] = [
        "Synthetic demo data must not be treated as a real incident corpus.",
        "Rule hits are not confirmed attacks.",
        "ML scores are experimental investigation signals.",
    ]
    if format != "csv":
        return summary
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["metric", "value"])
    writer.writerow([csv_cell("event_count"), csv_cell(summary["event_count"])])
    writer.writerow([csv_cell("detection_count"), csv_cell(summary["detection_count"])])
    writer.writerow([csv_cell("open_cases"), csv_cell(summary["open_cases"])])
    return PlainTextResponse(buf.getvalue(), media_type="text/csv")


@router.get("/models")
def models(db: DbDep, _: Reader) -> list[dict]:
    rows = db.scalars(select(ModelVersion).order_by(ModelVersion.created_at.desc())).all()
    if not rows:
        return [
            {
                "id": None,
                "name": "isolation_forest",
                "status": "unavailable",
                "notes": (
                    "Optional ML scoring is unavailable because no trained model artifact "
                    "is recorded."
                ),
            }
        ]
    return [
        {
            "id": m.id,
            "name": m.name,
            "version": m.version,
            "algorithm": m.algorithm,
            "preprocessing_version": m.preprocessing_version,
            "dataset_version": m.dataset_version,
            "created_at": m.created_at,
            "notes": m.notes,
        }
        for m in rows
    ]


@router.get("/models/{model_id}")
def model_detail(model_id: UUID, db: DbDep, _: Reader) -> dict:
    row = db.get(ModelVersion, model_id)
    if row is None:
        raise AppError(404, "not_found", "Model version not found")
    return {
        "id": row.id,
        "name": row.name,
        "version": row.version,
        "algorithm": row.algorithm,
        "preprocessing_version": row.preprocessing_version,
        "dataset_version": row.dataset_version,
        "created_at": row.created_at,
        "notes": row.notes,
    }


@router.get("/models/{model_id}/evaluation")
def model_eval(model_id: UUID, db: DbDep, _: Reader) -> dict:
    if db.get(ModelVersion, model_id) is None:
        raise AppError(404, "not_found", "Model version not found")
    row = db.scalars(
        select(ModelEvaluation)
        .where(ModelEvaluation.model_version_id == model_id)
        .order_by(ModelEvaluation.evaluated_at.desc())
    ).first()
    if row is None:
        return {
            "status": "unavailable",
            "metrics": None,
            "limitations": "No evaluation has been recorded for this lab yet.",
        }
    return {
        "status": "recorded",
        "metrics": row.metrics,
        "baseline_comparison": row.baseline_comparison,
        "limitations": row.limitations,
        "evaluated_at": row.evaluated_at,
    }


@router.get("/audit-logs")
def audit_logs(db: DbDep, _: Auditor, page: int = 1, page_size: int = 20) -> Page[dict]:
    page_size = min(max(page_size, 1), 100)
    total = db.scalar(select(func.count()).select_from(AuditLog)) or 0
    rows = db.scalars(
        select(AuditLog)
        .order_by(AuditLog.created_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    ).all()
    items = [
        {
            "id": a.id,
            "actor_id": a.actor_id,
            "action": a.action,
            "target_type": a.target_type,
            "target_id": a.target_id,
            "ip_address": a.ip_address,
            "details": a.details,
            "created_at": a.created_at,
        }
        for a in rows
    ]
    return Page(items=items, page=page, page_size=page_size, total=total)


@router.get("/audit-logs/integrity")
def audit_integrity(db: DbDep, _: Auditor) -> dict:
    """Check the organization's audit chain.

    Every row carries a hash over its own fields and the previous row's hash. A row edited
    after the fact, or a row removed from the middle, no longer matches. The oldest remaining
    row is taken as the start, because retention removes old history. Removing the newest
    rows cannot be seen from the database alone: compare `head_hash` with a copy kept outside
    (the export includes it).
    """
    rows = db.execute(
        text(
            """
            SELECT seq, prev_hash, row_hash,
                   audit_row_hash(prev_hash, id, actor_id, action, target_type, target_id,
                                  ip_address, details, created_at) AS expected,
                   lag(row_hash) OVER (ORDER BY seq) AS before
            FROM audit_logs ORDER BY seq
            """
        )
    ).all()
    broken: list[int] = []
    for index, row in enumerate(rows):
        links = index == 0 or row.prev_hash == row.before
        if row.row_hash != row.expected or not links:
            broken.append(row.seq)
    return {
        "ok": not broken,
        "checked": len(rows),
        "first_seq": rows[0].seq if rows else None,
        "last_seq": rows[-1].seq if rows else None,
        "head_hash": rows[-1].row_hash if rows else None,
        "broken_at": broken[:20],
    }


@router.get("/audit-logs/export")
def audit_export(
    db: DbDep, _: Auditor, after_seq: int = 0, limit: int = 1000
) -> dict:
    """Audit rows in chain order for a SIEM collector: call again with `next_seq` to continue."""
    limit = min(max(limit, 1), 5000)
    rows = db.scalars(
        select(AuditLog).where(AuditLog.seq > after_seq).order_by(AuditLog.seq).limit(limit)
    ).all()
    return {
        "items": [
            {
                "seq": a.seq,
                "id": a.id,
                "time": a.created_at,
                "actor_id": a.actor_id,
                "action": a.action,
                "target_type": a.target_type,
                "target_id": a.target_id,
                "ip_address": a.ip_address,
                "details": a.details,
                "prev_hash": a.prev_hash,
                "row_hash": a.row_hash,
            }
            for a in rows
        ],
        "next_seq": rows[-1].seq if rows else after_seq,
        "has_more": len(rows) == limit,
    }


SIGN_IN_FAILURE_ACTIONS = ("auth.login_failed", "auth.sso_failed", "auth.sso_identity_mismatch")


@router.get("/audit-logs/sign-in-security")
def sign_in_security(db: DbDep, _: Auditor, hours: int = 24) -> dict:
    """Failed password and SSO sign-ins in the last `hours`, for the Audit page.

    Reads the audit records the sign-in code already writes; nothing new is stored.
    """
    hours = min(max(hours, 1), 24 * 30)
    since = datetime.now(UTC) - timedelta(hours=hours)
    failed = AuditLog.action.in_(SIGN_IN_FAILURE_ACTIONS) & (AuditLog.created_at >= since)
    by_action = {
        action: count
        for action, count in db.execute(
            select(AuditLog.action, func.count()).where(failed).group_by(AuditLog.action)
        ).all()
    }
    top = db.execute(
        select(
            AuditLog.ip_address,
            AuditLog.target_id,
            func.count().label("n"),
            func.max(AuditLog.created_at),
        )
        .where(failed)
        .group_by(AuditLog.ip_address, AuditLog.target_id)
        .order_by(func.count().desc())
        .limit(8)
    ).all()
    return {
        "hours": hours,
        "total": sum(by_action.values()),
        "by_action": by_action,
        "top_sources": [
            {"ip_address": ip, "account": account, "attempts": n, "last_attempt": last}
            for ip, account, n, last in top
        ],
    }


@router.get("/settings")
def get_settings(
    db: DbDep, user: Annotated[TokenUser, Depends(require_roles(ADMIN, AUDITOR, ANALYST))]
) -> dict:
    row = db.scalar(select(SystemSetting).where(SystemSetting.key == "retention"))
    upload_row = db.scalar(
        select(SystemSetting).where(SystemSetting.key == "upload_retention")
    )
    return {
        "retention_days": (row.value or {}).get("days", settings.retention_days)
        if row
        else settings.retention_days,
        "upload_retention_days": (upload_row.value or {}).get(
            "days", settings.upload_retention_days
        )
        if upload_row
        else settings.upload_retention_days,
        "max_upload_bytes": settings.max_upload_bytes,
        "max_upload_rows": settings.max_upload_rows,
        "job_runner": settings.job_runner,
        "bind_note": "Compose publishes ports on 127.0.0.1 only.",
        "response_automation": "disabled",
    }


@router.patch("/settings")
def patch_settings(payload: SettingsPatch, db: DbDep, _: Admin) -> dict:
    if payload.retention_days is not None:
        if payload.retention_days < 1 or payload.retention_days > 3650:
            from app.core.errors import AppError

            raise AppError(400, "invalid_setting", "retention_days out of range")
        row = db.scalar(select(SystemSetting).where(SystemSetting.key == "retention"))
        if row is None:
            db.add(SystemSetting(key="retention", value={"days": payload.retention_days}))
        else:
            row.value = {"days": payload.retention_days}
    if payload.upload_retention_days is not None:
        row = db.scalar(select(SystemSetting).where(SystemSetting.key == "upload_retention"))
        if row is None:
            db.add(
                SystemSetting(
                    key="upload_retention", value={"days": payload.upload_retention_days}
                )
            )
        else:
            row.value = {"days": payload.upload_retention_days}
    if payload.retention_days is not None or payload.upload_retention_days is not None:
        db.commit()
    return get_settings(db, _)
