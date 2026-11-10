import ipaddress
from datetime import UTC, datetime, timedelta
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import selectinload

from app.api.deps import DbDep, client_ip, require_roles
from app.audit.service import write_audit
from app.core.errors import AppError
from app.core.permissions import ADMIN, ANALYST, AUDITOR, MUTATE_CASES
from app.models import (
    Case,
    CaseComment,
    CaseDetection,
    CaseStatusHistory,
    Detection,
    DetectionEvidence,
    ResponseSimulation,
    Role,
    User,
    UserRole,
)
from app.schemas.common import Page, TokenUser

router = APIRouter(prefix="/cases", tags=["cases"])
Reader = Annotated[TokenUser, Depends(require_roles(ADMIN, ANALYST, AUDITOR))]
Writer = Annotated[TokenUser, Depends(require_roles(*MUTATE_CASES))]
AdminWriter = Annotated[TokenUser, Depends(require_roles(ADMIN))]

STATUSES = {"new", "investigating", "resolved", "false-positive"}
SEVERITIES = {"informational", "low", "medium", "high", "critical"}
PRIORITIES = {"p1", "p2", "p3", "p4"}


class CaseCreate(BaseModel):
    title: str = Field(min_length=1, max_length=400)
    severity: str = "medium"
    priority: str = "p3"
    detection_ids: list[UUID] = Field(default_factory=list)
    assigned_to: UUID | None = None


class CasePatch(BaseModel):
    title: str | None = None
    status: str | None = None
    severity: str | None = None
    priority: str | None = None
    assigned_to: UUID | None = None


class CommentIn(BaseModel):
    body: str = Field(min_length=1, max_length=8000)


class ResponseSimulationIn(BaseModel):
    action_type: str = Field(min_length=1, max_length=64)
    target: str = Field(min_length=1, max_length=512)
    rationale: str = Field(min_length=10, max_length=2000)
    idempotency_key: str | None = Field(default=None, min_length=8, max_length=128)


SIMULATED_ACTIONS = {
    "simulate_host_isolation",
    "simulate_account_disable",
    "simulate_source_ip_block",
}


@router.get("")
def list_cases(
    db: DbDep,
    _: Reader,
    page: int = 1,
    page_size: int = 20,
    status: str | None = None,
    severity: str | None = None,
) -> Page[dict]:
    page_size = min(max(page_size, 1), 100)
    stmt = select(Case)
    count_stmt = select(func.count()).select_from(Case)
    if status:
        stmt = stmt.where(Case.status == status)
        count_stmt = count_stmt.where(Case.status == status)
    if severity:
        stmt = stmt.where(Case.severity == severity)
        count_stmt = count_stmt.where(Case.severity == severity)
    total = db.scalar(count_stmt) or 0
    rows = db.scalars(
        stmt.order_by(Case.updated_at.desc()).offset((page - 1) * page_size).limit(page_size)
    ).all()
    return Page(items=[_case(c) for c in rows], page=page, page_size=page_size, total=total)


@router.get("/assignees")
def list_case_assignees(db: DbDep, _: Reader) -> list[dict]:
    rows = db.execute(
        select(User.id, User.full_name, User.email)
        .join(UserRole, UserRole.user_id == User.id)
        .join(Role, Role.id == UserRole.role_id)
        .where(User.is_active.is_(True), Role.name.in_([ADMIN, ANALYST]))
        .distinct()
        .order_by(User.full_name, User.email)
    ).all()
    return [{"id": str(row.id), "full_name": row.full_name, "email": row.email} for row in rows]


@router.post("", status_code=201)
def create_case(payload: CaseCreate, db: DbDep, actor: Writer, request: Request) -> dict:
    if payload.severity not in SEVERITIES:
        raise AppError(400, "invalid_severity", "Unknown case severity")
    if payload.priority not in PRIORITIES:
        raise AppError(400, "invalid_priority", "Unknown case priority")
    if payload.assigned_to is not None:
        assignee = db.scalar(
            select(User)
            .join(UserRole, UserRole.user_id == User.id)
            .join(Role, Role.id == UserRole.role_id)
            .where(
                User.id == payload.assigned_to,
                User.is_active.is_(True),
                Role.name.in_([ADMIN, ANALYST]),
            )
        )
        if assignee is None:
            raise AppError(
                400, "invalid_assignee", "Assignee must be an active administrator or analyst"
            )
    case = Case(
        title=payload.title,
        severity=payload.severity,
        priority=payload.priority,
        assigned_to=payload.assigned_to,
        correlation_reason="Created manually by an analyst.",
    )
    db.add(case)
    db.flush()
    db.add(CaseStatusHistory(case_id=case.id, actor_id=actor.id, from_status=None, to_status="new"))
    for det_id in payload.detection_ids:
        if db.get(Detection, det_id) is None:
            raise AppError(400, "invalid_detection", "Detection not found")
        db.add(CaseDetection(case_id=case.id, detection_id=det_id))
    write_audit(
        db,
        actor_id=actor.id,
        action="case.create",
        target_type="case",
        target_id=str(case.id),
        ip_address=client_ip(request),
    )
    db.commit()
    return get_case(case.id, db, actor)


@router.get("/{case_id}")
def get_case(case_id: UUID, db: DbDep, _: Reader) -> dict:
    case = db.scalar(
        select(Case)
        .options(
            selectinload(Case.detections)
            .selectinload(CaseDetection.detection)
            .selectinload(Detection.event_links)
            .selectinload(DetectionEvidence.event),
            selectinload(Case.comments),
            selectinload(Case.history),
            selectinload(Case.response_simulations),
        )
        .where(Case.id == case_id)
    )
    if case is None:
        raise AppError(404, "not_found", "Case not found")
    body = _case(case)
    body["detections"] = [
        {
            "id": link.detection.id,
            "title": link.detection.title,
            "severity": link.detection.severity,
            "rule_id": link.detection.rule_id,
            "summary": link.detection.summary,
            "created_at": link.detection.created_at,
            "evidence": link.detection.evidence,
            "events": [
                {
                    "id": evidence.event.id,
                    "event_type": evidence.event.event_type,
                    "event_time": evidence.event.event_time,
                    "host_id": evidence.event.host_id,
                    "src_ip": str(evidence.event.src_ip) if evidence.event.src_ip else None,
                    "dst_ip": str(evidence.event.dst_ip) if evidence.event.dst_ip else None,
                    "src_port": evidence.event.src_port,
                    "dst_port": evidence.event.dst_port,
                    "attributes": evidence.event.attributes or {},
                }
                for evidence in link.detection.event_links
                if evidence.event is not None
            ],
        }
        for link in case.detections
        if link.detection
    ]
    body["comments"] = [
        {"id": c.id, "author_id": c.author_id, "body": c.body, "created_at": c.created_at}
        for c in sorted(case.comments, key=lambda x: x.created_at)
    ]
    body["history"] = [
        {
            "id": h.id,
            "from_status": h.from_status,
            "to_status": h.to_status,
            "actor_id": h.actor_id,
            "note": h.note,
            "created_at": h.created_at,
        }
        for h in sorted(case.history, key=lambda x: x.created_at)
    ]
    body["response_simulations"] = [
        _response_simulation(item)
        for item in sorted(case.response_simulations, key=lambda x: x.created_at)
    ]
    body["response_recommendation"] = {
        "available": True,
        "reason": (
            "Simulation records only. No host, account, network, or cloud action is executed."
        ),
        "simulate_only": True,
        "actions": sorted(SIMULATED_ACTIONS),
        "guidance": [
            "Verify linked evidence and confirm the target is in authorized scope.",
            "An analyst may propose a simulation; a different administrator must approve it.",
            "The approved simulation writes an audit record only and does not contact the target.",
        ],
    }
    return body


@router.post("/{case_id}/responses", status_code=201)
def propose_response_simulation(
    case_id: UUID,
    payload: ResponseSimulationIn,
    db: DbDep,
    actor: Writer,
    request: Request,
) -> dict:
    case = db.scalar(select(Case).where(Case.id == case_id).with_for_update())
    if case is None:
        raise AppError(404, "not_found", "Case not found")
    if payload.action_type not in SIMULATED_ACTIONS:
        raise AppError(400, "invalid_action", "Unsupported simulation action")
    target = payload.target.strip()
    if not target:
        raise AppError(400, "invalid_target", "Target cannot be blank")
    rationale = payload.rationale.strip()
    if len(rationale) < 10:
        raise AppError(
            400, "invalid_rationale", "Rationale must contain at least 10 non-whitespace characters"
        )
    if payload.action_type == "simulate_source_ip_block":
        try:
            target = str(ipaddress.ip_address(target))
        except ValueError as exc:
            raise AppError(
                400, "invalid_target", "Source IP simulation requires a valid IP address"
            ) from exc
    if payload.idempotency_key:
        existing = db.scalar(
            select(ResponseSimulation).where(
                ResponseSimulation.idempotency_key == payload.idempotency_key
            )
        )
        if existing:
            if (
                existing.case_id == case.id
                and existing.action_type == payload.action_type
                and existing.target == target
                and existing.rationale == rationale
            ):
                return _response_simulation(existing)
            raise AppError(
                409,
                "idempotency_conflict",
                "Idempotency key was already used for another simulation",
            )
    simulation = ResponseSimulation(
        case_id=case.id,
        action_type=payload.action_type,
        target=target,
        rationale=rationale,
        status="proposed",
        requested_by=actor.id,
        idempotency_key=payload.idempotency_key,
        expires_at=datetime.now(UTC) + timedelta(days=7),
    )
    db.add(simulation)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        if not payload.idempotency_key:
            raise
        existing = db.scalar(
            select(ResponseSimulation).where(
                ResponseSimulation.idempotency_key == payload.idempotency_key
            )
        )
        if existing is not None and _same_response_request(
            existing,
            case_id=case.id,
            action_type=payload.action_type,
            target=target,
            rationale=rationale,
        ):
            return _response_simulation(existing)
        raise AppError(
            409,
            "idempotency_conflict",
            "Idempotency key was already used for another simulation",
        ) from None
    write_audit(
        db,
        actor_id=actor.id,
        action="response.simulation.proposed",
        target_type="response_simulation",
        target_id=str(simulation.id),
        ip_address=client_ip(request),
        details={
            "case_id": str(case.id),
            "action_type": simulation.action_type,
            "target": simulation.target,
        },
    )
    db.commit()
    db.refresh(simulation)
    return _response_simulation(simulation)


@router.post("/{case_id}/responses/{response_id}/reject")
def reject_response_simulation(
    case_id: UUID,
    response_id: UUID,
    db: DbDep,
    actor: AdminWriter,
    request: Request,
    note: str = "",
) -> dict:
    simulation = db.scalar(
        select(ResponseSimulation)
        .where(
            ResponseSimulation.id == response_id,
            ResponseSimulation.case_id == case_id,
        )
        .with_for_update()
    )
    if simulation is None:
        raise AppError(404, "not_found", "Response simulation not found")
    if simulation.requested_by == actor.id:
        raise AppError(
            403, "separation_of_duties", "A different administrator must review this proposal"
        )
    if simulation.status != "proposed":
        raise AppError(409, "invalid_transition", "Only proposed simulations can be rejected")
    now = datetime.now(UTC)
    if simulation.expires_at <= now:
        simulation.status = "expired"
        write_audit(
            db,
            actor_id=actor.id,
            action="response.simulation.expired",
            target_type="response_simulation",
            target_id=str(simulation.id),
            ip_address=client_ip(request),
            details={"case_id": str(case_id)},
        )
        db.commit()
        raise AppError(409, "proposal_expired", "This response proposal has expired")
    if len(note.strip()) > 1000:
        raise AppError(
            400, "invalid_rejection_note", "Rejection note cannot exceed 1000 characters"
        )
    simulation.status = "rejected"
    simulation.rejected_by = actor.id
    simulation.rejected_at = now
    simulation.rejection_note = note.strip()
    write_audit(
        db,
        actor_id=actor.id,
        action="response.simulation.rejected",
        target_type="response_simulation",
        target_id=str(simulation.id),
        ip_address=client_ip(request),
        details={"case_id": str(case_id), "note": simulation.rejection_note},
    )
    db.commit()
    db.refresh(simulation)
    return _response_simulation(simulation)


@router.post("/{case_id}/responses/{response_id}/approve")
def approve_response_simulation(
    case_id: UUID,
    response_id: UUID,
    db: DbDep,
    actor: AdminWriter,
    request: Request,
) -> dict:
    simulation = db.scalar(
        select(ResponseSimulation)
        .where(
            ResponseSimulation.id == response_id,
            ResponseSimulation.case_id == case_id,
        )
        .with_for_update()
    )
    if simulation is None:
        raise AppError(404, "not_found", "Response simulation not found")
    if simulation.requested_by == actor.id:
        raise AppError(
            403, "separation_of_duties", "A different administrator must approve this proposal"
        )
    if simulation.status != "proposed":
        raise AppError(409, "invalid_transition", "Only proposed simulations can be approved")
    if simulation.expires_at <= datetime.now(UTC):
        simulation.status = "expired"
        write_audit(
            db,
            actor_id=actor.id,
            action="response.simulation.expired",
            target_type="response_simulation",
            target_id=str(simulation.id),
            ip_address=client_ip(request),
            details={"case_id": str(case_id)},
        )
        db.commit()
        raise AppError(409, "proposal_expired", "This response proposal has expired")
    simulation.status = "approved"
    simulation.approved_by = actor.id
    simulation.approved_at = datetime.now(UTC)
    write_audit(
        db,
        actor_id=actor.id,
        action="response.simulation.approved",
        target_type="response_simulation",
        target_id=str(simulation.id),
        ip_address=client_ip(request),
        details={"case_id": str(case_id), "action_type": simulation.action_type},
    )
    db.commit()
    db.refresh(simulation)
    return _response_simulation(simulation)


@router.post("/{case_id}/responses/{response_id}/simulate")
def simulate_response(
    case_id: UUID,
    response_id: UUID,
    db: DbDep,
    actor: AdminWriter,
    request: Request,
) -> dict:
    simulation = db.scalar(
        select(ResponseSimulation)
        .where(
            ResponseSimulation.id == response_id,
            ResponseSimulation.case_id == case_id,
        )
        .with_for_update()
    )
    if simulation is None:
        raise AppError(404, "not_found", "Response simulation not found")
    if simulation.status != "approved":
        raise AppError(409, "invalid_transition", "Only approved simulations can be recorded")
    simulation.status = "simulated"
    simulation.simulated_by = actor.id
    simulation.simulated_at = datetime.now(UTC)
    write_audit(
        db,
        actor_id=actor.id,
        action="response.simulation.recorded",
        target_type="response_simulation",
        target_id=str(simulation.id),
        ip_address=client_ip(request),
        details={
            "case_id": str(case_id),
            "action_type": simulation.action_type,
            "target": simulation.target,
            "execution": "none; audit record only",
        },
    )
    db.commit()
    db.refresh(simulation)
    return _response_simulation(simulation)


@router.patch("/{case_id}")
def patch_case(
    case_id: UUID, payload: CasePatch, db: DbDep, actor: Writer, request: Request
) -> dict:
    case = db.get(Case, case_id)
    if case is None:
        raise AppError(404, "not_found", "Case not found")
    if payload.status:
        if payload.status not in STATUSES:
            raise AppError(400, "invalid_status", "Unknown case status")
        db.add(
            CaseStatusHistory(
                case_id=case.id,
                actor_id=actor.id,
                from_status=case.status,
                to_status=payload.status,
            )
        )
        case.status = payload.status
    if payload.title is not None:
        case.title = payload.title
    if payload.severity is not None:
        if payload.severity not in SEVERITIES:
            raise AppError(400, "invalid_severity", "Unknown case severity")
        case.severity = payload.severity
    if payload.priority is not None:
        if payload.priority not in PRIORITIES:
            raise AppError(400, "invalid_priority", "Unknown case priority")
        case.priority = payload.priority
    if "assigned_to" in payload.model_fields_set:
        if payload.assigned_to is not None:
            assignee = db.scalar(
                select(User)
                .join(UserRole, UserRole.user_id == User.id)
                .join(Role, Role.id == UserRole.role_id)
                .where(
                    User.id == payload.assigned_to,
                    User.is_active.is_(True),
                    Role.name.in_([ADMIN, ANALYST]),
                )
            )
            if assignee is None:
                raise AppError(
                    400, "invalid_assignee", "Assignee must be an active administrator or analyst"
                )
        case.assigned_to = payload.assigned_to
    write_audit(
        db,
        actor_id=actor.id,
        action="case.update",
        target_type="case",
        target_id=str(case.id),
        ip_address=client_ip(request),
        details={
            "status": case.status,
            "severity": case.severity,
            "priority": case.priority,
            "assigned_to": str(case.assigned_to) if case.assigned_to else None,
        },
    )
    db.commit()
    return get_case(case.id, db, actor)


@router.post("/{case_id}/comments", status_code=201)
def add_comment(case_id: UUID, payload: CommentIn, db: DbDep, actor: Writer) -> dict:
    case = db.get(Case, case_id)
    if case is None:
        raise AppError(404, "not_found", "Case not found")
    comment = CaseComment(case_id=case.id, author_id=actor.id, body=payload.body)
    db.add(comment)
    db.commit()
    db.refresh(comment)
    return {"id": comment.id, "body": comment.body, "created_at": comment.created_at}


@router.get("/{case_id}/history")
def history(case_id: UUID, db: DbDep, user: Reader) -> list[dict]:
    return get_case(case_id, db, user)["history"]


def _response_simulation(item: ResponseSimulation) -> dict:
    return {
        "id": item.id,
        "case_id": item.case_id,
        "action_type": item.action_type,
        "target": item.target,
        "rationale": item.rationale,
        "status": item.status,
        "requested_by": item.requested_by,
        "approved_by": item.approved_by,
        "simulated_by": item.simulated_by,
        "created_at": item.created_at,
        "expires_at": item.expires_at,
        "approved_at": item.approved_at,
        "rejected_by": item.rejected_by,
        "rejected_at": item.rejected_at,
        "rejection_note": item.rejection_note,
        "simulated_at": item.simulated_at,
        "execution": "none; audit record only",
    }


def _same_response_request(
    item: ResponseSimulation,
    *,
    case_id: UUID,
    action_type: str,
    target: str,
    rationale: str,
) -> bool:
    return (
        item.case_id == case_id
        and item.action_type == action_type
        and item.target == target
        and item.rationale == rationale
    )


def _case(case: Case) -> dict:
    return {
        "id": case.id,
        "title": case.title,
        "status": case.status,
        "severity": case.severity,
        "priority": case.priority,
        "assigned_to": case.assigned_to,
        "correlation_reason": case.correlation_reason,
        "correlation_evidence": case.correlation_evidence,
        "created_at": case.created_at,
        "updated_at": case.updated_at,
    }
