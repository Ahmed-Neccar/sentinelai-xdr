from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.orm import selectinload

from app.api.deps import DbDep, require_roles
from app.audit.service import write_audit
from app.core.errors import AppError
from app.core.permissions import MANAGE_RULES, READ_EVENTS
from app.models import (
    CaseDetection,
    Detection,
    DetectionEvidence,
    DetectionRule,
    DetectionRuleVersion,
)
from app.schemas.common import Page, TokenUser

router = APIRouter(tags=["detections"])
Reader = Annotated[TokenUser, Depends(require_roles(*READ_EVENTS))]
Admin = Annotated[TokenUser, Depends(require_roles(*MANAGE_RULES))]


class RulePatch(BaseModel):
    enabled: bool


@router.get("/detections")
def list_detections(
    db: DbDep,
    _: Reader,
    page: int = 1,
    page_size: int = 20,
    severity: str | None = None,
    rule_id: str | None = None,
) -> Page[dict]:
    page_size = min(max(page_size, 1), 100)
    stmt = select(Detection)
    count_stmt = select(func.count()).select_from(Detection)
    if severity:
        stmt = stmt.where(Detection.severity == severity)
        count_stmt = count_stmt.where(Detection.severity == severity)
    if rule_id:
        stmt = stmt.where(Detection.rule_id == rule_id)
        count_stmt = count_stmt.where(Detection.rule_id == rule_id)
    total = db.scalar(count_stmt) or 0
    rows = db.scalars(
        stmt.order_by(Detection.created_at.desc()).offset((page - 1) * page_size).limit(page_size)
    ).all()
    return Page(items=[_det(d) for d in rows], page=page, page_size=page_size, total=total)


@router.get("/detections/{detection_id}")
def get_detection(detection_id: UUID, db: DbDep, _: Reader) -> dict:
    detection = db.scalar(
        select(Detection)
        .options(selectinload(Detection.event_links).selectinload(DetectionEvidence.event))
        .where(Detection.id == detection_id)
    )
    if detection is None:
        raise AppError(404, "not_found", "Detection not found")
    body = _det(detection)
    body["linked_events"] = [str(link.event_id) for link in detection.event_links]
    body["evidence_events"] = [
        {
            "id": link.event.id,
            "event_time": link.event.event_time,
            "event_type": link.event.event_type,
            "host_id": link.event.host_id,
            "src_ip": str(link.event.src_ip) if link.event.src_ip else None,
            "dst_ip": str(link.event.dst_ip) if link.event.dst_ip else None,
            "src_port": link.event.src_port,
            "dst_port": link.event.dst_port,
            "attributes": link.event.attributes or {},
        }
        for link in detection.event_links
        if link.event is not None
    ]
    case_links = db.scalars(
        select(CaseDetection)
        .options(selectinload(CaseDetection.case))
        .where(CaseDetection.detection_id == detection.id)
    ).all()
    body["related_cases"] = [
        {
            "id": link.case.id,
            "title": link.case.title,
            "status": link.case.status,
            "severity": link.case.severity,
            "priority": link.case.priority,
        }
        for link in case_links
        if link.case is not None
    ]
    return body


@router.get("/rules")
def list_rules(db: DbDep, _: Reader) -> list[dict]:
    rules = db.scalars(select(DetectionRule).options(selectinload(DetectionRule.versions))).all()
    return [_rule(r) for r in rules]


@router.get("/rules/{rule_pk}")
def get_rule(rule_pk: UUID, db: DbDep, _: Reader) -> dict:
    rule = db.scalar(
        select(DetectionRule)
        .options(selectinload(DetectionRule.versions))
        .where(DetectionRule.id == rule_pk)
    )
    if rule is None:
        raise AppError(404, "not_found", "Rule not found")
    return _rule(rule)


@router.patch("/rules/{rule_pk}")
def patch_rule(rule_pk: UUID, payload: RulePatch, db: DbDep, actor: Admin) -> dict:
    rule = db.get(DetectionRule, rule_pk)
    if rule is None:
        raise AppError(404, "not_found", "Rule not found")
    rule.enabled = payload.enabled
    write_audit(
        db,
        actor_id=actor.id,
        action="rule.enable" if payload.enabled else "rule.disable",
        target_type="rule",
        target_id=rule.rule_id,
    )
    db.commit()
    return {"id": rule.id, "rule_id": rule.rule_id, "enabled": rule.enabled}


@router.get("/rules/{rule_pk}/versions")
def rule_versions(rule_pk: UUID, db: DbDep, _: Reader) -> list[dict]:
    versions = db.scalars(
        select(DetectionRuleVersion).where(DetectionRuleVersion.rule_pk == rule_pk)
    ).all()
    return [
        {
            "id": v.id,
            "version": v.version,
            "severity": v.severity,
            "spec": v.spec,
            "created_at": v.created_at,
        }
        for v in versions
    ]


def _det(d: Detection) -> dict:
    return {
        "id": d.id,
        "title": d.title,
        "severity": d.severity,
        "status": d.status,
        "detector_kind": d.detector_kind,
        "rule_id": d.rule_id,
        "rule_version": d.rule_version,
        "model_version": d.model_version,
        "summary": d.summary,
        "evidence": d.evidence,
        "mitre": d.mitre,
        "score": d.score,
        "score_kind": d.score_kind,
        "created_at": d.created_at,
        "attribution_note": (
            "ATT&CK mappings are hypotheses based on telemetry patterns, "
            "not confirmed adversary activity."
            if d.mitre
            else None
        ),
    }


def _rule(rule: DetectionRule) -> dict:
    return {
        "id": rule.id,
        "rule_id": rule.rule_id,
        "title": rule.title,
        "description": rule.description,
        "enabled": rule.enabled,
        "current_version": rule.current_version,
        "versions": [
            {"version": v.version, "severity": v.severity, "spec": v.spec} for v in rule.versions
        ],
    }
