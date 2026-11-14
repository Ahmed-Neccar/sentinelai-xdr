from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from sqlalchemy import or_, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session, selectinload

from app.correlation.service import entity_keys_from_events, should_group
from app.detection.builtin_rules import BUILTIN_RULES
from app.detection.distinct import evaluate_distinct_rule
from app.detection.engine import evaluate_rule
from app.detection.login_pattern import evaluate_login_pattern
from app.detection.ml.infer import score_events
from app.detection.port_scan import evaluate_unique_port_rule
from app.models import (
    Case,
    CaseDetection,
    Detection,
    DetectionEvidence,
    DetectionRule,
    SecurityEvent,
)
from app.notifications.service import enqueue_detection_notifications


def event_to_dict(event: SecurityEvent) -> dict:
    return {
        "id": event.id,
        "event_time": event.event_time,
        "event_type": event.event_type,
        "src_ip": str(event.src_ip) if event.src_ip else None,
        "dst_ip": str(event.dst_ip) if event.dst_ip else None,
        "src_port": event.src_port,
        "dst_port": event.dst_port,
        "host_id": event.host_id,
        "severity": event.severity,
        "attributes": event.attributes or {},
        "username": (event.attributes or {}).get("username"),
    }


_WINDOW_COLUMNS = (
    SecurityEvent.id,
    SecurityEvent.event_time,
    SecurityEvent.event_type,
    SecurityEvent.src_ip,
    SecurityEvent.dst_ip,
    SecurityEvent.src_port,
    SecurityEvent.dst_port,
    SecurityEvent.host_id,
    SecurityEvent.severity,
    SecurityEvent.attributes,
)


def window_row_to_dict(row: Any) -> dict:
    attributes = row.attributes or {}
    return {
        "id": row.id,
        "event_time": row.event_time,
        "event_type": row.event_type,
        "src_ip": str(row.src_ip) if row.src_ip else None,
        "dst_ip": str(row.dst_ip) if row.dst_ip else None,
        "src_port": row.src_port,
        "dst_port": row.dst_port,
        "host_id": row.host_id,
        "severity": row.severity,
        "attributes": attributes,
        "username": attributes.get("username"),
    }


def load_detection_window(db: Session, job_id: UUID, lookback: datetime) -> list[dict]:
    """Load the job's events plus the look-back window as plain dicts.

    Only the columns the detectors read are selected. Loading full ORM entities
    here kept every recent event, including its raw payload, in the session for
    each ingestion job and live batch, which dominated worker memory.
    """
    rows = db.execute(
        select(*_WINDOW_COLUMNS).where(
            or_(SecurityEvent.event_time >= lookback, SecurityEvent.ingestion_job_id == job_id)
        )
    )
    return [window_row_to_dict(row) for row in rows]


class EventIndex:
    """Events grouped by type, so each rule only walks the events it can match.

    Every rule evaluator requires `match.event_type`; a rule without one gets all events.
    The original order is kept, because it decides the order of evidence ids.
    """

    def __init__(self, events: list[dict]) -> None:
        self.events = events
        self._by_type: dict[str, list[tuple[int, dict]]] = {}
        for position, event in enumerate(events):
            self._by_type.setdefault(str(event.get("event_type")), []).append((position, event))

    def for_spec(self, spec: dict) -> list[dict]:
        wanted = (spec.get("match") or {}).get("event_type")
        if isinstance(wanted, str):
            return [event for _, event in self._by_type.get(wanted, [])]
        if isinstance(wanted, list | tuple | set) and wanted:
            chosen = [row for name in set(wanted) for row in self._by_type.get(name, [])]
            chosen.sort(key=lambda row: row[0])
            return [event for _, event in chosen]
        return self.events


def load_enabled_specs(db: Session) -> list[dict]:
    rules = db.scalars(select(DetectionRule).where(DetectionRule.enabled.is_(True))).all()
    specs = []
    by_id = {item["rule_id"]: item for item in BUILTIN_RULES}
    for rule in rules:
        version = next((v for v in rule.versions if v.version == rule.current_version), None)
        if version:
            spec = dict(version.spec)
            spec["rule_id"] = rule.rule_id
            spec["version"] = version.version
            spec["title"] = rule.title
            spec["severity"] = version.severity
            specs.append(spec)
        elif rule.rule_id in by_id:
            specs.append(by_id[rule.rule_id])
    return specs


def persist_finding(
    db: Session, finding: dict, detector_kind: str = "rule"
) -> tuple[Detection, bool] | None:
    incoming_evidence = dict(finding.get("evidence") or {})
    statement = (
        pg_insert(Detection)
        .values(
            fingerprint=finding["fingerprint"],
            detector_kind=detector_kind,
            rule_id=finding.get("rule_id"),
            rule_version=finding.get("rule_version"),
            model_version=finding.get("model_version"),
            title=finding["title"],
            severity=finding["severity"],
            summary=finding.get("summary") or "",
            evidence=incoming_evidence,
            mitre=finding.get("mitre") or [],
            score=finding.get("score"),
            score_kind=finding.get("score_kind"),
        )
        .on_conflict_do_nothing(
            index_elements=[Detection.organization_id, Detection.fingerprint]
        )
        .returning(Detection.id)
    )
    detection_id = db.scalar(statement)
    is_new = detection_id is not None
    if detection_id is None:
        detection_id = db.scalar(
            select(Detection.id)
            .where(Detection.fingerprint == finding["fingerprint"])
            .with_for_update()
        )
        if detection_id is None:
            return None
    detection = db.get(Detection, detection_id)
    if detection is None:
        return None

    incoming_ids = list(dict.fromkeys(str(value) for value in finding.get("event_ids") or []))
    existing_evidence = dict(detection.evidence or {})
    existing_ids = existing_evidence.get("event_ids") or []
    merged_ids = list(dict.fromkeys([*(str(value) for value in existing_ids), *incoming_ids]))
    merged_evidence = {**existing_evidence, **incoming_evidence, "event_ids": merged_ids[:500]}
    for metric in ("count", "failures", "successes", "unique_dst_ports"):
        values = [
            int(evidence[metric])
            for evidence in (existing_evidence, incoming_evidence)
            if evidence.get(metric) is not None
        ]
        if values:
            merged_evidence[metric] = max(values)
    detection.evidence = merged_evidence

    def evidence_size(evidence: dict) -> int:
        return max(
            int(evidence.get("count") or 0),
            int(evidence.get("failures") or 0) + int(evidence.get("successes") or 0),
            int(evidence.get("unique_dst_ports") or 0),
            len(evidence.get("event_ids") or []),
        )

    if not is_new:
        if evidence_size(incoming_evidence) >= evidence_size(existing_evidence):
            detection.summary = finding.get("summary") or detection.summary
            detection.severity = finding.get("severity") or detection.severity
        detection.mitre = finding.get("mitre") or detection.mitre

    event_ids = list(dict.fromkeys(UUID(value) for value in incoming_ids))
    if event_ids:
        db.execute(
            pg_insert(DetectionEvidence)
            .values(
                [
                    {
                        "detection_id": detection.id,
                        "event_id": event_id,
                        "note": "Matched rule window",
                    }
                    for event_id in event_ids
                ]
            )
            .on_conflict_do_nothing(
                index_elements=[
                    DetectionEvidence.organization_id,
                    DetectionEvidence.detection_id,
                    DetectionEvidence.event_id,
                ]
            )
        )
    return detection, is_new


def correlate_new(db: Session, detection: Detection) -> None:
    payload = {
        "rule_id": detection.rule_id,
        "evidence": detection.evidence,
        "created_at": detection.created_at or datetime.now(UTC),
        "entities": entity_keys_from_events(
            db.scalars(
                select(SecurityEvent)
                .join(DetectionEvidence, DetectionEvidence.event_id == SecurityEvent.id)
                .where(DetectionEvidence.detection_id == detection.id)
            ).all()
        ),
    }
    open_cases = db.scalars(
        select(Case)
        .options(
            selectinload(Case.detections)
            .selectinload(CaseDetection.detection)
            .selectinload(Detection.event_links)
            .selectinload(DetectionEvidence.event)
        )
        .where(Case.status.in_(("new", "investigating")))
    ).all()
    enqueue_detection_notifications(db, detection)
    for case in open_cases:
        if not case.detections:
            continue
        for link in case.detections:
            other = link.detection
            if other is None:
                continue
            other_entities = entity_keys_from_events(
                [evidence.event for evidence in other.event_links if evidence.event is not None]
            )
            ok, reason = should_group(
                payload,
                {
                    "rule_id": other.rule_id,
                    "evidence": other.evidence,
                    "created_at": other.created_at,
                    "entities": other_entities,
                },
            )
            if ok:
                db.add(CaseDetection(case_id=case.id, detection_id=detection.id))
                case.correlation_reason = reason
                case.updated_at = datetime.now(UTC)
                return
    case = Case(
        title=f"Investigation: {detection.title}",
        status="new",
        severity=detection.severity,
        correlation_reason=(
            "New case opened because no open case shared source IP, related family, "
            "and time window."
        ),
        correlation_evidence={"seed_detection": str(detection.id)},
    )
    db.add(case)
    db.flush()
    db.add(CaseDetection(case_id=case.id, detection_id=detection.id))


def run_detection_for_job(db: Session, job_id: UUID) -> int:
    has_events = db.scalar(
        select(SecurityEvent.id).where(SecurityEvent.ingestion_job_id == job_id).limit(1)
    )
    if has_events is None:
        return 0
    lookback = datetime.now(UTC) - timedelta(hours=2)
    as_dicts = load_detection_window(db, job_id, lookback)
    created = 0
    index = EventIndex(as_dicts)
    for spec in load_enabled_specs(db):
        candidates = index.for_spec(spec)
        if spec.get("rule_id") == "port_scan_like" or spec.get("unique_field") == "dst_port":
            findings = evaluate_unique_port_rule(spec, candidates)
        elif spec.get("rule_id") == "suspicious_login_pattern":
            findings = evaluate_login_pattern(spec, candidates)
        elif spec.get("distinct_field"):
            findings = evaluate_distinct_rule(spec, candidates)
        else:
            findings = evaluate_rule(spec, candidates)
        for finding in findings:
            persisted = persist_finding(db, finding)
            if persisted:
                detection, is_new = persisted
                if is_new:
                    correlate_new(db, detection)
                    created += 1
    for finding in score_events(as_dicts):
        persisted = persist_finding(db, finding, detector_kind="anomaly")
        if persisted:
            detection, is_new = persisted
            if is_new:
                correlate_new(db, detection)
                created += 1
    return created
