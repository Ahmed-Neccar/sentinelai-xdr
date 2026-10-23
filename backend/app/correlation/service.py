from collections.abc import Iterable
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from typing import Any

RELATED_FAMILIES = {
    "windows_remote_interactive_logon": "credential",
    "entra_high_risk_signin": "credential",
    "aws_iam_credential_or_policy_change": "credential",
    "azure_role_assignment_change": "credential",
    "auth_bruteforce": "credential",
    "auth_bruteforce_username": "credential",
    "suspicious_login_pattern": "credential",
    "port_scan_like": "discovery",
    "unusual_conn_volume": "discovery",
    "office_spawns_powershell": "execution",
    "windows_service_installed": "persistence",
    "windows_scheduled_task_created": "persistence",
    "windows_audit_policy_changed": "security_control",
    "windows_security_log_cleared": "security_control",
    "repeat_high_severity": "severity",
    "suspicious_traffic_dns": "dns",
}

WINDOW = timedelta(minutes=30)
CROSS_TACTIC_PAIRS = {
    frozenset(("credential", "discovery")),
    frozenset(("credential", "execution")),
    frozenset(("credential", "persistence")),
    frozenset(("credential", "security_control")),
}


def _family(rule_id: str | None) -> str:
    return RELATED_FAMILIES.get(rule_id or "", "other")


def _src(detection: dict[str, Any]) -> str | None:
    evidence = detection.get("evidence") or {}
    if evidence.get("src_ip"):
        return evidence["src_ip"]
    group_key = evidence.get("group_key") or ""
    for part in group_key.split(","):
        if part.startswith("src_ip="):
            return part.split("=", 1)[1]
    return None


def entity_keys_from_events(events: Iterable[Any]) -> set[str]:
    """Return scoped hashes for stable entities without exposing raw identifiers."""
    entities: set[str] = set()
    for event in events:
        attrs = event.attributes or {}
        tenant = str(
            attrs.get("tenant_id")
            or attrs.get("subscription_id")
            or attrs.get("account_id")
            or "local"
        ).strip().casefold()
        candidates = [
            ("host", tenant, event.host_id),
            ("device", tenant, attrs.get("device_id")),
            ("account", tenant, attrs.get("account_id")),
            ("resource", tenant, attrs.get("resource_id")),
        ]
        username = attrs.get("username")
        if isinstance(username, str) and username.strip():
            normalized_username = username.strip().casefold()
            scope = "upn" if "@" in normalized_username else tenant
            candidates.append(("user", scope, normalized_username))
        for kind, scope, raw_value in candidates:
            if not isinstance(raw_value, str) or not raw_value.strip():
                continue
            material = f"{kind}\x1f{scope}\x1f{raw_value.strip().casefold()}".encode()
            entities.add(f"{kind}:{sha256(material).hexdigest()}")
    return entities


def _shared_entity(a: dict[str, Any], b: dict[str, Any]) -> str | None:
    shared = set(a.get("entities") or []) & set(b.get("entities") or [])
    return sorted(shared)[0] if shared else None


def should_group(a: dict[str, Any], b: dict[str, Any]) -> tuple[bool, str]:
    """Group only related detections sharing a source IP or a stable scoped entity."""
    src_a, src_b = _src(a), _src(b)
    shared_ip = bool(src_a and src_a == src_b)
    entity = _shared_entity(a, b)
    if not shared_ip and not entity:
        return False, "different_or_missing_source"
    fam_a, fam_b = _family(a.get("rule_id")), _family(b.get("rule_id"))
    same_family = fam_a == fam_b and fam_a != "other"
    cross_tactic = frozenset((fam_a, fam_b)) in CROSS_TACTIC_PAIRS
    if not same_family and not cross_tactic:
        return False, "unrelated_detection_families"
    ta = a.get("created_at")
    tb = b.get("created_at")
    try:
        if isinstance(ta, str):
            ta = datetime.fromisoformat(ta.replace("Z", "+00:00"))
        if isinstance(tb, str):
            tb = datetime.fromisoformat(tb.replace("Z", "+00:00"))
    except ValueError:
        return False, "invalid_timestamp"
    if ta is None or tb is None:
        return False, "missing_timestamp"
    if not isinstance(ta, datetime) or not isinstance(tb, datetime):
        return False, "invalid_timestamp"
    if ta.tzinfo is None:
        ta = ta.replace(tzinfo=UTC)
    if tb.tzinfo is None:
        tb = tb.replace(tzinfo=UTC)
    if abs(ta - tb) > WINDOW:
        return False, "outside_time_window"
    entity_kind = entity.split(":", 1)[0] if entity else "entity"
    relationship = "source IP" if shared_ip else f"shared {entity_kind} entity"
    if cross_tactic:
        reason = (
            f"Grouped related '{fam_a}' and '{fam_b}' findings because they share a {relationship} "
            f"and timestamps are within {int(WINDOW.total_seconds())}s."
        )
    else:
        reason = (
            f"Grouped because a {relationship} is shared, detection family is '{fam_a}', "
            f"and timestamps are within {int(WINDOW.total_seconds())}s."
        )
    return True, reason
