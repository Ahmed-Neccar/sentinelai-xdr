from datetime import UTC, datetime, timedelta

from app.correlation.service import entity_keys_from_events, should_group
from app.detection.builtin_rules import BUILTIN_RULES
from app.detection.engine import evaluate_rule


def rule(rule_id: str) -> dict:
    return next(spec for spec in BUILTIN_RULES if spec["rule_id"] == rule_id)


def event(event_type: str, **fields: object) -> dict:
    return {
        "id": f"event-{event_type}",
        "event_time": datetime.now(UTC),
        "event_type": event_type,
        "src_ip": None,
        "host_id": "lab-host",
        "attributes": {},
        **fields,
    }


def test_remote_desktop_rule_matches_even_when_windows_omits_source_ip() -> None:
    record = event(
        "auth.success",
        attributes={"source_name": "windows.security", "logon_type": "10"},
    )
    findings = evaluate_rule(rule("windows_remote_interactive_logon"), [record])
    assert len(findings) == 1
    assert findings[0]["evidence"]["group_key"] == "host_id=lab-host"


def test_remote_desktop_rule_ignores_ordinary_local_logon() -> None:
    record = event(
        "auth.success",
        attributes={"source_name": "windows.security", "logon_type": "2"},
    )
    assert evaluate_rule(rule("windows_remote_interactive_logon"), [record]) == []


def test_word_starting_powershell_matches_and_other_parent_does_not() -> None:
    spec = rule("office_spawns_powershell")
    matched = event(
        "process.start",
        attributes={
            "source_name": "windows.security",
            "process_name": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "parent_process_name": r"C:\Program Files\Microsoft Office\root\WINWORD.EXE",
        },
    )
    benign = event(
        "process.start",
        attributes={
            **matched["attributes"],
            "parent_process_name": r"C:\Windows\explorer.exe",
        },
    )
    assert len(evaluate_rule(spec, [matched])) == 1
    assert evaluate_rule(spec, [benign]) == []


def test_windows_account_and_privileged_group_findings_match_endpoint_telemetry() -> None:
    account = event(
        "endpoint.identity.account_created",
        attributes={"source_name": "windows.security", "target_username": "new-user"},
    )
    group = event(
        "endpoint.identity.group_member_added",
        attributes={
            "source_name": "windows.security",
            "group_name": "Administrators",
            "member_name": "S-1-5-21-1234",
        },
    )

    assert len(evaluate_rule(rule("windows_account_created"), [account])) == 1
    assert len(evaluate_rule(rule("windows_security_group_member_added"), [group])) == 1


def test_windows_task_change_rules_distinguish_create_update_and_delete() -> None:
    changed = event(
        "endpoint.persistence.scheduled_task_changed",
        attributes={"source_name": "windows.security", "task_name": r"\LabTask"},
    )
    deleted = event(
        "endpoint.persistence.scheduled_task_deleted",
        attributes={"source_name": "windows.security", "task_name": r"\LabTask"},
    )

    assert len(evaluate_rule(rule("windows_scheduled_task_changed"), [changed])) == 1
    assert len(evaluate_rule(rule("windows_scheduled_task_deleted"), [deleted])) == 1


def test_credential_and_discovery_detections_group_only_with_shared_ip_and_time() -> None:
    now = datetime.now(UTC)
    credential = {
        "rule_id": "auth_bruteforce",
        "evidence": {"src_ip": "192.0.2.10"},
        "created_at": now,
    }
    discovery = {
        "rule_id": "port_scan_like",
        "evidence": {"src_ip": "192.0.2.10"},
        "created_at": now + timedelta(minutes=1),
    }
    assert should_group(credential, discovery)[0] is True
    assert (
        should_group(
            credential,
            {**discovery, "evidence": {"src_ip": "192.0.2.11"}},
        )[0]
        is False
    )
    assert (
        should_group(
            credential,
            {**discovery, "created_at": now + timedelta(minutes=31)},
        )[0]
        is False
    )


def test_high_risk_identity_and_network_discovery_group_only_with_shared_source_and_time() -> None:
    now = datetime.now(UTC)
    identity = {
        "rule_id": "entra_high_risk_signin",
        "evidence": {"src_ip": "192.0.2.30"},
        "created_at": now,
    }
    discovery = {
        "rule_id": "port_scan_like",
        "evidence": {"src_ip": "192.0.2.30"},
        "created_at": now + timedelta(minutes=2),
    }
    assert should_group(identity, discovery)[0] is True
    assert should_group(identity, {**discovery, "evidence": {"src_ip": "192.0.2.31"}})[0] is False


def test_identity_and_endpoint_findings_group_by_shared_host_without_exposing_identifier() -> None:
    from types import SimpleNamespace

    now = datetime.now(UTC)
    entities = entity_keys_from_events(
        [
            SimpleNamespace(
                attributes={"username": "analyst@example.invalid", "tenant_id": "tenant-a"},
                host_id="workstation-17",
            )
        ]
    )
    identity = {
        "rule_id": "entra_high_risk_signin",
        "evidence": {},
        "entities": entities,
        "created_at": now,
    }
    endpoint = {
        "rule_id": "windows_service_installed",
        "evidence": {},
        "entities": entities,
        "created_at": now + timedelta(minutes=2),
    }
    grouped, reason = should_group(identity, endpoint)
    assert grouped is True
    assert "shared host entity" in reason
    assert "workstation-17" not in reason


def test_entity_correlation_rejects_unrelated_family_or_cross_tenant_host() -> None:
    from types import SimpleNamespace

    now = datetime.now(UTC)
    tenant_a = entity_keys_from_events(
        [SimpleNamespace(attributes={"tenant_id": "tenant-a"}, host_id="same-name")]
    )
    tenant_b = entity_keys_from_events(
        [SimpleNamespace(attributes={"tenant_id": "tenant-b"}, host_id="same-name")]
    )
    identity = {
        "rule_id": "entra_high_risk_signin",
        "evidence": {},
        "entities": tenant_a,
        "created_at": now,
    }
    assert (
        should_group(
            identity,
            {
                "rule_id": "unusual_conn_volume",
                "evidence": {},
                "entities": tenant_b,
                "created_at": now + timedelta(minutes=1),
            },
        )[0]
        is False
    )
    assert (
        should_group(
            identity,
            {
                "rule_id": "repeat_high_severity",
                "evidence": {},
                "entities": tenant_a,
                "created_at": now + timedelta(minutes=1),
            },
        )[0]
        is False
    )


def test_correlation_does_not_group_when_timestamp_is_missing_or_invalid() -> None:
    evidence = {"src_ip": "192.0.2.44"}
    assert (
        should_group(
            {"rule_id": "auth_bruteforce", "evidence": evidence},
            {
                "rule_id": "auth_bruteforce_username",
                "evidence": evidence,
                "created_at": datetime.now(UTC),
            },
        )[0]
        is False
    )
    assert (
        should_group(
            {
                "rule_id": "auth_bruteforce",
                "evidence": evidence,
                "created_at": "not-a-timestamp",
            },
            {
                "rule_id": "auth_bruteforce_username",
                "evidence": evidence,
                "created_at": datetime.now(UTC),
            },
        )[0]
        is False
    )
