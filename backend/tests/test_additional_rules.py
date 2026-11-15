from datetime import UTC, datetime

from app.detection.builtin_rules import BUILTIN_RULES
from app.detection.engine import evaluate_rule

SPECS = {item["rule_id"]: item for item in BUILTIN_RULES}
WHEN = datetime(2026, 11, 14, 10, 0, tzinfo=UTC)


def _event(event_type: str, **attributes) -> dict:
    return {
        "id": "e-1",
        "event_time": WHEN,
        "event_type": event_type,
        "host_id": "host-1",
        "attributes": attributes,
    }


def test_rule_ids_are_unique() -> None:
    assert len(SPECS) == len(BUILTIN_RULES)


def test_cloudtrail_tampering_matches_successful_changes_only() -> None:
    spec = SPECS["aws_cloudtrail_logging_tampered"]
    base = {
        "account_id": "123456789012",
        "service": "cloudtrail.amazonaws.com",
        "action": "StopLogging",
        "cloud_status": "success",
    }
    assert len(evaluate_rule(spec, [_event("cloud.aws.cloudtrail", **base)])) == 1
    failed = {**base, "cloud_status": "failure"}
    assert evaluate_rule(spec, [_event("cloud.aws.cloudtrail", **failed)]) == []
    read_only = {**base, "action": "LookupEvents"}
    assert evaluate_rule(spec, [_event("cloud.aws.cloudtrail", **read_only)]) == []


def test_azure_logging_and_network_rules() -> None:
    for rule_id, action in (
        ("azure_diagnostic_logging_deleted", "Microsoft.Insights/diagnosticSettings/delete"),
        (
            "azure_network_security_rule_changed",
            "Microsoft.Network/networkSecurityGroups/securityRules/write",
        ),
    ):
        base = {"subscription_id": "sub-1", "action": action, "outcome": "success"}
        assert len(evaluate_rule(SPECS[rule_id], [_event("cloud.azure.activity", **base)])) == 1
        failed = {**base, "outcome": "failure"}
        assert evaluate_rule(SPECS[rule_id], [_event("cloud.azure.activity", **failed)]) == []


def test_office_family_rules_match_their_own_parent_only() -> None:
    for parent in ("excel", "outlook", "powerpnt"):
        spec = SPECS[f"{parent}_spawns_powershell"]
        attributes = {
            "source_name": "windows.security",
            "process_name": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "parent_process_name": rf"C:\Program Files\Microsoft Office\root\Office16\{parent}.exe",
        }
        assert len(evaluate_rule(spec, [_event("process.start", **attributes)])) == 1
        other = {**attributes, "parent_process_name": r"C:\Windows\explorer.exe"}
        assert evaluate_rule(spec, [_event("process.start", **other)]) == []


def test_every_declared_attack_mapping_is_well_formed_and_hedged() -> None:
    import re

    from app.detection.builtin_rules import BUILTIN_RULES

    declared = [(spec["rule_id"], item) for spec in BUILTIN_RULES for item in spec.get("mitre", [])]
    assert len(declared) >= 10
    for rule_id, item in declared:
        assert re.fullmatch(r"T\d{4}(\.\d{3})?", item["technique_id"]), rule_id
        assert item["tactic"] and len(item["justification"]) > 30, rule_id



def test_a_rule_with_a_new_mapping_has_a_higher_version_so_existing_installs_receive_it() -> None:
    from app.detection.builtin_rules import BUILTIN_RULES

    for spec in BUILTIN_RULES:
        if spec["rule_id"] == "windows_security_log_cleared":
            assert spec["version"] >= 2 and spec["mitre"]
