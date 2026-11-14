from datetime import UTC, datetime, timedelta

from app.core.bootstrap import seed_rules
from app.detection.builtin_rules import BUILTIN_RULES
from app.detection.evaluate import evaluate_spec
from app.models import DetectionRule
from sqlalchemy import select

SPECS = {item["rule_id"]: item for item in BUILTIN_RULES}
SLOW = ("auth_bruteforce_username_slow", "password_spray_slow", "port_scan_slow")
START = datetime(2026, 11, 14, 10, 0, tzinfo=UTC)


def _event(kind: str, seconds: int, **fields) -> dict:
    return {
        "id": f"e{seconds}-{len(fields)}-{fields.get('username')}-{fields.get('dst_port')}",
        "event_time": START + timedelta(seconds=seconds),
        "event_type": kind,
        "src_ip": "203.0.113.9",
        "attributes": {},
        **fields,
    }


def test_slow_rules_are_defined_and_marked_off_by_default() -> None:
    assert len(SPECS) == len(BUILTIN_RULES)
    for rule_id in SLOW:
        assert SPECS[rule_id]["default_enabled"] is False
        assert "Experimental" in SPECS[rule_id]["description"]
    assert all(
        spec.get("default_enabled", True) for rule_id, spec in SPECS.items() if rule_id not in SLOW
    )


def test_a_slow_brute_force_is_seen_by_the_hour_rule_but_not_the_burst_rule() -> None:
    events = [
        _event("auth.failure", i * 300, username="ann") for i in range(12)
    ]  # one per five minutes
    assert evaluate_spec(SPECS["auth_bruteforce_username"], events) == []
    assert len(evaluate_spec(SPECS["auth_bruteforce_username_slow"], events)) == 1


def test_a_slow_spray_and_a_slow_scan_are_seen_by_the_hour_rules_only() -> None:
    spray = [_event("auth.failure", i * 240, username=f"user{i}") for i in range(12)]
    assert evaluate_spec(SPECS["password_spray"], spray) == []
    assert len(evaluate_spec(SPECS["password_spray_slow"], spray)) == 1
    scan = [_event("net.conn", i * 60, dst_port=1000 + i) for i in range(50)]
    assert evaluate_spec(SPECS["port_scan_like"], scan) == []
    assert len(evaluate_spec(SPECS["port_scan_slow"], scan)) == 1


def test_ordinary_activity_does_not_trip_the_slow_rules() -> None:
    one_user = [_event("auth.failure", i * 900, username="ann") for i in range(4)]
    assert evaluate_spec(SPECS["auth_bruteforce_username_slow"], one_user) == []
    few_users = [_event("auth.failure", i * 600, username=f"user{i}") for i in range(5)]
    assert evaluate_spec(SPECS["password_spray_slow"], few_users) == []
    few_ports = [_event("net.conn", i * 30, dst_port=443 + i % 3) for i in range(100)]
    assert evaluate_spec(SPECS["port_scan_slow"], few_ports) == []


def test_seeding_creates_the_slow_rules_disabled(tenant) -> None:
    with tenant.session() as db:
        seed_rules(db)
        db.commit()
        state = {rule.rule_id: rule.enabled for rule in db.scalars(select(DetectionRule))}
    for rule_id in SLOW:
        assert state[rule_id] is False
    assert state["auth_bruteforce"] is True and state["password_spray"] is True
