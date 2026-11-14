from datetime import UTC, datetime, timedelta

from app.detection.builtin_rules import BUILTIN_RULES
from app.detection.login_pattern import evaluate_login_pattern
from app.detection.port_scan import evaluate_unique_port_rule

SPECS = {item["rule_id"]: item for item in BUILTIN_RULES}
START = datetime(2026, 11, 14, 10, 0, tzinfo=UTC)


def _auth(kind: str, seconds: int, src: str = "10.0.0.7", ident: str | None = None) -> dict:
    return {
        "id": ident or f"{kind}-{seconds}-{src}",
        "event_time": START + timedelta(seconds=seconds),
        "event_type": kind,
        "src_ip": src,
    }


def test_failures_then_success_is_reported_with_evidence() -> None:
    events = [_auth("auth.failure", s) for s in (0, 10, 20)] + [_auth("auth.success", 30)]
    findings = evaluate_login_pattern(SPECS["suspicious_login_pattern"], events)
    assert len(findings) == 1
    evidence = findings[0]["evidence"]
    assert evidence["failures"] == 3 and evidence["successes"] == 1
    assert evidence["src_ip"] == "10.0.0.7" and len(findings[0]["event_ids"]) == 4


def test_a_success_before_the_failures_does_not_count() -> None:
    events = [_auth("auth.success", 0)] + [_auth("auth.failure", s) for s in (10, 20, 30)]
    assert evaluate_login_pattern(SPECS["suspicious_login_pattern"], events) == []


def test_too_few_failures_or_no_success_or_other_sources_do_not_match() -> None:
    spec = SPECS["suspicious_login_pattern"]
    two = [_auth("auth.failure", 0), _auth("auth.failure", 5), _auth("auth.success", 9)]
    assert evaluate_login_pattern(spec, two) == []
    only_failures = [_auth("auth.failure", s) for s in (0, 5, 9, 12)]
    assert evaluate_login_pattern(spec, only_failures) == []
    split = [_auth("auth.failure", s, src=f"10.0.0.{s}") for s in (0, 5, 9)]
    assert evaluate_login_pattern(spec, split + [_auth("auth.success", 20)]) == []


def test_string_timestamps_and_the_window_boundary() -> None:
    spec = SPECS["suspicious_login_pattern"]
    events = [_auth("auth.failure", s) for s in (0, 1, 2)] + [_auth("auth.success", 3)]
    for event in events:
        event["event_time"] = event["event_time"].isoformat().replace("+00:00", "Z")
    assert len(evaluate_login_pattern(spec, events)) == 1
    apart = [_auth("auth.failure", s) for s in (0, 1, 2)] + [_auth("auth.success", 900)]
    assert evaluate_login_pattern(spec, apart) == []


def _conn(port: int | None, seconds: int = 0, src: str | None = "10.0.0.9") -> dict:
    return {
        "id": f"c-{port}-{seconds}",
        "event_time": START + timedelta(seconds=seconds),
        "event_type": "net.conn",
        "src_ip": src,
        "dst_port": port,
    }


def test_many_distinct_ports_from_one_source_is_a_port_scan() -> None:
    spec = SPECS["port_scan_like"]
    events = [_conn(1000 + i, i) for i in range(12)]
    findings = evaluate_unique_port_rule(spec, events)
    assert len(findings) == 1
    assert findings[0]["evidence"]["unique_dst_ports"] == 12
    assert "10.0.0.9" in findings[0]["summary"]


def test_repeated_ports_missing_fields_and_other_types_are_ignored() -> None:
    spec = SPECS["port_scan_like"]
    same_port = [_conn(443, i) for i in range(40)]
    assert evaluate_unique_port_rule(spec, same_port) == []
    eleven = [_conn(1000 + i, i) for i in range(11)]
    assert evaluate_unique_port_rule(spec, eleven) == []
    noisy = eleven + [_conn(None, 20), _conn(2000, 21, src=None)]
    assert evaluate_unique_port_rule(spec, noisy) == []
    other = [{**_conn(1000 + i, i), "event_type": "dns.query"} for i in range(20)]
    assert evaluate_unique_port_rule(spec, other) == []
    assert evaluate_unique_port_rule({**spec, "match": {"event_type": "net.conn"}}, eleven) == []


def test_sample_ids_are_capped_and_the_fingerprint_is_stable() -> None:
    spec = SPECS["port_scan_like"]
    events = [_conn(1000 + i, i % 100) for i in range(80)]
    first = evaluate_unique_port_rule(spec, events)
    second = evaluate_unique_port_rule(spec, list(reversed(events)))
    assert first and len(first[0]["event_ids"]) <= 50
    assert first[0]["fingerprint"] == second[0]["fingerprint"]
