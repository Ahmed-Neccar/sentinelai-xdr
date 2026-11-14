from datetime import UTC, datetime, timedelta

from app.detection.builtin_rules import BUILTIN_RULES
from app.detection.distinct import evaluate_distinct_rule

SPEC = next(item for item in BUILTIN_RULES if item["rule_id"] == "password_spray")
START = datetime(2026, 11, 14, 10, 0, tzinfo=UTC)


def _failure(user: str | None, seconds: int, src: str | None = "203.0.113.7", **extra) -> dict:
    return {
        "id": f"f-{user}-{seconds}-{src}",
        "event_time": START + timedelta(seconds=seconds),
        "event_type": "auth.failure",
        "src_ip": src,
        "username": user,
        **extra,
    }


def test_many_accounts_from_one_address_is_reported_with_evidence() -> None:
    events = [_failure(f"user{i}", i * 10) for i in range(6)]
    [finding] = evaluate_distinct_rule(SPEC, events)
    assert finding["severity"] == "high"
    assert finding["evidence"]["count"] == 6 and finding["evidence"]["src_ip"] == "203.0.113.7"
    assert len(finding["event_ids"]) == 6
    assert finding["mitre"][0]["technique_id"] == "T1110.003"
    assert "6 distinct username values" in finding["summary"]


def test_one_account_guessed_many_times_is_not_a_spray() -> None:
    events = [_failure("admin", i) for i in range(50)]
    assert evaluate_distinct_rule(SPEC, events) == []


def test_below_the_threshold_other_sources_and_other_events_do_not_count() -> None:
    five = [_failure(f"user{i}", i) for i in range(5)]
    assert evaluate_distinct_rule(SPEC, five) == []
    split = [_failure(f"user{i}", i, src=f"203.0.113.{i}") for i in range(10)]
    assert evaluate_distinct_rule(SPEC, split) == []
    successes = [{**_failure(f"user{i}", i), "event_type": "auth.success"} for i in range(10)]
    assert evaluate_distinct_rule(SPEC, successes) == []


def test_missing_fields_the_window_and_attribute_usernames() -> None:
    missing = [_failure(None, i) for i in range(10)] + [_failure("u", 5, src=None)]
    assert evaluate_distinct_rule(SPEC, missing) == []
    # Six accounts spread over more than one window never reach six in a single one.
    spread = [_failure(f"user{i}", i * 400) for i in range(6)]
    assert evaluate_distinct_rule(SPEC, spread) == []
    # The user name may be carried in the attributes instead of the top-level field.
    nested = [{**_failure(None, i), "attributes": {"username": f"user{i}"}} for i in range(6)]
    assert len(evaluate_distinct_rule(SPEC, nested)) == 1


def test_repeated_evaluation_gives_the_same_fingerprint() -> None:
    events = [_failure(f"user{i}", i) for i in range(8)]
    first = evaluate_distinct_rule(SPEC, events)
    second = evaluate_distinct_rule(SPEC, list(reversed(events)))
    assert first[0]["fingerprint"] == second[0]["fingerprint"]


def test_a_spray_in_an_uploaded_file_becomes_a_finding_and_a_case(
    tenant, tmp_path, monkeypatch
) -> None:
    import json

    from app.core.bootstrap import seed_rules
    from app.core.config import settings

    monkeypatch.setattr(settings, "upload_dir", str(tmp_path))
    with tenant.session() as db:
        seed_rules(db)
        db.commit()
    now = datetime.now(UTC)
    rows = [
        {
            "event_time": (now - timedelta(seconds=i)).isoformat(),
            "event_type": "auth.failure",
            "src_ip": "203.0.113.50",
            "username": f"person{i}",
            "host_id": "vpn-gateway",
        }
        for i in range(8)
    ]
    upload = tenant.client.post(
        "/api/v1/ingest/upload",
        headers=tenant.headers["analyst"],
        files={"file": ("spray.json", json.dumps(rows), "application/json")},
    )
    assert upload.status_code == 202, upload.text
    found = tenant.client.get(
        "/api/v1/detections?rule_id=password_spray", headers=tenant.headers["analyst"]
    ).json()
    assert found["total"] == 1, found
    assert found["items"][0]["severity"] == "high"
    cases = tenant.client.get("/api/v1/cases", headers=tenant.headers["analyst"]).json()
    assert any("Password spraying" in case["title"] for case in cases["items"])
