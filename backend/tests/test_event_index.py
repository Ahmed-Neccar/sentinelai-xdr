import random
from datetime import UTC, datetime, timedelta

from app.detection.builtin_rules import BUILTIN_RULES
from app.detection.engine import evaluate_rule
from app.detection.run import EventIndex


def _events(count: int) -> list[dict]:
    rng = random.Random(3)  # noqa: S311 - seeded test data
    start = datetime(2026, 11, 14, 10, 0, tzinfo=UTC)
    types = ["auth.failure", "auth.success", "net.conn", "zeek.conn", "dns.query", "other"]
    return [
        {
            "id": f"e{i}",
            "event_time": start + timedelta(seconds=rng.randint(0, 600)),
            "event_type": rng.choice(types),
            "src_ip": f"10.0.0.{rng.randint(1, 5)}",
            "host_id": f"h{rng.randint(1, 3)}",
            "username": f"u{rng.randint(1, 3)}",
            "severity": rng.choice(["low", "high"]),
            "attributes": {},
        }
        for i in range(count)
    ]


def test_prefiltering_by_event_type_gives_the_same_findings_as_scanning_everything() -> None:
    events = _events(3000)
    index = EventIndex(events)
    for spec in BUILTIN_RULES:
        full = evaluate_rule(spec, events)
        narrowed = evaluate_rule(spec, index.for_spec(spec))
        assert narrowed == full, spec["rule_id"]


def test_list_types_keep_the_original_order_and_rules_without_a_type_see_everything() -> None:
    events = _events(200)
    index = EventIndex(events)
    both = index.for_spec({"match": {"event_type": ["net.conn", "auth.failure"]}})
    assert both == [e for e in events if e["event_type"] in ("net.conn", "auth.failure")]
    assert index.for_spec({"match": {"severity": ["high"]}}) is events
    assert index.for_spec({"match": {"event_type": "missing.type"}}) == []
