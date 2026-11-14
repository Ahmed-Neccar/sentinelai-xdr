"""Run one rule against a list of events with the evaluator its type needs.

Kept free of database imports so that the ingestion pipeline and the offline evaluation
(`research/`) apply exactly the same logic.
"""

from typing import Any

from app.detection.distinct import evaluate_distinct_rule
from app.detection.engine import evaluate_rule
from app.detection.login_pattern import evaluate_login_pattern
from app.detection.port_scan import evaluate_unique_port_rule


def evaluate_spec(spec: dict[str, Any], events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if spec.get("rule_id") == "port_scan_like" or spec.get("unique_field") == "dst_port":
        return evaluate_unique_port_rule(spec, events)
    if spec.get("rule_id") == "suspicious_login_pattern":
        return evaluate_login_pattern(spec, events)
    if spec.get("distinct_field"):
        return evaluate_distinct_rule(spec, events)
    return evaluate_rule(spec, events)


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
