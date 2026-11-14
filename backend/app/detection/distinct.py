"""Rules that count distinct values, such as many different user names tried from one address."""

from collections import defaultdict
from datetime import UTC, datetime
from typing import Any

from app.detection.engine import _window_start, fingerprint, matches


def evaluate_distinct_rule(
    spec: dict[str, Any], events: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Report groups with at least `threshold` distinct values of `distinct_field` in a window.

    The group is the first entry of `group_by` (default `src_ip`). Events without a group or
    without a value for the field are skipped.
    """
    field = spec["distinct_field"]
    group_field = (spec.get("group_by") or ["src_ip"])[0]
    window = int(spec.get("window_seconds") or 600)
    threshold = int(spec.get("threshold") or 5)
    values: dict[tuple, set[str]] = defaultdict(set)
    samples: dict[tuple, list[str]] = defaultdict(list)
    for event in events:
        if not matches(event, spec.get("match") or {}):
            continue
        group = event.get(group_field)
        value = event.get(field) or (event.get("attributes") or {}).get(field)
        if not group or not value:
            continue
        when = event["event_time"]
        if isinstance(when, str):
            when = datetime.fromisoformat(when.replace("Z", "+00:00"))
        key = (_window_start(when, window), group)
        values[key].add(str(value))
        if event.get("id") and len(samples[key]) < 50:
            samples[key].append(str(event["id"]))
    findings = []
    for key, distinct in values.items():
        window_start, group = key
        if len(distinct) < threshold:
            continue
        group_key = f"{group_field}={group}"
        findings.append(
            {
                "rule_id": spec["rule_id"],
                "rule_version": spec.get("version", 1),
                "title": spec["title"],
                "severity": spec["severity"],
                "summary": (
                    f"{len(distinct)} distinct {field} values from {group} in {window}s "
                    f"starting {window_start.astimezone(UTC).isoformat()} "
                    f"(threshold {threshold})."
                ),
                "fingerprint": fingerprint(
                    spec["rule_id"], spec.get("version", 1), group_key, window_start
                ),
                "evidence": {
                    "count": len(distinct),
                    "distinct_field": field,
                    "threshold": threshold,
                    group_field: group,
                    "window_start": window_start.isoformat(),
                    "event_ids": samples[key],
                },
                "mitre": spec.get("mitre") or [],
                "event_ids": samples[key],
            }
        )
    return findings
