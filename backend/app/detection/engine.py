from __future__ import annotations

import hashlib
from collections import defaultdict
from datetime import UTC, datetime
from typing import Any


def _first(*values: Any) -> Any:
    for value in values:
        if value not in (None, ""):
            return value
    return None


def _field(event: dict[str, Any], path: str) -> Any:
    if path.startswith("attributes."):
        return (event.get("attributes") or {}).get(path.split(".", 1)[1])
    return event.get(path)


def matches(event: dict[str, Any], match: dict[str, Any]) -> bool:
    for key, expected in match.items():
        actual = _field(event, key)
        if isinstance(expected, dict):
            op = expected.get("op", "eq")
            value = expected.get("value")
            text = "" if actual is None else str(actual)
            if op == "eq" and actual != value:
                return False
            if op == "contains" and str(value).lower() not in text.lower():
                return False
            if op == "startswith" and not text.lower().startswith(str(value).lower()):
                return False
            if op == "endswith" and not text.lower().endswith(str(value).lower()):
                return False
            if op == "in":
                if not isinstance(value, list | tuple | set) or actual not in value:
                    return False
            continue
        if isinstance(expected, list):
            if actual not in expected:
                return False
            continue
        if actual != expected:
            return False
    return True


def _window_start(event_time: datetime, window_seconds: int) -> datetime:
    epoch = int(event_time.astimezone(UTC).timestamp())
    aligned = epoch - (epoch % window_seconds)
    return datetime.fromtimestamp(aligned, tz=UTC)


def fingerprint(rule_id: str, version: int, group_key: str, window_start: datetime) -> str:
    raw = f"{rule_id}|{version}|{group_key}|{window_start.isoformat()}"
    return hashlib.sha256(raw.encode()).hexdigest()


def evaluate_rule(spec: dict[str, Any], events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Evaluate a count-over-window rule. Unsupported Sigma: pipelines, wildcards, lookups."""
    match = spec.get("match") or {}
    window = int(spec.get("window_seconds") or 300)
    threshold = int(spec.get("threshold") or 5)
    group_by = spec.get("group_by") or ["src_ip"]
    matched = [event for event in events if matches(event, match)]
    buckets: dict[tuple[Any, ...], list[dict[str, Any]]] = defaultdict(list)
    for event in matched:
        et = event["event_time"]
        if isinstance(et, str):
            et = datetime.fromisoformat(et.replace("Z", "+00:00"))
        ws = _window_start(et, window)
        key = tuple(
            _first(event.get(field), (event.get("attributes") or {}).get(field))
            for field in group_by
        )
        if any(part in (None, "") for part in key):
            continue
        buckets[(ws, key)].append(event)

    findings: list[dict[str, Any]] = []
    for (ws, key), group_events in buckets.items():
        if len(group_events) < threshold:
            continue
        group_key = ",".join(f"{field}={value}" for field, value in zip(group_by, key, strict=True))
        evidence_ids = [str(event["id"]) for event in group_events if event.get("id")]
        source_ips = {event.get("src_ip") for event in group_events if event.get("src_ip")}
        findings.append(
            {
                "rule_id": spec["rule_id"],
                "rule_version": spec.get("version", 1),
                "title": spec["title"],
                "severity": spec["severity"],
                "summary": (
                    f"{len(group_events)} matching events for {group_key} "
                    f"in a {window}s window starting {ws.isoformat()} "
                    f"(threshold {threshold}). Synthetic or lab telemetry only unless "
                    "labeled otherwise."
                ),
                "fingerprint": fingerprint(spec["rule_id"], spec.get("version", 1), group_key, ws),
                "evidence": {
                    "group_by": group_by,
                    "group_key": group_key,
                    "src_ip": next(iter(source_ips)) if len(source_ips) == 1 else None,
                    "window_seconds": window,
                    "window_start": ws.isoformat(),
                    "count": len(group_events),
                    "threshold": threshold,
                    "event_ids": evidence_ids[:50],
                    "sample_types": sorted(
                        {
                            value
                            for event in group_events
                            if isinstance((value := event.get("event_type")), str)
                        }
                    )[:10],
                },
                "mitre": spec.get("mitre") or [],
                "event_ids": evidence_ids,
            }
        )
    return findings
