from collections import defaultdict
from datetime import datetime
from typing import Any

from app.detection.engine import _window_start, fingerprint, matches


def _when(event: dict[str, Any]) -> datetime:
    value = event["event_time"]
    if isinstance(value, str):
        value = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return value


def evaluate_login_pattern(
    spec: dict[str, Any], events: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    window = int(spec.get("window_seconds") or 600)
    buckets: dict[tuple, list[dict[str, Any]]] = defaultdict(list)
    for event in events:
        if not matches(event, spec.get("match") or {}):
            continue
        src = event.get("src_ip")
        if not src:
            continue
        et = event["event_time"]
        if isinstance(et, str):
            et = datetime.fromisoformat(et.replace("Z", "+00:00"))
        ws = _window_start(et, window)
        buckets[(ws, src)].append(event)
    findings = []
    for (ws, src), group in buckets.items():
        failures = [e for e in group if e.get("event_type") == "auth.failure"]
        successes = [e for e in group if e.get("event_type") == "auth.success"]
        if len(failures) < 3 or not successes:
            continue
        # "Failures then success": a success counts only if it comes at or after the third
        # failure. A success followed by failures is an ordinary mistyped later attempt.
        third_failure = sorted(_when(e) for e in failures)[2]
        successes = [e for e in successes if _when(e) >= third_failure]
        if not successes:
            continue
        ids = [str(e["id"]) for e in group if e.get("id")]
        group_key = f"src_ip={src}"
        findings.append(
            {
                "rule_id": spec["rule_id"],
                "rule_version": spec.get("version", 1),
                "title": spec["title"],
                "severity": spec["severity"],
                "summary": (
                    f"{len(failures)} failures and {len(successes)} success(es) from {src} "
                    f"in window starting {ws.isoformat()}."
                ),
                "fingerprint": fingerprint(spec["rule_id"], spec.get("version", 1), group_key, ws),
                "evidence": {
                    "failures": len(failures),
                    "successes": len(successes),
                    "src_ip": src,
                    "event_ids": ids[:50],
                },
                "mitre": spec.get("mitre") or [],
                "event_ids": ids,
            }
        )
    return findings
