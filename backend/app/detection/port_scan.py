from collections import defaultdict
from datetime import UTC, datetime
from typing import Any

from app.detection.engine import _window_start, fingerprint


def evaluate_unique_port_rule(
    spec: dict[str, Any], events: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    window = int(spec.get("window_seconds") or 120)
    threshold = int(spec.get("threshold") or 12)
    match_types = spec.get("match", {}).get("event_type") or []
    if isinstance(match_types, str):
        match_types = [match_types]
    buckets: dict[tuple, set[int]] = defaultdict(set)
    samples: dict[tuple, list[str]] = defaultdict(list)
    for event in events:
        if event.get("event_type") not in match_types:
            continue
        port = event.get("dst_port")
        src = event.get("src_ip")
        if port is None or not src:
            continue
        et = event["event_time"]
        if isinstance(et, str):
            et = datetime.fromisoformat(et.replace("Z", "+00:00"))
        ws = _window_start(et, window)
        key = (ws, src)
        buckets[key].add(int(port))
        if event.get("id") and len(samples[key]) < 50:
            samples[key].append(str(event["id"]))
    findings = []
    for (ws, src), ports in buckets.items():
        if len(ports) < threshold:
            continue
        group_key = f"src_ip={src}"
        findings.append(
            {
                "rule_id": spec["rule_id"],
                "rule_version": spec.get("version", 1),
                "title": spec["title"],
                "severity": spec["severity"],
                "summary": (
                    f"{len(ports)} distinct destination ports from {src} "
                    f"in {window}s starting {ws.astimezone(UTC).isoformat()} "
                    f"(threshold {threshold})."
                ),
                "fingerprint": fingerprint(spec["rule_id"], spec.get("version", 1), group_key, ws),
                "evidence": {
                    "unique_dst_ports": len(ports),
                    "threshold": threshold,
                    "src_ip": src,
                    "window_start": ws.isoformat(),
                    "event_ids": samples[(ws, src)],
                },
                "mitre": spec.get("mitre") or [],
                "event_ids": samples[(ws, src)],
            }
        )
    return findings
