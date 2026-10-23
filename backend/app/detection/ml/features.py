from collections import defaultdict
from datetime import datetime
from typing import Any

FEATURE_VERSION = "features-v1"
FEATURE_NAMES = [
    "auth_failure_count",
    "auth_success_count",
    "conn_count",
    "unique_dst_ports",
    "unique_dst_ips",
    "high_severity_count",
]


def extract_entity_features(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for event in events:
        key = event.get("src_ip") or event.get("host_id")
        if not key:
            continue
        groups[str(key)].append(event)
    rows = []
    for entity, items in groups.items():
        ports = {e.get("dst_port") for e in items if e.get("dst_port") is not None}
        ips = {e.get("dst_ip") for e in items if e.get("dst_ip")}
        features = {
            "auth_failure_count": sum(1 for e in items if e.get("event_type") == "auth.failure"),
            "auth_success_count": sum(1 for e in items if e.get("event_type") == "auth.success"),
            "conn_count": sum(
                1
                for e in items
                if str(e.get("event_type", "")).endswith("conn")
                or e.get("event_type") == "net.conn"
            ),
            "unique_dst_ports": len(ports),
            "unique_dst_ips": len(ips),
            "high_severity_count": sum(
                1 for e in items if e.get("severity") in {"high", "critical"}
            ),
        }
        times = []
        for event in items:
            et = event.get("event_time")
            if isinstance(et, datetime):
                times.append(et)
        window = min(times).isoformat() if times else "na"
        rows.append(
            {
                "entity": entity,
                "window": window,
                "features": features,
                "vector": [features[name] for name in FEATURE_NAMES],
                "event_ids": [str(e["id"]) for e in items if e.get("id")][:50],
                "label": items[0].get("label"),
            }
        )
    return rows
