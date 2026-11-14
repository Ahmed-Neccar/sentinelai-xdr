"""Loading a labelled event file so that real data can be evaluated with the same code.

Format: JSON Lines, one event per line, with at least

    event_time   ISO-8601 time
    event_type   for example auth.failure, auth.success, net.conn, process.start
    entity       the unit that is labelled (source IP, host or account)
    label        "benign" or the name of an attack family (per event; an entity's label is the
                 attack family if any of its events has one, otherwise "benign")

and, where they exist, src_ip, dst_ip, dst_port, host_id, username, severity and attributes
(an object) in the same form as docs/EVENT_SCHEMA.md.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path


def load_labelled_events(path: Path) -> tuple[list[dict], dict[str, str]]:
    events: list[dict] = []
    labels: dict[str, str] = {}
    with path.open(encoding="utf-8") as handle:
        for number, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue
            raw = json.loads(line)
            for required in ("event_time", "event_type", "entity", "label"):
                if required not in raw:
                    raise ValueError(f"line {number}: missing {required}")
            when = datetime.fromisoformat(str(raw["event_time"]).replace("Z", "+00:00"))
            if when.tzinfo is None:
                when = when.replace(tzinfo=UTC)
            entity = str(raw["entity"])
            event = {
                "id": raw.get("id") or f"line{number}",
                "event_time": when,
                "event_type": raw["event_type"],
                "src_ip": raw.get("src_ip"),
                "dst_ip": raw.get("dst_ip"),
                "dst_port": raw.get("dst_port"),
                "host_id": raw.get("host_id"),
                "username": raw.get("username"),
                "severity": raw.get("severity") or "low",
                "attributes": raw.get("attributes") or {},
                "entity": entity,
            }
            events.append(event)
            label = str(raw["label"])
            if label != "benign" or entity not in labels:
                if labels.get(entity, "benign") == "benign":
                    labels[entity] = label
    return events, labels
