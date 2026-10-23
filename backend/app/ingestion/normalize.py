import re
from datetime import UTC, datetime
from ipaddress import ip_address
from typing import Any

from app.ingestion.schema import EVENT_SCHEMA_VERSION

SCHEMA_VERSION = EVENT_SCHEMA_VERSION
SEVERITIES = {"informational", "low", "medium", "high", "critical"}
SENSITIVE_KEY_PATTERN = re.compile(
    r"(?:^|[^a-z0-9])(?:password|passwd|passphrase|secret|token|api[\s_-]*key|authorization|cookie|credential|private[\s_-]*key)(?:$|[^a-z0-9])",
    re.IGNORECASE,
)


def parse_dt(value: Any) -> datetime | None:
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        dt = value
    else:
        text = str(value).replace("Z", "+00:00")
        try:
            dt = datetime.fromisoformat(text)
        except ValueError:
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def parse_ip(value: Any) -> str | None:
    if value in (None, ""):
        return None
    try:
        return str(ip_address(str(value)))
    except ValueError:
        return None


def parse_port(value: Any) -> int | None:
    if value in (None, ""):
        return None
    try:
        port = int(value)
    except (TypeError, ValueError):
        return None
    if 0 <= port <= 65535:
        return port
    return None


def parse_severity(value: Any) -> str:
    if not value:
        return "informational"
    text = str(value).strip().lower()
    aliases = {"info": "informational", "warn": "medium", "warning": "medium", "err": "high"}
    text = aliases.get(text, text)
    return text if text in SEVERITIES else "informational"


def redact(payload: Any) -> Any:
    if isinstance(payload, dict):
        out = {}
        for key, val in payload.items():
            key_text = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", str(key))
            if SENSITIVE_KEY_PATTERN.search(key_text):
                out[key] = "[redacted]"
            else:
                out[key] = redact(val)
        return out
    if isinstance(payload, list):
        return [redact(item) for item in payload[:500]]
    return payload


def first(*values: Any) -> Any:
    for value in values:
        if value not in (None, ""):
            return value
    return None
