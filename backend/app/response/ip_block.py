"""Policy for the response actions that are really executed.

All three are applied by an enrolled sensor on its own Windows host, never by
the server: a time-limited firewall block of one IP address, a time-limited
network isolation of the sensor host, and a time-limited disabling of one
local Windows account. An approved action is handed to the sensor in its
signed heartbeat response; the sensor applies it locally and reports back.
This module holds the rules both sides of that exchange rely on.

(The module keeps its original name; the IP block was the first such action.)
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta


@dataclass(frozen=True)
class ExecutedAction:
    name: str
    capability: str  # the sensor must have announced this at its last start
    apply: str  # verb sent to the sensor
    lift: str
    audit: str  # audit actions are "response.<audit>.<event>"
    label: str  # used in notifications
    min_minutes: int
    max_minutes: int
    default_minutes: int


ACTION = "block_source_ip"
ISOLATE = "isolate_host"
DISABLE_ACCOUNT = "disable_local_account"

EXECUTED: dict[str, ExecutedAction] = {
    ACTION: ExecutedAction(
        ACTION, "response.block_ip", "block", "unblock", "block", "IP block", 5, 24 * 60, 60
    ),
    # Isolation cuts a whole computer off, so it is kept short.
    ISOLATE: ExecutedAction(
        ISOLATE, "response.isolate_host", "isolate", "release", "isolation",
        "Host isolation", 5, 4 * 60, 30,
    ),
    DISABLE_ACCOUNT: ExecutedAction(
        DISABLE_ACCOUNT, "response.disable_account", "disable_account", "enable_account",
        "account", "Local account disable", 5, 24 * 60, 60,
    ),
}

CAPABILITY = EXECUTED[ACTION].capability
DEFAULT_MINUTES = EXECUTED[ACTION].default_minutes
MIN_MINUTES = EXECUTED[ACTION].min_minutes
MAX_MINUTES = EXECUTED[ACTION].max_minutes

# enforcement_status values
PENDING = "pending"  # approved, not yet handed to the sensor
DISPATCHED = "dispatched"  # handed to the sensor, no result yet
APPLIED = "applied"
REFUSED = "refused"  # the sensor declined, for example a protected address
FAILED = "failed"
REMOVAL_PENDING = "removal_pending"  # an administrator asked to lift it early
REMOVED = "removed"
CANCELLED = "cancelled"  # lifted before the sensor ever applied it

SENSOR_RESULTS = {"applied", "refused", "failed", "removed"}

# An approved action must reach its sensor within this time or it is cancelled.
# A sensor heartbeats every ten seconds, so a longer wait means it was not
# running, and the situation that justified the action may have changed.
DELIVERY_WINDOW = timedelta(minutes=15)

# Once handed to the sensor, a result must come back within this time or the action is
# closed as failed (timeout): a late application is not what was approved.
EXECUTION_TIMEOUT = timedelta(minutes=5)

# A sensor that has not contacted the server for longer than this is treated as offline.
# It heartbeats every ten seconds, so this tolerates a few missed beats.
ONLINE_WINDOW = timedelta(seconds=45)


def is_online(last_seen_at: datetime | None, now: datetime) -> bool:
    return last_seen_at is not None and now - last_seen_at <= ONLINE_WINDOW

# A local Windows account name: no path, option or shell characters, and it
# cannot start with a character that a command could read as a switch.
_ACCOUNT_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._ -]{0,19}$")


class BlockPolicyError(ValueError):
    """The requested action is not allowed; the message is safe to show."""


def normalize_block_target(value: str) -> str:
    """Return the canonical address, or raise for addresses that must never be blocked.

    Private addresses are allowed on purpose (an attacker can be on the local
    network). The sensor additionally refuses its own addresses, its gateways
    and its DNS servers, which only it can know.
    """
    try:
        address = ipaddress.ip_address(value.strip())
    except ValueError as exc:
        raise BlockPolicyError("A block requires one valid IP address") from exc
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    if (
        address.is_loopback
        or address.is_unspecified
        or address.is_multicast
        or address.is_link_local
        or address.is_reserved
        or (isinstance(address, ipaddress.IPv4Address) and int(address) == 0xFFFFFFFF)
    ):
        raise BlockPolicyError("This address is reserved and cannot be blocked")
    return str(address)


def normalize_account_name(value: str) -> str:
    name = value.strip()
    if not _ACCOUNT_NAME.match(name) or name.endswith((" ", ".")):
        raise BlockPolicyError(
            "Enter one local Windows account name (letters, digits, dot, dash, underscore, space)"
        )
    return name


def normalize_target(action: str, value: str, sensor_name: str) -> str:
    """The stored target for an executed action."""
    if action == ACTION:
        return normalize_block_target(value)
    if action == DISABLE_ACCOUNT:
        return normalize_account_name(value)
    if action == ISOLATE:
        # Isolation always concerns the chosen sensor computer itself; what the
        # requester typed is ignored so it cannot suggest another machine.
        return sensor_name[:255] or "sensor host"
    raise BlockPolicyError("Unsupported action")


def validate_minutes(value: int | None, action: str = ACTION) -> int:
    spec = EXECUTED[action]
    minutes = spec.default_minutes if value is None else value
    if not spec.min_minutes <= minutes <= spec.max_minutes:
        raise BlockPolicyError(
            f"Duration must be between {spec.min_minutes} and {spec.max_minutes} minutes"
        )
    return minutes


def block_until(applied_at: datetime, minutes: int) -> datetime:
    return applied_at.astimezone(UTC) + timedelta(minutes=minutes)


def next_status(current: str | None, result: str) -> str | None:
    """The enforcement status after a sensor report, or None if the report is not allowed."""
    if result in {"applied", "refused", "failed"}:
        return result if current in {PENDING, DISPATCHED} else None
    if result == "removed":
        return REMOVED if current in {APPLIED, REMOVAL_PENDING} else None
    return None
