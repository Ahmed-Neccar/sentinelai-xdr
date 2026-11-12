"""Policy for the one response action that is really executed: a time-limited
firewall block of one IP address on one enrolled sensor host.

The server never connects to a host. An approved block is handed to the
sensor in its signed heartbeat response; the sensor applies it locally and
reports back. This module holds the rules both sides of that exchange rely on.
"""

from __future__ import annotations

import ipaddress
from datetime import UTC, datetime, timedelta

ACTION = "block_source_ip"
CAPABILITY = "response.block_ip"
DEFAULT_MINUTES = 60
MIN_MINUTES = 5
MAX_MINUTES = 24 * 60

# enforcement_status values
PENDING = "pending"  # approved, waiting for the sensor to apply it
APPLIED = "applied"
REFUSED = "refused"  # the sensor declined, for example a protected address
FAILED = "failed"
REMOVAL_PENDING = "removal_pending"  # an administrator asked to lift it early
REMOVED = "removed"
CANCELLED = "cancelled"  # lifted before the sensor ever applied it

SENSOR_RESULTS = {"applied", "refused", "failed", "removed"}


class BlockPolicyError(ValueError):
    """The requested block is not allowed; the message is safe to show."""


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


def validate_minutes(value: int | None) -> int:
    minutes = DEFAULT_MINUTES if value is None else value
    if not MIN_MINUTES <= minutes <= MAX_MINUTES:
        raise BlockPolicyError(
            f"Block duration must be between {MIN_MINUTES} and {MAX_MINUTES} minutes"
        )
    return minutes


def block_until(applied_at: datetime, minutes: int) -> datetime:
    return applied_at.astimezone(UTC) + timedelta(minutes=minutes)


def next_status(current: str | None, result: str) -> str | None:
    """The enforcement status after a sensor report, or None if the report is not allowed."""
    if result in {"applied", "refused", "failed"}:
        return result if current == PENDING else None
    if result == "removed":
        return REMOVED if current in {APPLIED, REMOVAL_PENDING} else None
    return None
