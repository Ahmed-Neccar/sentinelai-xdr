"""Names and one-time credentials for a sensor that is about to be installed."""

from __future__ import annotations

import re
import secrets

# Reserved, never-routable domain: these accounts are machines, not mailboxes.
SENSOR_DOMAIN = "sensors.local"
_UNSAFE = re.compile(r"[^a-z0-9]+")


def account_slug(name: str) -> str:
    """A short, safe label from whatever the administrator called the computer."""
    slug = _UNSAFE.sub("-", name.strip().lower()).strip("-")[:24].strip("-")
    return slug or "computer"


def new_sensor_login(name: str) -> tuple[str, str]:
    """Return (email, password) for a new sensor account.

    The random suffix keeps two computers with the same name apart; the
    password is long and random because no person ever needs to type it.
    """
    email = f"sensor-{account_slug(name)}-{secrets.token_hex(3)}@{SENSOR_DOMAIN}"
    return email, secrets.token_urlsafe(32)
