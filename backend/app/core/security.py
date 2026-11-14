from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

import jwt
from pwdlib import PasswordHash

from app.core.config import settings

password_hasher = PasswordHash.recommended()
ALGORITHM = "HS256"


def hash_password(password: str) -> str:
    return password_hasher.hash(password)


def verify_password(password: str, hashed: str) -> bool:
    return password_hasher.verify(password, hashed)


# Hash of a random value nobody knows. Signing in as an unknown or inactive account verifies the
# submitted password against it, so that case costs as much time as a wrong password for a real
# account and the response time does not reveal which accounts exist.
_DUMMY_HASH = password_hasher.hash(uuid4().hex)


def burn_password_check(password: str) -> None:
    password_hasher.verify(password, _DUMMY_HASH)


def create_access_token(
    *,
    user_id: UUID,
    organization_id: UUID,
    roles: list[str],
    token_version: int,
    auth_methods: list[str] | None = None,
) -> str:
    now = datetime.now(UTC)
    payload = {
        "sub": str(user_id),
        "org": str(organization_id),
        "roles": roles,
        "tv": token_version,
        "amr": auth_methods or ["pwd"],
        "type": "access",
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=settings.access_token_minutes)).timestamp()),
        "jti": str(uuid4()),
    }
    return jwt.encode(payload, settings.secret_key, algorithm=ALGORITHM)


def create_refresh_token(
    *,
    user_id: UUID,
    organization_id: UUID,
    token_version: int,
    auth_methods: list[str] | None = None,
    session_started_at: datetime | None = None,
) -> tuple[str, datetime]:
    """Create a refresh token whose life never reaches past the session's absolute limit.

    `session_started_at` is when the person actually signed in; rotation passes it on so the
    limit counts from the sign-in and not from the latest refresh.
    """
    now = datetime.now(UTC)
    started = session_started_at or now
    exp = min(
        now + timedelta(hours=settings.refresh_token_hours),
        started + timedelta(hours=settings.session_max_hours),
    )
    payload = {
        "sub": str(user_id),
        "org": str(organization_id),
        "tv": token_version,
        "amr": auth_methods or ["pwd"],
        "type": "refresh",
        "sat": int(started.timestamp()),
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
        "jti": str(uuid4()),
    }
    return jwt.encode(payload, settings.secret_key, algorithm=ALGORITHM), exp


def decode_token(token: str) -> dict[str, Any]:
    return jwt.decode(token, settings.secret_key, algorithms=[ALGORITHM])
