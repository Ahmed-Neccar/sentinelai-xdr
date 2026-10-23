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
) -> tuple[str, datetime]:
    now = datetime.now(UTC)
    exp = now + timedelta(hours=settings.refresh_token_hours)
    payload = {
        "sub": str(user_id),
        "org": str(organization_id),
        "tv": token_version,
        "amr": auth_methods or ["pwd"],
        "type": "refresh",
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
        "jti": str(uuid4()),
    }
    return jwt.encode(payload, settings.secret_key, algorithm=ALGORITHM), exp


def decode_token(token: str) -> dict[str, Any]:
    return jwt.decode(token, settings.secret_key, algorithms=[ALGORITHM])
