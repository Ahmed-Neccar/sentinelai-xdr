from collections.abc import Callable
from typing import Annotated
from uuid import UUID

import jwt
from fastapi import Depends
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.core.client_address import client_ip  # noqa: F401 - re-exported for routers
from app.core.errors import AppError
from app.core.permissions import has_any
from app.core.security import decode_token
from app.db.session import get_db, set_organization_context
from app.models import User, UserRole
from app.schemas.common import TokenUser

bearer = HTTPBearer(auto_error=False)
DbDep = Annotated[Session, Depends(get_db)]


def get_current_user(
    db: DbDep,
    creds: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)],
) -> TokenUser:
    if creds is None or creds.scheme.lower() != "bearer":
        raise AppError(401, "unauthenticated", "Authentication required")
    try:
        payload = decode_token(creds.credentials)
    except jwt.ExpiredSignatureError as exc:
        raise AppError(401, "token_expired", "Access token expired") from exc
    except jwt.InvalidTokenError as exc:
        raise AppError(401, "invalid_token", "Invalid access token") from exc
    if payload.get("type") != "access":
        raise AppError(401, "invalid_token", "Invalid access token")
    try:
        organization_id = UUID(payload["org"])
    except (KeyError, ValueError, TypeError) as exc:
        raise AppError(401, "invalid_token", "Invalid access token") from exc
    set_organization_context(db, organization_id)
    user = db.scalar(
        select(User)
        .options(selectinload(User.roles).selectinload(UserRole.role))
        .where(User.id == UUID(payload["sub"]), User.organization_id == organization_id)
    )
    if user is None or not user.is_active:
        raise AppError(401, "unauthenticated", "User not found or inactive")
    if int(payload.get("tv", -1)) != user.token_version:
        raise AppError(401, "token_revoked", "Token has been revoked")
    roles = [link.role.name for link in user.roles if link.role is not None]
    return TokenUser(
        id=user.id,
        organization_id=user.organization_id,
        email=user.email,
        full_name=user.full_name,
        roles=roles,
        is_active=user.is_active,
        auth_methods=[
            method
            for method in payload.get("amr", ["pwd"])
            if method in {"pwd", "otp", "oidc"}
        ],
    )


def require_roles(*allowed: str) -> Callable[..., TokenUser]:
    allowed_set = set(allowed)

    def dependency(user: Annotated[TokenUser, Depends(get_current_user)]) -> TokenUser:
        if not has_any(user.roles, allowed_set):
            raise AppError(403, "forbidden", "You do not have permission for this action")
        return user

    return dependency
