"""SCIM 2.0 user provisioning (RFC 7643 and 7644), the subset identity providers use.

An identity provider such as Microsoft Entra calls these endpoints with a bearer token an
administrator created under Users, so that people are created, changed and switched off here
when they join, change role or leave the company. Deleting is soft: the account is disabled
and its sessions end, because audit entries and cases refer to it.
"""

import hashlib
import re
import secrets
from datetime import UTC, datetime
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request, Response
from fastapi.responses import JSONResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import DbDep, client_ip
from app.audit.service import write_audit
from app.core import identity
from app.core.auth_rate_limit import enforce_auth_rate_limit
from app.core.errors import AppError
from app.core.permissions import ADMIN, ALL_ROLES
from app.db.session import set_organization_context
from app.models import Organization, RefreshToken, ScimToken, User

router = APIRouter(prefix="/scim/v2", tags=["scim"])

USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"
LIST_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
SCIM_TYPE = "application/scim+json"
TOKEN_PREFIX = "scim_"  # noqa: S105 - token format marker, not a credential.
_TOKEN_FORMAT = re.compile(r"scim_([0-9a-f]{32})_[A-Za-z0-9_-]{20,100}")
_LAST_ADMIN = "The organization must keep at least one active administrator"


def hash_scim_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def new_scim_token(organization_id: UUID) -> str:
    return f"{TOKEN_PREFIX}{organization_id.hex}_{secrets.token_urlsafe(32)}"


class ScimContext:
    def __init__(self, organization: Organization, token: ScimToken) -> None:
        self.organization = organization
        self.token = token


def scim_context(request: Request, db: DbDep) -> ScimContext:
    header = request.headers.get("authorization", "")
    scheme, _, token = header.partition(" ")
    match = _TOKEN_FORMAT.fullmatch(token)
    if scheme.lower() != "bearer" or not match:
        raise AppError(401, "unauthenticated", "A SCIM token is required")
    organization_id = UUID(match.group(1))
    enforce_auth_rate_limit(f"scim:{organization_id.hex}", limit=1000)
    set_organization_context(db, organization_id)
    stored = db.scalar(select(ScimToken).where(ScimToken.token_hash == hash_scim_token(token)))
    organization = db.get(Organization, organization_id)
    if stored is None or stored.revoked or organization is None or not organization.is_active:
        raise AppError(401, "unauthenticated", "The SCIM token is invalid or revoked")
    stored.last_used_at = datetime.now(UTC)
    return ScimContext(organization, stored)


Scim = Annotated[ScimContext, Depends(scim_context)]


def _respond(body: dict, status: int = 200) -> JSONResponse:
    return JSONResponse(body, status_code=status, media_type=SCIM_TYPE)


def _serialize(user: User) -> dict:
    roles = sorted(identity.current_roles(user))
    return {
        "schemas": [USER_SCHEMA],
        "id": str(user.id),
        "externalId": user.scim_external_id,
        "userName": user.email,
        "displayName": user.full_name,
        "name": {"formatted": user.full_name},
        "emails": [{"value": user.email, "primary": True, "type": "work"}],
        "active": user.is_active,
        "roles": [{"value": value} for value in roles],
        "meta": {
            "resourceType": "User",
            "created": user.created_at.isoformat() if user.created_at else None,
            "location": f"/api/v1/scim/v2/Users/{user.id}",
        },
    }


def _truthy(value: Any) -> bool:
    if isinstance(value, str):
        return value.strip().lower() == "true"
    return bool(value)


def _role_values(value: Any) -> set[str]:
    items = value if isinstance(value, list) else [value]
    found: set[str] = set()
    for item in items:
        raw = item.get("value") if isinstance(item, dict) else item
        # A provisioning token never hands out the administrator role: an identity provider
        # that is compromised or misconfigured must not be able to create administrators.
        # Administrators are promoted here by hand or through an explicit group mapping.
        if isinstance(raw, str) and raw in ALL_ROLES and raw != ADMIN:
            found.add(raw)
    return found


def _display_name(payload: dict) -> str | None:
    if isinstance(payload.get("displayName"), str):
        return payload["displayName"][:200]
    name = payload.get("name")
    if isinstance(name, dict):
        if isinstance(name.get("formatted"), str) and name["formatted"]:
            return name["formatted"][:200]
        parts = [name.get("givenName"), name.get("familyName")]
        joined = " ".join(p for p in parts if isinstance(p, str) and p)
        return joined[:200] if joined else None
    return None


def _load(db: Session, user_id: str) -> User:
    try:
        parsed = UUID(user_id)
    except ValueError as exc:
        raise AppError(404, "not_found", "User not found") from exc
    user = identity.load_user(db, parsed)
    if user is None:
        raise AppError(404, "not_found", "User not found")
    return user


def _deactivate(db: Session, ctx: ScimContext, user: User) -> None:
    if (
        user.is_active
        and ADMIN in identity.current_roles(user)
        and identity.other_active_admins(db, ctx.organization.id, user.id) == 0
    ):
        raise AppError(409, "last_active_admin", _LAST_ADMIN)
    user.is_active = False
    user.token_version += 1
    for refresh in db.scalars(select(RefreshToken).where(RefreshToken.user_id == user.id)):
        refresh.revoked = True


def _apply(db: Session, ctx: ScimContext, user: User, attrs: dict) -> list[str]:
    """Apply SCIM attributes to an account and return the names of the fields that changed."""
    changed: list[str] = []
    if "active" in attrs:
        active = _truthy(attrs["active"])
        if active != user.is_active:
            if active:
                user.is_active = True
            else:
                _deactivate(db, ctx, user)
            changed.append("active")
    name = _display_name(attrs)
    if name is not None and name != user.full_name:
        user.full_name = name
        changed.append("displayName")
    external = attrs.get("externalId")
    if isinstance(external, str) and external[:255] != user.scim_external_id:
        user.scim_external_id = external[:255]
        changed.append("externalId")
    if "roles" in attrs:
        wanted = _role_values(attrs["roles"])
        have = identity.current_roles(user)
        if wanted and wanted != have:
            if (
                user.is_active
                and ADMIN in have
                and ADMIN not in wanted
                and identity.other_active_admins(db, ctx.organization.id, user.id) == 0
            ):
                raise AppError(409, "last_active_admin", _LAST_ADMIN)
            identity.set_roles(db, user, wanted)
            user.token_version += 1
            changed.append("roles")
    return changed


def _audit(db: Session, request: Request, action: str, user: User, changed: list[str]) -> None:
    write_audit(
        db,
        actor_id=None,
        action=action,
        target_type="user",
        target_id=str(user.id),
        ip_address=client_ip(request),
        details={"via": "scim", "changed": sorted(changed)},
    )


@router.get("/ServiceProviderConfig")
def service_provider_config() -> JSONResponse:
    return _respond(
        {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
            "patch": {"supported": True},
            "bulk": {"supported": False, "maxOperations": 0, "maxPayloadSize": 0},
            "filter": {"supported": True, "maxResults": 200},
            "changePassword": {"supported": False},
            "sort": {"supported": False},
            "etag": {"supported": False},
            "authenticationSchemes": [
                {"type": "oauthbearertoken", "name": "Bearer token", "primary": True}
            ],
        }
    )


@router.get("/Users")
def list_users(
    ctx: Scim,
    db: DbDep,
    filter: Annotated[str | None, Query(max_length=300)] = None,  # noqa: A002 - SCIM name.
    startIndex: Annotated[int, Query(ge=1)] = 1,  # noqa: N803 - SCIM name.
    count: Annotated[int, Query(ge=0, le=200)] = 100,
) -> JSONResponse:
    query = select(User).order_by(User.created_at, User.id)
    if filter:
        match = re.fullmatch(r'\s*(userName|externalId)\s+eq\s+"([^"]{1,320})"\s*', filter, re.I)
        if not match:
            raise AppError(400, "invalid_filter", "Only 'userName eq' and 'externalId eq' work")
        if match.group(1).lower() == "username":
            query = query.where(User.email == match.group(2).lower())
        else:
            query = query.where(User.scim_external_id == match.group(2))
    rows = db.scalars(query).all()
    page = rows[startIndex - 1 : startIndex - 1 + count]
    loaded = [identity.load_user(db, row.id) for row in page]
    return _respond(
        {
            "schemas": [LIST_SCHEMA],
            "totalResults": len(rows),
            "startIndex": startIndex,
            "itemsPerPage": len(loaded),
            "Resources": [_serialize(u) for u in loaded if u is not None],
        }
    )


@router.get("/Users/{user_id}")
def get_user(user_id: str, ctx: Scim, db: DbDep) -> JSONResponse:
    return _respond(_serialize(_load(db, user_id)))


@router.post("/Users")
def create_user(payload: dict, ctx: Scim, db: DbDep, request: Request) -> JSONResponse:
    email = payload.get("userName")
    valid = isinstance(email, str) and len(email) <= 320 and re.fullmatch(r"[^@\s]+@[^@\s]+", email)
    if not valid or not isinstance(email, str):
        raise AppError(400, "invalid_value", "userName must be an email address")
    if db.scalar(select(User).where(User.email == email.lower())):
        raise AppError(409, "conflict", "A user with this userName already exists")
    default = ctx.organization.default_role
    roles = _role_values(payload.get("roles", [])) or (
        {default} if default in ALL_ROLES else set()
    )
    external = payload.get("externalId")
    user = identity.create_account(
        db,
        ctx.organization,
        email=email,
        full_name=_display_name(payload) or "",
        roles=roles,
        active=_truthy(payload.get("active", True)),
        scim_external_id=external[:255] if isinstance(external, str) else None,
    )
    _audit(db, request, "scim.user_created", user, ["roles"] if roles else [])
    db.commit()
    return _respond(_serialize(_load(db, str(user.id))), 201)


@router.put("/Users/{user_id}")
def replace_user(
    user_id: str, payload: dict, ctx: Scim, db: DbDep, request: Request
) -> JSONResponse:
    user = _load(db, user_id)
    changed = _apply(db, ctx, user, payload)
    _audit(db, request, "scim.user_updated", user, changed)
    db.commit()
    return _respond(_serialize(_load(db, user_id)))


@router.patch("/Users/{user_id}")
def patch_user(
    user_id: str, payload: dict, ctx: Scim, db: DbDep, request: Request
) -> JSONResponse:
    user = _load(db, user_id)
    operations = payload.get("Operations")
    if not isinstance(operations, list):
        raise AppError(400, "invalid_syntax", "Operations is required")
    attrs: dict[str, Any] = {}
    for operation in operations:
        if not isinstance(operation, dict):
            continue
        action = str(operation.get("op", "")).lower()
        path = operation.get("path")
        value = operation.get("value")
        if action not in {"add", "replace", "remove"}:
            raise AppError(400, "invalid_syntax", "Unsupported operation")
        if action == "remove":
            continue  # An account is never left without roles or a name by a remove.
        if isinstance(path, str) and path:
            head = path.split(".")[0].split("[")[0]
            if head == "name" and "." in path:
                attrs.setdefault("name", {})[path.split(".", 1)[1]] = value
            elif head in {"active", "displayName", "externalId", "roles"}:
                attrs[head] = value
        elif isinstance(value, dict):
            attrs.update(value)
    attrs.pop("userName", None)  # The email is the account's identity here; it is not renamed.
    changed = _apply(db, ctx, user, attrs)
    _audit(db, request, "scim.user_updated", user, changed)
    db.commit()
    return _respond(_serialize(_load(db, user_id)))


@router.delete("/Users/{user_id}")
def delete_user(user_id: str, ctx: Scim, db: DbDep, request: Request) -> Response:
    user = _load(db, user_id)
    if user.is_active:
        _deactivate(db, ctx, user)
    _audit(db, request, "scim.user_deactivated", user, ["active"])
    db.commit()
    return Response(status_code=204)


@router.get("/Groups")
def list_groups(ctx: Scim) -> JSONResponse:
    # Groups are not provisioned; roles come from the roles attribute or the SSO group mapping.
    return _respond({"schemas": [LIST_SCHEMA], "totalResults": 0, "Resources": []})
