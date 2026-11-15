"""Administrator settings for single sign-on role mapping, provisioning and SCIM tokens."""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field
from sqlalchemy import select

from app.api.deps import DbDep, client_ip, require_roles
from app.api.v1.scim import hash_scim_token, new_scim_token
from app.audit.service import write_audit
from app.core import oidc
from app.core.errors import AppError
from app.core.permissions import ADMIN, ALL_ROLES, MANAGE_SETTINGS
from app.models import Organization, ScimToken, SsoRoleMapping
from app.schemas.common import TokenUser

router = APIRouter(prefix="/identity", tags=["identity"])
Admin = Annotated[TokenUser, Depends(require_roles(*MANAGE_SETTINGS))]


class IdentitySettingsIn(BaseModel):
    auto_provision: bool
    sync_roles: bool
    default_role: str | None = Field(default=None, max_length=64)


class MappingIn(BaseModel):
    claim_value: str = Field(min_length=1, max_length=255)
    role_name: str = Field(min_length=1, max_length=64)


class ScimTokenIn(BaseModel):
    name: str = Field(min_length=1, max_length=200)


def _organization(db: DbDep, actor: TokenUser) -> Organization:
    organization = db.get(Organization, actor.organization_id)
    if organization is None:
        raise AppError(404, "not_found", "Organization not found")
    return organization


@router.get("/settings")
def get_settings(db: DbDep, actor: Admin) -> dict:
    organization = _organization(db, actor)
    mappings = db.scalars(
        select(SsoRoleMapping).order_by(SsoRoleMapping.claim_value, SsoRoleMapping.role_name)
    ).all()
    tokens = db.scalars(select(ScimToken).order_by(ScimToken.created_at.desc())).all()
    return {
        "sso_enabled": oidc.enabled(),
        "auto_provision": organization.sso_auto_provision,
        "sync_roles": organization.sso_sync_roles,
        "default_role": organization.default_role,
        "mappings": [
            {"id": m.id, "claim_value": m.claim_value, "role_name": m.role_name} for m in mappings
        ],
        "scim_base_path": "/api/v1/scim/v2",
        "scim_tokens": [
            {
                "id": t.id,
                "name": t.name,
                "revoked": t.revoked,
                "created_at": t.created_at,
                "last_used_at": t.last_used_at,
            }
            for t in tokens
        ],
    }


@router.put("/settings")
def put_settings(payload: IdentitySettingsIn, db: DbDep, actor: Admin, request: Request) -> dict:
    if payload.default_role is not None and payload.default_role not in ALL_ROLES:
        raise AppError(400, "invalid_role", "Unknown role")
    if payload.default_role == ADMIN:
        raise AppError(
            400, "invalid_role", "Administrator cannot be the default role for new accounts"
        )
    organization = _organization(db, actor)
    organization.sso_auto_provision = payload.auto_provision
    organization.sso_sync_roles = payload.sync_roles
    organization.default_role = payload.default_role
    write_audit(
        db,
        actor_id=actor.id,
        action="identity.settings_changed",
        target_type="organization",
        target_id=str(organization.id),
        ip_address=client_ip(request),
        details={
            "auto_provision": payload.auto_provision,
            "sync_roles": payload.sync_roles,
            "default_role": payload.default_role,
        },
    )
    db.commit()
    return get_settings(db, actor)


@router.post("/mappings", status_code=201)
def add_mapping(payload: MappingIn, db: DbDep, actor: Admin, request: Request) -> dict:
    if payload.role_name not in ALL_ROLES:
        raise AppError(400, "invalid_role", "Unknown role")
    value = payload.claim_value.strip()
    if not value:
        raise AppError(400, "invalid_value", "The group or role value is empty")
    exists = db.scalar(
        select(SsoRoleMapping).where(
            SsoRoleMapping.claim_value == value, SsoRoleMapping.role_name == payload.role_name
        )
    )
    if exists:
        raise AppError(409, "conflict", "This mapping already exists")
    mapping = SsoRoleMapping(claim_value=value, role_name=payload.role_name)
    db.add(mapping)
    db.flush()
    write_audit(
        db,
        actor_id=actor.id,
        action="identity.mapping_added",
        target_type="sso_role_mapping",
        target_id=str(mapping.id),
        ip_address=client_ip(request),
        details={"claim_value": value, "role": payload.role_name},
    )
    db.commit()
    return {"id": mapping.id, "claim_value": value, "role_name": payload.role_name}


@router.delete("/mappings/{mapping_id}")
def delete_mapping(mapping_id: UUID, db: DbDep, actor: Admin, request: Request) -> dict:
    mapping = db.get(SsoRoleMapping, mapping_id)
    if mapping is None:
        raise AppError(404, "not_found", "Mapping not found")
    write_audit(
        db,
        actor_id=actor.id,
        action="identity.mapping_removed",
        target_type="sso_role_mapping",
        target_id=str(mapping.id),
        ip_address=client_ip(request),
        details={"claim_value": mapping.claim_value, "role": mapping.role_name},
    )
    db.delete(mapping)
    db.commit()
    return {"ok": True}


@router.post("/scim-tokens", status_code=201)
def create_scim_token(payload: ScimTokenIn, db: DbDep, actor: Admin, request: Request) -> dict:
    token = new_scim_token(actor.organization_id)
    row = ScimToken(name=payload.name.strip(), token_hash=hash_scim_token(token))
    db.add(row)
    db.flush()
    write_audit(
        db,
        actor_id=actor.id,
        action="identity.scim_token_created",
        target_type="scim_token",
        target_id=str(row.id),
        ip_address=client_ip(request),
        details={"name": row.name},
    )
    db.commit()
    # The only time the token is shown; only its hash is stored.
    return {"id": row.id, "name": row.name, "token": token}


@router.delete("/scim-tokens/{token_id}")
def revoke_scim_token(token_id: UUID, db: DbDep, actor: Admin, request: Request) -> dict:
    row = db.get(ScimToken, token_id)
    if row is None:
        raise AppError(404, "not_found", "Token not found")
    row.revoked = True
    write_audit(
        db,
        actor_id=actor.id,
        action="identity.scim_token_revoked",
        target_type="scim_token",
        target_id=str(row.id),
        ip_address=client_ip(request),
        details={"name": row.name},
    )
    db.commit()
    return {"ok": True}
