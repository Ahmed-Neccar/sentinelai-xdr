from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import selectinload

from app.api.deps import DbDep, client_ip, require_roles
from app.audit.service import write_audit
from app.core.auth_rate_limit import enforce_auth_rate_limit
from app.core.errors import AppError
from app.core.password_policy import check_new_password
from app.core.permissions import ADMIN, ALL_ROLES, MANAGE_USERS
from app.core.security import hash_password, verify_password
from app.models import Organization, Role, User, UserRole
from app.schemas.common import Page, TokenUser

router = APIRouter(prefix="/users", tags=["users"])
Admin = Annotated[TokenUser, Depends(require_roles(*MANAGE_USERS))]


class UserCreate(BaseModel):
    # Match the login identifier rules: local installations may use reserved
    # domains such as localhost.local and do not send email from this field.
    email: str = Field(min_length=3, max_length=320, pattern=r"^[^@\s]+@[^@\s]+$")
    password: str = Field(min_length=12, max_length=128)
    full_name: str = Field(default="", max_length=200)
    roles: list[str]
    is_active: bool = True


class UserPatch(BaseModel):
    full_name: str | None = Field(default=None, max_length=200)
    is_active: bool | None = None
    roles: list[str] | None = None
    password: str | None = Field(default=None, min_length=12, max_length=128)
    # The administrator's own password, required to set someone else's password.
    confirm_password: str | None = Field(default=None, max_length=256)
    # Forget the bound SSO identity so the next SSO sign-in with this email
    # binds again, for example after the person's provider account was rebuilt.
    unlink_sso: bool = False


def serialize(user: User) -> dict:
    return {
        "id": user.id,
        "email": user.email,
        "full_name": user.full_name,
        "is_active": user.is_active,
        "roles": [link.role.name for link in user.roles if link.role],
        "mfa_enabled": user.mfa_enabled_at is not None,
        "sso_linked": user.oidc_subject is not None,
        "created_at": user.created_at,
    }


@router.get("")
def list_users(db: DbDep, _: Admin, page: int = 1, page_size: int = 20) -> Page[dict]:
    page_size = min(max(page_size, 1), 100)
    page = max(page, 1)
    total = db.scalar(select(func.count()).select_from(User)) or 0
    rows = db.scalars(
        select(User)
        .options(selectinload(User.roles).selectinload(UserRole.role))
        .offset((page - 1) * page_size)
        .limit(page_size)
    ).all()
    return Page(items=[serialize(u) for u in rows], page=page, page_size=page_size, total=total)


@router.post("", status_code=201)
def create_user(payload: UserCreate, db: DbDep, actor: Admin, request: Request) -> dict:
    if db.scalar(select(User).where(User.email == payload.email.lower())):
        raise AppError(409, "conflict", "Email already exists")
    if any(role not in ALL_ROLES for role in payload.roles):
        raise AppError(400, "invalid_role", "Unknown role")
    check_new_password(payload.password, email=payload.email)
    user = User(
        organization_id=actor.organization_id,
        email=payload.email.lower(),
        hashed_password=hash_password(payload.password),
        full_name=payload.full_name,
        is_active=payload.is_active,
    )
    db.add(user)
    db.flush()
    roles = db.scalars(select(Role).where(Role.name.in_(payload.roles))).all()
    for role in roles:
        db.add(
            UserRole(
                organization_id=actor.organization_id,
                user_id=user.id,
                role_id=role.id,
            )
        )
    write_audit(
        db,
        actor_id=actor.id,
        action="user.create",
        target_type="user",
        target_id=str(user.id),
        ip_address=client_ip(request),
    )
    db.commit()
    loaded = db.scalar(
        select(User)
        .options(selectinload(User.roles).selectinload(UserRole.role))
        .where(User.id == user.id)
    )
    return serialize(loaded)  # type: ignore[arg-type]


@router.patch("/{user_id}")
def patch_user(
    user_id: UUID, payload: UserPatch, db: DbDep, actor: Admin, request: Request
) -> dict:
    # Serialize administrator changes per organization so two concurrent
    # requests cannot remove the final active administrator together.
    organization = db.scalar(
        select(Organization)
        .where(Organization.id == actor.organization_id)
        .with_for_update()
    )
    if organization is None:
        raise AppError(404, "not_found", "Organization not found")
    user = db.scalar(
        select(User)
        .options(selectinload(User.roles).selectinload(UserRole.role))
        .where(User.id == user_id)
    )
    if user is None:
        raise AppError(404, "not_found", "User not found")
    if payload.roles is not None and any(role not in ALL_ROLES for role in payload.roles):
        raise AppError(400, "invalid_role", "Unknown role")

    if payload.password:
        if user.id == actor.id:
            # Changing one's own password needs the current one: use POST /auth/password.
            raise AppError(
                400,
                "use_password_change",
                "Change your own password from Sign-in security, with your current password",
            )
        enforce_auth_rate_limit(f"admin-reset:{actor.organization_id}:{actor.id}", limit=8)
        admin_account = db.get(User, actor.id)
        if (
            admin_account is None
            or not payload.confirm_password
            or not verify_password(payload.confirm_password, admin_account.hashed_password)
        ):
            raise AppError(
                401, "invalid_credentials", "Confirm with your own password to set a password"
            )
        check_new_password(payload.password, email=user.email)

    current_roles = {link.role.name for link in user.roles if link.role is not None}
    next_roles = set(payload.roles) if payload.roles is not None else current_roles
    next_active = payload.is_active if payload.is_active is not None else user.is_active
    if user.is_active and ADMIN in current_roles and not (
        next_active and ADMIN in next_roles
    ):
        other_active_admins = db.scalar(
            select(func.count(func.distinct(User.id)))
            .join(UserRole, UserRole.user_id == User.id)
            .join(Role, Role.id == UserRole.role_id)
            .where(
                User.organization_id == actor.organization_id,
                User.is_active.is_(True),
                User.id != user.id,
                Role.name == ADMIN,
            )
        ) or 0
        if other_active_admins == 0:
            raise AppError(
                409,
                "last_active_admin",
                "The organization must keep at least one active administrator",
            )
    if payload.full_name is not None:
        user.full_name = payload.full_name
    if payload.is_active is not None:
        user.is_active = payload.is_active
        if not payload.is_active:
            user.token_version += 1
    if payload.password:
        user.hashed_password = hash_password(payload.password)
        user.token_version += 1
    if payload.unlink_sso and user.oidc_subject is not None:
        user.oidc_issuer = None
        user.oidc_subject = None
        user.token_version += 1
    if payload.roles is not None:
        user.roles.clear()
        db.flush()
        roles = db.scalars(select(Role).where(Role.name.in_(payload.roles))).all()
        for role in roles:
            db.add(
                UserRole(
                    organization_id=actor.organization_id,
                    user_id=user.id,
                    role_id=role.id,
                )
            )
    write_audit(
        db,
        actor_id=actor.id,
        action="user.update",
        target_type="user",
        target_id=str(user.id),
        ip_address=client_ip(request),
        # Field names only; never the new password or other values.
        details={
            "changed": sorted(
                set(payload.model_dump(exclude_unset=True, exclude_none=True))
                - {"confirm_password"}
            )
        },
    )
    db.commit()
    loaded = db.scalar(
        select(User)
        .options(selectinload(User.roles).selectinload(UserRole.role))
        .where(User.id == user.id)
    )
    return serialize(loaded)  # type: ignore[arg-type]
