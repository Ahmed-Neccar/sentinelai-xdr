"""Role mapping and account creation for people who arrive through single sign-on or SCIM."""

import secrets
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload

from app.core.permissions import ADMIN, ALL_ROLES
from app.core.security import hash_password
from app.models import Organization, Role, SsoRoleMapping, User, UserRole

MAX_CLAIM_VALUES = 200


def groups_from_claims(claims: dict) -> list[str]:
    """Group and role values from an ID token, as plain strings.

    Microsoft Entra sends group object ids in `groups` and app roles in `roles`; other
    providers use one or both. Anything that is not a list of short strings is ignored.
    """
    values: list[str] = []
    for key in ("groups", "roles"):
        raw = claims.get(key)
        if isinstance(raw, list):
            values.extend(v for v in raw if isinstance(v, str) and 0 < len(v) <= 255)
    return list(dict.fromkeys(values))[:MAX_CLAIM_VALUES]


def mapped_roles(db: Session, groups: list[str]) -> set[str]:
    """Our roles that the organization has mapped to any of these claim values."""
    if not groups:
        return set()
    rows = db.scalars(select(SsoRoleMapping).where(SsoRoleMapping.claim_value.in_(groups)))
    return {row.role_name for row in rows if row.role_name in ALL_ROLES}


def current_roles(user: User) -> set[str]:
    return {link.role.name for link in user.roles if link.role is not None}


def other_active_admins(db: Session, organization_id: UUID, user_id: UUID) -> int:
    return (
        db.scalar(
            select(func.count(func.distinct(User.id)))
            .join(UserRole, UserRole.user_id == User.id)
            .join(Role, Role.id == UserRole.role_id)
            .where(
                User.organization_id == organization_id,
                User.is_active.is_(True),
                User.id != user_id,
                Role.name == ADMIN,
            )
        )
        or 0
    )


def set_roles(db: Session, user: User, role_names: set[str]) -> None:
    """Replace the account's roles. Callers check the last-administrator rule first."""
    user.roles.clear()
    db.flush()
    for role in db.scalars(select(Role).where(Role.name.in_(sorted(role_names)))).all():
        db.add(UserRole(organization_id=user.organization_id, user_id=user.id, role_id=role.id))
    db.flush()
    db.expire(user, ["roles"])


def sync_roles_from_groups(db: Session, user: User, wanted: set[str]) -> bool:
    """Make the account's roles equal `wanted`. Returns True when something changed.

    Never removes the organization's last active administrator: the sync is skipped instead,
    because a locked-out organization is worse than a stale role.
    """
    have = current_roles(user)
    if not wanted or wanted == have:
        return False
    if (
        user.is_active
        and ADMIN in have
        and ADMIN not in wanted
        and other_active_admins(db, user.organization_id, user.id) == 0
    ):
        return False
    set_roles(db, user, wanted)
    user.token_version += 1
    return True


def create_account(
    db: Session,
    organization: Organization,
    *,
    email: str,
    full_name: str,
    roles: set[str],
    active: bool = True,
    oidc_issuer: str | None = None,
    oidc_subject: str | None = None,
    scim_external_id: str | None = None,
) -> User:
    """Create an account nobody can sign in to with a password.

    The stored password is a hash of random data that is thrown away, so the person can only
    arrive through single sign-on until an administrator sets a password.
    """
    user = User(
        organization_id=organization.id,
        email=email.lower(),
        hashed_password=hash_password(secrets.token_urlsafe(32)),
        full_name=full_name,
        is_active=active,
        oidc_issuer=oidc_issuer,
        oidc_subject=oidc_subject,
        scim_external_id=scim_external_id,
    )
    db.add(user)
    db.flush()
    if roles:
        set_roles(db, user, roles)
    return user


def load_user(db: Session, user_id: UUID) -> User | None:
    return db.scalar(
        select(User)
        .options(selectinload(User.roles).selectinload(UserRole.role))
        .where(User.id == user_id)
    )
