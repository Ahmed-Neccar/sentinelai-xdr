"""Provision an isolated organization and its first administrator."""

import argparse
from getpass import getpass

from sqlalchemy import select

from app.core.bootstrap import seed_roles, seed_rules
from app.core.security import hash_password
from app.db.session import SessionLocal, set_organization_context
from app.models import Organization, Role, User, UserRole


def create_organization(slug: str, name: str, email: str, password: str) -> None:
    if len(password) < 12:
        raise ValueError("Administrator password must be at least 12 characters")
    if "@" not in email or len(email) > 320:
        raise ValueError("Administrator email is invalid")
    with SessionLocal() as db:
        if db.scalar(select(Organization.id).where(Organization.slug == slug)):
            raise ValueError(f"Organization slug already exists: {slug}")
        seed_roles(db)
        organization = Organization(slug=slug, name=name)
        db.add(organization)
        db.flush()
        set_organization_context(db, organization.id)
        seed_rules(db)
        user = User(
            organization_id=organization.id,
            email=email.lower(),
            hashed_password=hash_password(password),
            full_name="Organization Administrator",
            is_active=True,
        )
        db.add(user)
        db.flush()
        administrator = db.scalar(select(Role).where(Role.name == "administrator"))
        if administrator is None:
            raise RuntimeError("Administrator role is missing")
        db.add(UserRole(user_id=user.id, role_id=administrator.id))
        db.commit()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("slug", help="Unique lowercase organization slug")
    parser.add_argument("name", help="Organization display name")
    parser.add_argument("admin_email", help="First organization administrator email")
    args = parser.parse_args()
    if not args.slug or len(args.slug) > 80 or not args.slug[0].isalnum() or any(
        char not in "abcdefghijklmnopqrstuvwxyz0123456789-" for char in args.slug
    ):
        parser.error("slug must be lowercase letters, numbers, and hyphens")
    password = getpass("New administrator password (12+ characters): ")
    confirmation = getpass("Confirm password: ")
    if password != confirmation:
        parser.error("Passwords do not match")
    create_organization(args.slug, args.name, args.admin_email, password)
    print(f"Organization '{args.slug}' created with its first administrator.")


if __name__ == "__main__":
    main()
