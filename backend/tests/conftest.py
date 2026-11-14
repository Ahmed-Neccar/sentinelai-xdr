"""Shared fixtures for API tests that need a real, migrated PostgreSQL database.

`tenant` creates an organization with an administrator, an analyst and an auditor, yields a
client with ready-made authorization headers, and deletes the organization afterwards.
Tests that use it are skipped when no test database is configured (as in a plain local run).
"""

import os
from dataclasses import dataclass
from uuid import UUID, uuid4

import pytest

PASSWORD = "Api-Test-Password-2026!"  # noqa: S105 - test-only account password
ROLES = ("administrator", "analyst", "auditor")


@dataclass
class Tenant:
    organization_id: UUID
    slug: str
    emails: dict[str, str]
    headers: dict[str, dict[str, str]]
    client: object

    def session(self):
        from app.db.session import SessionLocal, set_organization_context

        db = SessionLocal()
        set_organization_context(db, self.organization_id)
        return db


@pytest.fixture(autouse=True)
def fresh_auth_throttle():
    """Every test starts with an empty in-process login throttle.

    Without a Redis URL the throttle counts in memory per client address; all tests share the
    test client's address, so signing in from many tests would otherwise hit the 20-per-5-minutes
    limit and fail with 429.
    """
    from app.core import auth_rate_limit

    auth_rate_limit._local.clear()
    yield


@pytest.fixture
def tenant():
    if not os.environ.get("MFA_TEST_DATABASE_URL"):
        pytest.skip("Needs a migrated PostgreSQL test database")
    from app.core.security import hash_password
    from app.db.session import SessionLocal, set_organization_context
    from app.main import app
    from app.models import Organization, Role, User, UserRole
    from fastapi.testclient import TestClient
    from sqlalchemy import delete, select

    organization_id = uuid4()
    slug = f"api-test-{organization_id.hex}"
    emails = {role: f"{role}-{organization_id.hex}@example.test" for role in ROLES}
    with SessionLocal() as db:
        db.add(Organization(id=organization_id, slug=slug, name="API test organization"))
        db.commit()
        set_organization_context(db, organization_id)
        for role_name, email in emails.items():
            role = db.scalar(select(Role).where(Role.name == role_name))
            if role is None:
                role = Role(name=role_name, description="API test role")
                db.add(role)
                db.flush()
            user = User(
                organization_id=organization_id,
                email=email,
                hashed_password=hash_password(PASSWORD),
                full_name=role_name.title(),
            )
            db.add(user)
            db.flush()
            db.add(UserRole(organization_id=organization_id, user_id=user.id, role_id=role.id))
        db.commit()
    try:
        with TestClient(app) as client:
            headers = {}
            for role_name, email in emails.items():
                login = client.post(
                    "/api/v1/auth/login",
                    json={"organization_slug": slug, "email": email, "password": PASSWORD},
                )
                assert login.status_code == 200, login.text
                headers[role_name] = {"Authorization": f"Bearer {login.json()['access_token']}"}
            yield Tenant(organization_id, slug, emails, headers, client)
    finally:
        with SessionLocal() as db:
            set_organization_context(db, organization_id)
            db.execute(delete(Organization).where(Organization.id == organization_id))
            db.commit()
