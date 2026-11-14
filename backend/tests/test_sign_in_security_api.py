"""The Audit page's failed sign-in summary, against a real database (skipped without one)."""

import os
from uuid import uuid4

import pytest
from app.core.security import hash_password
from app.db.session import SessionLocal, set_organization_context
from app.main import app
from app.models import Organization, Role, User, UserRole
from fastapi.testclient import TestClient
from sqlalchemy import delete, select

pytestmark = pytest.mark.skipif(
    not os.environ.get("MFA_TEST_DATABASE_URL"),
    reason="Sign-in security API test requires a migrated PostgreSQL test database",
)
PASSWORD = "Sign-In-Security-Test-2026!"  # noqa: S105 - test-only account password


def _role(db, name: str) -> Role:
    role = db.scalar(select(Role).where(Role.name == name))
    if role is None:
        role = Role(name=name, description="Integration test role")
        db.add(role)
        db.flush()
    return role


def test_failed_sign_ins_are_summarised_for_administrators_only() -> None:
    organization_id = uuid4()
    slug = f"signin-test-{organization_id.hex}"
    admin = f"admin-{organization_id.hex}@example.test"
    analyst = f"analyst-{organization_id.hex}@example.test"
    with SessionLocal() as db:
        db.add(Organization(id=organization_id, slug=slug, name="Sign-in security test"))
        db.commit()
        set_organization_context(db, organization_id)
        for email, role_name in ((admin, "administrator"), (analyst, "analyst")):
            user = User(
                organization_id=organization_id,
                email=email,
                hashed_password=hash_password(PASSWORD),
                full_name=email,
            )
            db.add(user)
            db.flush()
            role = _role(db, role_name)
            db.add(UserRole(organization_id=organization_id, user_id=user.id, role_id=role.id))
        db.commit()
    try:
        with TestClient(app) as client:
            for _ in range(3):
                bad = client.post(
                    "/api/v1/auth/login",
                    json={"organization_slug": slug, "email": analyst, "password": "bad-pw-1234"},
                )
                assert bad.status_code == 401
            good = client.post(
                "/api/v1/auth/login",
                json={"organization_slug": slug, "email": admin, "password": PASSWORD},
            )
            assert good.status_code == 200, good.text
            headers = {"Authorization": f"Bearer {good.json()['access_token']}"}
            summary = client.get("/api/v1/audit-logs/sign-in-security", headers=headers)
            assert summary.status_code == 200, summary.text
            body = summary.json()
            assert body["total"] == 3 and body["by_action"] == {"auth.login_failed": 3}
            assert body["top_sources"][0]["account"] == analyst
            assert body["top_sources"][0]["attempts"] == 3

            analyst_login = client.post(
                "/api/v1/auth/login",
                json={"organization_slug": slug, "email": analyst, "password": PASSWORD},
            )
            token = analyst_login.json()["access_token"]
            denied = client.get(
                "/api/v1/audit-logs/sign-in-security", headers={"Authorization": f"Bearer {token}"}
            )
            assert denied.status_code == 403
    finally:
        with SessionLocal() as db:
            set_organization_context(db, organization_id)
            db.execute(delete(Organization).where(Organization.id == organization_id))
            db.commit()
