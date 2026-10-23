import base64
import hashlib
import hmac
import os
import struct
import time
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
    reason="MFA API integration requires a migrated PostgreSQL test database",
)
TEST_PASSWORD = "Mfa-Integration-Test-2026!"  # noqa: S105 - Test-only account password.


def _totp(secret: str, *, next_step: bool = False) -> str:
    key = base64.b32decode(secret + "=" * ((8 - len(secret) % 8) % 8))
    counter = int(time.time()) // 30 + int(next_step)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = (struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF) % 1_000_000
    return f"{value:06d}"


def test_mfa_enrollment_signin_recovery_and_organization_policy() -> None:
    organization_id = uuid4()
    slug = f"mfa-test-{organization_id.hex}"
    admin_email = f"admin-{organization_id.hex}@example.test"
    member_email = f"member-{organization_id.hex}@example.test"

    with SessionLocal() as db:
        db.add(Organization(id=organization_id, slug=slug, name="MFA integration test"))
        db.commit()
        set_organization_context(db, organization_id)
        admin_role = db.scalar(select(Role).where(Role.name == "administrator"))
        if admin_role is None:
            admin_role = Role(name="administrator", description="Integration test administrator")
            db.add(admin_role)
            db.flush()
        admin = User(
            organization_id=organization_id,
            email=admin_email,
            hashed_password=hash_password(TEST_PASSWORD),
            full_name="MFA test admin",
        )
        member = User(
            organization_id=organization_id,
            email=member_email,
            hashed_password=hash_password(TEST_PASSWORD),
            full_name="MFA test member",
        )
        db.add_all([admin, member])
        db.flush()
        db.add(UserRole(organization_id=organization_id, user_id=admin.id, role_id=admin_role.id))
        db.commit()

    try:
        with TestClient(app) as client:
            login = client.post(
                "/api/v1/auth/login",
                json={"organization_slug": slug, "email": admin_email, "password": TEST_PASSWORD},
            )
            assert login.status_code == 200, login.text
            admin_token = login.json()["access_token"]
            enrollment = client.post(
                "/api/v1/auth/mfa/enroll",
                headers={"Authorization": f"Bearer {admin_token}"},
                json={"current_password": TEST_PASSWORD},
            )
            assert enrollment.status_code == 200, enrollment.text
            enabled = client.post(
                "/api/v1/auth/mfa/enable",
                headers={"Authorization": f"Bearer {admin_token}"},
                json={"code": _totp(enrollment.json()["secret"])},
            )
            assert enabled.status_code == 200, enabled.text
            assert enabled.json()["user"]["auth_methods"] == ["pwd", "otp"]
            assert len(enabled.json()["recovery_codes"]) == 10
            recovery_code = enabled.json()["recovery_codes"][0]

            admin_token = enabled.json()["access_token"]
            required = client.patch(
                "/api/v1/auth/mfa/requirement",
                headers={"Authorization": f"Bearer {admin_token}"},
                json={"required": True},
            )
            assert required.status_code == 200, required.text
            assert client.get(
                "/api/v1/auth/mfa/status",
                headers={"Authorization": f"Bearer {admin_token}"},
            ).status_code == 401

            admin_challenge = client.post(
                "/api/v1/auth/login",
                json={"organization_slug": slug, "email": admin_email, "password": TEST_PASSWORD},
            )
            assert admin_challenge.status_code == 200, admin_challenge.text
            assert admin_challenge.json()["mfa_setup_required"] is False
            verified = client.post(
                "/api/v1/auth/mfa/verify",
                json={
                    "challenge_token": admin_challenge.json()["challenge_token"],
                    "code": recovery_code,
                },
            )
            assert verified.status_code == 200, verified.text
            assert verified.json()["user"]["auth_methods"] == ["pwd", "otp"]
            retry_challenge = client.post(
                "/api/v1/auth/login",
                json={"organization_slug": slug, "email": admin_email, "password": TEST_PASSWORD},
            )
            reused_recovery = client.post(
                "/api/v1/auth/mfa/verify",
                json={
                    "challenge_token": retry_challenge.json()["challenge_token"],
                    "code": recovery_code,
                },
            )
            assert reused_recovery.status_code == 401
            otp_verified = client.post(
                "/api/v1/auth/mfa/verify",
                json={
                    "challenge_token": retry_challenge.json()["challenge_token"],
                    "code": _totp(enrollment.json()["secret"], next_step=True),
                },
            )
            assert otp_verified.status_code == 200, otp_verified.text
            admin_refreshed = client.post("/api/v1/auth/refresh")
            assert admin_refreshed.status_code == 200, admin_refreshed.text
            assert admin_refreshed.json()["user"]["auth_methods"] == ["pwd", "otp"]

            member_challenge = client.post(
                "/api/v1/auth/login",
                json={"organization_slug": slug, "email": member_email, "password": TEST_PASSWORD},
            )
            assert member_challenge.status_code == 200, member_challenge.text
            assert member_challenge.json()["mfa_setup_required"] is True
            setup = client.post(
                "/api/v1/auth/mfa/setup",
                json={"challenge_token": member_challenge.json()["challenge_token"]},
            )
            assert setup.status_code == 200, setup.text
            confirmed = client.post(
                "/api/v1/auth/mfa/setup/confirm",
                json={
                    "challenge_token": member_challenge.json()["challenge_token"],
                    "code": _totp(setup.json()["secret"]),
                },
            )
            assert confirmed.status_code == 200, confirmed.text
            assert len(confirmed.json()["recovery_codes"]) == 10
            member_token = confirmed.json()["access_token"]
            member_recovery = confirmed.json()["recovery_codes"][0]
            rejected_disable = client.post(
                "/api/v1/auth/mfa/disable",
                headers={"Authorization": f"Bearer {member_token}"},
                json={"current_password": TEST_PASSWORD, "code": member_recovery},
            )
            assert rejected_disable.status_code == 409

            policy_disabled = client.patch(
                "/api/v1/auth/mfa/requirement",
                headers={"Authorization": f"Bearer {admin_refreshed.json()['access_token']}"},
                json={"required": False},
            )
            assert policy_disabled.status_code == 200, policy_disabled.text
            disabled = client.post(
                "/api/v1/auth/mfa/disable",
                headers={"Authorization": f"Bearer {member_token}"},
                json={"current_password": TEST_PASSWORD, "code": member_recovery},
            )
            assert disabled.status_code == 200, disabled.text
    finally:
        with SessionLocal() as db:
            set_organization_context(db, organization_id)
            db.execute(delete(Organization).where(Organization.id == organization_id))
            db.commit()
            assert db.scalar(
                select(Organization.id).where(Organization.id == organization_id)
            ) is None
