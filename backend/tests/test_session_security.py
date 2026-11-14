"""Session lifetime and password-change rules.

Before these rules existed every refresh handed out a brand-new full-lifetime token, so a
session that was used at least once per refresh period never expired, and anyone holding an
access token could set a new password without knowing the current one.
"""

from datetime import UTC, datetime, timedelta
from uuid import UUID

import jwt as pyjwt
import pytest
from app.core.config import settings
from app.core.security import ALGORITHM
from tests.conftest import PASSWORD

NEW_PASSWORD = "Fresh-Long-Password-77!"  # noqa: S105 - test-only value


def _login(tenant, email: str, password: str = PASSWORD):
    return tenant.client.post(
        "/api/v1/auth/login",
        json={"organization_slug": tenant.slug, "email": email, "password": password},
    )


def _bearer(response) -> dict[str, str]:
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def _use_cookie(client, cookie: str) -> None:
    client.cookies.clear()
    client.cookies.set("refresh_token", cookie, path="/api/v1/auth")


# --- absolute session lifetime -------------------------------------------------------------


def test_a_refreshed_session_cannot_outlive_the_absolute_limit(tenant) -> None:
    client = tenant.client
    login = _login(tenant, tenant.emails["analyst"])
    payload = pyjwt.decode(
        login.cookies.get("refresh_token"), settings.secret_key, algorithms=[ALGORITHM]
    )
    started = int(payload["sat"])
    assert abs(started - datetime.now(UTC).timestamp()) < 30

    # A session that began longer ago than the limit is refused even though the refresh token
    # itself has not expired.
    old_start = datetime.now(UTC) - timedelta(hours=settings.session_max_hours + 1)
    # Forge the claims directly: a token issued by the app is never valid past the limit, so
    # this is the case where the token's own expiry alone would still have let it through.
    token = pyjwt.encode(
        {**payload, "sat": int(old_start.timestamp()), "jti": "forged-for-test",
         "exp": int((datetime.now(UTC) + timedelta(hours=1)).timestamp())},
        settings.secret_key,
        algorithm=ALGORITHM,
    )
    _register(tenant, token, payload)
    _use_cookie(client, token)
    expired = client.post("/api/v1/auth/refresh")
    assert expired.status_code == 401
    assert expired.json()["error"]["code"] == "session_expired"


def _register(tenant, token: str, payload: dict) -> None:
    """Store the refresh token the way sign-in does, so only the claims decide the outcome."""
    import hashlib

    from app.db.session import SessionLocal, set_organization_context
    from app.models import RefreshToken

    with SessionLocal() as db:
        set_organization_context(db, UUID(payload["org"]))
        db.add(
            RefreshToken(
                user_id=UUID(payload["sub"]),
                organization_id=UUID(payload["org"]),
                token_hash=hashlib.sha256(token.encode()).hexdigest(),
                expires_at=datetime.now(UTC) + timedelta(hours=1),
            )
        )
        db.commit()


def test_rotation_keeps_the_original_session_start_and_caps_the_expiry(tenant) -> None:
    client = tenant.client
    login = _login(tenant, tenant.emails["analyst"])
    first = pyjwt.decode(
        login.cookies.get("refresh_token"), settings.secret_key, algorithms=[ALGORITHM]
    )
    _use_cookie(client, login.cookies.get("refresh_token"))
    rotated = client.post("/api/v1/auth/refresh")
    assert rotated.status_code == 200
    second = pyjwt.decode(
        rotated.cookies.get("refresh_token"), settings.secret_key, algorithms=[ALGORITHM]
    )
    assert second["sat"] == first["sat"]
    assert second["exp"] <= first["sat"] + settings.session_max_hours * 3600


# --- changing one's own password -----------------------------------------------------------


def test_own_password_needs_the_current_password(tenant) -> None:
    client = tenant.client
    login = _login(tenant, tenant.emails["analyst"])
    headers = _bearer(login)
    wrong = client.post(
        "/api/v1/auth/password",
        headers=headers,
        json={"current_password": "not-the-password-1", "new_password": NEW_PASSWORD},
    )
    assert wrong.status_code == 401
    assert wrong.json()["error"]["code"] == "invalid_credentials"
    # Nothing changed.
    assert _login(tenant, tenant.emails["analyst"]).status_code == 200


def test_changing_own_password_ends_every_other_session(tenant) -> None:
    client = tenant.client
    email = tenant.emails["analyst"]
    other = _login(tenant, email)
    other_cookie = other.cookies.get("refresh_token")
    current = _login(tenant, email)
    changed = client.post(
        "/api/v1/auth/password",
        headers=_bearer(current),
        json={"current_password": PASSWORD, "new_password": NEW_PASSWORD},
    )
    assert changed.status_code == 200, changed.text
    # The other device's access and refresh tokens are dead...
    assert client.get("/api/v1/auth/me", headers=_bearer(other)).status_code == 401
    _use_cookie(client, other_cookie)
    assert client.post("/api/v1/auth/refresh").status_code == 401
    # ...the caller keeps a working session...
    assert client.get("/api/v1/auth/me", headers=_bearer(changed)).status_code == 200
    # ...and only the new password signs in.
    assert _login(tenant, email).status_code == 401
    assert _login(tenant, email, NEW_PASSWORD).status_code == 200


@pytest.mark.parametrize(
    "weak",
    ["short-1", "aaaaaaaaaaaaaaaa", "password1234", "123456789012", PASSWORD],
)
def test_weak_or_unchanged_passwords_are_refused(tenant, weak: str) -> None:
    login = _login(tenant, tenant.emails["analyst"])
    response = tenant.client.post(
        "/api/v1/auth/password",
        headers=_bearer(login),
        json={"current_password": PASSWORD, "new_password": weak},
    )
    assert response.status_code in {400, 422}


def test_a_password_containing_the_account_name_is_refused(tenant) -> None:
    email = tenant.emails["analyst"]
    login = _login(tenant, email)
    response = tenant.client.post(
        "/api/v1/auth/password",
        headers=_bearer(login),
        json={"current_password": PASSWORD, "new_password": email.split("@")[0] + "!!"},
    )
    assert response.status_code == 400


# --- administrator changes -----------------------------------------------------------------


def _user_id(tenant, role: str) -> str:
    users = tenant.client.get("/api/v1/users", headers=tenant.headers["administrator"]).json()
    return next(u["id"] for u in users["items"] if u["email"] == tenant.emails[role])


def test_an_administrator_cannot_set_their_own_password_through_the_user_list(tenant) -> None:
    client, admin = tenant.client, tenant.headers["administrator"]
    response = client.patch(
        f"/api/v1/users/{_user_id(tenant, 'administrator')}",
        headers=admin,
        json={"password": NEW_PASSWORD, "confirm_password": PASSWORD},
    )
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "use_password_change"
    assert _login(tenant, tenant.emails["administrator"]).status_code == 200


def test_resetting_someone_elses_password_needs_the_administrators_own_password(tenant) -> None:
    client, admin = tenant.client, tenant.headers["administrator"]
    target = _user_id(tenant, "analyst")
    missing = client.patch(
        f"/api/v1/users/{target}", headers=admin, json={"password": NEW_PASSWORD}
    )
    assert missing.status_code == 401
    wrong = client.patch(
        f"/api/v1/users/{target}",
        headers=admin,
        json={"password": NEW_PASSWORD, "confirm_password": "not-my-password-1"},
    )
    assert wrong.status_code == 401
    assert _login(tenant, tenant.emails["analyst"]).status_code == 200
    ok = client.patch(
        f"/api/v1/users/{target}",
        headers=admin,
        json={"password": NEW_PASSWORD, "confirm_password": PASSWORD},
    )
    assert ok.status_code == 200
    assert _login(tenant, tenant.emails["analyst"], NEW_PASSWORD).status_code == 200


def test_new_accounts_follow_the_password_policy(tenant) -> None:
    response = tenant.client.post(
        "/api/v1/users",
        headers=tenant.headers["administrator"],
        json={
            "email": "weak.person@example.test",
            "password": "aaaaaaaaaaaaaaaa",
            "roles": ["analyst"],
        },
    )
    assert response.status_code == 400
