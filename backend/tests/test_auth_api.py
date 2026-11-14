import time

from app.core.security import burn_password_check
from tests.conftest import PASSWORD


def _login(tenant, email: str, password: str):
    return tenant.client.post(
        "/api/v1/auth/login",
        json={"organization_slug": tenant.slug, "email": email, "password": password},
    )


def test_failed_sign_ins_look_the_same_for_unknown_and_known_accounts(tenant) -> None:
    unknown = _login(tenant, "nobody@example.test", "whatever-password-1")
    wrong = _login(tenant, tenant.emails["analyst"], "whatever-password-1")
    assert unknown.status_code == wrong.status_code == 401
    assert unknown.json() == wrong.json()
    missing_org = tenant.client.post(
        "/api/v1/auth/login",
        json={"organization_slug": "no-such-org", "email": "a@b.test", "password": "x" * 12},
    )
    assert missing_org.status_code == 401


def test_unknown_accounts_cost_a_password_check(monkeypatch) -> None:
    calls = []
    monkeypatch.setattr(
        "app.core.security.password_hasher.verify", lambda password, hashed: calls.append(hashed)
    )
    burn_password_check("anything")
    assert len(calls) == 1


def test_unknown_and_inactive_accounts_are_not_noticeably_faster(tenant) -> None:
    admin = tenant.headers["administrator"]
    users = tenant.client.get("/api/v1/users", headers=admin).json()["items"]
    analyst = next(u for u in users if u["email"] == tenant.emails["analyst"])
    tenant.client.patch(f"/api/v1/users/{analyst['id']}", headers=admin, json={"is_active": False})

    def best_of(email: str) -> float:
        timings = []
        for _ in range(3):
            started = time.perf_counter()
            _login(tenant, email, PASSWORD)
            timings.append(time.perf_counter() - started)
        return min(timings)

    real = best_of(
        tenant.emails["auditor"]
    )  # real account, wrong role irrelevant: correct password
    unknown = best_of("nobody@example.test")
    inactive = best_of(tenant.emails["analyst"])
    # Password hashing dominates; an account that skips it would be ten times faster or more.
    assert unknown > real * 0.3 and inactive > real * 0.3


def test_refresh_rotation_logout_and_me(tenant) -> None:
    client = tenant.client
    login = _login(tenant, tenant.emails["analyst"], PASSWORD)
    assert login.status_code == 200
    cookie = login.cookies.get("refresh_token")
    assert cookie
    access = {"Authorization": f"Bearer {login.json()['access_token']}"}

    me = client.get("/api/v1/auth/me", headers=access).json()
    assert me["email"] == tenant.emails["analyst"] and me["roles"] == ["analyst"]
    assert client.get("/api/v1/auth/me").status_code == 401
    assert (
        client.get("/api/v1/auth/me", headers={"Authorization": "Bearer not.a.token"}).status_code
        == 401
    )

    client.cookies.set("refresh_token", cookie, path="/api/v1/auth")
    first = client.post("/api/v1/auth/refresh")
    assert first.status_code == 200, first.text
    # The used refresh token is revoked; presenting it again fails.
    client.cookies.clear()
    client.cookies.set("refresh_token", cookie, path="/api/v1/auth")
    assert client.post("/api/v1/auth/refresh").status_code == 401

    client.cookies.clear()
    assert client.post("/api/v1/auth/refresh").status_code == 401
    new_cookie = first.cookies.get("refresh_token")
    client.cookies.set("refresh_token", new_cookie, path="/api/v1/auth")
    fresh = {"Authorization": f"Bearer {first.json()['access_token']}"}
    assert client.post("/api/v1/auth/logout", headers=fresh).status_code == 200
    client.cookies.clear()
    client.cookies.set("refresh_token", new_cookie, path="/api/v1/auth")
    assert client.post("/api/v1/auth/refresh").status_code == 401
    client.cookies.clear()


def test_a_token_from_before_a_password_reset_stops_working(tenant) -> None:
    client = tenant.client
    login = _login(tenant, tenant.emails["analyst"], PASSWORD)
    access = {"Authorization": f"Bearer {login.json()['access_token']}"}
    assert client.get("/api/v1/auth/me", headers=access).status_code == 200
    admin = tenant.headers["administrator"]
    users = client.get("/api/v1/users", headers=admin).json()["items"]
    analyst = next(u for u in users if u["email"] == tenant.emails["analyst"])
    reset = client.patch(
        f"/api/v1/users/{analyst['id']}",
        headers=admin,
        json={"password": "Brand-new-password-3", "confirm_password": PASSWORD},
    )
    assert reset.status_code == 200
    assert client.get("/api/v1/auth/me", headers=access).status_code == 401


def test_repeated_failures_are_throttled(tenant) -> None:
    from app.core import auth_rate_limit

    auth_rate_limit._local.clear()  # the fixture itself signed in a few times
    codes = [
        _login(tenant, tenant.emails["auditor"], "wrong-password-1").status_code for _ in range(14)
    ]
    assert codes[:12] == [401] * 12
    assert 429 in codes[12:]
    # The throttle is per account: the correct password is refused while it is active.
    assert _login(tenant, tenant.emails["auditor"], PASSWORD).status_code == 429


def test_only_a_genuine_access_token_is_accepted_as_a_bearer_token(tenant) -> None:
    import jwt as pyjwt
    from app.core.config import settings
    from app.core.security import ALGORITHM, create_refresh_token

    client = tenant.client
    login = _login(tenant, tenant.emails["analyst"], PASSWORD)
    access = login.json()["access_token"]
    claims = pyjwt.decode(access, settings.secret_key, algorithms=[ALGORITHM])

    def me(token: str):
        return client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})

    assert me(access).status_code == 200
    refresh, _ = create_refresh_token(
        user_id=claims["sub"], organization_id=claims["org"], token_version=claims["tv"]
    )
    assert me(refresh).status_code == 401  # a refresh token is not an access token
    forged = pyjwt.encode(claims, "x" * 40, algorithm=ALGORITHM)
    assert me(forged).status_code == 401  # signed with another key
    unsigned = pyjwt.encode(claims, "", algorithm="none")
    assert me(unsigned).status_code == 401
    expired = pyjwt.encode({**claims, "exp": 1}, settings.secret_key, algorithm=ALGORITHM)
    expired_response = me(expired)
    assert expired_response.status_code == 401
    assert expired_response.json()["error"]["code"] == "token_expired"
    other_org = pyjwt.encode(
        {**claims, "org": "00000000-0000-0000-0000-000000000000"},
        settings.secret_key,
        algorithm=ALGORITHM,
    )
    assert me(other_org).status_code == 401
