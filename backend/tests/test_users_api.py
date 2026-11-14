from tests.conftest import PASSWORD


def test_only_administrators_manage_users(tenant) -> None:
    client, h = tenant.client, tenant.headers
    assert client.get("/api/v1/users", headers=h["analyst"]).status_code == 403
    assert client.get("/api/v1/users", headers=h["auditor"]).status_code == 403
    listing = client.get("/api/v1/users?page_size=2", headers=h["administrator"])
    assert listing.status_code == 200
    body = listing.json()
    assert body["total"] == 3 and len(body["items"]) == 2 and body["page_size"] == 2
    assert all("hashed_password" not in item for item in body["items"])


def test_create_user_validates_and_the_new_account_can_sign_in(tenant) -> None:
    client, admin = tenant.client, tenant.headers["administrator"]
    payload = {
        "email": "New.Person@Example.test",
        "password": "A-long-enough-password-1",
        "full_name": "New Person",
        "roles": ["analyst"],
    }
    created = client.post("/api/v1/users", headers=admin, json=payload)
    assert created.status_code == 201, created.text
    assert created.json()["email"] == "new.person@example.test"
    assert created.json()["roles"] == ["analyst"]

    assert client.post("/api/v1/users", headers=admin, json=payload).status_code == 409
    assert (
        client.post(
            "/api/v1/users", headers=admin, json={**payload, "email": "x@y.test", "roles": ["root"]}
        ).status_code
        == 400
    )
    assert (
        client.post(
            "/api/v1/users",
            headers=admin,
            json={**payload, "email": "z@y.test", "password": "short"},
        ).status_code
        == 422
    )
    login = client.post(
        "/api/v1/auth/login",
        json={
            "organization_slug": tenant.slug,
            "email": "new.person@example.test",
            "password": payload["password"],
        },
    )
    assert login.status_code == 200


def test_patch_user_changes_roles_password_and_activity(tenant) -> None:
    client, admin = tenant.client, tenant.headers["administrator"]
    users = client.get("/api/v1/users", headers=admin).json()["items"]
    analyst = next(u for u in users if u["email"] == tenant.emails["analyst"])

    changed = client.patch(
        f"/api/v1/users/{analyst['id']}",
        headers=admin,
        json={"roles": ["auditor"], "full_name": "Renamed"},
    )
    assert changed.status_code == 200 and changed.json()["roles"] == ["auditor"]

    reset = client.patch(
        f"/api/v1/users/{analyst['id']}",
        headers=admin,
        json={"password": "Another-long-password-2"},
    )
    assert reset.status_code == 200
    old = client.post(
        "/api/v1/auth/login",
        json={
            "organization_slug": tenant.slug,
            "email": tenant.emails["analyst"],
            "password": PASSWORD,
        },
    )
    assert old.status_code == 401

    disabled = client.patch(
        f"/api/v1/users/{analyst['id']}", headers=admin, json={"is_active": False}
    )
    assert disabled.status_code == 200 and disabled.json()["is_active"] is False
    blocked = client.post(
        "/api/v1/auth/login",
        json={
            "organization_slug": tenant.slug,
            "email": tenant.emails["analyst"],
            "password": "Another-long-password-2",
        },
    )
    assert blocked.status_code == 401

    assert (
        client.patch(
            f"/api/v1/users/{analyst['id']}", headers=admin, json={"roles": ["root"]}
        ).status_code
        == 400
    )
    missing = client.patch(
        "/api/v1/users/00000000-0000-0000-0000-000000000000", headers=admin, json={}
    )
    assert missing.status_code == 404


def test_the_last_active_administrator_cannot_be_removed(tenant) -> None:
    client, admin = tenant.client, tenant.headers["administrator"]
    users = client.get("/api/v1/users", headers=admin).json()["items"]
    me = next(u for u in users if u["email"] == tenant.emails["administrator"])
    for body in ({"is_active": False}, {"roles": ["analyst"]}):
        response = client.patch(f"/api/v1/users/{me['id']}", headers=admin, json=body)
        assert response.status_code in (400, 409), (body, response.text)
    still = client.get("/api/v1/users", headers=admin).json()["items"]
    assert any(u["email"] == tenant.emails["administrator"] and u["is_active"] for u in still)
