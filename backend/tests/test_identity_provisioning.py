"""SSO role mapping, automatic account creation, SCIM provisioning and forced sign-out."""

import json
import re

from app.core import oidc
from app.core.config import settings
from tests.conftest import PASSWORD


def _admin(tenant) -> dict[str, str]:
    return tenant.headers["administrator"]


def _put_settings(tenant, **values) -> None:
    body = {"auto_provision": False, "sync_roles": False, "default_role": None, **values}
    response = tenant.client.put("/api/v1/identity/settings", headers=_admin(tenant), json=body)
    assert response.status_code == 200, response.text


def _map(tenant, claim: str, role: str) -> None:
    response = tenant.client.post(
        "/api/v1/identity/mappings",
        headers=_admin(tenant),
        json={"claim_value": claim, "role_name": role},
    )
    assert response.status_code == 201, response.text


def _scim_token(tenant) -> dict[str, str]:
    created = tenant.client.post(
        "/api/v1/identity/scim-tokens", headers=_admin(tenant), json={"name": "Entra"}
    )
    assert created.status_code == 201, created.text
    return {"Authorization": f"Bearer {created.json()['token']}"}


def _users(tenant) -> list[dict]:
    return tenant.client.get("/api/v1/users?page_size=100", headers=_admin(tenant)).json()["items"]


def _user(tenant, email: str) -> dict | None:
    return next((u for u in _users(tenant) if u["email"] == email), None)


# --- administrator settings -----------------------------------------------------------------


def test_identity_settings_are_for_administrators_only(tenant) -> None:
    client = tenant.client
    for role in ("analyst", "auditor"):
        denied = client.get("/api/v1/identity/settings", headers=tenant.headers[role])
        assert denied.status_code == 403
    body = client.get("/api/v1/identity/settings", headers=_admin(tenant)).json()
    assert body["auto_provision"] is False and body["mappings"] == []


def test_mappings_validate_roles_and_reject_duplicates(tenant) -> None:
    client = tenant.client
    bad = client.post(
        "/api/v1/identity/mappings",
        headers=_admin(tenant),
        json={"claim_value": "g1", "role_name": "root"},
    )
    assert bad.status_code == 400
    _map(tenant, "g1", "analyst")
    again = client.post(
        "/api/v1/identity/mappings",
        headers=_admin(tenant),
        json={"claim_value": "g1", "role_name": "analyst"},
    )
    assert again.status_code == 409
    mappings = client.get("/api/v1/identity/settings", headers=_admin(tenant)).json()["mappings"]
    assert [m["claim_value"] for m in mappings] == ["g1"]
    gone = client.delete(f"/api/v1/identity/mappings/{mappings[0]['id']}", headers=_admin(tenant))
    assert gone.status_code == 200


def test_the_default_role_can_never_be_administrator(tenant) -> None:
    response = tenant.client.put(
        "/api/v1/identity/settings",
        headers=_admin(tenant),
        json={"auto_provision": True, "sync_roles": False, "default_role": "administrator"},
    )
    assert response.status_code == 400


def test_a_scim_token_is_shown_once_and_can_be_revoked(tenant) -> None:
    client = tenant.client
    headers = _scim_token(tenant)
    listing = client.get("/api/v1/identity/settings", headers=_admin(tenant)).json()["scim_tokens"]
    assert len(listing) == 1 and "token" not in listing[0] and not listing[0]["revoked"]
    assert client.get("/api/v1/scim/v2/Users", headers=headers).status_code == 200
    assert (
        client.delete(
            f"/api/v1/identity/scim-tokens/{listing[0]['id']}", headers=_admin(tenant)
        ).status_code
        == 200
    )
    assert client.get("/api/v1/scim/v2/Users", headers=headers).status_code == 401


# --- SCIM -----------------------------------------------------------------------------------


def test_scim_refuses_missing_wrong_and_user_tokens(tenant) -> None:
    client = tenant.client
    assert client.get("/api/v1/scim/v2/Users").status_code == 401
    wrong = {"Authorization": "Bearer nope"}
    assert client.get("/api/v1/scim/v2/Users", headers=wrong).status_code == 401
    forged = {"Authorization": f"Bearer scim_{tenant.organization_id.hex}_{'a' * 43}"}
    assert client.get("/api/v1/scim/v2/Users", headers=forged).status_code == 401
    # A normal user token is not a SCIM token.
    assert client.get("/api/v1/scim/v2/Users", headers=_admin(tenant)).status_code == 401
    # And a SCIM token does not open the normal API.
    token = _scim_token(tenant)
    assert client.get("/api/v1/users", headers=token).status_code == 401


def test_scim_creates_finds_updates_and_disables_a_person(tenant) -> None:
    client = tenant.client
    scim = _scim_token(tenant)
    created = client.post(
        "/api/v1/scim/v2/Users",
        headers=scim,
        json={
            "userName": "New.Hire@Example.test",
            "externalId": "ext-1",
            "name": {"givenName": "New", "familyName": "Hire"},
            "roles": [{"value": "analyst"}],
            "active": True,
        },
    )
    assert created.status_code == 201, created.text
    body = created.json()
    assert body["userName"] == "new.hire@example.test" and body["displayName"] == "New Hire"
    assert body["roles"] == [{"value": "analyst"}] and body["active"] is True
    uid = body["id"]

    assert (
        client.post(
            "/api/v1/scim/v2/Users", headers=scim, json={"userName": "new.hire@example.test"}
        ).status_code
        == 409
    )
    found = client.get(
        '/api/v1/scim/v2/Users?filter=userName eq "NEW.hire@example.test"', headers=scim
    ).json()
    assert found["totalResults"] == 1 and found["Resources"][0]["id"] == uid
    by_external = client.get('/api/v1/scim/v2/Users?filter=externalId eq "ext-1"', headers=scim)
    assert by_external.json()["totalResults"] == 1
    assert client.get("/api/v1/scim/v2/Users?filter=emails co x", headers=scim).status_code == 400

    # Entra sends booleans as strings and uses add/replace operations.
    patched = client.patch(
        f"/api/v1/scim/v2/Users/{uid}",
        headers=scim,
        json={
            "Operations": [
                {"op": "Replace", "path": "displayName", "value": "Renamed Hire"},
                {"op": "Replace", "path": "roles", "value": [{"value": "auditor"}]},
            ]
        },
    )
    assert patched.status_code == 200, patched.text
    assert patched.json()["displayName"] == "Renamed Hire"
    assert patched.json()["roles"] == [{"value": "auditor"}]

    # A provisioned person has no password to sign in with.
    assert (
        client.post(
            "/api/v1/auth/login",
            json={
                "organization_slug": tenant.slug,
                "email": "new.hire@example.test",
                "password": PASSWORD,
            },
        ).status_code
        == 401
    )

    off = client.patch(
        f"/api/v1/scim/v2/Users/{uid}",
        headers=scim,
        json={"Operations": [{"op": "Replace", "path": "active", "value": "False"}]},
    )
    assert off.status_code == 200 and off.json()["active"] is False
    assert client.delete(f"/api/v1/scim/v2/Users/{uid}", headers=scim).status_code == 204
    assert client.get(f"/api/v1/scim/v2/Users/{uid}", headers=scim).json()["active"] is False


def test_scim_disabling_a_person_ends_their_sessions(tenant) -> None:
    client = tenant.client
    scim = _scim_token(tenant)
    analyst = _user(tenant, tenant.emails["analyst"])
    access = tenant.headers["analyst"]
    assert client.get("/api/v1/auth/me", headers=access).status_code == 200
    response = client.patch(
        f"/api/v1/scim/v2/Users/{analyst['id']}",
        headers=scim,
        json={"Operations": [{"op": "replace", "value": {"active": False}}]},
    )
    assert response.status_code == 200
    assert client.get("/api/v1/auth/me", headers=access).status_code == 401


def test_scim_cannot_remove_the_last_administrator(tenant) -> None:
    client = tenant.client
    scim = _scim_token(tenant)
    admin = _user(tenant, tenant.emails["administrator"])
    off = client.patch(
        f"/api/v1/scim/v2/Users/{admin['id']}",
        headers=scim,
        json={"Operations": [{"op": "Replace", "path": "active", "value": False}]},
    )
    assert off.status_code == 409
    demote = client.patch(
        f"/api/v1/scim/v2/Users/{admin['id']}",
        headers=scim,
        json={"Operations": [{"op": "Replace", "path": "roles", "value": [{"value": "auditor"}]}]},
    )
    assert demote.status_code == 409
    assert client.delete(f"/api/v1/scim/v2/Users/{admin['id']}", headers=scim).status_code == 409
    assert _user(tenant, tenant.emails["administrator"])["is_active"] is True


def test_scim_uses_the_default_role_when_none_is_sent(tenant) -> None:
    _put_settings(tenant, default_role="auditor")
    scim = _scim_token(tenant)
    created = tenant.client.post(
        "/api/v1/scim/v2/Users", headers=scim, json={"userName": "dflt@example.test"}
    )
    assert created.json()["roles"] == [{"value": "auditor"}]


# --- forced sign-out ------------------------------------------------------------------------


def test_an_administrator_can_sign_a_person_out_everywhere(tenant) -> None:
    client = tenant.client
    analyst = _user(tenant, tenant.emails["analyst"])
    access = tenant.headers["analyst"]
    assert client.get("/api/v1/auth/me", headers=access).status_code == 200
    assert (
        client.post(f"/api/v1/users/{analyst['id']}/sign-out", headers=tenant.headers["analyst"])
        .status_code
        == 403
    )
    done = client.post(f"/api/v1/users/{analyst['id']}/sign-out", headers=_admin(tenant))
    assert done.status_code == 200
    assert client.get("/api/v1/auth/me", headers=access).status_code == 401
    # The account itself still works: they can simply sign in again.
    login = client.post(
        "/api/v1/auth/login",
        json={
            "organization_slug": tenant.slug,
            "email": tenant.emails["analyst"],
            "password": PASSWORD,
        },
    )
    assert login.status_code == 200


# --- single sign-on -------------------------------------------------------------------------


def _sso_login(tenant, monkeypatch, *, email: str, groups: list[str], subject: str = "sub-1"):
    """Run the SSO callback with a provider that returns this identity."""
    monkeypatch.setattr(settings, "oidc_issuer", "https://idp.example.test/")
    monkeypatch.setattr(
        oidc,
        "read_transaction",
        lambda transaction, state: {
            "organization_slug": tenant.slug,
            "verifier": "v",
            "nonce": "n",
        },
    )
    monkeypatch.setattr(
        oidc,
        "exchange_and_validate",
        lambda code, verifier, nonce: {
            "subject": subject,
            "email": email,
            "name": "Sso Person",
            "groups": groups,
        },
    )
    tenant.client.cookies.set(oidc.TRANSACTION_COOKIE, "x", path="/api/v1/auth/oidc")
    response = tenant.client.get(f"/api/v1/auth/oidc/callback?state={'s' * 24}&code=abc")
    match = re.search(r'id="oidc-result" type="application/json">(.*?)</script>', response.text)
    assert match, response.text
    return json.loads(match.group(1))


def test_sso_does_not_create_accounts_unless_the_organization_allows_it(
    tenant, monkeypatch
) -> None:
    _map(tenant, "soc-analysts", "analyst")
    result = _sso_login(tenant, monkeypatch, email="stranger@example.test", groups=["soc-analysts"])
    assert result.get("type") == "sentinelai-sso-error"
    assert _user(tenant, "stranger@example.test") is None


def test_sso_creates_an_account_with_the_roles_of_the_persons_groups(tenant, monkeypatch) -> None:
    _put_settings(tenant, auto_provision=True)
    _map(tenant, "soc-analysts", "analyst")
    _map(tenant, "soc-readers", "auditor")
    result = _sso_login(
        tenant,
        monkeypatch,
        email="joiner@example.test",
        groups=["soc-analysts", "unrelated-group"],
    )
    assert result.get("type") == "sentinelai-sso-result", result
    assert result["user"]["roles"] == ["analyst"]
    created = _user(tenant, "joiner@example.test")
    assert created["roles"] == ["analyst"] and created["sso_linked"] is True


def test_sso_refuses_a_new_person_whose_groups_map_to_nothing(tenant, monkeypatch) -> None:
    _put_settings(tenant, auto_provision=True)
    _map(tenant, "soc-analysts", "analyst")
    result = _sso_login(tenant, monkeypatch, email="nogroup@example.test", groups=["other"])
    assert result.get("type") == "sentinelai-sso-error"
    assert _user(tenant, "nogroup@example.test") is None


def test_sso_uses_the_default_role_when_no_group_matches(tenant, monkeypatch) -> None:
    _put_settings(tenant, auto_provision=True, default_role="auditor")
    result = _sso_login(tenant, monkeypatch, email="dflt@example.test", groups=[])
    assert result["user"]["roles"] == ["auditor"]


def test_sso_keeps_roles_in_step_with_groups_only_when_syncing_is_on(tenant, monkeypatch) -> None:
    _map(tenant, "soc-readers", "auditor")
    email = tenant.emails["analyst"]
    before = _sso_login(tenant, monkeypatch, email=email, groups=["soc-readers"])
    assert before["user"]["roles"] == ["analyst"]  # sync is off: nothing changes
    _put_settings(tenant, sync_roles=True)
    after = _sso_login(tenant, monkeypatch, email=email, groups=["soc-readers"])
    assert after["user"]["roles"] == ["auditor"]
    # No mapped group at all leaves the roles alone instead of locking the person out.
    still = _sso_login(tenant, monkeypatch, email=email, groups=["unmapped"])
    assert still["user"]["roles"] == ["auditor"]


def test_sso_sync_never_demotes_the_last_administrator(tenant, monkeypatch) -> None:
    _put_settings(tenant, sync_roles=True)
    _map(tenant, "soc-readers", "auditor")
    email = tenant.emails["administrator"]
    result = _sso_login(tenant, monkeypatch, email=email, groups=["soc-readers"])
    assert result["user"]["roles"] == ["administrator"]


def test_group_claims_are_read_defensively() -> None:
    from app.core.identity import groups_from_claims

    assert groups_from_claims({"groups": ["a", "b"], "roles": ["b", "c"]}) == ["a", "b", "c"]
    assert groups_from_claims({"groups": "not-a-list", "roles": [1, None, "", "ok"]}) == ["ok"]
    assert groups_from_claims({"groups": ["x" * 256]}) == []
    assert len(groups_from_claims({"groups": [str(n) for n in range(500)]})) == 200


def test_scim_cannot_grant_the_administrator_role(tenant) -> None:
    scim = _scim_token(tenant)
    created = tenant.client.post(
        "/api/v1/scim/v2/Users",
        headers=scim,
        json={"userName": "wannabe@example.test", "roles": [{"value": "administrator"}]},
    )
    assert created.status_code == 201
    assert created.json()["roles"] == []
    analyst = _user(tenant, tenant.emails["analyst"])
    promoted = tenant.client.patch(
        f"/api/v1/scim/v2/Users/{analyst['id']}",
        headers=scim,
        json={
            "Operations": [
                {"op": "Replace", "path": "roles", "value": [{"value": "administrator"}]}
            ]
        },
    )
    assert promoted.status_code == 200
    assert promoted.json()["roles"] == [{"value": "analyst"}]
