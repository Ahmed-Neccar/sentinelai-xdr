from types import SimpleNamespace

from app.models import CloudConnector
from sqlalchemy import select

URL = "/api/v1/cloud-connectors"
TENANT_ID = "11111111-1111-1111-1111-111111111111"
CLIENT_ID = "22222222-2222-2222-2222-222222222222"
SUBSCRIPTION_ID = "33333333-3333-3333-3333-333333333333"
SECRET = "super-secret-client-secret-value"  # noqa: S105 - test value


def _azure(name: str = "azure-prod", secret: str = SECRET) -> dict:
    return {
        "name": name,
        "provider": "azure_activity",
        "config": {
            "tenant_id": TENANT_ID,
            "client_id": CLIENT_ID,
            "subscription_id": SUBSCRIPTION_ID,
        },
        "credentials": {"client_secret": secret},
    }


def _aws(name: str = "aws-prod") -> dict:
    return {
        "name": name,
        "provider": "aws_cloudtrail",
        "config": {"region": "us-east-1"},
        "credentials": {"access_key_id": "AKIAEXAMPLE", "secret_access_key": "example-secret-key"},
    }


def test_connector_secrets_are_encrypted_and_never_returned(tenant) -> None:
    client, h = tenant.client, tenant.headers
    created = client.post(URL, headers=h["administrator"], json=_azure())
    assert created.status_code == 201, created.text
    assert SECRET not in created.text and created.json()["credentials_configured"] is True

    listing = client.get(URL, headers=h["analyst"])
    assert listing.status_code == 200 and SECRET not in listing.text
    assert [c["name"] for c in listing.json()] == ["azure-prod"]
    assert client.get(URL, headers=h["auditor"]).status_code == 403
    assert client.post(URL, headers=h["analyst"], json=_azure("other")).status_code == 403

    with tenant.session() as db:
        stored = db.scalar(select(CloudConnector.credentials_encrypted))
    assert stored and SECRET not in stored


def test_connector_validation(tenant) -> None:
    client, admin = tenant.client, tenant.headers["administrator"]
    assert client.post(URL, headers=admin, json=_azure()).status_code == 201
    assert client.post(URL, headers=admin, json=_azure()).status_code == 409

    wrong_fields = {**_azure("a"), "config": {"tenant_id": TENANT_ID}}
    assert client.post(URL, headers=admin, json=wrong_fields).status_code == 422
    not_uuid = _azure("b")
    not_uuid["config"]["tenant_id"] = "not-a-uuid"
    assert client.post(URL, headers=admin, json=not_uuid).status_code == 422
    wrong_credentials = {**_azure("c"), "credentials": {"password": "x"}}
    assert client.post(URL, headers=admin, json=wrong_credentials).status_code == 422
    empty_secret = {**_azure("d"), "credentials": {"client_secret": ""}}
    assert client.post(URL, headers=admin, json=empty_secret).status_code == 422
    unknown_provider = {**_azure("e"), "provider": "gcp"}
    assert client.post(URL, headers=admin, json=unknown_provider).status_code == 422
    extra_field = {**_azure("f"), "unexpected": True}
    assert client.post(URL, headers=admin, json=extra_field).status_code == 422
    bad_region = _aws("g")
    bad_region["config"]["region"] = "us east 1"
    assert client.post(URL, headers=admin, json=bad_region).status_code == 422
    assert client.post(URL, headers=admin, json=_aws("aws-1")).status_code == 201


def test_connector_lifecycle_replace_disable_revoke_and_poll(tenant, monkeypatch) -> None:
    client, h = tenant.client, tenant.headers
    admin = h["administrator"]
    connector = client.post(URL, headers=admin, json=_azure()).json()
    item = f"{URL}/{connector['id']}"

    queued: list[tuple[str, str]] = []
    from app.workers import tasks

    monkeypatch.setattr(
        tasks.poll_cloud_connector_task,
        "delay",
        lambda connector_id, org_id: queued.append((connector_id, org_id))
        or SimpleNamespace(id="t1"),
    )
    polled = client.post(f"{item}/poll", headers=admin)
    assert polled.status_code == 202 and queued == [(connector["id"], str(tenant.organization_id))]
    assert client.post(f"{item}/poll", headers=admin).status_code == 409  # already queued
    assert client.post(f"{item}/poll", headers=h["analyst"]).status_code == 403

    new_secret = "another-secret-value-123"  # noqa: S105 - test value
    # Credentials cannot be replaced while a poll is running; simulate it finishing.
    assert client.put(item, headers=admin, json=_azure(secret=new_secret)).status_code == 409
    with tenant.session() as db:
        row = db.scalar(select(CloudConnector))
        row.status = "idle"
        db.commit()
    replaced = client.put(item, headers=admin, json=_azure(secret=new_secret))
    assert replaced.status_code == 200, replaced.text
    assert new_secret not in replaced.text

    disabled = client.patch(item, headers=admin, json={"enabled": False})
    assert disabled.status_code == 200 and disabled.json()["status"] == "disabled"
    assert client.post(f"{item}/poll", headers=admin).status_code == 409  # disabled
    enabled = client.patch(item, headers=admin, json={"enabled": True})
    assert enabled.json()["status"] == "idle"

    revoked = client.delete(item, headers=admin)
    assert revoked.status_code == 200
    body = revoked.json()
    assert body["status"] == "revoked" and body["credentials_configured"] is False
    assert client.patch(item, headers=admin, json={"enabled": True}).status_code == 409
    with tenant.session() as db:
        assert db.scalar(select(CloudConnector.credentials_encrypted)) == ""

    missing = f"{URL}/00000000-0000-0000-0000-000000000000"
    assert client.patch(missing, headers=admin, json={"enabled": True}).status_code == 404
    assert client.delete(missing, headers=admin).status_code == 404
    assert client.post(f"{missing}/poll", headers=admin).status_code == 404


def test_a_poll_that_cannot_be_queued_is_reported_as_an_error(tenant, monkeypatch) -> None:
    client, admin = tenant.client, tenant.headers["administrator"]
    connector = client.post(URL, headers=admin, json=_aws()).json()
    from app.workers import tasks

    def broken(*_args):
        raise ConnectionError("broker down")

    monkeypatch.setattr(tasks.poll_cloud_connector_task, "delay", broken)
    response = client.post(f"{URL}/{connector['id']}/poll", headers=admin)
    assert response.status_code == 503
    assert "broker down" not in response.text
    listing = client.get(URL, headers=admin).json()
    assert (
        listing[0]["status"] == "error" and listing[0]["last_error"] == "Poll could not be queued"
    )
