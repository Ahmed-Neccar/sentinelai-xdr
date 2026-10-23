from datetime import UTC, datetime
from typing import Any

import httpx
import pytest
from app.api.v1.connectors import ConnectorInput
from app.connectors import cloud
from app.connectors.cloud import poll_cloud_events
from app.connectors.secrets import decrypt_credentials, encrypt_credentials
from cryptography.exceptions import InvalidTag
from pydantic import ValidationError


def test_connector_input_accepts_provider_scoped_minimum_permissions() -> None:
    payload = ConnectorInput.model_validate(
        {
            "name": "AWS audit",
            "provider": "aws_cloudtrail",
            "config": {"region": "eu-central-1"},
            "credentials": {"access_key_id": "AKIAEXAMPLE", "secret_access_key": "private"},
        }
    )
    assert payload.provider == "aws_cloudtrail"


def test_connector_input_rejects_unknown_provider_secrets() -> None:
    with pytest.raises(ValidationError):
        ConnectorInput.model_validate(
            {
                "name": "Entra",
                "provider": "entra_signin",
                "config": {"tenant_id": "tenant", "client_id": "client"},
                "credentials": {"client_secret": "private", "refresh_token": "unneeded"},
            }
        )


def test_cloud_credentials_are_authenticated_and_encrypted() -> None:
    credentials = {"client_secret": "do-not-store-in-cleartext"}
    ciphertext = encrypt_credentials(credentials)
    assert credentials["client_secret"] not in ciphertext
    assert decrypt_credentials(ciphertext) == credentials
    with pytest.raises(InvalidTag):
        decrypt_credentials(ciphertext[:-4] + "AAAA")


def test_azure_activity_poll_uses_read_only_api_and_returns_events(monkeypatch) -> None:
    seen: list[httpx.Request] = []
    real_client = httpx.Client

    def respond(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.url.host == "login.microsoftonline.com":
            return httpx.Response(200, json={"access_token": "test-token"}, request=request)
        return httpx.Response(
            200,
            json={
                "value": [
                    {
                        "eventTimestamp": "2026-10-23T10:00:00Z",
                        "operationName": "role.write",
                    }
                ]
            },
            request=request,
        )

    monkeypatch.setattr(
        "app.connectors.cloud.httpx.Client",
        lambda **kwargs: real_client(transport=httpx.MockTransport(respond), **kwargs),
    )
    events, checkpoint, truncated = poll_cloud_events(
        "azure_activity",
        {
            "tenant_id": "tenant-id",
            "client_id": "client-id",
            "subscription_id": "subscription-id",
        },
        {"client_secret": "secret"},
        datetime(2026, 10, 23, 9, 55, tzinfo=UTC),
        datetime(2026, 10, 23, 10, 5, tzinfo=UTC),
    )
    assert events[0]["operationName"] == "role.write"
    assert checkpoint == datetime(2026, 10, 23, 10, 5, tzinfo=UTC)
    assert not truncated
    assert seen[1].url.host == "management.azure.com"
    assert seen[1].headers["Authorization"] == "Bearer test-token"
    assert seen[1].url.params.get("api-version") == "2015-04-01"


def test_aws_cloudtrail_poll_uses_lookup_events_with_explicit_credentials(monkeypatch) -> None:
    seen: dict[str, Any] = {}

    class FakeCloudTrail:
        def lookup_events(self, **kwargs: Any) -> dict[str, Any]:
            seen["lookup"] = kwargs
            return {
                "Events": [
                    {
                        "CloudTrailEvent": (
                            '{"eventID":"evt-1","eventTime":"2026-10-23T10:00:00Z",'
                            '"eventName":"ConsoleLogin","eventSource":"signin.amazonaws.com"}'
                        )
                    }
                ]
            }

    class FakeSession:
        def __init__(self, **kwargs: Any) -> None:
            seen["credentials"] = kwargs

        def client(self, service: str, config: Any) -> FakeCloudTrail:
            seen["service"] = service
            return FakeCloudTrail()

    monkeypatch.setattr(cloud.boto3, "Session", FakeSession)
    events, checkpoint, truncated = poll_cloud_events(
        "aws_cloudtrail",
        {"region": "eu-central-1"},
        {"access_key_id": "access", "secret_access_key": "secret"},
        datetime(2026, 10, 23, 9, 55, tzinfo=UTC),
        datetime(2026, 10, 23, 10, 5, tzinfo=UTC),
    )
    assert events[0]["eventID"] == "evt-1"
    assert checkpoint == datetime(2026, 10, 23, 10, 5, tzinfo=UTC)
    assert not truncated
    assert seen["service"] == "cloudtrail"
    assert seen["credentials"]["aws_access_key_id"] == "access"
    assert seen["credentials"]["aws_secret_access_key"] == "secret"  # noqa: S105
    assert "StartTime" in seen["lookup"] and "EndTime" in seen["lookup"]


def test_pagination_cannot_redirect_to_an_untrusted_host(monkeypatch) -> None:
    real_client = httpx.Client

    def respond(request: httpx.Request) -> httpx.Response:
        if request.url.host == "login.microsoftonline.com":
            return httpx.Response(200, json={"access_token": "test-token"}, request=request)
        return httpx.Response(
            200,
            json={"value": [], "@odata.nextLink": "https://attacker.example/collect"},
            request=request,
        )

    monkeypatch.setattr(
        "app.connectors.cloud.httpx.Client",
        lambda **kwargs: real_client(transport=httpx.MockTransport(respond), **kwargs),
    )
    from app.connectors.cloud import CloudPollError

    with pytest.raises(CloudPollError, match="unexpected pagination host"):
        poll_cloud_events(
            "entra_signin",
            {"tenant_id": "tenant", "client_id": "client"},
            {"client_secret": "secret"},
            datetime(2026, 10, 23, 9, 55, tzinfo=UTC),
            datetime(2026, 10, 23, 10, 5, tzinfo=UTC),
        )
