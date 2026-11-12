import importlib.util
import json
from pathlib import Path

import httpx
import pytest

_PATH = Path(__file__).resolve().parents[2] / "scripts" / "create_sensor_account.py"
_SPEC = importlib.util.spec_from_file_location("create_sensor_account", _PATH)
assert _SPEC and _SPEC.loader
tool = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(tool)

ADMIN_PASSWORD = "admin-test-password"  # noqa: S105 - test value
SENSOR_PASSWORD = "sensor-test-password"  # noqa: S105 - test value


def _client(handler) -> httpx.Client:
    return httpx.Client(base_url="http://test", transport=httpx.MockTransport(handler))


def _token(roles: list[str]) -> dict:
    return {"access_token": "token-abc", "expires_in": 900, "user": {"roles": roles}}


def test_creates_an_ingestion_only_account() -> None:
    seen: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        if request.url.path == "/api/v1/auth/login":
            return httpx.Response(200, json=_token(["administrator"]))
        seen.update(body, authorization=request.headers["authorization"])
        return httpx.Response(
            201, json={"id": "1", "email": body["email"], "roles": body["roles"]}
        )

    with _client(handler) as client:
        token = tool.administrator_token(
            client, "admin@localhost.local", ADMIN_PASSWORD, "default", lambda: "000000"
        )
        created = tool.create_sensor_account(
            client, token, "sensor-vm@localhost.local", SENSOR_PASSWORD, "VM"
        )
    assert created["email"] == "sensor-vm@localhost.local"
    assert seen["roles"] == ["ingestion_service"]
    assert seen["authorization"] == "Bearer token-abc"


def test_completes_an_mfa_challenge() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v1/auth/login":
            return httpx.Response(
                200,
                json={
                    "mfa_required": True,
                    "mfa_setup_required": False,
                    "challenge_token": "c" * 30,
                },
            )
        assert json.loads(request.content) == {"challenge_token": "c" * 30, "code": "123456"}
        return httpx.Response(200, json=_token(["administrator"]))

    with _client(handler) as client:
        token = tool.administrator_token(client, "a@b", ADMIN_PASSWORD, "default", lambda: "123456")
    assert token == "token-abc"  # noqa: S105 - test value


def test_rejects_a_non_administrator() -> None:
    with _client(lambda request: httpx.Response(200, json=_token(["analyst"]))) as client:
        with pytest.raises(tool.AccountError, match="Only an administrator"):
            tool.administrator_token(client, "a@b", ADMIN_PASSWORD, "default", lambda: "")


def test_errors_never_echo_a_password() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v1/auth/login":
            return httpx.Response(
                401, json={"error": {"code": "invalid_credentials", "message": "Invalid email"}}
            )
        return httpx.Response(409, json={"error": {"code": "conflict", "message": "exists"}})

    with _client(handler) as client:
        with pytest.raises(tool.AccountError) as login_error:
            tool.administrator_token(client, "a@b", ADMIN_PASSWORD, "default", lambda: "")
        with pytest.raises(tool.AccountError) as conflict:
            tool.create_sensor_account(client, "t", "s@b", SENSOR_PASSWORD, "")
        with pytest.raises(tool.AccountError, match="at least 12"):
            tool.create_sensor_account(client, "t", "s@b", "short", "")
    assert "Invalid email" in str(login_error.value)
    assert "already exists" in str(conflict.value)
    assert ADMIN_PASSWORD not in str(login_error.value)
    assert SENSOR_PASSWORD not in str(conflict.value)
