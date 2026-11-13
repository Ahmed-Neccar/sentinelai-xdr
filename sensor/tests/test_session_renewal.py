import sys
from pathlib import Path

import httpx
import pytest

# live_sensor imports its sibling modules by bare name, as it does when run as a script.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from live_sensor import ApiClient, SensorAuthorizationError  # noqa: E402


def client_with(handler) -> tuple[ApiClient, list[str]]:
    """An ApiClient wired to a fake server, without creating key files or signing in."""
    calls: list[str] = []

    def recording(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        return handler(request)

    api = ApiClient.__new__(ApiClient)
    api.base_url = "http://test"
    api.session = httpx.Client(transport=httpx.MockTransport(recording))
    api._email, api._password = "sensor@example.test", "not-a-real-password"
    api.access_token = "old-token"  # noqa: S105 - test value
    return api, calls


def token(value: str) -> httpx.Response:
    return httpx.Response(200, json={"access_token": value})


def test_refresh_is_used_when_the_server_accepts_it() -> None:
    api, calls = client_with(lambda request: token("refreshed"))
    api._renew_access()
    assert api.access_token == "refreshed"  # noqa: S105 - test value
    assert calls == ["/api/v1/auth/refresh"]


def test_signs_in_again_when_the_refresh_cookie_is_not_accepted() -> None:
    # A production server marks the refresh cookie Secure; over plain http the
    # client never sends it back, so refresh answers 401.
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/refresh"):
            return httpx.Response(401, json={"error": {"code": "unauthenticated"}})
        return token("signed-in-again")

    api, calls = client_with(handler)
    api._renew_access()
    assert api.access_token == "signed-in-again"  # noqa: S105 - test value
    assert calls == ["/api/v1/auth/refresh", "/api/v1/auth/login"]


def test_a_revoked_sensor_stops_instead_of_retrying_forever() -> None:
    api, calls = client_with(lambda request: httpx.Response(401, json={}))
    with pytest.raises(SensorAuthorizationError):
        api._renew_access()
    assert calls == ["/api/v1/auth/refresh", "/api/v1/auth/login"]
    assert api.access_token == "old-token"  # noqa: S105 - test value


def test_server_trouble_is_not_mistaken_for_revocation() -> None:
    api, _ = client_with(lambda request: httpx.Response(503))
    with pytest.raises(RuntimeError) as failure:
        api._renew_access()
    assert not isinstance(failure.value, SensorAuthorizationError)

    def throttled(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401) if request.url.path.endswith("/refresh") else httpx.Response(429)

    api, _ = client_with(throttled)
    with pytest.raises(RuntimeError) as failure:
        api._renew_access()
    assert not isinstance(failure.value, SensorAuthorizationError)
