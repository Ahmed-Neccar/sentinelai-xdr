"""API-wide protections: every route declares who may call it, and calls are rate limited."""

import pytest
from app.api.v1.router import api_router
from app.core import api_rate_limit
from app.core.config import settings
from fastapi.routing import APIRoute

# Routes that are open to anyone on purpose. A new route that belongs here must be added by
# hand, which is the point: nobody ships an unauthenticated endpoint by forgetting a dependency.
PUBLIC = {
    ("POST", "/auth/login"),
    ("GET", "/auth/oidc/status"),
    ("GET", "/auth/oidc/start"),
    ("GET", "/auth/oidc/callback"),
    ("POST", "/auth/refresh"),
    ("POST", "/auth/mfa/setup"),
    ("POST", "/auth/mfa/setup/confirm"),
    ("POST", "/auth/mfa/verify"),
    ("GET", "/health"),
    ("GET", "/ready"),
    ("GET", "/metrics"),  # needs its own bearer token, checked in the handler
    ("GET", "/scim/v2/ServiceProviderConfig"),
}


def _dependency_names(dependant) -> set[str]:
    names: set[str] = set()
    for dep in dependant.dependencies:
        names.add(getattr(dep.call, "__qualname__", str(dep.call)))
        names |= _dependency_names(dep)
    return names


def _routes() -> list[tuple[str, str, set[str]]]:
    found = []

    def walk(routes) -> None:
        for route in routes:
            if isinstance(route, APIRoute):
                for method in sorted(route.methods - {"HEAD", "OPTIONS"}):
                    found.append((method, route.path, _dependency_names(route.dependant)))
            elif hasattr(route, "original_router"):  # an included router (FastAPI 0.16x)
                walk(route.original_router.routes)
            elif hasattr(route, "routes"):
                walk(route.routes)

    walk(api_router.routes)
    return found


def test_the_route_scan_sees_the_api() -> None:
    assert len(_routes()) > 80


def test_every_route_requires_a_login_or_is_on_the_public_list() -> None:
    open_routes = []
    for method, path, names in _routes():
        guarded = any(
            "get_current_user" in n or "scim_context" in n or n.endswith("dependency")
            for n in names
        )
        if not guarded and (method, path) not in PUBLIC:
            open_routes.append(f"{method} {path}")
    assert open_routes == [], f"routes without an authentication dependency: {open_routes}"


def test_the_public_list_has_no_stale_entries() -> None:
    existing = {(m, p) for m, p, _ in _routes()}
    assert PUBLIC <= existing


# --- rate limiting ---------------------------------------------------------------------------


@pytest.fixture
def limited(monkeypatch):
    monkeypatch.setattr(settings, "api_rate_limit_enabled", True)
    monkeypatch.setattr(settings, "redis_url", None)
    api_rate_limit._local.clear()
    yield
    api_rate_limit._local.clear()


def test_paths_are_classified() -> None:
    assert api_rate_limit.classify("GET", "/api/v1/health") is None
    assert api_rate_limit.classify("POST", "/api/v1/scim/v2/Users") is None
    assert api_rate_limit.classify("GET", "/api/v1/cases") == "normal"
    assert api_rate_limit.classify("POST", "/api/v1/ingest/upload") == "heavy"
    assert api_rate_limit.classify("GET", "/index.html") is None


def test_a_session_that_floods_the_api_is_slowed_down(tenant, monkeypatch, limited) -> None:
    monkeypatch.setattr(settings, "api_session_limit_per_minute", 10)
    headers = tenant.headers["analyst"]
    codes = [tenant.client.get("/api/v1/auth/me", headers=headers).status_code for _ in range(14)]
    assert codes[:10] == [200] * 10
    assert 429 in codes[10:]
    limited_response = tenant.client.get("/api/v1/auth/me", headers=headers)
    assert limited_response.status_code == 429
    assert limited_response.headers["retry-after"] == "60"
    assert limited_response.json()["error"]["code"] == "rate_limited"
    # Another session is not affected by this one's flood.
    other = tenant.headers["auditor"]
    assert tenant.client.get("/api/v1/auth/me", headers=other).status_code == 200


def test_probes_are_never_limited(tenant, monkeypatch, limited) -> None:
    monkeypatch.setattr(settings, "api_address_limit_per_minute", 10)
    monkeypatch.setattr(settings, "api_session_limit_per_minute", 10)
    codes = {tenant.client.get("/api/v1/ready").status_code for _ in range(30)}
    assert 429 not in codes


def test_expensive_calls_have_a_smaller_limit(tenant, monkeypatch, limited) -> None:
    monkeypatch.setattr(settings, "api_heavy_limit_per_minute", 3)
    headers = tenant.headers["auditor"]
    codes = [
        tenant.client.get("/api/v1/audit-logs/export?limit=1", headers=headers).status_code
        for _ in range(6)
    ]
    assert codes[:3] == [200] * 3 and 429 in codes[3:]


def test_the_limiter_is_off_in_development_unless_asked(monkeypatch) -> None:
    monkeypatch.setattr(settings, "api_rate_limit_enabled", None)
    assert api_rate_limit.enabled() is (not settings.is_development)
