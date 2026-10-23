from pathlib import Path

import pytest
from app.api.v1 import health
from app.core.config import Settings
from app.core.errors import AppError
from app.core.metrics import HttpMetrics
from app.ingestion.normalize import redact
from app.ingestion.parsers import normalize_generic
from app.workers.tasks import safe_upload_path
from pydantic import ValidationError


def test_upload_retention_defaults_and_rejects_values_outside_supported_range() -> None:
    assert Settings(_env_file=None).upload_retention_days == 30
    for value in (0, 3651):
        with pytest.raises(ValidationError):
            Settings(_env_file=None, UPLOAD_RETENTION_DAYS=value)


def test_safe_upload_path_allows_file_inside_upload_root(tmp_path: Path) -> None:
    upload_root = tmp_path / "uploads"
    upload_root.mkdir()
    source = upload_root / "event.json"

    assert safe_upload_path(upload_root, str(source)) == source


def test_safe_upload_path_rejects_parent_escape_and_missing_path(tmp_path: Path) -> None:
    upload_root = tmp_path / "uploads"
    upload_root.mkdir()

    assert safe_upload_path(upload_root, str(tmp_path / "outside.json")) is None
    assert safe_upload_path(upload_root, None) is None


def test_safe_upload_path_rejects_symlinked_parent_escape(tmp_path: Path) -> None:
    upload_root = tmp_path / "uploads"
    outside = tmp_path / "outside"
    upload_root.mkdir()
    outside.mkdir()
    link = upload_root / "linked"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("Directory symlinks are unavailable on this platform")

    assert safe_upload_path(upload_root, str(link / "event.json")) is None


def test_metrics_render_cumulative_histogram_and_escape_labels() -> None:
    metrics = HttpMetrics()
    metrics.observe("GET", '/items/"quoted"\npath', 200, 0.007)

    exposition = metrics.render()
    assert 'route="/items/\\"quoted\\"\\npath"' in exposition
    assert 'sentinel_http_requests_total{method="GET"' in exposition
    assert 'le="0.005"} 0' in exposition
    assert 'le="0.01"} 1' in exposition
    assert 'le="+Inf"} 1' in exposition
    assert "sentinel_http_request_duration_seconds_count" in exposition


def test_metrics_endpoint_is_disabled_and_requires_bearer_token(monkeypatch) -> None:
    monkeypatch.setattr(health.settings, "metrics_token", None)
    with pytest.raises(AppError) as disabled:
        health.metrics(authorization=None)
    assert disabled.value.status_code == 404

    monkeypatch.setattr(health.settings, "metrics_token", "private-test-token")
    with pytest.raises(AppError) as unauthorized:
        health.metrics(authorization="Basic private-test-token")
    assert unauthorized.value.status_code == 401

    response = health.metrics(authorization="Bearer private-test-token")
    assert response.status_code == 200
    assert "sentinel_http_requests_total" in response.body.decode()


def test_windows_account_and_group_metadata_survives_event_normalization() -> None:
    normalized = normalize_generic(
        {
            "event_time": "2026-10-23T10:00:00Z",
            "event_type": "endpoint.identity.group_member_added",
            "group_name": "Administrators",
            "member_name": "S-1-5-21-1234",
            "target_username": "Administrators",
        },
        1,
    )

    assert normalized["attributes"]["group_name"] == "Administrators"
    assert normalized["attributes"]["member_name"] == "S-1-5-21-1234"


def test_import_redaction_covers_nested_camelcase_and_separated_secret_keys() -> None:
    payload = {
        "accessToken": "access-value",
        "client_secret": "client-value",
        "X-API-Key": "api-value",
        "request": {
            "Set-Cookie": "cookie-value",
            "privateKey": "private-value",
            "userName": "analyst",
        },
    }

    sanitized = redact(payload)

    assert sanitized == {
        "accessToken": "[redacted]",
        "client_secret": "[redacted]",
        "X-API-Key": "[redacted]",
        "request": {
            "Set-Cookie": "[redacted]",
            "privateKey": "[redacted]",
            "userName": "analyst",
        },
    }
