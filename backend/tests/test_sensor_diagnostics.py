import pytest
from app.api.v1.ingest import LiveCaptureDiagnostics
from pydantic import ValidationError


def test_sensor_diagnostics_accept_bounded_observed_coverage() -> None:
    diagnostics = LiveCaptureDiagnostics.model_validate(
        {
            "interface": "Wi-Fi",
            "events_forwarded": 12,
            "event_counts": {"net.conn": 8, "auth.success": 4},
            "windows_event_ids_seen": [4624, 4688],
            "last_event_forwarded_at": "2026-10-23T10:00:00Z",
            "windows_collection_state": "enabled",
        }
    )

    assert diagnostics.events_forwarded == 12
    assert diagnostics.windows_event_ids_seen == [4624, 4688]


@pytest.mark.parametrize(
    "payload",
    [
        {"events_forwarded": -1},
        {"windows_collection_state": "healthy-even-if-not"},
        {"event_counts": {"x" * 65: 1}},
        {"windows_event_ids_seen": [4688, 70000]},
        {"windows_event_ids_configured": [4688, 4688]},
        {"unrecognized_secret": "must not be accepted"},
    ],
)
def test_sensor_diagnostics_reject_invalid_or_unbounded_payloads(payload: dict) -> None:
    with pytest.raises(ValidationError):
        LiveCaptureDiagnostics.model_validate(payload)
