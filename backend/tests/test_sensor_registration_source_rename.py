from types import SimpleNamespace
from uuid import uuid4

from app.api.v1.ingest import LiveCaptureStart, start_live_capture
from app.schemas.common import TokenUser


class Result:
    def __init__(self, rows):
        self.rows = rows

    def all(self):
        return self.rows


class FakeDb:
    def __init__(self, registration, source):
        self.registration = registration
        self.source = source
        self.scalar_calls = 0
        self.added = []

    def scalar(self, _statement):
        self.scalar_calls += 1
        # Source-name lookup, registration, prior owned session,
        # then duplicate-source and recent-session checks.
        return {
            1: None,
            2: self.registration,
            3: None,
            4: None,
            5: None,
        }[self.scalar_calls]

    def scalars(self, _statement):
        return Result([self.source])

    def get(self, _model, _key):
        return self.source

    def add(self, value):
        self.added.append(value)

    def flush(self):
        pass

    def commit(self):
        pass

    def refresh(self, _value):
        pass


def test_registered_sensor_reuses_source_when_controller_name_changes(monkeypatch) -> None:
    sensor_id = uuid4()
    user_id = uuid4()
    source_id = uuid4()
    source = SimpleNamespace(
        id=source_id,
        name="Ahmed-live-sensor",
        source_type="host_packet_headers",
        config={
            "sensor_id": str(sensor_id),
            "sensor_credential_user_id": str(user_id),
        },
    )
    registration = SimpleNamespace(
        sensor_id=sensor_id,
        credential_user_id=user_id,
        data_source_id=source_id,
        status="active",
        last_seen_at=None,
    )
    db = FakeDb(registration, source)
    actor = TokenUser(
        id=user_id,
        organization_id=uuid4(),
        email="sensor@example.local",
        full_name="",
        roles=["ingestion_service"],
        is_active=True,
    )
    request = SimpleNamespace(client=SimpleNamespace(host="127.0.0.1"))
    monkeypatch.setattr("app.api.v1.ingest.write_audit", lambda *_a, **_kw: None)
    monkeypatch.setattr("app.api.v1.ingest.client_ip", lambda _request: "127.0.0.1")

    result = start_live_capture(
        LiveCaptureStart(
            source_name=f"Ahmed-live-sensor-{str(sensor_id)[:8]}",
            sensor_id=str(sensor_id),
            host_name="Ahmed",
            sensor_version="0.3.0",
            capabilities=["network.headers"],
        ),
        db,
        actor,
        request,
    )

    assert result["data_source_id"] == source_id
    assert source.name == "Ahmed-live-sensor"
