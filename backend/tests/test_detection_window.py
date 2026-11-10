from datetime import UTC, datetime
from types import SimpleNamespace
from uuid import uuid4

from app.detection import run
from app.detection.run import event_to_dict, load_detection_window, window_row_to_dict
from sqlalchemy.dialects import postgresql


def _event(**overrides) -> SimpleNamespace:
    values = {
        "id": uuid4(),
        "event_time": datetime(2026, 11, 10, 9, 0, tzinfo=UTC),
        "event_type": "auth.failure",
        "src_ip": "198.51.100.24",
        "dst_ip": None,
        "src_port": 51000,
        "dst_port": 22,
        "host_id": "lab-auth-01",
        "severity": "low",
        "attributes": {"username": "analyst-demo", "logon_type": 3},
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def test_window_rows_match_the_previous_entity_representation() -> None:
    for event in (
        _event(),
        _event(src_ip=None, attributes=None, dst_ip="192.0.2.7"),
        _event(event_type="net.conn", attributes={}),
    ):
        assert window_row_to_dict(event) == event_to_dict(event)


class _RecordingSession:
    def __init__(self, rows: list) -> None:
        self.rows, self.statement = rows, None

    def execute(self, statement):
        self.statement = statement
        return iter(self.rows)


def test_window_query_selects_only_detector_columns_and_keeps_both_conditions() -> None:
    session = _RecordingSession([_event(), _event(event_type="net.conn")])
    job_id = uuid4()
    result = load_detection_window(session, job_id, datetime(2026, 11, 10, 7, 0, tzinfo=UTC))
    sql = str(session.statement.compile(dialect=postgresql.dialect()))
    selected = sql.split("FROM")[0]

    assert [item["event_type"] for item in result] == ["auth.failure", "net.conn"]
    assert "raw_payload" not in sql and "dedup_key" not in sql
    assert "security_events.attributes" in selected
    assert "security_events.event_time >=" in sql
    assert "security_events.ingestion_job_id =" in sql and " OR " in sql


def test_detection_is_skipped_when_the_job_has_no_events(monkeypatch) -> None:
    def fail(*_args, **_kwargs):
        raise AssertionError("the window must not be loaded for an empty job")

    monkeypatch.setattr(run, "load_detection_window", fail)
    session = SimpleNamespace(scalar=lambda _statement: None)
    assert run.run_detection_for_job(session, uuid4()) == 0
