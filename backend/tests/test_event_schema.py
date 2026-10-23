import pytest
from app.ingestion.parsers import ADAPTERS, RowError, validate_normalized_event


def test_all_ingestion_adapters_produce_valid_schema_v1_events() -> None:
    samples = {
        "generic_json": {"event_time": "2026-10-23T10:00:00Z", "event_type": "net.conn"},
        "generic_csv": {"event_time": "2026-10-23T10:00:00Z", "event_type": "net.conn"},
        "zeek_json": {
            "ts": "2026-10-23T10:00:00Z",
            "uid": "C-test",
            "id": {"orig_h": "192.0.2.10", "resp_h": "192.0.2.20", "orig_p": 50000, "resp_p": 443},
            "proto": "tcp",
        },
        "suricata_eve": {
            "timestamp": "2026-10-23T10:00:00Z",
            "event_type": "alert",
            "src_ip": "192.0.2.10",
            "dest_ip": "192.0.2.20",
            "src_port": 50000,
            "dest_port": 443,
            "proto": "TCP",
            "alert": {"severity": 1, "signature": "Example alert"},
        },
        "aws_cloudtrail": {
            "eventTime": "2026-10-23T10:00:00Z",
            "eventName": "ConsoleLogin",
            "eventSource": "signin.amazonaws.com",
        },
        "azure_activity": {
            "eventTimestamp": "2026-10-23T10:00:00Z",
            "operationName": "Microsoft.Authorization/roleAssignments/write",
        },
        "entra_signin": {
            "createdDateTime": "2026-10-23T10:00:00Z",
            "status": {"errorCode": 0},
        },
    }

    for adapter, raw in samples.items():
        normalized = ADAPTERS[adapter](raw, 1)
        validated = validate_normalized_event(normalized, 1)
        assert validated["schema_version"] == 1
        assert validated["event_time"].utcoffset().total_seconds() == 0


def test_schema_validation_quarantines_bad_fields_without_echoing_values() -> None:
    normalized = ADAPTERS["generic_json"](
        {"event_time": "2026-10-23T10:00:00Z", "event_type": "net.conn"}, 1
    )
    normalized.update({"src_ip": "not-an-ip", "dst_port": 70000, "schema_version": 2})

    with pytest.raises(RowError) as error:
        validate_normalized_event(normalized, 7)

    assert error.value.row_number == 7
    assert "src_ip" in error.value.message
    assert "dst_port" in error.value.message
    assert "schema_version" in error.value.message
    assert "not-an-ip" not in error.value.message


def test_zeek_connection_uid_is_not_misclassified_as_endpoint_host() -> None:
    event = ADAPTERS["zeek_json"](
        {
            "ts": "2026-10-23T10:00:00Z",
            "uid": "C-unique-connection",
            "id": {"orig_h": "192.0.2.10", "resp_h": "192.0.2.20"},
        },
        1,
    )

    assert event["host_id"] is None
    assert event["attributes"]["connection_id"] == "C-unique-connection"
    assert event["dedup_key"] == "C-unique-connection"


def test_suricata_source_host_context_is_not_endpoint_identity() -> None:
    event = ADAPTERS["suricata_eve"](
        {
            "timestamp": "2026-10-23T10:00:00Z",
            "event_type": "alert",
            "host": "sensor-east",
            "src_ip": "192.0.2.10",
            "dest_ip": "192.0.2.20",
        },
        1,
    )

    assert event["host_id"] is None
    assert event["attributes"]["source_host_context"] == "sensor-east"
