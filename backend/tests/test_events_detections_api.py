from datetime import UTC, datetime, timedelta
from urllib.parse import quote

from app.core.bootstrap import seed_rules
from app.models import Detection, DetectionEvidence, SecurityEvent

NOW = datetime(2026, 11, 14, 12, 0, tzinfo=UTC)


def _seed_events(tenant) -> list[SecurityEvent]:
    rows = [
        ("auth.failure", "10.0.0.1", "10.0.9.1", "pc-1", "high", NOW - timedelta(hours=3)),
        ("auth.failure", "10.0.0.2", "10.0.9.1", "pc-2", "low", NOW - timedelta(hours=2)),
        ("net.conn", "10.0.0.1", "8.8.8.8", "pc-1", "informational", NOW - timedelta(hours=1)),
        ("dns.query", "10.0.0.3", None, "server-1", "informational", NOW),
    ]
    events = [
        SecurityEvent(
            event_time=when,
            event_type=kind,
            src_ip=src,
            dst_ip=dst,
            host_id=host,
            severity=severity,
            attributes={"note": kind},
            raw_payload={"raw": True},
            dedup_key=f"seed-{i}",
        )
        for i, (kind, src, dst, host, severity, when) in enumerate(rows)
    ]
    with tenant.session() as db:
        db.add_all(events)
        db.commit()
        for event in events:
            db.refresh(event)
    return events


def test_event_listing_filters_pagination_and_detail(tenant) -> None:
    client, h = tenant.client, tenant.headers["analyst"]
    events = _seed_events(tenant)

    def ids(query: str) -> list[str]:
        response = client.get(f"/api/v1/events?{query}", headers=h)
        assert response.status_code == 200, response.text
        return [
            item["event_type"] + "@" + str(item["host_id"]) for item in response.json()["items"]
        ]

    everything = client.get("/api/v1/events?page_size=2", headers=h).json()
    assert everything["total"] == 4 and len(everything["items"]) == 2
    assert everything["items"][0]["event_type"] == "dns.query"  # newest first
    assert len(client.get("/api/v1/events?page=2&page_size=3", headers=h).json()["items"]) == 1

    assert sorted(ids("event_type=auth.failure")) == ["auth.failure@pc-1", "auth.failure@pc-2"]
    assert ids("src_ip=10.0.0.3") == ["dns.query@server-1"]
    assert ids("dst_ip=8.8.8.8") == ["net.conn@pc-1"]
    assert sorted(ids("host_id=pc-1")) == ["auth.failure@pc-1", "net.conn@pc-1"]
    assert ids("severity=low") == ["auth.failure@pc-2"]
    assert ids("q=SERVER") == ["dns.query@server-1"]
    assert ids("q=nothing-matches") == []
    since = quote((NOW - timedelta(minutes=90)).isoformat())
    assert sorted(ids(f"from={since}")) == ["dns.query@server-1", "net.conn@pc-1"]
    until = since
    assert sorted(ids(f"to={until}")) == ["auth.failure@pc-1", "auth.failure@pc-2"]

    detail = client.get(f"/api/v1/events/{events[0].id}", headers=h)
    assert detail.status_code == 200 and detail.json()["raw_payload"] == {"raw": True}
    assert (
        client.get("/api/v1/events/00000000-0000-0000-0000-000000000000", headers=h).status_code
        == 404
    )
    assert client.get("/api/v1/events").status_code == 401
    bad = client.get("/api/v1/events?src_ip=not-an-ip", headers=h)
    assert bad.status_code == 400 and bad.json()["error"]["code"] == "invalid_ip"


def test_hosts_inventory_and_detail(tenant) -> None:
    from app.api.v1 import hosts

    hosts._hosts_cache.clear()
    _seed_events(tenant)
    client, h = tenant.client, tenant.headers["analyst"]
    listing = client.get("/api/v1/hosts", headers=h)
    assert listing.status_code == 200
    by_host = {row["host_id"]: row for row in listing.json()}
    assert set(by_host) == {"pc-1", "pc-2", "server-1"}
    assert by_host["pc-1"]["event_count"] == 2
    assert by_host["pc-1"]["event_types"] == {"auth.failure": 1, "net.conn": 1}
    detail = client.get("/api/v1/hosts/pc-1", headers=h)
    assert detail.status_code == 200 and detail.json()["event_count"] == 2
    assert client.get("/api/v1/hosts/unknown-host", headers=h).status_code == 404


def test_detections_rules_and_enable_disable(tenant) -> None:
    client, h = tenant.client, tenant.headers
    events = _seed_events(tenant)
    with tenant.session() as db:
        seed_rules(db)
        detection = Detection(
            fingerprint="fp-1",
            detector_kind="rule",
            rule_id="auth_bruteforce",
            rule_version=1,
            title="Brute force",
            severity="high",
            summary="many failures",
            evidence={"count": 8},
            mitre=[],
        )
        other = Detection(
            fingerprint="fp-2",
            detector_kind="rule",
            rule_id="port_scan_like",
            rule_version=1,
            title="Scan",
            severity="medium",
            summary="",
            evidence={},
            mitre=[],
        )
        db.add_all([detection, other])
        db.flush()
        db.add(DetectionEvidence(detection_id=detection.id, event_id=events[0].id, note="x"))
        db.commit()
        detection_id = detection.id

    listing = client.get("/api/v1/detections", headers=h["analyst"]).json()
    assert listing["total"] == 2
    assert client.get("/api/v1/detections?severity=high", headers=h["analyst"]).json()["total"] == 1
    by_rule = client.get("/api/v1/detections?rule_id=port_scan_like", headers=h["analyst"]).json()
    assert [item["title"] for item in by_rule["items"]] == ["Scan"]

    detail = client.get(f"/api/v1/detections/{detection_id}", headers=h["analyst"]).json()
    assert detail["linked_events"] == [str(events[0].id)]
    assert detail["evidence_events"][0]["host_id"] == "pc-1"
    assert (
        client.get(
            "/api/v1/detections/00000000-0000-0000-0000-000000000000", headers=h["analyst"]
        ).status_code
        == 404
    )

    rules = client.get("/api/v1/rules", headers=h["analyst"]).json()
    assert len(rules) > 20
    rule = next(item for item in rules if item["rule_id"] == "auth_bruteforce")
    assert client.get(f"/api/v1/rules/{rule['id']}", headers=h["analyst"]).status_code == 200
    versions = client.get(f"/api/v1/rules/{rule['id']}/versions", headers=h["analyst"]).json()
    assert versions and versions[0]["spec"]["rule_id"] == "auth_bruteforce"

    assert (
        client.patch(
            f"/api/v1/rules/{rule['id']}", headers=h["analyst"], json={"enabled": False}
        ).status_code
        == 403
    )
    off = client.patch(
        f"/api/v1/rules/{rule['id']}", headers=h["administrator"], json={"enabled": False}
    )
    assert off.status_code == 200 and off.json()["enabled"] is False
    again = client.get(f"/api/v1/rules/{rule['id']}", headers=h["analyst"]).json()
    assert again["enabled"] is False
    assert (
        client.get(
            "/api/v1/rules/00000000-0000-0000-0000-000000000000", headers=h["analyst"]
        ).status_code
        == 404
    )
