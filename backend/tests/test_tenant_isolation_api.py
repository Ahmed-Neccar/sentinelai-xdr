"""Two organizations side by side: neither can see or change the other's data through the API."""

from datetime import UTC, datetime

from app.api.v1 import hosts
from app.models import Detection, SecurityEvent

HOOK = "https://hooks.example.com/services/T000/B000/isolation-test"


def _populate(tenant) -> dict[str, str]:
    """Give an organization one of everything and return the identifiers."""
    client, h = tenant.client, tenant.headers
    with tenant.session() as db:
        event = SecurityEvent(
            event_type="auth.failure",
            event_time=datetime(2026, 11, 14, 10, 0, tzinfo=UTC),
            host_id=f"host-of-{tenant.slug}",
            dedup_key=f"iso-{tenant.slug}",
        )
        detection = Detection(
            fingerprint=f"iso-{tenant.slug}",
            detector_kind="rule",
            rule_id="auth_bruteforce",
            title="Isolation test",
            severity="high",
            summary="",
            evidence={},
            mitre=[],
        )
        db.add_all([event, detection])
        db.commit()
        ids = {"event": str(event.id), "detection": str(detection.id)}
    case = client.post(
        "/api/v1/cases", headers=h["analyst"], json={"title": f"case of {tenant.slug}"}
    )
    ids["case"] = case.json()["id"]
    channel = client.post(
        "/api/v1/notification-channels",
        headers=h["administrator"],
        json={"name": "hook", "kind": "slack", "target": {"url": HOOK}},
    )
    ids["channel"] = channel.json()["id"]
    connector = client.post(
        "/api/v1/cloud-connectors",
        headers=h["administrator"],
        json={
            "name": "aws",
            "provider": "aws_cloudtrail",
            "config": {"region": "us-east-1"},
            "credentials": {"access_key_id": "AKIAEXAMPLE", "secret_access_key": "example-key"},
        },
    )
    ids["connector"] = connector.json()["id"]
    users = client.get("/api/v1/users", headers=h["administrator"]).json()["items"]
    ids["user"] = users[0]["id"]
    return ids


def test_an_organization_never_sees_or_changes_the_others_data(tenant, other_tenant) -> None:
    hosts._hosts_cache.clear()
    mine = _populate(tenant)
    theirs = _populate(other_tenant)
    client, h = tenant.client, tenant.headers
    admin, analyst = h["administrator"], h["analyst"]

    # Lists contain only this organization's rows.
    events = client.get("/api/v1/events", headers=analyst).json()
    assert [e["id"] for e in events["items"]] == [mine["event"]]
    detections = client.get("/api/v1/detections", headers=analyst).json()
    assert [d["id"] for d in detections["items"]] == [mine["detection"]]
    cases = client.get("/api/v1/cases", headers=analyst).json()
    assert [c["id"] for c in cases["items"]] == [mine["case"]]
    assert [
        c["id"] for c in client.get("/api/v1/notification-channels", headers=analyst).json()
    ] == [mine["channel"]]
    assert [c["id"] for c in client.get("/api/v1/cloud-connectors", headers=analyst).json()] == [
        mine["connector"]
    ]
    users = client.get("/api/v1/users", headers=admin).json()
    assert users["total"] == 3 and theirs["user"] not in [u["id"] for u in users["items"]]
    host_ids = {row["host_id"] for row in client.get("/api/v1/hosts", headers=analyst).json()}
    assert host_ids == {f"host-of-{tenant.slug}"}
    assert (
        client.get("/api/v1/hosts/host-of-" + other_tenant.slug, headers=analyst).status_code == 404
    )

    # Direct access to the other organization's identifiers is answered as "not found".
    assert client.get(f"/api/v1/events/{theirs['event']}", headers=analyst).status_code == 404
    assert (
        client.get(f"/api/v1/detections/{theirs['detection']}", headers=analyst).status_code == 404
    )
    assert client.get(f"/api/v1/cases/{theirs['case']}", headers=analyst).status_code == 404
    assert (
        client.patch(
            f"/api/v1/cases/{theirs['case']}", headers=analyst, json={"title": "taken over"}
        ).status_code
        == 404
    )
    assert (
        client.post(
            f"/api/v1/cases/{theirs['case']}/comments", headers=analyst, json={"body": "hi"}
        ).status_code
        == 404
    )
    assert (
        client.patch(
            f"/api/v1/users/{theirs['user']}", headers=admin, json={"is_active": False}
        ).status_code
        == 404
    )
    assert (
        client.patch(
            f"/api/v1/notification-channels/{theirs['channel']}",
            headers=admin,
            json={"enabled": False},
        ).status_code
        == 404
    )
    assert (
        client.delete(
            f"/api/v1/notification-channels/{theirs['channel']}", headers=admin
        ).status_code
        == 404
    )
    assert (
        client.patch(
            f"/api/v1/cloud-connectors/{theirs['connector']}",
            headers=admin,
            json={"enabled": False},
        ).status_code
        == 404
    )
    assert (
        client.delete(f"/api/v1/cloud-connectors/{theirs['connector']}", headers=admin).status_code
        == 404
    )

    # A case cannot link another organization's detection.
    link = client.post(
        "/api/v1/cases",
        headers=analyst,
        json={"title": "cross", "detection_ids": [theirs["detection"]]},
    )
    assert link.status_code == 400

    # Nothing of this organization changed, and the other organization is untouched.
    other = other_tenant.client
    other_cases = other.get("/api/v1/cases", headers=other_tenant.headers["analyst"]).json()[
        "items"
    ]
    assert [c["title"] for c in other_cases] == [f"case of {other_tenant.slug}"]
    other_users = other.get("/api/v1/users", headers=other_tenant.headers["administrator"]).json()
    assert all(u["is_active"] for u in other_users["items"])
    assert (
        other.get("/api/v1/cloud-connectors", headers=other_tenant.headers["analyst"]).json()[0][
            "enabled"
        ]
        is True
    )

    # Audit logs only contain the organization's own activity.
    logs = client.get("/api/v1/audit-logs?page_size=100", headers=h["auditor"]).json()["items"]
    assert logs and all(row["target_id"] != theirs["case"] for row in logs)
    summary = client.get("/api/v1/dashboard/summary", headers=analyst).json()
    assert summary["event_count"] == 1 and summary["open_cases"] == 1
