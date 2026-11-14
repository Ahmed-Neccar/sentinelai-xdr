from app.models import AuditLog
from sqlalchemy import select

HOOK = "https://hooks.example.com/services/T000/B000/not-a-real-token"
CHANNELS = "/api/v1/notification-channels"


def test_notification_channel_crud_and_test_queue(tenant) -> None:
    client, h = tenant.client, tenant.headers
    admin = h["administrator"]
    body = {"name": "ops", "kind": "slack", "target": {"url": HOOK}, "min_severity": "high"}
    assert client.post(CHANNELS, headers=h["analyst"], json=body).status_code == 403
    created = client.post(CHANNELS, headers=admin, json=body)
    assert created.status_code == 201, created.text
    channel = created.json()
    assert HOOK not in created.text and "target" not in channel
    assert client.post(CHANNELS, headers=admin, json=body).status_code == 409
    insecure = {**body, "name": "bad", "target": {"url": "http://hooks.example.com/x"}}
    assert client.post(CHANNELS, headers=admin, json=insecure).status_code == 422

    listing = client.get(CHANNELS, headers=h["analyst"]).json()
    assert [c["name"] for c in listing] == ["ops"]
    assert client.get(CHANNELS, headers=h["auditor"]).status_code == 403

    url = f"{CHANNELS}/{channel['id']}"
    assert client.patch(url, headers=admin, json={}).status_code == 400
    patched = client.patch(
        url, headers=admin, json={"min_severity": "critical", "include_summary": True}
    )
    assert patched.status_code == 200 and patched.json()["min_severity"] == "critical"

    assert client.post(f"{url}/test", headers=admin).status_code == 202
    assert client.post(f"{url}/test", headers=admin).status_code == 409
    client.patch(url, headers=admin, json={"enabled": False})
    assert client.post(f"{url}/test", headers=admin).status_code == 409

    assert client.delete(url, headers=h["analyst"]).status_code == 403
    assert client.delete(url, headers=admin).status_code == 204
    assert client.delete(url, headers=admin).status_code == 404
    with tenant.session() as db:
        actions = set(
            db.scalars(
                select(AuditLog.action).where(AuditLog.action.like("notification_channel.%"))
            )
        )
    assert {
        "notification_channel.created",
        "notification_channel.updated",
        "notification_channel.deleted",
    } <= actions


def test_dashboard_reports_settings_and_audit_log(tenant) -> None:
    client, h = tenant.client, tenant.headers
    summary = client.get("/api/v1/dashboard/summary", headers=h["analyst"])
    assert summary.status_code == 200
    assert summary.json()["event_count"] == 0 and summary.json()["open_cases"] == 0

    csv = client.get("/api/v1/reports/summary?format=csv", headers=h["analyst"])
    assert csv.status_code == 200 and csv.text.splitlines()[0] == "metric,value"
    assert client.get("/api/v1/reports/summary", headers=h["analyst"]).json()["limitations"]

    current = client.get("/api/v1/settings", headers=h["analyst"]).json()
    assert current["response_automation"] == "disabled"
    forbidden = client.patch("/api/v1/settings", headers=h["analyst"], json={"retention_days": 30})
    assert forbidden.status_code == 403
    admin = h["administrator"]
    changed = client.patch(
        "/api/v1/settings", headers=admin, json={"retention_days": 45, "upload_retention_days": 7}
    )
    assert changed.status_code == 200
    assert changed.json()["retention_days"] == 45
    assert changed.json()["upload_retention_days"] == 7
    assert (
        client.patch("/api/v1/settings", headers=admin, json={"retention_days": 0}).status_code
        == 422
    )
    too_long = {"upload_retention_days": 99999}
    assert client.patch("/api/v1/settings", headers=admin, json=too_long).status_code == 422

    client.post("/api/v1/cases", headers=h["analyst"], json={"title": "Audited"})
    logs = client.get("/api/v1/audit-logs?page_size=100", headers=h["auditor"])
    assert logs.status_code == 200
    actions = [row["action"] for row in logs.json()["items"]]
    assert "case.create" in actions and "auth.login" in actions
    assert client.get("/api/v1/audit-logs", headers=h["analyst"]).status_code == 403
