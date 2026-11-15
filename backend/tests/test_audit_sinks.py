"""Sending the audit log to an outside collector."""

from datetime import UTC, datetime, timedelta

import pytest
from app.api.v1 import audit_sinks as api_module
from app.audit import sink as sink_module
from app.db.session import SessionLocal, set_organization_context
from app.models import AuditSink
from app.notifications import delivery
from sqlalchemy import select

URL = "https://siem.example.com/hooks/sentinel"


class Collector:
    def __init__(self) -> None:
        self.messages: list[dict] = []
        self.fail = False

    def __call__(self, kind, target, message):
        if self.fail:
            raise delivery.DeliveryError("Destination answered HTTP 500")
        assert kind == "webhook" and target["url"] == URL
        self.messages.append(message)


@pytest.fixture
def collector():
    return Collector()


def _admin(tenant):
    return tenant.headers["administrator"]


def _create(tenant, **extra):
    body = {"name": "Splunk", "url": URL, "signing_secret": "s" * 20, **extra}
    return tenant.client.post("/api/v1/audit-sinks", headers=_admin(tenant), json=body)


def _generate(tenant, count=3):
    for _ in range(count):
        tenant.client.post(
            "/api/v1/auth/login",
            json={
                "organization_slug": tenant.slug,
                "email": "x@example.test",
                "password": "wrong-1234567",
            },
        )


def _push(tenant, collector, when=None) -> int:
    with SessionLocal() as db:
        set_organization_context(db, tenant.organization_id)
        sent = sink_module.push_all(db, when or datetime.now(UTC), sender=collector)
        db.commit()
    return sent


def test_only_administrators_manage_destinations_and_urls_are_checked(tenant) -> None:
    client = tenant.client
    assert client.get("/api/v1/audit-sinks", headers=tenant.headers["auditor"]).status_code == 403
    for bad in (
        "http://siem.example.com/x",
        "https://127.0.0.1/x",
        "https://user:pw@siem.example.com/x",
    ):
        response = client.post(
            "/api/v1/audit-sinks", headers=_admin(tenant), json={"name": "Bad", "url": bad}
        )
        assert response.status_code == 422, bad
    assert _create(tenant).status_code == 201
    assert _create(tenant).status_code == 409


def test_a_new_destination_starts_after_the_existing_log_unless_asked_to_replay(tenant) -> None:
    _generate(tenant)
    now = _create(tenant, name="From now")
    # Only its own creation is newer than where it starts.
    assert now.json()["behind"] <= 1 and now.json()["last_seq"] > 0
    replay = _create(tenant, name="Replay", from_beginning=True)
    assert replay.json()["last_seq"] == 0 and replay.json()["behind"] > 0


def test_new_rows_are_pushed_in_order_with_the_head_hash(tenant, collector) -> None:
    sink = _create(tenant, from_beginning=True).json()
    _generate(tenant, 4)
    assert _push(tenant, collector) > 4
    message = collector.messages[0]
    seqs = [row["seq"] for row in message["rows"]]
    assert seqs == sorted(seqs) and message["from_seq"] == seqs[0] and message["to_seq"] == seqs[-1]
    assert message["head_hash"] == message["rows"][-1]["row_hash"]
    assert _push(tenant, collector) == 0  # caught up
    listing = tenant.client.get("/api/v1/audit-sinks", headers=_admin(tenant)).json()
    assert listing[0]["id"] == sink["id"] and listing[0]["behind"] == 0


def test_a_failing_destination_is_retried_later_and_nothing_is_skipped(tenant, collector) -> None:
    _create(tenant, from_beginning=True)
    collector.fail = True
    now = datetime.now(UTC)
    assert _push(tenant, collector, now) == 0
    with SessionLocal() as db:
        set_organization_context(db, tenant.organization_id)
        item = db.scalar(select(AuditSink))
        assert item.last_seq == 0 and item.failures == 1 and "HTTP 500" in item.last_error
        assert item.next_attempt_at > now
    collector.fail = False
    assert _push(tenant, collector, now + timedelta(seconds=1)) == 0  # still waiting
    assert _push(tenant, collector, now + timedelta(hours=1)) > 0  # the same rows go out
    with SessionLocal() as db:
        set_organization_context(db, tenant.organization_id)
        item = db.scalar(select(AuditSink))
        assert item.failures == 0 and item.last_error is None and item.last_seq > 0


def test_a_disabled_destination_receives_nothing(tenant, collector) -> None:
    sink = _create(tenant, from_beginning=True).json()
    tenant.client.patch(
        f"/api/v1/audit-sinks/{sink['id']}", headers=_admin(tenant), json={"enabled": False}
    )
    assert _push(tenant, collector) == 0
    assert collector.messages == []


def test_the_destination_address_is_never_shown_back(tenant) -> None:
    sink = _create(tenant).json()
    assert "url" not in sink and "signing_secret" not in sink
    assert URL not in tenant.client.get("/api/v1/audit-sinks", headers=_admin(tenant)).text


def test_testing_and_deleting_a_destination(tenant, monkeypatch) -> None:
    sink = _create(tenant).json()
    path = f"/api/v1/audit-sinks/{sink['id']}"
    monkeypatch.setattr(api_module.delivery, "send", lambda kind, target, message: None)
    assert tenant.client.post(path + "/test", headers=_admin(tenant)).json() == {"ok": True}

    def refuse(kind, target, message):
        raise delivery.DeliveryError("Destination timed out")

    monkeypatch.setattr(api_module.delivery, "send", refuse)
    result = tenant.client.post(path + "/test", headers=_admin(tenant)).json()
    assert result == {"ok": False, "error": "Destination timed out"}
    assert tenant.client.delete(path, headers=_admin(tenant)).status_code == 200
    assert tenant.client.get("/api/v1/audit-sinks", headers=_admin(tenant)).json() == []
