"""Response actions must not start for a sensor that is away, and must not hang when it goes.

The earlier workflow test covers the happy path. These cover the failures: a sensor that is
offline when an action is proposed or approved, a delivery nobody picked up, and a sensor that
took an action and never reported back.
"""

import os
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from app.db.session import SessionLocal, set_organization_context
from app.main import app
from app.models import AuditLog, Organization, ResponseSimulation, SensorRegistration
from fastapi.testclient import TestClient
from sqlalchemy import delete, select
from tests.test_response_workflow_api import (
    ALL_CAPABILITIES,
    Sensor,
    _login,
    _role,
    _user,
)

pytestmark = pytest.mark.skipif(
    not os.environ.get("MFA_TEST_DATABASE_URL"),
    reason="Response lifecycle tests require a migrated PostgreSQL test database",
)


class World:
    def __init__(self, client, organization_id, admin1, admin2, sensor, case_id) -> None:
        self.client = client
        self.organization_id = organization_id
        self.admin1 = admin1
        self.admin2 = admin2
        self.sensor = sensor
        self.case_id = case_id
        self.responses = f"/api/v1/cases/{case_id}/responses"

    def propose(self, action="block_source_ip", target="203.0.113.9", minutes=5):
        return self.client.post(
            self.responses,
            headers=self.admin1,
            json={
                "action_type": action,
                "target": target,
                "rationale": "Lifecycle test of an executed action",
                "sensor_id": self.sensor.sensor_id,
                "duration_minutes": minutes,
            },
        )

    def approve(self, item_id):
        return self.client.post(f"{self.responses}/{item_id}/approve", headers=self.admin2)

    def row(self, item_id) -> dict:
        detail = self.client.get(f"/api/v1/cases/{self.case_id}", headers=self.admin1).json()
        return next(i for i in detail["response_simulations"] if i["id"] == item_id)

    def sensors(self) -> list[dict]:
        detail = self.client.get(f"/api/v1/cases/{self.case_id}", headers=self.admin1).json()
        return detail["response_recommendation"]["enforcing_sensors"]

    def make_sensor_silent(self, seconds=600) -> None:
        with SessionLocal() as db:
            set_organization_context(db, self.organization_id)
            registration = db.scalar(select(SensorRegistration))
            registration.last_seen_at = datetime.now(UTC) - timedelta(seconds=seconds)
            db.commit()

    def edit(self, item_id, **fields) -> None:
        with SessionLocal() as db:
            set_organization_context(db, self.organization_id)
            row = db.get(ResponseSimulation, item_id)
            for key, value in fields.items():
                setattr(row, key, value)
            db.commit()

    def audit(self) -> list[str]:
        with SessionLocal() as db:
            set_organization_context(db, self.organization_id)
            return list(
                db.scalars(
                    select(AuditLog.action)
                    .where(AuditLog.action.like("response.%"))
                    .order_by(AuditLog.seq)
                )
            )


@pytest.fixture
def world():
    organization_id = uuid4()
    slug = f"life-test-{organization_id.hex}"
    first = f"admin1-{organization_id.hex}@example.test"
    second = f"admin2-{organization_id.hex}@example.test"
    with SessionLocal() as db:
        db.add(Organization(id=organization_id, slug=slug, name="Lifecycle test"))
        db.commit()
        set_organization_context(db, organization_id)
        admin_role = _role(db, "administrator")
        _role(db, "ingestion_service")
        _user(db, organization_id, first, admin_role)
        _user(db, organization_id, second, admin_role)
        db.commit()
    try:
        with TestClient(app) as client:
            admin1, admin2 = _login(client, slug, first), _login(client, slug, second)
            enrollment = client.post(
                "/api/v1/ingest/live/sensors/enrollment", headers=admin1, json={"name": "Lab PC"}
            ).json()
            sensor = Sensor(client, slug, enrollment["email"], enrollment["password"])
            sensor.start(ALL_CAPABILITIES)
            case = client.post("/api/v1/cases", headers=admin1, json={"title": "Lifecycle"})
            yield World(client, organization_id, admin1, admin2, sensor, case.json()["id"])
    finally:
        with SessionLocal() as db:
            set_organization_context(db, organization_id)
            db.execute(delete(Organization).where(Organization.id == organization_id))
            db.commit()


# --- a sensor that is away ------------------------------------------------------------------


def test_the_sensor_list_says_which_sensors_are_online(world) -> None:
    assert world.sensors()[0]["online"] is True
    world.make_sensor_silent()
    assert world.sensors()[0]["online"] is False


@pytest.mark.parametrize("action", ["block_source_ip", "isolate_host", "disable_local_account"])
def test_nothing_is_proposed_for_an_offline_sensor(world, action) -> None:
    world.make_sensor_silent()
    target = {"disable_local_account": "sentinel-test"}.get(action, "203.0.113.9")
    response = world.propose(action, target)
    assert response.status_code == 409, response.text
    assert response.json()["error"]["code"] == "sensor_offline"


def test_a_proposal_cannot_be_approved_after_the_sensor_went_away(world) -> None:
    item = world.propose("isolate_host", "x", minutes=30).json()
    world.make_sensor_silent()
    refused = world.approve(item["id"])
    assert refused.status_code == 409
    assert refused.json()["error"]["code"] == "sensor_offline"
    # It stays proposed, so it can be approved once the sensor is back.
    assert world.row(item["id"])["status"] == "proposed"
    world.sensor.heartbeat()
    assert world.approve(item["id"]).status_code == 200


# --- delivery and execution ----------------------------------------------------------------


def test_delivery_moves_an_action_to_dispatched_and_a_report_finishes_it(world) -> None:
    item = world.propose().json()
    assert world.approve(item["id"]).status_code == 200
    assert world.row(item["id"])["enforcement_status"] == "pending"
    actions = world.sensor.heartbeat()
    assert [a["id"] for a in actions] == [item["id"]]
    row = world.row(item["id"])
    assert row["enforcement_status"] == "dispatched" and row["dispatched_at"]
    # Until the sensor answers, it is offered again, so a lost reply is not a lost action.
    assert [a["id"] for a in world.sensor.heartbeat()] == [item["id"]]
    assert world.sensor.report(item["id"], "applied", "done").json()["changed"] is True
    assert world.row(item["id"])["enforcement_status"] == "applied"
    assert "response.block.dispatched" in world.audit()


def test_an_action_the_sensor_never_answers_fails_with_a_timeout(world) -> None:
    item = world.propose().json()
    world.approve(item["id"])
    world.sensor.heartbeat()
    world.edit(item["id"], dispatched_at=datetime.now(UTC) - timedelta(minutes=30))
    assert world.sensor.heartbeat() == []  # no longer offered: it would be applied far too late
    row = world.row(item["id"])
    assert row["enforcement_status"] == "failed" and row["failure_code"] == "timeout"
    assert "response.block.failed" in world.audit()
    # A late report cannot revive it.
    assert world.sensor.report(item["id"], "applied").json()["changed"] is False


def test_the_sweep_closes_actions_even_when_the_sensor_never_returns(world) -> None:
    from app.response.lifecycle import sweep_stale_actions

    unanswered = world.propose(target="203.0.113.10").json()
    world.approve(unanswered["id"])
    world.sensor.heartbeat()
    world.edit(unanswered["id"], dispatched_at=datetime.now(UTC) - timedelta(minutes=30))
    # Approved after the sensor's last heartbeat, so nothing has handed it over yet.
    undelivered = world.propose().json()
    world.approve(undelivered["id"])
    world.edit(undelivered["id"], approved_at=datetime.now(UTC) - timedelta(minutes=20))
    forgotten = world.propose(target="203.0.113.11").json()
    world.edit(forgotten["id"], expires_at=datetime.now(UTC) - timedelta(hours=1))

    with SessionLocal() as db:
        set_organization_context(db, world.organization_id)
        counts = sweep_stale_actions(db, datetime.now(UTC))
        db.commit()
    assert counts == {"cancelled": 1, "failed": 1, "expired": 1}
    assert world.row(undelivered["id"])["enforcement_status"] == "cancelled"
    assert world.row(unanswered["id"])["failure_code"] == "timeout"
    assert world.row(forgotten["id"])["status"] == "expired"
    # Nothing left to do on a second pass.
    with SessionLocal() as db:
        set_organization_context(db, world.organization_id)
        assert sweep_stale_actions(db, datetime.now(UTC)) == {
            "cancelled": 0,
            "failed": 0,
            "expired": 0,
        }


def test_a_timed_out_action_can_still_be_lifted_because_it_may_be_in_effect(world) -> None:
    item = world.propose().json()
    world.approve(item["id"])
    world.sensor.heartbeat()
    world.edit(item["id"], dispatched_at=datetime.now(UTC) - timedelta(minutes=30))
    world.sensor.heartbeat()
    assert world.row(item["id"])["failure_code"] == "timeout"
    lifted = world.client.post(f"{world.responses}/{item['id']}/unblock", headers=world.admin1)
    assert lifted.status_code == 200
    assert lifted.json()["enforcement_status"] == "removal_pending"
    assert [a["action"] for a in world.sensor.heartbeat()] == ["unblock"]
    assert world.sensor.report(item["id"], "removed").json()["enforcement_status"] == "removed"


def test_recent_responses_lists_executed_actions_newest_first(world) -> None:
    first = world.propose(target="203.0.113.20").json()
    second = world.propose(target="203.0.113.21").json()
    listing = world.client.get("/api/v1/cases/responses/recent", headers=world.admin1)
    assert listing.status_code == 200
    ids = [item["id"] for item in listing.json()["items"]]
    assert ids[:2] == [second["id"], first["id"]]
    assert listing.json()["items"][0]["case_id"] == world.case_id
    assert world.client.get("/api/v1/cases/responses/recent").status_code == 401
