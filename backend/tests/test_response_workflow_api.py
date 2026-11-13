"""End-to-end API tests of the executed response workflow against a real database.

They cover what unit tests cannot: routing, role checks, separation of duties,
row-level security, the signed sensor exchange and the audit trail together.
Skipped unless a migrated PostgreSQL test database is configured (as in CI).
"""

import base64
import json
import os
import time
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from app.core.security import hash_password
from app.db.session import SessionLocal, set_organization_context
from app.main import app
from app.models import AuditLog, Organization, ResponseSimulation, Role, User, UserRole
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient
from sqlalchemy import delete, select

pytestmark = pytest.mark.skipif(
    not os.environ.get("MFA_TEST_DATABASE_URL"),
    reason="Response workflow API integration requires a migrated PostgreSQL test database",
)
PASSWORD = "Response-Integration-Test-2026!"  # noqa: S105 - test-only account password
ALL_CAPABILITIES = [
    "network.headers",
    "response.block_ip",
    "response.isolate_host",
    "response.disable_account",
]


class Sensor:
    """Speaks the sensor's signed protocol, like sensor/live_sensor.py does."""

    def __init__(self, client: TestClient, slug: str, email: str, password: str) -> None:
        self.client = client
        self.sensor_id = str(uuid4())
        self.key = Ed25519PrivateKey.generate()
        self.public_key = base64.b64encode(
            self.key.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            )
        ).decode("ascii")
        self.counter = 0
        login = client.post(
            "/api/v1/auth/login",
            json={"organization_slug": slug, "email": email, "password": password},
        )
        assert login.status_code == 200, login.text
        self.token = login.json()["access_token"]
        self.job_id = ""

    def post(self, path: str, payload: dict):
        body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
        self.counter += 1
        timestamp = str(int(time.time()))
        message = f"{self.sensor_id}\n{self.counter}\n{timestamp}\nPOST\n{path}\n".encode() + body
        return self.client.post(
            path,
            content=body,
            headers={
                "Authorization": f"Bearer {self.token}",
                "Content-Type": "application/json",
                "X-Sentinel-Sensor-ID": self.sensor_id,
                "X-Sentinel-Counter": str(self.counter),
                "X-Sentinel-Timestamp": timestamp,
                "X-Sentinel-Signature": base64.b64encode(self.key.sign(message)).decode("ascii"),
            },
        )

    def start(self, capabilities: list[str], host: str = "LAB-PC") -> None:
        started = self.post(
            "/api/v1/ingest/live/start",
            {
                "source_name": f"{host}-{self.sensor_id[:8]}",
                "sensor_id": self.sensor_id,
                "sensor_public_key": self.public_key,
                "host_name": host,
                "sensor_version": "test",
                "capabilities": capabilities,
            },
        )
        assert started.status_code == 201, started.text
        self.job_id = str(started.json()["id"])

    def heartbeat(self) -> list[dict]:
        response = self.post(f"/api/v1/ingest/live/{self.job_id}/heartbeat", {})
        assert response.status_code == 200, response.text
        return response.json()["response_actions"]

    def report(self, action_id: str, result: str, detail: str = ""):
        return self.post(
            f"/api/v1/ingest/live/{self.job_id}/actions/{action_id}/result",
            {"result": result, "detail": detail},
        )


def _role(db, name: str) -> Role:
    role = db.scalar(select(Role).where(Role.name == name))
    if role is None:
        role = Role(name=name, description="Integration test role")
        db.add(role)
        db.flush()
    return role


def _user(db, organization_id, email: str, role: Role) -> None:
    user = User(
        organization_id=organization_id,
        email=email,
        hashed_password=hash_password(PASSWORD),
        full_name=email,
    )
    db.add(user)
    db.flush()
    db.add(UserRole(organization_id=organization_id, user_id=user.id, role_id=role.id))


def _login(client: TestClient, slug: str, email: str) -> dict[str, str]:
    response = client.post(
        "/api/v1/auth/login",
        json={"organization_slug": slug, "email": email, "password": PASSWORD},
    )
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def _audit_actions(organization_id) -> list[str]:
    with SessionLocal() as db:
        set_organization_context(db, organization_id)
        return list(
            db.scalars(
                select(AuditLog.action)
                .where(AuditLog.action.like("response.%"))
                .order_by(AuditLog.created_at)
            )
        )


def test_executed_response_actions_end_to_end() -> None:
    organization_id = uuid4()
    slug = f"resp-test-{organization_id.hex}"
    first_admin = f"admin1-{organization_id.hex}@example.test"
    second_admin = f"admin2-{organization_id.hex}@example.test"
    analyst = f"analyst-{organization_id.hex}@example.test"

    with SessionLocal() as db:
        db.add(Organization(id=organization_id, slug=slug, name="Response integration test"))
        db.commit()
        set_organization_context(db, organization_id)
        admin_role, analyst_role = _role(db, "administrator"), _role(db, "analyst")
        _role(db, "ingestion_service")
        _user(db, organization_id, first_admin, admin_role)
        _user(db, organization_id, second_admin, admin_role)
        _user(db, organization_id, analyst, analyst_role)
        db.commit()

    try:
        with TestClient(app) as client:
            admin1 = _login(client, slug, first_admin)
            admin2 = _login(client, slug, second_admin)
            analyst_headers = _login(client, slug, analyst)

            # -- enrollment: only an administrator, password returned once -----
            assert client.post(
                "/api/v1/ingest/live/sensors/enrollment",
                headers=analyst_headers,
                json={"name": "Lab PC"},
            ).status_code == 403
            enrollment = client.post(
                "/api/v1/ingest/live/sensors/enrollment", headers=admin1, json={"name": "Lab PC"}
            )
            assert enrollment.status_code == 201, enrollment.text
            credentials = enrollment.json()
            assert credentials["email"].startswith("sensor-lab-pc-")
            assert len(credentials["password"]) >= 40

            sensor = Sensor(client, slug, credentials["email"], credentials["password"])
            sensor.start(ALL_CAPABILITIES)
            assert sensor.heartbeat() == []
            # A sensor account cannot use the people's API.
            sensor_headers = {"Authorization": f"Bearer {sensor.token}"}
            assert client.get("/api/v1/cases", headers=sensor_headers).status_code == 403
            assert client.get(
                "/api/v1/cases/pending-approvals", headers=sensor_headers
            ).status_code == 403

            case = client.post(
                "/api/v1/cases", headers=admin1, json={"title": "Response integration case"}
            )
            assert case.status_code == 201, case.text
            case_id = case.json()["id"]
            responses = f"/api/v1/cases/{case_id}/responses"

            def propose(action: str, target: str, minutes: int | None = 5, sensor_id=None):
                body = {
                    "action_type": action,
                    "target": target,
                    "rationale": "Integration test of an executed action",
                    "sensor_id": sensor_id or sensor.sensor_id,
                }
                if minutes is not None:
                    body["duration_minutes"] = minutes
                return client.post(responses, headers=admin1, json=body)

            def approve_as_other_admin(item: dict) -> int:
                path = f"{responses}/{item['id']}/approve"
                return client.post(path, headers=admin2).status_code

            # -- what the server refuses before anything reaches a sensor ------
            assert propose("block_source_ip", "127.0.0.1").status_code == 400
            assert propose("block_source_ip", "203.0.113.9", minutes=1).status_code == 400
            assert propose("isolate_host", "x", minutes=241).status_code == 400
            assert propose("disable_local_account", "/active:yes").status_code == 400
            unknown = propose("block_source_ip", "203.0.113.9", sensor_id=str(uuid4()))
            assert unknown.status_code == 400 and "sensor" in unknown.text.lower()
            assert client.post(
                responses,
                headers=admin1,
                json={
                    "action_type": "simulate_host_isolation",
                    "target": "host",
                    "rationale": "A simulation takes no sensor",
                    "sensor_id": sensor.sensor_id,
                },
            ).status_code == 400

            # -- IP block: propose, separation of duties, deliver, apply, lift --
            proposed = propose("block_source_ip", " 203.0.113.9 ")
            assert proposed.status_code == 201, proposed.text
            block = proposed.json()
            assert block["target"] == "203.0.113.9" and block["enforcement_status"] is None
            assert sensor.heartbeat() == []  # not approved yet

            pending_for_requester = client.get(
                "/api/v1/cases/pending-approvals", headers=admin1
            ).json()
            pending_for_other = client.get("/api/v1/cases/pending-approvals", headers=admin2).json()
            assert pending_for_requester["waiting_for_me"] == 0
            assert pending_for_other["waiting_for_me"] == 1
            assert pending_for_other["items"][0]["executed"] is True

            approve = f"{responses}/{block['id']}/approve"
            assert client.post(approve, headers=admin1).status_code == 403  # own proposal
            assert client.post(approve, headers=analyst_headers).status_code == 403
            assert client.post(approve, headers=admin2).status_code == 200
            assert client.post(approve, headers=admin2).status_code == 409  # only once
            assert client.post(
                f"{responses}/{block['id']}/simulate", headers=admin2
            ).status_code == 409  # an executed action is never "recorded" by hand

            actions = sensor.heartbeat()
            assert actions == [
                {
                    "id": block["id"],
                    "action": "block",
                    "ip": "203.0.113.9",
                    "target": "203.0.113.9",
                    "minutes": 5,
                }
            ]
            applied = sensor.report(block["id"], "applied", "blocked for 5 minutes")
            assert applied.status_code == 200 and applied.json()["changed"] is True
            assert sensor.report(block["id"], "applied").json()["changed"] is False  # repeat
            assert sensor.heartbeat() == []  # applied and not yet expired

            detail = client.get(f"/api/v1/cases/{case_id}", headers=admin1).json()
            record = next(i for i in detail["response_simulations"] if i["id"] == block["id"])
            assert record["enforcement_status"] == "applied" and record["block_until"]

            # Lifting is allowed to any administrator, including the requester.
            assert client.post(
                f"{responses}/{block['id']}/unblock", headers=analyst_headers
            ).status_code == 403
            lifted = client.post(f"{responses}/{block['id']}/unblock", headers=admin1)
            assert lifted.status_code == 200
            assert lifted.json()["enforcement_status"] == "removal_pending"
            assert sensor.heartbeat() == [
                {
                    "id": block["id"],
                    "action": "unblock",
                    "ip": "203.0.113.9",
                    "target": "203.0.113.9",
                }
            ]
            assert sensor.report(block["id"], "removed").json()["enforcement_status"] == "removed"
            assert sensor.report(block["id"], "applied").json()["changed"] is False  # no revival
            assert sensor.heartbeat() == []

            # -- refusal reported by the sensor ---------------------------------
            gateway = propose("block_source_ip", "192.168.1.1").json()
            assert approve_as_other_admin(gateway) == 200
            assert sensor.heartbeat()[0]["id"] == gateway["id"]
            refused = sensor.report(gateway["id"], "refused", "protected address")
            assert refused.json()["enforcement_status"] == "refused"
            assert sensor.heartbeat() == []

            # -- isolation: target is the sensor, and delivery has a deadline ---
            isolation = propose("isolate_host", "some-other-server", minutes=30).json()
            assert isolation["target"] == "LAB-PC" and isolation["duration_minutes"] == 30
            assert client.post(
                f"{responses}/{isolation['id']}/approve", headers=admin2
            ).status_code == 200
            with SessionLocal() as db:
                set_organization_context(db, organization_id)
                row = db.get(ResponseSimulation, isolation["id"])
                row.approved_at = datetime.now(UTC) - timedelta(minutes=20)  # sensor was away
                db.commit()
            assert sensor.heartbeat() == []  # too late: cancelled, not applied
            detail = client.get(f"/api/v1/cases/{case_id}", headers=admin1).json()
            stale = next(i for i in detail["response_simulations"] if i["id"] == isolation["id"])
            assert stale["enforcement_status"] == "cancelled"
            assert sensor.report(isolation["id"], "applied").json()["changed"] is False

            # -- account disable: cancelled before it reached the sensor --------
            account = propose("disable_local_account", "sentinel-test", minutes=10).json()
            assert account["target"] == "sentinel-test"
            assert approve_as_other_admin(account) == 200
            cancelled = client.post(f"{responses}/{account['id']}/unblock", headers=admin2)
            assert cancelled.json()["enforcement_status"] == "cancelled"
            assert sensor.heartbeat() == []

            # -- a sensor that did not opt in cannot be chosen, and one sensor
            #    cannot report for another -----------------------------------
            other_login = client.post(
                "/api/v1/ingest/live/sensors/enrollment", headers=admin1, json={"name": "Other"}
            ).json()
            other = Sensor(client, slug, other_login["email"], other_login["password"])
            other.start(["network.headers"], host="OTHER-PC")
            not_opted_in = propose("block_source_ip", "203.0.113.10", sensor_id=other.sensor_id)
            assert not_opted_in.status_code == 400
            mine = propose("block_source_ip", "203.0.113.11").json()
            assert approve_as_other_admin(mine) == 200
            assert other.heartbeat() == []  # not offered to the other sensor
            assert other.report(mine["id"], "applied").status_code == 404
            assert sensor.heartbeat()[0]["id"] == mine["id"]

            # An unsigned request with a valid token is not enough.
            unsigned = client.post(
                f"/api/v1/ingest/live/{sensor.job_id}/actions/{mine['id']}/result",
                headers=sensor_headers,
                json={"result": "applied", "detail": ""},
            )
            assert unsigned.status_code in (401, 403), unsigned.text

        actions = _audit_actions(organization_id)
        for expected in (
            "response.block.approved",
            "response.block.applied",
            "response.block.lift_requested",
            "response.block.removed",
            "response.block.refused",
            "response.isolation.approved",
            "response.isolation.delivery_expired",
            "response.account.approved",
            "response.account.lift_requested",
        ):
            assert expected in actions, (expected, actions)
        assert "response.isolation.applied" not in actions
    finally:
        with SessionLocal() as db:
            set_organization_context(db, organization_id)
            db.execute(delete(Organization).where(Organization.id == organization_id))
            db.commit()
