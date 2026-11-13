"""Checks run against an isolated stack started in production mode.

Started by rehearse_production.ps1, which supplies throwaway credentials through
the environment. Prints findings; exits non-zero if a check fails.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path
from uuid import uuid4

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "sensor"))

BASE = os.environ["REHEARSAL_API"]
ADMIN = os.environ["REHEARSAL_ADMIN_EMAIL"]
PASSWORD = os.environ["REHEARSAL_ADMIN_PASSWORD"]
BOOTSTRAP = os.environ.get("REHEARSAL_BOOTSTRAP_PASSWORD", PASSWORD)
TOKEN_MINUTES = int(os.environ.get("REHEARSAL_TOKEN_MINUTES", "1"))
failures: list[str] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    print(f"[{'ok' if ok else 'FAIL'}] {name}{(' - ' + detail) if detail else ''}")
    if not ok:
        failures.append(name)


def seed() -> int:
    """Before a switch: create data that must still work afterwards."""
    carried = Path(os.environ["REHEARSAL_SCRATCH"]) / "carried.json"
    with httpx.Client(base_url=BASE, timeout=15) as client:
        login = client.post("/api/v1/auth/login", json={"email": ADMIN, "password": BOOTSTRAP})
        if login.status_code != 200:
            print(f"seed: administrator sign-in failed ({login.status_code})")
            return 1
        admin = {"Authorization": f"Bearer {login.json()['access_token']}"}
        sensor = client.post(
            "/api/v1/ingest/live/sensors/enrollment", headers=admin, json={"name": "Carried PC"}
        )
        connector = client.post(
            "/api/v1/cloud-connectors",
            headers=admin,
            json={
                "name": "carried-connector",
                "provider": "azure_activity",
                "config": {
                    "tenant_id": str(uuid4()),
                    "client_id": str(uuid4()),
                    "subscription_id": str(uuid4()),
                },
                "credentials": {"client_secret": "rehearsal-" + uuid4().hex},
                "enabled": False,
            },
        )
        case = client.post("/api/v1/cases", headers=admin, json={"title": "Carried case"})
    if sensor.status_code != 201 or case.status_code != 201:
        print(f"seed: could not create data (sensor {sensor.status_code}, case {case.status_code})")
        return 1
    import json

    carried.write_text(
        json.dumps(
            {
                "sensor": sensor.json(),
                "case": case.json()["id"],
                "connector": connector.status_code,
                "old_token": login.json()["access_token"],
            }
        ),
        encoding="utf-8",
    )
    print(f"seed: created a sensor account, a case and a connector (connector {connector.status_code})")
    return 0


def harden() -> int:
    """Replace the administrator's placeholder password, as the operator must."""
    with httpx.Client(base_url=BASE, timeout=15) as client:
        login = client.post("/api/v1/auth/login", json={"email": ADMIN, "password": BOOTSTRAP})
        if login.status_code != 200:
            print(f"harden: sign-in with the bootstrap password failed ({login.status_code})")
            return 1
        body = login.json()
        changed = client.patch(
            f"/api/v1/users/{body['user']['id']}",
            headers={"Authorization": f"Bearer {body['access_token']}"},
            json={"password": PASSWORD},
        )
        again = client.post("/api/v1/auth/login", json={"email": ADMIN, "password": BOOTSTRAP})
    ok = changed.status_code == 200 and again.status_code == 401
    print(f"harden: administrator password changed ({changed.status_code}); old one now {again.status_code}")
    return 0 if ok else 1


def check_carried(client: httpx.Client, admin: dict[str, str]) -> None:
    carried = Path(os.environ["REHEARSAL_SCRATCH"]) / "carried.json"
    if not carried.exists():
        return
    import json

    data = json.loads(carried.read_text(encoding="utf-8"))
    old = client.get("/api/v1/cases", headers={"Authorization": f"Bearer {data['old_token']}"})
    check("tokens signed with the old weak key are rejected", old.status_code == 401, f"status {old.status_code}")
    case = client.get(f"/api/v1/cases/{data['case']}", headers=admin)
    check("a case created before the switch is still there", case.status_code == 200)
    again = client.post(
        "/api/v1/auth/login",
        json={"email": data["sensor"]["email"], "password": data["sensor"]["password"]},
    )
    check("a sensor account created before the switch can still sign in", again.status_code == 200)
    if data["connector"] == 201:
        connectors = client.get("/api/v1/cloud-connectors", headers=admin)
        names = [item.get("name") for item in connectors.json()] if connectors.status_code == 200 else []
        check("a cloud connector created before the switch is still listed", "carried-connector" in names)


def main() -> int:
    if len(sys.argv) > 1 and sys.argv[1] == "seed":
        return seed()
    if len(sys.argv) > 1 and sys.argv[1] == "harden":
        return harden()
    with httpx.Client(base_url=BASE, timeout=15) as client:
        check("health endpoint answers", client.get("/api/v1/health").status_code == 200)
        check("readiness reports dependencies", client.get("/api/v1/ready").status_code == 200)
        docs = [client.get(path).status_code for path in ("/docs", "/redoc", "/openapi.json")]
        check(
            "API documentation and schema are not served",
            all(status == 404 for status in docs),
            f"statuses {docs}",
        )

        login = client.post("/api/v1/auth/login", json={"email": ADMIN, "password": PASSWORD})
        check("administrator can sign in", login.status_code == 200, f"status {login.status_code}")
        if login.status_code != 200:
            return 1
        cookie = login.headers.get("set-cookie", "").lower()
        check("refresh cookie is marked Secure", "secure" in cookie.split("; ") or "; secure" in cookie)
        check("refresh cookie is HttpOnly", "httponly" in cookie)
        admin = {"Authorization": f"Bearer {login.json()['access_token']}"}
        check_carried(client, admin)

        # A non-browser client over http:// never returns a Secure cookie.
        refreshed = client.post("/api/v1/auth/refresh")
        check(
            "refresh over plain http is refused (cookie not returned by the client)",
            refreshed.status_code == 401,
            f"status {refreshed.status_code}",
        )

        bad = [
            client.post("/api/v1/auth/login", json={"email": ADMIN, "password": "wrong-" + uuid4().hex})
            for _ in range(3)
        ]
        check("wrong passwords are rejected", all(r.status_code == 401 for r in bad))

        enrollment = client.post(
            "/api/v1/ingest/live/sensors/enrollment", headers=admin, json={"name": "Rehearsal PC"}
        )
        check("sensor enrollment works", enrollment.status_code == 201, f"status {enrollment.status_code}")
        if enrollment.status_code != 201:
            return 1
        credentials = enrollment.json()

    # The real sensor client, with its identity kept out of sensor/runtime.
    import live_sensor

    scratch = Path(os.environ["REHEARSAL_SCRATCH"])
    key = live_sensor.Ed25519PrivateKey.generate()
    public = live_sensor.base64.b64encode(
        key.public_key().public_bytes(
            live_sensor.serialization.Encoding.Raw, live_sensor.serialization.PublicFormat.Raw
        )
    ).decode("ascii")
    counter = {"value": 0}

    def next_counter() -> int:
        counter["value"] += 1
        return counter["value"]

    live_sensor.get_or_create_sensor_key = lambda: (key, public)
    live_sensor.next_sensor_request_counter = next_counter
    sensor_id = str(uuid4())
    api = live_sensor.ApiClient(BASE, credentials["email"], credentials["password"], sensor_id)
    job = api.post(
        "/api/v1/ingest/live/start",
        {
            "source_name": f"rehearsal-{sensor_id[:8]}",
            "sensor_id": sensor_id,
            "sensor_public_key": public,
            "host_name": "REHEARSAL-PC",
            "sensor_version": "rehearsal",
            "capabilities": ["network.headers", "response.block_ip"],
        },
    )
    heartbeat = f"/api/v1/ingest/live/{job['id']}/heartbeat"
    first = api.post(heartbeat, {})
    check("sensor session and signed heartbeat work", "response_actions" in first)
    old_token = api.access_token
    wait = TOKEN_MINUTES * 60 + 8
    print(f"... waiting {wait} seconds for the sensor's access token to expire")
    time.sleep(wait)
    try:
        second = api.post(heartbeat, {})
        check(
            "sensor keeps working after its token expires (signs in again)",
            "response_actions" in second and api.access_token != old_token,
        )
    except Exception as exc:  # noqa: BLE001 - reported as a finding
        check("sensor keeps working after its token expires (signs in again)", False, repr(exc)[:160])
    (scratch / "done").write_text("done", encoding="utf-8")
    print(f"\n{len(failures)} check(s) failed." if failures else "\nAll checks passed.")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
