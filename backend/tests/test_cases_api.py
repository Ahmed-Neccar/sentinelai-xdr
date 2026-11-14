from app.models import Detection, User
from sqlalchemy import select

UNKNOWN = "00000000-0000-0000-0000-000000000000"


def _user_id(tenant, role: str) -> str:
    with tenant.session() as db:
        return str(db.scalar(select(User.id).where(User.email == tenant.emails[role])))


def _detection(tenant, fingerprint: str = "case-fp") -> str:
    with tenant.session() as db:
        detection = Detection(
            fingerprint=fingerprint,
            detector_kind="rule",
            rule_id="auth_bruteforce",
            rule_version=1,
            title="Brute force",
            severity="high",
            summary="",
            evidence={},
            mitre=[],
        )
        db.add(detection)
        db.commit()
        return str(detection.id)


def test_case_lifecycle_comments_history_and_filters(tenant) -> None:
    client, h = tenant.client, tenant.headers
    detection_id = _detection(tenant)
    analyst_id = _user_id(tenant, "analyst")
    post = client.post
    patch = client.patch

    created = post(
        "/api/v1/cases",
        headers=h["analyst"],
        json={
            "title": "Investigate",
            "severity": "high",
            "priority": "p2",
            "detection_ids": [detection_id],
        },
    )
    assert created.status_code == 201, created.text
    case = created.json()
    assert case["status"] == "new"
    assert [d["id"] for d in case["detections"]] == [detection_id]
    case_id = case["id"]

    # Validation.
    analyst = h["analyst"]
    assert (
        post("/api/v1/cases", headers=analyst, json={"title": "x", "severity": "huge"}).status_code
        == 400
    )
    assert (
        post("/api/v1/cases", headers=analyst, json={"title": "x", "priority": "p9"}).status_code
        == 400
    )
    unknown_detection = {"title": "x", "detection_ids": [UNKNOWN]}
    assert post("/api/v1/cases", headers=analyst, json=unknown_detection).status_code == 400
    auditor_id = _user_id(tenant, "auditor")
    not_assignable = {"title": "x", "assigned_to": auditor_id}
    assert post("/api/v1/cases", headers=analyst, json=not_assignable).status_code == 400
    assert post("/api/v1/cases", headers=h["auditor"], json={"title": "x"}).status_code == 403

    # Updates are recorded in the history.
    url = f"/api/v1/cases/{case_id}"
    updated = patch(
        url,
        headers=analyst,
        json={
            "status": "investigating",
            "assigned_to": analyst_id,
            "priority": "p1",
            "title": "Renamed",
        },
    )
    assert updated.status_code == 200, updated.text
    assert updated.json()["status"] == "investigating"
    assert updated.json()["title"] == "Renamed"
    assert patch(url, headers=analyst, json={"status": "done"}).status_code == 400
    unassigned = patch(url, headers=analyst, json={"assigned_to": None})
    assert unassigned.status_code == 200 and unassigned.json()["assigned_to"] is None
    assert patch(url, headers=analyst, json={"status": "resolved"}).status_code == 200

    history = client.get(f"{url}/history", headers=h["auditor"]).json()
    assert [(row["from_status"], row["to_status"]) for row in history] == [
        (None, "new"),
        ("new", "investigating"),
        ("investigating", "resolved"),
    ]

    comment = post(f"{url}/comments", headers=analyst, json={"body": "Checked the host"})
    assert comment.status_code == 201
    assert post(f"{url}/comments", headers=analyst, json={"body": ""}).status_code == 422
    assert post(f"{url}/comments", headers=h["auditor"], json={"body": "x"}).status_code == 403
    fetched = client.get(url, headers=h["auditor"]).json()
    assert [c["body"] for c in fetched["comments"]] == ["Checked the host"]

    # Listing and filters; the auditor can read.
    second = post(
        "/api/v1/cases", headers=analyst, json={"title": "Other", "severity": "low"}
    ).json()
    assert client.get("/api/v1/cases", headers=h["auditor"]).json()["total"] == 2
    resolved = client.get("/api/v1/cases?status=resolved", headers=h["auditor"]).json()
    assert [c["id"] for c in resolved["items"]] == [case_id]
    low = client.get("/api/v1/cases?severity=low", headers=h["auditor"]).json()
    assert [c["id"] for c in low["items"]] == [second["id"]]

    assignees = client.get("/api/v1/cases/assignees", headers=h["auditor"]).json()
    assert {row["email"] for row in assignees} == {
        tenant.emails["administrator"],
        tenant.emails["analyst"],
    }
    missing = f"/api/v1/cases/{UNKNOWN}"
    assert client.get(missing, headers=analyst).status_code == 404
    assert patch(missing, headers=analyst, json={"title": "x"}).status_code == 404
    assert post(f"{missing}/comments", headers=analyst, json={"body": "x"}).status_code == 404


def test_response_simulation_needs_an_administrator_to_approve(tenant) -> None:
    client, h = tenant.client, tenant.headers
    case_id = client.post("/api/v1/cases", headers=h["analyst"], json={"title": "Respond"}).json()[
        "id"
    ]
    proposal = {
        "action_type": "simulate_host_isolation",
        "target": "pc-1",
        "rationale": "Repeated failed sign-ins from this host",
    }
    responses = f"/api/v1/cases/{case_id}/responses"
    short = {**proposal, "rationale": "short"}
    assert client.post(responses, headers=h["analyst"], json=short).status_code == 422
    created = client.post(responses, headers=h["analyst"], json=proposal)
    assert created.status_code == 201, created.text
    response_id = created.json()["id"]

    approve = f"{responses}/{response_id}/approve"
    assert client.post(approve, headers=h["analyst"]).status_code == 403
    approved = client.post(approve, headers=h["administrator"])
    assert approved.status_code == 200, approved.text
    simulated = client.post(f"{responses}/{response_id}/simulate", headers=h["administrator"])
    assert simulated.status_code == 200, simulated.text
    assert (
        client.get("/api/v1/cases/pending-approvals", headers=h["administrator"]).status_code == 200
    )
