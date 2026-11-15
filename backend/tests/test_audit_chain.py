"""The audit log is a hash chain: edits and middle removals show up, updates are refused."""

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError


def _integrity(tenant) -> dict:
    response = tenant.client.get("/api/v1/audit-logs/integrity", headers=tenant.headers["auditor"])
    assert response.status_code == 200, response.text
    return response.json()


def _generate(tenant, count: int = 3) -> None:
    for _ in range(count):
        tenant.client.post(
            "/api/v1/auth/login",
            json={
                "organization_slug": tenant.slug,
                "email": "nobody@example.test",
                "password": "wrong-password-1",
            },
        )


def test_a_fresh_log_passes_the_integrity_check(tenant) -> None:
    _generate(tenant)
    report = _integrity(tenant)
    assert report["ok"] is True and report["checked"] >= 3 and report["broken_at"] == []
    assert report["head_hash"]


def test_rows_are_linked_to_the_one_before(tenant) -> None:
    _generate(tenant)
    items = tenant.client.get(
        "/api/v1/audit-logs/export", headers=tenant.headers["auditor"]
    ).json()["items"]
    for before, after in zip(items, items[1:], strict=False):
        assert after["prev_hash"] == before["row_hash"]


def test_removing_a_row_from_the_middle_is_detected(tenant) -> None:
    _generate(tenant, 4)
    items = tenant.client.get(
        "/api/v1/audit-logs/export", headers=tenant.headers["auditor"]
    ).json()["items"]
    middle = items[len(items) // 2]["seq"]
    with tenant.session() as db:
        db.execute(text("DELETE FROM audit_logs WHERE seq = :seq"), {"seq": middle})
        db.commit()
    report = _integrity(tenant)
    assert report["ok"] is False and report["broken_at"]


def test_rows_cannot_be_updated(tenant) -> None:
    _generate(tenant)
    with tenant.session() as db:
        with pytest.raises(DBAPIError, match="cannot be changed"):
            db.execute(text("UPDATE audit_logs SET action = 'x'"))
            db.commit()


def test_the_export_pages_by_sequence_number(tenant) -> None:
    _generate(tenant, 5)
    client, headers = tenant.client, tenant.headers["auditor"]
    first = client.get("/api/v1/audit-logs/export?limit=2", headers=headers).json()
    assert len(first["items"]) == 2 and first["has_more"] is True
    second = client.get(
        f"/api/v1/audit-logs/export?limit=2&after_seq={first['next_seq']}", headers=headers
    ).json()
    assert second["items"][0]["seq"] > first["items"][-1]["seq"]
    denied = client.get("/api/v1/audit-logs/export", headers=tenant.headers["analyst"])
    assert denied.status_code == 403
