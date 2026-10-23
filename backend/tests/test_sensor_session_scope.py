from types import SimpleNamespace
from uuid import uuid4

import pytest
from app.api.v1.ingest import _assert_live_session_access
from app.core.errors import AppError
from app.schemas.common import TokenUser


def actor(user_id, roles):
    return TokenUser(
        id=user_id,
        organization_id=uuid4(),
        email="sensor@example.local",
        full_name="",
        roles=roles,
        is_active=True,
    )


def test_ingestion_identity_can_operate_its_own_live_session() -> None:
    owner_id = uuid4()
    _assert_live_session_access(
        SimpleNamespace(created_by=owner_id),
        actor(owner_id, ["ingestion_service"]),
    )


def test_ingestion_identity_cannot_operate_another_live_session() -> None:
    with pytest.raises(AppError) as error:
        _assert_live_session_access(
            SimpleNamespace(created_by=uuid4()),
            actor(uuid4(), ["ingestion_service"]),
        )
    assert error.value.status_code == 404


def test_analyst_can_manage_live_sessions_for_the_sensor_dashboard() -> None:
    _assert_live_session_access(
        SimpleNamespace(created_by=uuid4()),
        actor(uuid4(), ["analyst"]),
    )
