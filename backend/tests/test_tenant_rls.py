import os
from uuid import uuid4

import pytest
from app.db.base import Base
from app.models import entities  # noqa: F401 — register application metadata.
from sqlalchemy import create_engine, text
from sqlalchemy.exc import DBAPIError


@pytest.mark.skipif(
    not os.environ.get("TENANT_TEST_DATABASE_URL"),
    reason="tenant row-security integration test requires a provisioned PostgreSQL runtime role",
)
def test_runtime_role_isolates_organization_rows() -> None:
    engine = create_engine(os.environ["TENANT_TEST_DATABASE_URL"])
    organization_a = uuid4()
    organization_b = uuid4()
    try:
        with engine.connect() as connection:
            transaction = connection.begin()
            try:
                role_flags = connection.execute(
                    text(
                        "SELECT rolsuper, rolbypassrls FROM pg_roles "
                        "WHERE rolname = current_user"
                    )
                ).one()
                assert role_flags == (False, False)
                tenant_tables = {
                    table.name
                    for table in Base.metadata.tables.values()
                    if "organization_id" in table.c
                }
                secured_tables = set(
                    connection.scalars(
                        text(
                            "SELECT relname FROM pg_class "
                            "WHERE relnamespace = 'public'::regnamespace "
                            "AND relkind = 'r' AND relrowsecurity AND relforcerowsecurity"
                        )
                    )
                )
                assert tenant_tables <= secured_tables
                connection.execute(
                    text("INSERT INTO organizations (id, slug, name) VALUES (:id, :slug, :name)"),
                    {"id": organization_a, "slug": f"test-{organization_a.hex}", "name": "A"},
                )
                connection.execute(
                    text("INSERT INTO organizations (id, slug, name) VALUES (:id, :slug, :name)"),
                    {"id": organization_b, "slug": f"test-{organization_b.hex}", "name": "B"},
                )
                connection.execute(
                    text("SELECT set_config('app.current_organization_id', :id, true)"),
                    {"id": str(organization_a)},
                )
                connection.execute(
                    text(
                        "INSERT INTO data_sources (id, organization_id, name, source_type, config) "
                        "VALUES (:id, :organization_id, :name, 'test', '{}'::jsonb)"
                    ),
                    {
                        "id": uuid4(),
                        "organization_id": organization_a,
                        "name": f"source-a-{organization_a.hex}",
                    },
                )
                connection.execute(
                    text("SELECT set_config('app.current_organization_id', :id, true)"),
                    {"id": str(organization_b)},
                )
                source_b = f"source-b-{organization_b.hex}"
                connection.execute(
                    text(
                        "INSERT INTO data_sources (id, organization_id, name, source_type, config) "
                        "VALUES (:id, :organization_id, :name, 'test', '{}'::jsonb)"
                    ),
                    {"id": uuid4(), "organization_id": organization_b, "name": source_b},
                )
                connection.execute(
                    text("SELECT set_config('app.current_organization_id', :id, true)"),
                    {"id": str(organization_a)},
                )
                visible = connection.scalar(text("SELECT count(*) FROM data_sources"))
                cross_tenant_update = connection.execute(
                    text("UPDATE data_sources SET name = 'changed' WHERE name = :name"),
                    {"name": source_b},
                )
                with pytest.raises(DBAPIError):
                    with connection.begin_nested():
                        connection.execute(
                            text(
                                "INSERT INTO data_sources "
                                "(id, organization_id, name, source_type, config) "
                                "VALUES (:id, :organization_id, :name, 'test', '{}'::jsonb)"
                            ),
                            {
                                "id": uuid4(),
                                "organization_id": organization_b,
                                "name": f"blocked-{organization_b.hex}",
                            },
                        )
                connection.execute(
                    text("SELECT set_config('app.current_organization_id', '', true)")
                )
                unscoped = connection.scalar(text("SELECT count(*) FROM data_sources"))
                assert visible == 1
                assert cross_tenant_update.rowcount == 0
                assert unscoped == 0
            finally:
                transaction.rollback()
    finally:
        engine.dispose()
