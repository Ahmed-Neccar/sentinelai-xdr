import pytest
from app.core.config import Settings
from pydantic import ValidationError

BASE_PRODUCTION_SETTINGS = {
    "SENTINEL_ENV": "production",
    "SECRET_KEY": "a" * 48,
    "MFA_ENCRYPTION_KEY": "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=",
    "CLOUD_CONNECTOR_ENCRYPTION_KEY": "YmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmI=",
    "SENTINEL_BOOTSTRAP_ADMIN_PASSWORD": "",
    "DATABASE_URL": "postgresql+psycopg://sentinel_runtime:strong-app-password@db:5432/sentinel",
    "REDIS_URL": "redis://redis:6379/0",
    "SENTINEL_JOB_RUNNER": "celery",
    "CORS_ORIGINS": "https://xdr.example.com",
}


def production_settings(**overrides: str) -> Settings:
    return Settings(_env_file=None, **(BASE_PRODUCTION_SETTINGS | overrides))


def test_production_configuration_accepts_secure_baseline() -> None:
    settings = production_settings()
    assert settings.sentinel_env == "production"


@pytest.mark.parametrize(
    ("key", "value", "message"),
    [
        ("SECRET_KEY", "dev-insecure-change-me", "SECRET_KEY"),
        ("SECRET_KEY", "replace-with-a-long-random-string", "SECRET_KEY"),
        ("MFA_ENCRYPTION_KEY", None, "MFA_ENCRYPTION_KEY"),
        ("MFA_ENCRYPTION_KEY", "not-a-valid-key", "MFA_ENCRYPTION_KEY"),
        ("CLOUD_CONNECTOR_ENCRYPTION_KEY", None, "CLOUD_CONNECTOR_ENCRYPTION_KEY"),
        (
            "CLOUD_CONNECTOR_ENCRYPTION_KEY",
            "not-a-valid-key",
            "CLOUD_CONNECTOR_ENCRYPTION_KEY",
        ),
        (
            "DATABASE_URL",
            "postgresql+psycopg://sentinel_runtime:sentinel_runtime_dev_only@db:5432/sentinel",
            "DATABASE_URL",
        ),
        ("REDIS_URL", None, "REDIS_URL"),
        ("SENTINEL_JOB_RUNNER", "thread", "SENTINEL_JOB_RUNNER"),
        ("CORS_ORIGINS", "http://xdr.example.com", "CORS_ORIGINS"),
    ],
)
def test_production_configuration_rejects_unsafe_defaults(
    key: str, value: str | None, message: str
) -> None:
    with pytest.raises(ValidationError, match=message):
        production_settings(**{key: value})


def test_unknown_environment_is_rejected() -> None:
    with pytest.raises(ValidationError, match="SENTINEL_ENV"):
        Settings(_env_file=None, SENTINEL_ENV="staging")


def test_connector_and_mfa_encryption_keys_must_be_distinct() -> None:
    with pytest.raises(ValidationError, match="must be different"):
        production_settings(
            CLOUD_CONNECTOR_ENCRYPTION_KEY=BASE_PRODUCTION_SETTINGS["MFA_ENCRYPTION_KEY"]
        )


@pytest.mark.parametrize(
    ("migration_url", "message"),
    [
        (None, "MIGRATION_DATABASE_URL"),
        (
            "postgresql+psycopg://sentinel_migrator:sentinel_migrator_dev_only@db:5432/sentinel",
            "private migration password",
        ),
        (
            "postgresql+psycopg://sentinel:strong-password@db:5432/sentinel",
            "bootstrap role",
        ),
    ],
)
def test_migration_component_requires_private_schema_owner_role(
    migration_url: str | None, message: str
) -> None:
    with pytest.raises(ValidationError, match=message):
        production_settings(
            SENTINEL_COMPONENT="migration",
            MIGRATION_DATABASE_URL=migration_url,
        )


def test_optional_settings_left_empty_by_compose_count_as_not_configured() -> None:
    # Compose passes ${METRICS_TOKEN:-} and the OIDC variables as empty strings.
    settings = production_settings(
        METRICS_TOKEN="",
        OIDC_ISSUER="",
        OIDC_CLIENT_ID="",
        OIDC_CLIENT_SECRET=" ",  # noqa: S106 - a blank value under test, not a secret
        OIDC_REDIRECT_URI="",
    )
    assert settings.metrics_token is None and settings.oidc_issuer is None
    # A token that is set must still be long enough, and empty required keys still fail.
    with pytest.raises(ValidationError, match="METRICS_TOKEN"):
        production_settings(METRICS_TOKEN="short")  # noqa: S106 - test value
    with pytest.raises(ValidationError, match="MFA_ENCRYPTION_KEY"):
        production_settings(MFA_ENCRYPTION_KEY="")
    with pytest.raises(ValidationError, match="CLOUD_CONNECTOR_ENCRYPTION_KEY"):
        production_settings(CLOUD_CONNECTOR_ENCRYPTION_KEY="")
