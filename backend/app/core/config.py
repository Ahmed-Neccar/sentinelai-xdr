import base64
import binascii
from functools import lru_cache
from urllib.parse import urlsplit

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=(".env", "../.env"), extra="ignore")

    app_name: str = "SentinelAI XDR"
    sentinel_env: str = Field(default="development", alias="SENTINEL_ENV")
    service_component: str = Field(default="api", alias="SENTINEL_COMPONENT")
    secret_key: str = Field(  # noqa: S105 - Development placeholder rejected outside development.
        default="dev-insecure-change-me",
        alias="SECRET_KEY",  # noqa: S105
    )
    mfa_encryption_key: str | None = Field(default=None, alias="MFA_ENCRYPTION_KEY")
    cloud_connector_encryption_key: str | None = Field(
        default=None, alias="CLOUD_CONNECTOR_ENCRYPTION_KEY"
    )
    metrics_token: str | None = Field(default=None, alias="METRICS_TOKEN")
    oidc_issuer: str | None = Field(default=None, alias="OIDC_ISSUER")
    oidc_client_id: str | None = Field(default=None, alias="OIDC_CLIENT_ID")
    oidc_client_secret: str | None = Field(default=None, alias="OIDC_CLIENT_SECRET")
    oidc_redirect_uri: str | None = Field(default=None, alias="OIDC_REDIRECT_URI")
    database_url: str = Field(
        default="postgresql+psycopg://sentinel:sentinel_dev_only@127.0.0.1:5432/sentinel",
        alias="DATABASE_URL",
    )
    migration_database_url: str | None = Field(default=None, alias="MIGRATION_DATABASE_URL")
    default_organization_slug: str = Field(
        default="default", alias="SENTINEL_DEFAULT_ORGANIZATION_SLUG"
    )
    default_organization_name: str = Field(
        default="SentinelAI Workspace", alias="SENTINEL_DEFAULT_ORGANIZATION_NAME"
    )
    redis_url: str | None = Field(default=None, alias="REDIS_URL")
    job_runner: str = Field(default="thread", alias="SENTINEL_JOB_RUNNER")
    cors_origins: str = Field(
        default="http://127.0.0.1:8080,http://127.0.0.1:5173",
        alias="CORS_ORIGINS",
    )
    # Reverse proxies whose X-Forwarded-For header is believed: comma-separated
    # addresses, CIDR ranges or resolvable host names. Empty means the header
    # is ignored and the connecting address is used.
    trusted_proxies: str = Field(default="", alias="TRUSTED_PROXIES")
    bootstrap_admin_email: str | None = Field(default=None, alias="SENTINEL_BOOTSTRAP_ADMIN_EMAIL")
    bootstrap_admin_password: str | None = Field(
        default=None, alias="SENTINEL_BOOTSTRAP_ADMIN_PASSWORD"
    )
    max_upload_bytes: int = Field(default=10 * 1024 * 1024, alias="MAX_UPLOAD_BYTES")
    max_upload_rows: int = Field(default=20_000, alias="MAX_UPLOAD_ROWS")
    retention_days: int = Field(default=90, ge=1, le=3650, alias="RETENTION_DAYS")
    upload_retention_days: int = Field(default=30, ge=1, le=3650, alias="UPLOAD_RETENTION_DAYS")
    access_token_minutes: int = Field(default=15, alias="ACCESS_TOKEN_MINUTES")
    refresh_token_hours: int = Field(default=8, alias="REFRESH_TOKEN_HOURS")
    # Hard ceiling for one sign-in. Each refresh rotates the token but never extends the
    # session beyond this, so a session cannot stay open for days by being used regularly.
    session_max_hours: int = Field(default=12, ge=1, le=720, alias="SESSION_MAX_HOURS")
    upload_dir: str = Field(default=".data/uploads", alias="UPLOAD_DIR")
    ml_artifact_dir: str = Field(default=".data/ml", alias="ML_ARTIFACT_DIR")

    @field_validator("job_runner")
    @classmethod
    def validate_runner(cls, value: str) -> str:
        allowed = {"celery", "thread", "inline"}
        if value not in allowed:
            raise ValueError(f"SENTINEL_JOB_RUNNER must be one of {allowed}")
        return value

    @field_validator(
        "metrics_token",
        "mfa_encryption_key",
        "cloud_connector_encryption_key",
        "oidc_issuer",
        "oidc_client_id",
        "oidc_client_secret",
        "oidc_redirect_uri",
        mode="before",
    )
    @classmethod
    def empty_means_not_configured(cls, value: object) -> object:
        # Compose passes an unset optional variable as an empty string. Without
        # this, production refused to start when METRICS_TOKEN was simply absent.
        if isinstance(value, str) and not value.strip():
            return None
        return value

    @field_validator("sentinel_env")
    @classmethod
    def validate_environment(cls, value: str) -> str:
        if value not in {"development", "production"}:
            raise ValueError("SENTINEL_ENV must be development or production")
        return value

    @field_validator("service_component")
    @classmethod
    def validate_component(cls, value: str) -> str:
        if value not in {"api", "worker", "migration"}:
            raise ValueError("SENTINEL_COMPONENT must be api, worker, or migration")
        return value

    @model_validator(mode="after")
    def validate_production_secrets(self) -> "Settings":
        if self.cloud_connector_encryption_key:
            try:
                connector_key = base64.urlsafe_b64decode(self.cloud_connector_encryption_key)
            except (ValueError, binascii.Error) as exc:
                raise ValueError(
                    "CLOUD_CONNECTOR_ENCRYPTION_KEY must be URL-safe base64 for 32 random bytes"
                ) from exc
            if len(connector_key) != 32:
                raise ValueError(
                    "CLOUD_CONNECTOR_ENCRYPTION_KEY must be URL-safe base64 for 32 random bytes"
                )
            if self.mfa_encryption_key:
                try:
                    mfa_key = base64.urlsafe_b64decode(self.mfa_encryption_key)
                except (ValueError, binascii.Error):
                    mfa_key = None
                if mfa_key == connector_key:
                    raise ValueError(
                        "MFA and cloud connector encryption keys must be different"
                    )
        if self.sentinel_env != "development":
            if (
                self.secret_key in {"dev-insecure-change-me", "replace-with-a-long-random-string"}
                or len(self.secret_key) < 32
            ):  # noqa: S105
                raise ValueError("SECRET_KEY must be at least 32 characters outside development")
            if self.bootstrap_admin_password and (
                len(self.bootstrap_admin_password) < 12
                or self.bootstrap_admin_password
                in {"change-me-now", "replace-with-a-separate-long-random-password"}
            ):
                raise ValueError(
                    "Bootstrap admin password must be private and at least 12 characters"
                )
            if self.service_component == "api":
                try:
                    key = base64.urlsafe_b64decode(self.mfa_encryption_key or "")
                except (ValueError, binascii.Error) as exc:
                    raise ValueError(
                        "MFA_ENCRYPTION_KEY must be URL-safe base64 for 32 random bytes"
                    ) from exc
                if len(key) != 32:
                    raise ValueError(
                        "MFA_ENCRYPTION_KEY must be URL-safe base64 for 32 random bytes"
                    )
                if not self.cloud_connector_encryption_key and self.service_component == "api":
                    raise ValueError(
                        "CLOUD_CONNECTOR_ENCRYPTION_KEY is required outside development"
                    )
                if self.metrics_token is not None and len(self.metrics_token) < 32:
                    raise ValueError("METRICS_TOKEN must be at least 32 characters when configured")
            oidc_values = (
                self.oidc_issuer,
                self.oidc_client_id,
                self.oidc_client_secret,
                self.oidc_redirect_uri,
            )
            if any(oidc_values) and not all(oidc_values):
                raise ValueError(
                    "OIDC_ISSUER, OIDC_CLIENT_ID, OIDC_CLIENT_SECRET, and "
                    "OIDC_REDIRECT_URI must be configured together"
                )
            if all(oidc_values):
                issuer = urlsplit(self.oidc_issuer or "")
                redirect = urlsplit(self.oidc_redirect_uri or "")
                if issuer.scheme != "https" or not issuer.netloc or issuer.query or issuer.fragment:
                    raise ValueError("OIDC_ISSUER must be an HTTPS issuer URL")
                if redirect.scheme != "https" or not redirect.netloc or redirect.fragment:
                    raise ValueError("OIDC_REDIRECT_URI must be an HTTPS URL without a fragment")
                if len(self.oidc_client_secret or "") < 32:
                    raise ValueError("OIDC_CLIENT_SECRET must be at least 32 characters")
            database = urlsplit(self.database_url)
            if database.password in {
                "sentinel_dev_only",
                "sentinel_runtime_dev_only",
                "sentinel_migrator_dev_only",
                "postgres",
                "password",
                "changeme",
            }:
                raise ValueError("DATABASE_URL must not use a development password in production")
            if database.username in {"sentinel", "postgres"}:
                raise ValueError("Service database must not use a bootstrap role")
            if self.service_component == "migration":
                migrator = urlsplit(self.migration_database_url or "")
                if not self.migration_database_url:
                    raise ValueError("MIGRATION_DATABASE_URL is required in production")
                if migrator.username in {"sentinel", "postgres"}:
                    raise ValueError("Migration database must not use a bootstrap role")
                if migrator.password in {
                    None,
                    "sentinel_dev_only",
                    "sentinel_migrator_dev_only",
                    "replace-with-a-long-random-string",
                    "postgres",
                    "password",
                    "changeme",
                }:
                    raise ValueError("MIGRATION_DATABASE_URL must use a private migration password")
            if self.redis_url is None:
                raise ValueError("REDIS_URL is required in production")
            if self.job_runner != "celery":
                raise ValueError("SENTINEL_JOB_RUNNER must be celery in production")
            if not self.cors_origin_list or any(
                urlsplit(origin).scheme != "https" or not urlsplit(origin).netloc
                for origin in self.cors_origin_list
            ):
                raise ValueError("CORS_ORIGINS must contain only HTTPS origins in production")
        return self

    @property
    def cors_origin_list(self) -> list[str]:
        return [part.strip() for part in self.cors_origins.split(",") if part.strip()]

    @property
    def is_development(self) -> bool:
        return self.sentinel_env == "development"


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
