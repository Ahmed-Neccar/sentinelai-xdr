"""Versioned canonical event envelope shared by all ingestion adapters."""

from datetime import UTC, datetime
from ipaddress import ip_address
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

EVENT_SCHEMA_VERSION = 1


class NormalizedEventV1(BaseModel):
    """Stable v1 event contract persisted by the ingestion pipeline."""

    model_config = ConfigDict(extra="forbid")

    event_time: datetime
    event_type: str = Field(min_length=1, max_length=128)
    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: int | None = Field(default=None, ge=0, le=65535)
    dst_port: int | None = Field(default=None, ge=0, le=65535)
    host_id: str | None = Field(default=None, max_length=255)
    severity: Literal["informational", "low", "medium", "high", "critical"] = "informational"
    attributes: dict[str, Any] = Field(default_factory=dict)
    raw_payload: dict[str, Any] = Field(default_factory=dict)
    schema_version: Literal[1] = 1
    dedup_key: str | None = Field(default=None, max_length=256)

    @field_validator("event_time")
    @classmethod
    def normalize_event_time(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            value = value.replace(tzinfo=UTC)
        return value.astimezone(UTC)

    @field_validator("event_type")
    @classmethod
    def normalize_event_type(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("event_type must not be blank")
        return value

    @field_validator("src_ip", "dst_ip", mode="before")
    @classmethod
    def validate_ip_address(cls, value: Any) -> str | None:
        if value in (None, ""):
            return None
        try:
            return str(ip_address(str(value)))
        except ValueError as exc:
            raise ValueError("must be a valid IPv4 or IPv6 address") from exc
