from typing import Generic, TypeVar
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

T = TypeVar("T")


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class ErrorDetail(BaseModel):
    code: str
    message: str
    details: dict = Field(default_factory=dict)


class Page(BaseModel, Generic[T]):
    items: list[T]
    page: int
    page_size: int
    total: int


class TokenUser(BaseModel):
    id: UUID
    organization_id: UUID
    email: str
    full_name: str
    roles: list[str]
    is_active: bool
    auth_methods: list[str] = Field(default_factory=list)
