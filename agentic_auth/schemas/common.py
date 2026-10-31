"""Shared response envelope, pagination, and error models (rest-response-standard)."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

DEFAULT_PAGE_LIMIT = 20
MAX_PAGE_LIMIT = 100


class PageInfo(BaseModel):
    next_cursor: str | None = None
    limit: int


class Page[T](BaseModel):
    data: list[T]
    page: PageInfo


class FieldError(BaseModel):
    loc: list[str]
    msg: str


class ErrorBody(BaseModel):
    code: str
    message: str
    details: dict[str, Any] | None = None


class ErrorEnvelope(BaseModel):
    error: ErrorBody


class PaginationParams(BaseModel):
    limit: int = Field(default=DEFAULT_PAGE_LIMIT, ge=1, le=MAX_PAGE_LIMIT)
    cursor: str | None = None
