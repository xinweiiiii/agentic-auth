"""Reconciliation diff model and report schemas."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, field_validator

from agentic_auth.schemas.agent import ManifestStatus


class DiffCode(StrEnum):
    DECLARED_EXCEEDS_DISCOVERED = "DECLARED_EXCEEDS_DISCOVERED"
    DATA_CLASS_CONFLICT = "DATA_CLASS_CONFLICT"
    DISCOVERY_UNAVAILABLE = "DISCOVERY_UNAVAILABLE"
    UNKNOWN_TOOL = "UNKNOWN_TOOL"


HARD_CODES = frozenset(
    {
        DiffCode.DECLARED_EXCEEDS_DISCOVERED,
        DiffCode.DATA_CLASS_CONFLICT,
        DiffCode.UNKNOWN_TOOL,
    }
)


class DiffEntry(BaseModel):
    tool_ref: str
    field: str
    declared: Any
    discovered: Any
    code: DiffCode
    remedy: str

    @field_validator("tool_ref", "remedy")
    @classmethod
    def _non_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("must not be empty")
        return v


class ReconciliationReport(BaseModel):
    manifest_version: int
    status: ManifestStatus
    discovery_ok: bool
    diff: list[DiffEntry]
