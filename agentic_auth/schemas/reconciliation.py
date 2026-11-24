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
    # 0.4.0 (feature 011, M3): the check against each MCP server's authorization server.
    # A declared data class (an OAuth scope, research R7) that server does not issue.
    DECLARED_EXCEEDS_AUTHORIZATION_SERVER = "DECLARED_EXCEEDS_AUTHORIZATION_SERVER"
    # Its metadata could not be fetched: blocks like DISCOVERY_UNAVAILABLE does.
    AUTHORIZATION_SERVER_UNAVAILABLE = "AUTHORIZATION_SERVER_UNAVAILABLE"
    # There was nothing to check against. Informational: never changes the status.
    AUTHORIZATION_SERVER_CHECK_SKIPPED = "AUTHORIZATION_SERVER_CHECK_SKIPPED"


HARD_CODES = frozenset(
    {
        DiffCode.DECLARED_EXCEEDS_DISCOVERED,
        DiffCode.DATA_CLASS_CONFLICT,
        DiffCode.UNKNOWN_TOOL,
        DiffCode.DECLARED_EXCEEDS_AUTHORIZATION_SERVER,
    }
)

# Reported so the diff says what was and was not checked, but never a reason to block.
INFORMATIONAL_CODES = frozenset({DiffCode.AUTHORIZATION_SERVER_CHECK_SKIPPED})


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
