"""Cold-start schemas — see ``contracts/coldstart.openapi.yaml``."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

MIN_RUN_DEADLINE = 10
MAX_RUN_DEADLINE = 3600
MAX_MOCK_TOOLS = 64


class SandboxStart(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scope: str = Field(
        min_length=1,
        max_length=255,
        description="The synthetic all-allow scope this run is driven under.",
    )
    deadline_seconds: int | None = Field(
        default=None,
        ge=MIN_RUN_DEADLINE,
        le=MAX_RUN_DEADLINE,
        description=(
            "The run ends here whether or not the agent stopped, and the proposal "
            "covers what was observed up to that point (FR-033)."
        ),
    )
    mock_tools: list[str] = Field(
        default_factory=list,
        max_length=MAX_MOCK_TOOLS,
        description=(
            "Tool refs the sandbox exposes. Every one is backed by a recorder that "
            "performs nothing; a ref not listed here is unreachable from the sandbox, "
            "which is what bounds the risk of observing an unknown agent."
        ),
    )


class ObservedRead(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tools: list[str] = Field(default_factory=list)
    data_classes: list[str] = Field(default_factory=list)
    downstream_agents: list[str] = Field(default_factory=list)
    deepest_chain: int = 1


class SandboxRunRead(BaseModel):
    model_config = ConfigDict(extra="forbid", from_attributes=True)

    id: uuid.UUID
    agent_id: uuid.UUID
    status: Literal["running", "completed", "deadline_exceeded", "failed"]
    scope: str
    started_at: datetime
    deadline_at: datetime
    ended_at: datetime | None = None
    recorder_errors: int = Field(
        default=0,
        description=(
            "Events the recorder could not write. Non-zero means observation was "
            "incomplete, so the proposal may be narrower than the agent's real "
            "behaviour — and the proposal says so rather than under-declaring quietly."
        ),
    )
    observed: ObservedRead | None = None


class SandboxRunListItem(BaseModel):
    model_config = ConfigDict(extra="forbid", from_attributes=True)

    id: uuid.UUID
    status: str
    started_at: datetime
    ended_at: datetime | None = None


class SandboxRunPage(BaseModel):
    model_config = ConfigDict(extra="forbid")

    data: list[SandboxRunListItem]
    next_cursor: str | None = None


class ProposedManifestRead(BaseModel):
    model_config = ConfigDict(extra="forbid")

    manifest_id: uuid.UUID
    agent_id: uuid.UUID
    run_id: uuid.UUID
    status: Literal["proposed"]
    doc: dict[str, Any]
    covers_no_behaviour: bool = Field(
        description=(
            "The run reached no tools at all. Marked rather than presented as a "
            "complete manifest, because an empty manifest and 'we watched and saw "
            "nothing' are the same document and completely different facts (FR-041)."
        )
    )


class RatifyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    run_id: uuid.UUID
    doc: dict[str, Any] | None = Field(
        default=None,
        description=(
            "The administrator's edited document. Omitted means 'ratify as generated'. "
            "Present means THIS is what gets pinned — what was approved, not what was "
            "proposed (FR-039)."
        ),
    )
    note: str | None = Field(default=None, max_length=1024)


__all__ = [
    "MAX_MOCK_TOOLS",
    "MAX_RUN_DEADLINE",
    "MIN_RUN_DEADLINE",
    "ObservedRead",
    "ProposedManifestRead",
    "RatifyRequest",
    "SandboxRunListItem",
    "SandboxRunPage",
    "SandboxRunRead",
    "SandboxStart",
]
