"""Request/response models for agent registration and reads."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict

from agentic_auth.schemas.manifest import AgentManifest, AgentName

ManifestStatus = Literal["reconciled", "needs_review", "rejected"]
# Phase 4 identity state.
AgentStatus = Literal["registered", "enrolled", "quarantined", "revoked"]


class OverrideDecl(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: str

    def validated_reason(self) -> str:
        if not self.reason.strip():
            raise ValueError("override.reason must not be empty")
        return self.reason


class AgentCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: AgentName
    manifest: AgentManifest
    override: OverrideDecl | None = None


class AgentRegistered(BaseModel):
    agent_id: uuid.UUID
    manifest_version: int
    status: ManifestStatus


class AgentRead(BaseModel):
    id: uuid.UUID
    name: str
    status: AgentStatus
    principal_ref: str | None
    trust_anchor_version: int | None
    latest_manifest_version: int | None
    latest_status: ManifestStatus | None
    created_at: datetime


class AgentListItem(BaseModel):
    id: uuid.UUID
    name: str
    status: AgentStatus
    trust_anchor_version: int | None
    latest_manifest_version: int | None
    latest_status: ManifestStatus | None
