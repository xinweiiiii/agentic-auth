"""Client mappings: which registered agent an IdP client acts as (feature 011, M4)."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class AgentClientCreate(BaseModel):
    """Map the IdP client ``client_id`` (the ``azp`` of its tokens) to this agent.

    The issuer is not accepted from the request: it is always the deployment's configured
    principal IdP, the only one whose tokens consent will verify.
    """

    model_config = ConfigDict(extra="forbid")

    client_id: str = Field(min_length=1, max_length=255, pattern=r"^\S+$")


class AgentClientRead(BaseModel):
    model_config = ConfigDict(extra="forbid", from_attributes=True)

    id: uuid.UUID
    agent_id: uuid.UUID
    issuer: str
    client_id: str
    created_at: datetime
    created_by: str
    removed_at: datetime | None = None
    removed_by: str | None = None
