"""Request/response models for the ``/v1/manifests`` endpoints."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict

from app.schemas.agent import ManifestStatus, OverrideDecl
from app.schemas.manifest import AgentManifest


class ManifestCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    agent: str
    manifest: AgentManifest
    override: OverrideDecl | None = None


class ManifestSubmitted(BaseModel):
    agent: str
    version: int
    status: ManifestStatus


class ManifestRead(BaseModel):
    agent: str
    version: int
    status: ManifestStatus
    attested_by: str
    doc: dict
    created_at: datetime


class ManifestListItem(BaseModel):
    version: int
    status: ManifestStatus
    created_at: datetime
