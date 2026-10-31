"""Read models for the compiled scope→capability DAG and scope catalog."""

from __future__ import annotations

from pydantic import BaseModel

from agentic_auth.schemas.manifest import DataClassDecl


class CatalogTool(BaseModel):
    ref: str
    data_classes: list[str]
    privileged: bool
    # Phase 4: RFC 6901 pointers a transaction token binds; None = whole body. Read-only.
    binding_params: list[str] | None = None


class DagPath(BaseModel):
    path: list[str]
    effective_hop_budget: int


class ScopeCatalog(BaseModel):
    scope: str
    version: int
    tools: list[CatalogTool]
    data_classes: DataClassDecl
    downstream_agents: list[str]
    hop_budget: int


class CompiledPolicyRead(BaseModel):
    scope: str
    version: int
    tools: list[CatalogTool]
    data_classes: DataClassDecl
    downstream_agents: list[str]
    hop_budget: int
    paths: list[DagPath]
