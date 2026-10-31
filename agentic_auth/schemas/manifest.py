"""The agent manifest — authored here as Pydantic v2 models.

``contracts/manifest.schema.json`` is exported from :meth:`AgentManifest.model_json_schema`
(see ``scripts/export_manifest_schema.py``); a unit test fails if the checked-in file
drifts.
"""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

AGENT_NAME_PATTERN = r"^[a-z0-9][a-z0-9-]{0,62}$"

AgentName = Annotated[str, StringConstraints(pattern=AGENT_NAME_PATTERN)]
ToolRef = Annotated[str, StringConstraints(pattern=r"^mcp://[^/]+/.+")]
AgentUri = Annotated[str, StringConstraints(pattern=r"^agent://[a-z0-9][a-z0-9-]{0,62}$")]
# RFC 6901: one or more "/" + reference-token segments; "~" only as ~0 / ~1.
JsonPointer = Annotated[str, StringConstraints(pattern=r"^(/([^/~]|~0|~1)*)+$", max_length=512)]
# fnmatch pattern over a target ref (or, for block_tainted_into, a data class).
Glob = Annotated[str, StringConstraints(min_length=1, max_length=512)]

MAX_HOP_BUDGET = 16


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ToolDecl(_Strict):
    ref: ToolRef
    data_classes: list[str] = Field(min_length=1)
    privileged: bool = False
    # Phase 4. Which parameters a transaction token binds, as RFC 6901 pointers. None =
    # the whole parameter body. Only meaningful on a privileged tool.
    binding_params: list[JsonPointer] | None = Field(default=None, min_length=1, max_length=64)


class DownstreamDecl(_Strict):
    ref: AgentUri
    max_hop_depth: int = Field(ge=1)


class DataClassDecl(_Strict):
    reads: list[str] = Field(default_factory=list)
    writes: list[str] = Field(default_factory=list)


class TaintPolicyDecl(_Strict):
    """Phase 4 provenance policy for THIS agent.

    ``trusted_sources``: globs over target refs whose results are trusted_internal for this
    agent. ``None`` means "my declared downstream agents, nothing else" — materialized by the
    compiler so the runtime never has to know the default. ``block_tainted_into``: targets a
    tainted context may not call; ``"privileged"`` means every privileged tool, a glob matches
    the target ref or the call's data class.
    """

    trusted_sources: list[Glob] | None = None
    block_tainted_into: list[Glob | Literal["privileged"]] = Field(
        default_factory=lambda: ["privileged"]
    )


class ManifestMetadata(_Strict):
    agent: AgentName
    # Server-assigned. MUST be absent/None on create; echoed on read.
    version: int | None = Field(default=None, ge=1)


class ManifestSpec(_Strict):
    tools: list[ToolDecl] = Field(min_length=1)
    data_classes: DataClassDecl = Field(default_factory=DataClassDecl)
    downstream_agents: list[DownstreamDecl] = Field(default_factory=list)
    hop_budget: int = Field(ge=1, le=MAX_HOP_BUDGET)
    taint_policy: TaintPolicyDecl = Field(default_factory=TaintPolicyDecl)


class AgentManifest(_Strict):
    apiVersion: Literal["agentic-auth/v1"]
    kind: Literal["AgentManifest"]
    metadata: ManifestMetadata
    spec: ManifestSpec

    @model_validator(mode="after")
    def _check_cross_fields(self) -> AgentManifest:
        declared = set(self.spec.data_classes.reads) | set(self.spec.data_classes.writes)
        for tool in self.spec.tools:
            missing = [dc for dc in tool.data_classes if dc not in declared]
            if missing:
                raise ValueError(
                    f"tool {tool.ref!r} lists data classes {missing} not present in "
                    f"spec.data_classes.reads/writes"
                )
            if tool.binding_params is not None and not tool.privileged:
                raise ValueError(
                    f"tool {tool.ref!r} declares binding_params but is not privileged; "
                    f"only a privileged tool receives a transaction token to bind"
                )
        for edge in self.spec.downstream_agents:
            if edge.max_hop_depth > self.spec.hop_budget:
                raise ValueError(
                    f"downstream {edge.ref!r} max_hop_depth "
                    f"({edge.max_hop_depth}) exceeds spec.hop_budget "
                    f"({self.spec.hop_budget})"
                )
        return self

    def ensure_create_form(self) -> None:
        """Raise ``ValueError`` if this document was submitted with a client-set version."""
        if self.metadata.version is not None:
            raise ValueError("metadata.version is server-assigned and must be omitted on create")

    def canonical_doc(self) -> dict:
        """Stable serialization stored verbatim so re-reads are byte-identical."""
        return self.model_dump(mode="json", exclude_none=False)
