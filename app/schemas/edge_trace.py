"""Edge recording and drift reporting — see contracts/edge-trace.schema.json and data-model.md §5.

Every model is closed (``extra="forbid"``). There is no field anywhere in this module that
could carry a token, a header, a credential, a query string, or a payload — the absence is
the guarantee (SC-012), and a line or file with an unknown field is rejected rather than
partially trusted.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

AgentName = Annotated[str, StringConstraints(pattern=r"^[a-z0-9][a-z0-9-]{0,62}$")]
Target = Annotated[
    str,
    StringConstraints(
        pattern=r"^(mcp://[^/\s]+/\S+|agent://[a-z0-9][a-z0-9-]{0,62})$", max_length=512
    ),
]
Reason = Annotated[str, StringConstraints(pattern=r"^[A-Z_]{1,32}$")]
Kind = Literal["tool", "delegation"]
Outcome = Literal["allow", "deny", "observed", "blocked_infra", "blocked_local"]
Source = Literal["sidecar", "sdk"]
Verdict = Literal["UNDECLARED_TOOL", "UNDECLARED_DELEGATION", "UNKNOWN_AGENT"]

# Outcomes where the policy actually evaluated this caller -> target edge.
EVALUATED_OUTCOMES: frozenset[str] = frozenset({"allow", "deny", "observed"})


def kind_of(target: str | None) -> Kind | None:
    if target is None:
        return None
    return "delegation" if target.startswith("agent://") else "tool"


class _Closed(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)


# -- the JSONL events file -----------------------------------------------------


class EdgeEvent(_Closed):
    v: Literal[1] = 1
    ts: datetime
    source: Source
    acting_agent: AgentName | None
    target: Target | None
    kind: Kind | None
    outcome: Outcome
    reason: Reason | None

    @model_validator(mode="after")
    def _kind_matches_target(self) -> Self:
        if self.kind != kind_of(self.target):
            raise ValueError(f"kind {self.kind!r} does not match target {self.target!r}")
        return self


class RecorderErrorLine(_Closed):
    v: Literal[1] = 1
    ts: datetime
    source: Source
    recorder_error: int = Field(ge=1, description="Events lost since the last successful write")


# -- the aggregated trace --------------------------------------------------------


class EdgeOutcomes(_Closed):
    allow: int = Field(default=0, ge=0)
    deny: int = Field(default=0, ge=0)
    observed: int = Field(default=0, ge=0)


class ObservedEdge(_Closed):
    from_: AgentName = Field(alias="from")
    to: Target
    kind: Kind
    count: int = Field(ge=1)
    outcomes: EdgeOutcomes

    @model_validator(mode="after")
    def _consistent(self) -> Self:
        total = self.outcomes.allow + self.outcomes.deny + self.outcomes.observed
        if self.count != total:
            raise ValueError(f"count {self.count} does not equal the sum of outcomes ({total})")
        if self.kind != kind_of(self.to):
            raise ValueError(f"kind {self.kind!r} does not match target {self.to!r}")
        return self


class Unattributed(_Closed):
    count: int = Field(default=0, ge=0)
    by_reason: dict[str, Annotated[int, Field(ge=1)]] = Field(default_factory=dict)


class TraceRun(_Closed):
    started_at: datetime
    finished_at: datetime
    command: list[str] | None
    event_files: list[str]
    exit_code: int | None


class EdgeTrace(_Closed):
    schema_version: Literal[1] = 1
    run: TraceRun
    edges: list[ObservedEdge]
    unattributed: Unattributed
    recorder_errors: int = Field(ge=0)
    events_total: int = Field(ge=0)


# -- the drift report --------------------------------------------------------------


class UndeclaredEdge(_Closed):
    from_: str = Field(alias="from")
    to: str
    kind: Kind
    count: int = Field(ge=1)
    verdict: Verdict
    runtime_reason: str
    manifest_path: str | None
    hint: str


class DriftError(_Closed):
    code: str
    message: str
    path: str | None = None


class DriftWarning(_Closed):
    code: str
    message: str


class DriftSummary(_Closed):
    edges_observed: int = Field(ge=0)
    edges_declared: int = Field(ge=0)
    edges_undeclared: int = Field(ge=0)
    calls_observed: int = Field(ge=0)
    unattributed_calls: int = Field(ge=0)


class DriftInputs(_Closed):
    manifest_dirs: list[str]
    trace: str
    manifests_loaded: int = Field(ge=0)
    skipped_files: list[str]
    generated_at: datetime | None = None


class DriftReport(_Closed):
    schema_version: Literal[1] = 1
    result: Literal["pass", "drift", "error"]
    summary: DriftSummary
    undeclared: list[UndeclaredEdge]
    errors: list[DriftError]
    warnings: list[DriftWarning]
    inputs: DriftInputs
