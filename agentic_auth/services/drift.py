"""The offline drift check — observed edges versus declared manifests.

Runs from files only: manifests from local directories, edges from a recorded trace. There is
no network code on this path — no discovery, no reconciliation, no control plane —
because the question is only "was every observed edge declared", and CI should be able to
answer it with no credentials and no services.

The verdict for every edge comes from :func:`agentic_auth.services.edge_rules.classify_edge`, the
function the runtime PDP calls, over an index built by the same compiler.

Never a pass without evidence. Invalid or missing inputs, lost events, and a run that
observed nothing at all are each a distinct ``error`` result.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

import yaml
from pydantic import ValidationError

from agentic_auth.errors import DagCycleError
from agentic_auth.schemas.edge_trace import (
    DriftError,
    DriftInputs,
    DriftReport,
    DriftSummary,
    DriftWarning,
    EdgeTrace,
    UndeclaredEdge,
)
from agentic_auth.schemas.manifest import AgentManifest
from agentic_auth.services.dag_compiler import DagCompiler
from agentic_auth.services.edge_rules import RUNTIME_REASON, EdgeVerdict, classify_edge
from agentic_auth.services.policy_loader import PolicyIndex, build_graph_index

MANIFEST_SUFFIXES = frozenset({".yaml", ".yml", ".json"})

# `mutmut run` leaves a handful of equivalent mutants here, all of which rewrite prose: the
# `message` of a `DriftError`/`DriftWarning`, or the text `_hint` composes. Neither is the
# machine contract — CI branches on the exit code, and a reader branches on `code`,
# `verdict`, `runtime_reason` and the edge itself, every one of which is asserted in
# tests/unit/test_drift_diff.py. Any mutant that changes a result, a verdict, a count, or
# which edges are reported is killed.


@dataclass
class LoadedManifests:
    manifests: dict[str, AgentManifest] = field(default_factory=dict)
    # agent name -> the file that declares it, as found under the given directory
    paths: dict[str, str] = field(default_factory=dict)
    skipped: list[str] = field(default_factory=list)
    errors: list[DriftError] = field(default_factory=list)
    empty_dirs: list[str] = field(default_factory=list)


def _field_errors(exc: ValidationError) -> str:
    return "; ".join(
        f"{'.'.join(str(p) for p in err['loc']) or '(root)'}: {err['msg']}" for err in exc.errors()
    )


def load_manifest_dirs(dirs: Sequence[Path]) -> LoadedManifests:
    loaded = LoadedManifests()
    for directory in dirs:
        if not directory.is_dir():
            loaded.errors.append(
                DriftError(
                    code="NO_MANIFESTS_FOUND",
                    message=f"manifest location {directory} is not a directory",
                    path=str(directory),
                )
            )
            continue

        # A flag, not a tally: nothing downstream cares how many this directory contributed,
        # only whether it contributed anything at all.
        contributed = False
        candidates = sorted(
            p for p in directory.rglob("*") if p.is_file() and p.suffix in MANIFEST_SUFFIXES
        )
        for path in candidates:
            try:
                doc = yaml.safe_load(path.read_text(encoding="utf-8"))  # also parses JSON
            except (yaml.YAMLError, UnicodeDecodeError) as exc:
                loaded.errors.append(
                    DriftError(
                        code="MANIFEST_INVALID",
                        message=f"not valid YAML or JSON: {type(exc).__name__}",
                        path=str(path),
                    )
                )
                continue

            if not isinstance(doc, dict) or doc.get("kind") != "AgentManifest":
                loaded.skipped.append(str(path))
                continue

            try:
                manifest = AgentManifest.model_validate(doc)
            except ValidationError as exc:
                loaded.errors.append(
                    DriftError(code="MANIFEST_INVALID", message=_field_errors(exc), path=str(path))
                )
                continue

            name = manifest.metadata.agent
            if name in loaded.manifests:
                loaded.errors.append(
                    DriftError(
                        code="MANIFEST_DUPLICATE_AGENT",
                        message=(
                            f"agent {name!r} is declared in both {loaded.paths[name]} and {path}"
                        ),
                        path=str(path),
                    )
                )
                continue

            loaded.manifests[name] = manifest
            loaded.paths[name] = str(path)
            contributed = True

        if not contributed:
            loaded.empty_dirs.append(str(directory))

    if not loaded.manifests and not loaded.errors:
        loaded.errors.append(
            DriftError(
                code="NO_MANIFESTS_FOUND",
                message="no AgentManifest documents under any --manifest location",
            )
        )
    return loaded


def declared_graph(manifests: Mapping[str, AgentManifest]) -> PolicyIndex:
    """Compile with the runtime's compiler, then index every agent. Raises ``DagCycleError``."""
    return build_graph_index(DagCompiler().compile(dict(manifests)))


def registration_order(manifests: Mapping[str, AgentManifest]) -> list[str]:
    """Leaf first: every downstream agent before the agent that delegates to it, so each
    reference resolves at compile time when registering against a control plane."""
    ordered: list[str] = []

    def visit(name: str, stack: tuple[str, ...]) -> None:
        if name in ordered or name not in manifests or name in stack:
            return
        for downstream in manifests[name].spec.downstream_agents:
            visit(downstream.ref.removeprefix("agent://"), (*stack, name))
        ordered.append(name)

    for name in sorted(manifests):
        visit(name, ())
    return ordered


def load_trace(path: Path) -> EdgeTrace | DriftError:
    if not path.is_file():
        return DriftError(code="TRACE_MISSING", message=f"no trace file at {path}", path=str(path))
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        return DriftError(
            code="TRACE_MALFORMED", message=f"not valid JSON: {type(exc).__name__}", path=str(path)
        )
    if isinstance(raw, dict) and raw.get("schema_version") not in (None, 1):
        return DriftError(
            code="TRACE_UNSUPPORTED_VERSION",
            message=(
                f"trace schema_version {raw.get('schema_version')!r} is not supported (expected 1)"
            ),
            path=str(path),
        )
    try:
        return EdgeTrace.model_validate(raw)
    except ValidationError as exc:
        return DriftError(code="TRACE_MALFORMED", message=_field_errors(exc), path=str(path))


def _hint(verdict: EdgeVerdict, caller: str, target: str, manifest_path: str | None) -> str:
    where = manifest_path or "its manifest"
    if verdict is EdgeVerdict.UNDECLARED_TOOL:
        return f"remove the call from {caller}, or add {target} to spec.tools in {where}"
    if verdict is EdgeVerdict.UNDECLARED_DELEGATION:
        return (
            f"remove the delegation from {caller}, or add {target} to spec.downstream_agents in "
            f"{where} (with that agent's manifest in a --manifest location)"
        )
    return f"no manifest declares agent {caller!r}; add its manifest to a --manifest location"


def diff(
    trace: EdgeTrace,
    graph: PolicyIndex,
    manifest_paths: Mapping[str, str],
    *,
    inputs: DriftInputs,
) -> DriftReport:
    """Pure: every observed edge judged by the runtime's own edge rule."""
    errors: list[DriftError] = []
    if trace.recorder_errors > 0:
        errors.append(
            DriftError(
                code="TRACE_RECORDER_ERRORS",
                message=(
                    f"{trace.recorder_errors} recorded event(s) were lost or unreadable; "
                    "the evidence is incomplete, so no pass can be reported"
                ),
            )
        )
    if not trace.edges:
        errors.append(
            DriftError(
                code="NO_EDGES_OBSERVED",
                message=(
                    "the trace contains no attributed edges — was the sidecar or SDK in the call "
                    "path, and could it reach the control plane?"
                ),
            )
        )

    undeclared: list[UndeclaredEdge] = []
    declared = 0
    for edge in sorted(trace.edges, key=lambda e: (e.from_, e.to)):
        verdict = classify_edge(graph, edge.from_, edge.to)
        if verdict is EdgeVerdict.DECLARED:
            declared += 1
            continue
        manifest_path = (
            None if verdict is EdgeVerdict.UNKNOWN_AGENT else manifest_paths.get(edge.from_)
        )
        undeclared.append(
            UndeclaredEdge(
                from_=edge.from_,
                to=edge.to,
                kind=edge.kind,
                count=edge.count,
                verdict=verdict.value,
                runtime_reason=RUNTIME_REASON[verdict].value,
                manifest_path=manifest_path,
                hint=_hint(verdict, edge.from_, edge.to, manifest_path),
            )
        )

    warnings: list[DriftWarning] = []
    if trace.unattributed.count:
        breakdown = ", ".join(f"{k}: {v}" for k, v in sorted(trace.unattributed.by_reason.items()))
        warnings.append(
            DriftWarning(
                code="UNATTRIBUTED_CALLS",
                message=f"{trace.unattributed.count} call(s) could not be attributed ({breakdown})",
            )
        )

    result = "error" if errors else ("drift" if undeclared else "pass")
    return DriftReport(
        result=result,
        summary=DriftSummary(
            edges_observed=len(trace.edges),
            edges_declared=declared,
            edges_undeclared=len(undeclared),
            calls_observed=sum(e.count for e in trace.edges),
            unattributed_calls=trace.unattributed.count,
        ),
        undeclared=undeclared,
        errors=errors,
        warnings=warnings,
        inputs=inputs,
    )


def _error_report(
    errors: list[DriftError], warnings: list[DriftWarning], inputs: DriftInputs
) -> DriftReport:
    return DriftReport(
        result="error",
        summary=DriftSummary(
            edges_observed=0,
            edges_declared=0,
            edges_undeclared=0,
            calls_observed=0,
            unattributed_calls=0,
        ),
        undeclared=[],
        errors=errors,
        warnings=warnings,
        inputs=inputs,
    )


def run_check(
    manifest_dirs: Sequence[Path], trace_path: Path, *, generated_at: datetime | None
) -> DriftReport:
    loaded = load_manifest_dirs(manifest_dirs)
    inputs = DriftInputs(
        manifest_dirs=[str(d) for d in manifest_dirs],
        trace=str(trace_path),
        manifests_loaded=len(loaded.manifests),
        skipped_files=loaded.skipped,
        generated_at=generated_at,
    )
    errors = list(loaded.errors)
    warnings = [
        DriftWarning(code="UNUSED_MANIFEST_DIR", message=f"{d} contributed no manifests")
        for d in loaded.empty_dirs
        if loaded.manifests  # an all-empty run is already the NO_MANIFESTS_FOUND error
    ]

    trace = load_trace(trace_path)
    if isinstance(trace, DriftError):
        errors.append(trace)

    graph: PolicyIndex | None = None
    if not loaded.errors:
        try:
            graph = declared_graph(loaded.manifests)
        except DagCycleError as exc:
            errors.append(DriftError(code="DELEGATION_CYCLE", message=exc.message))

    if errors or graph is None or isinstance(trace, DriftError):
        return _error_report(errors, warnings, inputs)

    report = diff(trace, graph, loaded.paths, inputs=inputs)
    return report.model_copy(update={"warnings": [*warnings, *report.warnings]})
