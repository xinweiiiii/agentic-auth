"""Agent-side provenance: label a value by where it came from.

The control plane derives most taint itself from the calls it decides.
This module covers what it cannot see — content the agent obtained outside the system —
and mirrors the same glob rules so an agent that holds its own manifest classifies the way
the PDP would. A label can only RAISE the effective taint at the next decision.
"""

from __future__ import annotations

import fnmatch
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from app.schemas.authorize import Taint


@dataclass(frozen=True)
class Provenance:
    source_ref: str
    trust: Taint


@dataclass(frozen=True)
class LabeledResult[T]:
    value: T
    provenance: Provenance

    @property
    def tainted(self) -> bool:
        return self.provenance.trust is Taint.UNTRUSTED_EXTERNAL


class SourceClassifier:
    """``trusted_globs`` are this agent's ``taint_policy.trusted_sources`` (materialized:
    include ``agent://<downstream>`` for each declared downstream agent). Anything unmatched
    is untrusted_external, exactly as the PDP decides."""

    def __init__(self, trusted_globs: Iterable[str] = ()) -> None:
        self._globs = tuple(trusted_globs)

    @classmethod
    def from_manifest(cls, manifest: dict[str, Any]) -> SourceClassifier:
        spec = manifest.get("spec", {})
        policy = spec.get("taint_policy") or {}
        trusted = policy.get("trusted_sources")
        if trusted is None:
            trusted = [d["ref"] for d in spec.get("downstream_agents", [])]
        return cls(trusted)

    def classify(self, source_ref: str) -> Taint:
        return (
            Taint.TRUSTED_INTERNAL
            if any(fnmatch.fnmatchcase(source_ref, g) for g in self._globs)
            else Taint.UNTRUSTED_EXTERNAL
        )

    def wrap[T](self, value: T, source_ref: str) -> LabeledResult[T]:
        return LabeledResult(value, Provenance(source_ref, self.classify(source_ref)))


__all__ = ["LabeledResult", "Provenance", "SourceClassifier"]
