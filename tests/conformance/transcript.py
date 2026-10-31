"""What a scenario observed, in a form two deployments can be compared on.

Identifiers differ between runs and deployments by construction — a session id, a JTI, a
signed token, a timestamp — so each is replaced by an ordinal in order of first appearance:
the first session id seen is ``<uuid:1>`` in both transcripts, and an identical scenario
therefore produces an identical transcript. Order is kept: it is part of what is compared.
"""

from __future__ import annotations

import json
import re
from typing import Any

from agentic_auth.sdk import Grant, PolicyDenied

# scenario -> deployment -> normalized steps
RESULTS: dict[str, dict[str, list[Any]]] = {}

# `deployment` is the one field that is allowed, and expected, to differ.
ALLOWED_DIFFERENCES = frozenset({"deployment"})

_PATTERNS = [
    ("jws", re.compile(r"\beyJ[\w-]+\.[\w-]+\.[\w-]+")),
    ("uuid", re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b")),
    ("ts", re.compile(r"\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?")),
]


def normalize(value: Any) -> Any:
    text = json.dumps(value, sort_keys=True, default=str)
    for kind, pattern in _PATTERNS:
        seen: dict[str, str] = {}

        def ordinal(match: re.Match[str], kind: str = kind, seen: dict[str, str] = seen) -> str:
            return seen.setdefault(match.group(0), f"<{kind}:{len(seen) + 1}>")

        text = pattern.sub(ordinal, text)
    return json.loads(text)


def strip_allowed(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: strip_allowed(v) for k, v in value.items() if k not in ALLOWED_DIFFERENCES}
    if isinstance(value, list):
        return [strip_allowed(v) for v in value]
    return value


class Transcript:
    def __init__(self, scenario: str, deployment: str) -> None:
        self.scenario = scenario
        self.deployment = deployment
        self.steps: list[Any] = []

    def add(self, step: str, payload: Any) -> None:
        self.steps.append([step, payload])

    def grant(self, step: str, grant: Grant) -> Grant:
        self.add(
            step,
            {
                "hop": grant.hop,
                "scope": grant.scope,
                "transaction_token": grant.transaction_token is not None,
                "taint": str(grant.taint) if grant.taint is not None else None,
            },
        )
        return grant

    def denial(self, step: str, denied: PolicyDenied) -> None:
        self.add(
            step,
            {
                "reason": denied.reason.value,
                "recoverable": denied.recoverable,
                "hop": denied.hop,
                "target": denied.target,
            },
        )

    def save(self) -> None:
        RESULTS.setdefault(self.scenario, {})[self.deployment] = normalize(self.steps)


def audit_view(page: dict[str, Any]) -> list[dict[str, Any]]:
    """The audit fields a scenario compares, oldest first (the list is newest first)."""
    rows = list(reversed(page["data"]))
    keep = (
        "hop",
        "acting_agent",
        "outcome",
        "deny_reason",
        "caller",
        "target",
        "data_class",
        "enforced",
        "policy_version",
        "chain_complete",
        "taint",
        "privileged",
        "guarantee_level",
        "deployment",
    )
    return [{k: row.get(k) for k in keep} for row in rows]


def chain_view(chain: dict[str, Any]) -> dict[str, Any]:
    return {
        "complete": chain["complete"],
        "break": chain["break"],
        "policy_version": chain["policy_version"],
        "root": {k: chain["root_consent"][k] for k in ("user_sub", "scope")},
        "hops": [
            {k: hop.get(k) for k in ("hop", "acting_agent", "target", "data_class", "decision")}
            for hop in chain["chain"]
        ],
    }
