"""Typed attribute builders — the one place the allowlist and the disclosure rule are applied.

Every span attribute this layer emits is produced here. Nothing else constructs attribute dicts,
so there is exactly one place to audit for two rules: no secrets, and pseudonymous by
default), and exactly one place a test has to sweep.

Two behaviours that look inconsistent but are not:

- **In tests, an attribute outside the contract raises.** In production it is dropped and the
  span is emitted without it. Telemetry must never be the reason a request fails, but a
  key that escaped review must never ship quietly either. ``_STRICT`` is on under pytest.
- **A pseudonym and its plaintext counterpart are never both present.** A backend that received
  both would hold two spellings of one identity, which defeats the point of the default.
"""

from __future__ import annotations

import os
from typing import Any

from app.observability import surface
from app.observability.config import ObservabilityConfig
from app.observability.ids import KIND_AGENT, KIND_CHAIN, KIND_TARGET, pseudonym

# Raise rather than drop when running under pytest, so a contract violation fails a build
# instead of silently thinning the surface.
_STRICT = "PYTEST_CURRENT_TEST" in os.environ or bool(
    os.environ.get("AGENTIC_AUTH_TELEMETRY_STRICT")
)

Attributes = dict[str, Any]


def _put(attrs: Attributes, key: str, value: Any) -> None:
    """Set one attribute, refusing anything outside the contract.

    ``None`` is dropped rather than exported: an absent attribute and an attribute explicitly
    set to null read differently in every backend, and "we did not know" is better expressed by
    absence.
    """
    if value is None:
        return
    reason = surface.forbidden_reason(key)
    if reason is not None:
        if _STRICT:
            raise AssertionError(f"telemetry surface violation: {reason}")
        return
    allowed = surface.ATTR_VALUES.get(key)
    if allowed is not None and isinstance(value, str) and value not in allowed:
        if _STRICT:
            raise AssertionError(f"{key}={value!r} is not a declared value for {key}")
        return
    attrs[key] = value


def _identity(
    attrs: Attributes,
    config: ObservabilityConfig,
    *,
    agent: str | None,
    act_chain: str | None,
    taint_source: str | None,
) -> None:
    """Pseudonymous by default, plaintext only with the explicit opt-in, never both.

    The chain is pseudonymised as one value rather than per actor. A per-actor list would let an
    observer count the hops and correlate repeated actors across sessions, which is most of what
    the plaintext chain would have told them.
    """
    if config.identity_disclosure:
        _put(attrs, surface.ATTR_AGENT, agent)
        _put(attrs, surface.ATTR_ACT_CHAIN, act_chain)
        _put(attrs, surface.ATTR_TAINT_SOURCE, taint_source)
        return

    if agent is not None:
        _put(attrs, surface.ATTR_AGENT_REF, pseudonym(KIND_AGENT, agent, config.key))
    if act_chain is not None:
        _put(attrs, surface.ATTR_ACT_CHAIN_REF, pseudonym(KIND_CHAIN, act_chain, config.key))
    if taint_source is not None:
        _put(attrs, surface.ATTR_TAINT_SOURCE_REF, pseudonym(KIND_TARGET, taint_source, config.key))


def chain_digest(act_chain: list[Any] | None) -> str | None:
    """Flatten a verified act chain into one stable string for pseudonymisation.

    Order matters — ``user:alice > router > billing`` is a different delegation from
    ``user:alice > billing > router`` — so the separator is positional, not a set.
    """
    if not act_chain:
        return None
    parts: list[str] = []
    for actor in act_chain:
        if isinstance(actor, dict):
            parts.append(str(actor.get("sub") or actor.get("agent") or actor))
        else:
            parts.append(str(actor))
    return ">".join(parts)


def decision_attributes(
    config: ObservabilityConfig,
    *,
    action_id: str | None,
    session_id: str,
    hop: int,
    outcome: str,
    deny_reason: str | None,
    recoverable: bool,
    enforced: bool,
    target_kind: str,
    data_class: str,
    privileged: bool,
    taint: str | None,
    policy_version: int,
    guarantee_level: str | None = None,
    acting_agent: str | None = None,
    act_chain: list[Any] | None = None,
    taint_source: str | None = None,
) -> Attributes:
    """``authz.decide``.

    ``action_id`` is the pointer the whole feature turns on: it resolves through
    ``GET /v1/audit/actions/{action_id}/chain`` to the verified delegation chain. It is ``None``
    only when the audit write itself failed, in which case the outcome is a deny with
    ``AUDIT_UNAVAILABLE`` — a span with neither is a bug, asserted in the integration tests.
    """
    attrs: Attributes = {}
    _put(attrs, surface.ATTR_ACTION_ID, action_id)
    _put(attrs, surface.ATTR_SESSION_ID, session_id)
    _put(attrs, surface.ATTR_HOP, hop)
    _put(attrs, surface.ATTR_OUTCOME, outcome)
    _put(attrs, surface.ATTR_DENY_REASON, deny_reason)
    _put(attrs, surface.ATTR_RECOVERABLE, recoverable)
    _put(attrs, surface.ATTR_ENFORCED, enforced)
    _put(attrs, surface.ATTR_TARGET_KIND, target_kind)
    _put(attrs, surface.ATTR_DATA_CLASS, data_class)
    _put(attrs, surface.ATTR_PRIVILEGED, privileged)
    _put(attrs, surface.ATTR_TAINT, taint)
    _put(attrs, surface.ATTR_POLICY_VERSION, policy_version)
    _put(attrs, surface.ATTR_GUARANTEE_LEVEL, guarantee_level)
    _identity(
        attrs,
        config,
        agent=acting_agent,
        act_chain=chain_digest(act_chain),
        taint_source=taint_source,
    )
    return attrs


def exchange_attributes(
    config: ObservabilityConfig,
    *,
    action_id: str | None,
    session_id: str | None,
    hop: int | None,
    result: str,
    pop_failure_cause: str | None = None,
    policy_version: int | None = None,
    acting_agent: str | None = None,
) -> Attributes:
    """``authz.exchange``. Never a token, a ``jti``, or a subject token — ``_put`` refuses those
    keys by substring, so this is enforced rather than merely intended."""
    attrs: Attributes = {}
    _put(attrs, surface.ATTR_ACTION_ID, action_id)
    _put(attrs, surface.ATTR_SESSION_ID, session_id)
    _put(attrs, surface.ATTR_HOP, hop)
    _put(attrs, surface.ATTR_RESULT, result)
    _put(attrs, surface.ATTR_POP_FAILURE_CAUSE, pop_failure_cause)
    _put(attrs, surface.ATTR_POLICY_VERSION, policy_version)
    _identity(attrs, config, agent=acting_agent, act_chain=None, taint_source=None)
    return attrs


def mint_attributes(
    config: ObservabilityConfig,
    *,
    action_id: str | None,
    session_id: str | None,
    result: str,
    policy_version: int | None = None,
    acting_agent: str | None = None,
) -> Attributes:
    """``authz.transaction.mint``. Records *that* a binding was computed, never the binding, the
    ``params_hash``, or any part of the request body."""
    attrs: Attributes = {}
    _put(attrs, surface.ATTR_ACTION_ID, action_id)
    _put(attrs, surface.ATTR_SESSION_ID, session_id)
    _put(attrs, surface.ATTR_RESULT, result)
    _put(attrs, surface.ATTR_POLICY_VERSION, policy_version)
    _identity(attrs, config, agent=acting_agent, act_chain=None, taint_source=None)
    return attrs


def pep_attributes(
    config: ObservabilityConfig,
    *,
    mode: str,
    outcome: str,
    block_cause: str | None = None,
    action_id: str | None = None,
    session_id: str | None = None,
    hop: int | None = None,
    http_method: str | None = None,
    http_status: int | None = None,
    error_type: str | None = None,
) -> Attributes:
    """``pep.forward``.

    ``outcome="observed_would_block"`` is its own value, never folded into ``allowed``: the call
    was forwarded, but it was refused on the merits, and collapsing the two would make observe
    mode read as a working guardrail.
    """
    attrs: Attributes = {}
    _put(attrs, surface.ATTR_PEP_MODE, mode)
    _put(attrs, surface.ATTR_PEP_OUTCOME, outcome)
    _put(attrs, surface.ATTR_PEP_BLOCK_CAUSE, block_cause)
    _put(attrs, surface.ATTR_ACTION_ID, action_id)
    _put(attrs, surface.ATTR_SESSION_ID, session_id)
    _put(attrs, surface.ATTR_HOP, hop)
    _put(attrs, surface.ATTR_HTTP_METHOD, http_method)
    _put(attrs, surface.ATTR_HTTP_STATUS, http_status)
    _put(attrs, surface.ATTR_ERROR_TYPE, error_type)
    return attrs
