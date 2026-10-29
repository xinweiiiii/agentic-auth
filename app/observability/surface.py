"""The telemetry surface: every name this layer is permitted to emit.

One module, consumed by the attribute builders *and* by the tests, so the contract and the code
cannot drift apart. The same pattern as ``app/services/edge_rules.py``, which Phase 3 made the
single shared rule module with ``test_edge_rules_parity.py`` holding runtime and CI to it.

https://authzai.dev/reference/telemetry-surface is the human-readable half, and
``tests/unit/test_telemetry_surface.py`` fails if the two enumerate different sets.

Two rules this module enforces mechanically:

- **Nothing outside these sets is ever emitted.** A builder that tries is a bug in tests and
  drops the key in production — telemetry must never be the reason a request fails.
- **No key collides with a reserved OpenTelemetry name** except where we deliberately reuse a
  standard one with its standard meaning (``error.type`` and the HTTP conventions).

Pure data and pure functions only. No imports beyond the standard library, so the tests run
without the ``otel`` extra installed.
"""

from __future__ import annotations

from types import MappingProxyType

# ----------------------------------------------------------------------------- span names

SPAN_DECIDE = "authz.decide"
SPAN_EXCHANGE = "authz.exchange"
SPAN_MINT = "authz.transaction.mint"
SPAN_PEP_FORWARD = "pep.forward"
SPAN_PEP_DECIDE = "pep.decide"
SPAN_PEP_EXCHANGE = "pep.exchange"
SPAN_PEP_MINT = "pep.mint"
SPAN_PEP_UPSTREAM = "pep.upstream"

SPAN_NAMES = frozenset(
    {
        SPAN_DECIDE,
        SPAN_EXCHANGE,
        SPAN_MINT,
        SPAN_PEP_FORWARD,
        SPAN_PEP_DECIDE,
        SPAN_PEP_EXCHANGE,
        SPAN_PEP_MINT,
        SPAN_PEP_UPSTREAM,
    }
)

# Spans emitted on the dispatch path. These never record an exception: the SDK would attach
# `exception.message` and a full `exception.stacktrace`, and a traceback through token
# verification can carry a token fragment.
DISPATCH_PATH_SPANS = SPAN_NAMES

# ------------------------------------------------------------------------ attribute keys

# Correlation. Opaque UUIDs that carry no identity on their own and are useless without the
# audit-reader check — they are the pointer from a trace back to the audit record, so they are NOT
# pseudonymised.
ATTR_ACTION_ID = "authz.action_id"
ATTR_SESSION_ID = "authz.session_id"
ATTR_HOP = "authz.hop"

# The decision.
ATTR_OUTCOME = "authz.outcome"
ATTR_DENY_REASON = "authz.deny_reason"
ATTR_RECOVERABLE = "authz.recoverable"
ATTR_ENFORCED = "authz.enforced"
ATTR_TARGET_KIND = "authz.target_kind"
ATTR_DATA_CLASS = "authz.data_class"
ATTR_PRIVILEGED = "authz.privileged"
ATTR_TAINT = "authz.taint"
ATTR_POLICY_VERSION = "authz.policy_version"
# Phase 5. How strong the enforcement actually was for this hop, as the enforcement point
# reported it. "How much traffic ran below full guarantee" is an operator question, so it
# belongs on the span as well as in the audit row.
ATTR_GUARANTEE_LEVEL = "authz.guarantee_level"

# Exchange / mint.
ATTR_RESULT = "authz.result"
ATTR_POP_FAILURE_CAUSE = "authz.pop_failure_cause"

# Enforcement point.
ATTR_PEP_MODE = "authz.pep.mode"
ATTR_PEP_OUTCOME = "authz.pep.outcome"
ATTR_PEP_BLOCK_CAUSE = "authz.pep.block_cause"

# Identity. Pseudonymous by default; the plaintext forms appear only with the disclosure opt-in,
# and never alongside their `_ref` counterpart.
ATTR_AGENT_REF = "authz.agent_ref"
ATTR_ACT_CHAIN_REF = "authz.act_chain_ref"
ATTR_TAINT_SOURCE_REF = "authz.taint_source_ref"
ATTR_AGENT = "authz.agent"
ATTR_ACT_CHAIN = "authz.act_chain"
ATTR_TAINT_SOURCE = "authz.taint_source"

PSEUDONYMOUS_ATTRS = frozenset({ATTR_AGENT_REF, ATTR_ACT_CHAIN_REF, ATTR_TAINT_SOURCE_REF})
DISCLOSED_ATTRS = frozenset({ATTR_AGENT, ATTR_ACT_CHAIN, ATTR_TAINT_SOURCE})

# Standard conventions, reused with their standard meaning.
ATTR_ERROR_TYPE = "error.type"
ATTR_HTTP_METHOD = "http.request.method"
ATTR_HTTP_STATUS = "http.response.status_code"

SEMCONV_ATTRS = frozenset({ATTR_ERROR_TYPE, ATTR_HTTP_METHOD, ATTR_HTTP_STATUS})

ATTR_KEYS = (
    frozenset(
        {
            ATTR_ACTION_ID,
            ATTR_SESSION_ID,
            ATTR_HOP,
            ATTR_OUTCOME,
            ATTR_DENY_REASON,
            ATTR_RECOVERABLE,
            ATTR_ENFORCED,
            ATTR_TARGET_KIND,
            ATTR_DATA_CLASS,
            ATTR_PRIVILEGED,
            ATTR_TAINT,
            ATTR_POLICY_VERSION,
            ATTR_GUARANTEE_LEVEL,
            ATTR_RESULT,
            ATTR_POP_FAILURE_CAUSE,
            ATTR_PEP_MODE,
            ATTR_PEP_OUTCOME,
            ATTR_PEP_BLOCK_CAUSE,
        }
    )
    | PSEUDONYMOUS_ATTRS
    | DISCLOSED_ATTRS
    | SEMCONV_ATTRS
)

# Never an attribute, on any span, at any disclosure setting. Checked by name so a future
# refactor that starts passing one of these through fails loudly.
FORBIDDEN_ATTR_SUBSTRINGS = (
    "token",
    "jti",
    "secret",
    "credential",
    "password",
    "authorization",
    "body",
    "params_hash",
    "binding",
    "query",
    "stacktrace",
)

# ------------------------------------------------------------------- structured log fields

LOG_COMPONENT = "authz.component"
LOG_FIELDS = frozenset({LOG_COMPONENT, ATTR_SESSION_ID, ATTR_ACTION_ID, ATTR_HOP, ATTR_ERROR_TYPE})

COMPONENT_CONTROL_PLANE = "control_plane"
COMPONENT_PEP = "pep"
COMPONENT_VERIFIER = "verifier"
COMPONENT_CLI = "cli"
COMPONENTS = frozenset({COMPONENT_CONTROL_PLANE, COMPONENT_PEP, COMPONENT_VERIFIER, COMPONENT_CLI})

# ----------------------------------------------------------------------------- metrics

# New families only. The Phase 3/4 families are owned by app/services/metrics.py and asserted
# unchanged by tests/unit/test_metric_compatibility.py — this layer must not restate them, or
# there would be two places to update and one would rot.
METRIC_PEP_CALLS = "agentic_auth_pep_calls"
METRIC_PEP_BLOCKS = "agentic_auth_pep_blocks"
METRIC_PEP_STAGE_DURATION = "agentic_auth_pep_stage_duration_seconds"
METRIC_PEP_OVERHEAD = "agentic_auth_pep_overhead_seconds"
METRIC_PEP_UP = "agentic_auth_pep_up"
METRIC_PEP_INFO = "agentic_auth_pep_info"
METRIC_TRACE_CONTEXT_REJECTED = "agentic_auth_trace_context_rejected"
METRIC_TELEMETRY_DROPPED = "agentic_auth_telemetry_dropped"
METRIC_IDENTITY_DISCLOSURE = "agentic_auth_telemetry_identity_disclosure"

NEW_METRIC_NAMES = frozenset(
    {
        METRIC_PEP_CALLS,
        METRIC_PEP_BLOCKS,
        METRIC_PEP_STAGE_DURATION,
        METRIC_PEP_OVERHEAD,
        METRIC_PEP_UP,
        METRIC_PEP_INFO,
        METRIC_TRACE_CONTEXT_REJECTED,
        METRIC_TELEMETRY_DROPPED,
        METRIC_IDENTITY_DISCLOSURE,
    }
)

# ------------------------------------------------------------------ closed value sets
#
# Every label value and every enum attribute value, enumerated. This is what bounds metric
# cardinality regardless of how many agents, sessions or targets exist, and
# what lets test_dashboard_artifacts.py catch a typo'd matcher like {cause="pdp_unavailable"}
# against the real value `pdp_unreachable`.

PEP_OUTCOMES = frozenset({"allowed", "blocked", "observed_would_block"})
# Derived by enumerating every return path in app/sidecar/enforce.py, not from a guess. The
# planning draft listed six; four more are needed to cover the code as written:
#   audit_unavailable  the contract names "audit record not committed" explicitly, and enforce()
#                      refuses on it (DenyReason.AUDIT_UNAVAILABLE)
#   unauthorized       a missing/malformed/refused bearer: the caller's fault, so neither a
#                      policy verdict nor a guardrail outage
#   unbindable         a privileged call whose body is not a JSON object
#   other              a cause we failed to classify; present so an unmapped path shows up as
#                      an odd label value rather than as a call that never happened
PEP_BLOCK_CAUSES = frozenset(
    {
        "policy",
        "pdp_unreachable",
        "exchange_unreachable",
        "mint_unreachable",
        "audit_unavailable",
        "body_too_large",
        "unbindable",
        "unauthorized",
        "unresolvable_call",
        "other",
    }
)
# Refusals caused by the guardrail's own unavailability rather than by policy. The distinction
# the cause label exists for: the difference between a guardrail that works and one that is broken.
# Refusals caused by the guardrail's own unavailability rather than by policy: the
# distinction, and the only causes that page. `unauthorized`, `unbindable`, `body_too_large`
# and `unresolvable_call` are deliberately absent — they are the caller's or the operator's
# mistake, and alerting on them would cry wolf.
PEP_INFRA_BLOCK_CAUSES = frozenset(
    {"pdp_unreachable", "exchange_unreachable", "mint_unreachable", "audit_unavailable"}
)
PEP_MODE_ENFORCING = "enforcing"
PEP_MODE_OBSERVING = "observing"
PEP_MODES = frozenset({PEP_MODE_ENFORCING, PEP_MODE_OBSERVING})
PEP_STAGES = frozenset({"decide", "exchange", "mint", "upstream"})
TRACE_CONTEXT_REJECT_CAUSES = frozenset({"malformed", "absent", "baggage_dropped"})
TELEMETRY_SIGNALS = frozenset({"span", "log"})
OUTCOMES = frozenset({"allow", "deny"})
TARGET_KINDS = frozenset({"tool", "agent"})
TAINTS = frozenset({"trusted_internal", "untrusted_external"})
# app.boundary.guarantee.Guarantee, mirrored here so this module keeps importing nothing.
GUARANTEE_LEVELS = frozenset({"full", "connector", "network", "consent_only"})

LABEL_VALUES: MappingProxyType[str, frozenset[str]] = MappingProxyType(
    {
        f"{METRIC_PEP_CALLS}:outcome": PEP_OUTCOMES,
        f"{METRIC_PEP_BLOCKS}:cause": PEP_BLOCK_CAUSES,
        f"{METRIC_PEP_STAGE_DURATION}:stage": PEP_STAGES,
        f"{METRIC_PEP_INFO}:mode": PEP_MODES,
        f"{METRIC_TRACE_CONTEXT_REJECTED}:cause": TRACE_CONTEXT_REJECT_CAUSES,
        f"{METRIC_TELEMETRY_DROPPED}:signal": TELEMETRY_SIGNALS,
    }
)

ATTR_VALUES: MappingProxyType[str, frozenset[str]] = MappingProxyType(
    {
        ATTR_OUTCOME: OUTCOMES,
        ATTR_TARGET_KIND: TARGET_KINDS,
        ATTR_TAINT: TAINTS,
        ATTR_GUARANTEE_LEVEL: GUARANTEE_LEVELS,
        ATTR_PEP_MODE: PEP_MODES,
        ATTR_PEP_OUTCOME: PEP_OUTCOMES,
        ATTR_PEP_BLOCK_CAUSE: PEP_BLOCK_CAUSES,
    }
)

# --------------------------------------------------------------------------- validation


def is_permitted_attr(key: str) -> bool:
    return key in ATTR_KEYS


def forbidden_reason(key: str) -> str | None:
    """Why ``key`` must never be emitted, or ``None`` if it is fine.

    Checked by substring rather than by exact name so that a plausible future addition —
    ``authz.subject_jti``, ``authz.request_body`` — is caught before it ships rather than after
    it has been exported to somebody's backend.
    """
    if key in ATTR_KEYS:
        return None
    lowered = key.lower()
    for needle in FORBIDDEN_ATTR_SUBSTRINGS:
        if needle in lowered:
            return f"{key!r} looks like a secret ({needle!r}) and is never emitted"
    return f"{key!r} is not in the telemetry surface contract"
