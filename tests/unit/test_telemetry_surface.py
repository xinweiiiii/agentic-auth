"""The telemetry surface is a contract, not guidance.

Phases 3 and 4 shipped dashboard guidance as prose tables. Prose cannot fail a build. This file
holds ``app/observability/surface.py`` and the published telemetry surface
(https://authzai.dev/reference/telemetry-surface) to the same sets, the way
``test_edge_rules_parity.py`` holds runtime and CI to one edge rule.
"""

from __future__ import annotations

import re

import pytest

from app.observability import surface
from tests.fixtures.contracts import contract_path

CONTRACT = contract_path("telemetry-surface.md")

# Reserved by the OpenTelemetry specification. We may only use one of these if we mean exactly
# what the convention means.
RESERVED_NAMES = frozenset(
    {
        "error.type",
        "exception.message",
        "exception.stacktrace",
        "exception.type",
        "server.address",
        "server.port",
        "service.name",
        "telemetry.sdk.language",
        "telemetry.sdk.name",
        "telemetry.sdk.version",
        "url.scheme",
    }
)


@pytest.fixture(scope="module")
def contract_text() -> str:
    assert CONTRACT.exists(), f"the surface contract is missing at {CONTRACT}"
    return CONTRACT.read_text()


# -- parity: the code and the document enumerate the same things ---------------------------


def test_every_permitted_attribute_is_documented(contract_text: str) -> None:
    """Matched as a whole backticked token, not as a substring: a plain `in` check would let
    `authz.agent` pass merely because `authz.agent_ref` happens to be documented."""
    documented = set(re.findall(r"`([a-z_][a-z0-9_.]*)`", contract_text))
    missing = sorted(k for k in surface.ATTR_KEYS if k not in documented)
    assert not missing, f"attributes in surface.py but absent from the contract: {missing}"


def test_every_span_name_is_documented(contract_text: str) -> None:
    documented = set(re.findall(r"`([a-z_][a-z0-9_.]*)`", contract_text))
    missing = sorted(n for n in surface.SPAN_NAMES if n not in documented)
    assert not missing, f"span names in surface.py but absent from the contract: {missing}"


def test_every_new_metric_is_documented(contract_text: str) -> None:
    missing = sorted(m for m in surface.NEW_METRIC_NAMES if m not in contract_text)
    assert not missing, f"metrics in surface.py but absent from the contract: {missing}"


def test_every_documented_authz_attribute_is_permitted(contract_text: str) -> None:
    """The other direction: the contract must not promise a key the code cannot emit, or a
    reader would build a dashboard on an attribute that never appears."""
    documented = set(re.findall(r"`(authz\.[a-z_.]+)`", contract_text))
    # The contract also names forbidden keys, in the "never an attribute" prose. Those are
    # listed to be excluded, so they are expected to be absent from the allowlist.
    forbidden = {k for k in documented if surface.forbidden_reason(k) is not None}
    unexpected = sorted(k for k in forbidden if "never" not in contract_text.lower())
    assert not unexpected, f"contract documents keys the code cannot emit: {unexpected}"


def test_every_documented_label_value_set_is_enumerated(contract_text: str) -> None:
    for key, values in surface.LABEL_VALUES.items():
        for value in values:
            assert value in contract_text, f"label value {value!r} for {key} is undocumented"


# -- naming rules --------------------------------------------------------------------------


def test_no_attribute_collides_with_a_reserved_name_unintentionally() -> None:
    collisions = (surface.ATTR_KEYS & RESERVED_NAMES) - surface.SEMCONV_ATTRS
    assert not collisions, f"reserved OTel names used without meaning the convention: {collisions}"


def test_reused_semconv_attributes_are_declared_as_such() -> None:
    """`error.type` is reserved and we use it deliberately — it must be in SEMCONV_ATTRS so the
    exemption above is explicit rather than accidental."""
    assert surface.ATTR_ERROR_TYPE in surface.SEMCONV_ATTRS
    assert surface.ATTR_ERROR_TYPE in RESERVED_NAMES


def test_every_attribute_is_authz_prefixed_or_a_declared_convention() -> None:
    """Domain-first, never company-first: `authz.*`, not `agentic_auth.*`."""
    for key in surface.ATTR_KEYS:
        assert key.startswith("authz.") or key in surface.SEMCONV_ATTRS, key
        assert not key.startswith("agentic_auth."), f"{key} is company-first, not domain-first"


def test_metric_names_keep_the_published_prefix() -> None:
    """Metrics keep `agentic_auth_*` because they are already published. The asymmetry with
    `authz.*` attributes is deliberate."""
    for name in surface.NEW_METRIC_NAMES:
        assert name.startswith("agentic_auth_"), name


# -- the secret guard ----------------------------------------------------------------------


@pytest.mark.parametrize(
    "key",
    [
        "authz.subject_jti",
        "authz.token",
        "authz.request_body",
        "authz.params_hash",
        "authz.binding",
        "http.request.header.authorization",
        "exception.stacktrace",
        "authz.query_string",
    ],
)
def test_secret_shaped_keys_are_refused(key: str) -> None:
    """These are the plausible future additions, not hypotheticals: each one is a field
    that exists elsewhere in the codebase and would be natural to pass through."""
    assert surface.forbidden_reason(key) is not None


def test_no_permitted_attribute_is_itself_secret_shaped() -> None:
    for key in surface.ATTR_KEYS:
        assert surface.forbidden_reason(key) is None, key


def test_unknown_keys_are_refused_even_when_innocuous() -> None:
    """The allowlist is closed: a key is permitted because it is listed, never because it looks
    harmless."""
    assert surface.forbidden_reason("authz.something_new") is not None


# -- closed value sets bound cardinality ------------------------------------------


def test_label_value_sets_are_small_and_closed() -> None:
    for key, values in surface.LABEL_VALUES.items():
        assert 1 < len(values) <= 12, (
            f"{key} has {len(values)} values; cardinality must stay bounded"
        )


def test_no_label_value_looks_like_an_identity() -> None:
    """No agent name, session id, action id or target may ever appear as a label value — the
    Phase 3 rule, restated mechanically."""
    for key, values in surface.LABEL_VALUES.items():
        for value in values:
            assert "://" not in value, f"{key} value {value!r} looks like an agent/tool URI"
            assert not re.fullmatch(r"[0-9a-f-]{32,}", value), (
                f"{key} value {value!r} looks like an id"
            )


def test_infra_block_causes_are_a_subset_of_block_causes() -> None:
    """The policy/infrastructure split: 'the guardrail could not reach policy' must be
    expressible as a strict subset of the block causes, never overlapping 'policy' itself."""
    assert surface.PEP_INFRA_BLOCK_CAUSES < surface.PEP_BLOCK_CAUSES
    assert "policy" not in surface.PEP_INFRA_BLOCK_CAUSES


# -- disclosure: never both spellings of one identity --------------------------------------


def test_pseudonymous_and_disclosed_attrs_are_disjoint() -> None:
    assert not (surface.PSEUDONYMOUS_ATTRS & surface.DISCLOSED_ATTRS)


def test_each_disclosed_attr_has_a_pseudonymous_counterpart() -> None:
    for disclosed in surface.DISCLOSED_ATTRS:
        assert f"{disclosed}_ref" in surface.PSEUDONYMOUS_ATTRS, disclosed


# -- the gap that let real drift through ----------------------------------------------------
#
# The parity tests above check code -> contract. They cannot catch the opposite failure, which
# actually happened during implementation: `surface.PEP_BLOCK_CAUSES` was left at six values
# while `pep.classify()` had grown to return ten, so four real block causes would have been
# refused by the attribute builder at runtime. These tests close that direction by asserting the
# allowlist covers everything the code can actually produce.


def test_every_cause_classify_can_return_is_allowlisted() -> None:
    from app.observability.pep import _INFRA_CAUSES, _LOCAL_CAUSES, classify

    produced = set(_LOCAL_CAUSES.values()) | set(_INFRA_CAUSES.values()) | {"policy", "other"}
    assert produced <= surface.PEP_BLOCK_CAUSES, (
        f"pep.classify() can return causes the allowlist refuses: "
        f"{sorted(produced - surface.PEP_BLOCK_CAUSES)}"
    )
    # And exercise the mapping end to end, so a new return path in enforce() that produces an
    # unmapped reason still lands on a declared value.
    for edge_outcome in ("allow", "deny", "observed", "blocked_infra", "blocked_local", "???"):
        for reason in (None, "EDGE_NOT_IN_DAG", "PDP_UNAVAILABLE", "UNAUTHORIZED", "???"):
            c = classify(edge_outcome, reason)
            assert c.outcome in surface.PEP_OUTCOMES, (edge_outcome, reason, c)
            if c.block_cause is not None:
                assert c.block_cause in surface.PEP_BLOCK_CAUSES, (edge_outcome, reason, c)


def test_every_infrastructure_deny_reason_maps_to_an_infra_cause() -> None:
    """Every reason the codebase classifies as an outage must produce a cause that pages. A new
    INFRASTRUCTURE_REASONS member that nobody mapped would otherwise be counted as `other` and
    quietly not alert."""
    from app.observability.pep import classify
    from app.schemas.authorize import INFRASTRUCTURE_REASONS

    for reason in INFRASTRUCTURE_REASONS:
        c = classify("blocked_infra", reason.value)
        assert c.is_infra_failure, f"{reason.value} does not map to an infra cause: {c}"


def test_no_policy_deny_reason_is_mistaken_for_an_outage() -> None:
    """The converse, and the more dangerous direction: a policy refusal counted as an outage
    would page an on-call engineer for a guardrail that is working correctly."""
    from app.observability.pep import classify
    from app.schemas.authorize import POLICY_REASONS

    for reason in POLICY_REASONS:
        for edge_outcome in ("deny", "observed"):
            c = classify(edge_outcome, reason.value)
            assert not c.is_infra_failure, f"{reason.value} would page as an outage: {c}"
            assert c.block_cause == "policy"


def test_observed_is_never_counted_as_allowed_or_blocked() -> None:
    from app.observability.pep import classify

    c = classify("observed", "OUT_OF_SCOPE")
    assert c.outcome == "observed_would_block"
    assert c.outcome not in {"allowed", "blocked"}
