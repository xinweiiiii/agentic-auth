"""The PDP decision matrix (T035).

The decision function is pure, so this is the cross-product of the four checks with no
fixtures and no database: in/out of scope x depth within/over budget x edge declared or
not x taint present or absent.
"""

from __future__ import annotations

import pytest

from app.boundary.guarantee import Guarantee
from app.schemas.authorize import AuthorizeRequest, DenyReason, Taint, is_recoverable
from app.services.pdp import decide
from app.services.policy_loader import build_index
from app.services.tokens.act_chain import nest
from app.services.tokens.profile import VerifiedToken
from tests.fixtures.chains import (
    KB_SEARCH,
    NOTIFIER,
    ORCHESTRATOR,
    SUMMARIZER,
    compiled_dag,
    shallow_dag,
)

SESSION = "s1"
USER = "user:alice"
VERSION = 1

KB_TOOL = "mcp://kb.internal/search"
ACCOUNTS_TOOL = "mcp://accounts.internal/read_account"


def _index(dag=None):
    dag = dag if dag is not None else compiled_dag(version=VERSION)
    return build_index(dag, scope=ORCHESTRATOR, version=VERSION)


def _token(
    *,
    holder: str,
    delegators: tuple[str, ...] = (),
    session: str = SESSION,
    version: int = VERSION,
    aud: str | None = None,
) -> VerifiedToken:
    """A verified token issued to ``holder``, having passed through ``delegators``."""
    act = None
    for d in delegators:
        act = nest(act, f"agent://{d}")
    audience = aud if aud is not None else (ORCHESTRATOR if act is None else f"agent://{holder}")
    return VerifiedToken(
        raw="<verified>",
        sub=USER,
        aud=audience,
        scope="kb.public",
        session_id=session,
        policy_version=version,
        hop=len(delegators) + 1,
        jti=f"j{len(delegators)}",
        expires_at=None,  # unused by decide()
        act=act,
    )


def _req(caller: str, target: str, data_class: str, taint: Taint | None = None):
    return AuthorizeRequest(
        session_id=SESSION,
        caller=caller,
        target=target,
        data_class=data_class,
        taint=taint,
        guarantee=Guarantee.FULL,
    )


def _decide(request, token, index=None):
    return decide(index or _index(), request, token, consented_scope=ORCHESTRATOR)


# -- the happy path, one hop at a time ---------------------------------------


def test_hop_one_delegation_from_the_root_grant_is_allowed() -> None:
    d = _decide(_req(USER, f"agent://{KB_SEARCH}", "kb.internal"), _token(holder=ORCHESTRATOR))
    assert d.allowed and d.hop == 1 and d.reason is None


def test_hop_one_tool_call_by_the_root_agent_is_allowed() -> None:
    d = _decide(_req(USER, KB_TOOL, "kb.public"), _token(holder=ORCHESTRATOR))
    assert d.allowed and d.hop == 1


def test_deeper_delegations_are_allowed_along_the_declared_route() -> None:
    d2 = _decide(
        _req(f"agent://{KB_SEARCH}", f"agent://{SUMMARIZER}", "account.read"),
        _token(holder=KB_SEARCH, delegators=(ORCHESTRATOR,)),
    )
    assert d2.allowed and d2.hop == 2

    d3 = _decide(
        _req(f"agent://{SUMMARIZER}", f"agent://{NOTIFIER}", "account.write"),
        _token(holder=SUMMARIZER, delegators=(ORCHESTRATOR, KB_SEARCH)),
    )
    assert d3.allowed and d3.hop == 3


def test_tool_call_at_the_deepest_hop_is_allowed() -> None:
    d = _decide(
        _req(f"agent://{NOTIFIER}", "mcp://accounts.internal/close_account", "account.write"),
        _token(holder=NOTIFIER, delegators=(ORCHESTRATOR, KB_SEARCH, SUMMARIZER)),
    )
    assert d.allowed and d.hop == 4


# -- out of scope ------------------------------------------------------------


def test_tool_the_caller_did_not_declare_is_out_of_scope() -> None:
    """kb-search may reach the kb tool; the accounts tool belongs to summarizer.

    The v1 flattened tool list would have allowed this.
    """
    d = _decide(
        _req(f"agent://{KB_SEARCH}", ACCOUNTS_TOOL, "account.read"),
        _token(holder=KB_SEARCH, delegators=(ORCHESTRATOR,)),
    )
    assert d.reason is DenyReason.OUT_OF_SCOPE
    assert d.hop == 2
    assert "does not declare tool" in d.message


def test_tool_no_agent_declares_is_out_of_scope() -> None:
    d = _decide(
        _req(USER, "mcp://ledger.internal/read_ledger", "ledger.read"), _token(holder=ORCHESTRATOR)
    )
    assert d.reason is DenyReason.OUT_OF_SCOPE
    assert d.hop == 1


def test_agent_outside_the_pinned_policy_is_out_of_scope() -> None:
    d = _decide(
        _req("agent://ghost", KB_TOOL, "kb.public"),
        _token(holder="ghost", delegators=(ORCHESTRATOR,)),
    )
    assert d.reason is DenyReason.OUT_OF_SCOPE
    assert d.hop == 2


# -- undeclared edges --------------------------------------------------------


def test_undeclared_delegation_edge_is_denied() -> None:
    """orchestrator -> summarizer skips kb-search; transitive reachability is not an edge."""
    d = _decide(_req(USER, f"agent://{SUMMARIZER}", "account.read"), _token(holder=ORCHESTRATOR))
    assert d.reason is DenyReason.EDGE_NOT_IN_DAG
    assert d.hop == 1
    assert "not a declared edge" in d.message


def test_reverse_edge_is_denied() -> None:
    d = _decide(
        _req(f"agent://{KB_SEARCH}", f"agent://{ORCHESTRATOR}", "kb.public"),
        _token(holder=KB_SEARCH, delegators=(ORCHESTRATOR,)),
    )
    assert d.reason is DenyReason.EDGE_NOT_IN_DAG
    assert d.hop == 2


def test_edge_removed_from_the_policy_is_denied() -> None:
    """The drift case: the code did not change, the manifest did."""
    index = build_index(
        compiled_dag(include_kb_edge=False, version=VERSION), scope=ORCHESTRATOR, version=VERSION
    )
    d = _decide(
        _req(USER, f"agent://{KB_SEARCH}", "kb.internal"), _token(holder=ORCHESTRATOR), index
    )
    assert d.reason is DenyReason.EDGE_NOT_IN_DAG
    assert d.hop == 1


def test_chain_not_starting_at_the_consented_scope_is_denied() -> None:
    d = _decide(
        _req(f"agent://{SUMMARIZER}", f"agent://{NOTIFIER}", "account.write"),
        _token(holder=SUMMARIZER, delegators=(KB_SEARCH,)),
    )
    assert d.reason is DenyReason.EDGE_NOT_IN_DAG
    assert d.hop == 2
    assert "consented scope" in d.message


# -- hop budget --------------------------------------------------------------


def test_hop_beyond_the_path_budget_is_denied() -> None:
    """shallow_dag caps the notifier route at 2; this hop is the 3rd."""
    index = build_index(shallow_dag(version=VERSION), scope=ORCHESTRATOR, version=VERSION)
    d = _decide(
        _req(f"agent://{SUMMARIZER}", f"agent://{NOTIFIER}", "account.write"),
        _token(holder=SUMMARIZER, delegators=(ORCHESTRATOR, KB_SEARCH)),
        index,
    )
    assert d.reason is DenyReason.HOP_BUDGET_EXCEEDED
    assert "hop budget for this path is 2" in d.message


def test_hop_exactly_at_the_budget_is_allowed() -> None:
    """Allowed *at* the budget, refused after it."""
    index = build_index(shallow_dag(version=VERSION), scope=ORCHESTRATOR, version=VERSION)
    d = _decide(
        _req(f"agent://{KB_SEARCH}", f"agent://{SUMMARIZER}", "account.read"),
        _token(holder=KB_SEARCH, delegators=(ORCHESTRATOR,)),
        index,
    )
    assert d.allowed and d.hop == 2


# -- data class --------------------------------------------------------------


def test_data_class_the_target_never_declared_is_refused() -> None:
    """Phase 2-4 regime (`consented_data_classes=None`, the default). An undeclared class
    answers SCOPE_NOT_CONSENTED, as it always has.

    Phase 5 splits this: with a consented subset in play, the same call answers
    OUT_OF_SCOPE and is NOT recoverable, because a step-up approval may never grant
    beyond the pinned manifest. Both regimes are covered in
    tests/unit/test_pdp_consent_subset.py; this one pins the shipped contract so it
    cannot drift under an existing deployment."""
    d = _decide(_req(USER, f"agent://{KB_SEARCH}", "account.write"), _token(holder=ORCHESTRATOR))
    assert d.reason is DenyReason.SCOPE_NOT_CONSENTED
    assert d.hop == 1
    assert d.recoverable is True


def test_every_other_reason_is_not_recoverable() -> None:
    for reason in (
        DenyReason.OUT_OF_SCOPE,
        DenyReason.HOP_BUDGET_EXCEEDED,
        DenyReason.EDGE_NOT_IN_DAG,
        DenyReason.PDP_UNAVAILABLE,
        DenyReason.TOKEN_SERVICE_UNAVAILABLE,
    ):
        assert is_recoverable(reason) is False


# -- token / caller binding --------------------------------------------------


def test_caller_not_matching_the_token_holder_is_denied() -> None:
    """The impersonation case: summarizer presenting kb-search's token."""
    d = _decide(
        _req(f"agent://{SUMMARIZER}", f"agent://{SUMMARIZER}", "account.read"),
        _token(holder=KB_SEARCH, delegators=(ORCHESTRATOR,)),
    )
    assert d.reason is DenyReason.OUT_OF_SCOPE
    assert d.hop == 2
    assert "is not who this token was issued to" in d.message


def test_token_from_another_session_is_denied() -> None:
    d = _decide(
        _req(USER, f"agent://{KB_SEARCH}", "kb.internal"),
        _token(holder=ORCHESTRATOR, session="someone-elses"),
    )
    assert d.reason is DenyReason.OUT_OF_SCOPE
    assert d.hop == 1
    assert "different session" in d.message


def test_token_pinned_to_another_policy_version_is_denied() -> None:
    d = _decide(
        _req(USER, f"agent://{KB_SEARCH}", "kb.internal"),
        _token(holder=ORCHESTRATOR, version=VERSION + 1),
    )
    assert d.reason is DenyReason.OUT_OF_SCOPE
    assert d.hop == 1
    assert "policy version" in d.message


def test_token_minted_for_a_tool_call_cannot_authorize_a_further_hop() -> None:
    """Single-hop binding, enforced at the decision point as well as the audience check."""
    d = _decide(
        _req(f"agent://{KB_SEARCH}", f"agent://{SUMMARIZER}", "account.read"),
        _token(holder=KB_SEARCH, delegators=(ORCHESTRATOR,), aud=KB_TOOL),
    )
    assert d.reason is DenyReason.OUT_OF_SCOPE
    assert d.hop == 2
    assert "cannot authorize a further hop" in d.message


# -- taint is carried, never consulted ---------------------------------------


@pytest.mark.parametrize("taint", [None, Taint.TRUSTED_INTERNAL, Taint.UNTRUSTED_EXTERNAL])
def test_taint_does_not_change_an_allow(taint) -> None:
    d = _decide(
        _req(USER, f"agent://{KB_SEARCH}", "kb.internal", taint), _token(holder=ORCHESTRATOR)
    )
    assert d.allowed


@pytest.mark.parametrize("taint", [None, Taint.TRUSTED_INTERNAL, Taint.UNTRUSTED_EXTERNAL])
def test_taint_does_not_change_a_deny(taint) -> None:
    d = _decide(
        _req(USER, f"agent://{SUMMARIZER}", "account.read", taint), _token(holder=ORCHESTRATOR)
    )
    assert d.reason is DenyReason.EDGE_NOT_IN_DAG
    assert d.hop == 1


def test_untrusted_input_into_a_privileged_tool_is_allowed_in_this_phase() -> None:
    """Phase 4 turns this into TAINTED_INTO_PRIVILEGED. Pinning today's behaviour so the
    change is deliberate rather than incidental."""
    d = _decide(
        _req(
            f"agent://{NOTIFIER}",
            "mcp://accounts.internal/close_account",
            "account.write",
            Taint.UNTRUSTED_EXTERNAL,
        ),
        _token(holder=NOTIFIER, delegators=(ORCHESTRATOR, KB_SEARCH, SUMMARIZER)),
    )
    assert d.allowed


# -- a declared edge with no compiled path -----------------------------------


def test_an_edge_with_no_compiled_path_denies_as_drift_not_as_budget() -> None:
    """`budget_for_path` returns 0 for a route the compiler never produced.

    Zero must mean "no such route" (EDGE_NOT_IN_DAG), not "budget of zero"
    (HOP_BUDGET_EXCEEDED) — the two send an operator to different places.
    """
    dag = compiled_dag(version=VERSION)
    # Keep the edge, drop the path that justifies it.
    dag["paths"] = [
        p for p in dag["paths"] if p["path"] != ["agent://orchestrator", "agent://kb-search"]
    ]
    index = build_index(dag, scope=ORCHESTRATOR, version=VERSION)

    d = _decide(
        _req(USER, f"agent://{KB_SEARCH}", "kb.internal"), _token(holder=ORCHESTRATOR), index
    )
    assert d.reason is DenyReason.EDGE_NOT_IN_DAG
    assert d.hop == 1
    assert "no compiled path" in d.message


def test_an_allow_reports_the_hop_it_was_decided_for() -> None:
    for delegators, expected in (((), 1), ((ORCHESTRATOR,), 2)):
        holder = ORCHESTRATOR if not delegators else KB_SEARCH
        target = f"agent://{KB_SEARCH}" if not delegators else f"agent://{SUMMARIZER}"
        dc = "kb.internal" if not delegators else "account.read"
        d = _decide(
            _req(USER if not delegators else f"agent://{KB_SEARCH}", target, dc),
            _token(holder=holder, delegators=delegators),
        )
        assert d.allowed and d.hop == expected


# -- the outcome string is part of the contract ------------------------------


def test_outcome_is_exactly_allow_or_deny() -> None:
    """The value is persisted and checked by a database constraint, so 'DENY' or any
    other near-miss is a bug, not a synonym."""
    allowed = _decide(
        _req(USER, f"agent://{KB_SEARCH}", "kb.internal"), _token(holder=ORCHESTRATOR)
    )
    denied = _decide(
        _req(USER, f"agent://{SUMMARIZER}", "account.read"), _token(holder=ORCHESTRATOR)
    )
    assert allowed.outcome == "allow"
    assert denied.outcome == "deny"
    assert allowed.allowed is True and denied.allowed is False


def test_hop_budget_denial_reports_the_hop_it_stopped_at() -> None:
    index = build_index(shallow_dag(version=VERSION), scope=ORCHESTRATOR, version=VERSION)
    d = _decide(
        _req(f"agent://{SUMMARIZER}", f"agent://{NOTIFIER}", "account.write"),
        _token(holder=SUMMARIZER, delegators=(ORCHESTRATOR, KB_SEARCH)),
        index,
    )
    assert d.outcome == "deny"
    assert d.hop == 3  # the depth that crossed the line, not the budget


def test_a_path_budget_of_one_still_allows_its_first_hop() -> None:
    """Budget 1 is a real budget. Only 0 means 'no such compiled route'."""
    dag = compiled_dag(version=VERSION)
    for path in dag["paths"]:
        if path["path"] == ["agent://orchestrator", "agent://kb-search"]:
            path["effective_hop_budget"] = 1
    index = build_index(dag, scope=ORCHESTRATOR, version=VERSION)

    d = _decide(
        _req(USER, f"agent://{KB_SEARCH}", "kb.internal"), _token(holder=ORCHESTRATOR), index
    )
    assert d.allowed and d.hop == 1


def test_a_path_budget_of_one_refuses_the_second_hop_as_budget_not_drift() -> None:
    dag = compiled_dag(version=VERSION)
    for path in dag["paths"]:
        if path["path"] == ["agent://orchestrator", "agent://kb-search", "agent://summarizer"]:
            path["effective_hop_budget"] = 1
    index = build_index(dag, scope=ORCHESTRATOR, version=VERSION)

    d = _decide(
        _req(f"agent://{KB_SEARCH}", f"agent://{SUMMARIZER}", "account.read"),
        _token(holder=KB_SEARCH, delegators=(ORCHESTRATOR,)),
        index,
    )
    assert d.reason is DenyReason.HOP_BUDGET_EXCEEDED
    assert d.hop == 2


def test_out_of_scope_tool_denial_reports_its_hop() -> None:
    d = _decide(
        _req(f"agent://{KB_SEARCH}", ACCOUNTS_TOOL, "account.read"),
        _token(holder=KB_SEARCH, delegators=(ORCHESTRATOR,)),
    )
    assert d.outcome == "deny"
    assert d.hop == 2


def test_a_delegation_chain_link_that_is_not_an_agent_is_denied() -> None:
    """Defence in depth: our issuer only ever nests `agent://` links, and a forged token
    fails verification first. The pure decision function is still tested directly for it,
    because 'unreachable today' is a property of the caller, not of this function.
    """
    token = VerifiedToken(
        raw="<verified>",
        sub=USER,
        aud=f"agent://{KB_SEARCH}",
        scope="kb.internal",
        session_id=SESSION,
        policy_version=VERSION,
        hop=2,
        jti="j1",
        expires_at=None,
        act={"sub": "user:mallory"},  # not an agent reference
    )
    d = _decide(_req(f"agent://{KB_SEARCH}", f"agent://{SUMMARIZER}", "account.read"), token)

    assert d.reason is DenyReason.EDGE_NOT_IN_DAG
    assert d.hop == 2
    assert "non-agent link" in d.message


# -- Phase 4: privileged and transaction_required -------------------------------------


def test_a_privileged_tool_call_is_flagged_and_requires_a_transaction() -> None:
    """notifier declares close_account privileged; the allow says so, and says to bind."""
    idx = _index()
    request = AuthorizeRequest(
        session_id=SESSION,
        caller=f"agent://{NOTIFIER}",
        target="mcp://accounts.internal/close_account",
        data_class="account.write",
        guarantee=Guarantee.FULL,
    )
    token = _token(holder=NOTIFIER, delegators=(ORCHESTRATOR, KB_SEARCH, SUMMARIZER))
    d = decide(idx, request, token, consented_scope=ORCHESTRATOR)
    assert d.allowed and d.privileged and d.transaction_required


def test_the_flag_off_keeps_privileged_but_drops_transaction_required() -> None:
    idx = _index()
    request = AuthorizeRequest(
        session_id=SESSION,
        caller=f"agent://{NOTIFIER}",
        target="mcp://accounts.internal/close_account",
        data_class="account.write",
        guarantee=Guarantee.FULL,
    )
    token = _token(holder=NOTIFIER, delegators=(ORCHESTRATOR, KB_SEARCH, SUMMARIZER))
    d = decide(idx, request, token, consented_scope=ORCHESTRATOR, transaction_tokens_enabled=False)
    assert d.allowed and d.privileged and not d.transaction_required


def test_an_ordinary_tool_and_a_delegation_are_not_privileged() -> None:
    idx = _index()
    # Under the root grant the presenter is the consenting human.
    tool = decide(
        idx,
        AuthorizeRequest(
            session_id=SESSION,
            caller=USER,
            target=KB_TOOL,
            data_class="kb.public",
            guarantee=Guarantee.FULL,
        ),
        _token(holder=ORCHESTRATOR),
        consented_scope=ORCHESTRATOR,
    )
    delegation = decide(
        idx,
        AuthorizeRequest(
            session_id=SESSION,
            caller=USER,
            target=f"agent://{KB_SEARCH}",
            data_class="kb.internal",
            guarantee=Guarantee.FULL,
        ),
        _token(holder=ORCHESTRATOR),
        consented_scope=ORCHESTRATOR,
    )
    assert tool.allowed and not tool.privileged and not tool.transaction_required
    assert delegation.allowed and not delegation.privileged and not delegation.transaction_required
