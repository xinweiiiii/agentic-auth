"""AGENT_REVOKED in the pure decision."""

from __future__ import annotations

from app.boundary.guarantee import Guarantee
from app.schemas.authorize import AuthorizeRequest, DenyReason
from app.services.pdp import decide  # noqa: E402  (after the fixture import for clarity)
from tests.fixtures.chains import KB_SEARCH, ORCHESTRATOR, SUMMARIZER
from tests.unit.test_pdp_matrix import SESSION, USER, _index, _token


def _request(caller: str, target: str, data_class: str) -> AuthorizeRequest:
    return AuthorizeRequest(
        session_id=SESSION,
        caller=caller,
        target=target,
        data_class=data_class,
        guarantee=Guarantee.FULL,
    )


def test_a_revoked_holder_is_refused() -> None:
    d = decide(
        _index(),
        _request(f"agent://{KB_SEARCH}", f"agent://{SUMMARIZER}", "account.read"),
        _token(holder=KB_SEARCH, delegators=(ORCHESTRATOR,)),
        consented_scope=ORCHESTRATOR,
        revoked=frozenset({KB_SEARCH}),
    )
    assert d.outcome == "deny" and d.reason is DenyReason.AGENT_REVOKED
    assert d.recoverable is False
    assert KB_SEARCH in (d.message or "")


def test_a_revoked_agent_anywhere_on_the_chain_is_refused() -> None:
    """orchestrator delegated to kb-search; orchestrator is revoked afterwards. kb-search's
    authority was built on it and does not survive."""
    d = decide(
        _index(),
        _request(f"agent://{KB_SEARCH}", f"agent://{SUMMARIZER}", "account.read"),
        _token(holder=KB_SEARCH, delegators=(ORCHESTRATOR,)),
        consented_scope=ORCHESTRATOR,
        revoked=frozenset({ORCHESTRATOR}),
    )
    assert d.reason is DenyReason.AGENT_REVOKED


def test_an_unrelated_revocation_changes_nothing() -> None:
    d = decide(
        _index(),
        _request(f"agent://{KB_SEARCH}", f"agent://{SUMMARIZER}", "account.read"),
        _token(holder=KB_SEARCH, delegators=(ORCHESTRATOR,)),
        consented_scope=ORCHESTRATOR,
        revoked=frozenset({"someone-else", "another-stranger"}),
    )
    assert d.allowed


def test_revocation_is_checked_before_taint_and_budget() -> None:
    from app.schemas.authorize import Taint

    d = decide(
        _index(),
        _request(USER, f"agent://{KB_SEARCH}", "kb.internal"),
        _token(holder=ORCHESTRATOR),
        consented_scope=ORCHESTRATOR,
        revoked=frozenset({ORCHESTRATOR}),
        taint=Taint.UNTRUSTED_EXTERNAL,
    )
    assert d.reason is DenyReason.AGENT_REVOKED


def test_the_default_is_no_revocations() -> None:
    d = decide(
        _index(),
        _request(USER, f"agent://{KB_SEARCH}", "kb.internal"),
        _token(holder=ORCHESTRATOR),
        consented_scope=ORCHESTRATOR,
    )
    assert d.allowed


def test_delegating_to_a_revoked_agent_is_refused() -> None:
    """Extending authority TO a revoked agent is refused, not only acting as one."""
    d = decide(
        _index(),
        _request(USER, f"agent://{KB_SEARCH}", "kb.internal"),
        _token(holder=ORCHESTRATOR),
        consented_scope=ORCHESTRATOR,
        revoked=frozenset({KB_SEARCH}),
    )
    assert d.reason is DenyReason.AGENT_REVOKED and KB_SEARCH in (d.message or "")


def test_a_revoked_tool_name_is_not_a_delegate() -> None:
    """Only agent:// targets are delegations; a tool ref never matches the revoked set."""
    d = decide(
        _index(),
        _request(USER, "mcp://kb.internal/search", "kb.public"),
        _token(holder=ORCHESTRATOR),
        consented_scope=ORCHESTRATOR,
        revoked=frozenset({"search"}),
    )
    assert d.allowed


def test_a_revoked_refusal_carries_the_hop_and_the_taint_it_was_decided_under() -> None:
    from app.schemas.authorize import Taint

    d = decide(
        _index(),
        _request(f"agent://{KB_SEARCH}", f"agent://{SUMMARIZER}", "account.read"),
        _token(holder=KB_SEARCH, delegators=(ORCHESTRATOR,)),
        consented_scope=ORCHESTRATOR,
        revoked=frozenset({KB_SEARCH}),
        taint=Taint.UNTRUSTED_EXTERNAL,
    )
    assert d.reason is DenyReason.AGENT_REVOKED
    assert d.hop == 2 and d.taint is Taint.UNTRUSTED_EXTERNAL
    assert d.privileged is False  # an ordinary deny never claims to be about a privileged tool
