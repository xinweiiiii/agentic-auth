"""The policy decision function.

Pure by construction: policy index + request + verified token in, decision out. No I/O,
no clock, no cache, no database. That is what makes the decision matrix testable without
fixtures, and it keeps the 15 ms per-hop budget achievable — loading the policy, reading
the session and recording the outcome all happen around this function, never inside it.

Three rules hold everywhere below.

**Deny is the default.** Every path that cannot establish an allow returns a deny. There
is no branch that resolves an unclear request to an allow.

**Depth comes from the token.** ``hop`` is read off the verified ``act`` chain, never from
anything the caller sent.

**``act`` says who delegated; ``aud`` says who holds.** The outermost ``act`` link is the
*previous* actor, not the current one. The agent entitled to present a token is the one it
was issued to. Reading the caller off ``act`` would let a delegator's identity stand in for
its delegate's, which is a privilege escalation, not a naming quibble.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.schemas.authorize import AuthorizeRequest, DenyReason, Taint, is_recoverable
from app.services.edge_rules import EdgeVerdict, classify_edge
from app.services.policy_loader import PolicyIndex
from app.services.tokens.profile import VerifiedToken

AGENT_PREFIX = "agent://"

# `mutmut run` leaves 14 equivalent mutants here, in three groups.
#
# Six rewrite the human-readable `message` argument of a `_deny(...)` (blanking it, shifting an
# index inside an f-string, changing a join separator). `message` is explicitly not the machine
# contract — callers branch on `reason` and `recoverable`, both of which every deny path asserts
# in tests/unit/test_pdp_matrix.py.
#
# Six more sit inside the `EdgeVerdict.UNKNOWN_AGENT` branch below, which is unreachable: the
# loop over `path_so_far` has already denied any agent outside `policy.agents`, so
# `classify_edge` cannot return that verdict here. The branch is kept anyway — an unhandled
# verdict must resolve to a deny — and being unreachable, mutating its arguments changes
# nothing observable.
#
# Two flip the DEFAULT of `_allow`'s keywords (`privileged`, `transaction_required`). The only
# call site passes both explicitly, so the defaults are never read.
#
# Every mutant that changes an outcome, a reason, a hop, a taint, a privileged flag or a
# comparison is killed.


@dataclass(frozen=True)
class Decision:
    outcome: str  # "allow" | "deny"
    hop: int
    reason: DenyReason | None = None
    message: str | None = None
    # Phase 4. The target is privileged in the pinned policy, and whether the caller must
    # mint a transaction token before calling it (privileged AND the feature is on).
    privileged: bool = False
    transaction_required: bool = False
    # Phase 4. The effective taint this decision was made under.
    taint: Taint | None = None

    @property
    def allowed(self) -> bool:
        return self.outcome == "allow"

    @property
    def recoverable(self) -> bool:
        return False if self.reason is None else is_recoverable(self.reason)


def _allow(
    hop: int,
    *,
    privileged: bool = False,
    transaction_required: bool = False,
    taint: Taint | None = None,
) -> Decision:
    return Decision(
        outcome="allow",
        hop=hop,
        privileged=privileged,
        transaction_required=transaction_required,
        taint=taint,
    )


def _deny(
    hop: int,
    reason: DenyReason,
    message: str,
    *,
    privileged: bool = False,
    taint: Taint | None = None,
) -> Decision:
    return Decision(
        outcome="deny", hop=hop, reason=reason, message=message, privileged=privileged, taint=taint
    )


def _agent_name(ref: str) -> str | None:
    """The bare agent name, or ``None`` if this is not an agent reference."""
    return ref.removeprefix(AGENT_PREFIX) if ref.startswith(AGENT_PREFIX) else None


def decide(
    policy: PolicyIndex,
    request: AuthorizeRequest,
    token: VerifiedToken,
    *,
    consented_scope: str,
    consented_data_classes: frozenset[str] | None = None,
    step_up: frozenset[str] = frozenset(),
    transaction_tokens_enabled: bool = True,
    taint: Taint | None = None,
    taint_enforced: bool = True,
    revoked: frozenset[str] = frozenset(),
) -> Decision:
    """Decide one hop against the session's pinned policy.

    ``taint`` is the EFFECTIVE taint the caller computed (token claim, agent label, session
    marks); this function only judges it. ``taint_enforced=False``
    records it without ever refusing on it.

    ``consented_data_classes`` is the subset of the pinned policy this session consented to,
    or ``None`` for "everything the policy declares" — which is exactly Phase 2-4 behaviour
    and the default. ``step_up`` is what a human has since approved for this session. Both
    are inputs computed by the caller, like ``taint`` and ``revoked``, so this function
    stays pure.
    """
    # Derived, never accepted: a caller-supplied count is attacker-controlled.
    hop = token.next_hop

    # -- the presented token must belong to this session and this caller -------
    if token.session_id != request.session_id:
        return _deny(hop, DenyReason.OUT_OF_SCOPE, "token belongs to a different session")

    if token.policy_version != policy.version:
        return _deny(
            hop,
            DenyReason.OUT_OF_SCOPE,
            f"token pinned to policy version {token.policy_version}, session to {policy.version}",
        )

    holder = token.holder
    if holder is None:
        # aud is a tool ref: this token was minted for a resource server, not for a
        # further hop. Single-hop binding, enforced at the decision point too.
        return _deny(
            hop,
            DenyReason.OUT_OF_SCOPE,
            f"token was issued for tool call {token.aud!r} and cannot authorize a further hop",
        )

    if request.caller != token.presenter:
        return _deny(
            hop,
            DenyReason.OUT_OF_SCOPE,
            f"caller {request.caller!r} is not who this token was issued to ({token.presenter!r})",
        )

    # -- the route travelled so far must be one the policy declares ------------
    delegators = token.act_chain[1:]  # index 0 is the consenting human
    path_so_far: list[str] = []
    for ref in delegators:
        name = _agent_name(ref)
        if name is None:
            return _deny(
                hop,
                DenyReason.EDGE_NOT_IN_DAG,
                f"delegation chain contains a non-agent link {ref!r}",
            )
        path_so_far.append(name)
    path_so_far.append(holder)

    # -- revocation: nothing built on a revoked agent survives ----------
    # Checked as soon as the chain is known and before anything else about it, so a
    # refusal names the revocation, not a downstream symptom of it.
    # Delegating TO a revoked agent extends authority to it, so the target counts too.
    delegate = _agent_name(request.target)
    revoked_here = [
        agent for agent in (*path_so_far, *((delegate,) if delegate else ())) if agent in revoked
    ]
    if revoked_here:
        return _deny(
            hop,
            DenyReason.AGENT_REVOKED,
            f"agent {revoked_here[0]!r} on this hop has a revoked trust anchor",
            taint=taint,
        )

    if path_so_far[0] != consented_scope:
        return _deny(
            hop,
            DenyReason.EDGE_NOT_IN_DAG,
            f"chain starts at {path_so_far[0]!r}, not the consented scope {consented_scope!r}",
        )
    for agent in path_so_far:
        if agent not in policy.agents:
            return _deny(
                hop, DenyReason.OUT_OF_SCOPE, f"agent {agent!r} is not in the pinned policy"
            )

    caller_agent = path_so_far[-1]
    target_agent = _agent_name(request.target)

    # -- can this caller reach this target at all? -----------------------------
    # The exact rule `agentic-auth drift check` applies offline (app/services/edge_rules.py),
    # so CI and the runtime can never disagree about whether an edge is declared.
    verdict = classify_edge(policy, caller_agent, request.target)
    if verdict is EdgeVerdict.UNDECLARED_DELEGATION:
        return _deny(
            hop,
            DenyReason.EDGE_NOT_IN_DAG,
            f"delegation {caller_agent!r} -> {target_agent!r} is not a declared edge",
        )
    if verdict is EdgeVerdict.UNDECLARED_TOOL:
        # The caller must itself declare the tool; reaching it through the flattened
        # closure would let any agent borrow any other agent's tools.
        return _deny(
            hop,
            DenyReason.OUT_OF_SCOPE,
            f"agent {caller_agent!r} does not declare tool {request.target!r}",
        )
    if verdict is not EdgeVerdict.DECLARED:
        # UNKNOWN_AGENT. Unreachable in practice — every agent on the path was checked
        # above — but an unclear verdict still resolves to a deny, never an allow.
        return _deny(
            hop, DenyReason.OUT_OF_SCOPE, f"agent {caller_agent!r} is not in the pinned policy"
        )
    full_path = (*path_so_far, target_agent) if target_agent is not None else tuple(path_so_far)

    # -- was this data class DECLARED, and was it CONSENTED? -------------------
    #
    # Two different questions, and Phase 5 stops conflating them.
    #
    # "Declared" is a fact about the pinned manifest: the policy either lists this data
    # class for the agent that will act on it, or it does not. Nothing a human approves
    # can change that, because consent may only widen WITHIN the pinned manifest.
    # So an undeclared class is OUT_OF_SCOPE — which is where "not in the
    # pinned policy" already lives, alongside its sibling "agent does not declare tool".
    #
    # "Consented" is a fact about this session: the human approved a subset of what the
    # manifest declares, possibly later widened by a step-up grant they answered. That
    # one IS recoverable, and it is the only thing SCOPE_NOT_CONSENTED now means.
    #
    # Before this split, SCOPE_NOT_CONSENTED fired for the undeclared case — the one
    # thing step-up must never grant — which made the sole recoverable reason recoverable
    # into nothing at all.
    #
    # With `consented_data_classes=None` (the default, and what the flag being off
    # produces) the consented set IS the declared set, the second branch cannot fire, and
    # the first keeps answering exactly as Phase 2-4 did.
    data_class_holder = target_agent or caller_agent
    if not policy.declares_data_class(data_class_holder, request.data_class):
        return _deny(
            hop,
            DenyReason.OUT_OF_SCOPE
            if consented_data_classes is not None
            else DenyReason.SCOPE_NOT_CONSENTED,
            f"data class {request.data_class!r} is not declared for {data_class_holder!r} "
            f"in the pinned policy",
        )
    if consented_data_classes is not None and request.data_class not in (
        consented_data_classes | step_up
    ):
        return _deny(
            hop,
            DenyReason.SCOPE_NOT_CONSENTED,
            f"data class {request.data_class!r} is declared for {data_class_holder!r} but "
            f"was not consented for this session",
        )

    # -- depth ------------------------------------------------------------------
    budget = policy.budget_for_path(full_path)
    if budget <= 0:
        return _deny(
            hop, DenyReason.EDGE_NOT_IN_DAG, f"no compiled path for {' -> '.join(full_path)}"
        )
    if hop > budget:
        return _deny(
            hop, DenyReason.HOP_BUDGET_EXCEEDED, f"effective hop budget for this path is {budget}"
        )

    privileged = target_agent is None and policy.is_privileged(caller_agent, request.target)

    # -- provenance ----------------------------------------------------
    # After every Phase 2 check, before the allow: injected content that steers the agent
    # toward a protected target is refused here, and a consent prompt cannot launder it.
    if (
        taint_enforced
        and taint is Taint.UNTRUSTED_EXTERNAL
        and policy.is_protected(caller_agent, request.target, request.data_class)
    ):
        return _deny(
            hop,
            DenyReason.TAINTED_INTO_PRIVILEGED,
            f"context is tainted by an untrusted source and {request.target!r} is protected",
            privileged=privileged,
            taint=taint,
        )

    return _allow(
        hop,
        privileged=privileged,
        transaction_required=privileged and transaction_tokens_enabled,
        taint=taint,
    )
