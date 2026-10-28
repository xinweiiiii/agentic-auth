"""``POST /v1/authorize`` — decide one hop against the session's pinned policy.

Always returns ``200`` with a decision body. A deny is a successful decision, not an HTTP
error: the sidecar and the SDK translate it into a refusal for the agent, and conflating
the two would make "the PDP is down" indistinguishable from "the PDP said no".

The response is rendered from what was **recorded**, after the record has committed. An
answer that would let a call leave the host is never sent for a decision that has no durable
audit row.
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Mapping
from datetime import UTC, datetime

from fastapi import APIRouter, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app import observability
from app.api.deps import PresentedTokenDep, SessionDep
from app.api.service_deps import (
    AuditServiceDep,
    RedisDep,
    RevocationServiceDep,
    SessionServiceDep,
)
from app.config import get_settings
from app.errors import DomainError
from app.models.audit_decision import target_kind_of
from app.observability import logs, surface
from app.schemas.authorize import AuthorizeDecision, AuthorizeRequest, DenyReason, Taint
from app.services import decision_cache, policy_loader
from app.services.audit import AuditService, RecordResult
from app.services.metrics import get_metrics
from app.services.pdp import Decision, decide
from app.services.taint import (
    Marked,
    TaintStore,
    TaintStoreUnavailable,
    ancestors_of,
    effective_taint,
)
from app.services.tokens.profile import VerifiedToken

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1", tags=["authorize"])

UNRECORDED_MESSAGE = "decision could not be recorded; refusing to dispatch without a record"


@router.post("/authorize", response_model=AuthorizeDecision)
async def authorize(
    request: Request,
    body: AuthorizeRequest,
    db: SessionDep,
    redis: RedisDep,
    sessions: SessionServiceDep,
    audit: AuditServiceDep,
    token: PresentedTokenDep,
    revocations: RevocationServiceDep,
) -> AuthorizeDecision:
    hop = token.next_hop

    try:
        session = await sessions.get(db, redis, body.session_id)
        policy = await policy_loader.load(db, redis, session.scope, session.policy_version)
    except DomainError:
        # An expired session or a missing/unenforceable policy is the caller's answer to
        # get, with its own status code. Re-raised rather than flattened into a deny.
        raise
    except Exception:
        # Anything else — a dropped connection, a malformed row — is a deny, recorded.
        # There is no path here that omits the record or returns an allow.
        # NOT logger.exception: with a sink attached the SDK exports `exception.message` and
        # the full `exception.stacktrace`, and a traceback through policy loading can carry
        # connection-string or token fragments. We keep the type and lose the trace — a
        # deliberate reduction, documented in contracts/phase-3-4-deltas.md §6. Do not revert.
        logger.warning(
            "policy load failed",
            extra=logs.fields(
                surface.COMPONENT_CONTROL_PLANE,
                session_id=body.session_id,
                error_type="PolicyLoadFailed",
            ),
        )
        rendered, _ = await _record(
            db,
            audit,
            body,
            Decision(
                outcome="deny",
                hop=hop,
                reason=DenyReason.PDP_UNAVAILABLE,
                message="policy could not be loaded",
            ),
            policy_version=token.policy_version,
            token=token,
            headers=request.headers,
        )
        return rendered

    settings = get_settings()

    # -- provenance (Phase 4, contracts/taint.md §3) ---------------------------------
    # What the session already knows about this context, from the calls it decided.
    caller_agent = token.holder
    protected = caller_agent is not None and policy.is_protected(
        caller_agent, body.target, body.data_class
    )
    store = TaintStore(redis)
    marked = Marked(False, None)
    taint_known = True
    try:
        marked = Marked.of(await store.marked(body.session_id), token.jti)
    except TaintStoreUnavailable:
        if protected:
            # Refusing on unknown taint is the only honest answer for a protected target.
            logger.warning(
                "taint store unavailable for a protected target",
                extra=logs.fields(
                    surface.COMPONENT_CONTROL_PLANE,
                    session_id=body.session_id,
                    error_type="TaintStoreUnavailable",
                ),
            )
            rendered, _ = await _record(
                db,
                audit,
                body,
                Decision(
                    outcome="deny",
                    hop=hop,
                    reason=DenyReason.PDP_UNAVAILABLE,
                    message="taint state could not be read for a protected target",
                ),
                policy_version=session.policy_version,
                token=token,
                headers=request.headers,
            )
            return rendered
        taint_known = False
    taint = effective_taint(token.taint, body.taint, marked.tainted) if taint_known else None
    taint_source = marked.source if marked.tainted else None
    if not marked.tainted and taint is Taint.UNTRUSTED_EXTERNAL:
        taint_source = "reported" if body.taint is Taint.UNTRUSTED_EXTERNAL else "inherited"

    revoked = await revocations.revoked_set(db, redis)
    chain_agents = {a.removeprefix("agent://") for a in token.act_chain[1:]}
    if caller_agent is not None:
        chain_agents.add(caller_agent)
    if body.target.startswith("agent://"):
        chain_agents.add(body.target.removeprefix("agent://"))  # delegating TO a revoked agent
    revoked_on_chain = frozenset(revoked & chain_agents)

    cache_key = decision_cache.key(
        body,
        policy_version=session.policy_version,
        hop=hop,
        # The chain is a decision input: the same call is allowed via one route and
        # denied via another when the effective budgets differ.
        act_chain=token.act_chain,
        taint=taint,
        revoked=revoked_on_chain,
    )
    decision = await decision_cache.get(redis, cache_key)
    if decision is None:
        decision = decide(
            policy,
            body,
            token,
            consented_scope=session.scope,
            transaction_tokens_enabled=settings.transaction_tokens_enabled,
            taint=taint,
            taint_enforced=settings.taint_enforcement_enabled,
            revoked=revoked_on_chain,
        )
        await decision_cache.put(redis, cache_key, decision)

    if decision.reason is DenyReason.AGENT_REVOKED:
        get_metrics().revoked_hop_refusals.labels(where="authorize").inc()
    if decision.reason is DenyReason.TAINTED_INTO_PRIVILEGED:
        get_metrics().taint_blocks.labels(source_class=_source_class(taint_source)).inc()

    rendered, record = await _record(
        db,
        audit,
        body,
        decision,
        policy_version=session.policy_version,
        token=token,
        taint_source=taint_source,
        headers=request.headers,
    )

    get_metrics().decisions_by_guarantee.labels(
        level=body.guarantee.value, outcome=rendered.outcome
    ).inc()

    # -- mark: this call reaches for a source the caller does not trust ---------------
    # On an allow (or an observe-mode forwarded policy deny) the result will be consumed
    # by this context and by every ancestor on the return path. Recorded first-writer-wins,
    # so the source that introduced the taint is the one the audit trail names.
    will_dispatch = rendered.allowed or (
        rendered.reason is not None and rendered.reason in _POLICY_FORWARDABLE and not body.enforced
    )
    if (
        will_dispatch
        and caller_agent is not None
        and not policy.is_trusted_source(caller_agent, body.target)
    ):
        contexts = ancestors_of(record.parent_chain, token.jti)
        try:
            await store.mark(
                body.session_id,
                contexts,
                body.target,
                action_id=str(record.action_id) if record.action_id else None,
                ttl_seconds=int((session.expires_at - _now()).total_seconds()),
            )
        except TaintStoreUnavailable:
            # An untrusted fetch whose taint cannot be remembered is how injected content
            # gets laundered. The allow is withdrawn; the record already says allow, and
            # the exchange will refuse because the response carries no usable action_id.
            logger.warning(
                "taint store unavailable while marking; withdrawing the allow",
                extra=logs.fields(
                    surface.COMPONENT_CONTROL_PLANE,
                    session_id=body.session_id,
                    error_type="TaintStoreUnavailable",
                ),
            )
            return _withdrawn(rendered, body, session.policy_version, token)
        _count_marks(contexts, token.jti)

    return rendered


_POLICY_FORWARDABLE = frozenset(
    {
        DenyReason.OUT_OF_SCOPE,
        DenyReason.HOP_BUDGET_EXCEEDED,
        DenyReason.EDGE_NOT_IN_DAG,
        DenyReason.SCOPE_NOT_CONSENTED,
        DenyReason.TAINTED_INTO_PRIVILEGED,
        DenyReason.AGENT_REVOKED,
        DenyReason.AGENT_NOT_ENROLLED,
    }
)


def _now() -> datetime:
    return datetime.now(UTC)


def _source_class(source: str | None) -> str:
    if source is None:
        return "unknown"
    if source == "reported":
        return "reported"
    if source.startswith("agent://"):
        return "agent"
    if source.startswith("mcp://"):
        return "tool"
    return "unknown"


def _count_marks(contexts: set[str], own_jti: str) -> None:
    metrics = get_metrics()
    for ctx in contexts:
        if ctx == own_jti:
            metrics.taint_marks.labels(propagation="self").inc()
        elif ctx == "*":
            metrics.taint_marks.labels(propagation="sentinel").inc()
        else:
            metrics.taint_marks.labels(propagation="ancestor").inc()


def _withdrawn(
    rendered: AuthorizeDecision, body: AuthorizeRequest, policy_version: int, token: VerifiedToken
) -> AuthorizeDecision:
    """An allow the caller must not act on: rendered as PDP_UNAVAILABLE with no action_id,
    which the exchange refuses and the sidecar/SDK treat as an outage (blocks in every mode)."""
    get_metrics().denials.labels(reason=DenyReason.PDP_UNAVAILABLE.value).inc()
    return AuthorizeDecision(
        outcome="deny",
        hop=rendered.hop,
        policy_version=policy_version,
        session_id=body.session_id,
        reason=DenyReason.PDP_UNAVAILABLE,
        recoverable=False,
        target=body.target,
        taint=rendered.taint,
        taint_source=rendered.taint_source,
        privileged=rendered.privileged,
        transaction_required=rendered.transaction_required,
        message="taint state could not be recorded; refusing to dispatch an untrusted fetch",
        action_id=None,
        acting_agent=token.holder,
        recorded=rendered.recorded,
        guarantee=body.guarantee,
    )


async def _record(
    db: AsyncSession,
    audit: AuditService,
    body: AuthorizeRequest,
    decision: Decision,
    *,
    policy_version: int,
    token: VerifiedToken,
    taint_source: str | None = None,
    step_up_ref: uuid.UUID | None = None,
    headers: Mapping[str, str] | None = None,
) -> tuple[AuthorizeDecision, RecordResult]:
    """Record, commit, then render from the result. Every decision is recorded — including
    the ones caused by an unreachable dependency, which are the ones an operator most needs
    to see."""
    # `enforced=false` means this decision was NOT acted on — which only a deny can be. An
    # allow in observe mode is still exchanged and forwarded, so it was acted on and is
    # recorded as enforced. That keeps `enforced=false` meaning exactly "would have been
    # blocked", which is the observe-mode report.
    #
    # Reported by the enforcement point, never seen by `decide()`: the PDP is mode-blind,
    # so observe mode changes a consequence and never an outcome.
    enforced = body.enforced or decision.allowed

    result = await audit.record(
        db,
        session_id=body.session_id,
        caller=body.caller,
        target=body.target,
        data_class=body.data_class,
        decision=decision,
        enforced=enforced,
        taint=decision.taint.value if decision.taint else None,
        taint_source=taint_source,
        policy_version=policy_version,
        token=token,
        privileged=decision.privileged,
        # Phase 5. What the enforcement point said it is; recorded on every row (FR-017).
        guarantee_level=body.guarantee.value,
        step_up_ref=step_up_ref,
    )

    # A call leaves the host on an allow, and on an unenforced (observe-mode) deny. Either
    # way, without a durable record it must not — so the answer becomes a refusal. An
    # enforced deny blocks regardless, and stays the deny it was.
    if not result.recorded and (decision.allowed or not enforced):
        decision = Decision(
            outcome="deny",
            hop=decision.hop,
            reason=DenyReason.AUDIT_UNAVAILABLE,
            message=UNRECORDED_MESSAGE,
        )

    if decision.reason is not None:
        get_metrics().denials.labels(reason=decision.reason.value).inc()

    rendered = AuthorizeDecision(
        outcome=decision.outcome,
        hop=decision.hop,
        policy_version=policy_version,
        session_id=body.session_id,
        reason=decision.reason,
        recoverable=decision.recoverable if decision.reason else None,
        target=body.target,
        taint=decision.taint,
        taint_source=taint_source,
        privileged=decision.privileged,
        transaction_required=decision.transaction_required,
        message=decision.message,
        action_id=result.action_id,
        acting_agent=token.holder,
        recorded=result.recorded,
        guarantee=body.guarantee,
    )
    _emit_decision_span(rendered, body, token, policy_version, taint_source, headers)
    return rendered, result


def _emit_decision_span(
    rendered: AuthorizeDecision,
    body: AuthorizeRequest,
    token: VerifiedToken,
    policy_version: int,
    taint_source: str | None,
    headers: Mapping[str, str] | None,
) -> None:
    """One span per decision, emitted from the single place every decision is rendered.

    Deliberately **after** the audit record has committed, so ``authz.action_id`` is the
    recorded id and never a guess. When the record failed there is no action id — and the
    decision has already been rewritten to a deny with ``AUDIT_UNAVAILABLE``, so the pair
    "no action id, no AUDIT_UNAVAILABLE" cannot occur (data-model.md §1).

    ``record_exception`` is off: the SDK would attach ``exception.message`` and a full
    ``exception.stacktrace``, and a traceback through token verification can carry a token
    fragment (research.md R7).
    """
    config = observability.config()
    if not config.enabled:
        return
    parent = observability.extract_parent(
        headers or {},
        session_id=str(body.session_id),
        key=config.key,
        metrics=get_metrics(),
    )
    attributes = observability.decision_attributes(
        config,
        action_id=str(rendered.action_id) if rendered.action_id else None,
        session_id=str(body.session_id),
        hop=rendered.hop,
        outcome=rendered.outcome,
        deny_reason=rendered.reason.value if rendered.reason else None,
        recoverable=bool(rendered.recoverable),
        enforced=body.enforced or rendered.allowed,
        target_kind=target_kind_of(body.target),
        data_class=body.data_class,
        privileged=bool(rendered.privileged),
        taint=rendered.taint.value if rendered.taint else None,
        policy_version=policy_version,
        guarantee_level=getattr(rendered, "guarantee", None) or getattr(body, "guarantee", None),
        acting_agent=token.holder,
        act_chain=list(token.act_chain),
        taint_source=taint_source,
    )
    with observability.tracer().start_as_current_span(
        surface.SPAN_DECIDE,
        context=parent,
        attributes=attributes,
        record_exception=False,
    ):
        pass
