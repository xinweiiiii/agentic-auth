"""RFC 8693 token exchange — the only place narrowed authority is minted.

The service re-runs the policy decision rather than trusting that ``/v1/authorize`` was
called first. That is not belt-and-braces: an exchange endpoint that issues on request
would hand out narrowed tokens for hops the PDP refused, which is exactly the containment
failure the phase exists to prevent. With the decision cache warm the re-check is a cache
hit, so honesty here costs almost nothing.

From Phase 3 it also refuses to mint unless the allow it is spending is **recorded**: the
``action_id`` must name a committed allow row for exactly this session, hop, target, data
class, and subject token. This request can only see committed rows, so an allow whose audit
commit never landed cannot be turned into a token — whatever the route or the sidecar did.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime

from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from agentic_auth.boundary.guarantee import Guarantee
from agentic_auth.config import get_settings
from agentic_auth.repositories import audit_decisions as audit_repo
from agentic_auth.schemas.authorize import AuthorizeRequest, DenyReason, Taint
from agentic_auth.schemas.token import TokenExchangeRequest, TokenExchangeResponse
from agentic_auth.services import policy_loader
from agentic_auth.services.anchors import AnchorCache
from agentic_auth.services.metrics import get_metrics
from agentic_auth.services.pdp import Decision, decide
from agentic_auth.services.revocation import RevocationService
from agentic_auth.services.sessions import SessionService
from agentic_auth.services.taint import Marked, TaintStore, TaintStoreUnavailable, effective_taint
from agentic_auth.services.tokens import replay
from agentic_auth.services.tokens.act_chain import nest
from agentic_auth.services.tokens.jwt_profile import LEEWAY_SECONDS, TokenVerificationError
from agentic_auth.services.tokens.profile import TokenProfile, VerifiedToken


class ExchangeRefused(Exception):
    """The exchange cannot proceed. ``oauth_error`` is the RFC 6749 §5.2 code."""

    def __init__(self, oauth_error: str, description: str) -> None:
        super().__init__(description)
        self.oauth_error = oauth_error
        self.description = description


@dataclass
class ExchangeDenied(Exception):
    """Policy refused this hop, so no token is issued.

    Carries everything the decision record needs — including the verified subject token,
    which the record's chain is built from — so the route does not have to re-derive
    context from a half-processed request.
    """

    decision: Decision
    target: str
    session_id: str
    caller: str
    data_class: str
    policy_version: int
    act_chain: list[str]
    # Phase 4: the effective taint and its source, for the record.
    taint_source: str | None = None
    # `repr=False`: a VerifiedToken holds the raw JWT, and a dataclass repr would put it in
    # any traceback or `logger.exception` that renders this exception. The audit record only
    # ever reads jti/holder/act_chain/action_id off it.
    token: VerifiedToken = field(repr=False, kw_only=True)

    def __str__(self) -> str:
        return self.decision.message or "hop denied"


def _normalized(session_id: str) -> str:
    try:
        return str(uuid.UUID(session_id))
    except (ValueError, TypeError, AttributeError):
        return session_id


class TokenExchangeService:
    def __init__(
        self,
        tokens: TokenProfile,
        sessions: SessionService,
        *,
        ttl_seconds: int | None = None,
    ) -> None:
        self._tokens = tokens
        self._sessions = sessions
        self._ttl = ttl_seconds or get_settings().hop_token_ttl_seconds

    async def exchange(
        self,
        db: AsyncSession,
        redis: Redis | None,
        body: TokenExchangeRequest,
        *,
        action_id: uuid.UUID,
        taint: Taint | None = None,
    ) -> tuple[TokenExchangeResponse, Decision, VerifiedToken]:
        subject = self._verify_subject(body.subject_token)

        holder = subject.holder
        if holder is None:
            raise ExchangeRefused(
                "invalid_grant",
                f"subject token was issued for tool call {subject.aud!r} and cannot be exchanged",
            )

        # Before the re-decision and before the jti is spent, so an exchange refused here
        # costs the caller nothing: the same subject token still works with the right id.
        await self._require_recorded_allow(db, action_id, subject, body)

        session = await self._sessions.get(db, redis, subject.session_id)
        policy = await policy_loader.load(db, redis, session.scope, session.policy_version)
        settings = get_settings()

        # Phase 4: with identity on, a bearer grant alone buys nothing.
        # The holder must prove possession of its enrolled key over THIS subject token.
        not_enrolled = False
        if settings.identity_required:
            not_enrolled = not await self._require_possession(db, redis, holder, body, subject)

        # Phase 4: re-decide under the same effective taint the PDP used, read fresh — a
        # context marked between authorize and exchange is refused here.
        protected = policy.is_protected(holder, body.resource, body.scope)
        try:
            # The allow being spent may itself have marked this context (its target is an
            # untrusted source). That mark is for the NEXT decision, not this exchange.
            marked = Marked.of(
                await TaintStore(redis).marked(subject.session_id),
                subject.jti,
                exclude_action_id=str(action_id),
            )
        except TaintStoreUnavailable:
            if protected:
                raise ExchangeRefused(
                    "invalid_grant", "taint state could not be read for a protected target"
                ) from None
            marked = Marked(False, None)
        effective = effective_taint(subject.taint, taint, marked.tainted)
        taint_source = marked.source if marked.tainted else None

        # This is an internal re-decision, not a report from an enforcement point: the
        # exchange re-checks the hop it is about to narrow for. `guarantee` is required on
        # the schema so no PEP can omit it, but nothing here is recorded under
        # it — this request never reaches `_record()`. FULL is the honest value for a
        # check the control plane performs on itself.
        request = AuthorizeRequest(
            session_id=subject.session_id,
            caller=subject.presenter,
            target=body.resource,
            data_class=body.scope,
            taint=taint,
            guarantee=Guarantee.FULL,
        )
        revoked = await RevocationService(AnchorCache(redis)).revoked_set(db, redis)
        decision = decide(
            policy,
            request,
            subject,
            consented_scope=session.scope,
            transaction_tokens_enabled=settings.transaction_tokens_enabled,
            taint=effective,
            taint_enforced=settings.taint_enforcement_enabled,
            revoked=revoked,
        )
        if decision.reason is DenyReason.AGENT_REVOKED:
            get_metrics().revoked_hop_refusals.labels(where="exchange").inc()
        if not_enrolled:
            # Recorded like any policy refusal: predictable from state, not an outage.
            decision = Decision(
                outcome="deny",
                hop=decision.hop,
                reason=DenyReason.AGENT_NOT_ENROLLED,
                message=f"agent {holder!r} has no live trust anchor; enroll it first",
                privileged=decision.privileged,
                taint=decision.taint,
            )
            get_metrics().exchange_pop_failures.labels(cause="not_enrolled").inc()
        if not decision.allowed:
            # A refused hop yields no token, ever.
            raise ExchangeDenied(
                decision=decision,
                target=body.resource,
                session_id=subject.session_id,
                caller=subject.presenter,
                data_class=body.scope,
                policy_version=session.policy_version,
                act_chain=subject.act_chain,
                taint_source=taint_source,
                token=subject,
            )

        if body.audience is not None and body.audience != body.resource:
            raise ExchangeRefused(
                "invalid_target",
                f"audience {body.audience!r} does not match resource {body.resource!r}",
            )

        # Spend the DECISION. After this point the same recorded
        # allow cannot buy a second token; the same subject token can still be exchanged
        # for OTHER recorded allows until it expires, which is what lets an agent make more
        # than one call at a hop. Deliberately the last check before minting.
        #
        # The guard must outlive the window in which `verify()` will still ACCEPT the
        # subject token, not merely its nominal lifetime. `verify()` allows LEEWAY_SECONDS
        # past `exp`, so a guard sized to `hop_token_ttl_seconds` from the moment of
        # spending always dies first and reopens a replay window — with the shipped
        # defaults (60s TTL, 60s leeway) that window is up to 59 seconds wide.
        remaining = (subject.expires_at - datetime.now(UTC)).total_seconds()
        guard_ttl = int(remaining) + LEEWAY_SECONDS + 1
        await replay.consume(
            redis, replay.spent_key(action_id), ttl_seconds=guard_ttl, subject_jti=subject.jti
        )

        access_token = self._tokens.mint_hop_token(
            sub=subject.sub,  # the human never changes
            target=body.resource,
            data_class=body.scope,
            session_id=subject.session_id,
            policy_version=session.policy_version,
            hop=decision.hop + 1,
            act=nest(subject.act, f"agent://{holder}"),
            # The next hop's audit row links to this one through this claim.
            action_id=str(action_id),
            # The delegate inherits its delegator's taint through this signed claim.
            taint=effective,
        )
        return (
            TokenExchangeResponse(
                access_token=access_token, expires_in=self._ttl, scope=body.scope
            ),
            decision,
            subject,
        )

    async def _require_possession(
        self,
        db: AsyncSession,
        redis: Redis | None,
        holder: str,
        body: TokenExchangeRequest,
        subject: VerifiedToken,
    ) -> bool:
        """Verify the actor_token against the holder's live anchor. Returns ``False`` when
        the holder has no live anchor (recorded as AGENT_NOT_ENROLLED by the caller); raises
        ``ExchangeRefused`` for a missing or bad actor_token."""
        anchor = await AnchorCache(redis).current(db, holder)
        if anchor is None or anchor.status != "enrolled" or anchor.jwks is None:
            return False
        metrics = get_metrics()
        if not body.actor_token:
            metrics.exchange_pop_failures.labels(cause="missing").inc()
            raise ExchangeRefused(
                "invalid_grant",
                "actor_token is required: sign the subject token with your enrolled key",
            )
        try:
            self._tokens.verify_actor_token(
                body.actor_token,
                anchor_jwks=anchor.jwks,
                subject_token=body.subject_token,
                expected_agent=holder,
            )
        except TokenVerificationError as exc:
            cause = "wrong_agent" if "different agent" in str(exc) else "invalid"
            metrics.exchange_pop_failures.labels(cause=cause).inc()
            raise ExchangeRefused("invalid_grant", str(exc)) from exc
        return True

    async def _require_recorded_allow(
        self,
        db: AsyncSession,
        action_id: uuid.UUID,
        subject: VerifiedToken,
        body: TokenExchangeRequest,
    ) -> None:
        row = await audit_repo.get_committed_allow(db, action_id)
        if row is None:
            raise ExchangeRefused("invalid_grant", f"no recorded allow decision {action_id}")
        if row.outcome != "allow":
            raise ExchangeRefused("invalid_grant", f"recorded decision {action_id} was a deny")

        bindings = (
            ("session_id", str(row.session_id), _normalized(subject.session_id)),
            ("hop", row.hop, subject.next_hop),
            ("target", row.target, body.resource),
            ("data_class", row.data_class, body.scope),
            ("subject_jti", row.subject_jti, subject.jti),
        )
        for bound, recorded, presented in bindings:
            if recorded != presented:
                raise ExchangeRefused(
                    "invalid_grant",
                    f"recorded decision {action_id} does not authorize this exchange: "
                    f"{bound} differs",
                )

    def _verify_subject(self, raw: str) -> VerifiedToken:
        try:
            # No audience is asserted here: the subject token's audience is whoever holds
            # it, and the holder is exactly what we are about to read off it.
            return self._tokens.verify(raw)
        except TokenVerificationError as exc:
            raise ExchangeRefused("invalid_grant", f"subject token rejected: {exc}") from exc


__all__ = [
    "TokenExchangeService",
    "ExchangeRefused",
    "ExchangeDenied",
    "DenyReason",
]
