"""The SDK client — inline enforcement for agent code you control.

Same endpoints, same decisions, same records as the sidecar. The difference is only where
enforcement sits: inline gives better errors and needs no extra process, but an agent can
skip it. The sidecar cannot be skipped when egress is pinned, which is why both exist.

With a trace path configured (or ``AGENTIC_AUTH_TRACE_PATH`` set, as ``agentic-auth drift
record`` does), every ``authorize`` also records one edge event, attributed to the agent the
decision service verified — the same shape the sidecar records.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

import httpx

from app.boundary.guarantee import Guarantee
from app.schemas.authorize import POLICY_REASONS, DenyReason, Taint
from app.schemas.token import GRANT_TYPE, JWT_TOKEN_TYPE
from app.sdk.context import HopContext
from app.sdk.errors import (
    ControlPlaneRejected,
    ControlPlaneUnavailable,
    ManifestRejected,
    PolicyDenied,
    TransactionParamsRequired,
)
from app.sdk.identity import AgentKey
from app.sdk.planes import AdminPlane, AuditPlane, IdentityPlane, Transport
from app.sdk.provenance import LabeledResult, SourceClassifier
from app.services.edge_trace import EdgeRecorder, recorder_from_env


@dataclass(frozen=True)
class Grant:
    """Narrowed authority for exactly one call — plus, for a privileged target, the
    transaction token bound to its parameters, and the identity assertion when the client
    holds an agent key."""

    access_token: str
    scope: str
    expires_in: int
    hop: int
    target: str = ""
    transaction_token: str | None = None
    identity_assertion: str | None = None
    # The effective taint the decision was made under, from the hop token's claim.
    taint: Taint | None = None
    # The audit row for the allow this grant was narrowed from. Pass it to
    # ``client.audit.chain(...)`` to read the delegation chain back to the consenting
    # human — the same id the resource server reads off the token it admits.
    action_id: str | None = None

    def headers(self) -> dict[str, str]:
        out = {"Authorization": f"Bearer {self.access_token}"}
        if self.transaction_token is not None:
            out["Txn-Token"] = self.transaction_token
        if self.identity_assertion is not None:
            out["Agent-Identity"] = self.identity_assertion
        return out


@dataclass(frozen=True)
class CompletedHop:
    hop: int
    target: str
    action_id: str | None


@dataclass(frozen=True)
class PartialOutcome:
    """What a chain that cannot resume gives back.

    The hops in ``completed`` already ran, and some of them had side effects that no
    refusal further along can undo. A bare exception would leave the caller guessing how
    far the task got; naming the hops is the difference between "it failed" and "it read
    the account but did not close it".
    """

    completed: tuple[CompletedHop, ...]
    blocked_hop: int
    blocked_target: str
    reason: DenyReason
    recoverable: bool
    challenge: dict[str, Any] | None = None

    @classmethod
    def from_denial(cls, completed: Sequence[CompletedHop], denied: PolicyDenied) -> PartialOutcome:
        return cls(
            completed=tuple(completed),
            blocked_hop=denied.hop,
            blocked_target=denied.target,
            reason=denied.reason,
            recoverable=denied.recoverable,
            challenge=denied.challenge,
        )


@dataclass(frozen=True)
class Session:
    session_id: str
    root_grant: str
    policy_version: int
    scope: str
    user_sub: str
    hop_budget: int
    expires_at: str
    # Phase 5. What the session actually consented to: None means every data class the
    # pinned policy declares, which is the Phase 2-4 behaviour and the default.
    data_classes: list[str] | None = None

    def context(self) -> HopContext:
        return HopContext(session_id=self.session_id, token=self.root_grant)


def _acting_agent(decision: dict) -> str | None:
    value = decision.get("acting_agent")
    return value if isinstance(value, str) and value else None


class AgenticAuthClient:
    def __init__(
        self,
        base_url: str,
        *,
        admin_token: str | None = None,
        audit_token: str | None = None,
        identity_token: str | None = None,
        client: httpx.AsyncClient | None = None,
        timeout: float = 5.0,
        trace_path: str | None = None,
        identity_key: AgentKey | None = None,
        agent_name: str | None = None,
        guarantee: Guarantee = Guarantee.FULL,
    ) -> None:
        if bool(identity_key) != bool(agent_name):
            raise ValueError("identity_key and agent_name must be given together")
        # Phase 5. The in-process client decides every hop before dispatch, so `full` is
        # accurate. Overridable only so an embedding that knows it is weaker can say so.
        self._guarantee = guarantee
        self._identity_key = identity_key
        self._agent_name = agent_name
        # Phase 4: classify sources the way the PDP would, when the agent holds its manifest.
        self._classifier = SourceClassifier()
        self._base_url = base_url.rstrip("/")
        self._admin_token = admin_token
        self._timeout = httpx.Timeout(timeout)
        self._client = client or httpx.AsyncClient()
        self._owns_client = client is None
        self._recorder: EdgeRecorder | None = (
            EdgeRecorder(trace_path, "sdk") if trace_path else recorder_from_env("sdk")
        )
        # The planes around the hop path, each with its own least-privileged bearer. The
        # read-only tokens fall back to the admin token, which every route also accepts —
        # so one credential works in a notebook and three work in production.
        transport = Transport(self._client, self._base_url, self._timeout)
        self.admin = AdminPlane(transport, admin_token)
        self.audit = AuditPlane(transport, audit_token or admin_token)
        self.identity = IdentityPlane(transport, identity_token or audit_token or admin_token)
        self._transport = transport

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    async def __aenter__(self) -> AgenticAuthClient:
        return self

    async def __aexit__(self, *_exc: object) -> None:
        await self.aclose()

    def use_manifest(self, manifest: dict[str, Any]) -> None:
        """Adopt this agent's manifest so ``wrap_result`` classifies like the PDP."""
        self._classifier = SourceClassifier.from_manifest(manifest)

    def wrap_result(
        self, value: Any, source_ref: str, *, trusted_sources: list[str] | None = None
    ) -> LabeledResult[Any]:
        """Label a value the agent obtained on its own. Unmatched
        sources are untrusted_external — the label can only raise taint."""
        classifier = (
            SourceClassifier(trusted_sources) if trusted_sources is not None else self._classifier
        )
        return classifier.wrap(value, source_ref)

    # -- ops: is it there, and what does it sign with? --------------------------

    async def healthz(self) -> dict[str, Any]:
        """Liveness. Answers without touching the database or Redis."""
        return await self._transport.json("GET", "/healthz")

    async def readyz(self) -> dict[str, Any]:
        """Readiness: the control plane could reach its database and Redis just now.

        Raises :class:`ControlPlaneUnavailable` when it could not — which is the answer,
        not an error to swallow. Check this before a deploy gate, never per hop.
        """
        return await self._transport.json("GET", "/readyz")

    async def jwks(self) -> dict[str, Any]:
        """The issuer's public keys. Unauthenticated by design: a resource server must be
        able to verify a hop token offline, with no call back on the hot path."""
        return await self._transport.json("GET", "/.well-known/jwks.json")

    def _admin_headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self._admin_token}"} if self._admin_token else {}

    def _record(
        self, acting_agent: str | None, target: str, outcome: str, reason: str | None
    ) -> None:
        if self._recorder is not None:
            self._recorder.record(
                acting_agent=acting_agent, target=target, outcome=outcome, reason=reason
            )

    async def consent(
        self,
        *,
        scope: str,
        user_sub: str,
        ttl_seconds: int | None = None,
        data_classes: list[str] | None = None,
    ) -> Session:
        """Record a human's consent and pin the policy version for the session."""
        body: dict[str, object] = {"scope": scope, "user_sub": user_sub}
        if ttl_seconds is not None:
            body["ttl_seconds"] = ttl_seconds
        if data_classes is not None:
            # Phase 5: consent to a subset. Omitting it consents to everything the pinned
            # policy declares, exactly as before.
            body["data_classes"] = list(data_classes)

        response = await self._client.post(
            f"{self._base_url}/v1/consent",
            headers=self._admin_headers(),
            json=body,
            timeout=self._timeout,
        )
        if response.status_code != 201:
            raise ControlPlaneUnavailable(
                f"consent failed with {response.status_code}: {response.text}"
            )
        return Session(**response.json())

    async def enroll(
        self,
        agent_id: str,
        *,
        key: AgentKey,
        agent_name: str,
        claims: dict[str, Any] | None = None,
        principal_assertion: str | None = None,
        enroll_token: str | None = None,
    ) -> dict[str, Any]:
        """Begin + sign + complete enrollment. Returns the
        outcome body: ``enrolled`` or ``quarantined``. Grants nothing."""
        headers = {"Authorization": f"Bearer {enroll_token or self._admin_token}"}
        doc = key.identity_document(
            agent_name, claims=claims, principal_assertion=principal_assertion
        )
        begun = await self._client.post(
            f"{self._base_url}/v1/agents/{agent_id}/enroll",
            headers=headers,
            json={"identity_doc": doc},
            timeout=self._timeout,
        )
        if begun.status_code != 201:
            raise ControlPlaneUnavailable(
                f"enrollment could not begin: {begun.status_code} {begun.text}"
            )
        challenge = begun.json()
        completed = await self._client.post(
            f"{self._base_url}/v1/agents/{agent_id}/enroll/complete",
            headers=headers,
            json={
                "challenge_id": challenge["challenge_id"],
                "signed_response": key.sign_challenge(agent_name, challenge["nonce"]),
            },
            timeout=self._timeout,
        )
        if completed.status_code != 200:
            raise ControlPlaneUnavailable(
                f"enrollment refused: {completed.status_code} {completed.text}"
            )
        return dict(completed.json())

    async def revoke(self, agent_id: str, *, reason: str | None = None) -> dict[str, Any]:
        """Admin: revoke an agent's trust anchor and every chain built on it."""
        response = await self._client.post(
            f"{self._base_url}/v1/agents/{agent_id}/revoke",
            headers=self._admin_headers(),
            json={"reason": reason} if reason else {},
            timeout=self._timeout,
        )
        if response.status_code != 200:
            raise ControlPlaneUnavailable(f"revoke failed: {response.status_code} {response.text}")
        return dict(response.json())

    async def authorize(
        self,
        ctx: HopContext,
        *,
        target: str,
        data_class: str,
        taint: Taint | str | None = None,
        params: dict[str, Any] | None = None,
    ) -> Grant:
        """Decide and narrow, in that order — and bind, for a privileged target.

        Both, never one: there is no legitimate reason to take a decision without acting
        on it, and an exchange without a decision would issue authority nobody approved.
        ``params`` is the call's JSON body; required when the decision says
        ``transaction_required``, ignored otherwise.
        """
        acting_agent: str | None = None
        effective_taint = _max_taint(ctx.taint, taint)
        try:
            decision = await self._decide(
                ctx, target=target, data_class=data_class, taint=effective_taint
            )
            acting_agent = _acting_agent(decision)
            if decision["outcome"] != "allow":
                raise PolicyDenied(
                    DenyReason(decision["reason"]),
                    message=decision.get("message") or "denied by policy",
                    target=target,
                    hop=decision.get("hop", ctx.hop),
                    session_id=ctx.session_id,
                    policy_version=decision.get("policy_version"),
                    action_id=decision.get("action_id"),
                    taint=decision.get("taint"),
                    taint_source=decision.get("taint_source"),
                    challenge=decision.get("step_up"),
                    data_class=data_class,
                )
            action_id = decision.get("action_id")
            if decision.get("recorded") is False or not action_id:
                # The exchange would refuse anyway; saying why here is the actionable part.
                raise ControlPlaneUnavailable(
                    "decision could not be recorded; refusing to proceed without a record"
                )
            transaction_required = bool(decision.get("transaction_required"))
            if transaction_required and params is None:
                raise TransactionParamsRequired(
                    f"{target} is privileged: pass params= so the call can be bound"
                )
            grant = await self._exchange(
                ctx,
                target=target,
                data_class=data_class,
                taint=effective_taint,
                action_id=str(action_id),
            )
            if transaction_required:
                assert params is not None
                grant = await self._mint_transaction(grant, params)
            if self._identity_key is not None and self._agent_name is not None:
                grant = Grant(
                    **{
                        **grant.__dict__,
                        "identity_assertion": self._identity_key.identity_assertion(
                            self._agent_name, grant.access_token, target
                        ),
                    }
                )
        except TransactionParamsRequired:
            self._record(acting_agent, target, "blocked_local", "TRANSACTION_PARAMS_REQUIRED")
            raise
        except PolicyDenied as denied:
            outcome = "deny" if denied.reason in POLICY_REASONS else "blocked_infra"
            self._record(acting_agent, target, outcome, denied.reason.value)
            raise
        except ControlPlaneUnavailable:
            self._record(acting_agent, target, "blocked_infra", None)
            raise

        self._record(acting_agent, target, "allow", None)
        return grant

    async def _decide(
        self, ctx: HopContext, *, target: str, data_class: str, taint: Taint | str | None
    ) -> dict:
        payload: dict[str, object] = {
            "session_id": ctx.session_id,
            "caller": ctx.caller,  # read off the token, not tracked alongside it
            "target": target,
            "data_class": data_class,
            # Phase 5. The in-process client is in the call path and decides every hop,
            # so it reports `full`. Mandatory on the request with no default, so this
            # cannot be forgotten silently.
            "guarantee": self._guarantee.value,
        }
        if taint is not None:
            payload["taint"] = taint.value if isinstance(taint, Taint) else taint

        try:
            response = await self._client.post(
                f"{self._base_url}/v1/authorize",
                headers=ctx.headers(),
                json=payload,
                timeout=self._timeout,
            )
        except httpx.HTTPError as exc:
            raise ControlPlaneUnavailable(f"decision service unreachable: {exc}") from exc

        if response.status_code != 200:
            raise ControlPlaneUnavailable(
                f"decision service returned {response.status_code}: {response.text}"
            )
        try:
            decision = response.json()
            decision["outcome"]
        except (ValueError, KeyError, TypeError) as exc:
            raise ControlPlaneUnavailable(
                f"decision service returned an unusable body: {exc}"
            ) from exc
        return decision

    async def _exchange(
        self,
        ctx: HopContext,
        *,
        target: str,
        data_class: str,
        taint: Taint | str | None,
        action_id: str,
    ) -> Grant:
        form: dict[str, str] = {
            "grant_type": GRANT_TYPE,
            "subject_token": ctx.token,
            "subject_token_type": JWT_TOKEN_TYPE,
            "resource": target,
            "scope": data_class,
            # The recorded allow this exchange spends; the token service refuses without it.
            "action_id": action_id,
        }
        if taint is not None:
            form["taint"] = taint.value if isinstance(taint, Taint) else str(taint)
        if self._identity_key is not None and self._agent_name is not None:
            # Proof of possession.
            form["actor_token"] = self._identity_key.actor_token(self._agent_name, ctx.token)
            form["actor_token_type"] = JWT_TOKEN_TYPE

        try:
            response = await self._client.post(
                f"{self._base_url}/v1/token/exchange", data=form, timeout=self._timeout
            )
        except httpx.HTTPError as exc:
            raise ControlPlaneUnavailable(f"token service unreachable: {exc}") from exc

        if response.status_code == 403:
            body = response.json()
            # The exchange re-decides, so it can refuse an allow the decision endpoint had
            # just granted — and it is the only place that establishes AGENT_NOT_ENROLLED,
            # since proof of possession is checked here. Take the reason it reports; fall
            # back to OUT_OF_SCOPE only when there is none to take.
            raise PolicyDenied(
                _deny_reason(body.get("reason")),
                message=body.get("error_description", "denied by policy"),
                target=target,
                hop=ctx.hop,
                session_id=ctx.session_id,
            )
        if response.status_code != 200:
            raise ControlPlaneUnavailable(
                f"token service returned {response.status_code}: {response.text}"
            )

        body = response.json()
        token = body.get("access_token")
        if not token:
            raise ControlPlaneUnavailable("token service returned no usable token")

        return Grant(
            access_token=token,
            scope=body.get("scope", data_class),
            expires_in=body.get("expires_in", 0),
            hop=ctx.hop + 1,
            target=target,
            taint=_token_taint(token),
            action_id=action_id,
        )

    async def _mint_transaction(self, grant: Grant, params: dict[str, Any]) -> Grant:
        """``POST /v1/token/transaction`` with the narrowed token."""
        try:
            response = await self._client.post(
                f"{self._base_url}/v1/token/transaction",
                headers={"Authorization": f"Bearer {grant.access_token}"},
                json={"params": params},
                timeout=self._timeout,
            )
        except httpx.HTTPError as exc:
            raise ControlPlaneUnavailable(f"transaction service unreachable: {exc}") from exc
        if response.status_code in (403, 409, 422):
            body = response.json().get("error", {})
            details = body.get("details") or {}
            reason = details.get("reason")
            deny_reason = (
                DenyReason(reason)
                if isinstance(reason, str) and reason in DenyReason.__members__
                else DenyReason.OUT_OF_SCOPE
            )
            raise PolicyDenied(
                deny_reason,
                message=body.get("message", "transaction token refused"),
                target=grant.target,
                hop=grant.hop,
                session_id="",
            )
        if response.status_code != 200:
            raise ControlPlaneUnavailable(
                f"transaction service returned {response.status_code}: {response.text}"
            )
        token = response.json().get("transaction_token")
        if not token:
            raise ControlPlaneUnavailable("transaction service returned no usable token")
        return Grant(**{**grant.__dict__, "transaction_token": token})

    async def call(self, grant: Grant, method: str, url: str, **kwargs: Any) -> httpx.Response:
        """Make the call the grant authorizes, with every header the resource needs."""
        headers = {**kwargs.pop("headers", {}), **grant.headers()}
        return await self._client.request(
            method, url, headers=headers, timeout=self._timeout, **kwargs
        )

    async def hop(
        self,
        ctx: HopContext,
        *,
        target: str,
        data_class: str,
        taint: Taint | str | None = None,
    ) -> tuple[Grant, HopContext]:
        """``authorize`` plus the context for whoever receives the delegation."""
        grant = await self.authorize(ctx, target=target, data_class=data_class, taint=taint)
        return grant, ctx.advanced(grant.access_token)

    async def run_chain(
        self, ctx: HopContext, plan: Sequence[tuple[str, str]]
    ) -> tuple[list[Grant], PartialOutcome | None]:
        """Walk a plan of ``(target, data_class)`` hops, stopping at the first refusal.

        Returns the grants that succeeded and, when something was refused, a
        :class:`PartialOutcome` naming what completed and where it stopped — rather than
        raising and discarding the history.

        The caller decides what to do next. If the outcome is recoverable it carries a
        challenge; if it is not, the task is over and the caller still knows exactly
        which hops took effect.
        """
        grants: list[Grant] = []
        completed: list[CompletedHop] = []
        current = ctx
        for target, data_class in plan:
            try:
                grant = await self.authorize(current, target=target, data_class=data_class)
            except PolicyDenied as denied:
                return grants, PartialOutcome.from_denial(completed, denied)
            grants.append(grant)
            completed.append(CompletedHop(hop=grant.hop, target=target, action_id=None))
            current = current.advanced(grant.access_token)
        return grants, None

    # -- step-up consent ---------------------------------------------

    async def step_up(self, denied: PolicyDenied) -> dict[str, Any]:
        """Raise a challenge for a refusal that carries one.

        Almost always unnecessary: a recoverable refusal already arrives with its
        challenge attached, so ``denied.challenge`` is the normal path. This exists for
        the case where the refusal was recorded earlier — an operator working through an
        audit trail, say — and only the action id is to hand.
        """
        if denied.action_id is None:
            raise ValueError("that refusal was never recorded; there is nothing to step up from")
        response = await self._client.post(
            f"{self._base_url}/v1/consent/step-up",
            headers=self._admin_headers(),
            json={
                "session_id": denied.session_id,
                "blocked_action_id": denied.action_id,
            },
            timeout=self._timeout,
        )
        if response.status_code != 201:
            raise ControlPlaneUnavailable(
                f"step-up challenge failed with {response.status_code}: {response.text}"
            )
        return response.json()

    async def approve(
        self, challenge: dict[str, Any], *, credential: str, approved: bool = True
    ) -> dict[str, Any]:
        """Answer a challenge as the consenting human.

        ``credential`` is the **human's**, not the agent's: the control plane refuses the
        session's own grant here, because an agent that could approve its own widening
        would make the whole flow decorative. The SDK does not hold this
        credential and does not try to — it is passed in by whatever channel the
        integrator uses to reach the person.
        """
        response = await self._client.post(
            f"{self._base_url}/v1/consent/step-up/complete",
            headers={"Authorization": f"Bearer {credential}"},
            json={"challenge_id": challenge["challenge_id"], "approved": approved},
            timeout=self._timeout,
        )
        if response.status_code != 200:
            raise ControlPlaneUnavailable(
                f"step-up completion failed with {response.status_code}: {response.text}"
            )
        return response.json()

    async def resume(
        self, ctx: HopContext, denied: PolicyDenied, *, taint: Taint | str | None = None
    ) -> Grant:
        """Re-attempt the hop that was blocked, after a human approved the widening.

        Re-attempting with the same context works because **a refused hop performs no
        exchange**, so the presented token was never spent: Phase 4 moved the single-use
        guard to ``spent:{action_id}``, and a refusal has no allow decision to spend.
        The delegation record is therefore the original one and the hop budget continues
        from where it was, which is the point.
        """
        if denied.data_class is None:
            raise ValueError("that refusal did not record a data class to resume with")
        return await self.authorize(
            ctx, target=denied.target, data_class=denied.data_class, taint=taint
        )


def _deny_reason(raw: object) -> DenyReason:
    """The reported reason, or ``OUT_OF_SCOPE`` when a refusal names none."""
    if isinstance(raw, str):
        try:
            return DenyReason(raw)
        except ValueError:
            return DenyReason.OUT_OF_SCOPE
    return DenyReason.OUT_OF_SCOPE


def _max_taint(*labels: Taint | str | None) -> Taint | None:
    """The highest label present; ``None`` when none is. Additive only."""
    present = [Taint(label) if isinstance(label, str) else label for label in labels if label]
    if not present:
        return None
    return (
        Taint.UNTRUSTED_EXTERNAL if Taint.UNTRUSTED_EXTERNAL in present else Taint.TRUSTED_INTERNAL
    )


def _token_taint(token: str) -> Taint | None:
    from app.sdk.context import _claims

    raw = _claims(token).get("taint")
    try:
        return Taint(raw) if raw else None
    except ValueError:
        return None


__all__ = [
    "AgenticAuthClient",
    # Re-exported so `from app.sdk.client import PolicyDenied` keeps working; they are
    # defined in app.sdk.errors, which the planes raise from too.
    "ControlPlaneRejected",
    "ControlPlaneUnavailable",
    "Grant",
    "ManifestRejected",
    "PolicyDenied",
    "Session",
    "TransactionParamsRequired",
]
