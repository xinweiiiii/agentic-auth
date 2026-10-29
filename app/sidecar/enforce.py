"""The single allow path.

Everything in this module exists to make one property structurally true: **forwarding is
reachable from exactly one place, guarded by one object.** ``enforce()`` returns either an
:class:`Allow` carrying a freshly issued token, or a :class:`Blocked` carrying a response
for the agent. There is no third outcome, no default-allow branch, and no ``except`` that
continues toward the forward path.

Every outcome also carries an :class:`EdgeAttribution` — what this call was, for edge
recording. It is data, computed here and consumed by ``app.py`` after the outcome is fixed;
nothing in this module performs the recording, and nothing about it can change an outcome.

Rules for anyone editing this file:

- No bare ``except`` that falls through to a forward.
- No ``except: pass``.
- Every outbound call carries an explicit timeout. No unbounded wait.
- If you add a return, it returns ``Blocked`` unless you can prove the hop was allowed.
"""

from __future__ import annotations

import base64
import binascii
import json
import logging
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from typing import Protocol

import httpx
from starlette.responses import JSONResponse

from app import observability
from app.observability.pep import StageTimer
from app.schemas.authorize import POLICY_REASONS, DenyReason
from app.schemas.token import GRANT_TYPE, JWT_TOKEN_TYPE
from app.sidecar import deny
from app.sidecar.config import SidecarConfig, Upstream


class EnforcementConfig(Protocol):
    """Everything ``enforce()`` reads off its config.

    Declared as a Protocol so the gateway can pass a :class:`~app.gateway.config.GatewayConfig`
    — which is deliberately *not* a ``SidecarConfig``, because it must not have a signing
    key — without either module importing the other.
    """

    pdp_url: str
    observe_mode: bool
    guarantee_level: str
    max_privileged_body_bytes: int

    @property
    def control_plane_timeout_seconds(self) -> float: ...


logger = logging.getLogger(__name__)

TARGET_HEADER = "x-agentic-target"
DATA_CLASS_HEADER = "x-agentic-data-class"
TAINT_HEADER = "x-agentic-taint"
SESSION_HEADER = "x-agentic-session"


@dataclass(frozen=True)
class EdgeAttribution:
    """What this call was, for edge recording.

    ``outcome`` is one of ``allow``, ``deny`` (policy refused), ``observed`` (policy
    refused, observe mode forwarded), ``blocked_infra`` (a dependency failed), or
    ``blocked_local`` (refused before any decision). ``acting_agent`` comes only from the
    decision service's verified answer — never from the presented token's unverified claims.
    """

    acting_agent: str | None
    target: str | None
    outcome: str
    reason: str | None


@dataclass(frozen=True)
class Allow:
    """The only success. Holding one means the PDP allowed this hop and a narrowed token
    was issued for it — and, for a privileged target, a transaction token bound to the
    buffered body."""

    token: str
    upstream: Upstream
    prefix: str
    target: str
    attribution: EdgeAttribution
    # Phase 4. Present together for a privileged call: the body was buffered to bind it.
    transaction_token: str | None = None
    body: bytes | None = None
    # Phase 4 identity: the Agent-Identity assertion for this call, when a key is configured.
    identity_assertion: str | None = None


@dataclass(frozen=True)
class Blocked:
    """Everything else. ``response`` goes straight back to the agent."""

    response: JSONResponse
    attribution: EdgeAttribution


@dataclass(frozen=True)
class Observed:
    """Observe mode only: policy said no, but the operator asked to watch rather than
    block. The ORIGINAL token is forwarded — no exchange happened for a denied hop."""

    upstream: Upstream
    prefix: str
    target: str
    reason: DenyReason
    attribution: EdgeAttribution


def _local(response: JSONResponse, target: str | None, reason: str) -> Blocked:
    return Blocked(response, EdgeAttribution(None, target, "blocked_local", reason))


def _infra(
    response: JSONResponse, acting_agent: str | None, target: str, reason: DenyReason
) -> Blocked:
    return Blocked(response, EdgeAttribution(acting_agent, target, "blocked_infra", reason.value))


def _infra_local(response: JSONResponse, acting_agent: str | None, target: str) -> Blocked:
    """An infrastructure block whose reason is a sidecar-local code, not a DenyReason."""
    return Blocked(
        response, EdgeAttribution(acting_agent, target, "blocked_infra", _reason_of(response))
    )


def _reason_of(response: JSONResponse) -> str:
    try:
        return str(json.loads(bytes(response.body))["error"]["details"]["reason"])
    except (ValueError, KeyError, TypeError):
        return "BLOCKED"


def _acting_agent(decision: Mapping[str, object]) -> str | None:
    value = decision.get("acting_agent")
    return value if isinstance(value, str) and value else None


def _unverified_claims(token: str) -> dict:
    """Read claims WITHOUT verifying — only ever to populate a request the PDP then
    checks authoritatively.

    This is safe precisely because it is not a decision: the PDP verifies the signature
    and denies any request whose ``session_id`` or ``caller`` disagrees with the token.
    A lie here buys a deny, never an allow. Using these values to decide anything locally
    would be a different and much worse thing.
    """
    try:
        payload = token.split(".")[1]
        return json.loads(base64.urlsafe_b64decode(payload + "=="))
    except (IndexError, ValueError, binascii.Error, UnicodeDecodeError):
        return {}


def _deny_reason(raw: object) -> DenyReason:
    """A reason we do not recognise is not a policy verdict anyone can predict from. Treat
    it as the decision service being unusable, which blocks in every mode — never as a
    policy reason observe mode would forward."""
    if not isinstance(raw, str):
        return DenyReason.PDP_UNAVAILABLE
    try:
        return DenyReason(raw)
    except ValueError:
        return DenyReason.PDP_UNAVAILABLE


def _has_traversal(path: str) -> bool:
    """True if the path contains anything that would make the matched prefix a lie.

    The prefix selects which policy target the call is authorized against; the same
    prefix is then stripped to build the upstream URL. If `httpx.URL` resolves a dot
    segment after that match, the two disagree — `/kb/../admin` is authorized as the
    `/kb` target and delivered to `/admin`. Reject rather than normalise: normalising
    would silently change which prefix matched, which is the same class of surprise.

    uvicorn percent-decodes before handing over `scope["path"]`, so `%2e%2e` arrives
    here already as `..` and is caught by the same check.
    """
    return "\\" in path or any(seg in ("..", ".") for seg in path.split("/"))


def _resolve_call(
    config: SidecarConfig, path: str, headers: Mapping[str, str]
) -> tuple[str, Upstream, str, str] | JSONResponse:
    if _has_traversal(path):
        return deny.not_mapped(path)
    match = config.resolve(path)
    if match is None:
        return deny.not_mapped(path)
    prefix, upstream = match

    target = upstream.target or headers.get(TARGET_HEADER)
    data_class = upstream.data_class or headers.get(DATA_CLASS_HEADER)
    if not target or not data_class:
        return deny.target_unresolved(path)
    return prefix, upstream, target, data_class


BodyReader = Callable[[int], Awaitable[bytes | None]]
"""Reads the request body up to a byte cap; returns ``None`` when the cap is exceeded."""


async def _no_body(_cap: int) -> bytes | None:
    return b""


ResolvedCall = tuple[str, Upstream, str, str]
"""``(prefix, upstream, target, data_class)`` — a route that has already been matched."""


async def enforce(
    client: httpx.AsyncClient,
    config: SidecarConfig | EnforcementConfig,
    *,
    path: str,
    headers: Mapping[str, str],
    body_reader: BodyReader = _no_body,
    identity: object | None = None,
    actor_token: str | None = None,
    resolved: ResolvedCall | JSONResponse | None = None,
    timer: StageTimer | None = None,
) -> Allow | Blocked | Observed:
    """Decide, narrow, and hand back the token to forward — or block.

    **This function has two callers**: the sidecar (:mod:`app.sidecar.app`) and the shared
    gateway (:mod:`app.gateway.app`). That is deliberate and is what makes "the gateway
    reaches the same decision as the sidecar" a structural property rather than a hope —
    there is one ``enforce()``, so the two can only diverge by disagreeing about their
    *inputs*, which the conformance suite exists to catch. Any change here must keep both
    callers working.

    ``body_reader`` is only ever called for a privileged target, so ordinary
    calls keep streaming. ``identity`` is an :class:`app.sidecar.identity.SidecarIdentity`
    or ``None``; typed loosely to keep this module free of the key-handling imports.

    ``actor_token`` is the gateway's path to proof-of-possession: it holds no signing key,
    so instead of minting an actor token it relays the one the agent
    supplied. Used only when ``identity`` is ``None``, so a sidecar with a key always
    signs its own rather than trusting a header.

    ``resolved`` lets a caller supply an already-matched route. The sidecar omits it and
    resolves from its own single-agent ``upstream_map``; the gateway passes the result of
    its shared, agent-keyed table.

    ``timer`` records per-stage latency. It defaults to a timer with no
    metrics attached, so every call site works unchanged and no branch is needed below.
    """
    timer = timer if timer is not None else StageTimer(None)
    if resolved is None:
        resolved = _resolve_call(config, path, headers)
    if isinstance(resolved, JSONResponse):
        return _local(resolved, None, _reason_of(resolved))
    prefix, upstream, target, data_class = resolved

    authorization = headers.get("authorization", "")
    if not authorization.startswith("Bearer "):
        return _local(
            deny.unauthorized("missing or malformed bearer token"), target, "UNAUTHORIZED"
        )
    presented = authorization.removeprefix("Bearer ").strip()

    claims = _unverified_claims(presented)
    session_id = headers.get(SESSION_HEADER) or claims.get("session_id")
    # Who holds this token: the agent it was issued to (`aud`) once delegation has
    # begun, or the consenting human (`sub`) under the root grant. Never the `act`
    # link — that is the previous actor, not the current one.
    caller = claims.get("aud") if claims.get("act") else claims.get("sub")
    if not session_id or not caller:
        return _local(
            deny.unauthorized("token does not carry a session or a subject"), target, "UNAUTHORIZED"
        )

    taint = headers.get(TAINT_HEADER)
    timeout = httpx.Timeout(config.control_plane_timeout_seconds)

    # -- 1. decide --------------------------------------------------------
    try:
        with timer.stage("decide"):
            decision_response = await client.post(
                f"{config.pdp_url}/v1/authorize",
                # Every leg the SDK controls carries trace context, so the control
                # plane's decision span lands in the same trace as this proxied call.
                headers=observability.inject({"Authorization": f"Bearer {presented}"}),
                json={
                    "session_id": session_id,
                    "caller": caller,
                    "target": target,
                    "data_class": data_class,
                    # Tell the PDP whether this decision will actually be acted on, so the
                    # record is truthful. It does not affect the decision.
                    "enforced": not config.observe_mode,
                    # Phase 5. Same contract as `enforced`: self-reported by the enforcement
                    # point, recorded, never an input to the decision. Mandatory with no
                    # default on the request, so omitting it is a 422 rather than a silent
                    # claim of full guarantee.
                    "guarantee": config.guarantee_level,
                    **({"taint": taint} if taint else {}),
                },
                timeout=timeout,
            )
    except Exception as exc:
        logger.warning(
            "policy decision point unreachable",
            extra={"authz.component": "pep", "error.type": type(exc).__name__},
        )
        return _infra(
            deny.policy_denied(
                DenyReason.PDP_UNAVAILABLE,
                f"decision service unreachable: {exc}",
                target=target,
            ),
            None,
            target,
            DenyReason.PDP_UNAVAILABLE,
        )

    if decision_response.status_code == 401:
        return _local(
            deny.unauthorized("presented token was rejected by the decision service"),
            target,
            "UNAUTHORIZED",
        )
    if decision_response.status_code != 200:
        return _infra(
            deny.policy_denied(
                DenyReason.PDP_UNAVAILABLE,
                f"decision service returned {decision_response.status_code}",
                target=target,
            ),
            None,
            target,
            DenyReason.PDP_UNAVAILABLE,
        )

    try:
        decision = decision_response.json()
        outcome = decision["outcome"]
    except (ValueError, KeyError, TypeError) as exc:
        return _infra(
            deny.policy_denied(
                DenyReason.PDP_UNAVAILABLE,
                f"decision service returned an unusable body: {exc}",
                target=target,
            ),
            None,
            target,
            DenyReason.PDP_UNAVAILABLE,
        )

    acting_agent = _acting_agent(decision)

    if outcome != "allow":
        reason = _deny_reason(decision.get("reason"))
        if config.observe_mode and reason in POLICY_REASONS:
            # Recorded by the PDP, not blocked here. The call proceeds carrying its
            # ORIGINAL token, because no exchange happened for a denied hop.
            logger.info(
                "observe mode: would have denied this call",
                extra={
                    "authz.component": "pep",
                    "authz.hop": decision.get("hop"),
                    "authz.action_id": decision.get("action_id"),
                },
            )
            return Observed(
                upstream=upstream,
                prefix=prefix,
                target=target,
                reason=reason,
                attribution=EdgeAttribution(acting_agent, target, "observed", reason.value),
            )
        # Observe mode predicts what POLICY would block. It never forwards an infrastructure
        # failure — that would pass an outage off as a prediction.
        response = deny.policy_denied(
            reason,
            decision.get("message") or "denied by policy",
            target=target,
            hop=decision.get("hop"),
            session_id=decision.get("session_id"),
            policy_version=decision.get("policy_version"),
        )
        if reason in POLICY_REASONS:
            return Blocked(response, EdgeAttribution(acting_agent, target, "deny", reason.value))
        return _infra(response, acting_agent, target, reason)

    # The PDP committed a record before answering, and the exchange refuses without one.
    # Checking here as well means a control plane that answers "allow" without a recorded
    # decision still cannot get a call dispatched down this path.
    action_id = decision.get("action_id")
    if decision.get("recorded") is False or not action_id:
        return _infra(
            deny.policy_denied(
                DenyReason.AUDIT_UNAVAILABLE,
                "decision could not be recorded; refusing to dispatch without a record",
                target=target,
            ),
            acting_agent,
            target,
            DenyReason.AUDIT_UNAVAILABLE,
        )

    # -- 1b. a privileged call must be bound: buffer the body, or refuse ----------
    transaction_required = bool(decision.get("transaction_required"))
    bound_body: bytes | None = None
    params: dict | None = None
    if transaction_required:
        bound_body = await body_reader(config.max_privileged_body_bytes)
        if bound_body is None:
            return _local(
                deny.unbindable(
                    deny.BODY_TOO_LARGE_TO_BIND,
                    f"body exceeds {config.max_privileged_body_bytes} bytes and cannot be bound",
                    target=target,
                ),
                target,
                deny.BODY_TOO_LARGE_TO_BIND,
            )
        try:
            parsed = json.loads(bound_body or b"{}")
        except ValueError:
            parsed = None
        if not isinstance(parsed, dict):
            return _local(
                deny.unbindable(
                    deny.PARAMS_NOT_AN_OBJECT,
                    "a privileged call's body must be a JSON object so it can be bound",
                    target=target,
                ),
                target,
                deny.PARAMS_NOT_AN_OBJECT,
            )
        params = parsed

    # -- 2. narrow --------------------------------------------------------
    exchange_form: dict[str, str] = {
        "grant_type": GRANT_TYPE,
        "subject_token": presented,
        "subject_token_type": JWT_TOKEN_TYPE,
        "resource": target,
        "scope": data_class,
        "action_id": str(action_id),
        **({"taint": taint} if taint else {}),
    }
    if identity is not None:
        exchange_form["actor_token"] = identity.actor_token(presented)  # type: ignore[attr-defined]
        exchange_form["actor_token_type"] = JWT_TOKEN_TYPE
    elif actor_token:
        # Relayed, not minted. The gateway cannot sign for an agent it does not hold a
        # key for, and holding every agent's key is the thing the identity split forbids.
        exchange_form["actor_token"] = actor_token
        exchange_form["actor_token_type"] = JWT_TOKEN_TYPE
    try:
        with timer.stage("exchange"):
            exchange_response = await client.post(
                f"{config.pdp_url}/v1/token/exchange",
                data=exchange_form,
                headers=observability.inject({}),
                timeout=timeout,
            )
    except Exception as exc:
        logger.warning(
            "token exchange unreachable",
            extra={"authz.component": "pep", "error.type": type(exc).__name__},
        )
        return _infra(
            deny.policy_denied(
                DenyReason.TOKEN_SERVICE_UNAVAILABLE,
                f"token service unreachable: {exc}",
                target=target,
            ),
            acting_agent,
            target,
            DenyReason.TOKEN_SERVICE_UNAVAILABLE,
        )

    if exchange_response.status_code != 200:
        # Distinguish "the service is down" from "the service said no". Both block, but
        # they send an operator to different places: one is an outage, the other is a
        # spent or refused token that no amount of retrying will fix.
        description = ""
        try:
            body = exchange_response.json()
            description = body.get("error_description") or body.get("error") or ""
        except ValueError:
            description = ""

        if exchange_response.status_code == 403:
            # Policy refused the hop between the decision and the exchange — normally a
            # narrower re-check, e.g. the resource did not match the allowed target.
            return Blocked(
                deny.policy_denied(
                    DenyReason.OUT_OF_SCOPE,
                    description or "token service refused this target",
                    target=target,
                ),
                EdgeAttribution(acting_agent, target, "deny", DenyReason.OUT_OF_SCOPE.value),
            )
        if exchange_response.status_code == 400:
            # The presented token itself was refused: already spent, expired, or altered.
            return _local(
                deny.unauthorized(
                    description or "presented token was refused by the token service"
                ),
                target,
                "UNAUTHORIZED",
            )
        return _infra(
            deny.policy_denied(
                DenyReason.TOKEN_SERVICE_UNAVAILABLE,
                f"token service returned {exchange_response.status_code}",
                target=target,
            ),
            acting_agent,
            target,
            DenyReason.TOKEN_SERVICE_UNAVAILABLE,
        )

    try:
        narrowed = exchange_response.json()["access_token"]
    except (ValueError, KeyError, TypeError) as exc:
        return _infra(
            deny.policy_denied(
                DenyReason.TOKEN_SERVICE_UNAVAILABLE,
                f"token service returned no usable token: {exc}",
                target=target,
            ),
            acting_agent,
            target,
            DenyReason.TOKEN_SERVICE_UNAVAILABLE,
        )
    if not narrowed:
        return _infra(
            deny.policy_denied(
                DenyReason.TOKEN_SERVICE_UNAVAILABLE,
                "token service returned an empty token",
                target=target,
            ),
            acting_agent,
            target,
            DenyReason.TOKEN_SERVICE_UNAVAILABLE,
        )

    # -- 3. bind (privileged only) -----------------------------------------
    transaction_token: str | None = None
    if transaction_required:
        assert params is not None  # set together with transaction_required above
        try:
            with timer.stage("mint"):
                mint_response = await client.post(
                    f"{config.pdp_url}/v1/token/transaction",
                    headers=observability.inject({"Authorization": f"Bearer {narrowed}"}),
                    json={"params": params},
                    timeout=timeout,
                )
        except Exception as exc:
            logger.warning(
                "transaction mint unreachable",
                extra={"authz.component": "pep", "error.type": type(exc).__name__},
            )
            return _infra_local(
                deny.transaction_unavailable(
                    f"transaction service unreachable: {exc}", target=target
                ),
                acting_agent,
                target,
            )
        if mint_response.status_code != 200:
            # 4xx: the mint refused (not privileged, already minted, tainted, too large) — a
            # policy-shaped refusal, 403. 5xx or unusable: an outage, 503.
            description = ""
            try:
                err = mint_response.json().get("error", {})
                description = err.get("message") or ""
                detail_reason = (err.get("details") or {}).get("reason")
            except ValueError:
                detail_reason = None
            if 400 <= mint_response.status_code < 500:
                return Blocked(
                    deny.policy_denied(
                        detail_reason or DenyReason.OUT_OF_SCOPE,
                        description or "transaction token refused",
                        target=target,
                    ),
                    EdgeAttribution(acting_agent, target, "deny", detail_reason or "OUT_OF_SCOPE"),
                )
            return _infra_local(
                deny.transaction_unavailable(
                    f"transaction service returned {mint_response.status_code}", target=target
                ),
                acting_agent,
                target,
            )
        try:
            transaction_token = mint_response.json()["transaction_token"]
        except (ValueError, KeyError, TypeError) as exc:
            return _infra_local(
                deny.transaction_unavailable(
                    f"transaction service returned no usable token: {exc}", target=target
                ),
                acting_agent,
                target,
            )
        if not transaction_token:
            return _infra_local(
                deny.transaction_unavailable(
                    "transaction service returned an empty token", target=target
                ),
                acting_agent,
                target,
            )

    identity_assertion = (
        identity.identity_assertion(narrowed, target)  # type: ignore[attr-defined]
        if identity is not None
        else None
    )

    # The only construction of Allow in the codebase.
    return Allow(
        token=narrowed,
        upstream=upstream,
        prefix=prefix,
        target=target,
        attribution=EdgeAttribution(acting_agent, target, "allow", None),
        transaction_token=transaction_token,
        body=bound_body,
        identity_assertion=identity_assertion,
    )
