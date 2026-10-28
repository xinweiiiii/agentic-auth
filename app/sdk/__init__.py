"""Agentic Authorization SDK — one import root for everything a customer writes against.

Four surfaces, in the order a team adopts them:

1. **The hop path** — :class:`AgenticAuthClient`. ``consent`` once per human intent, then
   ``authorize`` (decide and narrow, never one without the other) or ``hop`` (the same,
   plus the context the next agent receives) before every call, and ``call`` to make it
   with every header the resource needs.
2. **The planes around it** — ``client.admin`` registers manifests and reads compiled
   catalogs, ``client.audit`` reads decision history and delegation chains,
   ``client.identity`` reads pinned identity material and the revocation list. Each takes
   its own least-privileged bearer. See :mod:`app.sdk.planes`.
3. **The resource side** — :class:`Verifier` and its stores, for the owner of a tool or
   API that should admit only a call carrying a valid grant AND the calling agent's
   identity AND, for a privileged tool, a transaction token bound to that exact call.
   Offline after bootstrap. See :mod:`app.verify`.
4. **The CI gate** — :mod:`app.sdk.drift`: aggregate recorded edges and check them against
   the declared manifests, from files, with no credentials.

Propagation format, in full — two headers:

===========================  ==================================================
``Authorization``            ``Bearer <hop token>`` — carries ``act``, ``hop``,
                             ``policy_version`` inside a signed envelope
``X-Agentic-Session``        the session id, so the next hop can find its session
                             before parsing a token it has not yet verified
===========================  ==================================================

Nothing security-relevant travels in a header. A forged ``X-Agentic-Session`` that
disagrees with the token's own ``session_id`` is a deny.
"""

from app.schemas.authorize import DenyReason, Taint
from app.sdk.client import (
    AgenticAuthClient,
    CompletedHop,
    Grant,
    PartialOutcome,
    Session,
)
from app.sdk.context import SESSION_HEADER, HopContext
from app.sdk.errors import (
    ControlPlaneRejected,
    ControlPlaneUnavailable,
    ManifestRejected,
    PolicyDenied,
    TransactionParamsRequired,
)
from app.sdk.identity import AgentKey
from app.sdk.planes import (
    AdminPlane,
    AgentRegistration,
    AuditPlane,
    IdentityPlane,
    ManifestSubmission,
)
from app.sdk.provenance import LabeledResult, Provenance, SourceClassifier

# The resource side of the same product. Re-exported here so an integrator guarding a tool
# has one import root too; `app.verify` stays importable on its own, with pyjwt and nothing
# else, for a resource server that should not depend on the agent-side client.
from app.verify import (
    Admission,
    HttpAnchors,
    HttpJwks,
    InMemoryReplay,
    RedisReplay,
    StaticAnchors,
    StaticJwks,
    Verifier,
)

__all__ = [
    # -- hop path --------------------------------------------------------------
    "AgenticAuthClient",
    "HopContext",
    "Grant",
    "Session",
    "SESSION_HEADER",
    "AgentKey",
    "PartialOutcome",
    "CompletedHop",
    # -- decisions and refusals ------------------------------------------------
    "DenyReason",
    "Taint",
    "PolicyDenied",
    "ControlPlaneRejected",
    "ControlPlaneUnavailable",
    "ManifestRejected",
    "TransactionParamsRequired",
    # -- planes ----------------------------------------------------------------
    "AdminPlane",
    "AuditPlane",
    "IdentityPlane",
    "AgentRegistration",
    "ManifestSubmission",
    # -- provenance ------------------------------------------------------------
    "LabeledResult",
    "Provenance",
    "SourceClassifier",
    # -- resource side ---------------------------------------------------------
    "Admission",
    "HttpAnchors",
    "HttpJwks",
    "InMemoryReplay",
    "RedisReplay",
    "StaticAnchors",
    "StaticJwks",
    "Verifier",
]
