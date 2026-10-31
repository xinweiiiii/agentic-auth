"""How strong the enforcement actually was — the one field that keeps a weak deployment
from reading as a strong one.

PRD §8.3 FR-14's last rung says a reduced-guarantee mode "MUST be surfaced explicitly …
rather than silently degrading". This module is that requirement, made into a type.

**Reported by the enforcement point, never derived here.** ``AuthorizeRequest.guarantee``
follows ``AuthorizeRequest.enforced`` exactly: the PEP self-reports, the control plane
records, and the PDP never sees it. The control plane genuinely cannot tell a sidecar from
a gateway from a connector proxy — they all present a hop token over HTTP — so inferring
the level would mean inventing a per-PEP credential for a field whose whole job is honesty
about a deployment choice.

A PEP could report the wrong level. That is not the threat this field addresses: an
attacker who controls the enforcement point has already won by a shorter route. The field
exists so an *honest* deployment cannot accidentally look stronger than it is, which is an
operator-error problem.

See https://authzai.dev/explanation/enforcement-point-tradeoffs.
"""

from __future__ import annotations

from enum import StrEnum


class Guarantee(StrEnum):
    """Strongest to weakest. The order of declaration is not the contract — ``STRENGTH``
    is — but keeping them aligned makes the file readable."""

    # Every hop decided before dispatch, authority narrowed per hop, privileged calls
    # bound to their parameters, every decision audited. The sidecar, the gateway with
    # verified identity, and the resource-side guard.
    FULL = "full"
    # Same per-hop decision, but only for calls that go through the agent's configured
    # tool connector. A call made by some other route is not seen.
    CONNECTOR = "connector"
    # Same per-hop decision applied to whatever leaves the agent's runtime. Depends on
    # trust material installed in a runtime the integrator does not fully own.
    NETWORK = "network"
    # Coarse scoping at grant time, revocation, and an audit record at the edge. There is
    # no per-hop decision at all.
    CONSENT_ONLY = "consent_only"


STRENGTH: dict[Guarantee, int] = {
    Guarantee.FULL: 3,
    Guarantee.CONNECTOR: 2,
    Guarantee.NETWORK: 1,
    Guarantee.CONSENT_ONLY: 0,
}

# Every level has a strength. A new member without one would silently sort as weakest,
# which is the wrong direction to fail for a field about honesty.
assert set(Guarantee) == set(STRENGTH), "every guarantee level needs a strength"


def strongest(*levels: Guarantee) -> Guarantee:
    """The strongest of the modes that **actually decided** this call.

    Two modes deciding one call is ordinary: a connector proxy in front of a tool that
    also carries a resource-side guard. The outcome is the stricter of the two — a refusal
    anywhere refuses — but the recorded level is the strongest, because the resource guard
    genuinely did verify identity, grant and, for a privileged target, the call binding.

    "Actually decided" excludes a mode that was configured but not consulted for this
    call; the caller is responsible for passing only the levels that produced a verdict.
    """
    if not levels:
        raise ValueError(
            "strongest() needs at least one level: a decision with no guarantee level "
            "must not be emitted"
        )
    return max(levels, key=lambda level: STRENGTH[level])


def weakest(*levels: Guarantee) -> Guarantee:
    """The weakest of several levels — used when reporting what a deployment as a whole
    can promise, as opposed to what one decision achieved."""
    if not levels:
        raise ValueError("weakest() needs at least one level")
    return min(levels, key=lambda level: STRENGTH[level])


def is_degrade(previous: Guarantee, current: Guarantee) -> bool:
    """True when the level in force has become weaker.

    A degrade is written as its own audit event, so it lands in the same timeline
    as the decisions around it rather than in a separate log an operator has to correlate.
    Starting weak is a configuration, not a degrade, so this is only ever asked when a
    previous level exists.
    """
    return STRENGTH[current] < STRENGTH[previous]


__all__ = ["Guarantee", "STRENGTH", "strongest", "weakest", "is_degrade"]
