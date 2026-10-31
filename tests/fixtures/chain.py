"""The single conformance chain — one fixture, five enforcement points (FR-043, SC-001).

The claim Phase 5 has to defend is that gateway, sidecar and boundary adapters are *one
policy* deployed several ways, not three policies that happen to agree today. This file is
what makes that claim falsifiable: one chain, covering every decision shape the phases so
far produce, driven through every enforcement point and compared hop by hop.

See ``docs/contracts/conformance.md`` §1 for the
table this implements, and §4 for the two documented exceptions.

Built on the bank scenario (``tests/fixtures/bank.py``) rather than inventing a parallel
world, so every tool ref points at a host the fake discovery source advertises and every
manifest reconciles cleanly.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from agentic_auth.schemas.authorize import DenyReason
from tests.fixtures.bank import (
    BALANCE_AGENT,
    BANK_ASSISTANT,
    KB_SEARCH_TOOL,
    READ_BALANCE,
    SUPPORT_AGENT,
    TERMINATE_ACCOUNT,
    USER,
    bank_docs,
)
from tests.fixtures.chains import manifest_doc

# An agent that exists, is a declared delegate, and is then revoked — hop 5.
BILLING_AGENT = "billing-agent"
READ_INVOICES = "mcp://ledger.internal/read_ledger"

# Declared by support-agent and deliberately left out of what the session consents to —
# hop 6. Only a distinct case once consent has granularity below the scope
# (research.md R5); with granularity off, hop 6 cannot occur at all.
AUDIT_CLASS = "account.read"
# Declared by nobody — hop 7.
UNDECLARED_CLASS = "nonsense.class"

# What a session consents to when granularity is on. Deliberately omits AUDIT_CLASS.
CONSENTED_CLASSES = ["kb.internal", "account.write"]


@dataclass(frozen=True)
class Hop:
    """One hop and the answer every enforcement point must give for it.

    ``reason`` is the exact ``DenyReason``, not merely "a refusal": a suite that only
    compared allow/deny would pass while two enforcement points disagreed about *why*,
    which is most of what an operator reads.
    """

    name: str
    caller: str
    target: str
    data_class: str
    outcome: str
    reason: DenyReason | None = None
    recoverable: bool = False
    # Hops the resource-side guard can meaningfully judge from headers alone, and the
    # narrower reason it gives when it refuses. See conformance.md §4.1.
    guard_reason: str | None = None
    # Set on the hop that makes the context untrusted, so a driver knows the ordering
    # matters and cannot reorder the chain without noticing.
    taints: bool = False
    params: dict[str, Any] | None = None


def chain(*, consent_granularity: bool) -> list[Hop]:
    """The seven hops, in order. Order is load-bearing: hop 2 taints the context that
    hop 4 is refused for, so a driver must not reorder or skip.

    ``consent_granularity`` selects the regime. With it off, hop 6 cannot occur at all
    (there is no consented subset to be outside of) and hop 7 answers
    ``SCOPE_NOT_CONSENTED``, which is exactly Phase 2-4 behaviour. With it on, the two
    separate: hop 6 is the recoverable one, hop 7 is not (research.md R5).
    """
    support = f"agent://{SUPPORT_AGENT}"
    hops = [
        Hop(
            name="1-delegate-to-balance",
            caller=USER,
            target=f"agent://{BALANCE_AGENT}",
            data_class="account.read",
            outcome="allow",
        ),
        Hop(
            name="2-delegate-to-support",
            caller=f"agent://{BALANCE_AGENT}",
            target=support,
            data_class="kb.internal",
            outcome="allow",
        ),
        Hop(
            name="3-read-untrusted-kb",
            caller=support,
            target=KB_SEARCH_TOOL,
            data_class="kb.internal",
            outcome="allow",
            taints=True,
        ),
        Hop(
            name="4-privileged-while-tainted",
            caller=support,
            target=TERMINATE_ACCOUNT,
            data_class="account.write",
            outcome="deny",
            reason=DenyReason.TAINTED_INTO_PRIVILEGED,
            # conformance.md §4.1: the control plane never minted a transaction token for
            # a refused hop, so the privileged call reaches the guard without one. Same
            # outcome, narrower reason — correct, not a divergence.
            guard_reason="TXN_MISSING",
            params={"account_id": "acc-42"},
        ),
        Hop(
            name="5-delegate-to-revoked",
            caller=support,
            target=f"agent://{BILLING_AGENT}",
            data_class="ledger.read",
            outcome="deny",
            reason=DenyReason.AGENT_REVOKED,
        ),
    ]

    if consent_granularity:
        hops.append(
            Hop(
                name="6-declared-not-consented",
                caller=support,
                target=READ_BALANCE,
                data_class=AUDIT_CLASS,
                outcome="deny",
                reason=DenyReason.SCOPE_NOT_CONSENTED,
                recoverable=True,
            )
        )
    hops.append(
        Hop(
            name="7-undeclared-data-class",
            caller=support,
            target=READ_BALANCE,
            data_class=UNDECLARED_CLASS,
            outcome="deny",
            # The whole point of the split: undeclared is not recoverable, and with
            # granularity on it stops borrowing the name of the reason that is.
            reason=(
                DenyReason.OUT_OF_SCOPE if consent_granularity else DenyReason.SCOPE_NOT_CONSENTED
            ),
            recoverable=not consent_granularity,
            guard_reason="GRANT_AUDIENCE",
        )
    )
    return hops


def chain_docs() -> dict[str, dict[str, Any]]:
    """Manifests for the chain: the bank scenario, plus what the extra hops need.

    Two additions on top of ``bank_docs(widened=True)``:

    - ``billing-agent``, a *declared* delegate of support-agent. Hop 5 must be refused for
      ``AGENT_REVOKED`` specifically, so the edge has to be legal — otherwise the refusal
      would be ``EDGE_NOT_IN_DAG`` and the test would pass for the wrong reason.
    - ``account.audit`` on support-agent's reads, so hop 6 is a class the policy declares
      and the session did not consent to. Without it, hop 6 and hop 7 are the same case.
    """
    docs = bank_docs(widened=True)

    docs[BILLING_AGENT] = manifest_doc(
        BILLING_AGENT,
        hop_budget=4,
        tools=[{"ref": READ_INVOICES, "data_classes": ["ledger.read"], "privileged": False}],
    )
    support = docs[SUPPORT_AGENT]["spec"]
    support["downstream_agents"] = [
        *support.get("downstream_agents", []),
        {"ref": f"agent://{BILLING_AGENT}", "max_hop_depth": 4},
    ]
    # Hop 6 targets read_balance, so support-agent must declare the tool as well as the
    # class — otherwise the refusal names the tool and the data-class check never runs.
    #
    # Only classes the discovery source actually advertises: reconciliation (Phase 1)
    # refuses a manifest that declares more than is discoverable, and rightly so. That
    # is why "declared but not consented" is expressed through the SESSION's consented
    # subset rather than by inventing a class — which is the distinction Phase 5
    # introduces in the first place.
    support["tools"] = [
        *support["tools"],
        {"ref": READ_BALANCE, "data_classes": ["account.read"], "privileged": False},
    ]
    support["data_classes"]["reads"] = sorted(
        {*support["data_classes"].get("reads", []), "account.read", "ledger.read"}
    )
    return docs


ROOT_SCOPE = BANK_ASSISTANT
REVOKED_AGENT = BILLING_AGENT

__all__ = [
    "AUDIT_CLASS",
    "BILLING_AGENT",
    "CONSENTED_CLASSES",
    "Hop",
    "REVOKED_AGENT",
    "ROOT_SCOPE",
    "UNDECLARED_CLASS",
    "chain",
    "chain_docs",
]
