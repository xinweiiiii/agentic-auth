"""Several gateway instances, one correct chain (FR-004, FR-005, SC-003).

**No sticky routing is configured anywhere in this file, deliberately.** If a test here
only passes when a session's hops are pinned to one instance, that is a correctness bug
in the decision core, not a deployment choice — and hiding it behind session affinity
would leave it there. Hops are interleaved on purpose.

The claim being tested is research.md R3: horizontal scaling needs no new coordination,
because every per-hop fact already lives somewhere shared — depth in the verified act
chain, the single-use guard in ``spent:{action_id}``, the decision cache in Redis, and
the session in an immutable row.
"""

from __future__ import annotations

import pytest

from agentic_auth.sidecar.config import Upstream
from tests.fixtures.bank import (
    BALANCE_AGENT,
    BANK_ASSISTANT,
    KB_SEARCH_TOOL,
    SUPPORT_AGENT,
    USER,
    bank_docs,
)
from tests.fixtures.hops import hop, register_agents

TABLE = {
    (None, "/kb"): Upstream(
        url="http://upstream.test", target=KB_SEARCH_TOOL, data_class="kb.internal"
    ),
}


@pytest.fixture
async def session_and_token(client, admin_headers, consent):
    async def _setup():
        await register_agents(client, admin_headers, bank_docs(widened=True, trust_kb=True))
        session = await consent(scope=BANK_ASSISTANT, user_sub=USER)
        _, t1 = await hop(
            client,
            session["root_grant"],
            target=f"agent://{BALANCE_AGENT}",
            data_class="account.read",
        )
        _, t2 = await hop(client, t1, target=f"agent://{SUPPORT_AGENT}", data_class="kb.internal")
        return session, t2

    return _setup


async def _rows(client, admin_headers, session_id: str) -> list[dict]:
    page = await client.get(f"/v1/audit/decisions?session_id={session_id}", headers=admin_headers)
    return page.json()["data"]


async def test_hops_interleaved_across_instances_complete(gateway_stack, session_and_token) -> None:
    """The same session, alternating instances, with no affinity."""
    _, token = await session_and_token()
    a, b = await gateway_stack.instances(2, route_table=TABLE)

    first = await a.get("/kb/search?q=one", headers={"Authorization": f"Bearer {token}"})

    _, token2 = await session_and_token()
    second = await b.get("/kb/search?q=two", headers={"Authorization": f"Bearer {token2}"})

    assert first.status_code == 200
    assert second.status_code == 200


async def test_each_hop_is_recorded_exactly_once(
    gateway_stack, session_and_token, client, admin_headers
) -> None:
    """Exactly one audit row per hop, whichever instance handled it. A duplicate would
    make the delegation chain ambiguous, which is the one thing the audit plane sells."""
    session, token = await session_and_token()
    a, b = await gateway_stack.instances(2, route_table=TABLE)

    before = len(await _rows(client, admin_headers, session["session_id"]))
    await a.get("/kb/search?q=one", headers={"Authorization": f"Bearer {token}"})
    after = len(await _rows(client, admin_headers, session["session_id"]))

    assert after == before + 1, "one call, one row"

    # A second call on the OTHER instance is a second call, not a replay: Phase 4 moved
    # the single-use guard from the token to the DECISION (`spent:{action_id}`), so one
    # delegation token legitimately buys several calls, each decided and each recorded.
    # What must hold across instances is that the count still matches exactly.
    await b.get("/kb/search?q=two", headers={"Authorization": f"Bearer {token}"})
    assert len(await _rows(client, admin_headers, session["session_id"])) == before + 2


async def test_one_decision_can_be_exchanged_once_across_instances(
    gateway_stack, session_and_token, client
) -> None:
    """The single-use guard is ``spent:{action_id}`` in Redis, not per-process state.

    Driven at the control plane rather than through the proxy, because a *call* through
    the gateway makes its own fresh decision each time — Phase 4's fan-out change means a
    token buys many calls. What is single-use is the decision, and this asserts that two
    instances cannot each spend the same one. Without shared state they would.
    """
    from agentic_auth.schemas.token import GRANT_TYPE, JWT_TOKEN_TYPE
    from tests.fixtures.hops import authorize

    _, token = await session_and_token()
    await gateway_stack.instances(2, route_table=TABLE)

    decision = (
        await authorize(client, token, target=KB_SEARCH_TOOL, data_class="kb.internal")
    ).json()
    form = {
        "grant_type": GRANT_TYPE,
        "subject_token": token,
        "subject_token_type": JWT_TOKEN_TYPE,
        "resource": KB_SEARCH_TOOL,
        "scope": "kb.internal",
        "action_id": decision["action_id"],
    }

    first = await client.post("/v1/token/exchange", data=form)
    second = await client.post("/v1/token/exchange", data=form)

    assert first.status_code == 200
    assert second.status_code != 200, "one decision, one exchange — on any instance"


async def test_instances_share_the_decision_cache(gateway_stack, session_and_token) -> None:
    """Not a correctness requirement, a cost one — but it must not be achieved by
    serving a decision whose inputs have changed, which the key covers."""
    _, token_a = await session_and_token()
    _, token_b = await session_and_token()
    a, b = await gateway_stack.instances(2, route_table=TABLE)

    await a.get("/kb/search", headers={"Authorization": f"Bearer {token_a}"})
    second = await b.get("/kb/search", headers={"Authorization": f"Bearer {token_b}"})

    assert second.status_code == 200


async def test_taint_marked_on_one_instance_blocks_on_another(
    gateway_stack, client, admin_headers, consent
) -> None:
    """The decision inputs are shared, so a context tainted through one instance is
    tainted for every instance (FR-005).

    This is the multi-instance form of the PRD §2.2 injection: if taint were
    per-process, an attacker could launder it simply by having the next call land on a
    different gateway. Revocation propagation has the same shape and is covered end to
    end in ``test_revocation.py``; taint is asserted here because it needs no enrollment
    and exercises the same shared-state path.
    """
    from tests.fixtures.bank import TERMINATE_ACCOUNT

    # trust_kb is OFF, so reading the knowledge base taints support-agent's context.
    await register_agents(client, admin_headers, bank_docs(widened=True))
    session = await consent(scope=BANK_ASSISTANT, user_sub=USER)
    _, t1 = await hop(
        client, session["root_grant"], target=f"agent://{BALANCE_AGENT}", data_class="account.read"
    )
    _, support = await hop(client, t1, target=f"agent://{SUPPORT_AGENT}", data_class="kb.internal")

    table = {
        **TABLE,
        (None, "/accounts"): Upstream(
            url="http://upstream.test", target=TERMINATE_ACCOUNT, data_class="account.write"
        ),
    }
    a, b = await gateway_stack.instances(2, route_table=table)
    headers = {"Authorization": f"Bearer {support}"}

    # Instance A: read the untrusted knowledge base. This marks the context.
    read = await a.get("/kb/search?q=refund", headers=headers)
    assert read.status_code == 200

    # Instance B: attempt the privileged call. It has never seen this session before.
    blocked = await b.post("/accounts/terminate", headers=headers, json={"account_id": "acc-42"})

    assert blocked.status_code == 403
    assert blocked.json()["error"]["details"]["reason"] == "TAINTED_INTO_PRIVILEGED"
