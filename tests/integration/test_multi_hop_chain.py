"""A four-hop chain end to end.

Four hops, four distinct tokens, each naming one target, and the deepest still
resolving back through every intermediate agent to the consenting human.

Each hop decides and then exchanges against that recorded decision, which since Phase 3 is
the only way a narrowed token is issued.
"""

from __future__ import annotations

from tests.fixtures.chains import (
    KB_SEARCH,
    NOTIFIER,
    ORCHESTRATOR,
    SUMMARIZER,
    chain_docs,
    manifest_doc,
)
from tests.fixtures.hops import authorize, claims, exchange, hop

USER = "user:alice"

# The caller at each hop is whoever HOLDS the token — the agent it was issued to, not the
# agent that delegated it. `tests.fixtures.hops` reads it off the token.
CHAIN = [
    (f"agent://{KB_SEARCH}", "kb.internal"),
    (f"agent://{SUMMARIZER}", "account.read"),
    (f"agent://{NOTIFIER}", "account.write"),
]


async def test_four_hop_chain_narrows_at_every_hop(client, register_chain, consent) -> None:
    await register_chain()
    session = await consent()

    token = session["root_grant"]
    issued = [token]
    for target, data_class in CHAIN:
        decision, narrowed = await hop(client, token, target=target, data_class=data_class)
        assert decision["outcome"] == "allow", decision
        assert narrowed is not None
        token = narrowed
        issued.append(token)

        c = claims(token)
        assert c["aud"] == target  # exactly one target
        assert c["scope"] == data_class  # exactly one data class
        assert c["sub"] == USER  # the human never moves
        assert c["action_id"] == decision["action_id"]  # names the decision that allowed it

    assert len(set(issued)) == 4  # four distinct tokens

    deepest = claims(issued[-1])
    assert deepest["hop"] == 4
    assert deepest["act"] == {
        "sub": f"agent://{SUMMARIZER}",
        "act": {"sub": f"agent://{KB_SEARCH}", "act": {"sub": f"agent://{ORCHESTRATOR}"}},
    }


async def test_the_deepest_token_resolves_back_to_the_consenting_human(
    client, register_chain, consent
) -> None:
    """A resource server reads the whole chain off the token alone."""
    await register_chain()
    session = await consent()

    token = session["root_grant"]
    for target, data_class in CHAIN:
        _, narrowed = await hop(client, token, target=target, data_class=data_class)
        assert narrowed is not None
        token = narrowed

    c = claims(token)
    chain, act = [c["sub"]], c["act"]
    links = []
    while act is not None:
        links.append(act["sub"])
        act = act.get("act")
    chain += list(reversed(links))

    assert chain == [
        USER,
        f"agent://{ORCHESTRATOR}",
        f"agent://{KB_SEARCH}",
        f"agent://{SUMMARIZER}",
    ]


async def test_hop_beyond_the_budget_is_blocked_at_that_hop(
    client, admin_headers, register_chain, consent
) -> None:
    """Allowed *at* the budget, refused after it."""
    await register_chain()

    # Tighten summarizer's budget so the notifier route caps at 2.
    tight = manifest_doc(
        SUMMARIZER,
        hop_budget=2,
        tools=chain_docs()[SUMMARIZER]["spec"]["tools"],
        downstream=[{"ref": f"agent://{NOTIFIER}", "max_hop_depth": 2}],
    )
    r = await client.post(
        "/v1/manifests", headers=admin_headers, json={"agent": SUMMARIZER, "manifest": tight}
    )
    assert r.status_code == 201

    session = await consent()

    token = session["root_grant"]
    # hop 1 and hop 2 are inside the budget
    for target, data_class in CHAIN[:2]:
        decision, narrowed = await hop(client, token, target=target, data_class=data_class)
        assert decision["outcome"] == "allow", decision
        assert narrowed is not None
        token = narrowed

    # hop 3 crosses it
    denied = (
        await authorize(client, token, target=f"agent://{NOTIFIER}", data_class="account.write")
    ).json()
    assert denied["outcome"] == "deny"
    assert denied["reason"] == "HOP_BUDGET_EXCEEDED"
    assert denied["hop"] == 3

    # and the recorded refusal cannot be spent on a token
    r = await exchange(
        client,
        token,
        resource=f"agent://{NOTIFIER}",
        scope="account.write",
        action_id=denied["action_id"],
    )
    assert r.status_code == 400
    assert "access_token" not in r.json()
    assert "was a deny" in r.json()["error_description"]


async def test_every_hop_of_the_chain_is_recorded(client, register_chain, consent, db_session):
    from sqlalchemy import text

    await register_chain()
    session = await consent()
    sid = session["session_id"]

    token = session["root_grant"]
    for target, data_class in CHAIN[:2]:
        _, narrowed = await hop(client, token, target=target, data_class=data_class)
        assert narrowed is not None
        token = narrowed

    rows = (
        (
            await db_session.execute(
                text(
                    "SELECT hop, outcome, act_chain FROM audit_decisions WHERE session_id = :i "
                    "AND outcome = 'allow' ORDER BY hop, ts"
                ),
                {"i": sid},
            )
        )
        .mappings()
        .all()
    )

    hops = [r["hop"] for r in rows]
    assert hops == sorted(hops)
    assert hops[0] == 1
    # the chain recorded at the deeper hop is longer than at the shallower one
    assert len(rows[-1]["act_chain"]) > len(rows[0]["act_chain"])
