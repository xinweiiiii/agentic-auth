"""Taint derivation and propagation across hops."""

from __future__ import annotations

import pytest

from agentic_auth.schemas.authorize import DenyReason
from agentic_auth.services import taint as taint_module
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
from tests.fixtures.hops import authorize, claims, hop, register_agents


@pytest.fixture
async def bank(client, admin_headers, consent):
    async def _setup(**kwargs):
        await register_agents(client, admin_headers, bank_docs(widened=True, **kwargs))
        return await consent(scope=BANK_ASSISTANT, user_sub=USER)

    return _setup


async def _to_support(client, root_grant):
    _, t1 = await hop(
        client, root_grant, target=f"agent://{BALANCE_AGENT}", data_class="account.read"
    )
    _, t2 = await hop(client, t1, target=f"agent://{SUPPORT_AGENT}", data_class="kb.internal")
    return t1, t2


async def test_a_kb_read_taints_the_context_and_blocks_the_privileged_call(client, bank) -> None:
    session = await bank()
    _, support = await _to_support(client, session["root_grant"])

    kb = (await authorize(client, support, target=KB_SEARCH_TOOL, data_class="kb.internal")).json()
    assert kb["outcome"] == "allow" and kb["taint"] == "trusted_internal"

    blocked = (
        await authorize(client, support, target=TERMINATE_ACCOUNT, data_class="account.write")
    ).json()
    assert blocked["outcome"] == "deny"
    assert blocked["reason"] == DenyReason.TAINTED_INTO_PRIVILEGED.value
    assert blocked["recoverable"] is False
    assert blocked["taint"] == "untrusted_external"
    assert blocked["taint_source"] == KB_SEARCH_TOOL
    assert blocked["privileged"] is True


async def test_a_trusted_kb_does_not_taint(client, bank) -> None:
    session = await bank(trust_kb=True)
    _, support = await _to_support(client, session["root_grant"])
    await authorize(client, support, target=KB_SEARCH_TOOL, data_class="kb.internal")
    allowed = (
        await authorize(client, support, target=TERMINATE_ACCOUNT, data_class="account.write")
    ).json()
    assert allowed["outcome"] == "allow" and allowed["taint"] == "trusted_internal"


async def test_taint_travels_down_in_the_hop_token(client, bank) -> None:
    """bank-assistant reads the KB at hop 1; support-agent, two delegations later, is
    tainted through the signed claim without anyone reporting it."""
    session = await bank()
    root = session["root_grant"]
    # bank-assistant fetches the KB (untrusted for it: only balance-agent is trusted)
    kb = (await authorize(client, root, target=KB_SEARCH_TOOL, data_class="kb.public")).json()
    assert kb["outcome"] == "allow"
    _, t1 = await hop(client, root, target=f"agent://{BALANCE_AGENT}", data_class="account.read")
    assert claims(t1)["taint"] == "untrusted_external"
    _, t2 = await hop(client, t1, target=f"agent://{SUPPORT_AGENT}", data_class="kb.internal")
    assert claims(t2)["taint"] == "untrusted_external"

    blocked = (
        await authorize(client, t2, target=TERMINATE_ACCOUNT, data_class="account.write")
    ).json()
    assert blocked["reason"] == DenyReason.TAINTED_INTO_PRIVILEGED.value
    assert blocked["taint_source"] == "inherited"


async def test_taint_travels_up_to_the_delegator_through_the_chain(client, bank) -> None:
    """support-agent (hop 3) reads the KB; balance-agent (hop 2), its delegator, is now
    tainted too, because it will consume what support-agent returns."""
    session = await bank()
    t1, support = await _to_support(client, session["root_grant"])
    await authorize(client, support, target=KB_SEARCH_TOOL, data_class="kb.internal")

    # balance-agent's own privileged-shaped action: it has none, so check the effective
    # taint reported on an ordinary call instead.
    d = (await authorize(client, t1, target=READ_BALANCE, data_class="account.read")).json()
    assert d["outcome"] == "allow"
    assert d["taint"] == "untrusted_external"
    assert d["taint_source"] == KB_SEARCH_TOOL


async def test_a_sibling_delegated_before_the_taint_is_clean_and_one_after_is_not(
    client, bank
) -> None:
    session = await bank()
    _, t1 = await hop(
        client, session["root_grant"], target=f"agent://{BALANCE_AGENT}", data_class="account.read"
    )
    _, early = await hop(client, t1, target=f"agent://{SUPPORT_AGENT}", data_class="kb.internal")
    # balance-agent reads something untrusted (its trusted sources: support-agent only)
    await authorize(client, t1, target=READ_BALANCE, data_class="account.read")
    _, late = await hop(client, t1, target=f"agent://{SUPPORT_AGENT}", data_class="kb.internal")

    assert claims(early).get("taint") in (None, "trusted_internal")
    assert claims(late)["taint"] == "untrusted_external"


async def test_a_lower_reported_label_never_lowers_the_taint(client, bank) -> None:
    session = await bank()
    _, support = await _to_support(client, session["root_grant"])
    await authorize(client, support, target=KB_SEARCH_TOOL, data_class="kb.internal")
    c = claims(support)
    r = await client.post(
        "/v1/authorize",
        headers={"Authorization": f"Bearer {support}"},
        json={
            "session_id": c["session_id"],
            "caller": f"agent://{SUPPORT_AGENT}",
            "target": TERMINATE_ACCOUNT,
            "data_class": "account.write",
            "guarantee": "full",
            "taint": "trusted_internal",
        },
    )
    assert r.json()["reason"] == DenyReason.TAINTED_INTO_PRIVILEGED.value


async def test_a_reported_untrusted_label_raises_the_taint(client, bank) -> None:
    session = await bank()
    _, support = await _to_support(client, session["root_grant"])
    c = claims(support)
    r = await client.post(
        "/v1/authorize",
        headers={"Authorization": f"Bearer {support}"},
        json={
            "session_id": c["session_id"],
            "caller": f"agent://{SUPPORT_AGENT}",
            "target": TERMINATE_ACCOUNT,
            "data_class": "account.write",
            "guarantee": "full",
            "taint": "untrusted_external",
        },
    )
    body = r.json()
    assert body["reason"] == DenyReason.TAINTED_INTO_PRIVILEGED.value
    assert body["taint_source"] == "reported"


async def test_a_tainted_context_may_still_call_an_unprotected_tool(client, bank) -> None:
    session = await bank()
    _, support = await _to_support(client, session["root_grant"])
    await authorize(client, support, target=KB_SEARCH_TOOL, data_class="kb.internal")
    again = (
        await authorize(client, support, target=KB_SEARCH_TOOL, data_class="kb.internal")
    ).json()
    assert again["outcome"] == "allow" and again["taint"] == "untrusted_external"


async def test_enforcement_off_records_but_allows(client, bank, flags) -> None:
    flags(taint_enforcement_enabled=False)
    session = await bank()
    _, support = await _to_support(client, session["root_grant"])
    await authorize(client, support, target=KB_SEARCH_TOOL, data_class="kb.internal")
    d = (
        await authorize(client, support, target=TERMINATE_ACCOUNT, data_class="account.write")
    ).json()
    assert d["outcome"] == "allow"
    assert d["taint"] == "untrusted_external" and d["taint_source"] == KB_SEARCH_TOOL


async def test_the_exchange_re_decides_under_fresh_taint(client, bank) -> None:
    """An allow recorded BEFORE the context was tainted buys no token afterwards."""
    from tests.fixtures.hops import exchange

    session = await bank()
    _, support = await _to_support(client, session["root_grant"])
    early = (
        await authorize(client, support, target=TERMINATE_ACCOUNT, data_class="account.write")
    ).json()
    assert early["outcome"] == "allow"
    await authorize(client, support, target=KB_SEARCH_TOOL, data_class="kb.internal")  # now tainted
    r = await exchange(
        client,
        support,
        resource=TERMINATE_ACCOUNT,
        scope="account.write",
        action_id=early["action_id"],
    )
    assert r.status_code == 403
    assert r.json()["error"] == "invalid_target"


async def test_taint_store_down_refuses_a_protected_target_and_records_unknown_otherwise(
    client, bank, monkeypatch
) -> None:
    session = await bank()
    _, support = await _to_support(client, session["root_grant"])

    async def _boom(self, session_id):
        raise taint_module.TaintStoreUnavailable("redis is down")

    monkeypatch.setattr(taint_module.TaintStore, "marked", _boom)
    protected = (
        await authorize(client, support, target=TERMINATE_ACCOUNT, data_class="account.write")
    ).json()
    assert protected["outcome"] == "deny"
    assert protected["reason"] == DenyReason.PDP_UNAVAILABLE.value
    ordinary = (
        await authorize(client, support, target=KB_SEARCH_TOOL, data_class="kb.internal")
    ).json()
    # only the READ is broken here: the ordinary call proceeds, recorded with taint unknown
    assert ordinary["outcome"] == "allow" and ordinary["taint"] is None


async def test_a_mark_failure_withdraws_the_allow(client, bank, monkeypatch) -> None:
    session = await bank()
    _, support = await _to_support(client, session["root_grant"])

    async def _boom(self, *a, **kw):
        raise taint_module.TaintStoreUnavailable("redis is down")

    monkeypatch.setattr(taint_module.TaintStore, "mark", _boom)
    d = (await authorize(client, support, target=KB_SEARCH_TOOL, data_class="kb.internal")).json()
    assert d["outcome"] == "deny" and d["reason"] == DenyReason.PDP_UNAVAILABLE.value
    assert d["action_id"] is None


async def test_a_glob_protects_a_non_privileged_tool(client, admin_headers, consent) -> None:
    """block_tainted_into globs protect targets that are not privileged at all: here every
    kb.* data class. After one KB read the context is tainted, and a second KB read — an
    ordinary, non-privileged tool — is refused."""
    docs = bank_docs(widened=True)
    docs[SUPPORT_AGENT]["spec"]["taint_policy"] = {
        "trusted_sources": [],
        "block_tainted_into": ["kb.*"],
    }
    await register_agents(client, admin_headers, docs)
    session = await consent(scope=BANK_ASSISTANT, user_sub=USER)
    _, support = await _to_support(client, session["root_grant"])
    first = (
        await authorize(client, support, target=KB_SEARCH_TOOL, data_class="kb.internal")
    ).json()
    assert first["outcome"] == "allow"
    second = (
        await authorize(client, support, target=KB_SEARCH_TOOL, data_class="kb.internal")
    ).json()
    assert second["reason"] == DenyReason.TAINTED_INTO_PRIVILEGED.value
    assert second["privileged"] is False
    assert second["taint_source"] == KB_SEARCH_TOOL
