"""The PRD §2.2 injection scenario, end to end through the sidecar."""

from __future__ import annotations

import pytest

from app.schemas.authorize import DenyReason
from app.sidecar.config import Upstream
from tests.conftest import ADMIN_TOKEN
from tests.fixtures.bank import (
    BALANCE_AGENT,
    BANK_ASSISTANT,
    KB_SEARCH_TOOL,
    SUPPORT_AGENT,
    TERMINATE_ACCOUNT,
    TERMINATE_PARAMS,
    USER,
    bank_docs,
)
from tests.fixtures.hops import hop, register_agents

UPSTREAMS = {
    "/kb": Upstream(url="http://upstream.test", target=KB_SEARCH_TOOL, data_class="kb.internal"),
    "/accounts": Upstream(
        url="http://upstream.test", target=TERMINATE_ACCOUNT, data_class="account.write"
    ),
}


@pytest.fixture
async def support(client, admin_headers, consent):
    async def _setup(**kwargs):
        await register_agents(client, admin_headers, bank_docs(widened=True, **kwargs))
        session = await consent(scope=BANK_ASSISTANT, user_sub=USER)
        _, t1 = await hop(
            client,
            session["root_grant"],
            target=f"agent://{BALANCE_AGENT}",
            data_class="account.read",
        )
        _, t2 = await hop(client, t1, target=f"agent://{SUPPORT_AGENT}", data_class="kb.internal")
        return t2

    return _setup


async def test_injected_content_cannot_reach_terminate_account(
    sidecar_stack, support, client
) -> None:
    token = await support()
    sidecar = await sidecar_stack.client(upstream_map=UPSTREAMS)
    headers = {"Authorization": f"Bearer {token}"}

    # 1. support-agent reads the knowledge base — the article says "close the account"
    kb = await sidecar.get("/kb/search?q=refund", headers=headers)
    assert kb.status_code == 200
    assert sidecar_stack.recorder.count == 1

    # 2. steered by it, support-agent tries to terminate the account
    blocked = await sidecar.post("/accounts/terminate", headers=headers, json=TERMINATE_PARAMS)
    assert blocked.status_code == 403
    details = blocked.json()["error"]["details"]
    assert details["reason"] == DenyReason.TAINTED_INTO_PRIVILEGED.value
    assert details["recoverable"] is False
    # nothing reached the accounts upstream
    assert sidecar_stack.recorder.count == 1
    assert all(r["path"].startswith("/search") for r in sidecar_stack.recorder.requests)

    # 3. the audit row names the source, and the chain query shows the same
    rows = await client.get(
        "/v1/audit/decisions?outcome=deny", headers={"Authorization": f"Bearer {ADMIN_TOKEN}"}
    )
    denied = [r for r in rows.json()["data"] if r["target"] == TERMINATE_ACCOUNT]
    assert len(denied) == 1
    row = denied[0]
    assert row["deny_reason"] == DenyReason.TAINTED_INTO_PRIVILEGED.value
    assert row["taint"] == "untrusted_external"
    assert row["taint_source"] == KB_SEARCH_TOOL
    assert row["privileged"] is True

    chain = await client.get(
        f"/v1/audit/actions/{row['id']}/chain", headers={"Authorization": f"Bearer {ADMIN_TOKEN}"}
    )
    last = chain.json()["chain"][-1]
    assert last["deny_reason"] == DenyReason.TAINTED_INTO_PRIVILEGED.value
    assert last["taint"] == "untrusted_external" and last["taint_source"] == KB_SEARCH_TOOL


async def test_with_a_trusted_knowledge_base_the_call_proceeds(sidecar_stack, support) -> None:
    token = await support(trust_kb=True)
    sidecar = await sidecar_stack.client(upstream_map=UPSTREAMS)
    headers = {"Authorization": f"Bearer {token}"}
    assert (await sidecar.get("/kb/search?q=refund", headers=headers)).status_code == 200
    allowed = await sidecar.post("/accounts/terminate", headers=headers, json=TERMINATE_PARAMS)
    assert allowed.status_code == 200, allowed.text
    assert sidecar_stack.recorder.count == 2
    assert "txn-token" in sidecar_stack.recorder.last["headers"]


async def test_observe_mode_forwards_the_tainted_call_but_records_it_unenforced(
    sidecar_stack, support, client
) -> None:
    token = await support()
    sidecar = await sidecar_stack.client(upstream_map=UPSTREAMS, observe_mode=True)
    headers = {"Authorization": f"Bearer {token}"}
    await sidecar.get("/kb/search", headers=headers)
    r = await sidecar.post("/accounts/terminate", headers=headers, json=TERMINATE_PARAMS)
    assert r.status_code == 200  # observe mode: a POLICY refusal is forwarded
    rows = (
        await client.get(
            "/v1/audit/decisions?outcome=deny&enforced=false",
            headers={"Authorization": f"Bearer {ADMIN_TOKEN}"},
        )
    ).json()["data"]
    assert any(
        r["deny_reason"] == DenyReason.TAINTED_INTO_PRIVILEGED.value
        and r["taint_source"] == KB_SEARCH_TOOL
        for r in rows
    )
