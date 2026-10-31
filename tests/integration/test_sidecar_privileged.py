"""The sidecar's privileged path: buffer, bind, mint, forward with Txn-Token."""

from __future__ import annotations

import json

import pytest

from agentic_auth.sidecar.config import Upstream
from tests.fixtures.bank import (
    BALANCE_AGENT,
    BANK_ASSISTANT,
    SUPPORT_AGENT,
    TERMINATE_ACCOUNT,
    TERMINATE_PARAMS,
    USER,
    bank_docs,
)
from tests.fixtures.hops import claims, hop, register_agents

UPSTREAMS = {
    "/accounts": Upstream(
        url="http://upstream.test", target=TERMINATE_ACCOUNT, data_class="account.write"
    ),
    "/kb": Upstream(
        url="http://upstream.test", target="mcp://kb.internal/search", data_class="kb.internal"
    ),
}


@pytest.fixture
async def support(client, admin_headers, consent, flags):
    flags(taint_enforcement_enabled=False)
    await register_agents(client, admin_headers, bank_docs(widened=True))
    session = await consent(scope="bank-assistant", user_sub=USER)
    _, t1 = await hop(
        client, session["root_grant"], target=f"agent://{BALANCE_AGENT}", data_class="account.read"
    )
    _, t2 = await hop(client, t1, target=f"agent://{SUPPORT_AGENT}", data_class="kb.internal")
    return t2


async def test_a_privileged_call_is_forwarded_with_a_transaction_token(
    sidecar_stack, support
) -> None:
    sidecar = await sidecar_stack.client(upstream_map=UPSTREAMS)
    r = await sidecar.post(
        "/accounts/terminate",
        headers={"Authorization": f"Bearer {support}"},
        json=TERMINATE_PARAMS,
    )
    assert r.status_code == 200, r.text
    assert sidecar_stack.recorder.count == 1
    received = sidecar_stack.recorder.last
    assert json.loads(received["body"]) == TERMINATE_PARAMS  # body intact after buffering
    assert claims(received["token"])["aud"] == TERMINATE_ACCOUNT  # narrowed, not presented
    txn = received["headers"]["txn-token"]
    assert claims(txn)["aud"] == TERMINATE_ACCOUNT
    assert claims(txn)["action_id"] == claims(received["token"])["action_id"]


async def test_a_body_over_the_cap_is_blocked_not_forwarded(sidecar_stack, support) -> None:
    sidecar = await sidecar_stack.client(upstream_map=UPSTREAMS, max_privileged_body_bytes=256)
    r = await sidecar.post(
        "/accounts/terminate",
        headers={"Authorization": f"Bearer {support}"},
        json={**TERMINATE_PARAMS, "blob": "x" * 2048},
    )
    assert r.status_code == 403
    assert r.json()["error"]["details"]["reason"] == "BODY_TOO_LARGE_TO_BIND"
    assert sidecar_stack.recorder.count == 0


async def test_a_non_object_body_is_blocked(sidecar_stack, support) -> None:
    sidecar = await sidecar_stack.client(upstream_map=UPSTREAMS)
    r = await sidecar.post(
        "/accounts/terminate",
        headers={"Authorization": f"Bearer {support}", "content-type": "application/json"},
        content=b"[1, 2, 3]",
    )
    assert r.status_code == 403
    assert r.json()["error"]["details"]["reason"] == "PARAMS_NOT_AN_OBJECT"
    assert sidecar_stack.recorder.count == 0


async def test_transaction_service_down_blocks(sidecar_stack, support, monkeypatch) -> None:
    """The exchange succeeds, the mint cannot be reached: nothing is forwarded unbound."""
    sidecar = await sidecar_stack.client(upstream_map=UPSTREAMS)
    sidecar_stack.router.transaction_down = True
    r = await sidecar.post(
        "/accounts/terminate",
        headers={"Authorization": f"Bearer {support}"},
        json=TERMINATE_PARAMS,
    )
    assert r.status_code == 503
    assert r.json()["error"]["details"]["reason"] == "TRANSACTION_SERVICE_UNAVAILABLE"
    assert sidecar_stack.recorder.count == 0


async def test_a_mint_refusal_is_a_deny_not_an_outage(sidecar_stack, support, monkeypatch) -> None:
    """The mint answers 4xx: the sidecar blocks with the mint's reason and 403, never 503,
    and nothing is forwarded."""
    from agentic_auth.errors import PolicyDenied
    from agentic_auth.services import transactions

    async def _refuse(self, db, redis, token, params):
        raise PolicyDenied(
            "tainted context cannot mint call-bound authority",
            {"reason": "TAINTED_INTO_PRIVILEGED", "recoverable": False},
        )

    monkeypatch.setattr(transactions.TransactionService, "mint", _refuse)
    sidecar = await sidecar_stack.client(upstream_map=UPSTREAMS)
    r = await sidecar.post(
        "/accounts/terminate", headers={"Authorization": f"Bearer {support}"}, json=TERMINATE_PARAMS
    )
    assert r.status_code == 403
    assert r.json()["error"]["details"]["reason"] == "TAINTED_INTO_PRIVILEGED"
    assert sidecar_stack.recorder.count == 0


async def test_non_privileged_calls_still_stream_without_extra_headers(
    sidecar_stack, support
) -> None:
    sidecar = await sidecar_stack.client(upstream_map=UPSTREAMS)
    r = await sidecar.post(
        "/kb/search", headers={"Authorization": f"Bearer {support}"}, json={"q": "hello"}
    )
    assert r.status_code == 200, r.text
    received = sidecar_stack.recorder.last
    assert "txn-token" not in received["headers"]
    assert json.loads(received["body"]) == {"q": "hello"}


# -- Phase 4 identity through the sidecar -----------------------------------------


async def test_a_configured_key_adds_agent_identity_and_an_actor_token(
    sidecar_stack,
    client,
    admin_headers,
    consent,
    flags,
    fake_idp,
    principal_assertion_for,
    tmp_path,
) -> None:
    """With agent_name + identity_key_path, the sidecar signs an actor_token at the exchange
    (so identity_required passes) and puts Agent-Identity on the forwarded call."""
    from agentic_auth.sdk import AgentKey
    from tests.fixtures.hops import claims

    flags(taint_enforcement_enabled=False)
    await register_agents(client, admin_headers, bank_docs(widened=True))
    ids = {
        a["name"]: a["id"]
        for a in (await client.get("/v1/agents", headers=admin_headers)).json()["data"]
    }

    # enroll bank-assistant (the root holder) and balance-agent; the sidecar is balance-agent's
    keys = {}
    from agentic_auth.sdk import AgenticAuthClient
    from tests.conftest import ADMIN_TOKEN

    sdk = AgenticAuthClient(base_url="http://test", admin_token=ADMIN_TOKEN, client=client)
    for name in (BANK_ASSISTANT, BALANCE_AGENT):
        # Default kid: derived from the key, so a PEM saved and reloaded keeps it.
        key = AgentKey.generate()
        assert (
            await sdk.enroll(
                ids[name],
                key=key,
                agent_name=name,
                principal_assertion=principal_assertion_for(name),
            )
        )["status"] == "enrolled"
        keys[name] = key
    key_path = tmp_path / "balance.pem"
    keys[BALANCE_AGENT].save(key_path)

    session = await consent(scope=BANK_ASSISTANT, user_sub=USER)
    # hop 1 by hand with bank-assistant's key (identity on from here)
    flags(identity_required=True)
    root = AgenticAuthClient(
        base_url="http://test",
        admin_token=ADMIN_TOKEN,
        client=client,
        identity_key=keys[BANK_ASSISTANT],
        agent_name=BANK_ASSISTANT,
    )
    from agentic_auth.sdk import HopContext

    _, ctx = await root.hop(
        HopContext(session_id=session["session_id"], token=session["root_grant"]),
        target=f"agent://{BALANCE_AGENT}",
        data_class="account.read",
    )

    sidecar = await sidecar_stack.client(
        upstream_map={
            "/accounts": Upstream(
                url="http://upstream.test",
                target="mcp://accounts.internal/read_balance",
                data_class="account.read",
            )
        },
        agent_name=BALANCE_AGENT,
        identity_key_path=str(key_path),
    )
    r = await sidecar.get("/accounts/balance", headers={"Authorization": f"Bearer {ctx.token}"})
    assert r.status_code == 200, r.text
    received = sidecar_stack.recorder.last
    ident = claims(received["headers"]["agent-identity"])
    assert ident["sub"] == f"agent://{BALANCE_AGENT}"
    assert ident["aud"] == "mcp://accounts.internal/read_balance"


async def test_without_a_key_and_identity_required_the_sidecar_blocks(
    sidecar_stack, client, admin_headers, consent, flags
) -> None:
    flags(taint_enforcement_enabled=False)
    await register_agents(client, admin_headers, bank_docs(widened=True))
    session = await consent(scope=BANK_ASSISTANT, user_sub=USER)
    flags(identity_required=True)
    sidecar = await sidecar_stack.client(
        upstream_map={
            "/accounts": Upstream(
                url="http://upstream.test",
                target=f"agent://{BALANCE_AGENT}",
                data_class="account.read",
            )
        }
    )
    r = await sidecar.get(
        "/accounts/delegate", headers={"Authorization": f"Bearer {session['root_grant']}"}
    )
    # bank-assistant never enrolled: the exchange refuses AGENT_NOT_ENROLLED (a policy 403)
    assert r.status_code == 403, r.text
    assert sidecar_stack.recorder.count == 0


def test_agent_name_and_key_path_must_come_together(tmp_path) -> None:
    from agentic_auth.sidecar.config import SidecarConfig, SidecarConfigError

    with pytest.raises(SidecarConfigError):
        SidecarConfig(
            pdp_url="http://pdp", upstream_map={"/x": Upstream(url="http://u")}, agent_name="a"
        ).validate()
    with pytest.raises(SidecarConfigError):
        SidecarConfig(
            pdp_url="http://pdp",
            upstream_map={"/x": Upstream(url="http://u")},
            agent_name="a",
            identity_key_path=str(tmp_path / "missing.pem"),
        ).validate()
