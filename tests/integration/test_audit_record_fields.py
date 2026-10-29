"""Every decision lands as a complete audit row.

Driven through the PRD §2.3 bank scenario: two allowed delegations, then support-agent tries
the undeclared ``terminate_account`` and is refused.
"""

from __future__ import annotations

import json

from sqlalchemy import select

from app.models import AuditDecision
from tests.fixtures.bank import (
    BALANCE_AGENT,
    BANK_ASSISTANT,
    DRIFTED_CALLS,
    SUPPORT_AGENT,
    TERMINATE_ACCOUNT,
    bank_docs,
)
from tests.fixtures.hops import authorize, claims, consent_session, register_agents, run_calls


async def _bank_session(client, admin_headers) -> dict:
    await register_agents(client, admin_headers, bank_docs())
    return await consent_session(client, admin_headers, BANK_ASSISTANT)


async def _rows(db_session, session_id: str) -> list[AuditDecision]:
    result = await db_session.execute(
        select(AuditDecision)
        .where(AuditDecision.session_id == session_id)
        .order_by(AuditDecision.seq)
    )
    return list(result.scalars().all())


async def test_every_hop_of_the_prd_chain_is_recorded_with_every_field(
    client, admin_headers, db_session
) -> None:
    session = await _bank_session(client, admin_headers)

    decisions, presented = await run_calls(client, session["root_grant"], DRIFTED_CALLS)

    assert [d["outcome"] for d in decisions] == ["allow", "allow", "deny"]
    assert decisions[-1]["reason"] == "OUT_OF_SCOPE"

    rows = await _rows(db_session, session["session_id"])
    assert [r.hop for r in rows] == [1, 2, 3]
    assert [r.acting_agent for r in rows] == [BANK_ASSISTANT, BALANCE_AGENT, SUPPORT_AGENT]
    assert [r.target_kind for r in rows] == ["agent", "agent", "tool"]
    assert (rows[2].target, rows[2].deny_reason) == (TERMINATE_ACCOUNT, "OUT_OF_SCOPE")

    for row, token, decision in zip(rows, presented, decisions, strict=True):
        assert str(row.id) == decision["action_id"]
        assert decision["acting_agent"] == row.acting_agent
        assert row.subject_jti == claims(token)["jti"]
        assert row.policy_version == session["policy_version"]
        assert row.enforced is True
        assert row.data_class

    # Linked through the signed action_id claim, not by correlating rows.
    assert rows[0].parent_action_id is None
    assert rows[1].parent_action_id == rows[0].id
    assert rows[2].parent_action_id == rows[1].id
    assert all(r.chain_complete and r.chain_break is None for r in rows)
    assert [h["hop"] for h in rows[2].chain] == [1, 2, 3]


async def test_no_token_is_ever_stored_in_an_audit_row(client, admin_headers, db_session) -> None:
    session = await _bank_session(client, admin_headers)
    _, presented = await run_calls(client, session["root_grant"], DRIFTED_CALLS)

    rows = await _rows(db_session, session["session_id"])
    stored = json.dumps(
        [{c.name: getattr(r, c.name) for c in AuditDecision.__table__.columns} for r in rows],
        default=str,
    )

    for token in presented:
        assert token not in stored
        assert token.split(".")[2] not in stored  # not even the signature


async def test_a_policy_load_failure_is_recorded_as_a_deny(
    client, admin_headers, db_session, monkeypatch
) -> None:
    session = await _bank_session(client, admin_headers)

    from app.services import policy_loader

    async def _broken(*_args, **_kwargs):
        raise RuntimeError("policy store unreachable")

    monkeypatch.setattr(policy_loader, "load", _broken)

    body = (
        await authorize(
            client,
            session["root_grant"],
            target=f"agent://{BALANCE_AGENT}",
            data_class="account.read",
        )
    ).json()
    assert (body["outcome"], body["reason"], body["recorded"]) == ("deny", "PDP_UNAVAILABLE", True)

    rows = await _rows(db_session, session["session_id"])
    assert len(rows) == 1
    assert rows[0].deny_reason == "PDP_UNAVAILABLE"
    assert str(rows[0].id) == body["action_id"]


# -- Phase 4: taint, source, privileged, and the transaction fingerprint ----------


async def test_phase_4_fields_are_recorded_and_read_back(
    client, admin_headers, db_session, flags
) -> None:
    from tests.fixtures.bank import INJECTION_CALLS, KB_SEARCH_TOOL, TERMINATE_PARAMS
    from tests.fixtures.hops import hop

    flags(taint_enforcement_enabled=False)  # the widened chain allows terminate; taint is recorded
    await register_agents(client, admin_headers, bank_docs(widened=True))
    session = await consent_session(client, admin_headers, BANK_ASSISTANT)
    decisions, _ = await run_calls(client, session["root_grant"], INJECTION_CALLS[:-1])
    support = None
    # walk again to hold support-agent's token
    _, t1 = await hop(
        client, session["root_grant"], target=f"agent://{BALANCE_AGENT}", data_class="account.read"
    )
    _, support = await hop(client, t1, target=f"agent://{SUPPORT_AGENT}", data_class="kb.internal")
    await authorize(client, support, target=KB_SEARCH_TOOL, data_class="kb.internal")
    terminate, tool_token = await hop(
        client, support, target=TERMINATE_ACCOUNT, data_class="account.write"
    )
    minted = (
        await client.post(
            "/v1/token/transaction",
            headers={"Authorization": f"Bearer {tool_token}"},
            json={"params": TERMINATE_PARAMS},
        )
    ).json()

    rows = await _rows(db_session, session["session_id"])
    last = rows[-1]
    assert str(last.id) == terminate["action_id"]
    assert last.privileged is True
    assert last.taint == "untrusted_external" and last.taint_source == KB_SEARCH_TOOL

    # the read models
    page = (
        await client.get(
            f"/v1/audit/decisions?session_id={session['session_id']}&privileged=true",
            headers=admin_headers,
        )
    ).json()
    assert [d["id"] for d in page["data"]] == [terminate["action_id"]]
    item = page["data"][0]
    assert item["taint"] == "untrusted_external" and item["taint_source"] == KB_SEARCH_TOOL
    assert item["transaction"]["params_hash"] == minted["params_hash"]
    assert item["transaction"]["binding"] == minted["binding"]

    tainted = (
        await client.get(
            f"/v1/audit/decisions?session_id={session['session_id']}&taint=untrusted_external",
            headers=admin_headers,
        )
    ).json()
    assert terminate["action_id"] in {d["id"] for d in tainted["data"]}

    chain = (
        await client.get(f"/v1/audit/actions/{terminate['action_id']}/chain", headers=admin_headers)
    ).json()
    own = chain["chain"][-1]
    assert own["privileged"] is True and own["taint"] == "untrusted_external"
    assert own["transaction"]["params_hash"] == minted["params_hash"]
    assert all(h["transaction"] is None for h in chain["chain"][:-1])

    bad = await client.get("/v1/audit/decisions?taint=sort_of", headers=admin_headers)
    assert bad.status_code == 422


async def test_legacy_rows_report_the_phase_4_fields_as_unavailable(
    client, admin_headers, db_session
) -> None:
    """A row shaped like Phase 3 wrote it: null taint, no source, privileged false, no txn."""
    import uuid
    from datetime import UTC, datetime

    from app.repositories import audit_decisions as audit_repo

    await register_agents(client, admin_headers, bank_docs())
    session = await consent_session(client, admin_headers, BANK_ASSISTANT)
    row = await audit_repo.append(
        db_session,
        action_id=uuid.uuid4(),
        ts=datetime.now(UTC),
        session_id=uuid.UUID(session["session_id"]),
        caller="user:alice",
        target=TERMINATE_ACCOUNT,
        data_class="account.write",
        hop=1,
        outcome="allow",
        deny_reason=None,
        recoverable=False,
        enforced=True,
        taint=None,
        taint_source=None,
        privileged=False,
        policy_version=session["policy_version"],
        act_chain=["user:alice"],
        acting_agent=BANK_ASSISTANT,
        subject_jti=None,
        parent_action_id=None,
        chain=None,
        chain_complete=False,
        chain_break="LEGACY_RECORD",
    )
    await db_session.commit()
    page = (
        await client.get(
            f"/v1/audit/decisions?session_id={session['session_id']}", headers=admin_headers
        )
    ).json()
    item = next(d for d in page["data"] if d["id"] == str(row.id))
    assert item["taint"] is None and item["taint_source"] is None
    assert item["privileged"] is False and item["transaction"] is None
    chain = (await client.get(f"/v1/audit/actions/{row.id}/chain", headers=admin_headers)).json()
    assert chain["chain"][-1]["transaction"] is None


async def test_no_phase_4_secret_lands_in_any_table(
    client, admin_headers, db_session, flags, fake_idp, principal_assertion_for
) -> None:
    """Transaction tokens, challenge nonces, actor tokens, identity assertions and private
    keys never appear in a stored row."""
    from sqlalchemy import text

    from app.sdk import AgenticAuthClient, AgentKey
    from tests.conftest import ADMIN_TOKEN
    from tests.fixtures.bank import TERMINATE_PARAMS
    from tests.fixtures.identity import agent_keypair, identity_document, sign_challenge

    flags(taint_enforcement_enabled=False)
    await register_agents(client, admin_headers, bank_docs(widened=True))
    ids = {
        a["name"]: a["id"]
        for a in (await client.get("/v1/agents", headers=admin_headers)).json()["data"]
    }

    # enrollment by hand so we hold the nonce and the assertion
    key = agent_keypair(SUPPORT_AGENT)
    assertion = principal_assertion_for(SUPPORT_AGENT)
    doc = identity_document(key, principal_assertion=assertion)
    challenge = (
        await client.post(
            f"/v1/agents/{ids[SUPPORT_AGENT]}/enroll",
            headers=admin_headers,
            json={"identity_doc": doc},
        )
    ).json()
    signed = sign_challenge(key, challenge["nonce"])
    await client.post(
        f"/v1/agents/{ids[SUPPORT_AGENT]}/enroll/complete",
        headers=admin_headers,
        json={"challenge_id": challenge["challenge_id"], "signed_response": signed},
    )

    sdk_key = AgentKey.load(key.private_pem().decode(), kid=key.kid)
    sdk = AgenticAuthClient(
        base_url="http://test",
        admin_token=ADMIN_TOKEN,
        client=client,
        identity_key=sdk_key,
        agent_name=SUPPORT_AGENT,
    )
    session = await sdk.consent(scope=BANK_ASSISTANT, user_sub="user:alice")
    plain = AgenticAuthClient(base_url="http://test", admin_token=ADMIN_TOKEN, client=client)
    _, ctx = await plain.hop(
        session.context(), target=f"agent://{BALANCE_AGENT}", data_class="account.read"
    )
    _, ctx = await plain.hop(ctx, target=f"agent://{SUPPORT_AGENT}", data_class="kb.internal")
    grant = await sdk.authorize(
        ctx, target=TERMINATE_ACCOUNT, data_class="account.write", params=TERMINATE_PARAMS
    )
    actor = sdk_key.actor_token(SUPPORT_AGENT, ctx.token)

    secrets = [
        grant.transaction_token,
        grant.identity_assertion,
        actor,
        challenge["nonce"],
        signed,
        assertion,
        key.private_pem().decode(),
    ]
    for table in (
        "audit_decisions",
        "transaction_tokens",
        "trust_anchors",
        "agents",
        "sessions",
        "manifests",
    ):
        dump = str(
            (await db_session.execute(text(f"SELECT to_jsonb(t) FROM {table} t"))).scalars().all()
        )
        for secret in secrets:
            assert secret and secret not in dump, (table, secret[:12])
