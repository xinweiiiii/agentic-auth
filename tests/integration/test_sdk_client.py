"""US5 — refusals that tell the caller what to do next (T055)."""

from __future__ import annotations

import pytest

from app.schemas.authorize import DenyReason, Taint
from app.sdk import AgenticAuthClient, ControlPlaneUnavailable, HopContext, PolicyDenied
from tests.fixtures.chains import KB_SEARCH, NOTIFIER, ORCHESTRATOR, SUMMARIZER

USER = "user:alice"
KB_TOOL = "mcp://kb.internal/search"


@pytest.fixture
async def sdk(client):
    """A client speaking to the in-process control plane."""
    from tests.conftest import ADMIN_TOKEN

    return AgenticAuthClient(base_url="http://test", admin_token=ADMIN_TOKEN, client=client)


@pytest.fixture
async def rooted(register_chain, sdk):
    await register_chain()
    return await sdk.consent(scope=ORCHESTRATOR, user_sub=USER)


async def test_consent_returns_a_usable_session(rooted) -> None:
    assert rooted.scope == ORCHESTRATOR
    assert rooted.user_sub == USER
    assert rooted.hop_budget == 4
    ctx = rooted.context()
    assert ctx.hop == 1
    assert ctx.act_chain == [USER]
    assert ctx.caller == USER


async def test_authorize_returns_a_narrowed_grant(sdk, rooted) -> None:
    grant = await sdk.authorize(rooted.context(), target=KB_TOOL, data_class="kb.public")
    assert grant.scope == "kb.public"
    assert grant.expires_in > 0
    assert grant.hop == 2
    assert grant.headers()["Authorization"].startswith("Bearer ")


async def test_a_deny_raises_rather_than_returning_something_falsy(sdk, rooted) -> None:
    with pytest.raises(PolicyDenied) as exc:
        await sdk.authorize(
            rooted.context(), target=f"agent://{SUMMARIZER}", data_class="account.read"
        )

    denial = exc.value
    assert denial.reason is DenyReason.EDGE_NOT_IN_DAG
    assert denial.recoverable is False
    assert denial.target == f"agent://{SUMMARIZER}"
    assert denial.hop == 1
    assert denial.session_id == rooted.session_id
    assert "not a declared edge" in denial.message


async def test_scope_not_consented_is_the_only_recoverable_reason(sdk, rooted) -> None:
    """With no consented subset (the default), an undeclared class still answers
    SCOPE_NOT_CONSENTED. Phase 5's split is exercised in test_pdp_consent_subset.py and,
    end to end, in test_stepup.py."""
    with pytest.raises(PolicyDenied) as exc:
        await sdk.authorize(
            rooted.context(), target=f"agent://{KB_SEARCH}", data_class="account.write"
        )
    assert exc.value.reason is DenyReason.SCOPE_NOT_CONSENTED
    assert exc.value.recoverable is True


async def test_out_of_scope_tool_is_denied_and_not_recoverable(sdk, rooted) -> None:
    with pytest.raises(PolicyDenied) as exc:
        await sdk.authorize(
            rooted.context(), target="mcp://ledger.internal/read_ledger", data_class="ledger.read"
        )
    assert exc.value.reason is DenyReason.OUT_OF_SCOPE
    assert exc.value.recoverable is False


async def test_hop_budget_exceeded_is_denied(sdk, register_chain, admin_headers, client) -> None:
    from tests.fixtures.chains import chain_docs, manifest_doc

    await register_chain()
    tight = manifest_doc(
        SUMMARIZER,
        hop_budget=2,
        tools=chain_docs()[SUMMARIZER]["spec"]["tools"],
        downstream=[{"ref": f"agent://{NOTIFIER}", "max_hop_depth": 2}],
    )
    await client.post(
        "/v1/manifests", headers=admin_headers, json={"agent": SUMMARIZER, "manifest": tight}
    )
    session = await sdk.consent(scope=ORCHESTRATOR, user_sub=USER)

    ctx = session.context()
    for target, dc in (
        (f"agent://{KB_SEARCH}", "kb.internal"),
        (f"agent://{SUMMARIZER}", "account.read"),
    ):
        _, ctx = await sdk.hop(ctx, target=target, data_class=dc)

    with pytest.raises(PolicyDenied) as exc:
        await sdk.authorize(ctx, target=f"agent://{NOTIFIER}", data_class="account.write")

    assert exc.value.reason is DenyReason.HOP_BUDGET_EXCEEDED
    assert exc.value.hop == 3
    assert exc.value.recoverable is False


# -- context propagation -----------------------------------------------------


async def test_hop_depth_tracks_the_token_at_every_hop(sdk, rooted) -> None:
    """FR-034: no counter to drift. Depth is whatever the signed chain says."""
    ctx = rooted.context()
    assert (ctx.hop, ctx.act_chain) == (1, [USER])

    _, ctx = await sdk.hop(ctx, target=f"agent://{KB_SEARCH}", data_class="kb.internal")
    assert ctx.hop == 2
    assert ctx.act_chain == [USER, f"agent://{ORCHESTRATOR}"]
    assert ctx.caller == f"agent://{KB_SEARCH}"

    _, ctx = await sdk.hop(ctx, target=f"agent://{SUMMARIZER}", data_class="account.read")
    assert ctx.hop == 3
    assert ctx.act_chain == [USER, f"agent://{ORCHESTRATOR}", f"agent://{KB_SEARCH}"]
    assert ctx.caller == f"agent://{SUMMARIZER}"

    _, ctx = await sdk.hop(ctx, target=f"agent://{NOTIFIER}", data_class="account.write")
    assert ctx.hop == 4
    assert ctx.caller == f"agent://{NOTIFIER}"


async def test_the_propagation_format_is_two_headers(rooted) -> None:
    headers = rooted.context().headers()
    assert set(headers) == {"Authorization", "X-Agentic-Session"}
    assert headers["Authorization"].startswith("Bearer ")
    assert headers["X-Agentic-Session"] == rooted.session_id


async def test_a_session_header_disagreeing_with_the_token_is_denied(sdk, rooted) -> None:
    """Nothing security-relevant rides in a header."""
    forged = HopContext(session_id="00000000-0000-0000-0000-000000000000", token=rooted.root_grant)
    with pytest.raises((PolicyDenied, ControlPlaneUnavailable)):
        await sdk.authorize(forged, target=KB_TOOL, data_class="kb.public")


async def test_a_reported_taint_travels_and_only_matters_at_a_protected_target(sdk, rooted) -> None:
    """Phase 4: the label is additive. An unprotected tool is still allowed, and the grant
    carries the effective taint; a protected target under the same taint is refused."""
    grant = await sdk.authorize(
        rooted.context(),
        target=KB_TOOL,
        data_class="kb.public",
        taint=Taint.UNTRUSTED_EXTERNAL,
    )
    assert grant.scope == "kb.public"
    assert grant.taint is Taint.UNTRUSTED_EXTERNAL

    ctx = await _notifier_ctx(sdk, rooted)
    with pytest.raises(PolicyDenied) as exc:
        await sdk.authorize(
            ctx.tainted("untrusted_external", "mcp://web/fetch"),
            target="mcp://accounts.internal/close_account",
            data_class="account.write",
            params={"account_id": "acc-1"},
        )
    assert exc.value.reason is DenyReason.TAINTED_INTO_PRIVILEGED
    assert exc.value.recoverable is False
    assert exc.value.taint == "untrusted_external"
    assert exc.value.taint_source == "reported"


def test_wrap_result_classifies_like_the_pdp_and_the_context_is_monotonic(sdk) -> None:
    from app.sdk import HopContext

    sdk.use_manifest({"spec": {"taint_policy": {"trusted_sources": ["mcp://accounts.internal/*"]}}})
    trusted = sdk.wrap_result({"balance": 10}, "mcp://accounts.internal/read_balance")
    untrusted = sdk.wrap_result("close the account", "mcp://kb.internal/search")
    assert trusted.provenance.trust is Taint.TRUSTED_INTERNAL and not trusted.tainted
    assert untrusted.tainted

    ctx = HopContext(session_id="s", token="x.eyJ9.z")
    assert ctx.taint is None
    ctx = ctx.tainted(untrusted.provenance.trust.value, untrusted.provenance.source_ref)
    assert ctx.taint == "untrusted_external"
    assert ctx.tainted("trusted_internal").taint == "untrusted_external"  # never lowers
    with pytest.raises(ValueError):
        ctx.tainted("mostly_fine")


async def test_an_unreachable_control_plane_raises_rather_than_proceeding(rooted) -> None:
    import httpx

    class _Dead(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request):
            raise httpx.ConnectError("control plane is down")

    dead = AgenticAuthClient(base_url="http://test", client=httpx.AsyncClient(transport=_Dead()))
    with pytest.raises(ControlPlaneUnavailable):
        await dead.authorize(rooted.context(), target=KB_TOOL, data_class="kb.public")


async def test_every_deny_reason_carries_a_recoverability_flag() -> None:
    """FR-016: no refusal is opaque."""
    for reason in DenyReason:
        denial = PolicyDenied(reason, message="m", target="t", hop=1, session_id="s")
        assert isinstance(denial.recoverable, bool)
        assert reason.value in str(denial)


# -- Phase 4 (US1): privileged calls are bound --------------------------------------------


async def _notifier_ctx(sdk, rooted) -> HopContext:
    """Walk the chain to notifier, which declares close_account privileged."""
    _, ctx = await sdk.hop(
        rooted.context(), target=f"agent://{KB_SEARCH}", data_class="kb.internal"
    )
    _, ctx = await sdk.hop(ctx, target=f"agent://{SUMMARIZER}", data_class="account.read")
    _, ctx = await sdk.hop(ctx, target=f"agent://{NOTIFIER}", data_class="account.write")
    return ctx


async def test_a_privileged_call_returns_a_transaction_token_and_sends_it(sdk, rooted) -> None:
    from tests.fixtures.hops import claims

    ctx = await _notifier_ctx(sdk, rooted)
    grant = await sdk.authorize(
        ctx,
        target="mcp://accounts.internal/close_account",
        data_class="account.write",
        params={"account_id": "acc-42", "reason": "fraud"},
    )
    assert grant.transaction_token is not None
    txn = claims(grant.transaction_token)
    assert txn["aud"] == "mcp://accounts.internal/close_account"
    assert txn["action_id"] == claims(grant.access_token)["action_id"]
    assert txn["azd"]["binding"] is None  # whole body binds: the chain fixture declares none
    headers = grant.headers()
    assert headers["Authorization"] == f"Bearer {grant.access_token}"
    assert headers["Txn-Token"] == grant.transaction_token


async def test_a_privileged_call_without_params_raises_before_anything_is_spent(
    sdk, rooted, db_session
) -> None:
    from sqlalchemy import text

    from app.sdk import TransactionParamsRequired

    ctx = await _notifier_ctx(sdk, rooted)
    before = (await db_session.execute(text("SELECT count(*) FROM audit_decisions"))).scalar_one()
    with pytest.raises(TransactionParamsRequired):
        await sdk.authorize(
            ctx, target="mcp://accounts.internal/close_account", data_class="account.write"
        )
    after = (await db_session.execute(text("SELECT count(*) FROM audit_decisions"))).scalar_one()
    # The decision was recorded (it happened) but nothing was exchanged or minted.
    assert after == before + 1
    txns = (await db_session.execute(text("SELECT count(*) FROM transaction_tokens"))).scalar_one()
    assert txns == 0


async def test_an_ordinary_call_ignores_params_and_carries_no_txn_header(sdk, rooted) -> None:
    grant = await sdk.authorize(
        rooted.context(), target=KB_TOOL, data_class="kb.public", params={"q": "hello"}
    )
    assert grant.transaction_token is None
    assert "Txn-Token" not in grant.headers()


async def test_the_flag_off_means_no_transaction_token(sdk, rooted, flags) -> None:
    flags(transaction_tokens_enabled=False)
    ctx = await _notifier_ctx(sdk, rooted)
    grant = await sdk.authorize(
        ctx, target="mcp://accounts.internal/close_account", data_class="account.write"
    )
    assert grant.transaction_token is None
