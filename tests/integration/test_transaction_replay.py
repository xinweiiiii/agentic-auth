"""Call-bound authority at the resource: mutate, replay, expire (US1, SC-001, SC-002).

Drives ``app.verify.transaction.verify_transaction`` directly with tokens the real profile
minted, so every row of quickstart §2 is a resource-side fact, not a control-plane one.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from app.schemas.authorize import Taint
from app.services.tokens.act_chain import nest
from app.services.tokens.jwt_profile import JwtTokenProfile
from app.services.tokens.keys import load_or_generate
from app.verify import (
    InMemoryReplay,
    RedisReplay,
    ReplayStoreUnavailable,
    VerificationFailed,
    binding_hash,
    verify_grant,
    verify_transaction,
)
from tests.fixtures.bank import TERMINATE_ACCOUNT, TERMINATE_BINDING, TERMINATE_PARAMS

USER = "user:alice"
READ_BALANCE = "mcp://accounts.internal/read_balance"
ACTION_ID = "7c1e0000-0000-4000-8000-0000000000aa"


@pytest.fixture(scope="module")
def profile() -> JwtTokenProfile:
    return JwtTokenProfile(load_or_generate(), issuer="agentic-auth", ttl_seconds=60)


@pytest.fixture(scope="module")
def jwks(profile) -> dict[str, Any]:
    return profile.jwks()


def _grant(profile: JwtTokenProfile, target: str = TERMINATE_ACCOUNT) -> str:
    return profile.mint_hop_token(
        sub=USER,
        target=target,
        data_class="account.write",
        session_id="s1",
        policy_version=3,
        hop=3,
        act=nest(nest(None, "agent://balance-agent"), "agent://support-agent"),
        action_id=ACTION_ID,
        taint=Taint.TRUSTED_INTERNAL,
    )


@pytest.fixture
def minted(profile):
    """``(grant, transaction token)`` for terminate_account bound on /account_id."""
    grant_raw = _grant(profile)
    hop = profile.verify(grant_raw, audience=TERMINATE_ACCOUNT)
    txn = profile.mint_transaction_token(
        hop=hop,
        params_hash=binding_hash(TERMINATE_ACCOUNT, TERMINATE_PARAMS, TERMINATE_BINDING),
        binding=TERMINATE_BINDING,
    )
    return grant_raw, txn


def _verify(jwks, grant_raw, txn, *, target=TERMINATE_ACCOUNT, params=None, replay=None):
    grant = verify_grant(grant_raw, issuer_jwks=jwks, audience=target)
    return verify_transaction(
        txn,
        target=target,
        params=params if params is not None else TERMINATE_PARAMS,
        grant=grant,
        issuer_jwks=jwks,
        replay=replay or InMemoryReplay(),
    )


def test_valid_target_and_params_are_admitted_once(jwks, minted) -> None:
    grant_raw, txn = minted
    v = _verify(jwks, grant_raw, txn)
    assert (
        v.aud == TERMINATE_ACCOUNT and v.action_id == ACTION_ID and v.binding == TERMINATE_BINDING
    )


def test_the_same_token_for_another_tool_is_a_target_mismatch(jwks, profile, minted) -> None:
    _, txn = minted
    other_grant = _grant(profile, READ_BALANCE)
    grant = verify_grant(other_grant, issuer_jwks=jwks, audience=READ_BALANCE)
    with pytest.raises(VerificationFailed) as exc:
        verify_transaction(
            txn,
            target=READ_BALANCE,
            params=TERMINATE_PARAMS,
            grant=grant,
            issuer_jwks=jwks,
            replay=InMemoryReplay(),
        )
    assert exc.value.reason == "TXN_TARGET_MISMATCH"


def test_a_changed_binding_parameter_is_a_params_mismatch(jwks, minted) -> None:
    grant_raw, txn = minted
    with pytest.raises(VerificationFailed) as exc:
        _verify(jwks, grant_raw, txn, params={**TERMINATE_PARAMS, "account_id": "acc-43"})
    assert exc.value.reason == "TXN_PARAMS_MISMATCH"


def test_a_missing_binding_parameter_is_a_params_mismatch(jwks, minted) -> None:
    grant_raw, txn = minted
    params = {k: v for k, v in TERMINATE_PARAMS.items() if k != "account_id"}
    with pytest.raises(VerificationFailed) as exc:
        _verify(jwks, grant_raw, txn, params=params)
    assert exc.value.reason == "TXN_PARAMS_MISMATCH"


def test_a_changed_non_binding_parameter_is_admitted(jwks, minted) -> None:
    grant_raw, txn = minted
    _verify(jwks, grant_raw, txn, params={**TERMINATE_PARAMS, "reason": "customer request"})


def test_equivalent_serializations_of_the_params_are_admitted(jwks, minted) -> None:
    grant_raw, txn = minted
    reordered = {"notify": True, "reason": "fraud", "account_id": "acc-42"}
    _verify(jwks, grant_raw, txn, params=reordered)


def test_a_second_identical_presentation_is_a_replay(jwks, minted) -> None:
    grant_raw, txn = minted
    store = InMemoryReplay()
    _verify(jwks, grant_raw, txn, replay=store)
    with pytest.raises(VerificationFailed) as exc:
        _verify(jwks, grant_raw, txn, replay=store)
    assert exc.value.reason == "TXN_REPLAY"


async def test_two_concurrent_presentations_admit_exactly_one(jwks, minted, redis_client) -> None:
    """The store's claim is atomic (SET NX), so a race admits one caller, not two."""

    loop = asyncio.get_running_loop()

    class _SyncShim:
        """RedisReplay speaks to a sync client; the test suite holds an async one. The
        worker threads hand the coroutine back to THIS loop."""

        def set(self, key, value, ex=None, nx=False):
            fut = asyncio.run_coroutine_threadsafe(redis_client.set(key, value, ex=ex, nx=nx), loop)
            return fut.result(timeout=5)

    grant_raw, txn = minted
    store = RedisReplay(_SyncShim())
    results = await asyncio.gather(
        loop.run_in_executor(None, lambda: _outcome(jwks, grant_raw, txn, store)),
        loop.run_in_executor(None, lambda: _outcome(jwks, grant_raw, txn, store)),
    )
    assert sorted(results) == ["TXN_REPLAY", "admitted"]


def _outcome(jwks, grant_raw, txn, store) -> str:
    try:
        _verify(jwks, grant_raw, txn, replay=store)
        return "admitted"
    except VerificationFailed as exc:
        return exc.reason


def test_an_expired_token_is_refused(jwks, profile, flags) -> None:
    flags(transaction_token_ttl_seconds=-3600)
    grant_raw = _grant(profile)
    hop = profile.verify(grant_raw, audience=TERMINATE_ACCOUNT)
    txn = profile.mint_transaction_token(
        hop=hop,
        params_hash=binding_hash(TERMINATE_ACCOUNT, TERMINATE_PARAMS, TERMINATE_BINDING),
        binding=TERMINATE_BINDING,
    )
    with pytest.raises(VerificationFailed) as exc:
        _verify(jwks, grant_raw, txn)
    assert exc.value.reason == "TXN_EXPIRED"


def test_the_hop_token_alone_is_not_call_bound_authority(jwks, minted) -> None:
    grant_raw, _ = minted
    with pytest.raises(VerificationFailed) as exc:
        _verify(jwks, grant_raw, None)
    assert exc.value.reason == "TXN_MISSING"
    with pytest.raises(VerificationFailed) as exc:
        _verify(jwks, grant_raw, grant_raw)  # a hop token where a txn token belongs
    assert exc.value.reason == "TXN_INVALID"


def test_a_transaction_token_for_another_grant_is_refused(jwks, profile, minted) -> None:
    """Same target, different decision: the txn token names an action_id the grant does not."""
    _, txn = minted
    other = profile.mint_hop_token(
        sub=USER,
        target=TERMINATE_ACCOUNT,
        data_class="account.write",
        session_id="s1",
        policy_version=3,
        hop=3,
        act=nest(nest(None, "agent://balance-agent"), "agent://support-agent"),
        action_id="7c1e0000-0000-4000-8000-0000000000bb",
    )
    with pytest.raises(VerificationFailed) as exc:
        _verify(jwks, other, txn)
    assert exc.value.reason == "TXN_GRANT_MISMATCH"


def test_a_replay_store_that_cannot_answer_refuses(jwks, minted) -> None:
    class _Broken:
        def set(self, *a, **kw):
            raise ConnectionError("redis is down")

    grant_raw, txn = minted
    with pytest.raises(VerificationFailed) as exc:
        _verify(jwks, grant_raw, txn, replay=RedisReplay(_Broken()))
    assert exc.value.reason == "REPLAY_STORE_UNAVAILABLE"


def test_in_memory_store_expires_claims() -> None:
    now = [100.0]
    store = InMemoryReplay(clock=lambda: now[0])
    assert store.claim("k", 10) is True
    assert store.claim("k", 10) is False
    now[0] = 111.0
    assert store.claim("k", 10) is True


def test_store_unavailable_is_exported() -> None:
    assert issubclass(ReplayStoreUnavailable, RuntimeError)
