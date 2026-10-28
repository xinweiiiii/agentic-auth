"""``admit()`` is a conjunction: identity AND grant AND, when privileged, transaction
(US3, T058; spec FR-033..FR-037, SC-007)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from app.schemas.authorize import Taint
from app.services.tokens.act_chain import nest
from app.services.tokens.jwt_profile import JwtTokenProfile
from app.services.tokens.keys import load_or_generate
from app.verify import InMemoryReplay, StaticAnchors, StaticJwks, Verifier, binding_hash
from tests.fixtures.identity import agent_keypair, identity_assertion

USER = "user:alice"
SUPPORT = "support-agent"
BALANCE = "balance-agent"
TERMINATE = "mcp://accounts.internal/terminate_account"
READ_BALANCE = "mcp://accounts.internal/read_balance"
PARAMS = {"account_id": "acc-42", "reason": "fraud"}
BINDING = ["/account_id"]
ACTION_ID = "7c1e0000-0000-4000-8000-00000000c0de"


@pytest.fixture(scope="module")
def issuer() -> JwtTokenProfile:
    return JwtTokenProfile(load_or_generate(), issuer="agentic-auth", ttl_seconds=60)


@pytest.fixture(scope="module")
def support_key():
    return agent_keypair(SUPPORT, kid="sa-k1")


@pytest.fixture(scope="module")
def rotated_out_key():
    return agent_keypair(SUPPORT, kid="sa-k0")


def _anchor_read(name: str, key, *, status="enrolled", version=1, revoked=False) -> dict:
    return {
        "agent": name,
        "status": status,
        "trust_anchor_version": version,
        "jwks": {"keys": [key.jwk()]},
        "principal_ref": "https://idp.example#alice",
        "manifest_version": 1,
        "revoked": revoked,
        "revoked_at": None,
        "as_of": datetime.now(UTC).isoformat(),
    }


@pytest.fixture
def verifier(issuer, support_key):
    anchors = StaticAnchors(
        [
            _anchor_read(SUPPORT, support_key),
            _anchor_read(BALANCE, agent_keypair(BALANCE), status="quarantined", version=None),
        ]
    )
    return Verifier(
        issuer_jwks=StaticJwks(issuer.jwks()),
        anchors=anchors,
        replay=InMemoryReplay(),
        identity_required=True,
        freshness_seconds=30,
    )


def _grant(issuer, target=TERMINATE, *, holder=SUPPORT, action_id=ACTION_ID) -> str:
    return issuer.mint_hop_token(
        sub=USER,
        target=target,
        data_class="account.write",
        session_id="s1",
        policy_version=3,
        hop=3,
        act=nest(nest(None, f"agent://{BALANCE}"), f"agent://{holder}"),
        action_id=action_id,
        taint=Taint.TRUSTED_INTERNAL,
    )


def _txn(issuer, grant: str, target=TERMINATE, params=PARAMS) -> str:
    hop = issuer.verify(grant, audience=target)
    return issuer.mint_transaction_token(
        hop=hop, params_hash=binding_hash(target, params, BINDING), binding=BINDING
    )


def _headers(grant=None, identity=None, txn=None) -> dict[str, str]:
    h: dict[str, str] = {}
    if grant:
        h["Authorization"] = f"Bearer {grant}"
    if identity:
        h["Agent-Identity"] = identity
    if txn:
        h["Txn-Token"] = txn
    return h


# -- the matrix -------------------------------------------------------------------------


def test_identity_and_matching_grant_are_admitted(verifier, issuer, support_key) -> None:
    grant = _grant(issuer, READ_BALANCE)
    ident = identity_assertion(support_key, grant, READ_BALANCE)
    a = verifier.admit(_headers(grant, ident), target=READ_BALANCE)
    assert a.ok and a.grant is not None and a.identity is not None
    assert a.identity.agent == SUPPORT and a.grant.action_id == ACTION_ID


def test_identity_only_is_refused(verifier, issuer, support_key) -> None:
    grant = _grant(issuer, READ_BALANCE)
    ident = identity_assertion(support_key, grant, READ_BALANCE)
    a = verifier.admit(_headers(identity=ident), target=READ_BALANCE)
    assert not a.ok and a.reason == "GRANT_MISSING"


def test_grant_only_is_refused(verifier, issuer) -> None:
    a = verifier.admit(_headers(_grant(issuer, READ_BALANCE)), target=READ_BALANCE)
    assert not a.ok and a.reason == "IDENTITY_MISSING"


def test_identity_signed_by_a_non_pinned_key_is_refused(verifier, issuer, rotated_out_key) -> None:
    grant = _grant(issuer, READ_BALANCE)
    ident = identity_assertion(rotated_out_key, grant, READ_BALANCE)
    a = verifier.admit(_headers(grant, ident), target=READ_BALANCE)
    assert not a.ok and a.reason == "IDENTITY_INVALID"


def test_grant_for_another_target_is_refused_even_with_identity(
    verifier, issuer, support_key
) -> None:
    grant = _grant(issuer, TERMINATE)
    ident = identity_assertion(support_key, grant, READ_BALANCE)
    a = verifier.admit(_headers(grant, ident), target=READ_BALANCE)
    assert not a.ok and a.reason == "GRANT_TARGET_MISMATCH"


def test_identity_bound_to_a_different_grant_is_refused(verifier, issuer, support_key) -> None:
    grant = _grant(issuer, READ_BALANCE)
    other = _grant(issuer, READ_BALANCE, action_id="7c1e0000-0000-4000-8000-000000000bad")
    ident = identity_assertion(support_key, other, READ_BALANCE)
    a = verifier.admit(_headers(grant, ident), target=READ_BALANCE)
    assert not a.ok and a.reason == "IDENTITY_INVALID"


def test_identity_for_another_agent_is_refused(verifier, issuer, support_key) -> None:
    grant = _grant(issuer, READ_BALANCE)
    ident = identity_assertion(support_key, grant, READ_BALANCE, sub=f"agent://{BALANCE}")
    a = verifier.admit(_headers(grant, ident), target=READ_BALANCE)
    assert not a.ok and a.reason == "IDENTITY_INVALID"


def test_privileged_without_txn_token_is_refused(verifier, issuer, support_key) -> None:
    grant = _grant(issuer)
    ident = identity_assertion(support_key, grant, TERMINATE)
    a = verifier.admit(_headers(grant, ident), target=TERMINATE, params=PARAMS, privileged=True)
    assert not a.ok and a.reason == "TXN_MISSING"


def test_all_three_valid_are_admitted_once(verifier, issuer, support_key) -> None:
    grant = _grant(issuer)
    ident = identity_assertion(support_key, grant, TERMINATE)
    txn = _txn(issuer, grant)
    a = verifier.admit(
        _headers(grant, ident, txn), target=TERMINATE, params=PARAMS, privileged=True
    )
    assert a.ok and a.transaction is not None and a.transaction.action_id == ACTION_ID
    again = verifier.admit(
        _headers(grant, ident, txn), target=TERMINATE, params=PARAMS, privileged=True
    )
    assert not again.ok and again.reason == "TXN_REPLAY"


def test_a_quarantined_or_unknown_agent_has_no_identity(verifier, issuer) -> None:
    key = agent_keypair(BALANCE)
    grant = _grant(issuer, READ_BALANCE, holder=BALANCE)
    a = verifier.admit(
        _headers(grant, identity_assertion(key, grant, READ_BALANCE)), target=READ_BALANCE
    )
    assert not a.ok and a.reason == "IDENTITY_UNKNOWN_AGENT"
    ghost = agent_keypair("ghost")
    grant = _grant(issuer, READ_BALANCE, holder="ghost")
    a = verifier.admit(
        _headers(grant, identity_assertion(ghost, grant, READ_BALANCE)), target=READ_BALANCE
    )
    assert not a.ok and a.reason == "IDENTITY_UNKNOWN_AGENT"


def test_a_revoked_agent_is_refused(issuer, support_key) -> None:
    anchors = StaticAnchors([_anchor_read(SUPPORT, support_key)])
    anchors.revoke(SUPPORT)
    v = Verifier(StaticJwks(issuer.jwks()), anchors, InMemoryReplay(), identity_required=True)
    grant = _grant(issuer, READ_BALANCE)
    a = v.admit(
        _headers(grant, identity_assertion(support_key, grant, READ_BALANCE)), target=READ_BALANCE
    )
    assert not a.ok and a.reason == "IDENTITY_REVOKED"


def test_a_root_grant_is_never_valid_at_a_resource(verifier, issuer, support_key) -> None:
    root = issuer.mint_root_grant(
        sub=USER, scope="bank-assistant", session_id="s1", policy_version=1
    )
    a = verifier.admit(_headers(root), target="bank-assistant")
    assert not a.ok and a.reason == "GRANT_INVALID"


def test_identity_not_required_skips_the_identity_step(issuer, support_key) -> None:
    v = Verifier(
        StaticJwks(issuer.jwks()),
        StaticAnchors([]),
        InMemoryReplay(),
        identity_required=False,
    )
    a = v.admit(_headers(_grant(issuer, READ_BALANCE)), target=READ_BALANCE)
    assert a.ok and a.identity is None


def test_the_conjunction_never_admits_on_identity_alone_whatever_the_grant(
    verifier, issuer, support_key
) -> None:
    """A passing identity paired with a failing grant is refused WITH THE GRANT REASON."""
    grant = _grant(issuer, READ_BALANCE)
    ident = identity_assertion(support_key, grant, READ_BALANCE)
    forged_grant = grant[:-4] + "AAAA"
    a = verifier.admit(_headers(forged_grant, ident), target=READ_BALANCE)
    assert not a.ok and a.reason == "GRANT_INVALID"


def test_a_stale_anchor_view_refuses_every_identity(issuer, support_key) -> None:
    anchors = StaticAnchors([_anchor_read(SUPPORT, support_key)])
    anchors._as_of = datetime.now(UTC) - timedelta(seconds=120)  # 4x the window
    v = Verifier(StaticJwks(issuer.jwks()), anchors, InMemoryReplay(), freshness_seconds=30)
    grant = _grant(issuer, READ_BALANCE)
    a = v.admit(
        _headers(grant, identity_assertion(support_key, grant, READ_BALANCE)), target=READ_BALANCE
    )
    assert not a.ok and a.reason == "IDENTITY_STALE"


def test_metrics_count_admissions_and_rejection_causes(issuer, support_key) -> None:
    from prometheus_client import CollectorRegistry

    registry = CollectorRegistry()
    v = Verifier(
        StaticJwks(issuer.jwks()),
        StaticAnchors([_anchor_read(SUPPORT, support_key)]),
        InMemoryReplay(),
        metrics_registry=registry,
    )
    grant = _grant(issuer)
    ident = identity_assertion(support_key, grant, TERMINATE)
    txn = _txn(issuer, grant)
    v.admit(_headers(grant, ident, txn), target=TERMINATE, params=PARAMS, privileged=True)
    v.admit(_headers(grant, ident, txn), target=TERMINATE, params=PARAMS, privileged=True)
    v.admit(
        _headers(grant, ident, txn), target=TERMINATE, params={"account_id": "x"}, privileged=True
    )
    assert registry.get_sample_value("agentic_auth_admissions_total", {"result": "admitted"}) == 1
    assert registry.get_sample_value("agentic_auth_admissions_total", {"result": "TXN_REPLAY"}) == 1
    assert (
        registry.get_sample_value("agentic_auth_transaction_rejections_total", {"cause": "replay"})
        == 1
    )
    assert (
        registry.get_sample_value(
            "agentic_auth_transaction_rejections_total", {"cause": "params_mismatch"}
        )
        == 1
    )


def test_agent_key_repr_never_shows_the_key(support_key) -> None:
    from app.sdk.identity import AgentKey

    key = AgentKey.load(support_key.private_pem().decode(), kid="k")
    assert "PRIVATE" not in repr(key) and "-----" not in repr(key)


# -- mutation-testing gaps (T083) -----------------------------------------------------------------


def _foreign_issuer(issuer) -> JwtTokenProfile:
    """Same signing key, different `iss`: only the issuer check can tell it apart."""
    return JwtTokenProfile(issuer._key, issuer="evil", ttl_seconds=60)


def test_a_grant_from_another_issuer_name_is_refused(verifier, issuer, support_key) -> None:
    evil = _foreign_issuer(issuer)
    grant = _grant(evil, READ_BALANCE)
    a = verifier.admit(
        _headers(grant, identity_assertion(support_key, grant, READ_BALANCE)), target=READ_BALANCE
    )
    assert a.ok is False and a.reason == "GRANT_INVALID"


def test_a_transaction_token_from_another_issuer_name_is_refused(
    verifier, issuer, support_key
) -> None:
    grant = _grant(issuer)
    evil = _foreign_issuer(issuer)
    txn = _txn(evil, _grant(evil))  # an `evil`-issued txn for the same target and action
    a = verifier.admit(
        _headers(grant, identity_assertion(support_key, grant, TERMINATE), txn),
        target=TERMINATE,
        params=PARAMS,
        privileged=True,
    )
    assert a.ok is False and a.reason == "TXN_INVALID"


def test_the_default_issuer_is_agentic_auth(issuer, support_key) -> None:
    from app.verify.admit import admit

    grant = _grant(issuer, READ_BALANCE)
    a = admit(
        _headers(grant, identity_assertion(support_key, grant, READ_BALANCE)),
        target=READ_BALANCE,
        params=None,
        privileged=False,
        issuer_jwks=StaticJwks(issuer.jwks()),
        anchors=StaticAnchors([_anchor_read(SUPPORT, support_key)]),
        replay=InMemoryReplay(),
        identity_required=True,
        freshness_seconds=30,
    )
    assert a.ok is True


def test_a_refusal_is_a_real_false_not_a_falsy_value(verifier) -> None:
    a = verifier.admit({}, target=READ_BALANCE)
    assert a.ok is False and a.grant is None and a.identity is None and a.transaction is None


def test_leeway_is_honoured_at_every_step(issuer, support_key) -> None:
    """An 8-second-old grant, assertion or transaction token passes with 60 s of leeway and
    is refused with none — so the value reaches all three verifiers, one at a time."""

    def verifier_with(leeway: int) -> Verifier:
        return Verifier(
            StaticJwks(issuer.jwks()),
            StaticAnchors([_anchor_read(SUPPORT, support_key)]),
            InMemoryReplay(),
            leeway_seconds=leeway,
        )

    # grant only: stale grant, fresh assertion
    stale_issuer = JwtTokenProfile(issuer._key, issuer="agentic-auth", ttl_seconds=-8)
    stale_grant = _grant(stale_issuer, READ_BALANCE)
    ident = identity_assertion(support_key, stale_grant, READ_BALANCE)
    headers = _headers(stale_grant, ident)
    assert verifier_with(60).admit(headers, target=READ_BALANCE).ok is True
    refused = verifier_with(0).admit(headers, target=READ_BALANCE)
    assert refused.ok is False and refused.reason == "GRANT_EXPIRED"

    # identity only: fresh grant, stale assertion
    fresh = _grant(issuer, READ_BALANCE)
    stale_ident = identity_assertion(support_key, fresh, READ_BALANCE, lifetime=-8)
    headers = _headers(fresh, stale_ident)
    assert verifier_with(60).admit(headers, target=READ_BALANCE).ok is True
    refused = verifier_with(0).admit(headers, target=READ_BALANCE)
    assert refused.ok is False and refused.reason == "IDENTITY_INVALID"

    # transaction only: fresh grant, fresh assertion, stale transaction token
    from app.config import get_settings

    fresh_t = _grant(issuer)
    ident_t = identity_assertion(support_key, fresh_t, TERMINATE)
    settings = get_settings()
    previous = settings.transaction_token_ttl_seconds
    settings.transaction_token_ttl_seconds = -8
    try:
        stale_txn = _txn(issuer, fresh_t)
    finally:
        settings.transaction_token_ttl_seconds = previous
    headers = _headers(fresh_t, ident_t, stale_txn)
    ok = verifier_with(60).admit(headers, target=TERMINATE, params=PARAMS, privileged=True)
    assert ok.ok is True
    refused = verifier_with(0).admit(headers, target=TERMINATE, params=PARAMS, privileged=True)
    assert refused.ok is False and refused.reason == "TXN_EXPIRED"


def test_a_custom_issuer_name_reaches_the_grant_and_transaction_checks(support_key) -> None:
    """Grant, identity and transaction tokens issued as `acme` are admitted by a verifier
    configured for `acme` — and refused by the default one."""
    acme = JwtTokenProfile(load_or_generate(), issuer="acme", ttl_seconds=60)
    grant = _grant(acme)
    txn = _txn(acme, grant)
    headers = _headers(grant, identity_assertion(support_key, grant, TERMINATE), txn)

    def verifier(issuer_name: str) -> Verifier:
        return Verifier(
            StaticJwks(acme.jwks()),
            StaticAnchors([_anchor_read(SUPPORT, support_key)]),
            InMemoryReplay(),
            issuer=issuer_name,
        )

    admitted = verifier("acme").admit(headers, target=TERMINATE, params=PARAMS, privileged=True)
    assert admitted.ok is True and admitted.transaction is not None
    refused = verifier("agentic-auth").admit(
        headers, target=TERMINATE, params=PARAMS, privileged=True
    )
    assert refused.ok is False and refused.reason == "GRANT_INVALID"


def test_a_transaction_from_the_wrong_issuer_alone_is_refused_at_the_txn_step(
    issuer, support_key
) -> None:
    """The grant verifies (right issuer); only the transaction token has the wrong `iss`."""
    grant = _grant(issuer)
    evil = _foreign_issuer(issuer)
    txn = evil.mint_transaction_token(
        hop=issuer.verify(grant, audience=TERMINATE),
        params_hash=binding_hash(TERMINATE, PARAMS, BINDING),
        binding=BINDING,
    )
    v = Verifier(
        StaticJwks(issuer.jwks()),
        StaticAnchors([_anchor_read(SUPPORT, support_key)]),
        InMemoryReplay(),
    )
    a = v.admit(
        _headers(grant, identity_assertion(support_key, grant, TERMINATE), txn),
        target=TERMINATE,
        params=PARAMS,
        privileged=True,
    )
    assert a.ok is False and a.reason == "TXN_INVALID"


def test_a_refusal_explains_itself_and_an_ordinary_admission_carries_no_transaction(
    verifier, issuer, support_key
) -> None:
    refused = verifier.admit({}, target=READ_BALANCE)
    assert refused.detail and "bearer" in refused.detail.lower()
    assert refused.details == {"reason": "GRANT_MISSING", "detail": refused.detail}

    grant = _grant(issuer, READ_BALANCE)
    ok = verifier.admit(
        _headers(grant, identity_assertion(support_key, grant, READ_BALANCE)), target=READ_BALANCE
    )
    assert ok.ok is True and ok.transaction is None and ok.detail is None and ok.reason is None
