"""The one inbound-token validator (feature 011, research R2).

Used by the connector proxy, the gateway, consent, enrollment binding and step-up, so this
file is the conformance surface for all of them. Tokens are real, signed by the fake IdP;
the refusal cases are tokens an attacker could actually send.
"""

from __future__ import annotations

import hashlib

import httpx
import pytest
from httpx import ASGITransport

from agentic_auth.oauth.validate import (
    DEFAULT_ALGORITHMS,
    Check,
    IdpUnavailable,
    JwksCache,
    TokenInvalid,
    TokenValidator,
    check_algorithms,
    fingerprint,
)
from tests.fixtures.idp.server import AUDIENCE, ISSUER, JWKS_URL, FakeIdp, build_idp

RESOURCE = "https://mcp-proxy.example.com"


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def idp() -> FakeIdp:
    return FakeIdp()


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def cache(idp: FakeIdp, clock: Clock) -> JwksCache:
    app, _ = build_idp(idp)
    http = httpx.AsyncClient(transport=ASGITransport(app=app))
    return JwksCache(JWKS_URL, lambda: http, clock=clock)


@pytest.fixture
def validator(cache: JwksCache) -> TokenValidator:
    return TokenValidator(issuer=ISSUER, audiences=[RESOURCE, AUDIENCE], jwks=cache)


async def _refused(validator: TokenValidator, token: str) -> Check:
    with pytest.raises(TokenInvalid) as caught:
        await validator.validate(token)
    assert token not in str(caught.value)
    for segment in token.split("."):
        if len(segment) >= 8:
            assert segment not in str(caught.value)
    return caught.value.check


# -- accepted ------------------------------------------------------------------------


async def test_a_valid_access_token_becomes_an_inbound_token(idp, validator) -> None:
    token = idp.mint_access_token(aud=RESOURCE, scope="kb.public account.read")
    inbound = await validator.validate(token)

    assert inbound.issuer == ISSUER
    assert inbound.subject == "alice"
    assert inbound.principal == f"{ISSUER}#alice"
    assert inbound.client_id == "desktop-client"
    assert inbound.audiences == (RESOURCE,)
    assert inbound.scopes == ("kb.public", "account.read")
    assert inbound.fingerprint == hashlib.sha256(token.encode()).hexdigest()[:16]
    assert token not in repr(inbound)


async def test_one_of_several_audiences_matching_exactly_is_enough(idp, validator) -> None:
    token = idp.mint_access_token(aud=["https://other.example.com", RESOURCE])
    assert (await validator.validate(token)).audiences == ("https://other.example.com", RESOURCE)


async def test_client_id_falls_back_to_the_client_id_claim(idp, validator) -> None:
    token = idp.mint_access_token(aud=RESOURCE, azp=None, extra={"client_id": "cli-client"})
    assert (await validator.validate(token)).client_id == "cli-client"


async def test_no_client_claim_means_no_client(idp, validator) -> None:
    token = idp.mint_access_token(aud=RESOURCE, azp=None)
    inbound = await validator.validate(token)
    assert inbound.client_id is None
    assert inbound.scopes == ()


@pytest.mark.parametrize("seconds", [-30, 30])
async def test_clock_skew_inside_the_leeway_is_tolerated(idp, validator, seconds) -> None:
    if seconds < 0:
        token = idp.mint_access_token(aud=RESOURCE, expires_in=seconds)
    else:
        token = idp.mint_access_token(aud=RESOURCE, not_before=seconds)
    await validator.validate(token)


# -- refused -------------------------------------------------------------------------


async def test_a_bad_signature_is_refused(idp, validator) -> None:
    head, body, _ = idp.mint_access_token(aud=RESOURCE).split(".")
    _, _, other = FakeIdp().mint_access_token(aud=RESOURCE, kid=idp.kid).split(".")
    assert await _refused(validator, f"{head}.{body}.{other}") is Check.SIGNATURE


async def test_another_issuer_is_refused(idp, validator) -> None:
    token = idp.mint_access_token(aud=RESOURCE, issuer="https://evil.example.com")
    assert await _refused(validator, token) is Check.ISSUER


async def test_an_audience_that_only_resembles_ours_is_refused(idp, validator) -> None:
    for aud in [f"{RESOURCE}/", f"{RESOURCE}.evil.com", "https://mcp-proxy.example"]:
        token = idp.mint_access_token(aud=aud)
        assert await _refused(validator, token) is Check.AUDIENCE


async def test_an_expired_token_is_refused(idp, validator) -> None:
    token = idp.mint_access_token(aud=RESOURCE, expires_in=-120)
    assert await _refused(validator, token) is Check.EXPIRED


async def test_a_token_not_yet_valid_is_refused(idp, validator) -> None:
    token = idp.mint_access_token(aud=RESOURCE, not_before=120)
    assert await _refused(validator, token) is Check.NOT_YET_VALID


@pytest.mark.parametrize("alg", ["none", "HS256", "HS512"])
async def test_algorithms_an_attacker_chooses_are_refused(idp, validator, alg) -> None:
    token = idp.mint_access_token(aud=RESOURCE, alg=alg)
    assert await _refused(validator, token) is Check.ALGORITHM


async def test_an_algorithm_outside_the_operators_list_is_refused(idp, cache) -> None:
    validator = TokenValidator(
        issuer=ISSUER, audiences=[RESOURCE], jwks=cache, algorithms=["RS256"]
    )
    token = idp.mint_access_token(aud=RESOURCE)  # EdDSA
    assert await _refused(validator, token) is Check.ALGORITHM


@pytest.mark.parametrize("claim", ["sub", "exp", "iss", "aud"])
async def test_a_missing_required_claim_is_refused(idp, validator, claim) -> None:
    token = idp.mint_access_token(aud=RESOURCE, drop=(claim,))
    assert await _refused(validator, token) is Check.MALFORMED


@pytest.mark.parametrize("token", ["", "not-a-jwt", "a.b", "a.b.c", "Bearer x.y.z"])
async def test_garbage_is_malformed(validator, token) -> None:
    with pytest.raises(TokenInvalid) as caught:
        await validator.validate(token)
    assert caught.value.check is Check.MALFORMED


async def test_a_non_string_subject_is_malformed(idp, validator) -> None:
    token = idp.mint_access_token(aud=RESOURCE, extra={"sub": 42})
    assert await _refused(validator, token) is Check.MALFORMED


# -- keys: rotation, refresh limits, outages ----------------------------------------


async def test_a_rotated_key_is_picked_up_with_one_refresh(idp, validator) -> None:
    await validator.validate(idp.mint_access_token(aud=RESOURCE))
    fetches = idp.jwks_fetches
    idp.rotate()
    await validator.validate(idp.mint_access_token(aud=RESOURCE))
    assert idp.jwks_fetches == fetches + 1


async def test_an_unknown_kid_refreshes_at_most_once_per_30_seconds(idp, validator, clock) -> None:
    await validator.validate(idp.mint_access_token(aud=RESOURCE))
    fetches = idp.jwks_fetches

    for _ in range(5):
        token = idp.mint_access_token(aud=RESOURCE, kid="unknown-kid")
        assert await _refused(validator, token) is Check.SIGNATURE
    assert idp.jwks_fetches == fetches + 1

    clock.now += 31
    await _refused(validator, idp.mint_access_token(aud=RESOURCE, kid="unknown-kid"))
    assert idp.jwks_fetches == fetches + 2


async def test_a_warm_cache_survives_an_idp_outage(idp, validator) -> None:
    await validator.validate(idp.mint_access_token(aud=RESOURCE))
    idp.down = True
    await validator.validate(idp.mint_access_token(aud=RESOURCE))


async def test_a_cold_cache_with_the_idp_down_fails_closed(idp, validator) -> None:
    idp.down = True
    with pytest.raises(IdpUnavailable):
        await validator.validate(idp.mint_access_token(aud=RESOURCE))


async def test_an_expired_cache_with_the_idp_down_fails_closed(idp, validator, clock) -> None:
    await validator.validate(idp.mint_access_token(aud=RESOURCE))
    idp.down = True
    clock.now += 3601
    with pytest.raises(IdpUnavailable):
        await validator.validate(idp.mint_access_token(aud=RESOURCE))


async def test_a_network_error_is_unavailability(clock) -> None:
    def failing() -> httpx.AsyncClient:
        def boom(_: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("no route")

        return httpx.AsyncClient(transport=httpx.MockTransport(boom))

    validator = TokenValidator(
        issuer=ISSUER, audiences=[RESOURCE], jwks=JwksCache(JWKS_URL, failing, clock=clock)
    )
    with pytest.raises(IdpUnavailable):
        await validator.validate(FakeIdp().mint_access_token(aud=RESOURCE))


@pytest.mark.parametrize(
    ("cache_control", "ttl"),
    [
        (None, 300),
        ("max-age=10", 300),
        ("public, max-age=900", 900),
        ("max-age=86400", 3600),
        ("no-store", 300),
        ("max-age=nonsense", 300),
    ],
)
async def test_the_cache_lifetime_is_clamped_to_5_to_60_minutes(clock, cache_control, ttl) -> None:
    idp = FakeIdp()
    fetches = 0

    def handler(_: httpx.Request) -> httpx.Response:
        nonlocal fetches
        fetches += 1
        headers = {"cache-control": cache_control} if cache_control else {}
        return httpx.Response(200, json=idp.jwks(), headers=headers)

    http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    validator = TokenValidator(
        issuer=ISSUER, audiences=[RESOURCE], jwks=JwksCache(JWKS_URL, lambda: http, clock=clock)
    )
    await validator.validate(idp.mint_access_token(aud=RESOURCE))
    clock.now += ttl - 1
    await validator.validate(idp.mint_access_token(aud=RESOURCE))
    assert fetches == 1
    clock.now += 2
    await validator.validate(idp.mint_access_token(aud=RESOURCE))
    assert fetches == 2


@pytest.mark.parametrize("body", [b"not json", b"[]", b'{"keys": "nope"}'])
async def test_a_malformed_jwks_is_unavailability(clock, body) -> None:
    http = httpx.AsyncClient(
        transport=httpx.MockTransport(lambda _: httpx.Response(200, content=body))
    )
    validator = TokenValidator(
        issuer=ISSUER, audiences=[RESOURCE], jwks=JwksCache(JWKS_URL, lambda: http, clock=clock)
    )
    with pytest.raises(IdpUnavailable):
        await validator.validate(FakeIdp().mint_access_token(aud=RESOURCE))


# -- configuration -------------------------------------------------------------------


def test_the_default_algorithms_are_asymmetric_only() -> None:
    assert DEFAULT_ALGORITHMS == ("RS256", "ES256", "EdDSA")


@pytest.mark.parametrize("algorithms", [["none"], ["HS256"], ["RS256", "hs384"], [], ["XX999"]])
def test_unsafe_or_unknown_algorithm_lists_are_refused(algorithms) -> None:
    with pytest.raises(ValueError):
        check_algorithms(algorithms)


def test_a_validator_needs_an_audience(cache) -> None:
    with pytest.raises(ValueError, match="audience"):
        TokenValidator(issuer=ISSUER, audiences=[], jwks=cache)


def test_the_fingerprint_is_16_hex_characters_of_sha256() -> None:
    assert fingerprint("abc") == hashlib.sha256(b"abc").hexdigest()[:16]


async def test_unusable_jwks_entries_do_not_hide_the_valid_key(clock) -> None:
    """A JWKS may carry keys this verifier cannot use; skipping them must not stop at them."""
    idp = FakeIdp()
    noise = [
        "not-an-object",
        {"kty": "OKP", "crv": "Ed25519"},  # no kid
        {"kid": "rsa-broken", "kty": "RSA", "n": "!!", "e": "AQAB"},  # unusable
    ]
    body = {"keys": [*noise, *idp.jwks()["keys"]]}
    http = httpx.AsyncClient(
        transport=httpx.MockTransport(lambda _: httpx.Response(200, json=body))
    )
    validator = TokenValidator(
        issuer=ISSUER, audiences=[RESOURCE], jwks=JwksCache(JWKS_URL, lambda: http, clock=clock)
    )
    assert (await validator.validate(idp.mint_access_token(aud=RESOURCE))).subject == "alice"
