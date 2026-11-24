"""M1 start-up refusals for a connector proxy or gateway (feature 011, FR-020, quickstart V10).

Each names the setting to fix. A proxy that comes up as a protected resource but cannot
validate tokens, or cannot start sessions, is worse than one that refuses to start.
"""

from __future__ import annotations

import pytest

from agentic_auth.gateway.config import GatewayConfig, GatewayConfigError, load
from agentic_auth.sidecar.config import Upstream

TABLE = {(None, "/mcp"): Upstream(url="http://kb.internal", data_class="kb.public")}

M1 = {
    "oauth_resource_enabled": True,
    "resource_url": "https://mcp-proxy.example.com",
    "idp_issuer": "https://idp.example.com",
    "idp_jwks_url": "https://idp.example.com/.well-known/jwks.json",
    "consent_token": "consent-secret",
}


def _config(**overrides) -> GatewayConfig:
    return GatewayConfig(pdp_url="http://pdp.test", **{"route_table": TABLE, **M1, **overrides})


def test_m1_with_every_required_setting_starts() -> None:
    config = _config().validate()
    assert config.oauth_resource_enabled
    assert config.idp_algorithms == ("RS256", "ES256", "EdDSA")
    assert config.clock_leeway_seconds == 60
    assert config.session_cache_size == 10_000
    assert "consent-secret" not in repr(config)


def test_m1_is_off_by_default_and_needs_nothing() -> None:
    config = GatewayConfig(pdp_url="http://pdp.test", route_table=TABLE).validate()
    assert not config.oauth_resource_enabled


@pytest.mark.parametrize(
    ("setting", "env_name"),
    [
        ("resource_url", "RESOURCE_URL"),
        ("idp_issuer", "IDP_ISSUER"),
        ("consent_token", "CONSENT_TOKEN"),
    ],
)
def test_a_missing_required_setting_is_named(setting, env_name) -> None:
    with pytest.raises(GatewayConfigError, match=f"AGENTIC_AUTH_GATEWAY_{env_name}"):
        _config(**{setting: ""}).validate()


@pytest.mark.parametrize("url", ["http://mcp-proxy.example.com", "mcp-proxy.example.com"])
def test_a_resource_url_that_is_not_https_is_refused(url) -> None:
    with pytest.raises(GatewayConfigError, match="RESOURCE_URL"):
        _config(resource_url=url).validate()


def test_http_localhost_is_allowed_only_in_development() -> None:
    with pytest.raises(GatewayConfigError, match="AGENTIC_AUTH_DEV"):
        _config(resource_url="http://localhost:8090").validate()
    assert _config(resource_url="http://localhost:8090", dev=True).validate()
    with pytest.raises(GatewayConfigError):
        _config(resource_url="http://example.com", dev=True).validate()


def test_observe_mode_with_m1_is_refused() -> None:
    with pytest.raises(GatewayConfigError, match="observe"):
        _config(observe_mode=True).validate()


@pytest.mark.parametrize("algorithms", [("HS256",), ("none",), ("RS256", "HS512"), ()])
def test_unsafe_idp_algorithms_are_refused(algorithms) -> None:
    with pytest.raises(GatewayConfigError, match="IDP_ALGORITHMS"):
        _config(idp_algorithms=algorithms).validate()


@pytest.mark.parametrize("leeway", [-1, 301])
def test_the_clock_leeway_is_bounded(leeway) -> None:
    with pytest.raises(GatewayConfigError, match="CLOCK_LEEWAY_SECONDS"):
        _config(clock_leeway_seconds=leeway).validate()


def test_the_session_cache_needs_room() -> None:
    with pytest.raises(GatewayConfigError, match="SESSION_CACHE_SIZE"):
        _config(session_cache_size=0).validate()


def test_a_consent_scope_and_an_asserted_root_scope_together_are_refused() -> None:
    with pytest.raises(GatewayConfigError, match="ASSERTED_ROOT_SCOPE"):
        _config(consent_scope="a", asserted_root_scope="b").validate()


def test_m1_settings_load_from_the_environment(monkeypatch) -> None:
    env = {
        "PDP_URL": "http://pdp.test",
        "ROUTE_TABLE": '{"|/mcp": {"url": "http://kb.internal", "data_class": "kb.public"}}',
        "OAUTH_RESOURCE_ENABLED": "true",
        "RESOURCE_URL": "https://mcp-proxy.example.com",
        "IDP_ISSUER": "https://idp.example.com",
        "IDP_JWKS_URL": "https://idp.example.com/jwks",
        "IDP_ALGORITHMS": "RS256,EdDSA",
        "CLOCK_LEEWAY_SECONDS": "30",
        "CONSENT_TOKEN": "consent-secret",
        "SESSION_CACHE_SIZE": "500",
        "CONSENT_SCOPE": "orchestrator",
    }
    for name, value in env.items():
        monkeypatch.setenv(f"AGENTIC_AUTH_GATEWAY_{name}", value)

    config = load()
    assert config.oauth_resource_enabled
    assert config.resource_url == "https://mcp-proxy.example.com"
    assert config.idp_algorithms == ("RS256", "EdDSA")
    assert config.clock_leeway_seconds == 30
    assert config.session_cache_size == 500
    assert config.consent_scope == "orchestrator"
    assert config.consent_token == "consent-secret"


def test_the_data_classes_the_routes_carry_are_the_scopes() -> None:
    table = {
        **TABLE,
        (None, "/acct"): Upstream(url="http://accounts.internal", data_class="account.read"),
        (None, "/bare"): Upstream(url="http://bare.internal"),
    }
    config = _config(route_table=table).validate()
    assert config.scopes_supported == ("account.read", "kb.public")


# -- the IdP's keys are fetched before serving (contracts/protected-resource.md) ------------


async def test_start_up_fails_when_the_idp_keys_cannot_be_fetched() -> None:
    import httpx

    from agentic_auth.oauth.resource import startup_check

    http = httpx.AsyncClient(transport=httpx.MockTransport(lambda _: httpx.Response(503)))
    problem = await startup_check(_config().validate(), http)
    assert problem is not None and "IDP_JWKS_URL" in problem

    discovering = _config(idp_jwks_url="").validate()
    problem = await startup_check(discovering, http)
    assert problem is not None and "IDP_ISSUER" in problem


async def test_start_up_discovers_the_jwks_when_no_url_is_set() -> None:
    import httpx

    from tests.fixtures.idp.server import FakeIdp

    idp = FakeIdp(issuer="https://idp.example.com")

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/oauth-authorization-server"):
            return httpx.Response(200, json=idp.discovery())
        return httpx.Response(200, json=idp.jwks())

    from agentic_auth.oauth.resource import startup_check

    http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    assert await startup_check(_config(idp_jwks_url="").validate(), http) is None


async def test_start_up_with_m1_off_fetches_nothing() -> None:
    from agentic_auth.oauth.resource import startup_check

    config = GatewayConfig(pdp_url="http://pdp.test", route_table=TABLE).validate()
    assert await startup_check(config) is None
