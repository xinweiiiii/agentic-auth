"""Route resolution for the shared gateway (FR-004, research.md R4).

The property that matters here is narrow and easy to get wrong: **the agent comes from
the token, never from a header**. Centrally, trusting a header would let any agent claim
any other agent's routes, which is a privilege escalation dressed as a routing bug.
"""

from __future__ import annotations

import base64
import json

from starlette.responses import JSONResponse

from agentic_auth.gateway.config import GatewayConfig, GatewayConfigError, parse_route_table
from agentic_auth.gateway.resolve import agent_name, agent_of, resolve
from agentic_auth.sidecar.config import Upstream
from agentic_auth.sidecar.enforce import DATA_CLASS_HEADER, TARGET_HEADER

KB = Upstream(url="http://kb.test", target="mcp://kb.internal/search", data_class="kb.public")
KB_DEEP = Upstream(url="http://deep.test", target="mcp://kb.internal/deep", data_class="kb.public")
SUPPORT_KB = Upstream(
    url="http://support.test", target="mcp://kb.internal/support", data_class="kb.internal"
)
BARE = Upstream(url="http://bare.test")


def _config(**table: Upstream) -> GatewayConfig:
    parsed = {}
    for key, upstream in table.items():
        agent, _, prefix = key.partition("__")
        parsed[(agent or None, "/" + prefix.replace("__", "/"))] = upstream
    return GatewayConfig(pdp_url="http://pdp.test", route_table=parsed)


def _token(claims: dict) -> str:
    body = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
    return f"header.{body}.signature"


# -- reading the agent off the token -----------------------------------------


def test_the_holder_under_a_root_grant_is_the_human() -> None:
    assert agent_of(_token({"sub": "user:alice"})) == "user:alice"


def test_the_holder_after_delegation_is_the_audience() -> None:
    """`aud` is who holds it. Never the `act` link — that is the PREVIOUS actor, and
    reading the caller off it would let a delegator's identity stand in for its
    delegate's."""
    token = _token({"sub": "user:alice", "aud": "agent://support", "act": {"sub": "agent://kb"}})
    assert agent_of(token) == "agent://support"


def test_a_garbage_token_yields_no_agent() -> None:
    for bad in ("", "not-a-jwt", "a.b", "a.!!!.c"):
        assert agent_of(bad) is None


def test_a_human_holder_has_no_agent_specific_routes() -> None:
    assert agent_name("user:alice") is None
    assert agent_name(None) is None
    assert agent_name("agent://support") == "support"


# -- resolution ----------------------------------------------------------------


def test_longest_prefix_wins() -> None:
    config = _config(__kb=KB, __kb__deep=KB_DEEP)
    resolved = resolve(config, agent=None, path="/kb/deep/x", headers={})
    assert isinstance(resolved, tuple), resolved
    prefix, upstream, _, _ = resolved
    assert prefix == "/kb/deep" and upstream is KB_DEEP


def test_an_agent_specific_entry_beats_the_any_agent_fallback() -> None:
    """One prefix legitimately means different targets for different agents — which is
    the whole reason a shared table is keyed by (agent, prefix)."""
    config = _config(__kb=KB, support__kb=SUPPORT_KB)

    mine = resolve(config, agent="support", path="/kb/x", headers={})
    theirs = resolve(config, agent="billing", path="/kb/x", headers={})

    assert isinstance(mine, tuple) and mine[1] is SUPPORT_KB
    assert isinstance(theirs, tuple) and theirs[1] is KB


def test_another_agents_route_is_not_reachable_by_claiming_it_in_a_header() -> None:
    """The escalation this design exists to prevent. `resolve` takes the agent as an
    argument, and the caller derives it from the token — there is no header that can
    supply it."""
    config = _config(support__kb=SUPPORT_KB)

    resolved = resolve(
        config,
        agent="billing",
        path="/kb/x",
        headers={"x-agentic-agent": "support", "X-Agentic-Agent": "support"},
    )

    # No any-agent fallback exists, and billing has no entry, so there is no route at all.
    assert isinstance(resolved, JSONResponse)


def test_headers_supply_target_and_data_class_when_the_table_does_not() -> None:
    config = _config(__bare=BARE)
    resolved = resolve(
        config,
        agent="support",
        path="/bare/x",
        headers={TARGET_HEADER: "mcp://kb.internal/search", DATA_CLASS_HEADER: "kb.public"},
    )
    assert isinstance(resolved, tuple), resolved
    _, _, target, data_class = resolved
    assert target == "mcp://kb.internal/search"
    assert data_class == "kb.public"


def test_no_target_or_data_class_anywhere_is_blocked() -> None:
    """Guessing a data class would be inventing consent."""
    config = _config(__bare=BARE)
    resolved = resolve(config, agent="support", path="/bare/x", headers={})
    assert getattr(resolved, "status_code", None) == 403


def test_an_unmapped_path_is_blocked() -> None:
    config = _config(__kb=KB)
    resolved = resolve(config, agent="support", path="/nope", headers={})
    assert isinstance(resolved, JSONResponse)


# -- traversal -------------------------------------------------------------------


def test_traversal_is_refused_rather_than_normalised() -> None:
    """The matched prefix selects the policy target and is then stripped to build the
    upstream URL. A dot segment makes those two disagree: `/kb/../admin` authorized as
    `/kb` and delivered to `/admin`. Normalising would silently change which prefix
    matched, which is the same class of surprise."""
    config = _config(__kb=KB)
    for path in ("/kb/../admin", "/kb/./x", "/kb\\admin", "/../kb"):
        resolved = resolve(config, agent="support", path=path, headers={})
        assert isinstance(resolved, JSONResponse), path


# -- configuration ----------------------------------------------------------------


def test_route_table_keys_must_name_an_agent_slot() -> None:
    try:
        parse_route_table({"/kb": "http://x"})
    except GatewayConfigError as exc:
        assert "<agent>|<prefix>" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("a key without the agent separator must be refused")


def test_an_empty_agent_means_any_agent() -> None:
    table = parse_route_table({"|/kb": "http://x"})
    assert list(table) == [(None, "/kb")]


def test_a_prefix_must_be_a_path() -> None:
    try:
        parse_route_table({"support|kb": "http://x"})
    except GatewayConfigError as exc:
        assert "must start with" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("a prefix without a leading slash must be refused")
