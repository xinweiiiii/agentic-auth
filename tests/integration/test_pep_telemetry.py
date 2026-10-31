"""The enforcement point is no longer dark.

Before this phase nothing under ``agentic_auth/sidecar/`` emitted anything, so a sidecar that had
been silently forwarding every call looked exactly like a healthy one. Everything asserted here is
read from the PEP's own two routes — no database query, no log file — because that is the
situation an on-call operator is actually in.
"""

from __future__ import annotations

import re

import pytest

USER = "user:alice"

# An edge that is not in the declared DAG. `/bare` pins no target, so these headers decide
# what the hop is authorized against (see tests/integration/test_observe_mode.py).
DENIED = {
    "X-Agentic-Target": "agent://summarizer",
    "X-Agentic-Data-Class": "account.read",
}


def series(text: str, name: str, **labels: str) -> float | None:
    """One value out of a Prometheus exposition, or None when the series is absent.

    Absence and zero are different answers here — `absent(agentic_auth_pep_up)` is how a
    silent PEP is detected — so this deliberately does not coerce a missing series to 0.
    """
    if labels:
        selector = ",".join(f'{k}="{v}"' for k, v in sorted(labels.items()))
        pattern = rf"^{re.escape(name)}\{{{re.escape(selector)}\}} (\S+)$"
    else:
        pattern = rf"^{re.escape(name)} (\S+)$"
    for line in text.splitlines():
        m = re.match(pattern, line)
        if m:
            return float(m.group(1))
    return None


async def _rooted(register_chain, consent):
    await register_chain()
    return await consent()


# -- mode and liveness ------------------------------------------------------


async def test_an_enforcing_pep_reports_its_mode_and_liveness(sidecar_stack) -> None:
    sidecar = await sidecar_stack.client()
    text = (await sidecar.get("/__agentic/metrics")).text

    assert series(text, "agentic_auth_pep_up") == 1.0
    assert series(text, "agentic_auth_pep_info", mode="enforcing", version="0.1.0") == 1.0
    # The mode is unambiguous: the observing series must not exist at all, rather than be 0.
    assert series(text, "agentic_auth_pep_info", mode="observing", version="0.1.0") is None


async def test_an_observing_pep_is_unmistakable(sidecar_stack) -> None:
    """A PEP nobody meant to leave in observe mode is the failure this surfaces."""
    sidecar = await sidecar_stack.client(observe_mode=True)
    text = (await sidecar.get("/__agentic/metrics")).text

    assert series(text, "agentic_auth_pep_info", mode="observing", version="0.1.0") == 1.0
    assert series(text, "agentic_auth_pep_info", mode="enforcing", version="0.1.0") is None


async def test_status_reports_the_shape_the_contract_promises(sidecar_stack) -> None:
    sidecar = await sidecar_stack.client()
    body = (await sidecar.get("/__agentic/status")).json()

    assert body["mode"] == "enforcing"
    assert body["uptime_seconds"] >= 0
    assert body["upstreams"] == 3
    assert body["upstream_map_digest"].startswith("sha256:")
    assert body["pdp"] == {"reachable": False, "last_success_seconds_ago": None}
    assert body["telemetry"]["enabled"] is False
    assert body["version"]


async def test_status_never_leaks_the_upstream_map_itself(sidecar_stack) -> None:
    """Upstream URLs carry internal hostnames. The digest lets two PEPs be compared without
    publishing the configuration to anyone who can reach the status route."""
    sidecar = await sidecar_stack.client()
    raw = (await sidecar.get("/__agentic/status")).text

    assert "upstream.test" not in raw
    assert "mcp://kb.internal/search" not in raw


# -- allowed, blocked, and would-have-blocked are three different things -------------


async def test_an_allowed_call_is_counted_as_allowed(
    sidecar_stack, register_chain, consent
) -> None:
    session = await _rooted(register_chain, consent)
    sidecar = await sidecar_stack.client()

    r = await sidecar.get(
        "/kb/search", headers={"Authorization": f"Bearer {session['root_grant']}"}
    )
    assert r.status_code == 200, r.text

    text = (await sidecar.get("/__agentic/metrics")).text
    assert series(text, "agentic_auth_pep_calls_total", outcome="allowed") == 1.0
    assert series(text, "agentic_auth_pep_calls_total", outcome="blocked") is None


async def test_a_policy_denial_is_counted_as_blocked_by_policy(
    sidecar_stack, register_chain, consent
) -> None:
    session = await _rooted(register_chain, consent)
    sidecar = await sidecar_stack.client()

    # `/bare` has no target or data class pinned and the request supplies none, so the call
    # cannot be authorized against anything.
    r = await sidecar.get("/bare/x", headers={"Authorization": f"Bearer {session['root_grant']}"})
    assert r.status_code >= 400

    text = (await sidecar.get("/__agentic/metrics")).text
    assert series(text, "agentic_auth_pep_calls_total", outcome="blocked") == 1.0
    assert series(text, "agentic_auth_pep_calls_total", outcome="allowed") is None


async def test_observe_mode_is_never_counted_as_allowed(
    sidecar_stack, register_chain, consent
) -> None:
    """The call was forwarded, but it was refused on the merits. Folding it into
    `allowed` would make observe mode read as a working guardrail."""
    session = await _rooted(register_chain, consent)
    sidecar = await sidecar_stack.client(observe_mode=True)

    # `/bare` pins no target, so these headers are what the hop is authorized against, and
    # the edge is not in the declared DAG -> EDGE_NOT_IN_DAG, which observe mode forwards.
    # (A pinned prefix like `/kb` would override the header and be allowed.)
    r = await sidecar.get(
        "/bare", headers={"Authorization": f"Bearer {session['root_grant']}", **DENIED}
    )
    assert r.status_code == 200, "observe mode forwards"

    text = (await sidecar.get("/__agentic/metrics")).text
    assert series(text, "agentic_auth_pep_calls_total", outcome="observed_would_block") == 1.0
    assert series(text, "agentic_auth_pep_calls_total", outcome="allowed") is None
    assert series(text, "agentic_auth_pep_blocks_total", cause="policy") is None, (
        "a would-be block is not a block"
    )


# -- the distinction the whole story turns on ---------------------------------------


async def test_a_dead_control_plane_is_distinguishable_from_a_policy_refusal(
    sidecar_stack, register_chain, consent
) -> None:
    """The difference between a guardrail that works and one that is broken. From the agent's
    side both are just a refused call, which is why it has to be visible here."""
    session = await _rooted(register_chain, consent)
    sidecar = await sidecar_stack.client()
    sidecar_stack.router.pdp_down = True

    r = await sidecar.get(
        "/kb/search", headers={"Authorization": f"Bearer {session['root_grant']}"}
    )
    assert r.status_code >= 400

    text = (await sidecar.get("/__agentic/metrics")).text
    assert series(text, "agentic_auth_pep_blocks_total", cause="pdp_unreachable") == 1.0
    assert series(text, "agentic_auth_pep_blocks_total", cause="policy") is None

    status = (await sidecar.get("/__agentic/status")).json()
    assert status["pdp"]["reachable"] is False


async def test_a_refusal_before_dispatch_says_nothing_about_the_control_plane(
    sidecar_stack,
) -> None:
    """A missing bearer never reaches the decision endpoint, so it must not be counted as
    evidence that the control plane is healthy — reporting a dead PDP as reachable is exactly
    the kind of false comfort this feature exists to remove."""
    sidecar = await sidecar_stack.client()

    await sidecar.get("/kb/search")  # no Authorization header at all
    await sidecar.get("/not-mapped-anywhere")

    text = (await sidecar.get("/__agentic/metrics")).text
    assert series(text, "agentic_auth_pep_blocks_total", cause="unauthorized") == 1.0
    assert series(text, "agentic_auth_pep_blocks_total", cause="unresolvable_call") == 1.0

    status = (await sidecar.get("/__agentic/status")).json()
    assert status["pdp"]["reachable"] is False, "two calls that never contacted it"


async def test_a_dead_token_exchange_is_its_own_cause(
    sidecar_stack, register_chain, consent
) -> None:
    """`pdp_unreachable` and `exchange_unreachable` send an operator to different places."""
    session = await _rooted(register_chain, consent)
    sidecar = await sidecar_stack.client()
    sidecar_stack.router.transaction_down = True

    # A privileged target needs the mint; taking it down exercises the mint cause while
    # decide and exchange stay up.
    r = await sidecar.get(
        "/kb/search",
        headers={
            "Authorization": f"Bearer {session['root_grant']}",
            "X-Agentic-Target": "mcp://kb.internal/search",
            "X-Agentic-Data-Class": "kb.public",
        },
    )
    text = (await sidecar.get("/__agentic/metrics")).text

    if r.status_code >= 400:
        # Whatever the cause, it must not be mislabelled as a policy refusal.
        assert series(text, "agentic_auth_pep_blocks_total", cause="policy") is None
    # The decision endpoint was reached, so reachability is now true either way.
    assert (await sidecar.get("/__agentic/status")).json()["pdp"]["reachable"] is True


# -- what the guardrail costs -------------------------------------------------------


async def test_stage_latency_is_attributed_to_the_parts(
    sidecar_stack, register_chain, consent
) -> None:
    session = await _rooted(register_chain, consent)
    sidecar = await sidecar_stack.client()

    await sidecar.get("/kb/search", headers={"Authorization": f"Bearer {session['root_grant']}"})
    text = (await sidecar.get("/__agentic/metrics")).text

    for stage in ("decide", "exchange", "upstream"):
        count = series(text, "agentic_auth_pep_stage_duration_seconds_count", stage=stage)
        assert count == 1.0, f"no timing recorded for stage={stage}"


async def test_overhead_is_recorded_and_excludes_the_upstream_call(
    sidecar_stack, register_chain, consent
) -> None:
    """Overhead is total-minus-upstream rather than a separately accumulated number, so the
    two cross-check: a divergence means unaccounted time inside the PEP."""
    session = await _rooted(register_chain, consent)
    sidecar = await sidecar_stack.client()

    await sidecar.get("/kb/search", headers={"Authorization": f"Bearer {session['root_grant']}"})
    text = (await sidecar.get("/__agentic/metrics")).text

    overhead = series(text, "agentic_auth_pep_overhead_seconds_sum")
    upstream = series(text, "agentic_auth_pep_stage_duration_seconds_sum", stage="upstream")
    decide = series(text, "agentic_auth_pep_stage_duration_seconds_sum", stage="decide")

    assert overhead is not None and overhead > 0
    assert upstream is not None
    assert decide is not None and overhead >= decide, "overhead must cover the decide stage"


async def test_the_latency_of_a_failure_is_still_recorded(
    sidecar_stack, register_chain, consent
) -> None:
    """An unreachable control plane is exactly the latency an operator needs to see; dropping
    it would make an outage look instantaneous."""
    session = await _rooted(register_chain, consent)
    sidecar = await sidecar_stack.client()
    sidecar_stack.router.pdp_down = True

    await sidecar.get("/kb/search", headers={"Authorization": f"Bearer {session['root_grant']}"})
    text = (await sidecar.get("/__agentic/metrics")).text

    assert series(text, "agentic_auth_pep_stage_duration_seconds_count", stage="decide") == 1.0


# -- the routes themselves ------------------------------------------------------------------


async def test_the_reserved_namespace_does_not_shadow_a_proxied_path(
    sidecar_stack, register_chain, consent
) -> None:
    """The telemetry routes are additive: an ordinary call still proxies."""
    session = await _rooted(register_chain, consent)
    sidecar = await sidecar_stack.client()

    r = await sidecar.get(
        "/kb/search", headers={"Authorization": f"Bearer {session['root_grant']}"}
    )
    assert r.status_code == 200
    assert sidecar_stack.recorder.count == 1


async def test_metrics_carry_no_identities(sidecar_stack, register_chain, consent) -> None:
    """The Phase 3 rule, re-asserted on the new families: no agent name, user sub, session id
    or target may appear in a label value."""
    session = await _rooted(register_chain, consent)
    sidecar = await sidecar_stack.client()

    await sidecar.get("/kb/search", headers={"Authorization": f"Bearer {session['root_grant']}"})
    text = (await sidecar.get("/__agentic/metrics")).text

    assert USER not in text
    assert "mcp://kb.internal/search" not in text
    assert str(session["session_id"]) not in text
    assert "agent://" not in text


@pytest.mark.parametrize("route", ["/__agentic/metrics", "/__agentic/status"])
async def test_the_telemetry_routes_need_no_authorization(sidecar_stack, route: str) -> None:
    """They are bound to the sidecar's own listener, which is loopback by default, and they
    carry no identities — so requiring a credential would only make scraping harder."""
    sidecar = await sidecar_stack.client()
    assert (await sidecar.get(route)).status_code == 200
