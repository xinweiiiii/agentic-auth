"""What admitting an inbound IdP token costs a call (feature 011, SC-006, quickstart V9).

    pytest tests/load/test_inbound_validation_latency.py
    python -m tests.load.test_inbound_validation_latency --iterations 5000

The budget is **5 ms at p95** added to a call with warm keys and a warm session cache, so the
per-hop p95 of under 15 ms still holds. Measured on the gate alone, because the gate is the
whole of what M1 adds in front of the unchanged ``enforce()``: a 0.3.0 proxy runs everything
after it already. A cache miss adds one consent round trip, once per IdP token, and is not
part of the steady-state budget.

Measured in-process against the fake IdP, so the number is the validator's and the cache's,
not a network's: signature verification, claim checks and one hash lookup.
"""

from __future__ import annotations

import argparse
import asyncio
import statistics
import time

import httpx
from httpx import ASGITransport

from agentic_auth.oauth.resource import Admitted, ResourceGate, SessionCache, SessionEntry
from agentic_auth.oauth.validate import JwksCache, TokenValidator
from tests.fixtures.idp.server import ISSUER, JWKS_URL, FakeIdp, build_idp

RESOURCE = "https://mcp-proxy.test"
BUDGET_P95_MS = 5.0


def percentile(values: list[float], p: float) -> float:
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int(round(p / 100 * (len(ordered) - 1))))]


async def measure(iterations: int) -> dict[str, float]:
    idp = FakeIdp()
    app, _ = build_idp(idp)
    http = httpx.AsyncClient(transport=ASGITransport(app=app))
    gate = ResourceGate(
        resource_url=RESOURCE,
        authorization_server=ISSUER,
        scopes=("kb.public",),
        validator=TokenValidator(
            issuer=ISSUER, audiences=[RESOURCE], jwks=JwksCache(JWKS_URL, lambda: http)
        ),
        pdp_url="http://pdp.invalid",  # never called: the session is cached
        consent_token="unused",
        http=http,
        cache=SessionCache(),
    )
    token = idp.mint_access_token(aud=RESOURCE, scope="kb.public", expires_in=3600)
    gate.cache.put(token, SessionEntry("root-grant", "session-1", time.time() + 3600))
    headers = {"authorization": f"Bearer {token}"}

    assert isinstance(await gate.admit(headers, {}, data_class="kb.public"), Admitted)  # warm
    samples: list[float] = []
    for _ in range(iterations):
        started = time.perf_counter()
        result = await gate.admit(headers, {}, data_class="kb.public")
        samples.append((time.perf_counter() - started) * 1000)
        assert isinstance(result, Admitted)
    await http.aclose()
    return {
        "p50_ms": statistics.median(samples),
        "p95_ms": percentile(samples, 95),
        "p99_ms": percentile(samples, 99),
    }


async def test_admitting_a_token_with_warm_keys_stays_inside_the_budget() -> None:
    result = await measure(500)
    assert result["p95_ms"] <= BUDGET_P95_MS, result


def main() -> None:
    parser = argparse.ArgumentParser(description="What admitting an inbound IdP token costs")
    parser.add_argument("--iterations", type=int, default=5000)
    args = parser.parse_args()
    result = asyncio.run(measure(args.iterations))
    verdict = "PASS" if result["p95_ms"] <= BUDGET_P95_MS else "FAIL"
    print(
        f"{verdict}: p50 {result['p50_ms']:.3f} ms, p95 {result['p95_ms']:.3f} ms, "
        f"p99 {result['p99_ms']:.3f} ms (budget p95 <= {BUDGET_P95_MS} ms)"
    )


if __name__ == "__main__":
    main()
