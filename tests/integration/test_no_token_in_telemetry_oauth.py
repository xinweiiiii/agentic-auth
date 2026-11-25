"""INV-4: an inbound IdP token never appears in logs, edge traces or metrics (feature 011).

Only its fingerprint may. Driven through both enforcement points with good and bad tokens,
then every surface an operator can read is scanned for any fragment of any token sent.
"""

from __future__ import annotations

import json
import logging

from tests.fixtures.contracts import defs_schema
from tests.fixtures.upstream.recording import token_material


async def test_no_surface_carries_any_part_of_an_inbound_token(
    oauth_stack, tmp_path, caplog
) -> None:
    import jsonschema

    trace = tmp_path / "edges.jsonl"
    proxy = oauth_stack.proxy(trace_path=str(trace))
    gateway = oauth_stack.gateway(trace_path=str(trace))
    sent: list[str] = []

    def bearer(token: str) -> dict[str, str]:
        sent.append(token)
        return {"Authorization": f"Bearer {token}"}

    call = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "search"}}
    with caplog.at_level(logging.DEBUG):
        await proxy.post("/mcp", json=call, headers=bearer(oauth_stack.token()))
        await proxy.post("/mcp", json=call, headers=bearer(oauth_stack.token(expires_in=-600)))
        await proxy.post("/mcp", json=call, headers=bearer(oauth_stack.token(alg="none")))
        await proxy.post("/mcp", json=call, headers=bearer(oauth_stack.token(scope="x.y")))
        gw = {"aud": oauth_stack.gateway_url}
        await gateway.get("/kb/search", headers=bearer(oauth_stack.token(**gw)))
        await gateway.get("/kb/search", headers=bearer(oauth_stack.token(**gw, kid="nope")))
        metrics = (await gateway.get("/metrics")).text

    surfaces = {
        "edge trace": trace.read_text(),
        "logs": caplog.text
        + "\n".join(json.dumps(r.__dict__, default=str) for r in caplog.records),
        "metrics": metrics,
    }
    for token in sent:
        for fragment in token_material(token):
            for name, text in surfaces.items():
                assert fragment not in text, f"a token fragment reached the {name}"

    schema = defs_schema("edge-trace.schema.json", "EdgeEvent")
    lines = [json.loads(line) for line in trace.read_text().splitlines() if line]
    refusals = [line for line in lines if line["outcome"] == "blocked_local"]
    assert {line["reason"] for line in refusals} >= {"INVALID_TOKEN", "INSUFFICIENT_SCOPE"}
    for line in lines:
        jsonschema.validate(line, schema)
