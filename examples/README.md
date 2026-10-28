# Examples

| Directory | What it is |
|---|---|
| `e2e-notebook/` | **Start here.** One notebook that walks the whole product from a customer's side — register, enroll, consent, delegate, call a privileged tool, get injected, audit it, gate CI, revoke, survive an outage — using only the SDK. Runs against `docker compose up -d` and nothing else. |
| `phase4-e2e/` | The same Phase 4 ground, driven from the shell against a real uvicorn process: separate scripts per concern, for poking at one thing at a time. |
| `drift-fixture/` | Manifests and recorded traces used by the drift-check tests and `agentic-auth drift check`. |
| `kb-search-agent.{yaml,json}` | Single example manifests (below). |

## Example manifests

| File | Purpose |
|---|---|
| `kb-search-agent.yaml` | A well-formed manifest — reconciles cleanly against the fake discovery server (`tests/fixtures/discovery/server.py`) which advertises `kb.internal` and `accounts.internal`. |
| `kb-search-agent.json` | The same manifest wrapped as a `POST /v1/agents` request body (`{name, manifest}`). |

## Local loop

```bash
# validate offline
agentic-auth manifest validate examples/kb-search-agent.yaml

# preview the reconciliation diff (needs the discovery endpoints reachable)
agentic-auth manifest diff examples/kb-search-agent.yaml

# register against a running control plane
curl -sS -X POST localhost:8000/v1/agents \
  -H "Authorization: Bearer $AGENTIC_AUTH_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d @examples/kb-search-agent.json
```

To make `diff`/registration resolve, either run agents behind real hosts that expose
`/.well-known/oauth-protected-resource`, or serve the test fixture resources locally and map
`kb.internal` / `accounts.internal` to them.

## Over-broad variant

Add `account.write` to the `mcp://accounts.internal/read_account` tool's `data_classes`
(and to `spec.data_classes.writes`) to see a `DECLARED_EXCEEDS_DISCOVERED` diff naming that
exact tool ref.
