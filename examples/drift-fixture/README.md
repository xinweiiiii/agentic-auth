# Drift fixture: the undeclared `terminate_account` call

The PRD §2.3 scenario as a runnable drift check. A user consents to `bank-assistant`, which
delegates to `balance-agent`, which delegates to `support-agent`. `support-agent` then calls
`terminate_account`, which its manifest never declared.

| Directory | What it declares |
|---|---|
| `manifests/` | The agents as intended. `support-agent` declares knowledge-base search only |
| `manifests-widened/` | The same, plus `terminate_account` on `support-agent` (privileged) |

`tests/unit/test_drift_fixture_files.py` keeps these files identical to
`tests/fixtures/bank.py`, so this example cannot drift from the suite that exercises
it.

## The loop

Run from the repository root, with a control plane on `127.0.0.1:8099` (see
<https://authzai.dev/how-to/configure-the-ci-drift-check>).

**1. Register the manifests.** Tool hosts are usually unreachable in a test environment. An
unreachable capability source is `needs_review`, not a hard reject, so a recorded override
reason reconciles it. The admin token is read from the environment, never from argv.

```bash
export AGENTIC_AUTH_ADMIN_TOKEN=dev-admin-token
agentic-auth manifest register-dir examples/drift-fixture/manifests \
  --control-plane http://127.0.0.1:8099 \
  --override-reason "local drift fixture"
```

**2. Start the recording sidecar** (observe mode, trace path set):

```bash
python -m app.sidecar --config examples/drift-fixture/sidecar.yaml &
```

**3. Record your agent's test run.** Point the agent's tool and delegation base URLs at the
sidecar. The trace is written even if the tests fail, and the exit code is the tests' own.

```bash
agentic-auth drift record --out edge-trace.json -- pytest path/to/agent/tests
# or, for a sidecar that ran outside this command:
agentic-auth drift record --out edge-trace.json --events examples/drift-fixture/edge-events.jsonl
```

**4. Check.** This step is offline: it needs only the manifests and the trace.

```bash
agentic-auth drift check --manifest examples/drift-fixture/manifests --trace edge-trace.json
```

```text
agentic-auth drift check: DRIFT, 1 undeclared edge (3 edges observed, 2 declared)

  UNDECLARED_TOOL  support-agent -> mcp://accounts.internal/terminate_account   (1 call)
    runtime would deny: OUT_OF_SCOPE
    declared in: examples/drift-fixture/manifests/support-agent.yaml
    fix: remove the call from support-agent, or add mcp://accounts.internal/terminate_account to spec.tools in examples/drift-fixture/manifests/support-agent.yaml
```

Exit code `1`. Then either:

- **Fix the agent.** Remove the call, record again, and the check exits `0`.
- **Widen the manifest.** This is a deliberate, reviewable change:

  ```bash
  agentic-auth drift check --manifest examples/drift-fixture/manifests-widened --trace edge-trace.json
  # agentic-auth drift check: PASS ... exit 0
  ```

Exit codes: `0` pass, `1` drift, `2` the check could not run. Exit `2` is never a pass; the
full list of causes is at
<https://authzai.dev/reference/cli/drift>.
