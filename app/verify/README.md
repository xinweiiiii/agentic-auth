# `app.verify` — resource-side verification

For the owner of a tool or API who wants to admit only calls that carry a valid **grant**
(hop token) **and** a valid **identity** (the calling agent's own signature) **and**, for a
privileged tool, a valid **transaction token** bound to this exact call. Offline after
bootstrap; imports `pyjwt[crypto]` only (`httpx` for the `Http*` stores).

Contract: [`docs/verifier-library.md`](../../docs/verifier-library.md).

## Install and bootstrap

```python
from app.verify import Verifier, HttpJwks, HttpAnchors, InMemoryReplay, RedisReplay

verifier = Verifier(
    issuer_jwks=HttpJwks("https://control-plane/.well-known/jwks.json"),
    anchors=HttpAnchors(
        base_url="https://control-plane",
        token=os.environ["AGENTIC_AUTH_AUDIT_READ_TOKEN"],  # an identity-reader bearer
        agents=["support-agent", "balance-agent"],  # the agents this resource expects
        freshness_seconds=30,
    ),
    replay=RedisReplay(redis.Redis(...)),  # InMemoryReplay() for a single process
    identity_required=True,
)
await verifier.bootstrap()  # fetches issuer keys, each agent's identity, the revocation list;
# raises if the control plane is unreachable — never starts empty
```

`bootstrap()` starts a background refresh every `freshness_seconds / 2`. Past
`freshness_seconds` without a successful refresh every identity is refused as
`IDENTITY_STALE` until one succeeds. Call `await verifier.close()` on shutdown.

## Admit a call

```python
admission = verifier.admit(
    request.headers,  # Authorization, Agent-Identity, Txn-Token
    target="mcp://accounts.internal/terminate_account",
    params=parsed_json_body,  # required for a privileged tool
    privileged=True,
)
if not admission.ok:
    return 403, {
        "error": {"code": "not_admitted", "message": admission.detail, "details": admission.details}
    }
# admission.grant.action_id links this call to its audit row; admission.identity.agent is who called
```

`admit()` does no I/O apart from the replay claim. It is a conjunction: there is no path
that admits on identity alone, and no path that admits a privileged call without its
transaction token.

## Reasons

| Step | Reasons |
|---|---|
| grant | `GRANT_MISSING`, `GRANT_INVALID`, `GRANT_EXPIRED`, `GRANT_TARGET_MISMATCH` |
| identity | `IDENTITY_MISSING`, `IDENTITY_INVALID`, `IDENTITY_STALE`, `IDENTITY_UNKNOWN_AGENT`, `IDENTITY_REVOKED` |
| transaction | `TXN_MISSING`, `TXN_INVALID`, `TXN_EXPIRED`, `TXN_TARGET_MISMATCH`, `TXN_GRANT_MISMATCH`, `TXN_PARAMS_MISMATCH`, `TXN_UNSUPPORTED_BINDING`, `TXN_REPLAY`, `REPLAY_STORE_UNAVAILABLE` |

## Stores

- `StaticJwks(dict)` / `StaticAnchors([identity reads])` — anchors shipped as data; never
  stale; the integrator owns rotation. For tests and air-gapped deployments.
- `HttpJwks(url)` / `HttpAnchors(...)` — bootstrap and refresh from the control plane.
- `InMemoryReplay()` — one process. `RedisReplay(client)` — `SET NX EX`, for several instances.
  A store that cannot answer refuses (`REPLAY_STORE_UNAVAILABLE`).

## Metrics

Pass `metrics_registry=` a `prometheus_client.CollectorRegistry` to get
`agentic_auth_admissions_total{result}`, `agentic_auth_transaction_rejections_total{cause}` and
`agentic_auth_identity_view_age_seconds`.

## What it needs from the agent

`Authorization: Bearer <hop token>` (from `POST /v1/token/exchange`), `Agent-Identity`
(a JWT the agent signs with its enrolled key, bound to the exact grant string), and for a
privileged tool `Txn-Token` (from `POST /v1/token/transaction`). The SDK's `Grant.headers()`
and the sidecar produce all three.

## Telemetry (optional)

`Verifier` takes an optional `telemetry=` sink, the same shape as the optional
`metrics_registry=` above: you construct it, the verifier only calls it.

```python
from opentelemetry import trace
from app.observability import OtelSink
from app.verify import Verifier

verifier = Verifier(..., telemetry=OtelSink(trace.get_tracer_provider()))
```

`telemetry=None` (the default) emits nothing.

Two invariants hold here, and both are enforced by `tests/unit/test_verify_imports.py`:

- **This package imports no `opentelemetry` module and no `app.observability` module.** Its
  dependency floor is `pyjwt[crypto]`, and it stays there. The seam is a `TelemetrySink`
  `Protocol`, not an import, so `OtelSink` living in the other package costs this one nothing.
- **Nothing here installs process-global telemetry.** `trace.set_tracer_provider()` is global and
  warns-and-ignores on a second call, so a library that calls it in a host it does not own either
  hijacks the host's pipeline or silently fails to emit. You pass in the provider you already
  configured.

The emitted span is `verify.admit`, carrying the outcome, the deny reason and whether the target
was privileged. It deliberately does **not** carry the target: a target is an identity, and the
verifier runs inside your process where your disclosure policy applies.
