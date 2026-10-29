# Configuration

Every setting is read with an `AGENTIC_AUTH_` prefix, from the environment or a `.env`
file. [`.env.example`](.env.example) is the authoritative list and documents each entry
inline; this page is the organised view.

**Phases 4–6 are off by default.** With every flag below off you get manifest-driven
authorization, token exchange, and the audit chain — and nothing else changes.

## Core

| Setting | Default | Notes |
|---|---|---|
| `DATABASE_URL` | `postgresql+asyncpg://app:app@localhost:5432/agentic_auth` | PostgreSQL 16. |
| `REDIS_URL` | `redis://localhost:6379/0` | Sessions, replay guards, decision cache. |
| `ADMIN_TOKEN` | `dev-admin-token` | Full-trust credential for every control-plane write. **Replace before any shared deployment.** |
| `DISCOVERY_TIMEOUT_SECONDS` | `5` | RFC 9728 capability discovery. |

## Token issuance

| Setting | Default | Notes |
|---|---|---|
| `ISSUER` | `agentic-auth` | The `iss` on every issued token. |
| `ISSUER_PRIVATE_KEY` | *(empty)* | Ed25519 PEM. **Empty generates an ephemeral key at startup** — every token stops verifying on restart, and two replicas will not agree. Development only, and loud on purpose. |
| `ISSUER_KID` | thumbprint | Key id in the JWKS and each token header. |
| `HOP_TOKEN_TTL_SECONDS` | `60` | One hop. Long enough for a slow upstream, short enough that the replay set stays small. |
| `SESSION_TTL_SECONDS` | `1800` | A session pins its policy version for this window. Sized to one piece of agent work, not a user login. |
| `DECISION_CACHE_TTL_SECONDS` | `30` | The policy version is part of the cache key, so a pinned session cannot read another version's entry. |

Generate a key with:

```bash
openssl genpkey -algorithm ED25519 -out issuer-key.pem
```

## Audit

| Setting | Default | Notes |
|---|---|---|
| `AUDIT_READ_TOKEN` | *(empty)* | Read-only bearer for `GET /v1/audit/*`. Give auditors this, not the admin token. Empty disables it. |
| `AUDIT_WRITE_TIMEOUT_SECONDS` | `1.0` | An allowed call whose record cannot commit in time is refused (`AUDIT_UNAVAILABLE`), never dispatched without a record. |
| `METRICS_ENABLED` | `true` | Prometheus at `/metrics`. Internal networks only. Labels carry no identities. |
| `TRACE_PATH` | *(unset)* | Edge recording for the CI drift check. Passive — never changes what is forwarded or blocked. |

With more than one worker, point `PROMETHEUS_MULTIPROC_DIR` at an empty writable directory
so `/metrics` aggregates across them.

## Enforcement points

A sidecar is usually clearer configured by file than by environment — see [deploy the
sidecar](https://authzai.dev/how-to/deploy-the-sidecar-pep).

| Setting | Default | Notes |
|---|---|---|
| `SIDECAR_PDP_URL` | `http://127.0.0.1:8099` | |
| `SIDECAR_LISTEN_ADDR` | `127.0.0.1:8081` | |
| `SIDECAR_OBSERVE_MODE` | `false` | Decides and records without enforcing. **Per enforcement point, never deployment-wide.** Read `GET /v1/decisions?outcome=deny&enforced=false` before switching a sidecar to enforcing. |
| `SIDECAR_UPSTREAM_MAP` | — | JSON. A path prefix with no target and no data class is **blocked**, never guessed. |
| `GATEWAY_PDP_URL` / `GATEWAY_LISTEN_ADDR` | — | The shared enforcement service. It never holds an agent's signing key; it relays identity headers. |
| `GATEWAY_ROUTE_TABLE` | — | JSON, keyed `"<agent>\|<prefix>"` or `"\|<prefix>"` for any agent. |
| `GATEWAY_DECISION_DEADLINE_MS` | `2000` | Past it the call is refused, never retried. |

## Identity, taint, transaction tokens

Three independent controls. With all three off, Phase 1–3 behaviour is unchanged.

| Setting | Default | Notes |
|---|---|---|
| `TRANSACTION_TOKENS_ENABLED` | `true` | Privileged calls need a call-bound token. `false` → the route answers 404. |
| `TAINT_ENFORCEMENT_ENABLED` | `true` | Return `TAINTED_INTO_PRIVILEGED`. `false` still derives and records taint — tune first. |
| `IDENTITY_REQUIRED` | `false` | Require proof of possession at every exchange. **Enroll every agent before turning this on.** |
| `TRANSACTION_TOKEN_TTL_SECONDS` | `30` | One privileged call, minted right before it. |
| `MAX_PRIVILEGED_BODY_BYTES` | `1048576` | Larger is refused, never forwarded unbound. |
| `ENROLL_TOKEN` | *(empty)* | Bearer allowed to begin and complete enrollment. |
| `PRINCIPAL_IDP_ISSUER` / `_JWKS_URL` / `_AUDIENCE` | *(empty)* | The human IdP for principal binding. **Leave these empty and every enrollment completes as `quarantined`** rather than enrolling an agent nobody is accountable for. |
| `REVOCATION_FRESHNESS_SECONDS` | `30` | How long an offline verifier may run without refreshing revocation state. |

## Step-up and cold start

All off by default.

| Setting | Default | Notes |
|---|---|---|
| `CONSENT_GRANULARITY_ENABLED` | `false` | Let a session consent to a subset of its policy's data classes. |
| `STEP_UP_ENABLED` | `false` | Return a challenge on a recoverable deny. **Requires consent granularity** — without it, step-up could never grant anything, and the process refuses to start. |
| `SANDBOX_ENABLED` | `false` | Sandboxed observation and manifest proposal. Off → 404. |

## Observability

Off by default, and the OpenTelemetry SDK is never imported when off. Install with
`pip install -e '.[otel]'`.

| Setting | Default | Notes |
|---|---|---|
| `TELEMETRY_ENABLED` | `false` | |
| `TELEMETRY_KEY` | *(empty)* | **Required when telemetry is on.** Keys the pseudonyms in traces and logs. Empty → the exporter refuses to start and logs once; the process still serves traffic. There is no fallback to plaintext. Generate with `openssl rand -hex 32`. |
| `TELEMETRY_IDENTITY_DISCLOSURE` | `false` | Export real agent names instead of pseudonyms. The state is itself exported so it can be alerted on. Metric labels are unaffected either way. |
| `TELEMETRY_ALLOW_SAMPLE_RATIO` | `1.0` | Fraction of **allow** spans kept. Refusals ignore this entirely — a denied, fail-closed, taint-blocked or unrecorded decision is always exported. |

Where telemetry goes uses the standard `OTEL_*` variables, not names we invented. Metrics
are not exported this way: they stay on `/metrics`, collected with the Collector's
prometheus receiver.
