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

A route in `SIDECAR_UPSTREAM_MAP` or `GATEWAY_ROUTE_TABLE` may carry `relay_authorization`:
an operator credential the connector proxy sends upstream on relayed, non-`tools/call` methods
such as `initialize` and `tools/list`. **Since 0.4.0 the client's own `Authorization`, `Cookie`
and `Proxy-Authorization` headers are never relayed**, with every flag off: before it they were
forwarded unchanged. An upstream that needs a credential on those methods gets this instead.

### As an OAuth 2.1 protected resource (0.4.0, M1)

The connector proxy (`agentic-auth-boundary mcp-proxy`) and the gateway read the same settings,
under the `GATEWAY_` prefix. With `GATEWAY_OAUTH_RESOURCE_ENABLED`, a standard MCP client can
call them with no Agentic Auth code: it is challenged with `401`, finds your IdP through the
Protected Resource Metadata at `/.well-known/oauth-protected-resource`, signs the user in there,
and calls again with the IdP's access token. The proxy validates that token itself, starts a
session by calling consent with it, and runs the usual per-call decision. **The client's token
never goes upstream**; the upstream receives a narrowed hop token, as before.

| Setting | Default | Notes |
|---|---|---|
| `GATEWAY_OAUTH_RESOURCE_ENABLED` | `false` | Turns M1 on. Refused together with `GATEWAY_OBSERVE_MODE`: observe mode forwards would-be denials, and the only token it could forward is the client's. |
| `GATEWAY_RESOURCE_URL` | *(empty)* | **Required.** This proxy's public https URL: the `resource` in its metadata, and the audience every inbound token must carry. `http://localhost` is accepted only with `AGENTIC_AUTH_DEV=true`. |
| `GATEWAY_IDP_ISSUER` | *(empty)* | **Required.** Your IdP's issuer, named as the authorization server. Inbound tokens must carry exactly this `iss`. |
| `GATEWAY_IDP_JWKS_URL` | *(empty)* | Overrides the `jwks_uri` read from the IdP's discovery document. The keys are fetched before the process starts serving; if they cannot be, it refuses to start. |
| `GATEWAY_IDP_ALGORITHMS` | `RS256,ES256,EdDSA` | Accepted signing algorithms. `none` and `HS*` are refused at startup. |
| `GATEWAY_CLOCK_LEEWAY_SECONDS` | `60` | Tolerated clock skew on `exp` and `nbf`, at most 300. |
| `GATEWAY_CONSENT_TOKEN` | *(empty)* | **Required.** The control plane's `CONSENT_TOKEN`: lets this proxy call consent and nothing else. Never give a proxy the admin token. |
| `GATEWAY_CONSENT_SCOPE` | *(empty)* | The scope to start sessions in. Leave empty when the control plane maps clients to agents (`CLIENT_MAPPING_ENABLED`), which then picks the scope from the token's client. |
| `GATEWAY_ASSERTED_ROOT_SCOPE` | *(empty)* | **Only for a control plane with verified consent off.** Consent is then called with the subject this proxy validated as an *asserted* `user_sub`, and this scope. Sessions are recorded as `asserted`, refusals say `root_of_authority: asserted`, and the proxy logs a warning at start-up. With it set, the consent token can start a session for any user, so **run M1 with verified consent on** wherever you can. |
| `GATEWAY_SESSION_CACHE_SIZE` | `10000` | Sessions kept in memory, one per IdP token, until the earlier of the token's and the session's expiry. |

A token that fails validation is refused with `401` and `error="invalid_token"` before any
decision is made. It has no audit row, because no session exists yet; it is recorded in the edge
trace and the gateway's decision counter with reason `INVALID_TOKEN`, and logged with a token
fingerprint, never the token.

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
| `PRINCIPAL_IDP_ALGORITHMS` | `RS256,ES256,EdDSA` | Signing algorithms accepted on any token from the human IdP. `none` and `HS*` are refused at startup. **Applies with every flag off since 0.4.0**: before it, the token's own header chose. Set it if your IdP signs with another algorithm, such as `PS256`. |
| `REVOCATION_FRESHNESS_SECONDS` | `30` | How long an offline verifier may run without refreshing revocation state. |

## Step-up and cold start

All off by default.

| Setting | Default | Notes |
|---|---|---|
| `CONSENT_GRANULARITY_ENABLED` | `false` | Let a session consent to a subset of its policy's data classes. |
| `STEP_UP_ENABLED` | `false` | Return a challenge on a recoverable deny. **Requires consent granularity** — without it, step-up could never grant anything, and the process refuses to start. |
| `SANDBOX_ENABLED` | `false` | Sandboxed observation and manifest proposal. Off → 404. |

## MCP OAuth 2.1 (0.4.0)

All off by default. Each milestone is its own setting, so turn them on one at a time. The
connector proxy and gateway side (M1) is configured on each proxy or gateway; see
[Enforcement points](#enforcement-points).

| Setting | Default | Notes |
|---|---|---|
| `VERIFIED_CONSENT_ENABLED` | `false` | M2. Consent requires the user's IdP token as `subject_token`, verifies it itself against the principal IdP, and roots the session at `iss#sub` with `principal_source: verified`. An asserted `user_sub` alone is refused. Needs `PRINCIPAL_IDP_ISSUER`, `PRINCIPAL_IDP_JWKS_URL` and `CONSENT_IDP_AUDIENCES`, or the process refuses to start. |
| `CONSENT_IDP_AUDIENCES` | *(empty)* | Comma-separated audiences a `subject_token` may carry: this control plane's own identifier, plus the resource URL of every proxy or gateway that relays tokens to consent. |
| `CONSENT_TOKEN` | *(empty)* | Bearer that may call `POST /v1/consent` and nothing else. **Give this, never the admin token, to a proxy or gateway.** Empty disables it. |
| `CLIENT_MAPPING_ENABLED` | `false` | M4. An admin maps an IdP client (the `azp` of its tokens) to a registered agent with `POST /v1/agents/{agent_id}/clients`; consent then runs the session in that agent's scope, and a request that names another scope is refused. A client with no mapping, or whose agent has no pinned manifest, is refused with `CLIENT_NOT_AUTHORIZED` and `next: cold_start`: identified, not authorized. Agents are never created from an unknown client. **Requires `VERIFIED_CONSENT_ENABLED`.** Removing a mapping stops new sessions but does not end live ones, which expire within `SESSION_TTL_SECONDS`; revoke the agent for an immediate stop. |
| `AS_METADATA_ENABLED` | `false` | M3. Serves this control plane's RFC 8414 metadata at `/.well-known/oauth-authorization-server`, exchange-only: no authorization or registration endpoint, because logins and client registration belong to your IdP. Registration also follows each MCP server's `authorization_servers` and rejects a declared data class that server does not list in `scopes_supported`. **Requires `ISSUER` to be an https URL.** Changing `ISSUER` changes `iss` in every new token, so update any offline verifier pinned to the old value before you switch. |

Consent refusals happen before any session exists, so they have no audit row. They are counted
in `agentic_auth_consent_refusals_total{reason}` and logged with a token fingerprint, never
the token.

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
