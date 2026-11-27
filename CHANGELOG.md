# Changelog

Notable changes to this project. Format follows [Keep a
Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [semantic
versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

The MCP 2026-07-28 OAuth 2.1 baseline: a standard MCP client can authenticate to Agentic
Auth with no Agentic-Auth-specific code, and the root of every delegation chain can be a
human your IdP actually signed in. Your IdP stays the authorization server: Agentic Auth
never runs a login, an authorization endpoint or client registration. Each milestone is its
own setting, **off by default**; with all of them off, behaviour is unchanged apart from the
three changes listed under *Changed*.

- **The connector proxy and gateway as OAuth protected resources** (M1,
  `AGENTIC_AUTH_GATEWAY_OAUTH_RESOURCE_ENABLED`).
  - They publish Protected Resource Metadata (RFC 9728) naming your IdP, and answer a missing
    or bad token with `401` and a `WWW-Authenticate` challenge pointing at it.
  - They validate the IdP's access token themselves: signature against its JWKS, issuer,
    audience (RFC 8707, exactly this proxy's URL), expiry, and an allowed signing algorithm.
    A token that fails is refused before any policy decision.
  - A valid token starts a session through consent, once per token, and the usual per-call
    decision runs with that session's grant. **The client's token never goes upstream.**
  - The IdP's keys are fetched before the process serves; if they cannot be, it does not start.
    If they become unreachable later with none cached, calls are refused, never allowed.
- **Verified consent** (M2, `AGENTIC_AUTH_VERIFIED_CONSENT_ENABLED`). Consent takes the user's
  IdP token as `subject_token`, verifies it itself, and roots the session at `iss#sub`. The
  session, every audit row and the chain query say `principal_source: verified`. An asserted
  `user_sub` alone is refused, and one that disagrees with the token is refused without being
  echoed.
  - A new `AGENTIC_AUTH_CONSENT_TOKEN` may call consent and nothing else. Give it, never the
    admin token, to a proxy or gateway.
- **Client mapping** (M4, `AGENTIC_AUTH_CLIENT_MAPPING_ENABLED`). An admin maps an IdP client
  (its tokens' `azp`) to a registered agent at `/v1/agents/{agent_id}/clients`, and that
  client's sessions run in the agent's scope. An unmapped client, or one whose agent has no
  pinned manifest, is refused with `CLIENT_NOT_AUTHORIZED` and `next: cold_start`: identified,
  not authorized. Mappings are soft-removed, so the table is its own history.
- **Authorization server metadata** (M3, `AGENTIC_AUTH_AS_METADATA_ENABLED`). The control plane
  serves RFC 8414 metadata at `/.well-known/oauth-authorization-server`: token exchange, JWKS,
  consent, and no authorization or registration endpoint. Registration also follows each MCP
  server's `authorization_servers` and rejects a declared data class that server does not
  issue (`DECLARED_EXCEEDS_AUTHORIZATION_SERVER`), blocks when it is unreachable
  (`AUTHORIZATION_SERVER_UNAVAILABLE`), and notes when there was nothing to check
  (`AUTHORIZATION_SERVER_CHECK_SKIPPED`, never blocking).
- **An MCP authorization conformance suite** (`tests/conformance/mcp_auth`, M5), one test per
  named requirement in its `REQUIREMENTS.md`, run against the proxy and the gateway, server
  and embedded. **A release now publishes nothing unless it passes**, and the report is
  attached to the GitHub release as `mcp-conformance.xml`.
- `agentic_auth_consent_refusals_total{reason}`, for consent refusals, which have no audit row
  because no session exists yet.
- The embedded control plane supports every new setting, and its test IdP mints MCP-client
  access tokens. Sessions it roots are recorded as `principal_source: embedded-test`.

### Changed

These apply **with every flag off**.

- **Security: relayed MCP methods no longer carry the client's credentials.** The connector
  proxy used to relay `initialize`, `tools/list` and every other non-`tools/call` method with
  all inbound headers, so the agent's bearer token reached the upstream server. It now strips
  `Authorization`, `Cookie` and `Proxy-Authorization`.
  - Upgrade: an upstream that needs a credential on those methods gets an operator secret per
    route, `relay_authorization`.
- **Security: tokens from the human IdP must use an allowed signing algorithm.** Enrollment
  binding and step-up used to verify an ID token with whatever algorithm its header named.
  They now accept only `AGENTIC_AUTH_PRINCIPAL_IDP_ALGORITHMS`, default `RS256,ES256,EdDSA`;
  `none` and `HS*` are refused at startup.
  - Upgrade: if your IdP signs with another algorithm, such as `PS256`, set that variable.
- **Embedded stores created by 0.2.0 or 0.3.0 do not open.** The schema gained columns, which
  an embedded store cannot add in place, so opening one raises `StoreVersionMismatch`.
  - Upgrade: export it with the version that created it, and start a new store. Server
  deployments migrate as usual (`alembic upgrade head`, migration `0008_mcp_oauth_baseline`).
- The SDK's `Session` ignores response fields it does not know, so a newer control plane never
  breaks an older client's `consent()`. New consent response fields appear only when they
  carry information (verified consent on, or a mapped client).

### Upgrade notes

- **Turning on M3 changes `iss` in new tokens**, because it needs `AGENTIC_AUTH_ISSUER` to be an
  https URL (RFC 8414). Update any offline verifier pinned to the old issuer first.
- **Removing a client mapping does not end live sessions.** They expire within
  `SESSION_TTL_SECONDS`. Revoke the agent for an immediate stop.
- Running M1 with verified consent off needs `AGENTIC_AUTH_GATEWAY_ASSERTED_ROOT_SCOPE`, and
  roots sessions in an asserted subject: refusals say `root_of_authority: asserted`. Turn on
  verified consent wherever you can.

## [0.3.0] - 2026-11-01

### Added

The Phase 5 enforcement points and consent flows. They were declared in 0.1.x (the
`agentic-auth-gateway` and `agentic-auth-boundary` commands existed) but their code never
reached this repository, so those commands could not start.

- **Gateway** (`agentic-auth-gateway`, `agentic_auth.gateway`). A shared, central enforcement
  point that runs the same `enforce()` as the sidecar, so it reaches the same decisions.
  - It fails closed when the control plane is unreachable or past its decision deadline.
  - It supports observe mode, and runs as several stateless instances.
- **Boundary adapters** (`agentic-auth-boundary`, `agentic_auth.boundary`), for agents you
  cannot modify:
  - **Resource-server guard** (`RequireAgenticAuth` middleware): the tool admits only a
    grant plus identity.
  - **MCP connector proxy** (`agentic-auth-boundary mcp-proxy`): filters `tools/list` to
    what the manifest declares, and decides every `tools/call`.
  - Each labels its decisions with the guarantee level it can actually give.
- **Step-up consent.** A recoverable refusal (`SCOPE_NOT_CONSENTED`) carries a challenge.
  - The consenting human approves it at `/v1/consent/step-up/complete` with their own
    credential. The session's grant is not enough, so an agent cannot approve its own
    widening.
  - The blocked hop then resumes, with its hop budget intact.
  - `client.step_up()`, `client.approve()` and `client.resume()` now have a server to call.
- **Cold start.** A first-time agent can be registered with no manifest. It then authorizes
  nothing. To give it a manifest:
  1. Record what it does under test with `agentic-auth drift record`.
  2. Run `agentic-auth sandbox propose-local <trace> --agent <name>`, which proposes a manifest
     covering exactly what was observed.
  3. A person reviews the proposal, filling in data classes and marking privileged tools,
     then registers it. That review is the ratification: nothing governs until then.
- **Consent to a subset** (`consent(data_classes=...)`), behind
  `AGENTIC_AUTH_CONSENT_GRANULARITY_ENABLED`.
- **Feature flags.** Each new control is off by default: `CONSENT_GRANULARITY_ENABLED`,
  `STEP_UP_ENABLED` and `SANDBOX_ENABLED`. With them off, no new route is advertised and
  every decision is unchanged.
- **Contracts and testing:** `docs/contracts/conformance.md` and
  `docs/contracts/stepup.openapi.yaml`. A conformance test holds the SDK, sidecar and gateway
  to the same decisions.
- The embedded control plane serves step-up and sandbox too. The embedded/remote conformance
  suite now runs the full step-up flow: refused, approved by the human, resumed.

### Not yet included

- **Server-side sandbox observation.** `/v1/agents/{id}/sandbox` and `agentic-auth sandbox
  run` open an observation run. Nothing yet feeds a run the agent's calls, so a run ends
  empty and its proposal is marked `covers_no_behaviour`. Use `sandbox propose-local` (above)
  until then. Ratifying a server-side proposal works.
- **The egress proxy (network mode).** `agentic-auth-boundary egress-ca` generates the
  certificate authority, and the connection-inspection logic is in place and tested.
  `egress-proxy` itself does not run yet: it needs a CONNECT-capable listener, and it says
  so and exits rather than starting a proxy that cannot enforce.

### Fixed

- The OpenAPI document reports the package's version instead of a hard-coded `0.1.0`.

## [0.2.1] - 2026-10-31

### Added

- **Move an embedded instance to a deployment.** Starting from `EmbeddedControlPlane.export()`:
  - `agentic-auth manifest register-bundle <bundle>` re-registers every manifest version, in
    order and downstream first, through the admin API. Each version reconciles against the
    deployment's real capability discovery.
  - `agentic-auth audit import <bundle>` appends the exported decisions to a new
    append-only table, `imported_audit` (migration `0007`), apart from the deployment's own
    log. Re-running it adds nothing.
  - Enrollments are deliberately not carried over: an agent re-enrolls with its own key,
    because the bundle holds no private keys and enrollment is proof of possessing one.
  - A malformed bundle is refused, naming the line.

### Changed

- **The walkthrough notebook runs on the embedded control plane.** It needs
  `pip install 'authzai[notebook]'` and nothing else: no Docker, no PostgreSQL, no Redis
  server. Its outputs no longer show machine-specific paths, and
  `tests/embedded/test_walkthrough_notebook.py` runs it on every pull request.
- `EmbeddedControlPlane` gains:
  - `configure(**settings)`: change a setting for the rest of the run, as a redeploy would
  - `admin_token`, `audit_token`, `enroll_token` and `idp`
- Every `/.well-known/oauth-protected-resource` request inside an embedded instance is now
  answered by the capability source, including for a host with a tool server mounted.
- An embedded durable store created by 0.2.0 is moved forward when opened: the new table is
  created and existing data is kept. A store from any other schema revision is still
  refused.

## [0.2.0] - 2026-10-31

### Added

- **Published to PyPI as `authzai`.** Releases are built and published by a tag-triggered
  workflow, with no manual upload and no repository secret. Each release carries:
  - the same wheel and sdist on PyPI and on the GitHub release
  - `SHA256SUMS` and signed build provenance
  - a matching server image, `ghcr.io/xinweiiiii/agentic-auth`
  `RELEASING.md` covers cutting a release, recovering a half-finished one, and verifying a
  download.
- **Install options.** The base install is the offline verifier only (`pyjwt[crypto]`). The
  extras are:
  - `client`: the agent SDK
  - `drift`: the CLI and CI check
  - `embedded`: see below
  - `server`: the control plane, sidecar, gateway and boundary
  - `otel` and `all`
  Importing a surface without its extra names the extra to install.
- **Embedded control plane** (`agentic_auth.embedded`, `authzai[embedded]`). The whole control
  plane runs inside your process, on SQLite and an in-process Redis, with no server, database
  or open port. It is the same app, PDP, token exchange and audit log a deployment runs, and
  `cp.client()` returns the same `AgenticAuthClient`. Instances are isolated from each other.
  The store is temporary by default, or a single durable file that one process holds at a
  time. On reopen, sessions created before the restart are refused (`session_superseded`)
  rather than honoured without the taint and replay records they had. Embedded mode is **for
  development and testing only**. It says so when it starts, and every decision it records is
  labelled `deployment: embedded`. `tests/conformance` runs every scenario against both
  deployments and requires identical results.
- `audit_decisions.deployment` (`server` | `embedded`), migration `0006`. It is additive:
  existing rows read as `server`.

- The import root is now `agentic_auth`, not `app`. A top-level `app` package collided with
  the application package of almost every FastAPI or Flask project that installed this one.
  Imports become `from agentic_auth.sdk import AgenticAuthClient`, and the control plane runs
  as `uvicorn agentic_auth.main:app`. To migrate:
  `sed -E 's/\b(from|import) app\./\1 agentic_auth./g'`.
- Logger names follow the module path, so `app.api.v1.authorize` is now
  `agentic_auth.api.v1.authorize`. Update any logging configuration that names them.

### Fixed

- The 0.1.0 notes and the README described the decision log as "hash-chained". It is not:
  rows are append-only, enforced by the database, and each decision links to its parent, but
  no row carries a hash of the one before it. The README now says what the log actually
  guarantees.
- `scripts/export_manifest_schema.py` wrote to a path outside this repository. It now writes
  `docs/contracts/manifest.schema.json`, the file the drift test reads.

## [0.1.1] - 2026-10-29

### Fixed

- A non-editable install (`pip install "agentic-auth @ git+https://..."`, and the
  drift-check action's default install) shipped only the top-level `app` package, so the
  `agentic-auth` command failed with `ModuleNotFoundError: No module named 'app.cli'`.
  Every subpackage is now included, and CI installs the built package to keep it so.
- The secret scan failed on every pull request: `gitleaks-action` now requires
  `GITHUB_TOKEN` there, and no check here may need a secret. CI runs a pinned,
  checksum-verified gitleaks binary instead.

## [0.1.0] - 2026-10-29

First public release.

### Added

- **Control plane** — agent manifests, registration, reconciliation against discovered
  capabilities, and a compiler that turns declarations into a policy DAG.
- **PDP** — a decision per hop, recorded before anything is dispatched. An allowed call
  that cannot be recorded is refused rather than dispatched unrecorded.
- **Token exchange** (RFC 8693) — authority narrows at every hop, carrying an `act` chain
  naming who acts for whom.
- **Four enforcement points** — sidecar, gateway, boundary adapter, and in-process SDK.
- **Audit plane** — append-only, hash-chained decision log, queryable by action, agent, or
  delegation chain.
- **Identity** — agent enrollment bound to a human principal, proof of possession at
  exchange, and revocation that offline verifiers honour.
- **Taint and provenance** — content from untrusted sources is labelled, and the label
  follows it into later calls.
- **Transaction tokens** — a privileged call is bound to its exact parameters.
- **Step-up consent and cold start** — a recoverable deny can ask rather than fail, and a
  sandboxed run can propose a manifest.
- **Observability** — Prometheus metrics with no identities in any label, plus opt-in
  OpenTelemetry traces and logs that no-op when the SDK is absent. Dashboards and alert
  rules included.
- **CI drift check** — a GitHub Action failing a pull request when an agent's observed
  calls include an edge its manifests never declared.
- **Offline verifier library** (`app.verify`) — installable with `pyjwt[crypto]` alone.

[Unreleased]: https://github.com/xinweiiiii/agentic-auth/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/xinweiiiii/agentic-auth/compare/v0.2.1...v0.3.0
[0.2.1]: https://github.com/xinweiiiii/agentic-auth/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/xinweiiiii/agentic-auth/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/xinweiiiii/agentic-auth/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/xinweiiiii/agentic-auth/releases/tag/v0.1.0
