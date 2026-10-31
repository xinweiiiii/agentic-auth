# Changelog

Notable changes to this project. Format follows [Keep a
Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [semantic
versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
  - **Resource-server guard:** the tool admits only a grant plus identity.
  - **MCP connector proxy:** filters `tools/list` to what the manifest declares.
  - **Egress proxy.**
  - Each labels its decisions with the guarantee level it can actually give.
- **Step-up consent.** A recoverable refusal (`SCOPE_NOT_CONSENTED`) carries a challenge.
  - The consenting human approves it at `/v1/consent/step-up/complete` with their own
    credential. The session's grant is not enough, so an agent cannot approve its own
    widening.
  - The blocked hop then resumes, with its hop budget intact.
  - `client.step_up()`, `client.approve()` and `client.resume()` now have a server to call.
- **Cold start.** A first-time agent can be registered with no manifest and run in a sandbox
  (`/v1/agents/{id}/sandbox`, `agentic-auth sandbox`). A manifest is proposed from what it was
  observed doing, and a human ratifies it before it carries any authority.
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

[Unreleased]: https://github.com/xinweiiiii/agentic-auth/compare/v0.2.1...HEAD
[0.2.1]: https://github.com/xinweiiiii/agentic-auth/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/xinweiiiii/agentic-auth/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/xinweiiiii/agentic-auth/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/xinweiiiii/agentic-auth/releases/tag/v0.1.0
