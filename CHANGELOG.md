# Changelog

Notable changes to this project. Format follows [Keep a
Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [semantic
versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0rc1] - 2026-11-01

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
  as `uvicorn agentic_auth.main:app`. `app.*` imports are available through the opt-in
  `authzai-compat` package for the 0.2.x line.
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

[Unreleased]: https://github.com/xinweiiiii/agentic-auth/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/xinweiiiii/agentic-auth/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/xinweiiiii/agentic-auth/releases/tag/v0.1.0
