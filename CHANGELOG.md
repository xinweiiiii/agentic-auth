# Changelog

Notable changes to this project. Format follows [Keep a
Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [semantic
versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/xinweiiiii/agentic-auth/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/xinweiiiii/agentic-auth/releases/tag/v0.1.0
