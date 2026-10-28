# Observability artifacts

Dashboards and alert rules for the Agentic Authorization SDK, for the stack you already run.

The SDK **does not serve an operator surface of its own** — no console, no built-in dashboard
page. It emits primitives and ships these artifacts; you own the backend. That is deliberate
(`docs/PRD.md` §4.2: "not a full agent observability/tracing platform. We only emit primitives
observability tools need").

```
dashboards/
  guardrail-health.json    is it alive, is it enforcing, what does it cost
  rollout-tuning.json      what would enforcement block, before you turn it on
  chain-integrity.json     can the audit trail still answer "who authorized this"
alerts/
  guardrail.rules.yml      the four signals that must page, plus warnings
```

## Turning telemetry on

Four environment variables and nothing else — no code change in your application:

```bash
pip install -e '.[otel]'                         # the optional extra
export AGENTIC_AUTH_TELEMETRY_ENABLED=true
export AGENTIC_AUTH_TELEMETRY_KEY="$(openssl rand -hex 32)"
export OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318
```

`AGENTIC_AUTH_TELEMETRY_KEY` is **required**. It keys the identity pseudonyms in traces and logs,
and the session-derived trace ids. Without it the exporter refuses to start and logs once — the
process still serves traffic, but it will not export identities in the clear or behind an unkeyed
digest that anyone holding the telemetry could reverse.

Each enforcement point configures its own, under `AGENTIC_AUTH_SIDECAR_TELEMETRY_*`. There is
deliberately no fleet-wide switch: a setting that reads as fleet-wide while changing nothing in a
sidecar's process would be worse than no setting.

With nothing configured, the local surfaces still work: `GET /metrics` on the control plane,
`GET /__agentic/metrics` on each enforcement point, and JSON logs on stdout.

## Importing the dashboards

Grafana → Dashboards → New → Import → upload the JSON, then pick your Prometheus datasource
(each dashboard declares a `DS_PROMETHEUS` input).

## Loading the alerts

```yaml
# prometheus.yml
rule_files:
  - observability/alerts/guardrail.rules.yml
```

Four alerts are `critical` and are the ones that should page:

| Alert | What it means |
|---|---|
| `AgenticAuthAuditWriteFailing` | Decisions are not committing. `allow` = calls blocked for lack of a record; `deny` = refusal records lost. |
| `AgenticAuthPepCannotReachPolicy` | An enforcement point is fail-closing because it cannot reach the control plane — **not** because policy said no. |
| `AgenticAuthPepSilent` | No enforcement point is reporting. A guardrail that is silently not enforcing is worse than none, because the system looks protected. |
| `AgenticAuthChainIncomplete` | Chains are being written incomplete. A chain is materialized once, so these rows can never be completed later. |

Nothing that is the *caller's* mistake pages — an unauthorized bearer, an unmapped path, an
oversized body. A critical that fires for those teaches people to ignore criticals.

## Scraping

Both surfaces are Prometheus text exposition and carry **no identities in any label**, so they
need no credential. Keep them on an internal network.

```yaml
scrape_configs:
  - job_name: agentic-auth-control-plane
    static_configs:
      - targets: ['control-plane:8000']

  - job_name: agentic-auth-pep
    metrics_path: /__agentic/metrics
    static_configs:
      - targets: ['127.0.0.1:8081']
```

> **An enforcement point that is not scraped is not observable.** `AgenticAuthPepSilent` works by
> `absent(agentic_auth_pep_up)`, so a sidecar bound to loopback and never scraped produces no
> series at all — and absence is then indistinguishable from "never deployed". This is the one
> requirement the SDK satisfies by contract rather than in code. Pushing heartbeats to the
> control plane was rejected: it would make the control plane a dependency of every PEP's
> liveness signal, which is the coupling the sidecar exists to avoid.

## If you run an OTLP-only pipeline

Traces and logs go to `OTEL_EXPORTER_OTLP_ENDPOINT` directly. **Metrics do not** — they stay on
`prometheus-client` so that the metric names and labels published in the Phase 3 and Phase 4
contracts keep working exactly as they are. Collect them with the Collector's `prometheus`
receiver:

```yaml
receivers:
  prometheus:
    config:
      scrape_configs:
        - job_name: agentic-auth-control-plane
          static_configs:
            - targets: ['control-plane:8000']
        - job_name: agentic-auth-pep
          metrics_path: /__agentic/metrics
          static_configs:
            - targets: ['127.0.0.1:8081']

  otlp:
    protocols:
      http:
        endpoint: 0.0.0.0:4318
```

Two transports, one Collector, no code change. The reason metrics stay on
`prometheus-client` rather than moving to OTel: `PrometheusMetricReader` adds
`otel_scope_*` labels and a `target_info` series, registers a second writer into one registry,
and has no `PROMETHEUS_MULTIPROC_DIR` equivalent — any one of which would break a dashboard
someone already built.

## What is in traces, and what is not

Pseudonymous by default. A span carries the opaque `authz.session_id` and `authz.action_id`, and
`authz.agent_ref` / `authz.act_chain_ref` — keyed HMACs, stable within a deployment, not
reversible by anyone holding only the telemetry.

`AGENTIC_AUTH_TELEMETRY_IDENTITY_DISCLOSURE=true` swaps those for plaintext `authz.agent` and
`authz.act_chain`. The gauge `agentic_auth_telemetry_identity_disclosure` reports which posture a
deployment is in, so you can alert on any deployment that has it on.

To get from a span to a real identity without the opt-in, take `authz.action_id` and ask the audit
API — which is behind the audit-reader check, where identities belong:

```bash
curl -H "Authorization: Bearer $AGENTIC_AUTH_AUDIT_READ_TOKEN" \
  "$CONTROL_PLANE/v1/audit/actions/$ACTION_ID/chain"
```

No token, credential, request body, `params_hash`, binding, query string or stack trace appears in
any signal, at any disclosure setting. The full enumerated surface is published at
<https://authzai.dev/reference/telemetry-surface>, and
`tests/integration/test_no_secrets_in_telemetry.py` sweeps everything the suite emits to
keep it that way.

## These artifacts cannot silently rot

`tests/unit/test_dashboard_artifacts.py` parses every panel query and every alert
expression here, then resolves each metric name **and each label value** against the live
registry. A renamed metric or a typo'd label value fails the build — rather than producing a panel
that is merely empty and an alert that silently never fires.
