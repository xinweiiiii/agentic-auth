# Contract: Metrics

Metrics are emitted with `prometheus-client`. The control plane serves them at `GET /metrics`
(Prometheus text exposition, internal network only). The CLI writes them to a `.prom` textfile.

**Labels never carry identities.** No agent names, user subs, session ids, action ids or targets
appear in labels. This bounds cardinality and keeps audit identities behind the audit-reader
check. Per-agent breakdowns come from the audit history API, not from metrics.

## Control plane (`/metrics`)

| Name | Type | Labels | Meaning |
|---|---|---|---|
| `agentic_auth_decisions_total` | counter | `outcome` (`allow`\|`deny`), `enforced` (`true`\|`false`), `target_kind` (`tool`\|`agent`) | Decisions rendered by authorize and by exchange-time refusals, **counted only once recorded** |
| `agentic_auth_denials_total` | counter | `reason` (every `DenyReason`, including `AUDIT_UNAVAILABLE`) | Refusals returned to a caller, by reason |
| `agentic_auth_audit_write_failures_total` | counter | `outcome` (`allow`\|`deny`) | Audit rows that could not be committed. An `allow` value means the call was blocked instead; a `deny` value means a refusal record was lost |
| `agentic_auth_chain_query_duration_seconds` | histogram | `result` (`complete`\|`incomplete`\|`not_found`) | Chain query latency. Buckets: 0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5 |
| `agentic_auth_chain_queries_total` | counter | `result` (`complete`\|`incomplete`\|`not_found`) | Chain query outcomes; completeness ratio = complete / (complete + incomplete) |
| `agentic_auth_chain_writes_total` | counter | `complete` (`true`\|`false`), `break` (`none`\|`LEGACY_TOKEN`\|`PARENT_NOT_FOUND`\|`PARENT_MISMATCH`\|`PARENT_INCOMPLETE`) | Chain completeness decided at write time: the leading indicator for the query-side ratio |

## CLI (`drift check --metrics-out PATH.prom`)

| Name | Type | Labels | Meaning |
|---|---|---|---|
| `agentic_auth_drift_checks_total` | counter | `result` (`pass`\|`drift`\|`error`) | One increment per run (value is always 1 in a single textfile; aggregate across runs in your metrics store) |
| `agentic_auth_drift_undeclared_edges` | gauge | `verdict` (`UNDECLARED_TOOL`\|`UNDECLARED_DELEGATION`\|`UNKNOWN_AGENT`) | Undeclared edges found in this run |
| `agentic_auth_drift_observed_edges` | gauge | — | Distinct attributed edges in the trace |
| `agentic_auth_drift_unattributed_calls` | gauge | — | Calls that could not be attributed |

The same counts are always present in the JSON `DriftReport`, so CI systems without a
node-exporter can still collect them.

## Multi-process deployments

With more than one uvicorn or gunicorn worker, set `PROMETHEUS_MULTIPROC_DIR` to an empty,
writable directory. The control plane then builds its `/metrics` registry with
`multiprocess.MultiProcessCollector`, per the client_python multiprocess guidance.
Single-process is the default and needs no configuration.

## Dashboard guidance

| Panel | Query (PromQL) | Reads as |
|---|---|---|
| Decisions by outcome | `sum by (outcome) (rate(agentic_auth_decisions_total[5m]))` | Traffic shape; a sudden deny spike follows a manifest or policy change |
| Observe-mode would-be blocks | `sum(rate(agentic_auth_decisions_total{outcome="deny",enforced="false"}[5m]))` | What turning enforcement on would break right now |
| Deny reasons | `sum by (reason) (increase(agentic_auth_denials_total[1h]))` | `EDGE_NOT_IN_DAG` rising means drift reached production |
| Audit write failures (**page on any**) | `sum by (outcome) (increase(agentic_auth_audit_write_failures_total[5m])) > 0` | `allow` = calls blocked for lack of a record; `deny` = refusal records lost |
| Chain query p95 | `histogram_quantile(0.95, sum by (le) (rate(agentic_auth_chain_query_duration_seconds_bucket[5m])))` | SLO: < 0.5 s |
| Chain completeness | `sum(rate(agentic_auth_chain_queries_total{result="complete"}[1h])) / sum(rate(agentic_auth_chain_queries_total{result=~"complete\|incomplete"}[1h]))` | SLO: 1.0 for chains written after Phase 3 |
| CI drift catch rate | `sum(increase(agentic_auth_drift_checks_total{result="drift"}[30d]))` vs production `increase(agentic_auth_denials_total{reason="EDGE_NOT_IN_DAG"}[30d])` | The PRD §10 "caught in CI vs only in production" ratio |

Recommended alerts:

- `audit_write_failures_total` increases (critical)
- chain query p95 > 0.5 s for 10 m (warning)
- `chain_writes_total{complete="false", break!="LEGACY_TOKEN"}` increases (warning: a linkage bug,
  not legacy data)
