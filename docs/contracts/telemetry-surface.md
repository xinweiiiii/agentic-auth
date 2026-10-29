# Contract: Telemetry Surface

**The** enumerated surface. Every metric name, span name, attribute key and structured log field this
feature may emit is listed here. `app/observability/surface.py` holds the same set as code, and
`tests/unit/test_telemetry_surface.py` fails if the two disagree or if the integration suite emits a
key that is not here.

Same precedent as Phase 3's `services/edge_rules.py`: one rule module, runtime and tests held to it
by a parity test. Prose guidance was what Phases 3 and 4 shipped; prose cannot fail a build.

## 0. Rules that govern the whole surface

1. **Metric labels never carry identities.** Verbatim from `services/metrics.py`: no agent name, user
   sub, session id, action id or target in any label value. Every label below has a closed,
   enumerable value set, which is what keeps the aggregate surface bounded no matter how many
   agents, sessions or targets exist. Per-agent breakdowns come from
   `GET /v1/audit/decisions`, behind the audit-reader check.
2. **Traces and logs are pseudonymous by default.** Opaque UUIDs (`session_id`, `action_id`) pass
   through; agent names and the act chain are keyed HMACs, and are absent entirely unless
   `AGENTIC_AUTH_TELEMETRY_IDENTITY_DISCLOSURE=true`. See
   [pseudonymisation.md](./pseudonymisation.md).
3. **No secrets, ever.** No token, `jti`, credential, request or response body, `params_hash`,
   binding, or query string. No `exception.stacktrace` from a dispatch-path signal. See §5.
4. **Attribute namespace is `authz.*`.** Domain-first, never company-first, per OTel's naming
   guidance. Metric names keep the existing `agentic_auth_*` prefix because they are already
   published — the asymmetry is deliberate.
5. **Nothing here is read back.** Telemetry is write-only output. No authorization path branches on a
   span, a log field, or inbound trace context.

## 1. Metrics — existing families (unchanged, verified by test)

Every name and label in `docs/contracts/metrics/phase3.md` and
`docs/contracts/metrics/phase4.md` survives this phase byte-for-byte:
`agentic_auth_decisions`, `_denials`, `_audit_write_failures`, `_chain_query_duration_seconds`,
`_chain_queries`, `_chain_writes`, `_taint_blocks`, `_taint_marks`, `_transaction_mints`,
`_enrollments`, `_revocations`, `_revoked_hop_refusals`, `_exchange_pop_failures`, the
`_drift_*` family, and the verifier's `_admissions`, `_transaction_rejections`,
`_identity_view_age_seconds`.

`tests/unit/test_metric_compatibility.py` asserts each one still exists with the same label set.
**Adding a label to any of these is a breaking change** — it silently changes the
meaning of every `sum by (...)` an integrator wrote.

## 2. Metrics — new families

Served on the control plane at the existing `GET /metrics`, and on each PEP at
`GET /__agentic/metrics` ([pep-telemetry.md](./pep-telemetry.md)).

### Enforcement point

| Name | Type | Labels | Meaning |
|---|---|---|---|
| `agentic_auth_pep_calls_total` | counter | `outcome` (`allowed`\|`blocked`\|`observed_would_block`) | Proxied calls by what the PEP did. `observed_would_block` is forwarded but refused on the merits — never counted as `allowed` |
| `agentic_auth_pep_blocks_total` | counter | `cause` (see below) | **The most important series here.** Separates "policy said no" from "the guardrail could not reach policy" |

`cause` values, derived by enumerating every return path in `app/sidecar/enforce.py`:

| Value | Meaning | Guardrail's fault? |
|---|---|---|
| `policy` | a `POLICY_REASONS` deny — the guardrail worked | no |
| `pdp_unreachable` | `/v1/authorize` unreachable or unusable | **yes** |
| `exchange_unreachable` | `/v1/token/exchange` unreachable or unusable | **yes** |
| `mint_unreachable` | `/v1/token/transaction` unreachable or unusable | **yes** |
| `audit_unavailable` | the decision had no committed record, so the call was refused | **yes** |
| `unauthorized` | missing, malformed or refused bearer token | no — the caller's |
| `unresolvable_call` | no upstream mapping, or no target/data class | no — configuration |
| `body_too_large` | a privileged body over the bind cap | no — the caller's |
| `unbindable` | a privileged body that is not a JSON object | no — the caller's |
| `other` | unclassified; present so an unmapped path is visible rather than uncounted | investigate |

Only the four marked **yes** are in `PEP_INFRA_BLOCK_CAUSES` and only those page. Alerting on
the caller's mistakes would cry wolf.

| Name | Type | Labels | Meaning |
|---|---|---|---|
| `agentic_auth_pep_stage_duration_seconds` | histogram | `stage` (`decide`\|`exchange`\|`mint`\|`upstream`) | Where per-hop time went. Buckets as `CHAIN_QUERY_BUCKETS` |
| `agentic_auth_pep_overhead_seconds` | histogram | — | Guardrail-added time = total − `upstream`. Cross-checkable against the sum of the other stages |
| `agentic_auth_pep_up` | gauge | — | Always `1` while serving. Liveness is `absent()` on this, not a value |
| `agentic_auth_pep_info` | gauge | `mode` (`enforcing`\|`observing`), `version` | Always `1`. `mode` is the unambiguous answer to "is this thing actually enforcing" |

### Telemetry self-observation

| Name | Type | Labels | Meaning |
|---|---|---|---|
| `agentic_auth_trace_context_rejected_total` | counter | `cause` (`malformed`\|`absent`\|`baggage_dropped`) | Inbound context not used. `absent` is normal for agents the integrator does not control; `malformed` rising is a caller bug or an attempt |
| `agentic_auth_telemetry_dropped_total` | counter | `signal` (`span`\|`log`) | Signals lost to queue overflow or a failing sink. **Telemetry loss reporting itself** |
| `agentic_auth_telemetry_identity_disclosure` | gauge | — | `1` when full identities are being exported, `0` otherwise. A deployment can alert on `1` |

`agentic_auth_telemetry_dropped_total` is fed by `BatchSpanProcessor`'s own instrumentation (it takes
a `meter_provider`), not counted by hand.

## 3. Spans

| Name | Emitted by | Once per | Kind |
|---|---|---|---|
| `authz.decide` | control plane | `POST /v1/authorize` | server |
| `authz.exchange` | control plane | `POST /v1/token/exchange` | server |
| `authz.transaction.mint` | control plane | `POST /v1/token/transaction` | server |
| `pep.forward` | sidecar | proxied request | server |
| `pep.decide`, `pep.exchange`, `pep.mint`, `pep.upstream` | sidecar | child of `pep.forward` | client |

`record_exception=False` on all of them (§5).

### Attributes

| Key | Type | Values | On |
|---|---|---|---|
| `authz.action_id` | string | UUID | all, when a decision was recorded |
| `authz.session_id` | string | UUID | all |
| `authz.hop` | int | ≥ 1 | all |
| `authz.outcome` | string | `allow`\|`deny` | `authz.decide` |
| `authz.deny_reason` | string | existing `DenyReason` values | `authz.decide`, iff `outcome=deny` |
| `authz.recoverable` | bool | | `authz.decide` |
| `authz.enforced` | bool | | `authz.decide` |
| `authz.target_kind` | string | `tool`\|`agent` | `authz.decide` |
| `authz.data_class` | string | manifest vocabulary | `authz.decide` |
| `authz.privileged` | bool | | `authz.decide` |
| `authz.taint` | string | `trusted_internal`\|`untrusted_external` | `authz.decide`, when known |
| `authz.policy_version` | int | | all control-plane spans |
| `authz.guarantee_level` | string | `full`\|`connector`\|`network`\|`consent_only` | `authz.decide` |
| `authz.result` | string | per-endpoint result vocabulary | `authz.exchange`, `authz.transaction.mint` |
| `authz.pop_failure_cause` | string | `missing`\|`invalid`\|`wrong_agent`\|`not_enrolled` | `authz.exchange`, when applicable |
| `authz.pep.mode` | string | `enforcing`\|`observing` | `pep.forward` |
| `authz.pep.outcome` | string | `allowed`\|`blocked`\|`observed_would_block` | `pep.forward` |
| `authz.pep.block_cause` | string | as `pep_blocks_total` | `pep.forward`, when blocked |
| `authz.agent_ref` | string | 32-hex pseudonym of the acting agent | all, by default |
| `authz.act_chain_ref` | string | 32-hex pseudonym of the act chain | all, by default |
| `authz.taint_source_ref` | string | 32-hex pseudonym of the taint source | `authz.decide`, when tainted |
| `authz.agent` | string | `agent://name` plaintext | all, **only** with disclosure on |
| `authz.act_chain` | string | the delegating chain, plaintext | all, **only** with disclosure on |
| `authz.taint_source` | string | the taint source target, plaintext | **only** with disclosure on |
| `http.request.method`, `http.response.status_code` | | HTTP semconv | `pep.forward`, `pep.upstream` |
| `error.type` | string | exception class name | any span on a failure |

**Hard invariant.** `authz.deny_reason` is present ⟺ `authz.outcome = deny`, mirroring the
`ck_audit_decisions_reason_iff_deny` database constraint so a span and its audit row can never
disagree about whether a reason exists.

A pseudonym and its plaintext counterpart are **never emitted together** — a backend must never
receive two spellings of one identity.

**Never an attribute, on any span, at any disclosure setting:** `target` (the full tool/agent
URI), `caller`, `subject_jti`, any `jti`, `params_hash`, `binding`, request/response bodies, and
query strings. `app/observability/surface.py` refuses these by substring
(`FORBIDDEN_ATTR_SUBSTRINGS`), so a plausible future addition like `authz.subject_jti` fails a
test rather than shipping.

## 4. Structured log fields

Passed via stdlib `logging`'s `extra=`. `LoggingHandler._get_attributes` exports every non-reserved
`LogRecord` attribute, so `extra=` needs no adapter; `_translate` attaches `trace_id`/`span_id` from
the active context automatically.

| Field | Type | Notes |
|---|---|---|
| `authz.component` | string | `control_plane`\|`pep`\|`verifier`\|`cli` |
| `authz.session_id` | string | UUID, when in a session |
| `authz.action_id` | string | UUID, when a decision exists |
| `authz.hop` | int | when applicable |
| `error.type` | string | exception class name — **not** the message, **not** the trace |

**Severity.** An ordinary policy deny is `INFO`. A guardrail failure needing a human is
`WARNING` or above. A deny is never logged as an error. Python levels map to OTel severity in the
SDK (`WARNING`→`WARN`, `CRITICAL`→`FATAL`); we add no custom mapping.

**Message strings are static** so records group. Identifiers go in fields, never interpolated into
the text. The existing `logger.exception("policy load failed for session %s", body.session_id)` in
`api/v1/authorize.py` becomes `logger.warning("policy load failed", extra={...})` plus `error.type`.

## 5. Secret exclusion, and the two SDK paths that would leak

The allowlist above is the first control. The second exists because the SDK adds attributes we did
not ask for:

- `LoggingHandler._get_attributes` sets `exception.type`, `exception.message` (`str(value.args[0])`)
  and `exception.stacktrace` (the full formatted traceback) whenever `record.exc_info` is set.
- `Span.record_exception` does the same on spans.

A traceback through token verification can carry a token fragment in a frame-derived message.
`api/v1/authorize.py` already calls `logger.exception()` on three paths and `api/v1/token.py` on one,
so this is live, not hypothetical.

**Therefore:** no dispatch-path signal carries `exception.*`. Those call sites record `error.type`
and a bounded, static message. Spans set `record_exception=False`.

**Verification.** `tests/integration/test_no_secrets_in_telemetry.py` runs the existing
integration suite with an `InMemorySpanExporter` and an in-memory log exporter, then asserts over
everything captured: every attribute key ∈ this contract; no value matches a JWT-shaped or
high-entropy-blob pattern; no `exception.stacktrace` key present anywhere.

## 6. Metrics for integrators without Prometheus

Metrics stay `prometheus-client` (`PrometheusMetricReader` adds `otel_scope_*`
labels and a `target_info` series, registers a second writer into one registry, and has no
`PROMETHEUS_MULTIPROC_DIR` equivalent; any of those breaks multi-process exposition).

An OTLP-only pipeline reaches these metrics through the Collector's `prometheus` receiver:

```yaml
receivers:
  prometheus:
    config:
      scrape_configs:
        - job_name: agentic-auth-control-plane
          static_configs: [{ targets: ['control-plane:8000'] }]
        - job_name: agentic-auth-pep
          metrics_path: /__agentic/metrics
          static_configs: [{ targets: ['127.0.0.1:8081'] }]
```

Traces and logs go to `OTEL_EXPORTER_OTLP_ENDPOINT` directly. Two transports, one Collector, no
code change.

## 7. Multi-process deployments

Unchanged from Phase 3: with more than one uvicorn/gunicorn worker, set `PROMETHEUS_MULTIPROC_DIR`
to an empty writable directory and the control plane builds its `/metrics` registry with
`multiprocess.MultiProcessCollector`. Traces and logs need no equivalent — each worker exports
independently and the backend reassembles by trace id.
