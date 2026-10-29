# Contract — Metrics

New metrics for Phase 5, following the existing naming in `app/services/metrics.py`
(`agentic_auth_*`, Prometheus, built into `ControlPlaneMetrics` and exposed at `/metrics`).

## 1. Control plane

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `agentic_auth_decisions_by_guarantee` | Counter | `level`, `outcome` | Every decision, by guarantee level. **This is the operator view**: it is how you see what proportion of traffic runs below full guarantee. |
| `agentic_auth_guarantee_degrades` | Counter | `from`, `to` | A session's reported level changed. Non-zero deserves an alert — a degrade is never silent, and this is the signal. |
| `agentic_auth_step_up_challenges` | Counter | `reason` | Challenges raised. `reason` is always `SCOPE_NOT_CONSENTED` today; the label exists so a second recoverable reason would be visible rather than merged. |
| `agentic_auth_step_up_outcomes` | Counter | `outcome` | `approved` \| `declined` \| `expired` \| `replayed` \| `out_of_ceiling`. The approval rate is the denial-UX signal the PRD (§11) says we are iterating on. |
| `agentic_auth_step_up_resumptions` | Counter | `result` | `completed` \| `partial` \| `failed`. Distinguishes "the user approved and the task finished" from "approved but unresumable", which is the harder product problem. |
| `agentic_auth_sandbox_runs` | Counter | `status` | `completed` \| `deadline_exceeded` \| `failed`. |
| `agentic_auth_proposals_ratified` | Counter | `edited` | `true` when the administrator changed the document before ratifying, `false` otherwise. A high `true` rate means the proposal generator is missing things. |

## 2. Gateway

Exposed by the gateway process at its own `/metrics`, since it is a separate deployment.

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `agentic_auth_gateway_decisions` | Counter | `outcome`, `reason` | Mirrors the sidecar's view from the central point. |
| `agentic_auth_gateway_deadline_exceeded` | Counter | — | Decisions abandoned past `gateway_decision_deadline_ms`. Every increment is a refused call. |
| `agentic_auth_gateway_route_misses` | Counter | — | Paths with no route-table entry. A spike usually means a route table that has drifted from the agents it serves. |
| `agentic_auth_gateway_identity_relayed` | Counter | `present` | `true`/`false`: did the agent supply verifying identity headers? With `identity_required` on, `false` means the call was refused; it is also what decides whether the gateway may report `full`. |
| `agentic_auth_gateway_upstream_latency` | Histogram | — | Time from request in to response out, for the p95 < 25 ms budget. |

## 3. Boundary adapters

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `agentic_auth_boundary_admissions` | Counter | `mode`, `result` | `mode` ∈ `resource` \| `connector` \| `network`. `result` is `admitted` or an `admit()` reason. Extends Phase 4's `agentic_auth_admissions`, which the verifier library already emits for the resource case. |
| `agentic_auth_connector_tools_filtered` | Counter | — | Tools removed from a `tools/list` result because the pinned policy does not declare them. |
| `agentic_auth_egress_uninspectable` | Counter | `cause` | Connections refused because they could not be inspected. Never allowed-by-default, so every increment is a refusal. |

## 4. Reused unchanged

These already exist and keep their meaning; they simply now also count decisions made at the new
enforcement points, which is the point of there being one decision core:

`agentic_auth_decisions`, `agentic_auth_denials`, `agentic_auth_audit_write_failures`,
`agentic_auth_taint_blocks`, `agentic_auth_taint_marks`, `agentic_auth_transaction_mints`,
`agentic_auth_revoked_hop_refusals`, `agentic_auth_exchange_pop_failures`,
`agentic_auth_admissions`, `agentic_auth_identity_view_age_seconds`.

## 5. What is never a label

Same rule as Phase 4, asserted by the test suite:

- No challenge id, token, grant, transaction token, identity assertion or private key.
- No parameter value, and no `params_hash`.
- No `session_id`, `action_id` or agent `sub` as a label — unbounded cardinality, and a session id
  in a metric is a correlation channel the audit trail already provides properly.

`reason`, `outcome`, `level`, `mode` and `status` are all bounded enums.
