# Contract: Metrics (Phase 4 additions)

Same rules as Phase 3 (`docs/contracts/metrics/phase3.md`): `prometheus-client`,
`GET /metrics` on the control plane, **labels never carry identities**. Per-source and per-agent
breakdowns come from the audit history API.

## Control plane (`/metrics`)

| Name | Type | Labels | Meaning | Spec |
|---|---|---|---|---|
| `agentic_auth_denials_total` | counter | `reason` | Existing; now also `TAINTED_INTO_PRIVILEGED`, `AGENT_REVOKED`, `AGENT_NOT_ENROLLED` | FR-044 |
| `agentic_auth_taint_blocks_total` | counter | `source_class` (`tool`\|`agent`\|`reported`\|`unknown`) | `TAINTED_INTO_PRIVILEGED` refusals by what introduced the taint: a tool target, an agent target, an agent-reported label, or the `*` sentinel | FR-044 |
| `agentic_auth_taint_marks_total` | counter | `propagation` (`self`\|`ancestor`\|`sentinel`) | Contexts marked tainted, for tuning `trusted_sources` before enforcing | FR-044 |
| `agentic_auth_transaction_mints_total` | counter | `result` (`minted`\|`not_privileged`\|`already_minted`\|`tainted`\|`invalid_token`\|`too_large`) | `POST /v1/token/transaction` outcomes | FR-044 |
| `agentic_auth_enrollments_total` | counter | `outcome` (`enrolled`\|`quarantined`\|`rejected`\|`key_revoked`\|`idp_unavailable`\|`reconciliation_rejected`) | `enroll/complete` outcomes | FR-044 |
| `agentic_auth_revocations_total` | counter | — | Revocations that changed state (idempotent repeats are not counted) | FR-044 |
| `agentic_auth_revoked_hop_refusals_total` | counter | `where` (`authorize`\|`exchange`) | Hops refused because an agent on the chain is revoked | FR-044 |
| `agentic_auth_exchange_pop_failures_total` | counter | `cause` (`missing`\|`invalid`\|`wrong_agent`\|`not_enrolled`) | `actor_token` failures at the exchange | — |

## Verifier library (integrator's registry, optional)

| Name | Type | Labels | Meaning | Spec |
|---|---|---|---|---|
| `agentic_auth_admissions_total` | counter | `result` (`admitted`\|`<refusal reason>`) | `admit()` outcomes | FR-044 |
| `agentic_auth_transaction_rejections_total` | counter | `cause` (`target_mismatch`\|`params_mismatch`\|`replay`\|`expired`\|`malformed`\|`store_unavailable`) | Transaction-token rejections by cause (transaction-token.md) | FR-005, FR-044 |
| `agentic_auth_identity_view_age_seconds` | gauge | — | `now - as_of` of the anchor view; alert when it approaches `freshness_seconds` | FR-040 |

## Dashboard guidance

- **Tuning taint:** with enforcement off, `taint_marks_total` by `propagation` plus the audit
  filter `taint=untrusted_external` show which sources would block privileged calls once enforced.
- **Replay attempts:** `transaction_rejections_total{cause="replay"}` should be zero in steady
  state; any value is a token being presented twice.
- **Stuck in quarantine:** `enrollments_total{outcome="quarantined"}` minus later `enrolled` for
  the same agents; the list itself is `GET /v1/agents?status=quarantined`.
