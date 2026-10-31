# Contract — Cross-Mode Conformance

FR-043, FR-044, SC-001. One chain, five enforcement points, one answer.

The claim this phase has to defend is that gateway, sidecar and boundary adapters are *one policy*
deployed several ways, not three policies that happen to agree today. This file is what makes that
claim falsifiable.

## 1. The fixture

`tests/fixtures/chain.py` defines one chain, deliberately covering every decision shape the phases
so far produce:

| Hop | Shape | Expected |
|---|---|---|
| 1 | `user:alice` → `agent://support-agent`, `account.read` | allow |
| 2 | `support-agent` → `mcp://kb/search`, `kb.read` (untrusted source) | allow, marks the context tainted |
| 3 | `support-agent` → `mcp://bank/read_account`, `account.read` | allow, not privileged |
| 4 | `support-agent` → `mcp://bank/terminate_account`, `account.write` (privileged, tainted) | deny `TAINTED_INTO_PRIVILEGED`, not recoverable |
| 5 | `support-agent` → `agent://billing-agent` where `billing-agent` is revoked | deny `AGENT_REVOKED` |
| 6 | `support-agent` → `mcp://bank/read_account`, `account.audit` (declared, not consented) | deny `SCOPE_NOT_CONSENTED`, recoverable |
| 7 | `support-agent` → `mcp://bank/read_account`, `nonsense.class` (undeclared) | deny `OUT_OF_SCOPE`, not recoverable |

Hops 6 and 7 are the pair that only exists once consent has granularity below the scope
(research.md R5). With `consent_granularity_enabled=false` hop 6 cannot occur and hop 7 answers
`SCOPE_NOT_CONSENTED`; the fixture is parametrized over the flag so both regimes are covered.

## 2. The enforcement points

```python
PEPS = ["sidecar", "gateway", "resource_guard", "connector_proxy", "egress_proxy"]
```

`tests/conformance/test_all_peps.py` parametrizes the fixture over all five. One file, so an
operator asking "is this really one policy?" has one place to look.

## 3. What is compared

**Equal across every PEP, per hop:**

- `outcome` (`allow` | `deny`)
- `deny_reason` — the exact `DenyReason` value, not just the fact of a refusal
- `recoverable`
- `hop`
- the audit row's `(caller, target, data_class, policy_version, act_chain)`

**Deliberately not compared:**

- `guarantee_level` and the enforcement point — these are *expected* to differ; that is the whole
  purpose of the field. Asserted separately, per PEP, against the table in
  [guarantee-level.md](./guarantee-level.md) §2.
- The response envelope. It legitimately differs by transport — the connector proxy returns a
  JSON-RPC error, the others return the project envelope. Comparing bodies would force the suite to
  encode the very differences it exists to detect (research.md R14).
- Latency. Measured in `tests/load/multi_hop.py`, not here.

## 4. Documented exceptions (FR-044)

A mode that cannot observe an input the decision needs is a *lower guarantee level plus an
exception recorded here* — never a silently different decision. There are exactly two.

### 4.1 The resource-side guard sees one hop, not a chain

`app.verify.admit()` decides from the request headers alone: grant, identity, and for a privileged
target the transaction binding. It has no view of hop budget, delegation edges or context taint,
because those live in the control plane and the guard is deliberately offline-capable.

So the guard participates for hops 1, 3, 4 and 7 — where the presented artefacts are sufficient to
decide — and the suite asserts it *refuses* on hops 4 and 7 for the artefact that is missing or
mismatched, rather than asserting it reproduces `TAINTED_INTO_PRIVILEGED` by name. Hop 4's refusal
at the guard is `TXN_MISSING`: the control plane never minted a transaction token for a refused
hop, so the privileged call arrives without one and is refused. Same outcome, different and
narrower reason, and that is correct rather than a divergence.

### 4.2 A consent-only deployment makes no per-hop decision

It contributes coarse grant-time scoping, revocation and an edge audit row. The suite asserts that
asking it for a per-hop decision yields `503 guarantee_insufficient` — that it *declines* rather
than approximates (spec edge case, FR-015). It is not compared hop by hop, because there is nothing
per-hop to compare.

## 5. The suite is a gate

FR-043's "fails if any one of them diverges" means CI, not a report an operator reads. The
conformance job runs on every pull request alongside the existing drift check, and a divergence
fails the build.

This is the same discipline Phase 3 applied to `edge_rules.py`, where the CI drift check and the
runtime share one function so they cannot disagree. Here the shared function is `enforce()` and the
shared service is the control plane; the suite proves the sharing survived deployment.

## 6. Adding a sixth enforcement point

Add it to `PEPS` and make the suite pass. If it cannot observe something the fixture needs, it gets
an entry in §4 stating what it cannot see and which guarantee level that implies — a new exception
is a contract change, reviewed as one, not a test skip.
