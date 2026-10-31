# The Resource-Side Verifier Library (`agentic_auth.verify`)

Normative contract for the verifier library. A resource server implements against this.

For the owner of a tool or API who wants to admit only calls that carry a valid grant **and** a
valid identity **and**, for privileged tools, a valid transaction token. Importable with
`pyjwt[crypto]` only; no FastAPI, SQLAlchemy or Redis import (a unit test asserts the import
graph). Offline after bootstrap.

## Surface

```python
from agentic_auth.verify import Verifier, HttpJwks, HttpAnchors, RedisReplay, InMemoryReplay, Admission

verifier = Verifier(
    issuer_jwks=HttpJwks("https://control-plane/.well-known/jwks.json"),   # or StaticJwks(dict)
    anchors=HttpAnchors(
        base_url="https://control-plane", token=os.environ["AGENTIC_AUTH_AUDIT_READ_TOKEN"],
        agents=["support-agent", "balance-agent"], freshness_seconds=30,
    ),                                                                       # or StaticAnchors({name: AgentIdentityRead})
    replay=RedisReplay(redis) ,                                              # or InMemoryReplay() for a single process
    identity_required=True,
    leeway_seconds=60,
)
await verifier.bootstrap()          # fetches issuer JWKS, each agent's identity, the revocation list; starts the refresh loop

admission: Admission = verifier.admit(
    headers=request.headers,        # Authorization, Agent-Identity, Txn-Token
    target="mcp://accounts.internal/terminate_account",
    params=parsed_json_body,        # required when privileged=True
    privileged=True,
)
if not admission.ok:
    return 403, {"error": {"code": "not_admitted", "message": admission.reason, "details": admission.details}}
```

`admit()` does no I/O. `Admission` is `(ok: bool, reason: str | None, grant: VerifiedGrant | None,
identity: VerifiedIdentity | None, transaction: VerifiedTransaction | None)`.

## Checks, in order, all mandatory

1. **Grant** (`verify_grant`): `Authorization: Bearer` present → `GRANT_MISSING`; `alg`, `kid` in
   issuer JWKS, signature, `iss`, `exp`, required claims, `hop` agrees with `act` → `GRANT_INVALID`;
   `aud == target` → `GRANT_TARGET_MISMATCH`. Yields `holder_agent` (the outermost `act.sub`
   stripped of `agent://`, or `None` for a root-grant call, which is never valid at a resource →
   `GRANT_INVALID`).
2. **Identity** (when `identity_required`, `verify_identity`): `Agent-Identity` present →
   `IDENTITY_MISSING`; the anchor view is fresh → else `IDENTITY_STALE`; an anchor exists for
   `holder_agent` and is not revoked → else `IDENTITY_UNKNOWN_AGENT` / `IDENTITY_REVOKED`; `kid` in
   that anchor's JWKS, signature, `sub == "agent://" + holder_agent`, `aud == target`, `exp`,
   `grant_hash` matches the presented grant string → else `IDENTITY_INVALID`.
3. **Transaction** (when `privileged`, `verify_transaction`): see transaction-token.md
   "Verification order". `TXN_MISSING` when absent.

A refusal at any step stops the sequence; `reason` names the step.

## Stores

```python
class AnchorStore(Protocol):
    def current(self, agent: str) -> AgentIdentityRead | None: ...
    def revoked(self, agent: str) -> bool: ...
    def as_of(self) -> datetime | None: ...          # None until bootstrapped

class ReplayStore(Protocol):
    def claim(self, key: str, ttl_seconds: int) -> bool: ...   # True if first claim; raises ReplayStoreUnavailable
```

`HttpAnchors` reads `GET /v1/identity/agents/{name}` per configured agent and `GET /v1/identity/revocations`, needing only an identity-reader token, and refreshes every `freshness_seconds`; on failure it keeps the last view and lets
`as_of` age until `IDENTITY_STALE` refuses. `StaticAnchors` is for tests and air-gapped deployments
where anchors are shipped as files; it is never stale, and the integrator owns rotation.

## Metrics (optional)

`Verifier(metrics_registry=...)` emits `agentic_auth_transaction_rejections_total{cause}` and
`agentic_auth_admissions_total{result}`.

## Demonstration

`tests/fixtures/resource/server.py` is a Starlette app that guards one privileged and one ordinary
tool with `admit()` and records every admission and refusal. `tests/integration/test_identity_and_grant.py`
drives it through the sidecar.
