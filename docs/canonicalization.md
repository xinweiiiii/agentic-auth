# Parameter Canonicalization and the Binding Hash

Normative wire format. Written so a resource server in any language can compute the
same binding from this document alone.

This contract is written so that a resource server in any language can compute the same binding
from it alone . Nothing here depends on this project's code.

## 1. Canonical JSON: RFC 8785 (JCS)

`canonical_json(value) -> bytes` implements RFC 8785 exactly:

- Objects: members sorted by key, comparing keys as sequences of UTF-16 code units; no whitespace;
  `{"a":1,"b":2}`.
- Arrays: element order preserved; no whitespace.
- Strings: JSON-escaped per RFC 8785 §3.2.2.2: `\"`, `\\`, `\b`, `\f`, `\n`, `\r`, `\t`, other
  control characters as `\u00XX` lowercase hex; everything else literal UTF-8 (no `\uXXXX` for
  non-ASCII).
- Integers: decimal, no leading zeros, no `+`. Any JSON number that is mathematically an integer
  with magnitude < 10^21 is rendered as an integer: `1.0` → `1`, `100e-2` → `1`.
- Other numbers: ECMAScript `Number::toString` (shortest round-trip): `0.1` → `0.1`, `1e21` →
  `1e+21`, `1e-7` → `1e-7`, `123456789012345680000` → `123456789012345680000`. `-0` → `0`.
- `NaN`, `Infinity`, `-Infinity`: **rejected** (not valid JSON; RFC 8785 forbids them).
- Literals: `true`, `false`, `null`.
- Output is UTF-8 bytes.

## 2. Binding selection: RFC 6901 JSON Pointers

`select_binding(params, binding) -> object`:

- `binding = null` → the whole `params` object.
- `binding = ["/a", "/b/0/c"]` → the object `{ "/a": <value>, "/b/0/c": <value> }` containing one
  member per pointer **that resolves**. A pointer that does not resolve is omitted. Keys are the
  pointer strings themselves.
- Pointers are evaluated on the parsed JSON, so `~0`/`~1` escapes apply.

Because the same selection is applied at mint and at verify, "absent at both" matches and "present
at mint, absent at verify" (or vice versa) mismatches, which is the spec's edge-case behaviour.

## 3. The binding hash

```
document    = { "target": <target string>, "params": select_binding(params, binding) }
params_hash = base64url_no_padding( SHA-256( canonical_json(document) ) )
```

`target` is the exact target ref string (`mcp://accounts.internal/terminate_account`).

## 4. What the token carries

```json
"azd": {
  "target": "mcp://accounts.internal/terminate_account",
  "params_hash": "K3sQ…",
  "hash_alg": "sha-256",
  "canon": "rfc8785",
  "binding": ["/account_id"]        // or null
}
```

A verifier MUST reject an `azd` whose `hash_alg` or `canon` it does not implement.

## 5. Size and shape limits

- `params` MUST be a JSON object. Arrays or scalars at the top level are rejected at mint (`422`).
- The serialized `params` MUST be at most `AGENTIC_AUTH_MAX_PRIVILEGED_BODY_BYTES` (default
  1 MiB). Larger bodies are refused at the sidecar and at the mint; nothing is forwarded unbound.
- Nesting depth is capped at 64.

## 6. Test vectors (`tests/fixtures/jcs_vectors.json`)

Each vector is `{ "input": <json>, "canonical": "<string>" }` or `{ "input": …, "error": true }`.
The file contains RFC 8785 Appendix B verbatim, plus:

| Input | Canonical |
|---|---|
| `{"b":1,"a":2}` | `{"a":2,"b":1}` |
| `{"a": 1.0}` | `{"a":1}` |
| `{"a": 1e2}` | `{"a":100}` |
| `{"a": 0.1}` | `{"a":0.1}` |
| `{"a": -0.0}` | `{"a":0}` |
| `{"a": 1e-7}` | `{"a":1e-7}` |
| `{"a": 1e21}` | `{"a":1e+21}` |
| `{"€":"é", "a":"\n"}` | `{"a":"\n","€":"é"}` |
| `{"a": NaN}` | error |

And the binding-hash vector used by `test_transaction_replay.py`:

```
target  = "mcp://accounts.internal/terminate_account"
params  = {"reason": "fraud", "account_id": "acc-42", "notify": true}
binding = ["/account_id"]
document canonical = {"params":{"/account_id":"acc-42"},"target":"mcp://accounts.internal/terminate_account"}
```

The independent reference implementation (`tests/unit/test_canonical_reference.py`) is written
from this file only and must agree on every vector.
