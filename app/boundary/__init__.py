"""Boundary enforcement — the FR-14 rungs, in decreasing order of strength.

Each module here answers a different "what does the integrator actually control?":

- :mod:`app.boundary.resource` — you own the tool. A guard over Phase 4's
  :mod:`app.verify`, admitting only on identity AND grant AND (privileged) transaction.
  The calling agent's cooperation is irrelevant. Reports ``full``.
- :mod:`app.boundary.mcp` — you own the agent's tool configuration. Repoint it at this
  proxy and the agent never knows. Reports ``connector``.
- :mod:`app.boundary.egress` — you own the runtime and nothing else. A CONNECT proxy with
  TLS interception, so the agent's only route out is through us. Reports ``network``.

**None of them re-implements policy.** ``resource`` calls ``app.verify.Verifier.admit()``;
``mcp`` and ``egress`` call ``app.sidecar.enforce.enforce()``. That is what makes the
conformance suite meaningful rather than aspirational: there is one decision core, and the
modes differ only in transport and trust assumptions.

Import direction is one-way: this package imports :mod:`app.verify`, never the reverse, so
the verifier library's closed import graph is preserved.
"""

from __future__ import annotations

from app.boundary.guarantee import STRENGTH, Guarantee, is_degrade, strongest, weakest

__all__ = ["Guarantee", "STRENGTH", "strongest", "weakest", "is_degrade"]
