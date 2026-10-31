"""The shared gateway PEP — the same decision core, deployed once and centrally.

``agentic_auth/gateway/app.py`` calls :func:`agentic_auth.sidecar.enforce.enforce` unmodified.
There is one ``enforce()`` in this codebase, which is what makes "the gateway reaches the same
decision as the sidecar" a structural property rather than a hope, and what the conformance suite
(``tests/conformance/``) exists to keep true.

What a gateway deliberately does not have: a signing key. See
:mod:`agentic_auth.gateway.config` and research.md R2.
"""

from __future__ import annotations

from agentic_auth.gateway.config import GatewayConfig, GatewayConfigError, load

__all__ = ["GatewayConfig", "GatewayConfigError", "load"]
