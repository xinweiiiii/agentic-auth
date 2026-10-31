"""Cold start — a first-time agent earns a manifest by being watched.

An agent with no declared manifest is run in a sandbox where every tool is a mock that
records and performs nothing, and every call it attempts is allowed and recorded. From
that record :mod:`agentic_auth.coldstart.propose` folds a manifest candidate.

**The proposal governs nothing.** It is never compiled, so no session can pin it and no
decision can resolve against it, and only a human ratifying it makes it real (FR-036,
FR-037). ``tests/unit/test_proposed_is_inert.py`` asserts that directly rather than
trusting it to stay emergent.

Kept as its own package, importable from no decision path, because "a proposal that
reached the PDP" is the one failure this workstream cannot have.
"""

from __future__ import annotations

from agentic_auth.coldstart.propose import Observed, observe, propose, was_edited

__all__ = ["Observed", "observe", "propose", "was_edited"]
