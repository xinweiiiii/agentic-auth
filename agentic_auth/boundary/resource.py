"""Resource-side enforcement — the strongest rung of FR-14 (FR-007..FR-009).

**Use this when you own the tool.** The calling agent's cooperation is irrelevant: a call
is admitted only when it carries an identity that verifies against pinned material, a
grant valid for this target and this hop, and — for a privileged target — a call-bound
authority matching the parameters actually presented. An agent nobody can modify, that
will never run an enforcement process, is still governed here (FR-008).

Deliberately thin. Phase 4 shipped :mod:`agentic_auth.verify` as a dependency-light library
precisely so this would be a wrapper rather than a second implementation: everything this
module decides, ``Verifier.admit()`` decides, and the conjunction that makes identity
insufficient on its own lives there.

**Import direction is one-way.** This package imports :mod:`agentic_auth.verify`; nothing in
``agentic_auth.verify`` imports ``agentic_auth.boundary``. ``tests/unit/test_verify_imports.py``
keeps the verifier's closed import graph intact, so a resource server still installs it
without FastAPI, SQLAlchemy or Redis.

Usage::

    verifier = Verifier(issuer_jwks=HttpJwks(...), anchors=HttpAnchors(...), replay=...)
    await verifier.bootstrap()
    app.add_middleware(
        RequireAgenticAuth,
        verifier=verifier,
        target_for=lambda scope: f"mcp://bank{scope['path']}",
        privileged={"mcp://bank/terminate_account"},
    )
"""

from __future__ import annotations

import json
import logging
from collections.abc import Callable, Iterable

from starlette.types import ASGIApp, Message, Receive, Scope, Send

from agentic_auth.boundary.guarantee import Guarantee
from agentic_auth.verify import Admission, Verifier

logger = logging.getLogger(__name__)

# The guard is in the call path and checks identity, grant and binding, so `full` is what
# it honestly reports (contracts/guarantee-level.md §2).
GUARANTEE = Guarantee.FULL

# Refusals that mean "you presented nothing" rather than "what you presented is wrong".
# 401 invites the caller to authenticate; 403 tells it not to bother.
_UNAUTHENTICATED = frozenset({"GRANT_MISSING", "IDENTITY_MISSING", "TXN_MISSING"})

TargetFor = Callable[[Scope], str | None]
"""Maps a request to the policy target it is authorized against. ``None`` = not protected."""


class RequireAgenticAuth:
    """ASGI middleware admitting only on identity AND grant AND (privileged) transaction.

    ``target_for`` decides both *what* the call is authorized against and *whether* the
    route is protected at all: returning ``None`` passes the request straight through, so
    the guard is opt-in per resource and an unprotected route in the same app is
    untouched (spec story 2 scenario 8).

    ``privileged`` names the targets that additionally require a call-bound authority. It
    is a set rather than a flag on the request because the resource owner, not the caller,
    decides what is destructive.
    """

    def __init__(
        self,
        app: ASGIApp,
        *,
        verifier: Verifier,
        target_for: TargetFor,
        privileged: Iterable[str] = (),
        max_body_bytes: int = 1_048_576,
        on_admission: Callable[[Admission, str], None] | None = None,
    ) -> None:
        self.app = app
        self._verifier = verifier
        self._target_for = target_for
        self._privileged = frozenset(privileged)
        self._max_body_bytes = max_body_bytes
        self._on_admission = on_admission

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        target = self._target_for(scope)
        if target is None:
            await self.app(scope, receive, send)
            return

        privileged = target in self._privileged
        params: dict | None = None
        replay = receive

        if privileged:
            # Buffer the body so the binding can be recomputed. Over the cap is a refusal,
            # never a forward: a body too large to bind is a body we cannot say anything
            # about, and forwarding it unbound would be the silent pass this exists to
            # prevent. Same rule and same cap as the sidecar.
            body, overflow = await _buffer(receive, self._max_body_bytes)
            if overflow:
                await _refuse(
                    send,
                    403,
                    "BODY_TOO_LARGE_TO_BIND",
                    f"body exceeds {self._max_body_bytes} bytes and cannot be bound",
                )
                return
            try:
                parsed = json.loads(body or b"{}")
            except ValueError:
                parsed = None
            if not isinstance(parsed, dict):
                await _refuse(
                    send,
                    403,
                    "TXN_PARAMS_MISMATCH",
                    "a privileged call's body must be a JSON object so it can be bound",
                )
                return
            params = parsed
            replay = _replay(body)

        admission = self._verifier.admit(
            _headers(scope), target=target, params=params, privileged=privileged
        )
        if self._on_admission is not None:
            self._on_admission(admission, target)

        if not admission.ok:
            reason = admission.reason or "FORBIDDEN"
            status = 401 if reason in _UNAUTHENTICATED else 403
            # The reason names exactly the step that failed and nothing else, so a
            # resource can answer precisely without leaking what it knows about the rest.
            await _refuse(send, status, reason, admission.detail or "not admitted")
            return

        await self.app(scope, replay, send)


async def _buffer(receive: Receive, cap: int) -> tuple[bytes, bool]:
    chunks: list[bytes] = []
    total = 0
    while True:
        message = await receive()
        if message["type"] != "http.request":
            break
        chunk = message.get("body", b"")
        total += len(chunk)
        if total > cap:
            return b"", True
        chunks.append(chunk)
        if not message.get("more_body", False):
            break
    return b"".join(chunks), False


def _replay(body: bytes) -> Receive:
    """Hand the buffered bytes to the app, exactly as they were bound."""
    sent = False

    async def receive() -> Message:
        nonlocal sent
        if sent:
            return {"type": "http.disconnect"}
        sent = True
        return {"type": "http.request", "body": body, "more_body": False}

    return receive


def _headers(scope: Scope) -> dict[str, str]:
    return {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope.get("headers", [])}


async def _refuse(send: Send, status: int, reason: str, detail: str) -> None:
    body = json.dumps(
        {
            "error": {
                "code": "unauthorized" if status == 401 else "forbidden",
                "message": detail,
                "details": {"reason": reason, "guarantee_level": GUARANTEE.value},
            }
        }
    ).encode()
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode()),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})


__all__ = ["GUARANTEE", "RequireAgenticAuth", "TargetFor"]
