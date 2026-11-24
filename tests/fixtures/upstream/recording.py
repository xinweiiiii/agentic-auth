"""No-passthrough assertions over what an upstream actually received (INV-1).

Works on either recorder: the generic upstream's ``Recorder`` and the MCP server's
``McpRecorder``. The check is deliberately blunt — any appearance of the whole token, any
of its three segments, or its ``jti`` anywhere in any header or body fails — because a
leak that re-encodes part of a token is still a leak, and a substring scan is the only
check that does not need to guess how it was re-encoded.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

import jwt

#: Segments shorter than this are too likely to collide with ordinary text to be evidence.
_MIN_FRAGMENT = 8


def token_material(token: str) -> list[str]:
    """Every fragment of ``token`` whose presence upstream counts as passthrough."""
    fragments = [token, *[part for part in token.split(".") if len(part) >= _MIN_FRAGMENT]]
    try:
        jti = jwt.decode(token, options={"verify_signature": False}).get("jti")
    except jwt.PyJWTError:
        jti = None
    if isinstance(jti, str) and len(jti) >= _MIN_FRAGMENT:
        fragments.append(jti)
    return fragments


def received_text(recorder: Any) -> Iterable[str]:
    """Every header value and body the recorder saw, as text."""
    if hasattr(recorder, "requests"):  # tests.fixtures.upstream.server.Recorder
        for request in recorder.requests:
            yield from (f"{k}: {v}" for k, v in request["headers"].items())
            yield request.get("query", "")
            yield request.get("body", "")
    else:  # tests.fixtures.mcp.server.McpRecorder
        for headers in recorder.headers:
            yield from (f"{k}: {v}" for k, v in headers.items())
        yield from getattr(recorder, "bodies", [])


def assert_no_token_material(token: str, *recorders: Any) -> None:
    """Fail if any part of ``token`` reached any of ``recorders``."""
    fragments = token_material(token)
    for recorder in recorders:
        for text in received_text(recorder):
            for fragment in fragments:
                if fragment in text:
                    label = "the whole token" if fragment == token else "a token fragment"
                    # Say where, not what: the message must not repeat the token it caught.
                    where = text.split(": ", 1)[0] if ": " in text[:64] else "a request body"
                    raise AssertionError(
                        f"{label} reached the upstream ({type(recorder).__name__}) in {where!r}"
                    )


__all__ = ["assert_no_token_material", "received_text", "token_material"]
