"""Opaque cursors for the decision history.

A cursor carries two insertion sequence numbers: ``before`` (page strictly below it) and
``hwm`` (the high-water mark fixed when the first page was served). Holding ``hwm`` across
the iteration is what keeps paging stable while decisions keep being recorded: a row
appended mid-iteration has ``seq > hwm`` and never appears in it.

Opaque to clients, but never trusted: anything that does not decode to a well-formed cursor
is a ``422`` naming ``cursor`` — not a silent restart at page one, which is what Phase 2's
id-anchored cursor did.
"""

from __future__ import annotations

import base64
import binascii
import json

from agentic_auth.errors import QueryValidationError

CURSOR_VERSION = 1


def encode_cursor(before: int, hwm: int) -> str:
    raw = json.dumps({"v": CURSOR_VERSION, "before": before, "hwm": hwm}, separators=(",", ":"))
    return base64.urlsafe_b64encode(raw.encode()).rstrip(b"=").decode()


def _invalid(reason: str) -> QueryValidationError:
    return QueryValidationError(
        f"invalid cursor: {reason}", [{"loc": ["query", "cursor"], "msg": reason}]
    )


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def decode_cursor(cursor: str) -> tuple[int, int]:
    """``(before, hwm)``, or ``QueryValidationError``."""
    try:
        padded = cursor + "=" * (-len(cursor) % 4)
        data = json.loads(base64.urlsafe_b64decode(padded))
    except (ValueError, binascii.Error, UnicodeDecodeError) as exc:
        raise _invalid("not a cursor issued by this API") from exc

    if not isinstance(data, dict) or data.get("v") != CURSOR_VERSION:
        raise _invalid("unsupported cursor version")
    before, hwm = data.get("before"), data.get("hwm")
    if not (_is_int(before) and _is_int(hwm)):
        raise _invalid("malformed cursor")
    assert isinstance(before, int) and isinstance(hwm, int)  # narrowed above
    if before < 1 or hwm < 1 or before > hwm:
        raise _invalid("malformed cursor")
    return before, hwm
