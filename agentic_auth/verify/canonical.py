"""RFC 8785 JSON Canonicalization Scheme, and the transaction-token binding hash.

This is the one implementation the control plane MINTS with and a resource server VERIFIES
with (``docs/canonicalization.md``). It is
written from the RFC so an independent implementation agrees with it, and it imports only
the standard library so ``agentic_auth.verify`` stays installable without the control plane.

Rules, in RFC order:

- object members sorted by key as UTF-16 code units; no whitespace anywhere
- strings escaped per §3.2.2.2; non-ASCII stays literal UTF-8
- integers as-is; every other number per ECMAScript ``Number::toString`` (shortest
  round-trip digits, positional between 1e-7 and 1e21, ``1e+21`` style exponents outside);
  ``-0`` → ``0``
- ``NaN`` / ``Infinity`` rejected (they are not JSON)
"""

from __future__ import annotations

import base64
import hashlib
import math
from collections.abc import Mapping, Sequence
from decimal import Decimal
from typing import Any

# `mutmut run` leaves 11 equivalent mutants in this module, none of which changes a result:
#
# - three change only the CASE of a codec name (`"utf-16-be"`, `"utf-8"`, `"ascii"`); Python
#   codec lookup is case-insensitive;
# - two strip a longer character SET that removes the same characters: `rstrip("XX0XX")` on a
#   digit string and `rstrip(b"XX=XX")` on a base64 digest. Neither string contains `X`, and
#   the 43rd character of a 32-byte base64 digest encodes 4 bits, so it is never `X`;
# - five sit on `_number` boundaries no input reaches: `value <= 0` (zero returned above),
#   `n < 21` (a 21-digit positional number needs more than 17 significant digits),
#   `n <= 1` (n = 1 is taken by the branch before), and the sign of an exponent `e >= 0` /
#   `e > 1` (this branch only runs for n > 21 or n <= -6, so e >= 21 or e <= -7);
# - one is `first = None` for `first = False`: both are falsy at its only use.
#
# Every mutant that changes a rendered number, a key order, a depth limit, a pointer
# resolution or a hash is killed (tests/unit/test_canonical.py, test_phase4_edges.py, and the
# independent reference in test_canonical_reference.py).

MAX_DEPTH = 64
HASH_ALG = "sha-256"
CANON = "rfc8785"

_ESCAPES = {
    '"': '\\"',
    "\\": "\\\\",
    "\b": "\\b",
    "\f": "\\f",
    "\n": "\\n",
    "\r": "\\r",
    "\t": "\\t",
}


class CanonicalizationError(ValueError):
    """The value cannot be canonicalized: not JSON, or deeper than allowed."""


def _utf16_key(key: str) -> bytes:
    """Sort keys by UTF-16 code units (RFC 8785 §3.2.3): big-endian UTF-16 bytes compare
    in code-unit order, which is what the RFC specifies (and differs from code-point order
    only for supplementary-plane characters)."""
    return key.encode("utf-16-be")


def _string(value: str) -> str:
    out: list[str] = ['"']
    for ch in value:
        if ch in _ESCAPES:
            out.append(_ESCAPES[ch])
        elif ord(ch) < 0x20:
            out.append(f"\\u{ord(ch):04x}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _number(value: float) -> str:
    """ECMAScript ``Number::toString`` for a finite double (ECMA-262 §6.1.6.1.20).

    With ``s`` the shortest round-trip digit string of ``k`` digits and ``n`` such that
    ``value = s × 10^(n-k)``:

    - ``k <= n <= 21``  → the digits followed by ``n-k`` zeros
    - ``0 < n <= 21``   → digits with a point after the first ``n``
    - ``-6 < n <= 0``   → ``0.`` then ``-n`` zeros then the digits
    - otherwise         → ``d.ddd e±(n-1)`` (no point when ``k == 1``)
    """
    if math.isnan(value) or math.isinf(value):
        raise CanonicalizationError("NaN and Infinity are not JSON numbers")
    if value == 0:
        return "0"  # covers -0.0
    sign = "-" if value < 0 else ""  # value == 0 returned above; -0.0 is "0"
    # repr() is the shortest string that round-trips, exactly the digits ES6 picks.
    digits_tuple, raw_exponent = Decimal(repr(abs(value))).as_tuple()[1:]
    exponent = int(raw_exponent)  # finite by construction; as_tuple types it loosely
    digits = "".join(str(d) for d in digits_tuple)
    stripped = digits.rstrip("0")
    exponent += len(digits) - len(stripped)
    # `Decimal.as_tuple()` never has leading zeros, and a nonzero value has a nonzero digit.
    digits = stripped
    k = len(digits)
    n = k + exponent

    if k <= n <= 21:
        body = digits + "0" * (n - k)
    elif 0 < n <= 21:
        body = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        body = "0." + "0" * (-n) + digits
    else:
        mantissa = digits if k == 1 else digits[0] + "." + digits[1:]
        e = n - 1
        body = f"{mantissa}e{'+' if e > 0 else '-'}{abs(e)}"
    return sign + body


def _canonical(value: Any, depth: int, out: list[str]) -> None:
    if depth > MAX_DEPTH:
        raise CanonicalizationError(f"nesting deeper than {MAX_DEPTH}")
    if value is None:
        out.append("null")
    elif value is True:
        out.append("true")
    elif value is False:
        out.append("false")
    elif isinstance(value, int):
        out.append(str(value))
    elif isinstance(value, float):
        out.append(_number(value))
    elif isinstance(value, str):
        out.append(_string(value))
    elif isinstance(value, Mapping):
        out.append("{")
        first = True
        for key in sorted(value, key=_utf16_key):
            if not isinstance(key, str):
                raise CanonicalizationError("object keys must be strings")
            if not first:
                out.append(",")
            first = False
            out.append(_string(key))
            out.append(":")
            _canonical(value[key], depth + 1, out)
        out.append("}")
    elif isinstance(value, Sequence) and not isinstance(value, bytes | bytearray):
        out.append("[")
        for index, item in enumerate(value):
            if index:
                out.append(",")
            _canonical(item, depth + 1, out)
        out.append("]")
    else:
        raise CanonicalizationError(f"{type(value).__name__} is not a JSON value")


def canonical_json(value: Any) -> bytes:
    """The RFC 8785 canonical form of ``value``, as UTF-8 bytes."""
    out: list[str] = []
    _canonical(value, 0, out)
    return "".join(out).encode("utf-8")


# -- binding selection: RFC 6901 --------------------------------------------------------


def _resolve_pointer(document: Any, pointer: str) -> tuple[bool, Any]:
    if pointer == "":
        return True, document
    if not pointer.startswith("/"):
        raise CanonicalizationError(f"invalid JSON pointer {pointer!r}")
    node = document
    for raw in pointer.split("/")[1:]:
        token = raw.replace("~1", "/").replace("~0", "~")
        if isinstance(node, Mapping):
            if token not in node:
                return False, None
            node = node[token]
        elif isinstance(node, Sequence) and not isinstance(node, str | bytes):
            if not token.isdigit() or int(token) >= len(node):
                return False, None
            node = node[int(token)]
        else:
            return False, None
    return True, node


def select_binding(params: Mapping[str, Any], binding: Sequence[str] | None) -> dict[str, Any]:
    """The object a transaction token binds: the whole body, or ``{pointer: value}`` for
    every pointer that resolves. Pointers that do not resolve are omitted, on both sides,
    so "absent at both" matches and "present at one side only" mismatches."""
    if binding is None:
        return dict(params)
    selected: dict[str, Any] = {}
    for pointer in binding:
        found, value = _resolve_pointer(params, pointer)
        if found:
            selected[pointer] = value
    return selected


def binding_document(
    target: str, params: Mapping[str, Any], binding: Sequence[str] | None
) -> dict[str, Any]:
    return {"target": target, "params": select_binding(params, binding)}


def binding_hash(target: str, params: Mapping[str, Any], binding: Sequence[str] | None) -> str:
    """base64url, no padding, of SHA-256 over the canonical binding document."""
    digest = hashlib.sha256(canonical_json(binding_document(target, params, binding))).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


__all__ = [
    "CANON",
    "HASH_ALG",
    "MAX_DEPTH",
    "CanonicalizationError",
    "binding_document",
    "binding_hash",
    "canonical_json",
    "select_binding",
]
