"""An independent canonicalizer, written ONLY from contracts/canonicalization.md, must agree
with ``app.verify.canonical`` on every vector (SC-003).

Deliberately naive and separate: it shares no code with the implementation. Where the two
disagree, one of them misreads the RFC — and the vectors say which.
"""

from __future__ import annotations

import json
import math
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest

from app.verify.canonical import canonical_json

VECTORS = json.loads(
    (Path(__file__).resolve().parents[1] / "fixtures" / "jcs_vectors.json").read_text()
)


def _ref_number(x: float) -> str:
    if x == 0:
        return "0"
    if math.isnan(x) or math.isinf(x):
        raise ValueError
    sign = "-" if x < 0 else ""
    d = Decimal(repr(abs(x)))
    digits, exp = d.as_tuple()[1], d.as_tuple()[2]
    s = "".join(map(str, digits)).rstrip("0")
    exp += len(digits) - len(s)
    s = s.lstrip("0") or "0"
    k, n = len(s), len(s) + exp
    if k <= n <= 21:
        return sign + s + "0" * (n - k)
    if 0 < n <= 21:
        return sign + s[:n] + "." + s[n:]
    if -6 < n <= 0:
        return sign + "0." + "0" * (-n) + s
    m = s if k == 1 else s[0] + "." + s[1:]
    return f"{sign}{m}e{'+' if n - 1 > 0 else '-'}{abs(n - 1)}"


def _ref_string(s: str) -> str:
    table = {
        '"': '\\"',
        "\\": "\\\\",
        "\b": "\\b",
        "\f": "\\f",
        "\n": "\\n",
        "\r": "\\r",
        "\t": "\\t",
    }
    return '"' + "".join(table.get(c, f"\\u{ord(c):04x}" if ord(c) < 0x20 else c) for c in s) + '"'


def _ref(v: Any) -> str:
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, float):
        return _ref_number(v)
    if isinstance(v, str):
        return _ref_string(v)
    if isinstance(v, list):
        return "[" + ",".join(_ref(i) for i in v) + "]"
    if isinstance(v, dict):
        keys = sorted(v, key=lambda k: k.encode("utf-16-be"))
        return "{" + ",".join(_ref_string(k) + ":" + _ref(v[k]) for k in keys) + "}"
    raise ValueError(type(v))


@pytest.mark.parametrize(
    "vector", [v for v in VECTORS["vectors"] if not v.get("error")], ids=lambda v: v["name"]
)
def test_reference_and_implementation_agree(vector) -> None:
    reference = _ref(vector["input"])
    assert reference == vector["canonical"], "the reference misreads the contract"
    assert canonical_json(vector["input"]).decode() == reference


def test_reference_agrees_on_the_binding_document() -> None:
    v = VECTORS["binding_vector"]
    doc = {"target": v["target"], "params": {"/account_id": v["params"]["account_id"]}}
    assert _ref(doc) == v["document_canonical"] == canonical_json(doc).decode()
