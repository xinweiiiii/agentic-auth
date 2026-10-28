"""Regenerate ``tests/fixtures/jcs_vectors.json``.

RFC 8785 Appendix B verbatim, plus this project's cases from
``docs/canonicalization.md`` §6. The
canonical strings are typed here by hand from the RFC, NOT produced by ``app.verify``, so
the vectors are an independent check on the implementation.

Run from the repository root:  ``python scripts/gen_jcs_vectors.py``
"""

from __future__ import annotations

import json
from pathlib import Path

OUT = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "jcs_vectors.json"

# fmt: off
VECTORS: list[dict] = [
    # -- RFC 8785 Appendix B ------------------------------------------------------
    {
        "name": "rfc-b-arrays",
        "input": [56, {"d": True, "10": None, "1": []}],
        "canonical": '[56,{"1":[],"10":null,"d":true}]',
    },
    {
        "name": "rfc-b-french",
        "input": {
            "peach": "This sorting order",
            "p\u00e9ch\u00e9": "is wrong according to French",
            "p\u00each\u00e9": "but canonicalization MUST",
            "sin": "ignore locale",
        },
        "canonical": (
            '{"peach":"This sorting order","p\u00e9ch\u00e9":"is wrong according to French",'
            '"p\u00each\u00e9":"but canonicalization MUST","sin":"ignore locale"}'
        ),
    },
    {
        "name": "rfc-b-structures",
        "input": {
            "1": {"f": {"f": "hi", "F": 5}, "\n": 56.0},
            "10": {},
            "": "empty",
            "a": {},
            "111": [{"e": "yes", "E": "no"}],
            "A": {},
        },
        "canonical": (
            '{"":"empty","1":{"\\n":56,"f":{"F":5,"f":"hi"}},"10":{},'
            '"111":[{"E":"no","e":"yes"}],"A":{},"a":{}}'
        ),
    },
    {
        "name": "rfc-b-unicode",
        "input": {"Unnormalized Unicode": "A\u030a"},
        "canonical": '{"Unnormalized Unicode":"A\u030a"}',
    },
    {
        "name": "rfc-b-values",
        "input": {
            "numbers": [333333333.33333329, 1e30, 4.50, 2e-3, 0.000000000000000000000000001],
            "string": "\u20ac$\u000f\u000aA'\u0042\u0022\u005c\\\"/",
            "literals": [None, True, False],
        },
        "canonical": (
            '{"literals":[null,true,false],'
            '"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],'
            '"string":"\u20ac$\\u000f\\nA\'B\\"\\\\\\\\\\"/"}'
        ),
    },
    # -- project cases (contracts/canonicalization.md §6) -----------------------------
    {"name": "key-order", "input": {"b": 1, "a": 2}, "canonical": '{"a":2,"b":1}'},
    {"name": "integral-float", "input": {"a": 1.0}, "canonical": '{"a":1}'},
    {"name": "exponent-int", "input": {"a": 1e2}, "canonical": '{"a":100}'},
    {"name": "fraction", "input": {"a": 0.1}, "canonical": '{"a":0.1}'},
    {"name": "negative-zero", "input": {"a": -0.0}, "canonical": '{"a":0}'},
    {"name": "small-exponent", "input": {"a": 1e-7}, "canonical": '{"a":1e-7}'},
    {"name": "large-exponent", "input": {"a": 1e21}, "canonical": '{"a":1e+21}'},
    {
        "name": "big-integer-float",
        "input": {"a": 123456789012345680000.0},
        "canonical": '{"a":123456789012345680000}',
    },
    {
        "name": "non-ascii-and-control",
        "input": {"\u20ac": "\u00e9", "a": "\n"},
        "canonical": '{"a":"\\n","\u20ac":"\u00e9"}',
    },
    {
        "name": "nested-arrays-keep-order",
        "input": {"z": [3, 1, 2], "y": [[2], [1]]},
        "canonical": '{"y":[[2],[1]],"z":[3,1,2]}',
    },
    {"name": "nan", "input_repr": "NaN", "error": True},
    {"name": "infinity", "input_repr": "Infinity", "error": True},
    {"name": "neg-infinity", "input_repr": "-Infinity", "error": True},
]
# fmt: on

BINDING_VECTOR = {
    "target": "mcp://accounts.internal/terminate_account",
    "params": {"reason": "fraud", "account_id": "acc-42", "notify": True},
    "binding": ["/account_id"],
    "document_canonical": (
        '{"params":{"/account_id":"acc-42"},"target":"mcp://accounts.internal/terminate_account"}'
    ),
    "whole_body_canonical": (
        '{"params":{"account_id":"acc-42","notify":true,"reason":"fraud"},'
        '"target":"mcp://accounts.internal/terminate_account"}'
    ),
}


def main() -> None:
    OUT.write_text(
        json.dumps(
            {"vectors": VECTORS, "binding_vector": BINDING_VECTOR}, ensure_ascii=False, indent=2
        )
        + "\n"
    )
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()
