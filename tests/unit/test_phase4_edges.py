"""Boundary and negative cases for the Phase 4 pure modules (mutation testing).

Each test pins one behaviour a mutant of ``canonical``, ``admit`` or ``taint`` changed and
the first round of tests did not notice.
"""

from __future__ import annotations

import pytest

from agentic_auth.services.taint import SENTINEL, ancestors_of
from agentic_auth.verify.canonical import (
    CanonicalizationError,
    binding_hash,
    canonical_json,
    select_binding,
)

# -- ES6 Number::toString boundaries ---------------------------------------------------------


@pytest.mark.parametrize(
    "value,expected",
    [
        (-1.5, "-1.5"),
        (-0.25, "-0.25"),
        (-1e-7, "-1e-7"),
        (-1.5e25, "-1.5e+25"),
        (0.5, "0.5"),
        (10.5, "10.5"),
        (123456.789, "123456.789"),
        (1e20, "100000000000000000000"),
        (1e21, "1e+21"),
        (1.5e21, "1.5e+21"),
        (1.5e25, "1.5e+25"),
        (0.000001, "0.000001"),
        (0.0000015, "0.0000015"),
        (1e-7, "1e-7"),
        (1.5e-7, "1.5e-7"),
        (123e-9, "1.23e-7"),
        (2.5e-10, "2.5e-10"),
        (100.0, "100"),
        (-100.0, "-100"),
        (0.1 + 0.2, "0.30000000000000004"),
    ],
)
def test_number_formatting_matches_ecmascript(value: float, expected: str) -> None:
    assert canonical_json(value).decode() == expected


def test_a_negative_integer_and_bool_are_not_confused() -> None:
    assert canonical_json([-3, True, False, 0, None]).decode() == "[-3,true,false,0,null]"


# -- depth ----------------------------------------------------------------------------------------


def _nested(levels: int) -> dict:
    node: dict = {}
    for _ in range(levels):
        node = {"x": node}
    return node


def test_depth_64_is_accepted_and_65_is_refused() -> None:
    canonical_json(_nested(64))
    with pytest.raises(CanonicalizationError, match="deeper than 64"):
        canonical_json(_nested(65))


def _nested_list(levels: int) -> list:
    node: list = []
    for _ in range(levels):
        node = [node]
    return node


def test_the_depth_limit_applies_to_arrays_and_mixed_nesting_too() -> None:
    canonical_json(_nested_list(64))
    with pytest.raises(CanonicalizationError, match="deeper than 64"):
        canonical_json(_nested_list(65))
    mixed: object = {}
    for index in range(65):
        mixed = [mixed] if index % 2 else {"x": mixed}
    with pytest.raises(CanonicalizationError):
        canonical_json(mixed)


# -- pointers ------------------------------------------------------------------------------------


def test_a_pointer_never_descends_into_a_string() -> None:
    """A str is a Sequence in Python; RFC 6901 on JSON must not index into its characters."""
    assert select_binding({"a": "xyz"}, ["/a/0"]) == {}
    assert select_binding({"a": "xyz"}, ["/a"]) == {"/a": "xyz"}


def test_list_indexes_are_bounded_and_numeric() -> None:
    params = {"l": [10, 20]}
    assert select_binding(params, ["/l/0", "/l/1"]) == {"/l/0": 10, "/l/1": 20}
    assert select_binding(params, ["/l/2", "/l/-1", "/l/x", "/l/"]) == {}


def test_the_root_pointer_selects_the_whole_document() -> None:
    assert select_binding({"a": 1}, [""]) == {"": {"a": 1}}


def test_a_pointer_without_a_leading_slash_is_refused() -> None:
    with pytest.raises(CanonicalizationError):
        select_binding({"a": 1}, ["a"])


def test_pointers_do_not_descend_through_scalars() -> None:
    assert select_binding({"a": 5}, ["/a/b"]) == {}
    assert select_binding({"a": None}, ["/a/b"]) == {}


def test_the_binding_hash_is_43_url_safe_characters_without_padding() -> None:
    h = binding_hash("mcp://x/y", {"a": 1}, None)
    assert (
        len(h) == 43
        and "=" not in h
        and set(h) <= set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
    )


def test_a_binding_hash_is_always_43_characters() -> None:
    """base64url of 32 bytes is 43 characters plus one `=`, stripped. (The 43rd character
    encodes 4 bits, so it is never `X`: stripping "XX=XX" instead of "=" is equivalent.)"""
    hashes = [binding_hash("mcp://x/y", {"n": i}, None) for i in range(600)]
    assert {len(h) for h in hashes} == {43}


def test_canonical_json_is_utf8_bytes() -> None:
    out = canonical_json({"é": "€"})
    assert isinstance(out, bytes) and out == '{"é":"€"}'.encode()


# -- taint ------------------------------------------------------------------------------


def test_ancestors_treat_a_non_string_or_empty_jti_as_unknown() -> None:
    chain = [{"subject_jti": 42}, {"subject_jti": ""}, {"subject_jti": None}, {}]
    assert ancestors_of(chain, "own") == {"own", SENTINEL}
    assert ancestors_of([{"subject_jti": "j1"}], "own") == {"own", "j1"}
