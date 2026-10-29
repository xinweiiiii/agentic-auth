"""Decision-history cursors: opaque, but never trusted."""

from __future__ import annotations

import base64
import json

import pytest

from app.errors import QueryValidationError
from app.services.audit_cursor import decode_cursor, encode_cursor


def _raw(payload: object) -> str:
    return base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()


def test_a_cursor_round_trips() -> None:
    assert decode_cursor(encode_cursor(before=40, hwm=60)) == (40, 60)


def test_the_cursor_is_url_safe_and_unpadded() -> None:
    cursor = encode_cursor(before=123456789, hwm=987654321)
    assert "=" not in cursor and "+" not in cursor and "/" not in cursor


@pytest.mark.parametrize(
    "cursor",
    [
        pytest.param("not base64 !!", id="not base64"),
        pytest.param(_raw("a string"), id="not an object"),
        pytest.param(base64.urlsafe_b64encode(b"{not json").decode(), id="not json"),
        pytest.param(_raw({"v": 2, "before": 1, "hwm": 2}), id="wrong version"),
        pytest.param(_raw({"v": 1, "hwm": 2}), id="missing before"),
        pytest.param(_raw({"v": 1, "before": "1", "hwm": 2}), id="string seq"),
        pytest.param(_raw({"v": 1, "before": True, "hwm": 2}), id="boolean seq"),
        pytest.param(_raw({"v": 1, "before": 0, "hwm": 2}), id="non-positive"),
        pytest.param(_raw({"v": 1, "before": 5, "hwm": 2}), id="before past the high-water mark"),
    ],
)
def test_anything_else_is_a_validation_error_naming_the_cursor(cursor: str) -> None:
    with pytest.raises(QueryValidationError) as exc:
        decode_cursor(cursor)

    assert exc.value.status_code == 422
    assert exc.value.details == {
        "fields": [{"loc": ["query", "cursor"], "msg": exc.value.details["fields"][0]["msg"]}]
    }
