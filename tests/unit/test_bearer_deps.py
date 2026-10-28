"""Audit read access: reader token or admin token, nothing else (T013, FR-020)."""

from __future__ import annotations

import pytest

from app.api.deps import require_audit_reader
from app.config import get_settings
from app.errors import UnauthorizedError
from tests.conftest import ADMIN_TOKEN

READER_TOKEN = "test-audit-reader"


@pytest.fixture
def reader_token(monkeypatch):
    monkeypatch.setenv("AGENTIC_AUTH_AUDIT_READ_TOKEN", READER_TOKEN)
    get_settings.cache_clear()
    yield READER_TOKEN
    monkeypatch.delenv("AGENTIC_AUTH_AUDIT_READ_TOKEN")
    get_settings.cache_clear()


async def test_the_reader_token_is_accepted(reader_token) -> None:
    await require_audit_reader(f"Bearer {reader_token}")


async def test_the_admin_token_is_accepted(reader_token) -> None:
    await require_audit_reader(f"Bearer {ADMIN_TOKEN}")


async def test_the_admin_token_is_accepted_with_no_reader_token_configured() -> None:
    assert get_settings().audit_read_token == ""
    await require_audit_reader(f"Bearer {ADMIN_TOKEN}")


async def test_an_empty_reader_setting_does_not_accept_an_empty_bearer() -> None:
    assert get_settings().audit_read_token == ""
    with pytest.raises(UnauthorizedError):
        await require_audit_reader("Bearer ")


async def test_a_wrong_token_is_refused(reader_token) -> None:
    with pytest.raises(UnauthorizedError, match="invalid audit reader bearer token"):
        await require_audit_reader("Bearer not-the-token")


@pytest.mark.parametrize("header", [None, "", "Basic abc", "bearer lowercase"])
async def test_a_missing_or_malformed_header_is_refused(header) -> None:
    with pytest.raises(UnauthorizedError):
        await require_audit_reader(header)


# -- both bearer checks are constant-time -------------------------------------------


def test_both_bearer_checks_compare_in_constant_time() -> None:
    """`!=` stops at the first differing byte, leaking how much of a token was guessed.

    A grep-shaped test, deliberately: the property is textual, and the next person to add a
    credential check in this module needs to be told which comparison to use.
    """
    import ast
    import inspect

    from app.api import deps

    tree = ast.parse(inspect.getsource(deps))
    checkers = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.AsyncFunctionDef) and node.name.startswith("require_")
    ]
    assert {f.name for f in checkers} == {
        "require_admin",
        "require_audit_reader",
        "require_enroller",
        "require_identity_reader",
    }

    for func in checkers:
        compares = [
            node
            for node in ast.walk(func)
            if isinstance(node, ast.Compare)
            and any(isinstance(op, ast.Eq | ast.NotEq) for op in node.ops)
        ]
        assert not compares, (
            f"{func.name} compares a credential with ==/!=; use hmac.compare_digest"
        )
        assert "compare_digest" in ast.dump(func), f"{func.name} does not use compare_digest"


# -- Phase 4: enroller and identity-reader bearers (T055) --------------------------------


async def test_enroller_accepts_the_enroller_token_and_admin(monkeypatch) -> None:
    from app.api.deps import require_enroller
    from app.config import get_settings

    settings = get_settings()
    monkeypatch.setattr(settings, "enroll_token", "enroll-secret")
    await require_enroller(authorization="Bearer enroll-secret")
    await require_enroller(authorization=f"Bearer {settings.admin_token}")


async def test_enroller_refuses_wrong_missing_and_empty(monkeypatch) -> None:
    from app.api.deps import require_enroller
    from app.config import get_settings
    from app.errors import UnauthorizedError

    settings = get_settings()
    monkeypatch.setattr(settings, "enroll_token", "")
    with pytest.raises(UnauthorizedError):
        await require_enroller(authorization="Bearer ")  # empty setting never accepts empty
    with pytest.raises(UnauthorizedError):
        await require_enroller(authorization="Bearer nope")
    with pytest.raises(UnauthorizedError):
        await require_enroller(authorization=None)


async def test_identity_reader_accepts_audit_reader_and_admin(monkeypatch) -> None:
    from app.api.deps import require_identity_reader
    from app.config import get_settings
    from app.errors import UnauthorizedError

    settings = get_settings()
    monkeypatch.setattr(settings, "audit_read_token", "reader-secret")
    await require_identity_reader(authorization="Bearer reader-secret")
    await require_identity_reader(authorization=f"Bearer {settings.admin_token}")
    with pytest.raises(UnauthorizedError):
        await require_identity_reader(authorization="Bearer nope")
