"""``require_extra`` names the install option, in the format contracts/packaging.md fixes."""

from __future__ import annotations

import pytest

from agentic_auth._extras import require_extra


def test_present_dependencies_pass() -> None:
    require_extra("agentic_auth.sdk", "client", "json", "pytest")


def test_missing_dependency_names_the_extra() -> None:
    with pytest.raises(ImportError) as err:
        require_extra("agentic_auth.embedded", "embedded", "json", "no_such_module_anywhere")
    assert str(err.value) == (
        "agentic_auth.embedded needs the 'embedded' extra: pip install 'authzai[embedded]'"
    )
    assert err.value.name == "no_such_module_anywhere"


def test_first_missing_dependency_is_the_one_reported() -> None:
    with pytest.raises(ImportError) as err:
        require_extra("m", "server", "missing_one_xyz", "missing_two_xyz")
    assert err.value.name == "missing_one_xyz"
