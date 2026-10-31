"""Each extra installs what its surface needs and nothing heavier (FR-004, SC-003).

The table is data-model.md's "Extra" table. A row fails if the surface does not import in an
environment holding only that extra, or if importing it drags in a module the extra exists to
keep out — a client that pulls in FastAPI is the server stack with extra steps.
"""

from __future__ import annotations

import json

import pytest

pytestmark = pytest.mark.packaging

SERVER_ONLY = ("fastapi", "starlette", "sqlalchemy", "uvicorn", "asyncpg", "alembic", "redis")

BOUNDARIES = [
    pytest.param(None, ["agentic_auth.verify"], (*SERVER_ONLY, "httpx", "pydantic"), id="base"),
    pytest.param("client", ["agentic_auth.sdk"], SERVER_ONLY, id="client"),
    # drift builds on client: the CLI that runs the check also registers manifests over HTTP.
    pytest.param("drift", ["agentic_auth.sdk.drift", "agentic_auth.cli"], SERVER_ONLY, id="drift"),
    pytest.param(
        "embedded",
        ["agentic_auth.embedded", "agentic_auth.sdk"],
        # The redis *client* is in: fakeredis is built on it. The server-only pieces are not.
        ("uvicorn", "asyncpg", "alembic"),
        id="embedded",
    ),
    pytest.param(
        "server",
        ["agentic_auth.main", "agentic_auth.cli", "agentic_auth.embedded"],
        (),
        id="server",
    ),
]

PROBE = """
import importlib, json, sys
for name in {surface!r}:
    importlib.import_module(name)
print(json.dumps(sorted({{m.split('.')[0] for m in sys.modules}})))
"""


@pytest.mark.parametrize(("extra", "surface", "forbidden"), BOUNDARIES)
def test_extra_imports_its_surface_and_nothing_heavier(
    venv_factory, extra, surface, forbidden
) -> None:
    env = venv_factory(extra)
    result = env.run(PROBE.format(surface=surface))
    assert result.returncode == 0, result.stderr[-3000:]
    loaded = set(json.loads(result.stdout))
    leaked = sorted(loaded & set(forbidden))
    assert leaked == [], f"authzai[{extra or ''}] importing {surface} loaded {leaked}"


def test_base_install_is_at_most_five_third_party_packages(venv_factory) -> None:
    """SC-003. pyjwt, cryptography, cffi, pycparser today."""
    installed = set(venv_factory(None).installed()) - {"pip", "setuptools", "wheel", "authzai"}
    assert len(installed) <= 5, sorted(installed)
