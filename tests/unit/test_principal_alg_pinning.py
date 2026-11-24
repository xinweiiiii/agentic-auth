"""The human IdP's token no longer chooses its own algorithm (feature 011, research F4).

0.3.0 decoded with ``algorithms=[header["alg"]]``. This applies with every flag off, so it
is a listed exception in spec FR-019: enrollment binding and step-up accept only the
operator's list, default ``RS256, ES256, EdDSA``.
"""

from __future__ import annotations

import pytest

from agentic_auth.services.enrollment_rules import Bound, Unbindable
from agentic_auth.services.principal import PrincipalBinder
from tests.fixtures.idp.server import AUDIENCE, ISSUER

AGENT = "support-agent"


def _assertion(idp, *, alg: str = "EdDSA") -> str:
    return idp.mint_access_token(aud=AUDIENCE, alg=alg, extra={"agent": f"agent://{AGENT}"})


async def test_an_assertion_with_an_allowed_algorithm_binds(fake_idp) -> None:
    result = await PrincipalBinder().bind(_assertion(fake_idp), AGENT)
    assert result == Bound(f"{ISSUER}#alice")


@pytest.mark.parametrize("alg", ["none", "HS256"])
async def test_binding_refuses_an_algorithm_the_token_chose(fake_idp, alg) -> None:
    result = await PrincipalBinder().bind(_assertion(fake_idp, alg=alg), AGENT)
    assert isinstance(result, Unbindable)
    assert "algorithm" in result.detail


@pytest.mark.parametrize("alg", ["none", "HS256"])
async def test_step_up_refuses_an_algorithm_the_token_chose(fake_idp, alg) -> None:
    with pytest.raises(ValueError, match="algorithm"):
        await PrincipalBinder().verify_human(_assertion(fake_idp, alg=alg))


async def test_an_operator_list_without_eddsa_refuses_an_eddsa_idp(fake_idp, flags) -> None:
    flags(principal_idp_algorithms="RS256,ES256")
    result = await PrincipalBinder().bind(_assertion(fake_idp), AGENT)
    assert isinstance(result, Unbindable)
    with pytest.raises(ValueError, match="algorithm"):
        await PrincipalBinder().verify_human(_assertion(fake_idp))


async def test_the_idp_being_down_is_still_unreachable_not_unbindable(fake_idp) -> None:
    from agentic_auth.services.enrollment_rules import Unreachable

    fake_idp.down = True
    result = await PrincipalBinder().bind(_assertion(fake_idp), AGENT)
    assert isinstance(result, Unreachable)
