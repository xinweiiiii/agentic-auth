"""TAINTED_INTO_PRIVILEGED in the pure decision."""

from __future__ import annotations

import pytest

from agentic_auth.boundary.guarantee import Guarantee
from agentic_auth.schemas.authorize import AuthorizeRequest, DenyReason, Taint
from agentic_auth.schemas.manifest import AgentManifest
from agentic_auth.services.dag_compiler import DagCompiler
from agentic_auth.services.pdp import decide
from agentic_auth.services.policy_loader import build_index
from agentic_auth.services.tokens.act_chain import nest
from agentic_auth.services.tokens.profile import VerifiedToken

SESSION = "s1"
USER = "user:alice"
ROOT = "root"
WORKER = "worker"
TERMINATE = "mcp://accounts.internal/terminate"
POST = "mcp://ledger.internal/post"
SEARCH = "mcp://kb.internal/search"


def _index():
    manifests = {
        ROOT: AgentManifest.model_validate(
            {
                "apiVersion": "agentic-auth/v1",
                "kind": "AgentManifest",
                "metadata": {"agent": ROOT},
                "spec": {
                    "tools": [{"ref": SEARCH, "data_classes": ["kb.read"]}],
                    "data_classes": {"reads": ["kb.read"], "writes": []},
                    "downstream_agents": [{"ref": f"agent://{WORKER}", "max_hop_depth": 3}],
                    "hop_budget": 4,
                },
            }
        ),
        WORKER: AgentManifest.model_validate(
            {
                "apiVersion": "agentic-auth/v1",
                "kind": "AgentManifest",
                "metadata": {"agent": WORKER},
                "spec": {
                    "tools": [
                        {"ref": SEARCH, "data_classes": ["kb.read"]},
                        {"ref": TERMINATE, "data_classes": ["account.write"], "privileged": True},
                        {"ref": POST, "data_classes": ["ledger.write"]},
                    ],
                    "data_classes": {
                        "reads": ["kb.read"],
                        "writes": ["account.write", "ledger.write"],
                    },
                    "downstream_agents": [],
                    "hop_budget": 3,
                    "taint_policy": {
                        "trusted_sources": [],
                        "block_tainted_into": ["privileged", "*.write"],
                    },
                },
            }
        ),
    }
    return build_index(DagCompiler().compile(manifests)[ROOT].to_dag(), scope=ROOT, version=1)


def _worker_token() -> VerifiedToken:
    return VerifiedToken(
        raw="<verified>",
        sub=USER,
        aud=f"agent://{WORKER}",
        scope="kb.read",
        session_id=SESSION,
        policy_version=1,
        hop=2,
        jti="j-worker",
        expires_at=__import__("datetime").datetime.max.replace(tzinfo=__import__("datetime").UTC),
        act=nest(None, f"agent://{ROOT}"),
    )


def _request(target: str, data_class: str) -> AuthorizeRequest:
    return AuthorizeRequest(
        session_id=SESSION,
        caller=f"agent://{WORKER}",
        target=target,
        data_class=data_class,
        guarantee=Guarantee.FULL,
    )


CASES = [
    # (taint, target, data_class, enforced) -> expected outcome / reason
    (Taint.UNTRUSTED_EXTERNAL, TERMINATE, "account.write", True, "deny"),
    (Taint.UNTRUSTED_EXTERNAL, POST, "ledger.write", True, "deny"),  # *.write glob
    (Taint.UNTRUSTED_EXTERNAL, SEARCH, "kb.read", True, "allow"),  # unprotected
    (Taint.TRUSTED_INTERNAL, TERMINATE, "account.write", True, "allow"),
    (Taint.TRUSTED_INTERNAL, POST, "ledger.write", True, "allow"),
    (None, TERMINATE, "account.write", True, "allow"),  # unknown reads as trusted
    (Taint.UNTRUSTED_EXTERNAL, TERMINATE, "account.write", False, "allow"),  # flag off
    (Taint.UNTRUSTED_EXTERNAL, POST, "ledger.write", False, "allow"),
]


@pytest.mark.parametrize("taint,target,data_class,enforced,expected", CASES)
def test_the_taint_matrix(taint, target, data_class, enforced, expected) -> None:
    d = decide(
        _index(),
        _request(target, data_class),
        _worker_token(),
        consented_scope=ROOT,
        taint=taint,
        taint_enforced=enforced,
    )
    assert d.outcome == expected, d
    if expected == "deny":
        assert d.reason is DenyReason.TAINTED_INTO_PRIVILEGED
        assert d.recoverable is False
    # the effective taint travels on the decision either way
    assert d.taint is taint


def test_the_taint_deny_follows_every_phase_2_check() -> None:
    """An undeclared edge is still EDGE_NOT_IN_DAG / OUT_OF_SCOPE when tainted: taint is the
    last question, not the first, so a refusal names the structural problem."""
    d = decide(
        _index(),
        _request("mcp://nowhere.internal/x", "kb.read"),
        _worker_token(),
        consented_scope=ROOT,
        taint=Taint.UNTRUSTED_EXTERNAL,
    )
    assert d.outcome == "deny" and d.reason is DenyReason.OUT_OF_SCOPE


def test_privileged_is_reported_on_the_taint_deny() -> None:
    d = decide(
        _index(),
        _request(TERMINATE, "account.write"),
        _worker_token(),
        consented_scope=ROOT,
        taint=Taint.UNTRUSTED_EXTERNAL,
    )
    assert d.privileged is True and d.reason is DenyReason.TAINTED_INTO_PRIVILEGED


def test_decide_never_mutates_or_raises_on_taint() -> None:
    for taint in (None, Taint.TRUSTED_INTERNAL, Taint.UNTRUSTED_EXTERNAL):
        decide(
            _index(),
            _request(SEARCH, "kb.read"),
            _worker_token(),
            consented_scope=ROOT,
            taint=taint,
        )


def test_a_taint_refusal_reports_its_hop_and_the_taint() -> None:
    d = decide(
        _index(),
        _request(TERMINATE, "account.write"),
        _worker_token(),
        consented_scope=ROOT,
        taint=Taint.UNTRUSTED_EXTERNAL,
    )
    assert d.reason is DenyReason.TAINTED_INTO_PRIVILEGED
    assert d.hop == 2 and d.taint is Taint.UNTRUSTED_EXTERNAL and d.privileged is True


def test_other_denies_are_not_flagged_privileged() -> None:
    d = decide(
        _index(),
        _request("mcp://nowhere.internal/x", "kb.read"),
        _worker_token(),
        consented_scope=ROOT,
        taint=Taint.UNTRUSTED_EXTERNAL,
    )
    assert d.outcome == "deny" and d.privileged is False and d.transaction_required is False
