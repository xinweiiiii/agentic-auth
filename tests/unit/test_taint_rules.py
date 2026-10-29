"""The pure taint rules."""

from __future__ import annotations

from app.schemas.authorize import Taint
from app.schemas.manifest import AgentManifest
from app.services.dag_compiler import DagCompiler
from app.services.policy_loader import build_index
from app.services.taint import (
    SENTINEL,
    Mark,
    Marked,
    ancestors_of,
    classify_source,
    effective_taint,
    is_protected,
)


def _policy():
    manifests = {
        "root": AgentManifest.model_validate(
            {
                "apiVersion": "agentic-auth/v1",
                "kind": "AgentManifest",
                "metadata": {"agent": "root"},
                "spec": {
                    "tools": [{"ref": "mcp://kb.internal/search", "data_classes": ["kb.read"]}],
                    "data_classes": {"reads": ["kb.read"], "writes": []},
                    "downstream_agents": [{"ref": "agent://worker", "max_hop_depth": 3}],
                    "hop_budget": 4,
                },
            }
        ),
        "worker": AgentManifest.model_validate(
            {
                "apiVersion": "agentic-auth/v1",
                "kind": "AgentManifest",
                "metadata": {"agent": "worker"},
                "spec": {
                    "tools": [
                        {"ref": "mcp://kb.internal/search", "data_classes": ["kb.read"]},
                        {
                            "ref": "mcp://accounts.internal/terminate",
                            "data_classes": ["account.write"],
                            "privileged": True,
                        },
                        {"ref": "mcp://ledger.internal/post", "data_classes": ["ledger.write"]},
                        {"ref": "mcp://ledger.internal/read", "data_classes": ["ledger.read"]},
                    ],
                    "data_classes": {
                        "reads": ["kb.read", "ledger.read"],
                        "writes": ["account.write", "ledger.write"],
                    },
                    "downstream_agents": [],
                    "hop_budget": 3,
                    "taint_policy": {
                        "trusted_sources": [
                            "mcp://accounts.internal/*",
                            "mcp://ledger.internal/read",
                        ],
                        "block_tainted_into": ["privileged", "*.write"],
                    },
                },
            }
        ),
    }
    return build_index(DagCompiler().compile(manifests)["root"].to_dag(), scope="root", version=1)


def test_classify_source_trusts_only_what_a_glob_names() -> None:
    p = _policy()
    assert (
        classify_source(p, "worker", "mcp://accounts.internal/read_balance")
        is Taint.TRUSTED_INTERNAL
    )
    assert classify_source(p, "worker", "mcp://ledger.internal/read") is Taint.TRUSTED_INTERNAL
    assert classify_source(p, "worker", "mcp://kb.internal/search") is Taint.UNTRUSTED_EXTERNAL
    assert classify_source(p, "worker", "mcp://ledger.internal/post") is Taint.UNTRUSTED_EXTERNAL


def test_default_trusted_sources_are_the_declared_downstream_agents() -> None:
    p = _policy()
    assert classify_source(p, "root", "agent://worker") is Taint.TRUSTED_INTERNAL
    assert classify_source(p, "root", "agent://stranger") is Taint.UNTRUSTED_EXTERNAL
    assert classify_source(p, "root", "mcp://kb.internal/search") is Taint.UNTRUSTED_EXTERNAL


def test_unknown_agent_trusts_nothing() -> None:
    assert classify_source(_policy(), "ghost", "agent://worker") is Taint.UNTRUSTED_EXTERNAL


def test_is_protected_covers_privileged_target_globs_and_data_class_globs() -> None:
    p = _policy()
    assert is_protected(p, "worker", "mcp://accounts.internal/terminate", "account.write")
    assert is_protected(p, "worker", "mcp://ledger.internal/post", "ledger.write")  # *.write
    assert not is_protected(p, "worker", "mcp://kb.internal/search", "kb.read")
    assert not is_protected(p, "worker", "mcp://ledger.internal/read", "ledger.read")
    # root has the default policy and no privileged tools: nothing is protected
    assert not is_protected(p, "root", "mcp://kb.internal/search", "kb.read")


def test_effective_taint_is_max_and_never_lowers() -> None:
    T, U = Taint.TRUSTED_INTERNAL, Taint.UNTRUSTED_EXTERNAL
    assert effective_taint(None, None, False) is T
    assert effective_taint(T, T, False) is T
    assert effective_taint(U, None, False) is U  # the token's floor
    assert effective_taint(None, U, False) is U  # agent-reported raises
    assert effective_taint(None, None, True) is U  # the store marks
    assert effective_taint(U, T, False) is U  # a lower report cannot lower the floor
    assert effective_taint(T, T, True) is U


def test_ancestors_of_collects_every_subject_jti_and_sentinels_the_unknown() -> None:
    chain = [
        {"hop": 1, "subject_jti": "j1"},
        {"hop": 2, "subject_jti": "j2"},
    ]
    assert ancestors_of(chain, "j3") == {"j1", "j2", "j3"}
    assert ancestors_of(None, "j1") == {"j1"}
    legacy = [{"hop": 1}, {"hop": 2, "subject_jti": None}, {"hop": 3, "subject_jti": "j3"}]
    assert ancestors_of(legacy, "j4") == {SENTINEL, "j3", "j4"}


def test_marked_prefers_the_exact_context_then_the_sentinel() -> None:
    marks = [
        Mark("j1", "mcp://kb.internal/search", "a1", 10.0),
        Mark(SENTINEL, "mcp://web/fetch", "a2", 5.0),
    ]
    assert Marked.of(marks, "j1") == Marked(True, "mcp://kb.internal/search")
    assert Marked.of(marks, "j9") == Marked(True, "mcp://web/fetch")
    assert Marked.of([Mark("j1", "x", None, 1.0)], "j9") == Marked(False, None)


def test_the_exchange_excludes_the_mark_its_own_decision_made_but_no_other() -> None:
    """A tool call's allow marks the context for the NEXT decision. Spending that allow
    must not see it; any other decision's mark, earlier or later, still counts."""
    own = [Mark("j1", "mcp://kb.internal/search", "a1", 1.0)]
    assert Marked.of(own, "j1", exclude_action_id="a1") == Marked(False, None)
    assert Marked.of(own, "j1", exclude_action_id="a2") == Marked(True, "mcp://kb.internal/search")
    assert Marked.of(own, "j1") == Marked(True, "mcp://kb.internal/search")
    both = [*own, Mark("j1", "mcp://web/fetch", "a2", 2.0)]
    assert Marked.of(both, "j1", exclude_action_id="a1") == Marked(True, "mcp://web/fetch")
    assert Marked.of(both, "j1") == Marked(True, "mcp://kb.internal/search")  # the earliest
    sentinel = [Mark(SENTINEL, "mcp://web/fetch", "a1", 1.0)]
    assert Marked.of(sentinel, "j1", exclude_action_id="a1") == Marked(False, None)


def test_mark_round_trips_and_tolerates_a_bare_source() -> None:
    m = Mark("j1", "mcp://kb.internal/search", "a1", 12.5)
    assert m.field == "j1|a1"
    assert Mark.decode(m.field, m.encode()) == m
    assert Mark.decode("j2|-", "mcp://legacy/source") == Mark(
        "j2", "mcp://legacy/source", None, 0.0
    )
