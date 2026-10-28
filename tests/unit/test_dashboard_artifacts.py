"""The shipped dashboards and alerts still resolve (spec 007 FR-027a, SC-013).

Phases 3 and 4 shipped dashboard *guidance* as prose tables. Prose cannot fail a build, so a
renamed metric left the guidance quietly wrong. These artifacts are checked instead.

The label-value check (`test_every_label_matcher_uses_a_declared_value`) is the one that earns
its keep. A typo'd value — `cause="pdp_unavailable"` against the real `pdp_unreachable` —
produces a panel that is *empty* rather than broken, and an alert that silently never fires.
That is strictly worse than a missing dashboard, and it is exactly what prose could never catch.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest
from prometheus_client import CollectorRegistry

from app.observability import surface
from app.services.metrics import (
    build_control_plane_metrics,
    build_pep_metrics,
    build_verifier_metrics,
)

REPO = Path(__file__).resolve().parents[2]
OBSERVABILITY = REPO / "observability"
DASHBOARDS = sorted((OBSERVABILITY / "dashboards").glob("*.json"))
RULES = sorted((OBSERVABILITY / "alerts").glob("*.rules.yml"))

# Suffixes prometheus_client appends; a query names the series, the registry names the family.
_SUFFIXES = ("_total", "_bucket", "_sum", "_count", "_created")

# PromQL functions and keywords that look like identifiers but are not metric names.
_NOT_METRICS = frozenset(
    {
        "sum",
        "rate",
        "increase",
        "count",
        "max",
        "min",
        "avg",
        "by",
        "without",
        "le",
        "histogram_quantile",
        "absent",
        "absent_over_time",
        "irate",
        "delta",
        "topk",
        "bottomk",
        "group",
        "stddev",
        "quantile",
        "clamp_max",
        "clamp_min",
        "on",
        "ignoring",
        "and",
        "or",
        "unless",
        "offset",
        "bool",
        "vector",
        "scalar",
        "time",
        "changes",
    }
)


def _live_families() -> dict[str, frozenset[str]]:
    """Family name -> declared label names, from the registries the code actually builds."""
    out: dict[str, frozenset[str]] = {}
    for build in (build_control_plane_metrics, build_pep_metrics, build_verifier_metrics):
        registry: CollectorRegistry = build().registry
        for collector in list(registry._collector_to_names):  # noqa: SLF001
            name = getattr(collector, "_name", None)
            if name:
                out[name] = frozenset(getattr(collector, "_labelnames", ()) or ())
    # The drift metrics live in their own per-run registry.
    from app.services.metrics import build_drift_metrics

    for collector in list(build_drift_metrics().registry._collector_to_names):  # noqa: SLF001
        name = getattr(collector, "_name", None)
        if name:
            out[name] = frozenset(getattr(collector, "_labelnames", ()) or ())
    return out


LIVE = _live_families()


def _strip_suffix(name: str) -> str:
    for suffix in _SUFFIXES:
        if name.endswith(suffix):
            return name[: -len(suffix)]
    return name


def _queries() -> list[tuple[str, str]]:
    """(source, promql) for every expression in every shipped artifact."""
    import yaml

    found: list[tuple[str, str]] = []
    for path in DASHBOARDS:
        doc = json.loads(path.read_text())
        for p in doc.get("panels", []):
            for target in p.get("targets", []):
                if target.get("expr"):
                    found.append((f"{path.name}:{p['title']}", target["expr"]))
    for path in RULES:
        doc = yaml.safe_load(path.read_text())
        for group in doc.get("groups", []):
            for rule in group.get("rules", []):
                found.append((f"{path.name}:{rule['alert']}", rule["expr"]))
    return found


QUERIES = _queries()


def _metric_names(expr: str) -> set[str]:
    """Identifiers in metric position: an `agentic_auth_*` name, stripped of its suffix."""
    raw = set(re.findall(r"\b([a-zA-Z_][a-zA-Z0-9_]*)\b(?=\s*[{\[\(]|\s|$)", expr))
    return {
        _strip_suffix(n) for n in raw if n.startswith("agentic_auth_") and n not in _NOT_METRICS
    }


def _label_matchers(expr: str) -> list[tuple[str, str, str]]:
    """(metric, label, value) for every equality matcher, including inside a regex alternation."""
    out: list[tuple[str, str, str]] = []
    for metric, selector in re.findall(r"\b(agentic_auth_[a-zA-Z0-9_]*)\{([^}]*)\}", expr):
        family = _strip_suffix(metric)
        for label, op, value in re.findall(r'(\w+)\s*(=~|!~|!=|=)\s*"([^"]*)"', selector):
            if op in ("!=", "!~"):
                continue  # an exclusion need not name an existing value
            for part in value.split("|") if op == "=~" else [value]:
                part = part.strip()
                if part and not re.search(r"[.*+?\[\]()]", part):
                    out.append((f"{family}:{label}", label, part))
    return out


# -- sanity: the artifacts exist and parse --------------------------------------------------


def test_the_artifacts_exist() -> None:
    assert DASHBOARDS, "no dashboards shipped under observability/dashboards/"
    assert RULES, "no alert rules shipped under observability/alerts/"
    assert QUERIES, "no queries extracted — the parser is broken, not the artifacts"


@pytest.mark.parametrize("path", DASHBOARDS, ids=lambda p: p.name)
def test_each_dashboard_is_valid_json_with_the_expected_shape(path: Path) -> None:
    doc = json.loads(path.read_text())
    assert doc["uid"] and doc["title"] and doc["description"]
    assert doc["panels"], "a dashboard with no panels"
    for p in doc["panels"]:
        assert p["title"], f"untitled panel in {path.name}"
        assert p["targets"], f"panel {p['title']!r} has no query"


# -- the resolver: every referenced metric exists --------------------------------------------


@pytest.mark.parametrize(("source", "expr"), QUERIES, ids=[q[0] for q in QUERIES])
def test_every_referenced_metric_is_in_the_contract(source: str, expr: str) -> None:
    documented = surface.NEW_METRIC_NAMES | set(LIVE)
    for name in _metric_names(expr):
        assert name in documented, f"{source} references undocumented metric {name!r}"


@pytest.mark.parametrize(("source", "expr"), QUERIES, ids=[q[0] for q in QUERIES])
def test_every_referenced_metric_exists_in_a_live_registry(source: str, expr: str) -> None:
    """Checked against the registries the code actually builds, not only against the contract
    document — so the contract and the code must *both* agree."""
    for name in _metric_names(expr):
        assert name in LIVE, f"{source} references {name!r}, which no registry defines"


@pytest.mark.parametrize(("source", "expr"), QUERIES, ids=[q[0] for q in QUERIES])
def test_every_label_matcher_names_a_real_label(source: str, expr: str) -> None:
    for metric, selector in re.findall(r"\b(agentic_auth_[a-zA-Z0-9_]*)\{([^}]*)\}", expr):
        family = _strip_suffix(metric)
        if family not in LIVE:
            continue
        for label, _op in re.findall(r'(\w+)\s*(=~|!~|!=|=)\s*"[^"]*"', selector):
            assert label in LIVE[family], (
                f"{source} filters {family} on {label!r}, which is not one of its labels "
                f"{sorted(LIVE[family])}"
            )


@pytest.mark.parametrize(("source", "expr"), QUERIES, ids=[q[0] for q in QUERIES])
def test_every_label_matcher_uses_a_declared_value(source: str, expr: str) -> None:
    """The test that earns its keep: a typo'd value gives an empty panel and an alert that
    never fires, which is worse than a broken one because nobody notices."""
    for key, _label, value in _label_matchers(expr):
        declared = surface.LABEL_VALUES.get(key)
        if declared is None:
            continue  # a Phase 3/4 family whose values this phase does not own
        assert value in declared, (
            f"{source} matches {key}={value!r}, which is not a declared value: {sorted(declared)}"
        )


# -- the negative case: prove the resolver bites --------------------------------------------


def test_a_typod_label_value_is_caught(tmp_path: Path) -> None:
    """T042. Without this, the resolver could be silently vacuous — a parser that extracts
    nothing passes every assertion above."""
    bad = 'increase(agentic_auth_pep_blocks_total{cause="pdp_unavailable"}[5m]) > 0'
    matchers = _label_matchers(bad)
    assert matchers, "the matcher parser extracted nothing, so the real test is vacuous"
    key, _label, value = matchers[0]
    assert key == "agentic_auth_pep_blocks:cause"
    assert value == "pdp_unavailable"
    assert value not in surface.LABEL_VALUES[key], (
        "the real value is 'pdp_unreachable'; this must not be accepted"
    )


def test_a_renamed_metric_is_caught() -> None:
    bad = "sum(rate(agentic_auth_pep_calls_total_renamed[5m]))"
    names = _metric_names(bad)
    assert names, "the metric-name parser extracted nothing"
    assert not names <= set(LIVE), "a renamed metric must not resolve"


def test_the_parser_finds_the_metrics_in_a_real_query() -> None:
    expr = (
        "histogram_quantile(0.95, sum by (le, stage) "
        "(rate(agentic_auth_pep_stage_duration_seconds_bucket[5m])))"
    )
    assert _metric_names(expr) == {"agentic_auth_pep_stage_duration_seconds"}


# -- promtool, when available ---------------------------------------------------------------


@pytest.mark.parametrize("path", RULES, ids=lambda p: p.name)
def test_promtool_accepts_the_rules(path: Path) -> None:
    promtool = shutil.which("promtool")
    if promtool is None:
        pytest.skip("promtool is not installed")
    result = subprocess.run(
        [promtool, "check", "rules", str(path)], capture_output=True, text=True, timeout=60
    )
    assert result.returncode == 0, result.stdout + result.stderr


# -- the alerts that must exist -------------------------------------------------------------


def test_the_four_must_page_alerts_are_present() -> None:
    """FR-026. These ship armed rather than left for an integrator to discover."""
    import yaml

    names = {
        rule["alert"]
        for path in RULES
        for group in yaml.safe_load(path.read_text())["groups"]
        for rule in group["rules"]
    }
    for required in (
        "AgenticAuthAuditWriteFailing",
        "AgenticAuthPepCannotReachPolicy",
        "AgenticAuthPepSilent",
        "AgenticAuthChainIncomplete",
    ):
        assert required in names, f"{required} is not shipped"


def test_every_alert_explains_what_to_do() -> None:
    """An alert whose description is a restatement of its expression wakes someone up with no
    idea what to do."""
    import yaml

    for path in RULES:
        for group in yaml.safe_load(path.read_text())["groups"]:
            for rule in group["rules"]:
                annotations = rule.get("annotations", {})
                assert annotations.get("summary"), f"{rule['alert']} has no summary"
                assert len(annotations.get("description", "")) > 80, (
                    f"{rule['alert']} needs a description that says what to do"
                )
                assert rule["labels"]["severity"] in {"critical", "warning", "info"}


def test_only_guardrail_failures_are_critical() -> None:
    """A critical that fires for the caller's mistakes teaches people to ignore criticals. The
    caller-error causes must not appear in any critical alert."""
    import yaml

    caller_errors = surface.PEP_BLOCK_CAUSES - surface.PEP_INFRA_BLOCK_CAUSES - {"policy"}
    for path in RULES:
        for group in yaml.safe_load(path.read_text())["groups"]:
            for rule in group["rules"]:
                if rule["labels"]["severity"] != "critical":
                    continue
                for cause in caller_errors:
                    assert cause not in rule["expr"], (
                        f"{rule['alert']} would page on {cause!r}, which is the caller's "
                        "mistake, not a guardrail failure"
                    )
