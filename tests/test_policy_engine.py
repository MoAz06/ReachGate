import pytest
from src.reachgate.graph_walker import ReachabilityResult
from src.reachgate.policy_engine import evaluate, Verdict, REACHABLE_THRESHOLD


def _occurrence(severity="high", name="SQL Injection"):
    return {"uuid": "test-uuid", "name": name, "severity": severity}


def _reachable(hops=2, path=None):
    return ReachabilityResult(
        reachable=True,
        path=path or ["File:app.py", "Definition:handle_request", "Definition:vulnerable_fn"],
        hops=hops,
        entry_point="app.py",
        vulnerable_file="src/db/query_builder.py",
        vulnerable_definition="query_builder.build",
    )


def _not_reachable():
    return ReachabilityResult(
        reachable=False,
        vulnerable_file="scripts/legacy/import_tool.py",
    )


def test_reachable_verdict_when_path_exists():
    receipt = evaluate(_reachable(), _occurrence())
    assert receipt.verdict == Verdict.REACHABLE


def test_not_reachable_verdict_when_no_path():
    receipt = evaluate(_not_reachable(), _occurrence())
    assert receipt.verdict == Verdict.NOT_REACHABLE


def test_risk_score_at_least_threshold_for_reachable():
    receipt = evaluate(_reachable(), _occurrence())
    assert receipt.risk_score >= REACHABLE_THRESHOLD


def test_risk_score_below_threshold_for_not_reachable():
    receipt = evaluate(_not_reachable(), _occurrence())
    assert receipt.risk_score < REACHABLE_THRESHOLD


def test_path_exists_rule_triggers_for_reachable():
    receipt = evaluate(_reachable(), _occurrence())
    rule_names = [r.name for r in receipt.triggered_rules]
    assert "path_exists" in rule_names


def test_path_exists_rule_does_not_trigger_for_not_reachable():
    receipt = evaluate(_not_reachable(), _occurrence())
    rule_names = [r.name for r in receipt.triggered_rules]
    assert "path_exists" not in rule_names


def test_direct_import_rule_triggers_for_low_hop_count():
    receipt = evaluate(_reachable(hops=1), _occurrence())
    rule_names = [r.name for r in receipt.triggered_rules]
    assert "direct_import" in rule_names


def test_direct_import_rule_does_not_trigger_for_high_hop_count():
    receipt = evaluate(_reachable(hops=8), _occurrence())
    rule_names = [r.name for r in receipt.triggered_rules]
    assert "direct_import" not in rule_names


def test_high_severity_rule_triggers():
    receipt = evaluate(_reachable(), _occurrence(severity="critical"))
    rule_names = [r.name for r in receipt.triggered_rules]
    assert "high_severity" in rule_names


def test_medium_severity_rule_triggers():
    receipt = evaluate(_reachable(), _occurrence(severity="medium"))
    rule_names = [r.name for r in receipt.triggered_rules]
    assert "medium_severity" in rule_names


def test_receipt_contains_path():
    result = _reachable()
    receipt = evaluate(result, _occurrence())
    assert receipt.path == result.path


def test_receipt_as_dict_has_required_keys():
    receipt = evaluate(_reachable(), _occurrence())
    d = receipt.as_dict()
    for key in ("verdict", "risk_score", "risk_breakdown", "path", "hops"):
        assert key in d


def test_same_finding_different_reachability_different_verdict():
    occ = _occurrence()
    reachable_receipt = evaluate(_reachable(), occ)
    not_reachable_receipt = evaluate(_not_reachable(), occ)
    assert reachable_receipt.verdict != not_reachable_receipt.verdict
