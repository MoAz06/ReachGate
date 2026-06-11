"""UNKNOWN verdict: insufficient evidence must never become NOT_REACHABLE."""

import json
from unittest.mock import MagicMock

from src.reachgate.config import PolicyConfig, ReachGateConfig
from src.reachgate.graph_walker import GraphWalker
from src.reachgate.path_strategy import PathNode, SearchOutcome
from src.reachgate.policy_engine import POLICY_VERSION, Verdict, evaluate


def _config():
    return ReachGateConfig(
        version="1",
        entrypoint_patterns=["src/routes/**/*"],
        policy=PolicyConfig(min_hops=1, max_hops=4),
    )


class _OutcomeStrategy:
    """Strategy fake that returns a fixed SearchOutcome."""
    max_visited = 40
    max_seconds = 60
    cache_hits = 0

    def __init__(self, outcome):
        self._outcome = outcome

    def search(self, entry_file, target_ids, max_hops):
        return self._outcome


def _occ(file="src/db/query.py", severity="high"):
    return {
        "uuid": "occ-1",
        "name": "Test finding",
        "severity": severity,
        "location": json.dumps({"file": file}),
    }


def _client(definitions=None, entry_files=None):
    client = MagicMock()
    client.api_calls = 7
    client.get_definitions_for_file.return_value = definitions if definitions is not None else [
        {"id": "99", "name": "query", "file_path": "src/db/query.py"}
    ]
    client.get_files_matching.return_value = entry_files if entry_files is not None else [
        {"id": "1", "path": "src/routes/users.py"}
    ]
    client.get_imported_symbols.return_value = []
    return client


def _walk(strategy_outcome, **client_kwargs):
    client = _client(**client_kwargs)
    strategy = _OutcomeStrategy(strategy_outcome)
    walker = GraphWalker(client, _config(), strategy=strategy)
    return walker.check_reachability(_occ())


def test_no_location_is_unknown():
    client = _client()
    walker = GraphWalker(client, _config())
    result = walker.check_reachability({"location": ""})
    receipt = evaluate(result, {"severity": "high"})
    assert receipt.verdict == Verdict.UNKNOWN
    assert receipt.verdict_basis == "insufficient_evidence:no_location"


def test_no_definitions_is_unknown():
    result = _walk(None, definitions=[])
    receipt = evaluate(result, _occ())
    assert receipt.verdict == Verdict.UNKNOWN
    assert "no_definitions_indexed" in receipt.verdict_basis


def test_no_entrypoints_is_unknown():
    result = _walk(None, entry_files=[])
    receipt = evaluate(result, _occ())
    assert receipt.verdict == Verdict.UNKNOWN
    assert "no_entrypoints" in receipt.verdict_basis


def test_bounds_hit_is_unknown_not_not_reachable():
    out = SearchOutcome(path=None, termination="max_hops_hit",
                        nodes_visited=15, hops_used=4)
    receipt = evaluate(_walk(out), _occ())
    assert receipt.verdict == Verdict.UNKNOWN
    assert "bounds_hit" in receipt.verdict_basis


def test_visited_cap_is_unknown():
    out = SearchOutcome(path=None, termination="visited_cap_hit",
                        nodes_visited=40, hops_used=2)
    receipt = evaluate(_walk(out), _occ())
    assert receipt.verdict == Verdict.UNKNOWN


def test_api_error_is_unknown():
    out = SearchOutcome(path=None, termination="frontier_exhausted",
                        nodes_visited=3, hops_used=2, api_errors=1)
    receipt = evaluate(_walk(out), _occ())
    assert receipt.verdict == Verdict.UNKNOWN
    assert "api_error" in receipt.verdict_basis


def test_frontier_exhausted_is_honest_not_reachable():
    out = SearchOutcome(path=None, termination="frontier_exhausted",
                        nodes_visited=8, hops_used=2)
    result = _walk(out)
    receipt = evaluate(result, _occ())
    assert receipt.verdict == Verdict.NOT_REACHABLE
    assert receipt.verdict_basis == "no_path_search_exhaustive"
    assert result.certificate.frontier_exhausted


def test_path_found_is_reachable_with_basis():
    path = [
        PathNode(entity="File", node_id="1", label="src/routes/users.py"),
        PathNode(entity="Definition", node_id="99", label="query"),
    ]
    out = SearchOutcome(path=path, termination="path_found",
                        nodes_visited=2, hops_used=1)
    receipt = evaluate(_walk(out), _occ())
    assert receipt.verdict == Verdict.REACHABLE
    assert receipt.verdict_basis == "path_found"


def test_certificate_is_attached_and_versioned():
    out = SearchOutcome(path=None, termination="frontier_exhausted",
                        nodes_visited=8, hops_used=2)
    result = _walk(out)
    receipt = evaluate(result, _occ())
    cert = receipt.certificate
    assert cert is not None
    assert cert.policy_version == POLICY_VERSION
    assert cert.entrypoints_checked == 1
    assert cert.target_definitions_found == 1
    # Static counter on the fake client -> per-finding delta is zero.
    assert cert.orbit_api_calls == 0
    assert "graph_edges" in cert.strategies_attempted
    # No path found -> nothing contributed evidence.
    assert cert.evidence_modes == []


def test_definitions_api_failure_is_unknown_not_crash():
    client = _client()
    client.get_definitions_for_file.side_effect = RuntimeError("API down")
    walker = GraphWalker(client, _config(), strategy=_OutcomeStrategy(None))
    receipt = evaluate(walker.check_reachability(_occ()), _occ())
    assert receipt.verdict == Verdict.UNKNOWN
    assert "api_error" in receipt.verdict_basis


def test_files_api_failure_is_unknown_not_crash():
    client = _client()
    client.get_files_matching.side_effect = RuntimeError("API down")
    walker = GraphWalker(client, _config(), strategy=_OutcomeStrategy(None))
    receipt = evaluate(walker.check_reachability(_occ()), _occ())
    assert receipt.verdict == Verdict.UNKNOWN
    assert "api_error" in receipt.verdict_basis


def test_imported_symbols_failure_is_unknown_not_silent_no_path():
    # Edge walk exhausts cleanly, but the fallback query fails: the search
    # is incomplete, so NOT_REACHABLE would be dishonest.
    client = _client()
    client.get_imported_symbols.side_effect = RuntimeError("API down")
    out = SearchOutcome(path=None, termination="frontier_exhausted",
                        nodes_visited=8, hops_used=2)
    walker = GraphWalker(client, _config(), strategy=_OutcomeStrategy(out))
    receipt = evaluate(walker.check_reachability(_occ()), _occ())
    assert receipt.verdict == Verdict.UNKNOWN
    assert "api_error" in receipt.verdict_basis


def test_certificate_counts_are_per_finding_not_cumulative():
    class _CountingClient:
        """api_calls grows across findings; certificate must report deltas."""
        def __init__(self):
            self.api_calls = 10  # pretend earlier findings already cost 10

        def get_definitions_for_file(self, f):
            self.api_calls += 1
            return [{"id": "99", "name": "query", "file_path": f}]

        def get_files_matching(self, patterns):
            self.api_calls += 1
            return [{"id": "1", "path": "src/routes/users.py"}]

        def get_imported_symbols(self, path):
            self.api_calls += 1
            return []

    out = SearchOutcome(path=None, termination="frontier_exhausted",
                        nodes_visited=8, hops_used=2)
    walker = GraphWalker(_CountingClient(), _config(),
                         strategy=_OutcomeStrategy(out))
    result = walker.check_reachability(_occ())
    assert result.certificate.orbit_api_calls == 3  # not 13


def test_evidence_modes_only_set_when_path_found():
    path = [
        PathNode(entity="File", node_id="1", label="src/routes/users.py"),
        PathNode(entity="Definition", node_id="99", label="query"),
    ]
    out = SearchOutcome(path=path, termination="path_found",
                        nodes_visited=2, hops_used=1)
    result = _walk(out)
    assert result.certificate.evidence_modes == ["graph_edges"]
    assert result.certificate.strategies_attempted == ["graph_edges"]


def test_fingerprint_present_and_stable_across_runs():
    out = SearchOutcome(path=None, termination="frontier_exhausted",
                        nodes_visited=8, hops_used=2)
    r1 = evaluate(_walk(out), _occ())
    # Second run with different dynamic metrics must produce same fingerprint.
    out2 = SearchOutcome(path=None, termination="frontier_exhausted",
                         nodes_visited=31, hops_used=3)
    r2 = evaluate(_walk(out2), _occ())
    assert r1.fingerprint == r2.fingerprint
    assert len(r1.fingerprint) == 16
