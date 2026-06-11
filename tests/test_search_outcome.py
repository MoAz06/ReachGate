"""BoundedBFS.search must report WHY each walk terminated — that distinction
(exhaustive vs bounds-limited) is what makes NOT_REACHABLE honest."""

from unittest.mock import MagicMock

from src.reachgate.path_strategy import BoundedBFS

ENTRY = {"id": "1", "path": "app.py"}
TARGETS = {"99"}


def _neighbors_graph(graph):
    def get_code_neighbors(entity, node_id):
        return graph.get(str(node_id), [])
    return get_code_neighbors


def _client(graph):
    client = MagicMock()
    client.get_code_neighbors.side_effect = _neighbors_graph(graph)
    return client


def test_search_path_found():
    client = _client({"1": [{"type": "Definition", "id": "99", "name": "f"}]})
    out = BoundedBFS(client).search(ENTRY, TARGETS, max_hops=5)
    assert out.found
    assert out.termination == "path_found"
    assert out.hops_used == 1


def test_search_frontier_exhausted():
    client = _client({"1": [{"type": "File", "id": "2", "path": "other.py"}]})
    out = BoundedBFS(client).search(ENTRY, TARGETS, max_hops=5)
    assert not out.found
    assert out.termination == "frontier_exhausted"
    assert not out.cap_hit


def test_search_max_hops_hit_when_frontier_remains():
    # Chain longer than max_hops: hop limit ends the walk, not the graph.
    client = _client({
        "1": [{"type": "File", "id": "2", "path": "a.py"}],
        "2": [{"type": "File", "id": "3", "path": "b.py"}],
        "3": [{"type": "Definition", "id": "99", "name": "f"}],
    })
    out = BoundedBFS(client).search(ENTRY, TARGETS, max_hops=2)
    assert not out.found
    assert out.termination == "max_hops_hit"
    assert out.cap_hit


def test_search_visited_cap_hit():
    fanout = [{"type": "File", "id": str(i), "path": f"f{i}.py"} for i in range(10, 30)]
    client = _client({"1": fanout})
    out = BoundedBFS(client, max_visited=5).search(ENTRY, TARGETS, max_hops=5)
    assert not out.found
    assert out.termination == "visited_cap_hit"
    assert out.cap_hit


def test_search_timeout_hit():
    client = _client({"1": [{"type": "File", "id": "2", "path": "a.py"}]})
    out = BoundedBFS(client, max_seconds=-1).search(ENTRY, TARGETS, max_hops=5)
    assert not out.found
    assert out.termination == "timeout_hit"
    assert out.cap_hit


def test_search_counts_api_errors(monkeypatch):
    monkeypatch.setattr("src.reachgate.path_strategy.time.sleep", lambda s: None)
    client = MagicMock()
    client.get_code_neighbors.side_effect = RuntimeError("API down")
    out = BoundedBFS(client).search(ENTRY, TARGETS, max_hops=5)
    assert not out.found
    assert out.api_errors == 1


def test_neighbors_retries_transient_failure(monkeypatch):
    # One flaky call followed by success: no api_error, path still found.
    monkeypatch.setattr("src.reachgate.path_strategy.time.sleep", lambda s: None)
    client = MagicMock()
    client.get_code_neighbors.side_effect = [
        RuntimeError("transient"),
        [{"type": "Definition", "id": "99", "name": "f"}],
    ]
    out = BoundedBFS(client).search(ENTRY, TARGETS, max_hops=5)
    assert out.found
    assert out.api_errors == 0


def test_neighbors_failures_are_not_cached(monkeypatch):
    # A failed lookup must not poison the cache as "no neighbors": that
    # would fake an exhaustive NOT_REACHABLE in later walks.
    monkeypatch.setattr("src.reachgate.path_strategy.time.sleep", lambda s: None)
    client = MagicMock()
    client.get_code_neighbors.side_effect = RuntimeError("API down")
    bfs = BoundedBFS(client)
    bfs.search(ENTRY, TARGETS, max_hops=2)
    calls_after_first = client.get_code_neighbors.call_count
    bfs.search(ENTRY, TARGETS, max_hops=2)
    # Second walk retried the API instead of trusting a cached failure.
    assert client.get_code_neighbors.call_count > calls_after_first


def test_search_counts_nodes_visited():
    client = _client({
        "1": [{"type": "File", "id": "2", "path": "a.py"},
              {"type": "File", "id": "3", "path": "b.py"}],
    })
    out = BoundedBFS(client).search(ENTRY, TARGETS, max_hops=5)
    assert out.nodes_visited == 3  # entry + 2 neighbors


def test_search_cache_hits_counted_across_walks():
    client = _client({"1": [{"type": "File", "id": "2", "path": "a.py"}]})
    bfs = BoundedBFS(client)
    bfs.search(ENTRY, TARGETS, max_hops=3)
    assert bfs.cache_hits == 0
    bfs.search(ENTRY, TARGETS, max_hops=3)
    assert bfs.cache_hits > 0


def test_find_path_wrapper_still_returns_path():
    client = _client({"1": [{"type": "Definition", "id": "99", "name": "f"}]})
    path = BoundedBFS(client).find_path(ENTRY, TARGETS, max_hops=5)
    assert path is not None
    assert path[-1].node_id == "99"
