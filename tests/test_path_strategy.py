from unittest.mock import MagicMock

from src.reachgate.path_strategy import BoundedBFS, PathNode, _to_path_node

ENTRY = {"id": "1", "path": "app.py"}
TARGETS = {"99"}


# --- _to_path_node ---

def test_to_path_node_reads_type_field():
    node = _to_path_node({"type": "Definition", "id": "99", "name": "load_config"})
    assert node == PathNode(entity="Definition", node_id="99", label="load_config")


def test_to_path_node_falls_back_to_path_label():
    node = _to_path_node({"type": "File", "id": "1", "path": "app.py"})
    assert node.label == "app.py"


# --- BoundedBFS ---

def _neighbors_graph(graph):
    """Build a get_code_neighbors mock from {node_id: [neighbor dicts]}."""
    def get_code_neighbors(entity, node_id):
        return graph.get(str(node_id), [])
    return get_code_neighbors


def test_bfs_finds_direct_neighbor():
    client = MagicMock()
    client.get_code_neighbors.side_effect = _neighbors_graph({
        "1": [{"type": "Definition", "id": "99", "name": "load_config"}],
    })
    path = BoundedBFS(client).find_path(ENTRY, TARGETS, max_hops=5)
    assert path is not None
    assert len(path) == 2
    assert path[-1].node_id == "99"


def test_bfs_finds_multi_hop_path():
    client = MagicMock()
    client.get_code_neighbors.side_effect = _neighbors_graph({
        "1": [{"type": "File", "id": "2", "path": "routes/orders.py"}],
        "2": [{"type": "File", "id": "3", "path": "services/parser.py"}],
        "3": [{"type": "Definition", "id": "99", "name": "load_config"}],
    })
    path = BoundedBFS(client).find_path(ENTRY, TARGETS, max_hops=5)
    assert path is not None
    assert len(path) == 4
    assert [n.label for n in path] == [
        "app.py", "routes/orders.py", "services/parser.py", "load_config",
    ]


def test_bfs_finds_any_of_multiple_targets():
    client = MagicMock()
    client.get_code_neighbors.side_effect = _neighbors_graph({
        "1": [{"type": "Definition", "id": "77", "name": "other"}],
    })
    path = BoundedBFS(client).find_path(ENTRY, {"77", "99"}, max_hops=5)
    assert path is not None
    assert path[-1].node_id == "77"


def test_bfs_respects_max_hops():
    client = MagicMock()
    client.get_code_neighbors.side_effect = _neighbors_graph({
        "1": [{"type": "File", "id": "2", "path": "a.py"}],
        "2": [{"type": "File", "id": "3", "path": "b.py"}],
        "3": [{"type": "Definition", "id": "99", "name": "load_config"}],
    })
    assert BoundedBFS(client).find_path(ENTRY, TARGETS, max_hops=2) is None


def test_bfs_returns_none_when_no_path():
    client = MagicMock()
    client.get_code_neighbors.side_effect = _neighbors_graph({
        "1": [{"type": "File", "id": "2", "path": "other.py"}],
    })
    assert BoundedBFS(client).find_path(ENTRY, TARGETS, max_hops=5) is None


def test_bfs_handles_cycles():
    client = MagicMock()
    client.get_code_neighbors.side_effect = _neighbors_graph({
        "1": [{"type": "File", "id": "2", "path": "a.py"}],
        "2": [{"type": "File", "id": "1", "path": "app.py"}],  # cycle back
    })
    assert BoundedBFS(client).find_path(ENTRY, TARGETS, max_hops=10) is None


def test_bfs_survives_neighbor_query_errors():
    client = MagicMock()
    client.get_code_neighbors.side_effect = RuntimeError("API down")
    assert BoundedBFS(client).find_path(ENTRY, TARGETS, max_hops=5) is None


def test_bfs_caches_neighbor_lookups():
    client = MagicMock()
    client.get_code_neighbors.side_effect = _neighbors_graph({
        "1": [{"type": "File", "id": "2", "path": "a.py"}],
        "2": [{"type": "File", "id": "3", "path": "b.py"}],
    })
    bfs = BoundedBFS(client)
    bfs.find_path(ENTRY, {"unreachable"}, max_hops=3)
    first = client.get_code_neighbors.call_count
    bfs.find_path(ENTRY, {"unreachable"}, max_hops=3)
    # Second walk reuses the cache: no new neighbor queries.
    assert client.get_code_neighbors.call_count == first


def test_bfs_returns_start_when_entry_is_target():
    client = MagicMock()
    path = BoundedBFS(client).find_path({"id": "99", "path": "x"}, TARGETS, max_hops=5)
    assert path is not None
    assert len(path) == 1
