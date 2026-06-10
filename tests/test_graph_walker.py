import json
import pytest
from unittest.mock import MagicMock
from src.reachgate.graph_walker import GraphWalker, extract_file_from_location, ReachabilityResult
from src.reachgate.config import ReachGateConfig, PolicyConfig
from src.reachgate.path_strategy import PathNode


def _config():
    return ReachGateConfig(
        version="1",
        entrypoint_patterns=["src/routes/**/*", "app.py"],
        policy=PolicyConfig(min_hops=1, max_hops=10),
    )


class _FakeStrategy:
    """Returns a fixed path (or None) regardless of inputs."""
    def __init__(self, path):
        self._path = path

    def find_path(self, entry_file, target_definition, max_hops):
        return self._path


def test_extract_file_from_sast_location():
    loc = json.dumps({"file": "src/db/query_builder.py", "start_line": 42})
    assert extract_file_from_location(loc) == "src/db/query_builder.py"


def test_extract_file_returns_none_for_invalid_json():
    assert extract_file_from_location("not-json") is None


def test_extract_file_returns_none_for_empty_string():
    assert extract_file_from_location("") is None


def test_check_reachability_returns_not_reachable_when_no_location():
    client = MagicMock()
    walker = GraphWalker(client, _config())
    result = walker.check_reachability({"location": ""})
    assert not result.reachable


def test_check_reachability_reachable_when_path_found():
    client = MagicMock()
    client.get_definitions_for_file.return_value = [{"id": "99", "fqn": "db.query", "file_path": "src/db/query_builder.py"}]
    client.get_files_matching.return_value = [{"id": "1", "path": "src/routes/users.py"}]
    strategy = _FakeStrategy([
        PathNode(entity="File", node_id="1", label="src/routes/users.py"),
        PathNode(entity="Definition", node_id="50", label="handle"),
        PathNode(entity="Definition", node_id="99", label="query"),
    ])
    walker = GraphWalker(client, _config(), strategy=strategy)
    occ = {"location": json.dumps({"file": "src/db/query_builder.py", "start_line": 42})}
    result = walker.check_reachability(occ)
    assert result.reachable
    assert result.hops == 2


def test_check_reachability_not_reachable_when_no_path():
    client = MagicMock()
    client.get_definitions_for_file.return_value = [{"id": "99", "fqn": "legacy.fn", "file_path": "scripts/legacy/tool.py"}]
    client.get_files_matching.return_value = [{"id": "1", "path": "src/routes/users.py"}]
    strategy = _FakeStrategy(None)
    walker = GraphWalker(client, _config(), strategy=strategy)
    occ = {"location": json.dumps({"file": "scripts/legacy/tool.py", "start_line": 17})}
    result = walker.check_reachability(occ)
    assert not result.reachable
