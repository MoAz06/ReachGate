import json
import pytest
from unittest.mock import MagicMock
from src.reachgate.graph_walker import (
    GraphWalker,
    ReachabilityResult,
    extract_file_from_location,
    import_resolves_to,
)
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

    def find_path(self, entry_file, target_ids, max_hops):
        return self._path


def test_import_resolves_relative_path_without_extension():
    assert import_resolves_to(
        "../services/fetch_versions",
        "content/frontend/404/archives_redirect.js",
        "content/frontend/services/fetch_versions.js",
    )


def test_import_resolves_rejects_different_module():
    assert not import_resolves_to(
        "../services/other",
        "content/frontend/404/archives_redirect.js",
        "content/frontend/services/fetch_versions.js",
    )


def test_import_resolves_absolute_module_path():
    assert import_resolves_to(
        "content/frontend/services/fetch_versions.js",
        "anything.js",
        "content/frontend/services/fetch_versions.js",
    )


def test_import_resolves_empty_path_is_false():
    assert not import_resolves_to("", "a.js", "b.js")


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
    client.get_imported_symbols.return_value = []
    strategy = _FakeStrategy(None)
    walker = GraphWalker(client, _config(), strategy=strategy)
    occ = {"location": json.dumps({"file": "scripts/legacy/tool.py", "start_line": 17})}
    result = walker.check_reachability(occ)
    assert not result.reachable


def test_imported_symbol_fallback_finds_named_import():
    """When edge BFS fails, a matching ImportedSymbol node is a 2-hop path."""
    client = MagicMock()
    client.get_definitions_for_file.return_value = [
        {"id": "99", "name": "getArchivesVersions", "file_path": "content/frontend/services/fetch_versions.js"}
    ]
    client.get_files_matching.return_value = [{"id": "1", "path": "src/routes/redirect.js"}]
    client.get_imported_symbols.return_value = [
        {
            "identifier_name": "getArchivesVersions",
            "import_path": "../../content/frontend/services/fetch_versions",
            "import_type": "NamedImport",
            "file_path": "src/routes/redirect.js",
        }
    ]
    walker = GraphWalker(client, _config(), strategy=_FakeStrategy(None))
    occ = {"location": json.dumps({"file": "content/frontend/services/fetch_versions.js"})}
    result = walker.check_reachability(occ)
    assert result.reachable
    assert result.hops == 2
    assert result.path == [
        "File:src/routes/redirect.js",
        "ImportedSymbol:getArchivesVersions",
        "Definition:getArchivesVersions",
    ]


def test_found_path_below_min_hops_is_unknown_not_not_reachable():
    """A path WAS found but is shorter than policy.min_hops.

    A found path proves reachability, so the verdict must never be
    NOT_REACHABLE. Before the fix this path was silently dropped and the
    walk fell through to an (exhaustive) NOT_REACHABLE. It must now be an
    explicit UNKNOWN/below_min_hops instead.
    """
    from src.reachgate.graph_walker import REASON_BELOW_MIN_HOPS

    config = ReachGateConfig(
        version="1",
        entrypoint_patterns=["src/routes/**/*", "app.py"],
        policy=PolicyConfig(min_hops=2, max_hops=10),
    )
    client = MagicMock()
    client.get_definitions_for_file.return_value = [
        {"id": "99", "name": "query", "file_path": "src/routes/users.py"}
    ]
    client.get_files_matching.return_value = [{"id": "1", "path": "src/routes/users.py"}]
    client.get_imported_symbols.return_value = []
    # A 1-hop path: entry file -> definition. 1 < min_hops(2).
    strategy = _FakeStrategy([
        PathNode(entity="File", node_id="1", label="src/routes/users.py"),
        PathNode(entity="Definition", node_id="99", label="query"),
    ])
    walker = GraphWalker(client, config, strategy=strategy)
    occ = {"location": json.dumps({"file": "src/routes/users.py", "start_line": 5})}
    result = walker.check_reachability(occ)

    # The path was found, so this is NOT an exhaustive no-path proof.
    assert not result.reachable
    assert result.evidence_reason == REASON_BELOW_MIN_HOPS


def test_imported_symbol_fallback_reachable_at_min_hops_one():
    """min_hops=1: a 2-hop imported-symbol path is REACHABLE (parity case)."""
    config = ReachGateConfig(
        version="1",
        entrypoint_patterns=["src/routes/**/*", "app.py"],
        policy=PolicyConfig(min_hops=1, max_hops=10),
    )
    client = MagicMock()
    client.get_definitions_for_file.return_value = [
        {"id": "99", "name": "getArchivesVersions",
         "file_path": "content/frontend/services/fetch_versions.js"}
    ]
    client.get_files_matching.return_value = [{"id": "1", "path": "src/routes/redirect.js"}]
    client.get_imported_symbols.return_value = [
        {
            "identifier_name": "getArchivesVersions",
            "import_path": "../../content/frontend/services/fetch_versions",
            "import_type": "NamedImport",
            "file_path": "src/routes/redirect.js",
        }
    ]
    walker = GraphWalker(client, config, strategy=_FakeStrategy(None))
    occ = {"location": json.dumps({"file": "content/frontend/services/fetch_versions.js"})}
    result = walker.check_reachability(occ)
    assert result.reachable
    assert result.hops == 2


def test_imported_symbol_fallback_below_min_hops_is_unknown():
    """min_hops=3: the same 2-hop imported-symbol path proves reachability,
    so it must be UNKNOWN/below_min_hops -- never NOT_REACHABLE. This covers
    the parity gate added to the ImportedSymbol fallback in Fase 1.
    """
    from src.reachgate.graph_walker import REASON_BELOW_MIN_HOPS

    config = ReachGateConfig(
        version="1",
        entrypoint_patterns=["src/routes/**/*", "app.py"],
        policy=PolicyConfig(min_hops=3, max_hops=10),
    )
    client = MagicMock()
    client.get_definitions_for_file.return_value = [
        {"id": "99", "name": "getArchivesVersions",
         "file_path": "content/frontend/services/fetch_versions.js"}
    ]
    client.get_files_matching.return_value = [{"id": "1", "path": "src/routes/redirect.js"}]
    client.get_imported_symbols.return_value = [
        {
            "identifier_name": "getArchivesVersions",
            "import_path": "../../content/frontend/services/fetch_versions",
            "import_type": "NamedImport",
            "file_path": "src/routes/redirect.js",
        }
    ]
    walker = GraphWalker(client, config, strategy=_FakeStrategy(None))
    occ = {"location": json.dumps({"file": "content/frontend/services/fetch_versions.js"})}
    result = walker.check_reachability(occ)
    assert not result.reachable
    assert result.evidence_reason == REASON_BELOW_MIN_HOPS


def test_imported_symbol_fallback_rejects_wrong_module():
    """Same symbol name imported from a different module is not a path."""
    client = MagicMock()
    client.get_definitions_for_file.return_value = [
        {"id": "99", "name": "getArchivesVersions", "file_path": "content/frontend/services/fetch_versions.js"}
    ]
    client.get_files_matching.return_value = [{"id": "1", "path": "src/routes/redirect.js"}]
    client.get_imported_symbols.return_value = [
        {
            "identifier_name": "getArchivesVersions",
            "import_path": "./other_module",
            "import_type": "NamedImport",
            "file_path": "src/routes/redirect.js",
        }
    ]
    walker = GraphWalker(client, _config(), strategy=_FakeStrategy(None))
    occ = {"location": json.dumps({"file": "content/frontend/services/fetch_versions.js"})}
    result = walker.check_reachability(occ)
    assert not result.reachable
