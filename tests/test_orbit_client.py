"""Integration-grade tests for OrbitClient.

The fixtures are real responses captured from the live GitLab Orbit API
(schema_version 0.1, format_version 2.1.0). respx mocks the HTTP layer so the
client's request-building and response-parsing are verified against the real
wire format without a network call.
"""

import json
from pathlib import Path

import httpx
import pytest
import respx

from src.reachgate.orbit_client import OrbitClient

FIXTURES = Path(__file__).parent / "fixtures"
QUERY_URL = "https://gitlab.com/api/v4/orbit/query"


def _load(name):
    return json.loads((FIXTURES / name).read_text())


def _client():
    return OrbitClient("https://gitlab.com", "glpat-test-token")


@respx.mock
def test_query_wraps_body_and_sets_auth_header():
    route = respx.post(QUERY_URL).mock(
        return_value=httpx.Response(200, json={"result": {"nodes": [], "edges": []}, "row_count": 0})
    )
    _client().query({"query_type": "traversal", "node": {"id": "p", "entity": "Project"}})

    sent = json.loads(route.calls.last.request.content)
    assert sent["format"] == "raw"
    assert sent["query"]["query_type"] == "traversal"
    assert route.calls.last.request.headers["Authorization"] == "Bearer glpat-test-token"


@respx.mock
def test_get_code_neighbors_filters_to_code_edges():
    respx.post(QUERY_URL).mock(
        return_value=httpx.Response(200, json=_load("orbit_neighbors_response.json"))
    )
    neighbors = _client().get_code_neighbors("File", "3514832492658439102")

    types = {n["type"] for n in neighbors}
    # DEFINES + IMPORTS targets kept; ON_BRANCH (Branch) dropped.
    assert "Definition" in types
    assert "ImportedSymbol" in types
    assert "Branch" not in types
    assert len(neighbors) == 3


@respx.mock
def test_get_code_neighbors_sends_neighbors_query_with_id_filter():
    route = respx.post(QUERY_URL).mock(
        return_value=httpx.Response(200, json=_load("orbit_neighbors_response.json"))
    )
    _client().get_code_neighbors("File", "3514832492658439102")

    inner = json.loads(route.calls.last.request.content)["query"]
    assert inner["query_type"] == "neighbors"
    assert inner["neighbors"]["node"] == inner["node"]["id"]
    assert inner["node"]["filters"]["id"]["op"] == "eq"


@respx.mock
def test_get_vulnerability_occurrences_parses_nodes():
    respx.post(QUERY_URL).mock(
        return_value=httpx.Response(200, json=_load("orbit_vuln_response.json"))
    )
    occs = _client().get_vulnerability_occurrences(severity=["high", "critical"])

    assert len(occs) == 2
    assert occs[0]["name"] == "RSA private key"
    assert "location" in occs[0]


@respx.mock
def test_get_file_by_path_returns_first_or_none():
    respx.post(QUERY_URL).mock(
        return_value=httpx.Response(200, json={"result": {"nodes": [], "edges": []}, "row_count": 0})
    )
    assert _client().get_file_by_path("does/not/exist.py") is None


@respx.mock
def test_get_imported_symbols_names_columns_explicitly():
    # The live API rejects columns=["*"] with a 400 compile_error; the
    # query must name real ImportedSymbol columns (regression for the
    # bug where every fallback call failed and flipped verdicts UNKNOWN).
    route = respx.post(QUERY_URL).mock(
        return_value=httpx.Response(200, json={"result": {"nodes": [], "edges": []}, "row_count": 0})
    )
    _client().get_imported_symbols("src/app.js")

    inner = json.loads(route.calls.last.request.content)["query"]
    columns = inner["node"]["columns"]
    assert "*" not in columns
    assert "identifier_name" in columns
    assert "import_path" in columns


def test_literal_needle_extracts_longest_glob_free_segment():
    # Internal-wildcard globs must not be searched as literal substrings.
    assert OrbitClient._literal_needle("cmd/**/main.*") == "main."
    assert OrbitClient._literal_needle("src/routes/**/*") == "routes"
    assert OrbitClient._literal_needle("app/controllers/**/*") == "controllers"
    assert OrbitClient._literal_needle("app.py") == "app.py"
    assert OrbitClient._literal_needle("server.ts") == "server.ts"
    # No usable literal at all.
    assert OrbitClient._literal_needle("**/*") == ""


@respx.mock
def test_get_files_matching_uses_literal_needle_not_raw_glob():
    # Regression: "cmd/**/main.*" used to be sent as the literal substring
    # "cmd/**/main." (matching nothing). It must now send a glob-free needle.
    route = respx.post(QUERY_URL).mock(
        return_value=httpx.Response(200, json={"result": {"nodes": [], "edges": []}, "row_count": 0})
    )
    _client().get_files_matching(["cmd/**/main.*", "src/routes/**/*"])

    sent_needles = [
        json.loads(c.request.content)["query"]["node"]["filters"]["path"]["value"]
        for c in route.calls
    ]
    assert "main." in sent_needles
    assert "routes" in sent_needles
    # No raw glob characters leaked into any search value.
    assert all("*" not in n for n in sent_needles)


@respx.mock
def test_get_files_matching_skips_patterns_without_usable_literal():
    route = respx.post(QUERY_URL).mock(
        return_value=httpx.Response(200, json={"result": {"nodes": [], "edges": []}, "row_count": 0})
    )
    # "**/*" has no >=3-char literal segment; it must be skipped, not sent.
    _client().get_files_matching(["**/*"])
    assert not route.called


@respx.mock
def test_get_status_hits_status_endpoint():
    route = respx.get("https://gitlab.com/api/v4/orbit/status").mock(
        return_value=httpx.Response(200, json={"status": "healthy"})
    )
    assert _client().get_status()["status"] == "healthy"
    assert route.called
