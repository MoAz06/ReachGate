"""Orbit REST API client.

All query bodies and the response shape are validated against the live
GitLab Orbit API (June 2026, schema_version 0.1, format_version 2.1.0):

  POST /api/v4/orbit/query
  body: {"query": <inner>, "format": "raw"}
  response: {"result": {"nodes": [...], "edges": [...]}, "row_count": N}

Inner query shapes:
  traversal (single): {"query_type":"traversal","node":{...,"filters":{...}},"limit":N}
  traversal (multi):  {"query_type":"traversal","nodes":[...],"relationships":[...],"limit":N}
  neighbors:          {"query_type":"neighbors","node":{...},"neighbors":{"node":"<alias>"}}

A filter on at least one node is REQUIRED (no full table scans). Node ids
come back as strings. Edges carry from_id, to_id, and type.
"""

from __future__ import annotations

import re
from typing import Any

import httpx


class OrbitClient:
    def __init__(self, gitlab_url: str, token: str, project_id: int | str | None = None):
        self._base = gitlab_url.rstrip("/")
        self._project_id = project_id
        self._headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }
        # Counted for the reachability certificate (audit metadata).
        self.api_calls = 0

    # --- Low-level ---

    def query(self, inner: dict[str, Any]) -> dict[str, Any]:
        """Run a query and return the raw {"result": {...}, "row_count": N} body."""
        url = f"{self._base}/api/v4/orbit/query"
        body = {"query": inner, "format": "raw"}
        self.api_calls += 1
        resp = httpx.post(url, headers=self._headers, json=body, timeout=30)
        resp.raise_for_status()
        return resp.json()

    def query_nodes(self, inner: dict[str, Any]) -> list[dict[str, Any]]:
        return self.query(inner).get("result", {}).get("nodes", [])

    def query_result(self, inner: dict[str, Any]) -> tuple[list[dict], list[dict]]:
        result = self.query(inner).get("result", {})
        return result.get("nodes", []), result.get("edges", [])

    # --- Convenience query builders ---

    def get_vulnerability_occurrences(
        self,
        severity: list[str] | None = None,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """Vulnerability occurrences carrying a parseable code location."""
        node: dict[str, Any] = {
            "id": "occ",
            "entity": "VulnerabilityOccurrence",
            "columns": ["id", "uuid", "name", "severity", "location"],
            "filters": {"uuid": {"op": "is_not_null"}},
        }
        if severity:
            node["filters"] = {"severity": {"op": "in", "value": severity}}

        return self.query_nodes({
            "query_type": "traversal",
            "node": node,
            "limit": limit,
        })

    def get_definitions_for_file(self, file_path: str) -> list[dict[str, Any]]:
        return self.query_nodes({
            "query_type": "traversal",
            "node": {
                "id": "d",
                "entity": "Definition",
                "columns": ["id", "file_path", "fqn", "name", "start_line", "end_line"],
                "filters": {"file_path": {"op": "eq", "value": file_path}},
            },
            "limit": 100,
        })

    def get_file_by_path(self, file_path: str) -> dict[str, Any] | None:
        nodes = self.query_nodes({
            "query_type": "traversal",
            "node": {
                "id": "f",
                "entity": "File",
                "columns": ["id", "path", "name", "language"],
                "filters": {"path": {"op": "eq", "value": file_path}},
            },
            "limit": 1,
        })
        return nodes[0] if nodes else None

    @staticmethod
    def _literal_needle(pattern: str) -> str:
        """Longest literal (glob-free) segment of a glob pattern.

        The Orbit `contains` filter is a plain substring match, so a glob
        like ``cmd/**/main.*`` must NOT be sent verbatim - it would search
        for the literal substring ``cmd/**/main.`` and match nothing. We
        split the pattern on path separators and glob metacharacters and
        return the longest remaining literal run (e.g. ``main.`` for
        ``cmd/**/main.*``, ``routes`` for ``src/routes/**/*``). This is a
        coarse prefetch; ``ReachGateConfig.is_entrypoint`` does the exact
        glob filtering afterwards, so over-fetching is safe.
        """
        segments = re.split(r"[/*?]+", pattern)
        literals = [s for s in segments if s]
        return max(literals, key=len) if literals else ""

    def get_files_matching(self, patterns: list[str]) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        seen_needles: set[str] = set()
        for pattern in patterns:
            needle = self._literal_needle(pattern)
            if len(needle) < 3:
                # API rejects search patterns under 3 chars. Without a usable
                # literal we cannot prefetch; is_entrypoint still filters any
                # files surfaced by other patterns, so just skip this one.
                continue
            if needle in seen_needles:
                continue  # avoid redundant identical queries
            seen_needles.add(needle)
            results.extend(self.query_nodes({
                "query_type": "traversal",
                "node": {
                    "id": "f",
                    "entity": "File",
                    "columns": ["id", "path", "name"],
                    "filters": {"path": {"op": "contains", "value": needle}},
                },
                "limit": 200,
            }))
        return results

    def get_imported_symbols(self, file_path: str) -> list[dict[str, Any]]:
        """ImportedSymbol nodes for a file.

        Some languages (notably JavaScript) are indexed with import
        relationships as ImportedSymbol nodes rather than IMPORTS/CALLS
        edges; these are first-class reachability evidence.

        Columns must be named explicitly: the API rejects ["*"] with a
        400 compile_error (verified live against schema_version 0.1).
        """
        return self.query_nodes({
            "query_type": "traversal",
            "node": {
                "id": "imp",
                "entity": "ImportedSymbol",
                "columns": [
                    "id", "file_path", "import_type", "import_path",
                    "identifier_name", "identifier_alias",
                ],
                "filters": {"file_path": {"op": "eq", "value": file_path}},
            },
            "limit": 200,
        })

    # Code-graph edges used for reachability walks.
    CODE_EDGES = {"DEFINES", "IMPORTS", "CALLS"}

    def get_code_neighbors(self, entity: str, node_id: str) -> list[dict[str, Any]]:
        """Neighbors of a node reachable over DEFINES/IMPORTS/CALLS edges.

        Uses the `neighbors` query, then keeps only targets connected by a
        code edge (filtering out ON_BRANCH and similar structural edges).
        """
        nodes, edges = self.query_result({
            "query_type": "neighbors",
            "node": {
                "id": "n",
                "entity": entity,
                "filters": {"id": {"op": "eq", "value": int(node_id)}},
            },
            "neighbors": {"node": "n"},
        })

        nodes_by_id = {n.get("id"): n for n in nodes}
        out: list[dict[str, Any]] = []
        for edge in edges:
            if edge.get("type") not in self.CODE_EDGES:
                continue
            if str(edge.get("from_id")) != str(node_id):
                continue
            target = nodes_by_id.get(edge.get("to_id"))
            if target:
                out.append(target)
        return out

    def get_graph_schema(self, expand: str | None = None) -> dict[str, Any]:
        url = f"{self._base}/api/v4/orbit/schema"
        params = {"expand": expand} if expand else None
        resp = httpx.get(url, headers=self._headers, params=params, timeout=30)
        resp.raise_for_status()
        return resp.json()

    def get_status(self) -> dict[str, Any]:
        url = f"{self._base}/api/v4/orbit/status"
        resp = httpx.get(url, headers=self._headers, timeout=30)
        resp.raise_for_status()
        return resp.json()
