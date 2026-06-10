"""Orbit REST API client (wraps /api/v4/orbit/query)."""

from __future__ import annotations

import json
from typing import Any

import httpx


class OrbitClient:
    def __init__(self, gitlab_url: str, token: str, project_id: int | str):
        self._base = gitlab_url.rstrip("/")
        self._project_id = project_id
        self._headers = {"PRIVATE-TOKEN": token, "Content-Type": "application/json"}

    def query(self, body: dict[str, Any]) -> dict[str, Any]:
        url = f"{self._base}/api/v4/orbit/query"
        params = {"project_id": self._project_id}
        resp = httpx.post(url, headers=self._headers, params=params, json=body, timeout=30)
        resp.raise_for_status()
        return resp.json()

    # --- Convenience query builders ---

    def get_vulnerability_occurrences(
        self,
        severity: list[str] | None = None,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        filters: dict[str, Any] = {}
        if severity:
            filters["severity"] = {"op": "in", "value": severity}

        body: dict[str, Any] = {
            "query_type": "traversal",
            "nodes": [
                {
                    "id": "v",
                    "entity": "Vulnerability",
                    "filters": {"state": "detected"},
                },
                {
                    "id": "occ",
                    "entity": "VulnerabilityOccurrence",
                    "columns": [
                        "id", "uuid", "name", "severity",
                        "location", "report_type",
                    ],
                    **({"filters": filters} if filters else {}),
                },
            ],
            "relationships": [{"type": "HAS_FINDING", "from": "v", "to": "occ"}],
            "limit": limit,
        }
        result = self.query(body)
        return result.get("data", [])

    def get_definitions_for_file(self, file_path: str) -> list[dict[str, Any]]:
        body = {
            "query_type": "traversal",
            "nodes": [
                {
                    "id": "def",
                    "entity": "Definition",
                    "columns": ["id", "file_path", "fqn", "name", "start_line", "end_line"],
                    "filters": {"file_path": {"op": "eq", "value": file_path}},
                }
            ],
            "limit": 100,
        }
        result = self.query(body)
        return result.get("data", [])

    def find_path(
        self,
        from_entity: str,
        from_id: int,
        to_entity: str,
        to_id: int,
        max_hops: int = 10,
    ) -> dict[str, Any]:
        body = {
            "query_type": "pathfinding",
            "from": {"entity": from_entity, "id": from_id},
            "to": {"entity": to_entity, "id": to_id},
            "max_hops": max_hops,
        }
        return self.query(body)

    def get_files_matching(self, patterns: list[str]) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for pattern in patterns:
            body = {
                "query_type": "traversal",
                "nodes": [
                    {
                        "id": "f",
                        "entity": "File",
                        "columns": ["id", "path", "name"],
                        "filters": {"path": {"op": "contains", "value": pattern.strip("*/")}},
                    }
                ],
                "limit": 200,
            }
            result = self.query(body)
            results.extend(result.get("data", []))
        return results

    def get_graph_schema(self) -> dict[str, Any]:
        return self.query({"query_type": "schema"})
