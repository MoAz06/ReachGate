"""Path-finding over the Orbit code graph.

The Orbit API has no pathfinding query type, so reachability is reconstructed
with a bounded breadth-first search over DEFINES / IMPORTS / CALLS edges using
the `neighbors` query. The search targets a SET of definition ids (all the
definitions in the vulnerable file) in a single walk, and caches neighbor
lookups, so cost is bounded by nodes visited rather than (entries x definitions).
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Protocol

from .orbit_client import OrbitClient


@dataclass(frozen=True)
class PathNode:
    entity: str
    node_id: str
    label: str


class PathStrategy(Protocol):
    def find_path(
        self,
        entry_file: dict[str, Any],
        target_ids: set[str],
        max_hops: int,
    ) -> list[PathNode] | None:
        """Return a path from entry file to any node in target_ids, or None."""
        ...


def _to_path_node(raw: dict[str, Any]) -> PathNode:
    entity = raw.get("type") or raw.get("entity") or "?"
    label = str(
        raw.get("name")
        or raw.get("path")
        or raw.get("file_path")
        or raw.get("identifier_name")
        or raw.get("id")
    )
    return PathNode(entity=entity, node_id=str(raw.get("id")), label=label)


class BoundedBFS:
    """Breadth-first search over DEFINES/IMPORTS/CALLS edges toward a target set,
    bounded by max_hops, with a per-instance neighbor cache."""

    def __init__(
        self,
        client: OrbitClient,
        max_visited: int | None = None,
        max_seconds: float | None = None,
    ):
        self._client = client
        self._max_visited = max_visited
        self._max_seconds = max_seconds
        self._cache: dict[str, list[dict[str, Any]]] = {}

    def _neighbors(self, entity: str, node_id: str) -> list[dict[str, Any]]:
        if node_id in self._cache:
            return self._cache[node_id]
        try:
            result = self._client.get_code_neighbors(entity, node_id)
        except Exception:
            result = []
        self._cache[node_id] = result
        return result

    def find_path(
        self,
        entry_file: dict[str, Any],
        target_ids: set[str],
        max_hops: int,
    ) -> list[PathNode] | None:
        target_ids = {str(t) for t in target_ids}
        start = PathNode(
            entity="File",
            node_id=str(entry_file["id"]),
            label=str(entry_file.get("path") or entry_file["id"]),
        )
        if start.node_id in target_ids:
            return [start]

        frontier: list[tuple[PathNode, list[PathNode]]] = [(start, [start])]
        visited: set[str] = {start.node_id}
        deadline = time.monotonic() + self._max_seconds if self._max_seconds else None

        for _ in range(max_hops):
            next_frontier: list[tuple[PathNode, list[PathNode]]] = []
            for node, path in frontier:
                if deadline and time.monotonic() > deadline:
                    return None
                for raw in self._neighbors(node.entity, node.node_id):
                    nb = _to_path_node(raw)
                    if nb.node_id in visited:
                        continue
                    visited.add(nb.node_id)
                    new_path = path + [nb]
                    if nb.node_id in target_ids:
                        return new_path
                    next_frontier.append((nb, new_path))
                if self._max_visited and len(visited) >= self._max_visited:
                    return None
            frontier = next_frontier
            if not frontier:
                return None
        return None
