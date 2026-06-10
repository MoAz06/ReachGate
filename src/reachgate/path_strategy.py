"""Path-finding over the Orbit code graph.

The Orbit API has no pathfinding query type, so reachability is reconstructed
with a bounded breadth-first search over DEFINES / IMPORTS / CALLS edges using
the `neighbors` query (one query per visited node, frontier capped at max_hops).
"""

from __future__ import annotations

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
        target_definition: dict[str, Any],
        max_hops: int,
    ) -> list[PathNode] | None:
        """Return the node path from entry file to target definition, or None."""
        ...


def _to_path_node(raw: dict[str, Any]) -> PathNode:
    # Orbit nodes carry their type under "type"; some callers use "entity".
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
    """Breadth-first search over DEFINES/IMPORTS/CALLS edges, one neighbors
    query per visited node, bounded by max_hops."""

    def __init__(self, client: OrbitClient):
        self._client = client

    def find_path(
        self,
        entry_file: dict[str, Any],
        target_definition: dict[str, Any],
        max_hops: int,
    ) -> list[PathNode] | None:
        target_id = str(target_definition["id"])
        start = PathNode(
            entity="File",
            node_id=str(entry_file["id"]),
            label=str(entry_file.get("path") or entry_file["id"]),
        )
        if start.node_id == target_id:
            return [start]

        frontier: list[tuple[PathNode, list[PathNode]]] = [(start, [start])]
        visited: set[str] = {start.node_id}

        for _ in range(max_hops):
            next_frontier: list[tuple[PathNode, list[PathNode]]] = []
            for node, path in frontier:
                try:
                    neighbors = self._client.get_code_neighbors(node.entity, node.node_id)
                except Exception:
                    continue
                for raw in neighbors:
                    nb = _to_path_node(raw)
                    if nb.node_id in visited:
                        continue
                    visited.add(nb.node_id)
                    new_path = path + [nb]
                    if nb.node_id == target_id:
                        return new_path
                    next_frontier.append((nb, new_path))
            frontier = next_frontier
            if not frontier:
                return None
        return None
