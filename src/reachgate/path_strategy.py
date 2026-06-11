"""Path-finding over the Orbit code graph.

The Orbit API has no pathfinding query type, so reachability is reconstructed
with a bounded breadth-first search over DEFINES / IMPORTS / CALLS edges using
the `neighbors` query. The search targets a SET of definition ids (all the
definitions in the vulnerable file) in a single walk, and caches neighbor
lookups, so cost is bounded by nodes visited rather than (entries x definitions).

Every walk reports WHY it terminated (SearchOutcome.termination), so the
policy layer can distinguish an exhaustive no-path proof (frontier exhausted)
from a search that was cut off by a bound (hops / visited / timeout) — only
the former justifies NOT_REACHABLE.
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


# Walk termination reasons.
PATH_FOUND = "path_found"
FRONTIER_EXHAUSTED = "frontier_exhausted"
MAX_HOPS_HIT = "max_hops_hit"
VISITED_CAP_HIT = "visited_cap_hit"
TIMEOUT_HIT = "timeout_hit"

_CAP_TERMINATIONS = {MAX_HOPS_HIT, VISITED_CAP_HIT, TIMEOUT_HIT}


@dataclass
class SearchOutcome:
    """Result of one bounded walk, including why it stopped."""

    path: list[PathNode] | None
    termination: str
    nodes_visited: int = 0
    hops_used: int = 0
    api_errors: int = 0

    @property
    def found(self) -> bool:
        return self.path is not None

    @property
    def cap_hit(self) -> bool:
        """True when a search bound (not the graph itself) ended the walk."""
        return self.termination in _CAP_TERMINATIONS


class PathStrategy(Protocol):
    def search(
        self,
        entry_file: dict[str, Any],
        target_ids: set[str],
        max_hops: int,
    ) -> SearchOutcome:
        """Walk from entry file toward target_ids; report path and termination."""
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
        self.max_visited = max_visited
        self.max_seconds = max_seconds
        self._cache: dict[str, list[dict[str, Any]]] = {}
        self.cache_hits = 0
        self._walk_api_errors = 0

    # Transient HTTPS failures are common on long walks (observed live as
    # multi-second 5xx bursts); one flaky call must not flip a verdict to
    # UNKNOWN, so retry with exponential backoff (1s, 2s, 4s) first.
    NEIGHBOR_RETRIES = 3

    def _neighbors(self, entity: str, node_id: str) -> list[dict[str, Any]]:
        if node_id in self._cache:
            self.cache_hits += 1
            return self._cache[node_id]
        for attempt in range(1 + self.NEIGHBOR_RETRIES):
            try:
                result = self._client.get_code_neighbors(entity, node_id)
            except Exception:
                if attempt < self.NEIGHBOR_RETRIES:
                    time.sleep(1.0 * (2 ** attempt))
                    continue
                # Genuine failure: count it, and never cache it — a cached
                # empty result would silently pass for "no neighbors" in
                # later walks and could fake an exhaustive NOT_REACHABLE.
                self._walk_api_errors += 1
                return []
            self._cache[node_id] = result
            return result
        return []  # unreachable; keeps type checkers happy

    def find_path(
        self,
        entry_file: dict[str, Any],
        target_ids: set[str],
        max_hops: int,
    ) -> list[PathNode] | None:
        """Backwards-compatible wrapper: path only, no termination info."""
        return self.search(entry_file, target_ids, max_hops).path

    def search(
        self,
        entry_file: dict[str, Any],
        target_ids: set[str],
        max_hops: int,
    ) -> SearchOutcome:
        target_ids = {str(t) for t in target_ids}
        self._walk_api_errors = 0
        start = PathNode(
            entity="File",
            node_id=str(entry_file["id"]),
            label=str(entry_file.get("path") or entry_file["id"]),
        )
        if start.node_id in target_ids:
            return SearchOutcome(
                path=[start], termination=PATH_FOUND, nodes_visited=1
            )

        frontier: list[tuple[PathNode, list[PathNode]]] = [(start, [start])]
        visited: set[str] = {start.node_id}
        deadline = time.monotonic() + self.max_seconds if self.max_seconds else None

        def outcome(path, termination, hops):
            return SearchOutcome(
                path=path,
                termination=termination,
                nodes_visited=len(visited),
                hops_used=hops,
                api_errors=self._walk_api_errors,
            )

        for hop in range(max_hops):
            next_frontier: list[tuple[PathNode, list[PathNode]]] = []
            for node, path in frontier:
                if deadline and time.monotonic() > deadline:
                    return outcome(None, TIMEOUT_HIT, hop + 1)
                for raw in self._neighbors(node.entity, node.node_id):
                    nb = _to_path_node(raw)
                    if nb.node_id in visited:
                        continue
                    visited.add(nb.node_id)
                    new_path = path + [nb]
                    if nb.node_id in target_ids:
                        return outcome(new_path, PATH_FOUND, hop + 1)
                    next_frontier.append((nb, new_path))
                if self.max_visited and len(visited) >= self.max_visited:
                    return outcome(None, VISITED_CAP_HIT, hop + 1)
            frontier = next_frontier
            if not frontier:
                return outcome(None, FRONTIER_EXHAUSTED, hop + 1)
        return outcome(None, MAX_HOPS_HIT, max_hops)
