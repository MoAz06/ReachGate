"""Walk the Orbit code graph from entry points to a vulnerable definition."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from .config import ReachGateConfig
from .orbit_client import OrbitClient
from .path_strategy import BoundedBFS, PathStrategy


@dataclass
class ReachabilityResult:
    reachable: bool
    path: list[str] = field(default_factory=list)
    hops: int = 0
    entry_point: str | None = None
    vulnerable_file: str | None = None
    vulnerable_definition: str | None = None


def extract_file_from_location(location_json: str) -> str | None:
    """Parse VulnerabilityOccurrence.location JSON and return the file path."""
    try:
        loc = json.loads(location_json)
        # SAST findings use {"file": "path/to/file.py", "start_line": N}
        return loc.get("file") or loc.get("path")
    except (json.JSONDecodeError, TypeError):
        return None


class GraphWalker:
    def __init__(
        self,
        client: OrbitClient,
        config: ReachGateConfig,
        strategy: PathStrategy | None = None,
    ):
        self._client = client
        self._config = config
        self._strategy = strategy or BoundedBFS(client)

    def check_reachability(self, occurrence: dict[str, Any]) -> ReachabilityResult:
        location_json = occurrence.get("location", "")
        vuln_file = extract_file_from_location(location_json)

        if not vuln_file:
            return ReachabilityResult(reachable=False, vulnerable_file=None)

        definitions = self._client.get_definitions_for_file(vuln_file)
        entry_files = self._client.get_files_matching(self._config.entrypoint_patterns)

        for entry in entry_files:
            if not self._config.is_entrypoint(entry.get("path", "")):
                continue

            for defn in definitions:
                result = self._try_path(entry, defn, vuln_file)
                if result.reachable:
                    return result

        return ReachabilityResult(reachable=False, vulnerable_file=vuln_file)

    def _try_path(
        self,
        entry_file: dict[str, Any],
        vuln_definition: dict[str, Any],
        vuln_file: str,
    ) -> ReachabilityResult:
        path = self._strategy.find_path(
            entry_file, vuln_definition, self._config.policy.max_hops
        )
        if not path:
            return ReachabilityResult(reachable=False)

        hops = len(path) - 1
        if hops < self._config.policy.min_hops:
            return ReachabilityResult(reachable=False)

        path_labels = [f"{n.entity}:{n.label}" for n in path]

        return ReachabilityResult(
            reachable=True,
            path=path_labels,
            hops=hops,
            entry_point=entry_file.get("path"),
            vulnerable_file=vuln_file,
            vulnerable_definition=vuln_definition.get("fqn") or vuln_definition.get("name"),
        )
