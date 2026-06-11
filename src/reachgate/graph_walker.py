"""Walk the Orbit code graph from entry points to a vulnerable definition."""

from __future__ import annotations

import json
import posixpath
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


def import_resolves_to(import_path: str, importing_file: str, target_file: str) -> bool:
    """True if a module import path resolves to the target file.

    Relative paths are resolved against the importing file's directory;
    extensions are ignored ('../services/fetch_versions' matches
    'content/frontend/services/fetch_versions.js').
    """
    if not import_path:
        return False
    if import_path.startswith("."):
        base = posixpath.dirname(importing_file)
        resolved = posixpath.normpath(posixpath.join(base, import_path))
    else:
        resolved = import_path
    target_no_ext = target_file.rsplit(".", 1)[0]
    return resolved in (target_file, target_no_ext)


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
        target_ids = {str(d["id"]) for d in definitions if d.get("id") is not None}
        if not target_ids:
            return ReachabilityResult(reachable=False, vulnerable_file=vuln_file)

        # Dedupe by path: the global graph contains the same path in many
        # forks; one walk per declared entry point is enough.
        entry_files: list[dict[str, Any]] = []
        seen_paths: set[str] = set()
        for f in self._client.get_files_matching(self._config.entrypoint_patterns):
            p = f.get("path", "")
            if not p or p in seen_paths or not self._config.is_entrypoint(p):
                continue
            seen_paths.add(p)
            entry_files.append(f)

        for entry in entry_files:
            path = self._strategy.find_path(
                entry, target_ids, self._config.policy.max_hops
            )
            if not path:
                continue
            hops = len(path) - 1
            if hops < self._config.policy.min_hops:
                continue
            return ReachabilityResult(
                reachable=True,
                path=[f"{n.entity}:{n.label}" for n in path],
                hops=hops,
                entry_point=entry.get("path"),
                vulnerable_file=vuln_file,
                vulnerable_definition=path[-1].label,
            )

        # Fallback: some languages (notably JavaScript) are indexed with
        # import relationships as ImportedSymbol nodes rather than
        # IMPORTS/CALLS edges. A named import of a vulnerable definition
        # from the vulnerable file is a valid 2-hop path.
        definition_names = {d.get("name") for d in definitions if d.get("name")}
        for entry in entry_files:
            entry_path = entry.get("path", "")
            result = self._check_imported_symbols(
                entry_path, definition_names, vuln_file
            )
            if result:
                return result

        return ReachabilityResult(reachable=False, vulnerable_file=vuln_file)

    def _check_imported_symbols(
        self,
        entry_path: str,
        definition_names: set[str],
        vuln_file: str,
    ) -> ReachabilityResult | None:
        try:
            symbols = self._client.get_imported_symbols(entry_path)
        except Exception:
            return None
        for sym in symbols:
            name = sym.get("identifier_name")
            if name not in definition_names:
                continue
            if not import_resolves_to(
                sym.get("import_path", ""), entry_path, vuln_file
            ):
                continue
            return ReachabilityResult(
                reachable=True,
                path=[
                    f"File:{entry_path}",
                    f"ImportedSymbol:{name}",
                    f"Definition:{name}",
                ],
                hops=2,
                entry_point=entry_path,
                vulnerable_file=vuln_file,
                vulnerable_definition=name,
            )
        return None
