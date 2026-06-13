"""Walk the Orbit code graph from entry points to a vulnerable definition."""

from __future__ import annotations

import json
import posixpath
from dataclasses import dataclass, field
from typing import Any

from .certificate import SearchCertificate, hash_entrypoint_globs
from .config import ReachGateConfig
from .orbit_client import OrbitClient
from .path_strategy import (
    BoundedBFS,
    FRONTIER_EXHAUSTED,
    PATH_FOUND,
    PathStrategy,
    SearchOutcome,
)

# Reasons the walk could not produce sufficient evidence for a verdict.
# Any of these maps to UNKNOWN in the policy engine — never NOT_REACHABLE.
REASON_NO_LOCATION = "no_location"
REASON_NO_DEFINITIONS = "no_definitions_indexed"
REASON_NO_ENTRYPOINTS = "no_entrypoints"
REASON_BOUNDS_HIT = "bounds_hit"
REASON_API_ERROR = "api_error"
# A path WAS found, but it was shorter than the configured policy.min_hops.
# A found path proves reachability, so this can never be NOT_REACHABLE; the
# operator asked us not to count sub-min_hops paths as REACHABLE, so the only
# honest remaining verdict is UNKNOWN with an explicit reason.
REASON_BELOW_MIN_HOPS = "below_min_hops"


@dataclass
class ReachabilityResult:
    reachable: bool
    path: list[str] = field(default_factory=list)
    hops: int = 0
    entry_point: str | None = None
    vulnerable_file: str | None = None
    vulnerable_definition: str | None = None
    # None means the search produced a definitive answer; a reason string
    # means evidence was insufficient and the verdict must be UNKNOWN.
    evidence_reason: str | None = None
    certificate: SearchCertificate | None = None


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

    def _new_certificate(self) -> SearchCertificate:
        # Snapshot cumulative counters so the certificate reports this
        # finding's cost, not everything since the client/strategy started.
        self._api_calls_start = getattr(self._client, "api_calls", 0)
        self._cache_hits_start = getattr(self._strategy, "cache_hits", 0)
        return SearchCertificate(
            max_hops=self._config.policy.max_hops,
            max_visited=getattr(self._strategy, "max_visited", None),
            max_seconds=getattr(self._strategy, "max_seconds", None),
            entrypoint_globs_hash=hash_entrypoint_globs(
                self._config.entrypoint_patterns
            ),
        )

    def _finalize(self, cert: SearchCertificate) -> SearchCertificate:
        cert.orbit_api_calls = (
            getattr(self._client, "api_calls", 0) - self._api_calls_start
        )
        cert.cache_hits = (
            getattr(self._strategy, "cache_hits", 0) - self._cache_hits_start
        )
        return cert

    def _search(
        self, entry: dict[str, Any], target_ids: set[str], max_hops: int
    ) -> SearchOutcome:
        # Legacy strategies (test fakes) may only implement find_path; treat
        # their answer as a completed search.
        search = getattr(self._strategy, "search", None)
        if search is not None:
            return search(entry, target_ids, max_hops)
        path = self._strategy.find_path(entry, target_ids, max_hops)
        return SearchOutcome(
            path=path,
            termination=PATH_FOUND if path else FRONTIER_EXHAUSTED,
            nodes_visited=len(path) if path else 0,
        )

    def check_reachability(self, occurrence: dict[str, Any]) -> ReachabilityResult:
        cert = self._new_certificate()
        location_json = occurrence.get("location", "")
        vuln_file = extract_file_from_location(location_json)

        if not vuln_file:
            return ReachabilityResult(
                reachable=False,
                vulnerable_file=None,
                evidence_reason=REASON_NO_LOCATION,
                certificate=self._finalize(cert),
            )

        # Any failed Orbit call means the evidence is incomplete: UNKNOWN,
        # never a crash and never a silent no-path.
        try:
            definitions = self._client.get_definitions_for_file(vuln_file)
        except Exception:
            cert.api_errors += 1
            return ReachabilityResult(
                reachable=False,
                vulnerable_file=vuln_file,
                evidence_reason=REASON_API_ERROR,
                certificate=self._finalize(cert),
            )
        target_ids = {str(d["id"]) for d in definitions if d.get("id") is not None}
        cert.target_definitions_found = len(target_ids)
        if not target_ids:
            return ReachabilityResult(
                reachable=False,
                vulnerable_file=vuln_file,
                evidence_reason=REASON_NO_DEFINITIONS,
                certificate=self._finalize(cert),
            )

        # Dedupe by path: the global graph contains the same path in many
        # forks; one walk per declared entry point is enough.
        try:
            matching_files = self._client.get_files_matching(
                self._config.entrypoint_patterns
            )
        except Exception:
            cert.api_errors += 1
            return ReachabilityResult(
                reachable=False,
                vulnerable_file=vuln_file,
                evidence_reason=REASON_API_ERROR,
                certificate=self._finalize(cert),
            )
        entry_files: list[dict[str, Any]] = []
        seen_paths: set[str] = set()
        for f in matching_files:
            p = f.get("path", "")
            if not p or p in seen_paths or not self._config.is_entrypoint(p):
                continue
            seen_paths.add(p)
            entry_files.append(f)

        cert.entrypoints_checked = len(entry_files)
        if not entry_files:
            return ReachabilityResult(
                reachable=False,
                vulnerable_file=vuln_file,
                evidence_reason=REASON_NO_ENTRYPOINTS,
                certificate=self._finalize(cert),
            )

        cert.strategies_attempted.append("graph_edges")
        outcomes: list[SearchOutcome] = []
        # Set when a path is found but filtered out by policy.min_hops. A found
        # path proves reachability, so this must never be allowed to fall
        # through to NOT_REACHABLE (see REASON_BELOW_MIN_HOPS).
        found_below_min_hops = False
        for entry in entry_files:
            outcome = self._search(entry, target_ids, self._config.policy.max_hops)
            outcomes.append(outcome)
            cert.nodes_visited += outcome.nodes_visited
            cert.api_errors += outcome.api_errors
            cert.max_hops_hit |= outcome.termination == "max_hops_hit"
            cert.visited_cap_hit |= outcome.termination == "visited_cap_hit"
            cert.timeout_hit |= outcome.termination == "timeout_hit"
            path = outcome.path
            if not path:
                continue
            hops = len(path) - 1
            if hops < self._config.policy.min_hops:
                found_below_min_hops = True
                continue
            cert.evidence_modes.append("graph_edges")
            return ReachabilityResult(
                reachable=True,
                path=[f"{n.entity}:{n.label}" for n in path],
                hops=hops,
                entry_point=entry.get("path"),
                vulnerable_file=vuln_file,
                vulnerable_definition=path[-1].label,
                certificate=self._finalize(cert),
            )

        # Fallback: some languages (notably JavaScript) are indexed with
        # import relationships as ImportedSymbol nodes rather than
        # IMPORTS/CALLS edges. A named import of a vulnerable definition
        # from the vulnerable file is a valid 2-hop path.
        cert.strategies_attempted.append("imported_symbol")
        definition_names = {d.get("name") for d in definitions if d.get("name")}
        for entry in entry_files:
            entry_path = entry.get("path", "")
            result = self._check_imported_symbols(
                entry_path, definition_names, vuln_file, cert
            )
            if result:
                # A found import path proves reachability. Apply the same
                # min_hops policy gate as the graph-edges path so both
                # evidence modes treat a sub-min_hops path identically.
                if result.hops < self._config.policy.min_hops:
                    found_below_min_hops = True
                    continue
                cert.evidence_modes.append("imported_symbol")
                result.certificate = self._finalize(cert)
                return result

        # No path. NOT_REACHABLE is only honest when every walk ran to
        # completion (frontier exhausted, or a found-but-filtered path) and
        # no API call failed; otherwise the absence of a path proves nothing.
        # A path that WAS found but filtered by min_hops proves reachability,
        # so it can never be NOT_REACHABLE - it is UNKNOWN/below_min_hops.
        if cert.api_errors:
            evidence_reason = REASON_API_ERROR
        elif found_below_min_hops:
            evidence_reason = REASON_BELOW_MIN_HOPS
        elif cert.bounds_hit:
            evidence_reason = REASON_BOUNDS_HIT
        else:
            evidence_reason = None
            cert.frontier_exhausted = True

        return ReachabilityResult(
            reachable=False,
            vulnerable_file=vuln_file,
            evidence_reason=evidence_reason,
            certificate=self._finalize(cert),
        )

    def _check_imported_symbols(
        self,
        entry_path: str,
        definition_names: set[str],
        vuln_file: str,
        cert: SearchCertificate,
    ) -> ReachabilityResult | None:
        try:
            symbols = self._client.get_imported_symbols(entry_path)
        except Exception:
            # Counted so a failed fallback query surfaces as UNKNOWN
            # (api_error) instead of silently passing for NOT_REACHABLE.
            cert.api_errors += 1
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
