"""Reachability certificate: auditable metadata for every verdict.

A verdict without a record of HOW the search ran is just an assertion. The
certificate captures the search bounds, what was actually visited, which
evidence modes produced the verdict, and whether any bound cut the search
short — enough to judge the verdict's strength and to replay it.

The receipt fingerprint is intentionally computed ONLY from stable inputs
(finding identity, verdict, path, policy version, declared attack surface).
Dynamic metrics (api calls, nodes visited, timing) are excluded so the same
finding under the same policy always produces the same fingerprint — that is
what makes idempotent GitLab actions safe.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

STRATEGY_NAME = "bounded-bfs-v1"


@dataclass
class SearchCertificate:
    strategy: str = STRATEGY_NAME
    policy_version: str = ""  # filled in by the policy engine
    max_hops: int = 0
    max_visited: int | None = None
    max_seconds: float | None = None
    entrypoints_checked: int = 0
    target_definitions_found: int = 0
    nodes_visited: int = 0
    max_hops_hit: bool = False
    visited_cap_hit: bool = False
    timeout_hit: bool = False
    frontier_exhausted: bool = False
    api_errors: int = 0
    orbit_api_calls: int = 0
    cache_hits: int = 0
    # What was tried, vs. what actually produced the verdict's evidence.
    # A fallback that found nothing is attempted, not evidence.
    strategies_attempted: list[str] = field(default_factory=list)
    evidence_modes: list[str] = field(default_factory=list)
    entrypoint_globs_hash: str = ""

    @property
    def bounds_hit(self) -> bool:
        return self.max_hops_hit or self.visited_cap_hit or self.timeout_hit

    def as_dict(self) -> dict[str, Any]:
        return {
            "strategy": self.strategy,
            "policy_version": self.policy_version,
            "bounds": {
                "max_hops": self.max_hops,
                "max_visited": self.max_visited,
                "max_seconds": self.max_seconds,
            },
            "entrypoints_checked": self.entrypoints_checked,
            "target_definitions_found": self.target_definitions_found,
            "nodes_visited": self.nodes_visited,
            "max_hops_hit": self.max_hops_hit,
            "visited_cap_hit": self.visited_cap_hit,
            "timeout_hit": self.timeout_hit,
            "frontier_exhausted": self.frontier_exhausted,
            "api_errors": self.api_errors,
            "orbit_api_calls": self.orbit_api_calls,
            "cache_hits": self.cache_hits,
            "strategies_attempted": self.strategies_attempted,
            "evidence_modes": self.evidence_modes,
            "entrypoint_globs_hash": self.entrypoint_globs_hash,
        }


def hash_entrypoint_globs(patterns: list[str]) -> str:
    """Stable hash of the declared attack surface (order-independent)."""
    canonical = json.dumps(sorted(patterns), separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()[:12]


def compute_fingerprint(
    *,
    occurrence_uuid: str | None,
    occurrence_name: str | None,
    severity: str | None,
    verdict: str,
    vulnerable_file: str | None,
    vulnerable_definition: str | None,
    path: list[str],
    policy_version: str,
    entrypoint_globs_hash: str,
) -> str:
    """Stable receipt fingerprint. NO dynamic metrics — see module docstring."""
    canonical = json.dumps(
        {
            "occurrence_uuid": occurrence_uuid,
            "occurrence_name": occurrence_name,
            "severity": severity,
            "verdict": verdict,
            "vulnerable_file": vulnerable_file,
            "vulnerable_definition": vulnerable_definition,
            "path": path,
            "policy_version": policy_version,
            "entrypoint_globs_hash": entrypoint_globs_hash,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode()).hexdigest()[:16]
