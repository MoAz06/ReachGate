"""ReachGate agent entry point for GitLab Duo Agent Platform."""

from __future__ import annotations

import os
from typing import Any

from .actions import GitLabActions
from .config import load_config
from .graph_walker import GraphWalker
from .orbit_client import OrbitClient
from .path_strategy import BoundedBFS
from .policy_engine import evaluate

# Wall-clock budget per BFS walk. Without it, a live walk is bounded only by
# max_hops (depth), never by time, so a slow/large graph could keep the agent
# running for a very long time. A timeout makes such a walk terminate as an
# honest UNKNOWN (timeout_hit -> bounds_hit), never a false NOT_REACHABLE. This
# is intentionally time-only: no node-visit cap, so a large-but-healthy graph
# is not pushed to UNKNOWN by a visited budget.
DEFAULT_MAX_SECONDS_PER_WALK = 120.0


def run(
    gitlab_url: str | None = None,
    token: str | None = None,
    project_id: str | None = None,
    mr_iid: int | None = None,
    config_path: str = "reachgate.yml",
    severity_filter: list[str] | None = None,
    max_seconds_per_walk: float | None = DEFAULT_MAX_SECONDS_PER_WALK,
) -> list[dict[str, Any]]:
    gitlab_url = gitlab_url or os.environ.get("GITLAB_URL", "https://gitlab.com")
    token = token or os.environ.get("GITLAB_TOKEN")
    if not token:
        raise RuntimeError(
            "GITLAB_TOKEN is not set; required for the live Orbit query "
            "(personal access token with api scope)."
        )
    project_id = project_id or os.environ.get("GITLAB_PROJECT_ID") or os.environ.get("CI_PROJECT_ID")

    if mr_iid is None:
        _raw = os.environ.get("GITLAB_MR_IID") or os.environ.get("CI_MERGE_REQUEST_IID")
        mr_iid = int(_raw) if _raw else None

    config = load_config(config_path)
    client = OrbitClient(gitlab_url, token, project_id)
    # Time-only bound (no max_visited) so an overlong walk ends as an honest
    # UNKNOWN instead of running unbounded; pass None to disable the timeout.
    strategy = BoundedBFS(client, max_seconds=max_seconds_per_walk)
    walker = GraphWalker(client, config, strategy=strategy)
    actions = GitLabActions(gitlab_url, token, project_id)

    occurrences = client.get_vulnerability_occurrences(
        severity=severity_filter or ["critical", "high", "medium"],
    )

    results = []
    for occ in occurrences:
        reachability = walker.check_reachability(occ)
        receipt = evaluate(reachability, occ)
        outcome = actions.handle(receipt, mr_iid=mr_iid)
        results.append({
            "occurrence": occ.get("name"),
            "verdict": receipt.verdict.value,
            "risk_score": receipt.risk_score,
            "action": outcome.get("action"),
        })

    return results


if __name__ == "__main__":
    import json
    import sys

    try:
        print(json.dumps(run(), indent=2))
    except RuntimeError as e:
        # e.g. missing GITLAB_TOKEN: print one clean line, no traceback.
        print(f"reachgate: {e}", file=sys.stderr)
        sys.exit(2)
