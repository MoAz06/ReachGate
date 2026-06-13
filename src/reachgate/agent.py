"""ReachGate agent entry point for GitLab Duo Agent Platform."""

from __future__ import annotations

import os
from typing import Any

from .actions import GitLabActions
from .config import load_config
from .graph_walker import GraphWalker
from .orbit_client import OrbitClient
from .policy_engine import evaluate


def run(
    gitlab_url: str | None = None,
    token: str | None = None,
    project_id: str | None = None,
    mr_iid: int | None = None,
    config_path: str = "reachgate.yml",
    severity_filter: list[str] | None = None,
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
    walker = GraphWalker(client, config)
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
    print(json.dumps(run(), indent=2))
