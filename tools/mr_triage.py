"""MR triage demo: run the live engine and post receipts on the merge request.

Runs inside the reachgate-triage CI job on merge request pipelines. Walks the
live Orbit graph for two real findings on the GitLab docs-site, then posts
each receipt as an MR comment; the REACHABLE finding also gets a work item.

Required environment (provided by GitLab CI):
    GITLAB_TOKEN              masked CI/CD variable, api scope
    CI_PROJECT_ID             target project for comments / work items
    CI_MERGE_REQUEST_IID      the MR to comment on
"""

from __future__ import annotations

import json
import os
import sys
import time

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from reachgate.actions import GitLabActions, render_receipt  # noqa: E402
from reachgate.config import PolicyConfig, ReachGateConfig  # noqa: E402
from reachgate.graph_walker import GraphWalker  # noqa: E402
from reachgate.orbit_client import OrbitClient  # noqa: E402
from reachgate.path_strategy import BoundedBFS  # noqa: E402
from reachgate.policy_engine import evaluate  # noqa: E402

FINDINGS = [
    {
        "uuid": "demo-ssrf",
        "name": "Server-side request forgery (SSRF)",
        "severity": "high",
        "location": json.dumps({"file": "content/frontend/services/fetch_versions.js"}),
    },
    {
        "uuid": "demo-pathtraversal",
        "name": "Improper limitation of a pathname ('Path Traversal')",
        "severity": "medium",
        "location": json.dumps({"file": "scripts/create_issues.js"}),
    },
]

# Each visited node is one HTTPS round-trip; keep MR pipelines fast.
MAX_ENTRYPOINTS = 2
MAX_VISITED = 40
MAX_SECONDS_PER_WALK = 60
MAX_HOPS = 4


def discover_entrypoints(client: OrbitClient, needle: str) -> list[str]:
    """Attack surface for the demo: app files that import the vulnerable service."""
    nodes = client.query_nodes({
        "query_type": "traversal",
        "node": {
            "id": "s", "entity": "ImportedSymbol",
            "columns": ["id", "identifier_name", "import_path", "file_path"],
            "filters": {"import_path": {"op": "contains", "value": needle}},
        },
        "limit": 50,
    })
    paths = sorted({n.get("file_path") for n in nodes if n.get("file_path")})
    preferred = [p for p in paths if "spec" not in p and "test" not in p]
    return (preferred or paths)[:MAX_ENTRYPOINTS]


def main() -> int:
    token = os.environ.get("GITLAB_TOKEN")
    project_id = os.environ.get("GITLAB_PROJECT_ID") or os.environ.get("CI_PROJECT_ID")
    mr_iid_raw = os.environ.get("GITLAB_MR_IID") or os.environ.get("CI_MERGE_REQUEST_IID")
    if not token or not project_id or not mr_iid_raw:
        print("Need GITLAB_TOKEN, CI_PROJECT_ID and CI_MERGE_REQUEST_IID.")
        return 1
    mr_iid = int(mr_iid_raw)

    t0 = time.perf_counter()
    client = OrbitClient("https://gitlab.com", token)
    actions = GitLabActions("https://gitlab.com", token, project_id)

    entrypoints = discover_entrypoints(client, "fetch_versions")
    if not entrypoints:
        print("No entry points discovered; aborting without posting.")
        return 1
    print(f"Entry points: {entrypoints}")

    config = ReachGateConfig(
        version="1",
        entrypoint_patterns=entrypoints,
        policy=PolicyConfig(min_hops=1, max_hops=MAX_HOPS),
    )
    strategy = BoundedBFS(client, max_visited=MAX_VISITED,
                          max_seconds=MAX_SECONDS_PER_WALK)
    walker = GraphWalker(client, config, strategy=strategy)

    for finding in FINDINGS:
        result = walker.check_reachability(finding)
        receipt = evaluate(result, finding)
        print(render_receipt(receipt))
        outcome = actions.handle(receipt, mr_iid=mr_iid)
        print(f"-> {outcome.get('action')} (MR !{mr_iid})")

    print(f"[timing] total {time.perf_counter() - t0:.1f}s")
    return 0


if __name__ == "__main__":
    sys.exit(main())
