"""MR triage: run the live engine and upsert receipts on the merge request.

Runs inside the reachgate-triage CI job on merge request pipelines. Walks the
live Orbit graph for each finding, then upserts its receipt as an MR comment,
idempotent by fingerprint: a rerun updates in place instead of duplicating.

This MR flow is comment-only by design -- it never creates work items. Work
item creation belongs to the agent/catalog flow (actions.handle()), not here.

Required environment (provided by GitLab CI):
    GITLAB_TOKEN              masked CI/CD variable, api scope
    CI_PROJECT_ID             target project for the MR comments
    CI_MERGE_REQUEST_IID      the MR to comment on
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time

import httpx

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from reachgate.actions import GitLabActions, render_receipt, write_artifact  # noqa: E402
from reachgate.config import PolicyConfig, ReachGateConfig, load_config  # noqa: E402
from reachgate.findings import FindingsLoadError, load_findings  # noqa: E402
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
# MAX_HOPS=6: preflight (tools/preflight_bounds.py) showed both demo walks
# exhaust their frontier by hop 5, so the no-path verdict is exhaustive
# (honest NOT_REACHABLE) instead of bounds-limited (UNKNOWN).
MAX_ENTRYPOINTS = 2
MAX_VISITED = 40
MAX_SECONDS_PER_WALK = 120  # per-walk; live runs measured ~30s/walk, 2x margin
MAX_HOPS = 6


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


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="ReachGate MR triage")
    parser.add_argument("--findings", help="Path to a GitLab SAST or native findings JSON")
    parser.add_argument("--config", help="Path to reachgate.yml (BYO mode)")
    return parser.parse_args(argv)


def _run_triage(args, token: str, project_id: str, mr_iid: int) -> int:
    """The live triage work: walk Orbit and upsert MR receipts.

    May raise httpx.HTTPError (live Orbit/GitLab) or FindingsLoadError /
    config errors (BYO mode). main() turns those into clean exit code 2.
    """
    t0 = time.perf_counter()
    client = OrbitClient("https://gitlab.com", token)
    actions = GitLabActions("https://gitlab.com", token, project_id)

    findings_path = args.findings or os.environ.get("REACHGATE_FINDINGS_FILE")

    if findings_path:
        # Bring-your-own findings: load the declared attack surface from real
        # config (reachgate.yml) instead of the demo discovery, so the
        # reachability verdict reflects the caller's project, not the demo.
        findings = load_findings(findings_path)
        config_path = args.config or os.environ.get("REACHGATE_CONFIG", "reachgate.yml")
        config = load_config(config_path)
        print(f"BYO mode: {len(findings)} finding(s) from {findings_path}, "
              f"config {config_path}")
    else:
        # Demo default (Fase 1 proof): hardcoded findings + live discovery.
        findings = FINDINGS
        entrypoints = discover_entrypoints(client, "fetch_versions")
        if not entrypoints:
            print("No entry points discovered; aborting without posting.")
            return 1
        config = ReachGateConfig(
            version="1",
            entrypoint_patterns=entrypoints,
            policy=PolicyConfig(min_hops=1, max_hops=MAX_HOPS),
        )
        print(f"Demo mode: entry points {entrypoints}")

    strategy = BoundedBFS(client, max_visited=MAX_VISITED,
                          max_seconds=MAX_SECONDS_PER_WALK)
    walker = GraphWalker(client, config, strategy=strategy)

    receipts = []
    for finding in findings:
        result = walker.check_reachability(finding)
        receipt = evaluate(result, finding)
        receipts.append(receipt)
        print(render_receipt(receipt))
        # MR flow is comment-only and idempotent: upsert the receipt, never
        # create work items here (that belongs to the agent/catalog flow).
        res = actions.upsert_mr_receipt(mr_iid, receipt)
        print(f"-> {res['action']} occ={receipt.occurrence_id} "
              f"fp={receipt.fingerprint} (MR !{mr_iid})")
        if res.get("warning"):
            print(f"   warning: {res['warning']}")

    # Always write the artifact, even when every comment was unchanged.
    artifact_path = write_artifact(receipts)
    print(f"Wrote {artifact_path} ({len(receipts)} receipts)")

    print(f"[timing] total {time.perf_counter() - t0:.1f}s")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    token = os.environ.get("GITLAB_TOKEN")
    project_id = os.environ.get("GITLAB_PROJECT_ID") or os.environ.get("CI_PROJECT_ID")
    mr_iid_raw = os.environ.get("GITLAB_MR_IID") or os.environ.get("CI_MERGE_REQUEST_IID")
    if not token or not project_id or not mr_iid_raw:
        print("Need GITLAB_TOKEN, CI_PROJECT_ID and CI_MERGE_REQUEST_IID.")
        return 1
    mr_iid = int(mr_iid_raw)

    # Turn live Orbit/GitLab failures and BYO input/config errors into one
    # clean CI log line with a deliberate exit code 2 -- never a traceback.
    try:
        return _run_triage(args, token, project_id, mr_iid)
    except httpx.HTTPStatusError as e:
        code = e.response.status_code
        hint = " (check GITLAB_TOKEN scope)" if code in (401, 403) else ""
        print(f"mr_triage: GitLab/Orbit request failed: HTTP {code}{hint}",
              file=sys.stderr)
        return 2
    except httpx.HTTPError as e:
        # Connection / timeout / transport errors.
        print(f"mr_triage: GitLab/Orbit request failed: {type(e).__name__}: {e}",
              file=sys.stderr)
        return 2
    except FindingsLoadError as e:
        print(f"mr_triage: could not load findings: {e}", file=sys.stderr)
        return 2
    except (FileNotFoundError, ValueError, KeyError, TypeError) as e:
        # BYO config problems (missing/invalid reachgate.yml).
        print(f"mr_triage: configuration error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
