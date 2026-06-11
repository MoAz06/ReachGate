"""Live test: create a real GitLab issue + MR comment via GitLabActions.

Usage:
    export GITLAB_TOKEN="glpat-xxxxx"
    export GITLAB_PROJECT_ID="83119911"
    python tools/test_actions.py
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from reachgate.actions import GitLabActions, render_receipt
from reachgate.policy_engine import PolicyReceipt, TriggeredRule, Verdict


def main() -> int:
    token = os.environ.get("GITLAB_TOKEN")
    project_id = os.environ.get("GITLAB_PROJECT_ID")
    if not token or not project_id:
        print("Set GITLAB_TOKEN and GITLAB_PROJECT_ID first.")
        return 1

    receipt = PolicyReceipt(
        verdict=Verdict.REACHABLE,
        risk_score=85,
        triggered_rules=[
            TriggeredRule("path_exists", 50, "A graph path exists from a declared entry point to the vulnerable definition."),
            TriggeredRule("direct_import", 20, "Vulnerable code is directly or nearly directly imported (<=2 hops)."),
            TriggeredRule("high_severity", 15, "Finding severity is critical or high."),
        ],
        path=["File:content/frontend/404/archives_redirect.js", "Definition:getArchivesVersions"],
        hops=1,
        entry_point="content/frontend/404/archives_redirect.js",
        vulnerable_file="content/frontend/services/fetch_versions.js",
        vulnerable_definition="getArchivesVersions",
        occurrence_id="demo-ssrf",
        occurrence_name="Server-side request forgery (SSRF)",
        severity="high",
    )

    print("--- Receipt preview ---")
    print(render_receipt(receipt))
    print()

    actions = GitLabActions("https://gitlab.com", token, project_id)
    result = actions.handle(receipt, mr_iid=None)

    print(f"Result: {result}")
    if result.get("work_item"):
        wi = result["work_item"]
        print(f"Work item created: {wi.get('web_url') or wi.get('id')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
