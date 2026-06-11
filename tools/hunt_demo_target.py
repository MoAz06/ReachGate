"""Hunt the live Orbit graph for a real demo target.

Looks for a security finding whose location.file ALSO exists as an indexed File
node, meaning that project has both source code and a finding in the same file,
which is what a reachability walk needs.

Usage (PowerShell):
    $env:GITLAB_TOKEN = "glpat-xxxxx"
    python tools/hunt_demo_target.py 2>&1 | clip
"""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from reachgate.graph_walker import extract_file_from_location  # noqa: E402
from reachgate.orbit_client import OrbitClient  # noqa: E402


def main() -> int:
    token = os.environ.get("GITLAB_TOKEN")
    if not token:
        print("Set $env:GITLAB_TOKEN first.")
        return 1

    client = OrbitClient("https://gitlab.com", token)

    print("Fetching vulnerability occurrences...")
    occs = client.get_vulnerability_occurrences(limit=100)
    print(f"got {len(occs)} occurrences\n")

    matches = []
    sast_like = []
    for occ in occs:
        loc_raw = occ.get("location", "")
        # Skip dependency-scan findings (lockfiles); we want SAST-style file+line.
        if '"dependency"' in loc_raw:
            continue
        vuln_file = extract_file_from_location(loc_raw)
        if not vuln_file:
            continue
        sast_like.append((occ, vuln_file))

    print(f"{len(sast_like)} SAST-style findings with a file path\n")

    for occ, vuln_file in sast_like:
        file_node = client.get_file_by_path(vuln_file)
        if file_node:
            defs = client.get_definitions_for_file(vuln_file)
            matches.append({
                "finding": occ.get("name"),
                "severity": occ.get("severity"),
                "file": vuln_file,
                "file_node_id": file_node.get("id"),
                "definitions": len(defs),
            })
            print("=== MATCH ===")
            print(json.dumps(matches[-1], indent=2))

    print(f"\n\nTOTAL MATCHES (finding file is also an indexed File node): {len(matches)}")
    if not matches:
        print("No finding's file is indexed as source. Demo needs our own pushed+indexed app.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
