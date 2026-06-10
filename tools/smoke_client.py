"""Live smoke test for the rewritten OrbitClient against the real API.

Exercises every client method end-to-end on a known-indexed file.

Usage (PowerShell):
    $env:GITLAB_TOKEN = "glpat-xxxxx"
    python scripts/smoke_client.py 2>&1 | clip
"""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from reachgate.orbit_client import OrbitClient  # noqa: E402

KNOWN_FILE = "src/lib/utils.js"


def main() -> int:
    token = os.environ.get("GITLAB_TOKEN")
    if not token:
        print("Set $env:GITLAB_TOKEN first.")
        return 1

    client = OrbitClient("https://gitlab.com", token)

    print("== status ==")
    print(client.get_status().get("status"))

    print("\n== get_file_by_path ==")
    f = client.get_file_by_path(KNOWN_FILE)
    print(json.dumps(f, indent=2))
    if not f:
        print("File not found; cannot continue neighbor test.")
        return 0

    print("\n== get_definitions_for_file ==")
    defs = client.get_definitions_for_file(KNOWN_FILE)
    print(json.dumps(defs, indent=2)[:1500])

    print("\n== get_code_neighbors (THE critical one: id filter + neighbors) ==")
    neighbors = client.get_code_neighbors("File", f["id"])
    print(f"count: {len(neighbors)}")
    print(json.dumps(neighbors, indent=2)[:2000])

    print("\n== get_vulnerability_occurrences (high/critical) ==")
    occs = client.get_vulnerability_occurrences(severity=["high", "critical"], limit=3)
    print(json.dumps(occs, indent=2)[:1500])

    return 0


if __name__ == "__main__":
    sys.exit(main())
