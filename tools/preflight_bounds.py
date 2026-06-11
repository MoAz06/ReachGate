"""Preflight: verify WHY each demo finding's BFS terminates.

Before trusting a NOT_REACHABLE verdict, we must know whether the walk
exhausts its frontier within the demo bounds (honest exhaustive negative)
or hits a cap (UNKNOWN under policy). Uses BoundedBFS.search() directly,
replicating the demo conditions: same entry-point discovery, same caps,
same shared cache.

Usage:
    $env:GITLAB_TOKEN = "glpat-xxxxx"
    python tools/preflight_bounds.py

Optional:
    $env:PREFLIGHT_MAX_HOPS = "8"
    $env:PREFLIGHT_MAX_VISITED = "60"
"""

from __future__ import annotations

import os
import sys
import time

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from reachgate.orbit_client import OrbitClient  # noqa: E402
from reachgate.path_strategy import BoundedBFS  # noqa: E402

MAX_ENTRYPOINTS = 2
MAX_VISITED = int(os.environ.get("PREFLIGHT_MAX_VISITED", 40))
MAX_SECONDS_PER_WALK = 120
MAX_HOPS = int(os.environ.get("PREFLIGHT_MAX_HOPS", 6))

FINDINGS = [
    ("Finding A (SSRF)", "content/frontend/services/fetch_versions.js"),
    ("Finding B (Path Traversal)", "scripts/create_issues.js"),
]


def discover_importers(client: OrbitClient, needle: str) -> list[str]:
    nodes = client.query_nodes({
        "query_type": "traversal",
        "node": {
            "id": "s", "entity": "ImportedSymbol",
            "columns": ["id", "identifier_name", "import_path", "file_path"],
            "filters": {"import_path": {"op": "contains", "value": needle}},
        },
        "limit": 50,
    })
    return sorted({n.get("file_path") for n in nodes if n.get("file_path")})


def main() -> int:
    token = os.environ.get("GITLAB_TOKEN")
    if not token:
        print("Set GITLAB_TOKEN first.")
        return 1

    client = OrbitClient("https://gitlab.com", token)

    importers = discover_importers(client, "fetch_versions")
    preferred = [p for p in importers
                 if "spec" not in p and "test" not in p
                 and p != "content/frontend/services/fetch_versions.js"]
    entrypoints = (preferred or importers)[:MAX_ENTRYPOINTS]
    print(f"entry points: {entrypoints}")
    print(f"bounds: max_hops={MAX_HOPS} max_visited={MAX_VISITED} "
          f"max_seconds={MAX_SECONDS_PER_WALK}\n")

    strategy = BoundedBFS(client, max_visited=MAX_VISITED,
                          max_seconds=MAX_SECONDS_PER_WALK)

    caps_hit = 0
    for label, vuln_file in FINDINGS:
        print(f"=== {label}: {vuln_file} ===")
        definitions = client.get_definitions_for_file(vuln_file)
        target_ids = {str(d["id"]) for d in definitions if d.get("id") is not None}
        print(f"  definitions indexed: {len(target_ids)}")
        if not target_ids:
            print("  -> UNKNOWN (no_definitions_indexed)\n")
            continue
        for ep_path in entrypoints:
            f = client.get_file_by_path(ep_path)
            if not f:
                print(f"  entry {ep_path}: File node not found")
                continue
            t0 = time.perf_counter()
            out = strategy.search(f, target_ids, MAX_HOPS)
            dt = time.perf_counter() - t0
            caps_hit += out.cap_hit
            print(f"  entry {ep_path}:")
            print(f"    termination={out.termination}  nodes_visited={out.nodes_visited}"
                  f"  hops_used={out.hops_used}  api_errors={out.api_errors}  {dt:.1f}s")
            if out.path:
                print(f"    path: {' -> '.join(n.label for n in out.path)}")
        print()

    if caps_hit:
        print(f"RESULT: {caps_hit} walk(s) hit a cap -> would be UNKNOWN. "
              "Raise bounds before relying on NOT_REACHABLE in the demo.")
        return 2
    print("RESULT: no caps hit. No-path walks are exhaustive "
          "(honest NOT_REACHABLE).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
