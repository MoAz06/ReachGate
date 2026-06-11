"""End-to-end ReachGate demo against the live Orbit graph.

Discovers who imports a vulnerable file (the upstream entry points), then runs
the real engine (config -> BoundedBFS walk -> policy -> receipt) on two real
findings to show the flip: one reachable, one not.

Every Orbit call is timed and printed so the run is observable: the dominant
cost is HTTP latency (one neighbors query per visited node).

Usage (PowerShell):
    $env:GITLAB_TOKEN = "glpat-xxxxx"
    python tools/demo_e2e.py

Optional:
    $env:REACHGATE_DIAGNOSE = "1"   # also check ImportedSymbol -> Definition resolution
"""

from __future__ import annotations

import json
import os
import sys
import time

# Windows consoles default to cp1252; the receipt contains emoji.
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from reachgate.actions import render_receipt  # noqa: E402
from reachgate.config import PolicyConfig, ReachGateConfig  # noqa: E402
from reachgate.graph_walker import GraphWalker  # noqa: E402
from reachgate.orbit_client import OrbitClient  # noqa: E402
from reachgate.path_strategy import BoundedBFS  # noqa: E402
from reachgate.policy_engine import evaluate  # noqa: E402

REACHABLE_FINDING = {
    "uuid": "demo-ssrf",
    "name": "Server-side request forgery (SSRF)",
    "severity": "high",
    "location": json.dumps({"file": "content/frontend/services/fetch_versions.js"}),
}
UNREACHABLE_FINDING = {
    "uuid": "demo-pathtraversal",
    "name": "Improper limitation of a pathname ('Path Traversal')",
    "severity": "medium",
    "location": json.dumps({"file": "scripts/create_issues.js"}),
}

# Keep the live demo fast: each visited node costs one HTTPS round-trip.
# MAX_HOPS=6: preflight showed both demo walks exhaust their frontier by
# hop 5, so no-path means exhaustive NOT_REACHABLE rather than UNKNOWN.
MAX_ENTRYPOINTS = 2
MAX_VISITED = 40
MAX_SECONDS_PER_WALK = 120  # per-walk; live runs measured ~30s/walk, 2x margin
MAX_HOPS = 6


class TimedOrbitClient(OrbitClient):
    """OrbitClient that prints one line per API call with elapsed time."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.calls = 0

    def query(self, inner):
        t0 = time.perf_counter()
        out = super().query(inner)
        self.calls += 1
        dt = time.perf_counter() - t0
        qt = inner.get("query_type", "?")
        rows = out.get("row_count", "?")
        print(f"  [orbit #{self.calls:>3}] {qt:<10} {dt:5.2f}s  rows={rows}",
              flush=True)
        return out


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
    paths = sorted({n.get("file_path") for n in nodes if n.get("file_path")})
    return paths


def diagnose_resolution(client, importer_file, needle):
    """Check the one unconfirmed assumption: does an internal ImportedSymbol
    resolve to a Definition (cross-file edge) via the neighbors query?"""
    print(f"\n--- diagnostic: cross-file import resolution from {importer_file} ---")
    f = client.get_file_by_path(importer_file)
    if not f:
        print("  importer file not found as a File node")
        return
    neighbors = client.get_code_neighbors("File", f["id"])
    syms = [n for n in neighbors if n.get("type") == "ImportedSymbol"
            and needle in (n.get("import_path") or "")]
    print(f"  importer has {len(syms)} ImportedSymbol(s) referencing '{needle}'")
    for s in syms[:2]:
        resolved = client.get_code_neighbors("ImportedSymbol", s["id"])
        defs = [r for r in resolved if r.get("type") == "Definition"]
        print(f"    symbol {s.get('identifier_name')} ({s.get('import_path')}): "
              f"resolves to {len(defs)} Definition(s)")
        for d in defs[:2]:
            print(f"      -> {d.get('name')} in {d.get('file_path')}")


def run_finding(client, strategy, entrypoints, finding, label):
    print(f"\n{'#' * 70}\n# {label}\n{'#' * 70}")
    t0 = time.perf_counter()
    calls_before = client.calls
    config = ReachGateConfig(
        version="1",
        entrypoint_patterns=entrypoints,
        policy=PolicyConfig(min_hops=1, max_hops=MAX_HOPS),
    )
    walker = GraphWalker(client, config, strategy=strategy)
    result = walker.check_reachability(finding)
    receipt = evaluate(result, finding)
    print(render_receipt(receipt))
    print(f"[timing] {label.split(':')[0]}: {time.perf_counter() - t0:.1f}s, "
          f"{client.calls - calls_before} API calls", flush=True)


def main() -> int:
    token = os.environ.get("GITLAB_TOKEN")
    if not token:
        print("Set $env:GITLAB_TOKEN first.")
        return 1

    t_start = time.perf_counter()
    client = TimedOrbitClient("https://gitlab.com", token)

    print("Discovering importers of fetch_versions...")
    importers = discover_importers(client, "fetch_versions")
    print(json.dumps(importers, indent=2))

    if not importers:
        print("No importers found; falling back to the file itself as entry point.")
        importers = ["content/frontend/services/fetch_versions.js"]

    # Declared attack surface = files that import the vulnerable service.
    # Prefer real app code over specs, and cap hard: each BFS entry costs
    # up to MAX_VISITED sequential HTTPS round-trips.
    preferred = [p for p in importers
                 if "spec" not in p and "test" not in p
                 and p != "content/frontend/services/fetch_versions.js"]
    entrypoints = (preferred or importers)[:MAX_ENTRYPOINTS]
    print(f"\nUsing {len(entrypoints)} entry point(s): {entrypoints}")

    if os.environ.get("REACHGATE_DIAGNOSE"):
        diagnose_resolution(client, entrypoints[0], "fetch_versions")

    # One shared strategy: the neighbor cache carries over between findings,
    # so Finding B reuses everything Finding A already fetched.
    strategy = BoundedBFS(client, max_visited=MAX_VISITED,
                          max_seconds=MAX_SECONDS_PER_WALK)

    run_finding(client, strategy, entrypoints, REACHABLE_FINDING,
                "Finding A: SSRF in fetch_versions.js (expect REACHABLE)")
    run_finding(client, strategy, entrypoints, UNREACHABLE_FINDING,
                "Finding B: Path Traversal in scripts/create_issues.js (expect NOT_REACHABLE)")

    print(f"\n[timing] total: {time.perf_counter() - t_start:.1f}s, "
          f"{client.calls} API calls")
    return 0


if __name__ == "__main__":
    sys.exit(main())
