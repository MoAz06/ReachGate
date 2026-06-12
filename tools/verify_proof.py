"""Verify ReachGate's captured proof artifacts.

This checks the two receipt artifacts committed under docs/proof/ -- the
Phase 1 run (MR !2) and the Phase 2 rerun (MR !3) -- and confirms they say
exactly what the merge-request receipts claim:

  * both are schema 1.0 with two findings;
  * one REACHABLE (basis path_found) and one NOT_REACHABLE
    (basis no_path_search_exhaustive);
  * the NOT_REACHABLE verdict is an *exhaustive* negative -- frontier
    exhausted, no search bound hit, zero API errors;
  * the same finding fingerprints identically across MR !2 and MR !3, which
    is what makes the MR triage idempotent.

It verifies the CAPTURED artifacts, offline. It does not call GitLab. To see
the same thing live, rerun the pipelines linked from docs/JUDGE_REPLAY.md.

Standard library only. No network, no token, no dependencies.
Exit 0 if every check passes, 1 otherwise.
"""

from __future__ import annotations

import json
import os
import sys

PROOF_DIR = os.path.join(os.path.dirname(__file__), "..", "docs", "proof")
MR2 = os.path.join(PROOF_DIR, "mr2-reachgate-receipts.json")
MR3 = os.path.join(PROOF_DIR, "mr3-reachgate-receipts-rerun.json")

EXPECTED_BASIS = {
    "REACHABLE": "path_found",
    "NOT_REACHABLE": "no_path_search_exhaustive",
}


class Checker:
    def __init__(self) -> None:
        self.failures: list[str] = []

    def check(self, label: str, ok: bool) -> None:
        if not ok:
            self.failures.append(label)

    def require(self, label: str, ok: bool) -> bool:
        # Like check(), but signals callers to stop drilling deeper.
        self.check(label, ok)
        return ok


def _load(path: str, c: Checker) -> dict | None:
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        c.check(f"{os.path.basename(path)}: file present", False)
    except json.JSONDecodeError as e:
        c.check(f"{os.path.basename(path)}: valid JSON ({e})", False)
    return None


def _by_occurrence(artifact: dict) -> dict[str, dict]:
    return {f.get("occurrence_id"): f for f in artifact.get("findings", [])}


def verify_artifact(name: str, artifact: dict, c: Checker) -> None:
    c.check(f"{name}: schema_version == 1.0",
            artifact.get("schema_version") == "1.0")

    findings = artifact.get("findings", [])
    if not c.require(f"{name}: exactly 2 findings", len(findings) == 2):
        return

    verdicts = {f.get("verdict") for f in findings}
    c.check(f"{name}: verdicts are REACHABLE + NOT_REACHABLE",
            verdicts == {"REACHABLE", "NOT_REACHABLE"})

    for f in findings:
        verdict = f.get("verdict")
        tag = f"{name}/{f.get('occurrence_id')}"
        c.check(f"{tag}: verdict_basis == {EXPECTED_BASIS.get(verdict)!r}",
                f.get("verdict_basis") == EXPECTED_BASIS.get(verdict))

        cert = f.get("certificate") or {}
        c.check(f"{tag}: api_errors == 0", cert.get("api_errors") == 0)
        c.check(f"{tag}: no search bound hit",
                cert.get("max_hops_hit") is False
                and cert.get("visited_cap_hit") is False
                and cert.get("timeout_hit") is False)
        if verdict == "NOT_REACHABLE":
            c.check(f"{tag}: NOT_REACHABLE is exhaustive (frontier_exhausted)",
                    cert.get("frontier_exhausted") is True)


def verify_fingerprints_match(mr2: dict, mr3: dict, c: Checker) -> None:
    a, b = _by_occurrence(mr2), _by_occurrence(mr3)
    c.check("MR2/MR3 cover the same findings", set(a) == set(b))
    for occ in sorted(set(a) & set(b)):
        c.check(f"{occ}: fingerprint identical across MR2 and MR3",
                a[occ].get("fingerprint") == b[occ].get("fingerprint"))


def main() -> int:
    c = Checker()
    mr2 = _load(MR2, c)
    mr3 = _load(MR3, c)

    if mr2 is not None:
        verify_artifact("MR2", mr2, c)
    if mr3 is not None:
        verify_artifact("MR3", mr3, c)
    if mr2 is not None and mr3 is not None:
        verify_fingerprints_match(mr2, mr3, c)

    if c.failures:
        print("ReachGate proof FAILED")
        for f in c.failures:
            print(f"  x {f}")
        return 1

    ssrf = _by_occurrence(mr2)["demo-ssrf"]["fingerprint"]
    pt = _by_occurrence(mr2)["demo-pathtraversal"]["fingerprint"]
    print("ReachGate proof verified")
    print("- MR2: REACHABLE + NOT_REACHABLE receipts valid")
    print(f"- MR3: same fingerprints on rerun ({ssrf}, {pt})")
    print("- NOT_REACHABLE is exhaustive: frontier exhausted, "
          "no bounds hit, API errors 0")
    print("- verifies captured artifacts offline; rerun the linked MRs "
          "for live proof")
    return 0


if __name__ == "__main__":
    sys.exit(main())
