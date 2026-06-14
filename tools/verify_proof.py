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
UNKNOWN = os.path.join(PROOF_DIR, "unknown-reachgate-receipt.json")
VEX = os.path.join(PROOF_DIR, "reachgate.openvex.json")
SARIF = os.path.join(PROOF_DIR, "reachgate.sarif.json")

# Import the VEX mapping so the cross-check uses the exact same logic that
# produced the document -- no second, drifting copy of the rules.
try:
    from tools import export_vex  # imported as a package (tests, -m)
except ImportError:  # run directly: python tools/verify_proof.py
    import export_vex

# SARIF cross-check reuses the exporter's own integrity rules so there is no
# second, drifting copy of the verdict->level mapping or honesty invariants.
try:
    from tools import export_sarif  # imported as a package (tests, -m)
except ImportError:  # run directly: python tools/verify_proof.py
    import export_sarif

UNKNOWN_BASIS = "insufficient_evidence:no_definitions_indexed"

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


def verify_unknown(artifact: dict, c: Checker) -> None:
    """The UNKNOWN artifact proves the third verdict is real and honest: a
    finding Orbit has indexed but with no definitions to walk to produces
    UNKNOWN with a reason -- never a NOT_REACHABLE dressed up as proof."""
    name = "UNKNOWN"
    c.check(f"{name}: schema_version == 1.0",
            artifact.get("schema_version") == "1.0")

    findings = artifact.get("findings", [])
    if not c.require(f"{name}: exactly 1 finding", len(findings) == 1):
        return
    f = findings[0]
    tag = f"{name}/{f.get('occurrence_id')}"

    c.check(f"{tag}: verdict == UNKNOWN", f.get("verdict") == "UNKNOWN")
    c.check(f"{tag}: verdict_basis == {UNKNOWN_BASIS!r}",
            f.get("verdict_basis") == UNKNOWN_BASIS)

    cert = f.get("certificate") or {}
    c.check(f"{tag}: target_definitions_found == 0",
            cert.get("target_definitions_found") == 0)
    c.check(f"{tag}: api_errors == 0", cert.get("api_errors") == 0)
    c.check(f"{tag}: no search bound hit",
            cert.get("max_hops_hit") is False
            and cert.get("visited_cap_hit") is False
            and cert.get("timeout_hit") is False)
    # UNKNOWN is NOT an exhaustive negative: the search never ran a frontier
    # to exhaustion, so frontier_exhausted must be false. This is what keeps
    # UNKNOWN distinct from NOT_REACHABLE.
    c.check(f"{tag}: not exhaustive (frontier_exhausted == false)",
            cert.get("frontier_exhausted") is False)


def verify_vex(vex: dict, findings: list[dict], c: Checker) -> None:
    """Cross-check the exported OpenVEX against the receipts it came from, so
    the VEX claim is falsifiable too: every status must match what the
    receipts justify, and nothing non-exhaustive may read as not_affected."""
    name = "VEX"
    c.check(f"{name}: @context is OpenVEX",
            vex.get("@context") == export_vex.OPENVEX_CONTEXT)
    statements = vex.get("statements") or []
    c.check(f"{name}: has statements", len(statements) > 0)
    for problem in export_vex.crosscheck(vex, findings):
        c.check(f"{name}: {problem}", False)


def verify_sarif(sarif: dict, findings: list[dict], c: Checker) -> None:
    """Cross-check the exported SARIF against the receipts it came from, so the
    SARIF view is falsifiable too. Reuses the exporter's own crosscheck() (the
    single source of truth for the verdict->level mapping and the honesty
    invariants), then re-asserts the load-bearing claims independently:

      * every receipt fingerprint appears in the SARIF;
      * each verdict maps to its SARIF level (error/note/warning);
      * UNKNOWN stays an evidence gap, never presented as safe;
      * NOT_REACHABLE keeps the configured-bounds wording, never "safe".
    """
    name = "SARIF"
    c.check(f"{name}: version == 2.1.0",
            sarif.get("version") == export_sarif.SARIF_VERSION)
    runs = sarif.get("runs") or []
    if not c.require(f"{name}: has a run with results",
                     bool(runs) and bool(runs[0].get("results"))):
        return
    results = runs[0]["results"]

    # 1) Reuse the exporter's own integrity check: one voice, no drift.
    for problem in export_sarif.crosscheck(sarif, findings):
        c.check(f"{name}: {problem}", False)

    # 2) Independent re-assertion of the invariants that matter most, stated
    #    here rather than delegated, so the verifier still catches a regression
    #    even if crosscheck() were ever weakened.
    by_fp = {
        (r.get("partialFingerprints") or {}).get("reachgateFingerprint"): r
        for r in results
    }
    for f in findings:
        fp = f.get("fingerprint")
        verdict = f.get("verdict")
        tag = f"{name}/{fp}"
        r = by_fp.get(fp)
        if not c.require(f"{tag}: fingerprint present in SARIF", r is not None):
            continue
        c.check(f"{tag}: verdict {verdict} -> level "
                f"{export_sarif._LEVEL.get(verdict)!r}",
                r.get("level") == export_sarif._LEVEL.get(verdict))
        text = (r.get("message") or {}).get("text", "")
        low = text.lower()
        if verdict == "UNKNOWN":
            c.check(f"{tag}: UNKNOWN framed as evidence gap",
                    "evidence gap" in text)
            c.check(f"{tag}: UNKNOWN never presented as safe",
                    "is safe" not in low and "not_affected" not in low)
        if verdict == "NOT_REACHABLE":
            c.check(f"{tag}: NOT_REACHABLE keeps configured-bounds wording",
                    export_sarif.NOT_REACHABLE_WORDING in text)
            c.check(f"{tag}: NOT_REACHABLE never claims global safety",
                    "is safe" not in low)


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
    unknown = _load(UNKNOWN, c)

    if mr2 is not None:
        verify_artifact("MR2", mr2, c)
    if mr3 is not None:
        verify_artifact("MR3", mr3, c)
    if mr2 is not None and mr3 is not None:
        verify_fingerprints_match(mr2, mr3, c)
    if unknown is not None:
        verify_unknown(unknown, c)

    # VEX cross-check is optional: only run when the document is present, so a
    # checkout without it still verifies the receipts. When present it must be
    # consistent with the same MR !2 + UNKNOWN receipts it is built from.
    vex = _load(VEX, c) if os.path.exists(VEX) else None
    vex_checked = False
    if vex is not None and mr2 is not None and unknown is not None:
        findings = mr2.get("findings", []) + unknown.get("findings", [])
        verify_vex(vex, findings, c)
        vex_checked = True

    # SARIF cross-check is optional too: soft-skip when the document is absent
    # so a checkout without it still verifies the receipts. When present it
    # must be consistent with the same MR !2 + UNKNOWN receipts it is built
    # from (same sources as export_sarif.DEFAULT_SOURCES).
    sarif = _load(SARIF, c) if os.path.exists(SARIF) else None
    sarif_checked = False
    if sarif is not None and mr2 is not None and unknown is not None:
        findings = mr2.get("findings", []) + unknown.get("findings", [])
        verify_sarif(sarif, findings, c)
        sarif_checked = True

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
    print("- UNKNOWN is honest: a real indexed file with no definitions "
          "yields insufficient_evidence, not fake-green")
    if vex_checked:
        print("- OpenVEX export matches the receipts: affected / not_affected "
              "(exhaustive only) / under_investigation, cross-checked")
    if sarif_checked:
        print("- SARIF export matches the receipts: error / note / warning "
              "levels, fingerprints, UNKNOWN evidence gap, NOT_REACHABLE "
              "within configured bounds, cross-checked")
    print("- verifies captured artifacts offline; rerun the linked MRs "
          "for live proof")
    return 0


if __name__ == "__main__":
    sys.exit(main())
