"""Fix verification: a derived evidence layer over two receipt artifacts.

ReachGate's engine emits *receipts* — one per finding, each carrying a verdict,
the graph path, a reachability certificate, and a stable fingerprint (see
``certificate.py``). This module never re-decides anything and never calls
GitLab or Orbit. It consumes two already-captured receipt artifacts — a
BEFORE and an AFTER run — and proves, deterministically, whether reachability
for each finding was *removed*, *introduced*, left *unchanged*, or is simply
*incomparable*.

It is intentionally conservative. The whole point of ReachGate is that missing
evidence is never dressed up as safe, so this layer inherits the same rule:

  * ``reachability_removed`` (a real, provable fix) is only claimed when the
    AFTER receipt is an *exhaustive* NOT_REACHABLE under the *same* policy.
  * UNKNOWN never means fixed.
  * A different policy version is never a fix or a regression — it is
    incomparable, because the two runs did not measure the same thing.
  * If finding identity cannot be matched, it is incomparable, not fixed.

Standard library only. No network, no token, no engine semantics changes.
"""

from __future__ import annotations

import json
from typing import Any

# Verdict labels (mirror the engine's; we only read them, never produce them).
REACHABLE = "REACHABLE"
NOT_REACHABLE = "NOT_REACHABLE"
UNKNOWN = "UNKNOWN"

# Fix-proof classifications.
REACHABILITY_REMOVED = "reachability_removed"
REACHABILITY_INTRODUCED = "reachability_introduced"
UNCHANGED = "unchanged"
INCOMPARABLE = "incomparable"

SCHEMA_VERSION = "1.0"


class FixProofError(Exception):
    """A user-facing problem with an input artifact (missing / invalid JSON)."""


def _load(path: str) -> dict[str, Any]:
    """Read and decode a receipt artifact. Raises FixProofError on any problem."""
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        raise FixProofError(f"file not found: {path}")
    except IsADirectoryError:
        raise FixProofError(f"not a file: {path}")
    except json.JSONDecodeError as exc:
        raise FixProofError(f"invalid JSON in {path}: {exc}")
    if not isinstance(data, dict):
        raise FixProofError(
            f"{path}: expected a receipt object with a 'findings' list"
        )
    return data


def _policy_version(artifact: dict[str, Any]) -> str | None:
    """Policy version recorded at the artifact's top level, if any."""
    policy = artifact.get("policy")
    if isinstance(policy, dict):
        version = policy.get("version")
        if isinstance(version, str):
            return version
    return None


def _finding_policy_version(finding: dict[str, Any]) -> str | None:
    """Policy version recorded inside a finding's certificate, if any."""
    cert = finding.get("certificate")
    if isinstance(cert, dict):
        version = cert.get("policy_version")
        if isinstance(version, str):
            return version
    return None


def _index_by_identity(artifact: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Index findings by their stable identity (occurrence_id).

    We deliberately key on ``occurrence_id``, NOT the receipt fingerprint: the
    fingerprint folds in the verdict and the path, so a finding that was fixed
    fingerprints differently before and after — exactly the case we must still
    match to prove the fix. Identity is what stays stable across a fix.

    A finding with no usable identity is excluded here and handled separately
    so it can be reported as incomparable rather than silently dropped.
    """
    index: dict[str, dict[str, Any]] = {}
    for finding in artifact.get("findings") or []:
        if not isinstance(finding, dict):
            continue
        occ = finding.get("occurrence_id")
        if isinstance(occ, str) and occ:
            index[occ] = finding
    return index


def _identity_ambiguous(artifact: dict[str, Any]) -> bool:
    """True when two findings share one occurrence_id, or any lack identity."""
    seen: set[str] = set()
    for finding in artifact.get("findings") or []:
        if not isinstance(finding, dict):
            continue
        occ = finding.get("occurrence_id")
        if not (isinstance(occ, str) and occ):
            return True
        if occ in seen:
            return True
        seen.add(occ)
    return False


def is_exhaustive_not_reachable(finding: dict[str, Any]) -> bool:
    """A NOT_REACHABLE backed by a genuinely exhaustive search.

    Mirrors the engine/verifier definition exactly (see verify_proof.py): the
    frontier was exhausted, no search bound was hit, and there were zero API
    errors. Anything less is NOT an exhaustive negative and must never be
    treated as a fix.
    """
    if finding.get("verdict") != NOT_REACHABLE:
        return False
    cert = finding.get("certificate")
    if not isinstance(cert, dict):
        return False
    return (
        cert.get("frontier_exhausted") is True
        and cert.get("max_hops_hit") is False
        and cert.get("visited_cap_hit") is False
        and cert.get("timeout_hit") is False
        and cert.get("api_errors") == 0
    )


def _evidence_equivalent(before: dict[str, Any], after: dict[str, Any]) -> bool:
    """Whether two receipts describe the same verdict and the same evidence.

    Used to distinguish a true ``unchanged`` from a subtle change. The receipt
    fingerprint already folds finding identity, verdict, path, policy version,
    and the declared attack surface into one stable hash — so equal fingerprints
    mean equivalent evidence. When fingerprints are absent we fall back to
    comparing the verdict, basis, and path directly.
    """
    bfp, afp = before.get("fingerprint"), after.get("fingerprint")
    if bfp is not None and afp is not None:
        return bfp == afp
    return (
        before.get("verdict") == after.get("verdict")
        and before.get("verdict_basis") == after.get("verdict_basis")
        and before.get("path") == after.get("path")
    )


def _classify_pair(
    before: dict[str, Any] | None,
    after: dict[str, Any] | None,
) -> tuple[str, str]:
    """Classify one matched finding. Returns (classification, reason).

    ``before``/``after`` may be None when the finding is absent on that side.
    Policy-version comparison is handled by the caller; here we assume the
    versions are already known to match (or that absence is intentional).
    """
    after_verdict = after.get("verdict") if after else None
    before_verdict = before.get("verdict") if before else None

    # An AFTER that is UNKNOWN can never be a fix: missing evidence is not safe.
    if after is not None and after_verdict == UNKNOWN:
        return INCOMPARABLE, "after verdict is UNKNOWN; insufficient evidence to prove a fix"

    # reachability_removed: REACHABLE -> exhaustive NOT_REACHABLE.
    if before_verdict == REACHABLE:
        if after_verdict == NOT_REACHABLE:
            if is_exhaustive_not_reachable(after):
                return (
                    REACHABILITY_REMOVED,
                    "before REACHABLE; after NOT_REACHABLE with an exhaustive "
                    "search (frontier exhausted, no bounds hit, 0 API errors)",
                )
            return (
                INCOMPARABLE,
                "after NOT_REACHABLE is not exhaustive (a bound was hit, the "
                "frontier was not exhausted, or there were API errors); not a "
                "proven fix",
            )
        if after_verdict == REACHABLE:
            if _evidence_equivalent(before, after):
                return UNCHANGED, "still REACHABLE with equivalent evidence"
            return UNCHANGED, "still REACHABLE"
        if after is None:
            return (
                INCOMPARABLE,
                "before REACHABLE but the finding is absent in the after "
                "artifact; cannot prove it was fixed vs. merely dropped",
            )

    # reachability_introduced: exhaustive NOT_REACHABLE (or absent) -> REACHABLE.
    if after_verdict == REACHABLE:
        if before is None:
            return (
                REACHABILITY_INTRODUCED,
                "finding absent before; after is REACHABLE",
            )
        if before_verdict == NOT_REACHABLE and is_exhaustive_not_reachable(before):
            return (
                REACHABILITY_INTRODUCED,
                "before exhaustively NOT_REACHABLE; after is REACHABLE",
            )
        if before_verdict == NOT_REACHABLE:
            # Before was a weak negative, so we cannot call this a regression
            # against a proven-safe baseline.
            return (
                INCOMPARABLE,
                "after REACHABLE but the before NOT_REACHABLE was not "
                "exhaustive; no proven-safe baseline to regress from",
            )
        if before_verdict == UNKNOWN:
            return (
                INCOMPARABLE,
                "after REACHABLE but before was UNKNOWN; no proven-safe "
                "baseline to regress from",
            )

    # unchanged: equivalent verdict + evidence on both sides.
    if before is not None and after is not None and _evidence_equivalent(before, after):
        return UNCHANGED, f"verdict and evidence unchanged ({after_verdict})"

    # Same non-reachable verdict but evidence differs, or any other combination
    # we have not promoted to removed/introduced/unchanged: be conservative.
    if before is not None and after is not None and before_verdict == after_verdict:
        return UNCHANGED, f"verdict unchanged ({after_verdict})"

    return (
        INCOMPARABLE,
        "verdict transition does not prove a fix or a regression "
        f"(before={before_verdict}, after={after_verdict})",
    )


def compare(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    """Compare two receipt artifacts and return a deterministic fix-proof.

    The result is a plain dict, safe to serialize byte-stably. Findings are
    reported in sorted occurrence_id order. Policy mismatch and ambiguous
    identity short-circuit every finding to ``incomparable`` with the reason,
    because under those conditions no per-finding claim can be trusted.
    """
    before_policy = _policy_version(before)
    after_policy = _policy_version(after)

    before_index = _index_by_identity(before)
    after_index = _index_by_identity(after)
    all_ids = sorted(set(before_index) | set(after_index))

    # Global short-circuits: nothing below can be trusted under these.
    policy_mismatch = (
        before_policy is not None
        and after_policy is not None
        and before_policy != after_policy
    )
    ambiguous = _identity_ambiguous(before) or _identity_ambiguous(after)

    results: list[dict[str, Any]] = []
    for occ in all_ids:
        b = before_index.get(occ)
        a = after_index.get(occ)

        if policy_mismatch:
            classification, reason = (
                INCOMPARABLE,
                f"policy version differs (before={before_policy}, "
                f"after={after_policy}); the two runs did not measure the same "
                "thing",
            )
        elif ambiguous:
            classification, reason = (
                INCOMPARABLE,
                "finding identity is ambiguous in one of the artifacts "
                "(duplicate or missing occurrence_id); cannot match reliably",
            )
        else:
            # Per-finding policy guard: even when top-level policy matches, a
            # finding whose certificate policy_version disagrees is incomparable.
            b_fpv = _finding_policy_version(b) if b else None
            a_fpv = _finding_policy_version(a) if a else None
            if b_fpv is not None and a_fpv is not None and b_fpv != a_fpv:
                classification, reason = (
                    INCOMPARABLE,
                    f"per-finding policy version differs (before={b_fpv}, "
                    f"after={a_fpv})",
                )
            else:
                classification, reason = _classify_pair(b, a)

        results.append(
            {
                "occurrence_id": occ,
                "classification": classification,
                "reason": reason,
                "before_verdict": b.get("verdict") if b else None,
                "after_verdict": a.get("verdict") if a else None,
                "before_fingerprint": b.get("fingerprint") if b else None,
                "after_fingerprint": a.get("fingerprint") if a else None,
            }
        )

    summary = {
        REACHABILITY_REMOVED: 0,
        REACHABILITY_INTRODUCED: 0,
        UNCHANGED: 0,
        INCOMPARABLE: 0,
    }
    for r in results:
        summary[r["classification"]] = summary.get(r["classification"], 0) + 1

    return {
        "schema_version": SCHEMA_VERSION,
        "policy": {
            "before": before_policy,
            "after": after_policy,
            "match": (before_policy == after_policy)
            if (before_policy is not None and after_policy is not None)
            else None,
        },
        "summary": summary,
        "findings": results,
    }


def render_json(proof: dict[str, Any]) -> str:
    """Byte-stable JSON: sorted keys, compact-but-readable, trailing newline."""
    return json.dumps(proof, sort_keys=True, indent=2, ensure_ascii=False) + "\n"


_SYMBOL = {
    REACHABILITY_REMOVED: "FIXED   ",
    REACHABILITY_INTRODUCED: "REGRESS ",
    UNCHANGED: "SAME    ",
    INCOMPARABLE: "N/A     ",
}


def render_text(proof: dict[str, Any]) -> str:
    """Human-readable, deterministic text report."""
    lines: list[str] = []
    summary = proof["summary"]
    counts = " ".join(
        f"{key}={summary.get(key, 0)}"
        for key in (
            REACHABILITY_REMOVED,
            REACHABILITY_INTRODUCED,
            UNCHANGED,
            INCOMPARABLE,
        )
    )
    lines.append(f"ReachGate fix-proof: {counts}")

    policy = proof["policy"]
    if policy["match"] is False:
        lines.append(
            f"  ! policy version differs (before={policy['before']}, "
            f"after={policy['after']}): all findings are incomparable"
        )
    else:
        lines.append(f"  policy version: {policy['after'] or policy['before'] or 'n/a'}")

    for r in proof["findings"]:
        sym = _SYMBOL.get(r["classification"], "        ")
        lines.append(
            f"  {sym} {r['occurrence_id']}  "
            f"{r['before_verdict']} -> {r['after_verdict']}"
        )
        lines.append(f"      {r['classification']}: {r['reason']}")

    lines.append(
        "  note: reachability_removed requires an exhaustive after NOT_REACHABLE "
        "under the same policy; UNKNOWN is never a fix."
    )
    return "\n".join(lines) + "\n"


def fixcheck(before_path: str, after_path: str) -> dict[str, Any]:
    """Load two receipt artifacts from disk and return the fix-proof dict."""
    before = _load(before_path)
    after = _load(after_path)
    return compare(before, after)
