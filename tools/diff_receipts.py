"""Diff two ReachGate receipt artifacts.

Given an OLD and a NEW `reachgate-receipts.json`, this reports how each
finding changed between the two runs. It matches findings by their stable
`occurrence_id` and compares the receipt `fingerprint` — the same fingerprint
that makes MR triage idempotent (see src/reachgate/certificate.py). Two runs
of the same finding under the same policy fingerprint identically, so this
turns the receipts into a security regression review:

  * UNCHANGED  — same occurrence_id, same fingerprint
  * CHANGED    — same occurrence_id, different fingerprint
  * NEW        — only in the new artifact
  * REMOVED    — only in the old artifact

It makes NO assumptions about how many findings an artifact has or which
verdicts appear; it diffs whatever is there.

With `--fail-on-new-reachable` the tool exits 1 only when a finding that is
now REACHABLE was not REACHABLE before — i.e. a NEW finding with verdict
REACHABLE, or a CHANGED finding whose new verdict is REACHABLE. UNKNOWN and
NOT_REACHABLE never count as reachable. Without the flag it always exits 0.

Standard library only. No network, no token, no dependencies.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

REACHABLE = "REACHABLE"


class InputError(Exception):
    """A user-facing problem with an input artifact (missing / invalid JSON)."""


def _load(path: str) -> dict[str, Any]:
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        raise InputError(f"file not found: {path}")
    except IsADirectoryError:
        raise InputError(f"not a file: {path}")
    except json.JSONDecodeError as e:
        raise InputError(f"invalid JSON in {path}: {e}")


def _by_occurrence(artifact: dict[str, Any]) -> dict[str, dict]:
    index: dict[str, dict] = {}
    for finding in artifact.get("findings", []):
        occ = finding.get("occurrence_id")
        if occ is not None:
            index[occ] = finding
    return index


def _triple(finding: dict) -> tuple[str | None, str | None, str | None]:
    return (
        finding.get("verdict"),
        finding.get("verdict_basis"),
        finding.get("fingerprint"),
    )


def classify(old: dict[str, dict], new: dict[str, dict]) -> dict[str, list[str]]:
    """Bucket occurrence_ids into UNCHANGED / CHANGED / NEW / REMOVED."""
    old_ids, new_ids = set(old), set(new)
    both = old_ids & new_ids

    unchanged, changed = [], []
    for occ in both:
        if old[occ].get("fingerprint") == new[occ].get("fingerprint"):
            unchanged.append(occ)
        else:
            changed.append(occ)

    return {
        "UNCHANGED": sorted(unchanged),
        "CHANGED": sorted(changed),
        "NEW": sorted(new_ids - old_ids),
        "REMOVED": sorted(old_ids - new_ids),
    }


def gate_failures(
    buckets: dict[str, list[str]],
    old: dict[str, dict],
    new: dict[str, dict],
) -> list[str]:
    """occurrence_ids that became REACHABLE between old and new.

    A NEW finding that is REACHABLE, or a CHANGED finding whose NEW verdict is
    REACHABLE. UNKNOWN and NOT_REACHABLE never count.
    """
    failures = []
    for occ in buckets["NEW"]:
        if new[occ].get("verdict") == REACHABLE:
            failures.append(occ)
    for occ in buckets["CHANGED"]:
        if new[occ].get("verdict") == REACHABLE:
            failures.append(occ)
    return sorted(failures)


def _fmt(finding: dict) -> str:
    verdict, basis, fp = _triple(finding)
    return f"verdict={verdict} basis={basis} fingerprint={fp}"


def render(
    buckets: dict[str, list[str]],
    old: dict[str, dict],
    new: dict[str, dict],
) -> list[str]:
    lines = []
    counts = " ".join(f"{k}={len(v)}" for k, v in buckets.items())
    lines.append(f"ReachGate receipt diff: {counts}")

    for occ in buckets["CHANGED"]:
        ov, ob, ofp = _triple(old[occ])
        nv, nb, nfp = _triple(new[occ])
        lines.append(f"  ~ CHANGED  {occ}")
        lines.append(f"      verdict={ov} basis={ob} fingerprint={ofp}")
        lines.append(f"      -> verdict={nv} basis={nb} fingerprint={nfp}")
    for occ in buckets["NEW"]:
        lines.append(f"  + NEW      {occ}  {_fmt(new[occ])}")
    for occ in buckets["REMOVED"]:
        lines.append(f"  - REMOVED  {occ}  {_fmt(old[occ])}")
    for occ in buckets["UNCHANGED"]:
        lines.append(f"  = UNCHANGED {occ}  {_fmt(new[occ])}")

    return lines


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Diff two ReachGate receipt artifacts by occurrence_id.",
    )
    parser.add_argument("old_artifact", help="path to the OLD receipts JSON")
    parser.add_argument("new_artifact", help="path to the NEW receipts JSON")
    parser.add_argument(
        "--fail-on-new-reachable",
        action="store_true",
        help="exit 1 if any finding became REACHABLE (NEW or CHANGED-to-REACHABLE)",
    )
    args = parser.parse_args(argv)

    try:
        old = _by_occurrence(_load(args.old_artifact))
        new = _by_occurrence(_load(args.new_artifact))
    except InputError as e:
        print(f"diff_receipts: {e}", file=sys.stderr)
        return 2

    buckets = classify(old, new)
    for line in render(buckets, old, new):
        print(line)

    if args.fail_on_new_reachable:
        failures = gate_failures(buckets, old, new)
        if failures:
            print("FAIL: findings became REACHABLE: " + ", ".join(failures))
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
