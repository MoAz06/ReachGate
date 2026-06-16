"""Regression blame: which changed files sit ON a reachable path (deterministic).

ReachGate's engine emits a receipt per finding, and a REACHABLE receipt carries
the actual graph ``path`` from a declared entry point to the vulnerable
definition. This module answers one narrow, deterministic question:

    Of the files a change set touches, which ones lie ON that reachable path?

It is a pure set intersection of two facts -- the File nodes recorded in the
receipt path (plus the entry point and the vulnerable file) and the list of
files a diff changed. There is no heuristic, no git blame on edges, no model
judgement. The claim it supports is strictly an OVERLAP claim:

    "this change touches files on the reachable path: X, Y"

It deliberately does NOT claim a change *introduced* or *caused* reachability.
Touching a file that already sits on an existing reachable path does not mean
the change created that path. Proving introduction needs a BEFORE/AFTER receipt
diff (see ``fixproof.py`` -> ``reachability_introduced``), which compares two
runs. This module compares one receipt against a file list and stays on the
honest side of that line: overlap, never causation.

Provenance note: the changed-files list must come from the SAME repository the
receipt describes (its entry points / paths). Like ``reachgate.yml``, that
mapping is the caller's responsibility; the tool reports the overlap it is
given and never assumes the diff and the receipt are from the same place.

Standard library only. No network, no token, no engine-semantics changes.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from typing import Any

SCHEMA_VERSION = "1.0"

REACHABLE = "REACHABLE"


class BlameError(Exception):
    """A user-facing problem (missing/invalid receipt, or git unavailable)."""


def _node_file(node: str) -> str | None:
    """Return the file path for a ``File:<path>`` graph node, else None.

    Definition / ImportedSymbol nodes are not source files and contribute no
    path file.
    """
    if not isinstance(node, str):
        return None
    kind, sep, rest = node.partition(":")
    if kind == "File" and sep and rest:
        return rest
    return None


def path_files(finding: dict[str, Any]) -> list[str]:
    """All real source files associated with a finding's reachable path.

    The File nodes along the recorded graph ``path``, plus the declared
    ``entry_point`` and the ``vulnerable_file`` when present. Sorted and
    de-duplicated for deterministic output.
    """
    files: set[str] = set()
    for node in finding.get("path") or []:
        f = _node_file(node)
        if f:
            files.add(f)
    entry = finding.get("entry_point")
    if isinstance(entry, str) and entry:
        files.add(entry)
    vuln = finding.get("vulnerable_file")
    if isinstance(vuln, str) and vuln:
        files.add(vuln)
    return sorted(files)


def _normalize(paths) -> set[str]:
    """Normalize a file list to forward slashes, stripped, non-empty."""
    out: set[str] = set()
    for p in paths or []:
        if not isinstance(p, str):
            continue
        norm = p.strip().replace("\\", "/")
        if norm:
            out.add(norm)
    return out


def blame_finding(finding: dict[str, Any], changed: set[str]) -> dict[str, Any]:
    """Compute the overlap between one finding's path files and ``changed``."""
    pf = path_files(finding)
    pf_norm = _normalize(pf)
    overlap = sorted(pf_norm & changed)
    return {
        "occurrence_id": finding.get("occurrence_id"),
        "occurrence_name": finding.get("occurrence_name"),
        "verdict": finding.get("verdict"),
        "fingerprint": finding.get("fingerprint"),
        "path_files": pf,
        "touched_files": overlap,
        "touches_path": bool(overlap),
        # Only a REACHABLE finding has a proven path; an overlap there is the
        # load-bearing signal. For other verdicts the overlap is reported but
        # carries no reachable-path meaning.
        "reachable": finding.get("verdict") == REACHABLE,
    }


def blame(findings: list[dict[str, Any]], changed_files) -> dict[str, Any]:
    """Build a deterministic blame report over findings vs. a changed-file set."""
    changed = _normalize(changed_files)
    results = [blame_finding(f, changed) for f in findings]
    results.sort(key=lambda r: (str(r.get("occurrence_id")),
                                str(r.get("fingerprint"))))

    reachable_touched = sum(
        1 for r in results if r["reachable"] and r["touches_path"]
    )
    any_touched = sum(1 for r in results if r["touches_path"])
    return {
        "schema_version": SCHEMA_VERSION,
        "changed_files": sorted(changed),
        "summary": {
            "findings": len(results),
            "reachable_paths_touched": reachable_touched,
            "paths_touched": any_touched,
        },
        "findings": results,
    }


# --- inputs ----------------------------------------------------------------

def load_findings(path: str) -> list[dict[str, Any]]:
    """Load findings from a ReachGate receipt artifact."""
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        raise BlameError(f"receipt not found: {path}")
    except json.JSONDecodeError as exc:
        raise BlameError(f"invalid JSON in {path}: {exc}")
    if isinstance(data, dict):
        findings = data.get("findings")
    elif isinstance(data, list):
        findings = data
    else:
        findings = None
    if not isinstance(findings, list):
        raise BlameError(f"{path}: no 'findings' list in receipt")
    return findings


def git_changed_files(base: str, head: str = "HEAD", cwd: str | None = None) -> list[str]:
    """Files changed between two git refs (``git diff --name-only base..head``).

    Raises BlameError if git is unavailable or the refs cannot be diffed.
    """
    try:
        out = subprocess.run(
            ["git", "diff", "--name-only", f"{base}..{head}"],
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise BlameError(f"could not run git: {exc}")
    if out.returncode != 0:
        raise BlameError(
            f"git diff {base}..{head} failed: {out.stderr.strip() or 'unknown error'}"
        )
    return [line.strip() for line in out.stdout.splitlines() if line.strip()]


# --- renderers -------------------------------------------------------------

def render_json(report: dict[str, Any]) -> str:
    return json.dumps(report, sort_keys=True, indent=2, ensure_ascii=False) + "\n"


def render_text(report: dict[str, Any]) -> str:
    s = report["summary"]
    lines = [
        f"ReachGate blame: {s['reachable_paths_touched']} reachable path(s) "
        f"touched, {s['paths_touched']} finding path(s) touched, "
        f"{s['findings']} finding(s), {len(report['changed_files'])} changed file(s)"
    ]
    for r in report["findings"]:
        mark = "REACH-TOUCH" if (r["reachable"] and r["touches_path"]) else (
            "touch" if r["touches_path"] else "----"
        )
        lines.append(
            f"  [{mark}] {r['occurrence_id']} ({r['verdict']}) "
            f"fp={r['fingerprint']}"
        )
        if r["touched_files"]:
            lines.append("      touches on path: " + ", ".join(r["touched_files"]))
    lines.append(
        "  note: 'touches a file on the reachable path' is an OVERLAP, not a "
        "claim that this change introduced reachability (that needs a "
        "before/after receipt diff -- see `reachgate fixcheck`)."
    )
    return "\n".join(lines) + "\n"


def render_markdown(report: dict[str, Any], *, source: str | None = None) -> str:
    s = report["summary"]
    lines = ["## ReachGate path-overlap (regression blame)", ""]
    if source:
        lines.append(f"- **Receipt:** `{source}`")
    lines.append(f"- **Changed files:** {len(report['changed_files'])}")
    lines.append(
        f"- **Reachable paths touched:** {s['reachable_paths_touched']} "
        f"of {s['findings']} finding(s)"
    )
    lines.append("")
    lines.append("| finding | verdict | touches path? | files on path touched |")
    lines.append("|---|---|---|---|")
    for r in report["findings"]:
        touch = "yes" if r["touches_path"] else "no"
        if r["reachable"] and r["touches_path"]:
            touch = "**yes (reachable path)**"
        files = ", ".join(f"`{f}`" for f in r["touched_files"]) or "-"
        lines.append(
            f"| `{r['occurrence_id']}` | {r['verdict']} | {touch} | {files} |"
        )
    lines.append("")
    lines.append(
        "> This is an **overlap** signal: the change touches files that lie on "
        "an existing reachable path. It is **not** a claim that the change "
        "*introduced* or *caused* reachability -- proving introduction needs a "
        "before/after receipt diff (`reachgate fixcheck` -> "
        "`reachability_introduced`)."
    )
    return "\n".join(lines) + "\n"


# --- CLI -------------------------------------------------------------------

def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="reachgate blame",
        description=(
            "Report which changed files lie on a finding's reachable path "
            "(deterministic overlap; never a causation claim)."
        ),
    )
    parser.add_argument("receipt", help="path to a ReachGate receipt JSON")
    parser.add_argument(
        "--changed-files", nargs="*", default=None,
        help="explicit list of changed files (from the receipt's repository).",
    )
    parser.add_argument(
        "--base", default=None,
        help="git base ref; with --head, changed files = git diff base..head.",
    )
    parser.add_argument(
        "--head", default="HEAD",
        help="git head ref (default: HEAD); used with --base.",
    )
    parser.add_argument(
        "--repo", default=None,
        help="run git in this directory (default: current directory).",
    )
    parser.add_argument(
        "--format", choices=("text", "json", "markdown"), default="text",
        help="output format (default: text).",
    )
    parser.add_argument(
        "--output", default=None,
        help="write to a file instead of stdout.",
    )
    args = parser.parse_args(argv)

    try:
        findings = load_findings(args.receipt)
        if args.changed_files is not None:
            changed = args.changed_files
        elif args.base is not None:
            changed = git_changed_files(args.base, args.head, cwd=args.repo)
        else:
            print(
                "error: provide --changed-files <...> or --base <ref> [--head <ref>]\n"
                "  The changed files must come from the repository the receipt "
                "describes.",
                file=sys.stderr,
            )
            return 2
        report = blame(findings, changed)
    except BlameError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.format == "json":
        rendered = render_json(report)
    elif args.format == "markdown":
        rendered = render_markdown(report, source=args.receipt)
    else:
        rendered = render_text(report)

    if args.output:
        from pathlib import Path
        out = Path(args.output)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(rendered, encoding="utf-8")
        print(f"wrote {out}")
    else:
        print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
