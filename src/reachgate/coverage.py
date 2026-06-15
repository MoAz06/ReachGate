"""Coverage / blind-spot report, derived only from existing receipts.

ReachGate's honesty model has a third verdict (UNKNOWN) precisely because
reachability is bounded by what was declared and what Orbit indexed. This
module turns that honesty into something a reviewer can read at a glance: a
coverage report computed *only* from the captured receipt artifacts -- no live
GitLab/Orbit calls, no new judgement, no invented numbers.

It reports:
  * verdict counts (REACHABLE / NOT_REACHABLE / UNKNOWN);
  * UNKNOWN reason counts, each with the typed meaning + next action from
    guidance.py (the single source of truth);
  * which findings carry a code location (a file to anchor a walk) vs. which
    are dependency/SCA-style advisories with no code anchor;
  * an entry-point / path evidence summary where the receipt records it;
  * an explicit, honest "blind spots" section.

Everything here is presentation over fields the engine already wrote. It never
changes a verdict, a fingerprint, the policy, or the proof schema.

Standard library only. No network, no token, no dependencies.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from .guidance import guidance_for_basis, reason_from_basis

VERDICT_ORDER = ("REACHABLE", "NOT_REACHABLE", "UNKNOWN")

# A file path that looks like a dependency/SCA advisory rather than an indexed
# source file. Heuristic and presentation-only: it never changes a verdict, it
# just labels why an UNKNOWN has no code anchor in the coverage summary.
_ADVISORY_HINTS = ("CVE-", "GHSA-", "advisory", "/gem/", "/npm/", "/pip/")


class CoverageError(ValueError):
    """Raised when receipts cannot be read for a coverage report."""


@dataclass
class CoverageReport:
    """Aggregated, presentation-only coverage over a set of receipts."""

    total_findings: int = 0
    verdict_counts: dict[str, int] = field(default_factory=dict)
    unknown_reason_counts: dict[str, int] = field(default_factory=dict)
    with_location: int = 0
    without_location: int = 0
    advisory_like: int = 0
    entrypoints_seen: set[str] = field(default_factory=set)
    reachable_paths: list[list[str]] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)


def _looks_like_advisory(vuln_file: str | None) -> bool:
    if not vuln_file:
        return False
    low = vuln_file.lower()
    return any(hint.lower() in low for hint in _ADVISORY_HINTS)


def _load_findings(path: Path) -> list[dict]:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise CoverageError(f"{Path(path).name}: file not found") from exc
    except json.JSONDecodeError as exc:
        raise CoverageError(f"{Path(path).name}: invalid JSON ({exc})") from exc
    if not isinstance(data, dict):
        raise CoverageError(f"{Path(path).name}: top-level JSON must be an object")
    findings = data.get("findings")
    if not isinstance(findings, list):
        raise CoverageError(f"{Path(path).name}: no findings list")
    return findings


def build_coverage(sources) -> CoverageReport:
    """Aggregate a CoverageReport from one or more receipt artifact paths.

    Deterministic: depends only on the file contents, never on wall-clock time
    or call ordering beyond the supplied source order.
    """
    report = CoverageReport()
    for path in sources:
        report.sources.append(Path(path).name)
        for finding in _load_findings(Path(path)):
            report.total_findings += 1
            verdict = str(finding.get("verdict", "UNKNOWN"))
            report.verdict_counts[verdict] = report.verdict_counts.get(verdict, 0) + 1

            vuln_file = finding.get("vulnerable_file")
            if isinstance(vuln_file, str) and vuln_file:
                report.with_location += 1
                if _looks_like_advisory(vuln_file):
                    report.advisory_like += 1
            else:
                report.without_location += 1

            entry = finding.get("entry_point")
            if isinstance(entry, str) and entry:
                report.entrypoints_seen.add(entry)

            if verdict == "REACHABLE":
                path_nodes = finding.get("path") or []
                if path_nodes:
                    report.reachable_paths.append([str(n) for n in path_nodes])

            if verdict == "UNKNOWN":
                reason = reason_from_basis(finding.get("verdict_basis")) or "unspecified"
                report.unknown_reason_counts[reason] = (
                    report.unknown_reason_counts.get(reason, 0) + 1
                )
    return report


def _ordered_verdicts(report: CoverageReport) -> list[tuple[str, int]]:
    rows = []
    for verdict in VERDICT_ORDER:
        if verdict in report.verdict_counts:
            rows.append((verdict, report.verdict_counts[verdict]))
    # Any non-standard verdict, sorted for determinism.
    for verdict in sorted(report.verdict_counts):
        if verdict not in VERDICT_ORDER:
            rows.append((verdict, report.verdict_counts[verdict]))
    return rows


def render_text(report: CoverageReport) -> str:
    """Human-readable coverage / blind-spot report (deterministic text)."""
    lines: list[str] = []
    lines.append("ReachGate coverage / blind-spot report")
    lines.append(f"sources: {', '.join(report.sources) or 'n/a'}")
    lines.append(f"findings analyzed: {report.total_findings}")
    lines.append("")

    lines.append("verdicts:")
    for verdict, count in _ordered_verdicts(report):
        lines.append(f"  {verdict:<14} {count}")
    lines.append("")

    lines.append("code anchor (can a walk even start?):")
    lines.append(f"  with code location:    {report.with_location}")
    lines.append(f"  without code location: {report.without_location}")
    lines.append(
        f"  dependency/SCA-like:   {report.advisory_like} "
        "(advisory file path, no indexed code anchor)"
    )
    lines.append("")

    if report.entrypoints_seen:
        lines.append("entry points observed in receipts:")
        for entry in sorted(report.entrypoints_seen):
            lines.append(f"  - {entry}")
        lines.append("")

    if report.reachable_paths:
        lines.append("reachable path evidence:")
        for nodes in report.reachable_paths:
            lines.append(f"  - {' -> '.join(nodes)}")
        lines.append("")

    lines.append("UNKNOWN reasons (why evidence was insufficient):")
    if report.unknown_reason_counts:
        for reason in sorted(report.unknown_reason_counts):
            count = report.unknown_reason_counts[reason]
            lines.append(f"  [{count}] {reason}")
            guidance = guidance_for_basis(f"insufficient_evidence:{reason}")
            if guidance is not None:
                lines.append(f"        meaning:     {guidance.meaning}")
                lines.append(f"        next action: {guidance.next_action}")
    else:
        lines.append("  (none)")
    lines.append("")

    lines.append("blind spots / limitations (honest by design):")
    lines.append(
        "  - Reachability is only as complete as the declared entry points "
        "(reachgate.yml) and the configured search bounds."
    )
    lines.append(
        "  - NOT_REACHABLE is scoped to those bounds; it is not a global "
        "safety claim."
    )
    lines.append(
        "  - Dependency/SCA advisories with no indexed code definition stay "
        "UNKNOWN by design rather than fake-green."
    )
    lines.append(
        "  - Path accuracy depends on Orbit's indexing depth and language "
        "coverage for the target repository."
    )
    return "\n".join(lines) + "\n"


def render_json(report: CoverageReport) -> dict:
    """Machine-readable coverage report (deterministic, stable key order)."""
    unknown = {}
    for reason in sorted(report.unknown_reason_counts):
        guidance = guidance_for_basis(f"insufficient_evidence:{reason}")
        unknown[reason] = {
            "count": report.unknown_reason_counts[reason],
            "meaning": guidance.meaning if guidance else None,
            "next_action": guidance.next_action if guidance else None,
        }
    return {
        "sources": list(report.sources),
        "findings_analyzed": report.total_findings,
        "verdict_counts": {v: c for v, c in _ordered_verdicts(report)},
        "code_anchor": {
            "with_location": report.with_location,
            "without_location": report.without_location,
            "advisory_like": report.advisory_like,
        },
        "entrypoints_seen": sorted(report.entrypoints_seen),
        "reachable_paths": [list(p) for p in report.reachable_paths],
        "unknown_reasons": unknown,
        "blind_spots": [
            "Reachability is only as complete as the declared entry points "
            "(reachgate.yml) and the configured search bounds.",
            "NOT_REACHABLE is scoped to those bounds; it is not a global "
            "safety claim.",
            "Dependency/SCA advisories with no indexed code definition stay "
            "UNKNOWN by design rather than fake-green.",
            "Path accuracy depends on Orbit's indexing depth and language "
            "coverage for the target repository.",
        ],
    }
