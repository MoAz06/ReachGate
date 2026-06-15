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

import html
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


_BLIND_SPOTS = (
    "Reachability is only as complete as the declared entry points "
    "(reachgate.yml) and the configured search bounds.",
    "NOT_REACHABLE is scoped to those bounds; it is not a global safety claim.",
    "Dependency/SCA advisories with no indexed code definition stay UNKNOWN by "
    "design rather than fake-green.",
    "Path accuracy depends on Orbit's indexing depth and language coverage for "
    "the target repository.",
)


def _e(value) -> str:
    return html.escape(str(value), quote=True)


def render_html(report: CoverageReport) -> str:
    """Static HTML coverage / blind-spot report.

    Self-contained: no JavaScript, no CDN, no external resources -- just inline
    CSS, so it is safe to open offline or ship inside the evidence capsule. It
    presents the same data as render_text / render_json: verdict counts, the
    UNKNOWN reason breakdown with typed next actions, the code-anchor split, and
    an honest blind-spots section.
    """
    verdict_rows = "".join(
        f"<tr><td>{_e(v)}</td><td class=\"num\">{_e(c)}</td></tr>"
        for v, c in _ordered_verdicts(report)
    )

    unknown_blocks = []
    for reason in sorted(report.unknown_reason_counts):
        count = report.unknown_reason_counts[reason]
        guidance = guidance_for_basis(f"insufficient_evidence:{reason}")
        meaning = guidance.meaning if guidance else ""
        action = guidance.next_action if guidance else ""
        unknown_blocks.append(
            f"<div class=\"reason\"><p class=\"reason-head\">"
            f"<span class=\"badge\">{_e(count)}</span> "
            f"<code>{_e(reason)}</code></p>"
            f"<p class=\"meaning\">{_e(meaning)}</p>"
            f"<p class=\"action\"><strong>Next action</strong> {_e(action)}</p>"
            f"</div>"
        )
    unknown_html = "".join(unknown_blocks) or "<p>(no UNKNOWN findings)</p>"

    entrypoints = "".join(
        f"<li><code>{_e(e)}</code></li>" for e in sorted(report.entrypoints_seen)
    ) or "<li>(none recorded)</li>"

    paths = "".join(
        f"<li><code>{_e(' -> '.join(p))}</code></li>"
        for p in report.reachable_paths
    ) or "<li>(none)</li>"

    blind = "".join(f"<li>{_e(b)}</li>" for b in _BLIND_SPOTS)
    sources = ", ".join(_e(s) for s in report.sources) or "n/a"

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ReachGate coverage / blind-spot report</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif;
    margin: 0; background: #f6f0e1; color: #241d12; line-height: 1.6; }}
  main {{ max-width: 880px; margin: 0 auto; padding: 32px 24px 64px; }}
  h1 {{ font-size: 1.7rem; margin: 0 0 4px; }}
  h2 {{ font-size: 1.2rem; margin: 30px 0 10px; border-bottom: 2px solid #241d12;
    padding-bottom: 6px; }}
  .sub {{ color: #6c6049; font-size: .9rem; margin: 0 0 8px; }}
  table {{ border-collapse: collapse; width: 100%; max-width: 360px; }}
  th, td {{ text-align: left; padding: 7px 10px; border-bottom: 1px solid #d6c9a9; }}
  td.num {{ text-align: right; font-variant-numeric: tabular-nums; font-weight: 700; }}
  code {{ font-family: "Courier New", monospace; background: #efe6d2; padding: 1px 5px; }}
  .reason {{ border: 1px solid #d6c9a9; border-left: 4px solid #8f6410;
    background: #efe4c8; padding: 12px 14px; margin: 10px 0; }}
  .reason-head {{ margin: 0 0 6px; }}
  .badge {{ display: inline-block; min-width: 22px; text-align: center;
    background: #8f6410; color: #f6f0e1; border-radius: 3px; padding: 0 6px;
    font-weight: 700; }}
  .meaning {{ margin: 4px 0; }}
  .action strong {{ text-transform: uppercase; font-size: .7rem; letter-spacing: .08em;
    color: #8f6410; margin-right: 6px; }}
  ul {{ margin: 6px 0; padding-left: 20px; }}
  .anchor {{ display: flex; gap: 24px; flex-wrap: wrap; }}
  .anchor div {{ background: #efe6d2; border: 1px solid #d6c9a9; padding: 10px 16px; }}
  .anchor .big {{ font-size: 1.6rem; font-weight: 700; }}
  footer {{ margin-top: 30px; padding-top: 14px; border-top: 1px solid #d6c9a9;
    color: #6c6049; font-size: .82rem; }}
</style>
</head>
<body>
<main>
  <h1>ReachGate coverage / blind-spot report</h1>
  <p class="sub">sources: {sources} &middot; findings analyzed: {_e(report.total_findings)}</p>

  <h2>Verdicts</h2>
  <table><tr><th>verdict</th><th class="num">count</th></tr>{verdict_rows}</table>

  <h2>Code anchor &mdash; can a walk even start?</h2>
  <div class="anchor">
    <div><span class="big">{_e(report.with_location)}</span><br>with code location</div>
    <div><span class="big">{_e(report.without_location)}</span><br>without code location</div>
    <div><span class="big">{_e(report.advisory_like)}</span><br>dependency/SCA-like</div>
  </div>

  <h2>Entry points observed</h2>
  <ul>{entrypoints}</ul>

  <h2>Reachable path evidence</h2>
  <ul>{paths}</ul>

  <h2>UNKNOWN reasons &mdash; why evidence was insufficient</h2>
  {unknown_html}

  <h2>Blind spots / limitations (honest by design)</h2>
  <ul>{blind}</ul>

  <footer>
    Derived only from the captured receipts, offline. NOT_REACHABLE is scoped to
    the configured search bounds; UNKNOWN is never presented as safe. Advisory by
    default &mdash; the deterministic engine decides, the AI only explains.
  </footer>
</main>
</body>
</html>
"""
