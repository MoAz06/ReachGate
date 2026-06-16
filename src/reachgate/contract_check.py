"""Machine-checkable Evidence Contract validator.

``docs/EVIDENCE_CONTRACT.md`` states exactly which claims a ReachGate receipt
may make. This module makes that contract *enforceable* on arbitrary receipt
artifacts: it never re-decides a verdict and never calls GitLab/Orbit — it only
checks that the claims a receipt already carries are allowed by the contract.

The whole point is the positioning line:

    "Don't trust our marketing. Run `reachgate contract-check receipt.json` and
     verify whether this evidence is allowed to claim what it claims."

It deliberately reuses the existing, already-enforced invariants rather than
inventing new ones:

  * the exhaustive-search definition comes from
    ``fixproof.is_exhaustive_not_reachable`` (the same rule the verifier and the
    OpenVEX export use);
  * UNKNOWN guidance comes from ``guidance.guidance_for_basis``.

Contract rules enforced (see EVIDENCE_CONTRACT.md):
  * REACHABLE may carry a path; it is never treated as safe.
  * NOT_REACHABLE is "safe within configured bounds" ONLY when its certificate
    is exhaustive (frontier exhausted, 0 API errors, no bound hit). A
    non-exhaustive NOT_REACHABLE is a contract FAIL — it overclaims a negative
    the search did not earn.
  * UNKNOWN is always an evidence gap, never safe — and a receipt that presents
    UNKNOWN is contract-conformant precisely because it does not overclaim.
  * Missing / ambiguous fields produce a clear diagnostic, never a traceback.

Status model:
  * Each finding gets pass / warn / fail.
  * Overall is FAIL if any finding overclaims (an unsafe / overclaiming state);
    WARN if there are only non-fatal gaps; PASS otherwise.

Standard library only. No network, no token. Deterministic output.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from .fixproof import is_exhaustive_not_reachable
from .guidance import guidance_for_basis, reason_from_basis

REACHABLE = "REACHABLE"
NOT_REACHABLE = "NOT_REACHABLE"
UNKNOWN = "UNKNOWN"

PASS = "pass"
WARN = "warn"
FAIL = "fail"

# Rank for combining statuses into an overall verdict (higher wins).
_RANK = {PASS: 0, WARN: 1, FAIL: 2}

SCHEMA_VERSION = "1.0"


class ContractCheckError(Exception):
    """A user-facing problem reading an artifact (missing / invalid JSON)."""


@dataclass
class Diagnostic:
    """One contract observation about one finding."""

    status: str  # pass | warn | fail
    rule: str  # short contract-rule id, e.g. "not_reachable.exhaustive"
    message: str

    def as_dict(self) -> dict[str, Any]:
        return {"status": self.status, "rule": self.rule, "message": self.message}


@dataclass
class FindingResult:
    occurrence_id: str | None
    verdict: str | None
    status: str
    diagnostics: list[Diagnostic] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "occurrence_id": self.occurrence_id,
            "verdict": self.verdict,
            "status": self.status,
            "diagnostics": [d.as_dict() for d in self.diagnostics],
        }


@dataclass
class ContractCheckResult:
    overall: str
    summary: dict[str, int]
    findings: list[FindingResult] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "overall": self.overall,
            "summary": self.summary,
            "findings": [f.as_dict() for f in self.findings],
        }


def _worst(statuses: list[str]) -> str:
    """Combine finding statuses into one, FAIL > WARN > PASS."""
    if not statuses:
        return PASS
    return max(statuses, key=lambda s: _RANK.get(s, 0))


def _finding_status(diags: list[Diagnostic]) -> str:
    return _worst([d.status for d in diags])


def _check_reachable(finding: dict[str, Any]) -> list[Diagnostic]:
    diags: list[Diagnostic] = []
    # REACHABLE may carry a path; an empty path is a gap, not an overclaim.
    path = finding.get("path")
    if isinstance(path, list) and path:
        diags.append(
            Diagnostic(
                PASS, "reachable.path",
                "REACHABLE carries a graph path; treated as exploitable context, "
                "never as safe.",
            )
        )
    else:
        diags.append(
            Diagnostic(
                WARN, "reachable.path",
                "REACHABLE without a recorded graph path; verdict stands but the "
                "path evidence is missing.",
            )
        )
    if finding.get("verdict_basis") in (None, ""):
        diags.append(
            Diagnostic(
                WARN, "reachable.basis",
                "REACHABLE without a verdict_basis (expected 'path_found').",
            )
        )
    return diags


def _check_not_reachable(finding: dict[str, Any]) -> list[Diagnostic]:
    diags: list[Diagnostic] = []
    cert = finding.get("certificate")
    if not isinstance(cert, dict):
        # A NOT_REACHABLE with no certificate cannot prove it was exhaustive,
        # so it must not be trusted as safe-within-bounds: contract FAIL.
        diags.append(
            Diagnostic(
                FAIL, "not_reachable.certificate",
                "NOT_REACHABLE without a certificate cannot prove an exhaustive "
                "search; it must not be treated as safe within bounds.",
            )
        )
        return diags

    if is_exhaustive_not_reachable(finding):
        diags.append(
            Diagnostic(
                PASS, "not_reachable.exhaustive",
                "NOT_REACHABLE is exhaustive (frontier exhausted, no bound hit, "
                "0 API errors); safe only within the configured bounds.",
            )
        )
    else:
        # Spell out exactly which precondition failed, for an auditable reason.
        reasons = []
        if cert.get("frontier_exhausted") is not True:
            reasons.append("frontier not exhausted")
        if cert.get("api_errors") not in (0, None) and cert.get("api_errors"):
            reasons.append(f"api_errors={cert.get('api_errors')}")
        if cert.get("max_hops_hit") is True:
            reasons.append("max_hops_hit")
        if cert.get("visited_cap_hit") is True:
            reasons.append("visited_cap_hit")
        if cert.get("timeout_hit") is True:
            reasons.append("timeout_hit")
        detail = ", ".join(reasons) or "search did not run to completion"
        diags.append(
            Diagnostic(
                FAIL, "not_reachable.exhaustive",
                "NOT_REACHABLE is NOT exhaustive (" + detail + "); under the "
                "contract this must be UNKNOWN, never a safe-within-bounds "
                "negative.",
            )
        )
    return diags


def _check_unknown(finding: dict[str, Any]) -> list[Diagnostic]:
    diags: list[Diagnostic] = []
    basis = finding.get("verdict_basis")
    reason = reason_from_basis(basis)
    # UNKNOWN is always contract-conformant: it is an evidence gap, not safe.
    if reason is None:
        diags.append(
            Diagnostic(
                WARN, "unknown.basis",
                "UNKNOWN without an 'insufficient_evidence:<reason>' basis; "
                "still an evidence gap (never safe), but the typed reason is "
                "missing.",
            )
        )
    else:
        guidance = guidance_for_basis(basis)
        action = guidance.next_action if guidance else "review the finding manually"
        diags.append(
            Diagnostic(
                PASS, "unknown.evidence_gap",
                f"UNKNOWN is a typed evidence gap ({reason}); never safe. "
                f"Next action: {action}",
            )
        )
    return diags


def check_finding(finding: dict[str, Any]) -> FindingResult:
    """Validate a single receipt finding against the Evidence Contract."""
    if not isinstance(finding, dict):
        return FindingResult(
            occurrence_id=None, verdict=None, status=FAIL,
            diagnostics=[
                Diagnostic(FAIL, "finding.shape",
                           "finding is not an object; cannot validate.")
            ],
        )

    occ = finding.get("occurrence_id")
    verdict = finding.get("verdict")

    diags: list[Diagnostic] = []
    if verdict == REACHABLE:
        diags += _check_reachable(finding)
    elif verdict == NOT_REACHABLE:
        diags += _check_not_reachable(finding)
    elif verdict == UNKNOWN:
        diags += _check_unknown(finding)
    else:
        diags.append(
            Diagnostic(
                FAIL, "verdict.value",
                f"unrecognized verdict {verdict!r}; the contract only defines "
                "REACHABLE, NOT_REACHABLE, and UNKNOWN.",
            )
        )

    return FindingResult(
        occurrence_id=occ if isinstance(occ, str) else None,
        verdict=verdict if isinstance(verdict, str) else None,
        status=_finding_status(diags),
        diagnostics=diags,
    )


def check_artifact(artifact: dict[str, Any]) -> ContractCheckResult:
    """Validate a whole receipt artifact. Deterministic, sorted output."""
    if not isinstance(artifact, dict):
        result = ContractCheckResult(
            overall=FAIL,
            summary={PASS: 0, WARN: 0, FAIL: 1},
            findings=[
                FindingResult(
                    None, None, FAIL,
                    [Diagnostic(FAIL, "artifact.shape",
                                "artifact is not a JSON object.")],
                )
            ],
        )
        return result

    findings = artifact.get("findings")
    results: list[FindingResult] = []
    if not isinstance(findings, list) or not findings:
        results.append(
            FindingResult(
                None, None, FAIL,
                [Diagnostic(FAIL, "artifact.findings",
                            "artifact has no 'findings' list to validate.")],
            )
        )
    else:
        for finding in findings:
            results.append(check_finding(finding))

    # Stable order: by occurrence_id (None last), preserving input order within
    # equal ids so a malformed artifact still renders predictably.
    results_sorted = sorted(
        enumerate(results),
        key=lambda pair: (pair[1].occurrence_id is None, pair[1].occurrence_id or "", pair[0]),
    )
    ordered = [r for _, r in results_sorted]

    summary = {PASS: 0, WARN: 0, FAIL: 0}
    for r in ordered:
        summary[r.status] = summary.get(r.status, 0) + 1

    overall = _worst([r.status for r in ordered])
    return ContractCheckResult(overall=overall, summary=summary, findings=ordered)


# --- IO + rendering --------------------------------------------------------

def _load(path: str) -> dict[str, Any]:
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        raise ContractCheckError(f"file not found: {path}")
    except IsADirectoryError:
        raise ContractCheckError(f"not a file: {path}")
    except json.JSONDecodeError as exc:
        raise ContractCheckError(f"invalid JSON in {path}: {exc}")
    return data


def check_file(path: str) -> ContractCheckResult:
    """Load a receipt artifact and validate it. Raises ContractCheckError."""
    return check_artifact(_load(path))


def check_files(paths: list[str]) -> dict[str, ContractCheckResult]:
    """Validate multiple artifacts. Keyed by path, deterministic by caller."""
    return {p: check_file(p) for p in paths}


def render_json(result: ContractCheckResult) -> str:
    """Byte-stable JSON: sorted keys, trailing newline."""
    return json.dumps(result.as_dict(), sort_keys=True, indent=2, ensure_ascii=False) + "\n"


_SYMBOL = {PASS: "PASS", WARN: "WARN", FAIL: "FAIL"}


def render_text(result: ContractCheckResult, *, source: str | None = None) -> str:
    lines: list[str] = []
    s = result.summary
    header = (
        f"ReachGate contract-check: {result.overall.upper()} "
        f"(pass={s.get(PASS, 0)} warn={s.get(WARN, 0)} fail={s.get(FAIL, 0)})"
    )
    if source:
        header += f"  [{source}]"
    lines.append(header)
    for f in result.findings:
        occ = f.occurrence_id or "<no occurrence_id>"
        lines.append(f"  {_SYMBOL.get(f.status, '?')}  {occ}  verdict={f.verdict}")
        for d in f.diagnostics:
            lines.append(f"      [{_SYMBOL.get(d.status, '?')}] {d.rule}: {d.message}")
    lines.append(
        "  contract: UNKNOWN is never safe; NOT_REACHABLE is safe only within "
        "the configured bounds when exhaustive. See docs/EVIDENCE_CONTRACT.md."
    )
    return "\n".join(lines) + "\n"


def render_markdown(result: ContractCheckResult, *, source: str | None = None) -> str:
    s = result.summary
    lines: list[str] = []
    lines.append("## ReachGate contract-check")
    lines.append("")
    if source:
        lines.append(f"- **Artifact:** `{source}`")
    lines.append(f"- **Overall:** {result.overall.upper()}")
    lines.append(
        f"- **Counts:** pass={s.get(PASS, 0)}, warn={s.get(WARN, 0)}, "
        f"fail={s.get(FAIL, 0)}"
    )
    lines.append("")
    lines.append("| finding | verdict | status |\n|---|---|---|")
    for f in result.findings:
        occ = f.occurrence_id or "(no occurrence_id)"
        lines.append(f"| `{occ}` | {f.verdict} | {_SYMBOL.get(f.status, '?')} |")
    lines.append("")
    lines.append("### Diagnostics")
    for f in result.findings:
        occ = f.occurrence_id or "(no occurrence_id)"
        lines.append(f"- `{occ}`:")
        for d in f.diagnostics:
            lines.append(f"  - **{_SYMBOL.get(d.status, '?')}** `{d.rule}`: {d.message}")
    lines.append("")
    lines.append(
        "> `UNKNOWN` is never safe; `NOT_REACHABLE` is safe only within the "
        "configured bounds, and only when exhaustive. "
        "See `docs/EVIDENCE_CONTRACT.md`."
    )
    return "\n".join(lines) + "\n"
