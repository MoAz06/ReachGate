"""Export SARIF 2.1.0 from ReachGate reachability receipts.

ReachGate already produces a verifiable receipt per finding (verdict, graph
path, certificate, fingerprint). This turns those receipts into a
standards-aligned SARIF 2.1.0 document so SAST/code-flow tooling and code
scanning UIs can consume the reachability evidence machine-readably -- not
just as an MR comment or an OpenVEX (SCA) statement.

Mapping (deterministic, derived only from receipts -- no new judgement):
  REACHABLE      -> result level "error",   reachable code-flow shown as a
                    SARIF codeFlow/threadFlow over the real graph path.
  NOT_REACHABLE  -> result level "note",    message states "not reachable
                    within configured search bounds" (never "safe").
  UNKNOWN        -> result level "warning",  typed evidence reason + next
                    action from guidance.py; never presented as safe.

Honesty rules carried from the receipts:
  * NOT_REACHABLE is only "within configured bounds", never a global safety
    claim. A non-exhaustive NOT_REACHABLE keeps the same honest wording.
  * UNKNOWN is a typed evidence gap, never fake-green.
  * Source locations are only emitted when the receipt actually carries a
    file (vulnerable_file / path nodes). We never invent a location or line.

Standard library only. No network, no token, no dependencies.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
PROOF_DIR = REPO_ROOT / "docs" / "proof"

# Reuse the typed UNKNOWN guidance (pure stdlib) so SARIF, receipts, and the
# judge page all speak with one voice. Single source of truth.
sys.path.insert(0, str(REPO_ROOT / "src"))
from reachgate.guidance import guidance_for_basis  # noqa: E402

# Same canonical captured proof the OpenVEX export is built from: MR !2
# (REACHABLE + NOT_REACHABLE) plus the honest UNKNOWN receipt, so the SARIF
# exercises all three verdict levels.
DEFAULT_SOURCES = (
    PROOF_DIR / "mr2-reachgate-receipts.json",
    PROOF_DIR / "unknown-reachgate-receipt.json",
)
DEFAULT_OUTPUT = PROOF_DIR / "reachgate.sarif.json"

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/"
    "Schemata/sarif-schema-2.1.0.json"
)
TOOL_NAME = "ReachGate"
TOOL_INFO_URI = "https://gitlab.com/gitlab-ai-hackathon/transcend/39037247"

# SARIF result levels per verdict.
_LEVEL = {
    "REACHABLE": "error",
    "NOT_REACHABLE": "note",
    "UNKNOWN": "warning",
}

# Honest, reused wording. NOT_REACHABLE is never "safe".
NOT_REACHABLE_WORDING = "not reachable within configured search bounds"


class SarifError(ValueError):
    """Raised when source receipts cannot be turned into SARIF."""


def _path_file(node: str) -> str | None:
    """Extract a file path from a path node like 'File:foo/bar.js'.

    Returns the path for a File node, else None (Definition/ImportedSymbol
    nodes are not source files we can anchor a physicalLocation to).
    """
    if not node:
        return None
    kind, _, rest = node.partition(":")
    if kind == "File" and rest:
        return rest
    return None


def _artifact_uri(finding: dict) -> str | None:
    """The best real source file for the finding's primary location.

    Prefer the vulnerable_file recorded on the receipt; never invent one.
    """
    vuln = finding.get("vulnerable_file")
    return vuln if isinstance(vuln, str) and vuln else None


def _physical_location(uri: str) -> dict:
    # No line numbers: receipts do not carry start_line, and we never invent
    # source locations. Region is intentionally omitted.
    return {"artifactLocation": {"uri": uri}}


def _code_flow(finding: dict) -> list[dict] | None:
    """Build a SARIF codeFlow/threadFlow from the real graph path.

    Only File nodes become threadFlow locations (they have a physical file);
    Definition / ImportedSymbol nodes are carried as the step message so the
    full path stays visible without inventing file anchors for them.
    """
    path = finding.get("path") or []
    if not path:
        return None
    thread_locations = []
    for node in path:
        uri = _path_file(node)
        loc: dict = {"message": {"text": node}}
        if uri:
            loc["physicalLocation"] = _physical_location(uri)
        thread_locations.append({"location": loc})
    if not thread_locations:
        return None
    return [{"threadFlows": [{"locations": thread_locations}]}]


def _rule_id(finding: dict) -> str:
    """Stable rule id per verdict, e.g. reachgate.reachable."""
    verdict = str(finding.get("verdict", "unknown")).lower()
    return f"reachgate.{verdict}"


def _message_text(finding: dict) -> str:
    verdict = finding.get("verdict")
    name = finding.get("occurrence_name") or finding.get("occurrence_id") or "finding"
    basis = finding.get("verdict_basis") or ""
    fp = finding.get("fingerprint") or "n/a"
    if verdict == "REACHABLE":
        path = finding.get("path") or []
        path_str = " -> ".join(path) if path else "declared entry point -> vulnerable definition"
        return (
            f"REACHABLE: {name}. A graph path exists from a declared entry "
            f"point to the vulnerable definition ({path_str}). "
            f"Basis {basis}; fingerprint {fp}."
        )
    if verdict == "NOT_REACHABLE":
        return (
            f"NOT_REACHABLE: {name} is {NOT_REACHABLE_WORDING} "
            f"(frontier exhausted, no bound hit, 0 API errors). This is not a "
            f"global safety claim. Basis {basis}; fingerprint {fp}."
        )
    # UNKNOWN: typed evidence gap with a next action, never fake-green.
    guidance = guidance_for_basis(basis)
    if guidance is not None:
        return (
            f"UNKNOWN / {guidance.reason}: {name}. {guidance.meaning} "
            f"Next action: {guidance.next_action} "
            f"This is a typed evidence gap, not a safety claim. "
            f"Basis {basis}; fingerprint {fp}."
        )
    return (
        f"UNKNOWN: {name}. Insufficient evidence -- not a safety claim, and "
        f"explicitly not NOT_REACHABLE. Basis {basis}; fingerprint {fp}."
    )


def _properties(finding: dict) -> dict:
    cert = finding.get("certificate") or {}
    props = {
        "verdict": finding.get("verdict"),
        "verdict_basis": finding.get("verdict_basis"),
        "fingerprint": finding.get("fingerprint"),
        "policy_version": cert.get("policy_version"),
        "risk_score": finding.get("risk_score"),
    }
    if finding.get("severity") is not None:
        props["severity"] = finding.get("severity")
    return props


def result_for(finding: dict) -> dict:
    verdict = finding.get("verdict")
    level = _LEVEL.get(verdict, "warning")
    result: dict = {
        "ruleId": _rule_id(finding),
        "level": level,
        "message": {"text": _message_text(finding)},
        "partialFingerprints": {
            "reachgateFingerprint": finding.get("fingerprint") or "n/a"
        },
        "properties": _properties(finding),
    }
    uri = _artifact_uri(finding)
    if uri:
        result["locations"] = [{"physicalLocation": _physical_location(uri)}]
    code_flow = _code_flow(finding)
    if code_flow:
        result["codeFlows"] = code_flow
    return result


def _rules(findings: list[dict]) -> list[dict]:
    """One SARIF reportingDescriptor per distinct verdict, stable order."""
    descriptors = {
        "REACHABLE": {
            "id": "reachgate.reachable",
            "name": "Reachable",
            "shortDescription": {
                "text": "Vulnerable code is reachable from a declared entry point."
            },
            "defaultConfiguration": {"level": "error"},
        },
        "NOT_REACHABLE": {
            "id": "reachgate.not_reachable",
            "name": "NotReachableWithinBounds",
            "shortDescription": {
                "text": (
                    "No path within configured search bounds "
                    "(not a global safety claim)."
                )
            },
            "defaultConfiguration": {"level": "note"},
        },
        "UNKNOWN": {
            "id": "reachgate.unknown",
            "name": "TypedEvidenceGap",
            "shortDescription": {
                "text": (
                    "Insufficient evidence: a typed evidence gap with a next "
                    "action, never presented as safe."
                )
            },
            "defaultConfiguration": {"level": "warning"},
        },
    }
    present = []
    for verdict in ("REACHABLE", "NOT_REACHABLE", "UNKNOWN"):
        if any(f.get("verdict") == verdict for f in findings):
            present.append(descriptors[verdict])
    return present


def build_sarif(findings: list[dict], *, policy_version: str = "") -> dict:
    """Build a SARIF 2.1.0 document from ReachGate findings (deterministic)."""
    results = [result_for(f) for f in findings]
    tool_driver: dict = {
        "name": TOOL_NAME,
        "informationUri": TOOL_INFO_URI,
        "rules": _rules(findings),
    }
    if policy_version:
        tool_driver["version"] = f"policy-{policy_version}"
    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {"driver": tool_driver},
                "results": results,
            }
        ],
    }


def crosscheck(sarif: dict, findings: list[dict]) -> list[str]:
    """Confirm a SARIF document is faithful to the receipts it came from.

    Returns a list of problems (empty == consistent). Lets the SARIF export
    be falsifiable, in the same spirit as the receipts and the OpenVEX.
    """
    problems: list[str] = []
    runs = sarif.get("runs") or []
    if not runs:
        return ["SARIF has no runs"]
    results = runs[0].get("results") or []
    by_fp = {}
    for r in results:
        fp = (r.get("partialFingerprints") or {}).get("reachgateFingerprint")
        by_fp[fp] = r
    for finding in findings:
        fp = finding.get("fingerprint")
        r = by_fp.get(fp)
        if r is None:
            problems.append(f"{fp}: no SARIF result for fingerprint")
            continue
        verdict = finding.get("verdict")
        expected_level = _LEVEL.get(verdict)
        if r.get("level") != expected_level:
            problems.append(
                f"{fp}: level {r.get('level')!r} != expected {expected_level!r}"
            )
        text = (r.get("message") or {}).get("text", "")
        # Integrity invariants, stated independently of the builder.
        if verdict == "NOT_REACHABLE" and NOT_REACHABLE_WORDING not in text:
            problems.append(f"{fp}: NOT_REACHABLE missing configured-bounds wording")
        if verdict == "UNKNOWN":
            if "evidence gap" not in text:
                problems.append(f"{fp}: UNKNOWN not framed as evidence gap")
            if "not_affected" in text or "is safe" in text:
                problems.append(f"{fp}: UNKNOWN presented as safe (fake-green)")
        if verdict == "REACHABLE" and finding.get("path"):
            if not r.get("codeFlows"):
                problems.append(f"{fp}: REACHABLE with a path but no codeFlow")
    return problems


def _load_artifact(path: Path) -> dict:
    try:
        with Path(path).open(encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError as exc:
        raise SarifError(f"{Path(path).name}: file not found") from exc
    except json.JSONDecodeError as exc:
        raise SarifError(f"{Path(path).name}: invalid JSON ({exc})") from exc
    if not isinstance(data, dict):
        raise SarifError(f"{Path(path).name}: top-level JSON must be an object")
    return data


def load_findings(paths) -> tuple[list[dict], str]:
    findings: list[dict] = []
    policy_version = ""
    for path in paths:
        data = _load_artifact(Path(path))
        policy_version = (data.get("policy") or {}).get("version") or policy_version
        items = data.get("findings")
        if not isinstance(items, list) or not items:
            raise SarifError(f"{Path(path).name}: no findings")
        findings.extend(items)
    return findings, policy_version


def generate(
    sources=DEFAULT_SOURCES,
    output: Path = DEFAULT_OUTPUT,
) -> dict:
    findings, policy_version = load_findings(sources)
    sarif = build_sarif(findings, policy_version=policy_version)
    problems = crosscheck(sarif, findings)
    if problems:
        raise SarifError("SARIF inconsistent with receipts: " + "; ".join(problems))
    out = Path(output)
    out.parent.mkdir(parents=True, exist_ok=True)
    tmp = out.with_name(f".{out.name}.tmp")
    tmp.write_text(
        json.dumps(sarif, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    tmp.replace(out)
    return sarif


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Export SARIF 2.1.0 from ReachGate receipts.",
    )
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT),
                        help="Output SARIF JSON path.")
    parser.add_argument("sources", nargs="*", default=list(DEFAULT_SOURCES),
                        help="Receipt artifact JSON files.")
    args = parser.parse_args(argv)
    sources = args.sources or list(DEFAULT_SOURCES)
    try:
        sarif = generate(sources=sources, output=Path(args.output))
    except SarifError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    results = sarif["runs"][0]["results"]
    counts: dict[str, int] = {}
    for r in results:
        lvl = r.get("level", "?")
        counts[lvl] = counts.get(lvl, 0) + 1
    summary = ", ".join(f"{k}={v}" for k, v in sorted(counts.items()))
    print(f"wrote {args.output} ({len(results)} results: {summary})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
