"""Export OpenVEX from ReachGate reachability receipts.

ReachGate already produces a verifiable receipt per finding (verdict, graph
path, certificate, fingerprint). This turns those receipts into a
standards-aligned OpenVEX document so downstream supply-chain tooling can
consume the exploitability context machine-readably -- not just as an MR
comment.

The mapping is deliberately conservative, because a VEX ``not_affected`` tells
every downstream consumer to ignore a CVE:

  REACHABLE       -> affected            (+ action_statement)
  NOT_REACHABLE   -> not_affected        ONLY if the search was exhaustive
                     (justification: vulnerable_code_not_in_execute_path)
  UNKNOWN         -> under_investigation
  anything else, including a NOT_REACHABLE whose certificate shows a bound was
  hit or an API error occurred -> under_investigation, never not_affected.

That last rule is the whole point: ReachGate refuses to emit a clean VEX
``not_affected`` from a search that did not actually run to completion.

OpenVEX fit note: VEX is conventionally a CVE/component (SCA) artifact. CVE-
bearing findings map cleanly; SAST/CWE-style findings are carried as
vulnerability statements against the project as the product, which is honest
but not canonical SCA-VEX. This is "VEX export from reachability receipts",
not "universal VEX for every finding type".

Packaging note:
  This module is the canonical home of the OpenVEX export. ``tools/export_vex.py``
  is a thin shim re-exporting from here, so a repo checkout keeps working and a
  bare ``pip install`` gets the same logic. Default source/output paths resolve
  via :mod:`reachgate._resources`: ``docs/proof/`` in a checkout, the bundled
  package-data copy otherwise.

Standard library only. No network, no token, no dependencies.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

from . import _resources

PROOF_DIR = _resources.proof_dir()

# By default we build one document from the canonical captured proof: MR !2
# (REACHABLE + NOT_REACHABLE) plus the honest UNKNOWN receipt, so the output
# exercises all three VEX statuses.
DEFAULT_SOURCES = (
    PROOF_DIR / "mr2-reachgate-receipts.json",
    PROOF_DIR / "unknown-reachgate-receipt.json",
)
DEFAULT_OUTPUT = PROOF_DIR / "reachgate.openvex.json"
DEFAULT_PRODUCT = "https://gitlab.com/gitlab-ai-hackathon/transcend/39037247"

OPENVEX_CONTEXT = "https://openvex.dev/ns/v0.2.0"
DEFAULT_AUTHOR = "ReachGate"
JUSTIFICATION_NOT_IN_PATH = "vulnerable_code_not_in_execute_path"

AFFECTED = "affected"
NOT_AFFECTED = "not_affected"
UNDER_INVESTIGATION = "under_investigation"

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


class VexError(ValueError):
    """Raised when source receipts cannot be turned into VEX."""


def _cve_or_name(finding: dict) -> str:
    """Best vulnerability identifier for the statement.

    Prefer a real CVE id found in the finding (the SCA-style case VEX is built
    for); otherwise fall back to the finding name. Honest, not invented.
    """
    for field in (
        finding.get("vulnerable_file"),
        finding.get("occurrence_name"),
        finding.get("occurrence_id"),
    ):
        if field:
            m = _CVE_RE.search(str(field))
            if m:
                return m.group(0).upper()
    return str(
        finding.get("occurrence_name")
        or finding.get("occurrence_id")
        or "unknown-finding"
    )


def is_exhaustive(cert: dict) -> bool:
    """True only when the walk genuinely ran to completion: frontier emptied,
    no bound hit, no API error. This gates every ``not_affected``."""
    return (
        cert.get("frontier_exhausted") is True
        and int(cert.get("api_errors") or 0) == 0
        and cert.get("max_hops_hit") is False
        and cert.get("visited_cap_hit") is False
        and cert.get("timeout_hit") is False
    )


def _status_for(finding: dict) -> str:
    cert = finding.get("certificate") or {}
    verdict = finding.get("verdict")
    if verdict == "REACHABLE":
        return AFFECTED
    if verdict == "NOT_REACHABLE" and is_exhaustive(cert):
        return NOT_AFFECTED
    # UNKNOWN, or a NOT_REACHABLE whose search did not actually complete.
    return UNDER_INVESTIGATION


def statement_for(finding: dict, product_id: str, policy_version: str) -> dict:
    """One OpenVEX statement for a single ReachGate finding."""
    status = _status_for(finding)
    fp = finding.get("fingerprint") or "n/a"
    stmt: dict = {
        "vulnerability": {"name": _cve_or_name(finding)},
        "products": [{"@id": product_id}],
        "status": status,
    }
    if status == NOT_AFFECTED:
        stmt["justification"] = JUSTIFICATION_NOT_IN_PATH
        stmt["status_notes"] = (
            "ReachGate exhaustive graph search within configured bounds "
            "(frontier exhausted, 0 bounds hit, 0 API errors). "
            f"Reachability fingerprint {fp}; policy {policy_version}."
        )
    elif status == AFFECTED:
        path = finding.get("path") or []
        path_str = " -> ".join(path) if path else "declared entry point -> vulnerable definition"
        stmt["action_statement"] = (
            "ReachGate found a graph path from a declared entry point to the "
            f"vulnerable definition ({path_str}). Fingerprint {fp}. "
            "Triage and remediate."
        )
    else:  # under_investigation
        basis = finding.get("verdict_basis") or "insufficient_evidence"
        stmt["status_notes"] = (
            f"ReachGate could not complete the search: {basis}. Insufficient "
            "evidence -- not safe, and explicitly not NOT_REACHABLE. "
            f"Fingerprint {fp}; policy {policy_version}."
        )
    return stmt


def _document_id(author: str, product_id: str, statements: list[dict]) -> str:
    """Stable @id derived only from content (never the timestamp), so the same
    receipts always produce the same document id."""
    canonical = json.dumps(
        {"author": author, "product": product_id, "statements": statements},
        sort_keys=True,
        separators=(",", ":"),
    )
    digest = hashlib.sha256(canonical.encode()).hexdigest()[:16]
    # A URN, not an https IRI: the document does not live on openvex.dev, and a
    # stable content-addressed id is exactly the deterministic-evidence story.
    return f"urn:reachgate:openvex:{digest}"


def build_vex(
    findings: list[dict],
    *,
    product_id: str = DEFAULT_PRODUCT,
    author: str = DEFAULT_AUTHOR,
    policy_version: str = "",
    timestamp: str | None = None,
    version: int = 1,
) -> dict:
    """Build an OpenVEX document from ReachGate findings.

    De-duplicates on (vulnerability, product, status) so a finding seen in
    multiple captured runs yields a single statement. The timestamp is
    metadata only and never feeds the document @id.
    """
    statements: list[dict] = []
    seen: set[tuple[str, str, str]] = set()
    for finding in findings:
        stmt = statement_for(finding, product_id, policy_version)
        key = (stmt["vulnerability"]["name"], product_id, stmt["status"])
        if key in seen:
            continue
        seen.add(key)
        statements.append(stmt)

    from datetime import datetime, timezone
    ts = timestamp or datetime.now(timezone.utc).isoformat()
    return {
        "@context": OPENVEX_CONTEXT,
        "@id": _document_id(author, product_id, statements),
        "author": author,
        "timestamp": ts,
        "version": version,
        "tooling": f"ReachGate (policy {policy_version})" if policy_version else "ReachGate",
        "statements": statements,
    }


def crosscheck(vex: dict, findings: list[dict]) -> list[str]:
    """Confirm a VEX document is faithful to the receipts it came from.

    Returns a list of problems (empty == consistent). This is what lets the
    VEX export itself be falsifiable, in the same spirit as the receipts.
    """
    problems: list[str] = []
    statements = vex.get("statements") or []
    by_vuln = {
        (s.get("vulnerability") or {}).get("name"): s for s in statements
    }
    for finding in findings:
        name = _cve_or_name(finding)
        stmt = by_vuln.get(name)
        if stmt is None:
            problems.append(f"{name}: no VEX statement")
            continue
        expected = _status_for(finding)
        if stmt.get("status") != expected:
            problems.append(
                f"{name}: status {stmt.get('status')!r} != expected {expected!r}"
            )
        if stmt.get("status") == NOT_AFFECTED and not stmt.get("justification"):
            problems.append(f"{name}: not_affected without justification")
    # The integrity invariant, stated independently of the mapping above:
    # nothing whose search did not complete may be not_affected.
    for finding in findings:
        cert = finding.get("certificate") or {}
        if finding.get("verdict") != "NOT_REACHABLE" or not is_exhaustive(cert):
            name = _cve_or_name(finding)
            stmt = by_vuln.get(name)
            if stmt and stmt.get("status") == NOT_AFFECTED:
                problems.append(
                    f"{name}: not_affected but search was not exhaustive"
                )
    return problems


def _load_artifact(path: Path) -> dict:
    try:
        with Path(path).open(encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError as exc:
        raise VexError(f"{Path(path).name}: file not found") from exc
    except json.JSONDecodeError as exc:
        raise VexError(f"{Path(path).name}: invalid JSON ({exc})") from exc
    if not isinstance(data, dict):
        raise VexError(f"{Path(path).name}: top-level JSON must be an object")
    return data


def load_findings(paths) -> tuple[list[dict], str, str | None]:
    """Flatten findings across receipt artifacts.

    Returns (findings, policy_version, source_timestamp). source_timestamp is
    the latest ``generated_at`` across the source artifacts, so the exported
    document's timestamp tracks the evidence rather than wall-clock now() --
    re-running over unchanged receipts produces a byte-identical file.
    """
    findings: list[dict] = []
    policy_version = ""
    timestamps: list[str] = []
    for path in paths:
        data = _load_artifact(Path(path))
        policy_version = (data.get("policy") or {}).get("version") or policy_version
        gen = data.get("generated_at")
        if gen:
            timestamps.append(str(gen))
        items = data.get("findings")
        if not isinstance(items, list) or not items:
            raise VexError(f"{Path(path).name}: no findings")
        findings.extend(items)
    source_timestamp = max(timestamps) if timestamps else None
    return findings, policy_version, source_timestamp


def generate(
    sources=DEFAULT_SOURCES,
    output: Path = DEFAULT_OUTPUT,
    product_id: str = DEFAULT_PRODUCT,
    timestamp: str | None = None,
) -> dict:
    findings, policy_version, source_timestamp = load_findings(sources)
    vex = build_vex(
        findings,
        product_id=product_id,
        policy_version=policy_version,
        # Prefer an explicit timestamp, else the receipts' own generated_at, so
        # the committed proof file stays deterministic across reruns.
        timestamp=timestamp or source_timestamp,
    )
    problems = crosscheck(vex, findings)
    if problems:
        raise VexError("VEX inconsistent with receipts: " + "; ".join(problems))
    out = Path(output)
    out.parent.mkdir(parents=True, exist_ok=True)
    tmp = out.with_name(f".{out.name}.tmp")
    tmp.write_text(
        json.dumps(vex, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    tmp.replace(out)
    return vex


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Export OpenVEX from ReachGate receipts.",
    )
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT),
                        help="Output OpenVEX JSON path.")
    parser.add_argument("--product", default=DEFAULT_PRODUCT,
                        help="Product @id (project URL or purl).")
    parser.add_argument("--timestamp", default=None,
                        help="ISO timestamp; defaults to the receipts' "
                             "generated_at for a deterministic file.")
    parser.add_argument("sources", nargs="*", default=list(DEFAULT_SOURCES),
                        help="Receipt artifact JSON files.")
    args = parser.parse_args(argv)
    sources = args.sources or list(DEFAULT_SOURCES)
    try:
        vex = generate(sources=sources, output=Path(args.output),
                       product_id=args.product, timestamp=args.timestamp)
    except VexError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    counts: dict[str, int] = {}
    for s in vex["statements"]:
        counts[s["status"]] = counts.get(s["status"], 0) + 1
    summary = ", ".join(f"{k}={v}" for k, v in sorted(counts.items()))
    print(f"wrote {args.output} ({len(vex['statements'])} statements: {summary})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
