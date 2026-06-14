"""Build the offline ReachGate judge proof page from captured receipts.

Standard library only. No network, no token, no generated claims outside the
proof artifacts under docs/proof/.
"""

from __future__ import annotations

import argparse
import html
import json
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]

# Single source of truth for UNKNOWN guidance. guidance.py is pure stdlib (no
# third-party deps, no network), so importing it keeps this generator's
# "standard library only" property while avoiding a second, drift-prone copy.
sys.path.insert(0, str(REPO_ROOT / "src"))
from reachgate.guidance import guidance_for_basis  # noqa: E402
DEFAULT_OUTPUT = REPO_ROOT / "docs" / "judge-proof.html"

MR2_URL = (
    "https://gitlab.com/gitlab-ai-hackathon/transcend/39037247"
    "/-/merge_requests/2"
)
MR3_URL = (
    "https://gitlab.com/gitlab-ai-hackathon/transcend/39037247"
    "/-/merge_requests/3"
)

PROOF_FILES = (
    (
        "mr2",
        "MR !2 canonical proof",
        REPO_ROOT / "docs" / "proof" / "mr2-reachgate-receipts.json",
    ),
    (
        "mr3",
        "MR !3 idempotency rerun",
        REPO_ROOT / "docs" / "proof" / "mr3-reachgate-receipts-rerun.json",
    ),
    (
        "unknown",
        "UNKNOWN proof",
        REPO_ROOT / "docs" / "proof" / "unknown-reachgate-receipt.json",
    ),
)

VERDICT_ORDER = ("REACHABLE", "NOT_REACHABLE", "UNKNOWN")
VERDICT_COPY = {
    "REACHABLE": "urgent",
    "NOT_REACHABLE": "safe within configured bounds",
    "UNKNOWN": "honest uncertainty, not safe",
}


class ProofError(ValueError):
    """Raised when captured proof artifacts are missing required evidence."""


def _json(path: Path) -> dict:
    try:
        with path.open(encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError as exc:
        raise ProofError(f"{path.name}: file not found") from exc
    except json.JSONDecodeError as exc:
        raise ProofError(f"{path.name}: invalid JSON ({exc})") from exc
    if not isinstance(data, dict):
        raise ProofError(f"{path.name}: top-level JSON must be an object")
    return data


def load_proofs(proof_files=PROOF_FILES) -> list[dict]:
    proofs = []
    for key, label, path in proof_files:
        proofs.append({
            "key": key,
            "label": label,
            "filename": path.name,
            "data": _json(Path(path)),
        })
    return proofs


def _require(ok: bool, message: str) -> None:
    if not ok:
        raise ProofError(message)


def _required(mapping: dict, field: str, context: str):
    if field not in mapping or mapping[field] is None:
        raise ProofError(f"{context}: missing {field}")
    return mapping[field]


def _policy_version(proof: dict) -> str:
    data = proof["data"]
    policy = _required(data, "policy", proof["filename"])
    _require(isinstance(policy, dict),
             f"{proof['filename']}: policy must be an object")
    version = _required(policy, "version", proof["filename"])
    return str(version)


def _findings(proof: dict) -> list[dict]:
    findings = _required(proof["data"], "findings", proof["filename"])
    _require(isinstance(findings, list),
             f"{proof['filename']}: findings must be a list")
    _require(len(findings) > 0, f"{proof['filename']}: findings is empty")
    for i, finding in enumerate(findings):
        context = f"{proof['filename']} finding[{i}]"
        _require(isinstance(finding, dict), f"{context}: must be an object")
        for field in ("occurrence_id", "verdict", "verdict_basis",
                      "fingerprint", "certificate"):
            _required(finding, field, context)
        _require(isinstance(finding["certificate"], dict),
                 f"{context}: certificate must be an object")
    return findings


def _by_occurrence(proof: dict) -> dict[str, dict]:
    result = {}
    for finding in _findings(proof):
        occ = str(finding["occurrence_id"])
        _require(occ not in result,
                 f"{proof['filename']}: duplicate occurrence_id {occ}")
        result[occ] = finding
    return result


def _cert(finding: dict, proof: dict) -> dict:
    cert = finding["certificate"]
    context = f"{proof['filename']} {finding['occurrence_id']} certificate"
    for field in ("policy_version", "api_errors", "max_hops_hit",
                  "visited_cap_hit", "timeout_hit", "frontier_exhausted"):
        _required(cert, field, context)
    return cert


def _no_bounds_hit(cert: dict) -> bool:
    return (
        cert.get("max_hops_hit") is False
        and cert.get("visited_cap_hit") is False
        and cert.get("timeout_hit") is False
    )


def validate_proofs(proofs: list[dict]) -> None:
    by_key = {proof["key"]: proof for proof in proofs}
    for key in ("mr2", "mr3", "unknown"):
        _require(key in by_key, f"missing proof artifact key {key}")

    versions = set()
    for proof in proofs:
        data = proof["data"]
        _require(data.get("schema_version") == "1.0",
                 f"{proof['filename']}: schema_version must be 1.0")
        version = _policy_version(proof)
        versions.add(version)
        for finding in _findings(proof):
            cert = _cert(finding, proof)
            _require(
                str(cert["policy_version"]) == version,
                (
                    f"{proof['filename']} {finding['occurrence_id']}: "
                    "certificate policy_version differs from artifact policy"
                ),
            )

    _require(len(versions) == 1, "proof artifacts disagree on policy version")

    mr2 = by_key["mr2"]
    mr3 = by_key["mr3"]
    unknown = by_key["unknown"]
    mr2_findings = _by_occurrence(mr2)
    mr3_findings = _by_occurrence(mr3)

    _require(
        set(mr2_findings) == set(mr3_findings),
        "MR !2 and MR !3 occurrence ids differ",
    )

    for occurrence_id in sorted(mr2_findings):
        left = mr2_findings[occurrence_id]
        right = mr3_findings[occurrence_id]
        _require(
            left["fingerprint"] == right["fingerprint"],
            f"{occurrence_id}: fingerprint differs between MR !2 and MR !3",
        )
        _require(
            left["verdict"] == right["verdict"],
            f"{occurrence_id}: verdict differs between MR !2 and MR !3",
        )

    mr2_verdicts = {finding["verdict"] for finding in mr2_findings.values()}
    _require("REACHABLE" in mr2_verdicts, "MR !2 has no REACHABLE finding")
    _require(
        "NOT_REACHABLE" in mr2_verdicts,
        "MR !2 has no NOT_REACHABLE finding",
    )

    for proof in (mr2, mr3):
        for finding in _findings(proof):
            cert = _cert(finding, proof)
            context = f"{proof['filename']} {finding['occurrence_id']}"
            _require(cert["api_errors"] == 0,
                     f"{context}: api_errors must be 0")
            _require(_no_bounds_hit(cert),
                     f"{context}: search bounds must not be hit")
            if finding["verdict"] == "NOT_REACHABLE":
                _require(
                    cert["frontier_exhausted"] is True,
                    f"{context}: NOT_REACHABLE must be frontier_exhausted",
                )

    unknown_findings = _findings(unknown)
    _require(
        all(finding["verdict"] == "UNKNOWN" for finding in unknown_findings),
        f"{unknown['filename']}: every finding must be UNKNOWN",
    )
    for finding in unknown_findings:
        cert = _cert(finding, unknown)
        context = f"{unknown['filename']} {finding['occurrence_id']}"
        _require(cert["api_errors"] == 0,
                 f"{context}: api_errors must be 0")
        _require(_no_bounds_hit(cert),
                 f"{context}: search bounds must not be hit")
        _require(
            cert["frontier_exhausted"] is False,
            f"{context}: UNKNOWN must not claim exhaustive negative proof",
        )


def _e(value) -> str:
    if value is None:
        return "n/a"
    return html.escape(str(value), quote=True)


def _fmt_list(values) -> str:
    if not values:
        return "n/a"
    return ", ".join(_e(value) for value in values)


def _row(label: str, value) -> str:
    return f"<tr><th>{_e(label)}</th><td>{_e(value)}</td></tr>"


_NODE_ICONS = {
    "File": "▢", "Definition": "ƒ", "ImportedSymbol": "⇲",
    "entry": "◉", "target": "⌀",
}
_ROLE_TAG = {
    "entry": "attack surface",
    "mid": "hop",
    "vuln": "vulnerable def",
    "safe": "vulnerable def",
    "unknown": "vulnerable def",
}


def _node_chip(raw, role: str) -> str:
    """One node in the graph walk: a stacked kind/name plate, role-styled."""
    kind, _, name = str(raw).partition(":")
    if not name:
        kind, name = "node", str(raw)
    icon = _NODE_ICONS.get(role) or _NODE_ICONS.get(kind, "•")
    tag = _ROLE_TAG.get(role, kind)
    return (
        f'<li class="node {role}">'
        f'<span class="node-role">{_e(tag)}</span>'
        f'<span class="node-body">'
        f'<span class="node-icon" aria-hidden="true">{icon}</span>'
        f'<span class="node-name">{_e(name)}</span>'
        f"</span></li>"
    )


def _connector(found: bool, label: str = "") -> str:
    """Walk link. Found = a live flowing edge; none = a severed wall, so a
    no-path verdict reads as 'we walked and hit a wall', not an empty gap."""
    if found:
        return (
            '<li class="connector found" aria-hidden="true">'
            '<span class="wire"></span><span class="head">&#9654;</span></li>'
        )
    text = f'<span class="connector-label">{_e(label)}</span>' if label else ""
    return (
        '<li class="connector severed" aria-hidden="true">'
        '<span class="wire"></span><span class="cut">&#10005;</span>'
        f"{text}</li>"
    )


def _path_timeline(finding: dict) -> str:
    """The graph walk, rendered as the hero exhibit of each card.

    A real path becomes attack-surface(blue) -> ... -> vulnerable-def(red)
    with a live flowing edge, mirroring the Mermaid receipt in the README. A
    no-path verdict shows the same two endpoints joined by a SEVERED edge that
    names why the walk stopped, so NOT_REACHABLE / UNKNOWN read as evidence of
    an exhausted search, never as an empty box.
    """
    path = finding.get("path") or []
    verdict = finding.get("verdict")
    if path:
        items = []
        last = len(path) - 1
        for i, node in enumerate(path):
            role = "entry" if i == 0 else "vuln" if i == last else "mid"
            items.append(_node_chip(node, role))
            if i != last:
                items.append(_connector(found=True))
        return f"<ol class=\"path-flow found\">\n{''.join(items)}\n</ol>"

    entry = finding.get("entry_point") or "declared entry points"
    target = (
        finding.get("vulnerable_definition")
        or finding.get("vulnerable_file")
        or "finding"
    )
    if verdict == "UNKNOWN":
        edge, target_role = "evidence insufficient", "unknown"
    else:
        edge, target_role = "no path within bounds", "safe"
    items = [
        _node_chip(f"entry:{entry}", "entry"),
        _connector(found=False, label=edge),
        _node_chip(f"target:{target}", target_role),
    ]
    return f"<ol class=\"path-flow empty\">\n{''.join(items)}\n</ol>"


def _unknown_guidance_panel(finding: dict) -> str:
    """Typed, actionable panel for an UNKNOWN finding.

    Derived from the finding's verdict_basis via the shared guidance table --
    no new artifact fields. Makes UNKNOWN read as a typed evidence gap with a
    concrete next action, not a shrug. Returns "" for non-UNKNOWN verdicts.
    """
    if finding.get("verdict") != "UNKNOWN":
        return ""
    guidance = guidance_for_basis(finding.get("verdict_basis"))
    if guidance is None:
        return ""
    return f"""
<section class="unknown-panel">
  <p class="panel-label"><span>UNKNOWN / {_e(guidance.reason)}</span>
    <span class="flowtip">typed evidence gap</span></p>
  <p class="unknown-meaning">{_e(guidance.meaning)}</p>
  <p class="unknown-action"><strong>Next action</strong> {_e(guidance.next_action)}</p>
</section>
"""


def _summary_items(proofs: list[dict]) -> list[tuple[str, str, str]]:
    by_key = {proof["key"]: proof for proof in proofs}
    mr2_findings = _findings(by_key["mr2"])
    mr3_by_occurrence = _by_occurrence(by_key["mr3"])
    unknown_findings = _findings(by_key["unknown"])

    reachable = sum(1 for finding in mr2_findings
                    if finding["verdict"] == "REACHABLE")
    not_reachable = sum(1 for finding in mr2_findings
                        if finding["verdict"] == "NOT_REACHABLE")
    unknown = sum(1 for finding in unknown_findings
                  if finding["verdict"] == "UNKNOWN")
    same_fingerprints = all(
        finding["fingerprint"]
        == mr3_by_occurrence[finding["occurrence_id"]]["fingerprint"]
        for finding in mr2_findings
    )
    api_errors = sum(
        int(finding["certificate"].get("api_errors") or 0)
        for proof in proofs
        for finding in _findings(proof)
    )

    return [
        ("Verdicts proven", str(len(VERDICT_ORDER)),
         "red, green, and honest yellow"),
        ("Reachable", str(reachable),
         "path-backed finding in MR !2"),
        ("Not reachable", str(not_reachable),
         "exhaustive within configured bounds"),
        ("Unknown", str(unknown),
         "insufficient evidence, not fake-green"),
        ("MR !3 rerun", "same" if same_fingerprints else "changed",
         "fingerprints match MR !2"),
        ("API errors", str(api_errors),
         "across captured proof receipts"),
    ]


def _summary_strip(proofs: list[dict]) -> str:
    cards = []
    for label, value, detail in _summary_items(proofs):
        cards.append(f"""
<li>
  <span class="metric-label">{_e(label)}</span>
  <span class="metric-value">{_e(value)}</span>
  <span class="metric-detail">{_e(detail)}</span>
</li>
""")
    return f"<ul class=\"summary-strip\">\n{''.join(cards)}\n</ul>"


_VERDICT_ICON = {"REACHABLE": "🔴", "NOT_REACHABLE": "🟢", "UNKNOWN": "🟡"}

_SOURCE_LABEL = {
    "mr2": "MR !2",
    "mr3": "MR !3",
    "unknown": "captured UNKNOWN receipt",
}


def _reproduced_chip(entry: dict) -> str:
    """A trust chip stating where this exact fingerprint was reproduced."""
    sources = entry.get("sources") or [entry["key"]]
    if "mr2" in sources and "mr3" in sources:
        return (
            '<span class="repro" title="Same fingerprint in both runs">'
            "🔁 Reproduced in MR !2 + MR !3 · identical fingerprint</span>"
        )
    label = _SOURCE_LABEL.get(sources[0], sources[0])
    return f'<span class="repro mono">Captured in {_e(label)}</span>'


def _entry_html(entry: dict) -> str:
    finding = entry["finding"]
    cert = finding["certificate"]
    bounds = cert.get("bounds") or {}
    breakdown = finding.get("risk_breakdown") or []
    rules = ", ".join(
        _e(f"{rule.get('rule', 'n/a')} +{rule.get('weight', 'n/a')}")
        for rule in breakdown
    ) or "no rules triggered"

    evidence_rows = "".join([
        _row("frontier_exhausted", cert.get("frontier_exhausted")),
        _row("api_errors", cert.get("api_errors")),
        _row("max_hops_hit", cert.get("max_hops_hit")),
        _row("visited_cap_hit", cert.get("visited_cap_hit")),
        _row("timeout_hit", cert.get("timeout_hit")),
        _row("strategies_attempted", _fmt_list(cert.get("strategies_attempted"))),
        _row("evidence_modes", _fmt_list(cert.get("evidence_modes"))),
    ])

    summary_rows = "".join([
        _row("artifact", entry["filename"]),
        _row("occurrence_id", finding.get("occurrence_id")),
        _row("basis", finding.get("verdict_basis")),
        _row("fingerprint", finding.get("fingerprint")),
        _row("policy_version", cert.get("policy_version")),
        _row("risk_score", finding.get("risk_score")),
        _row("rule_breakdown", rules),
    ])

    certificate_rows = "".join([
        _row("strategy", cert.get("strategy")),
        _row("max_hops", bounds.get("max_hops")),
        _row("max_visited", bounds.get("max_visited")),
        _row("max_seconds", bounds.get("max_seconds")),
        _row("entrypoints_checked", cert.get("entrypoints_checked")),
        _row("target_definitions_found", cert.get("target_definitions_found")),
        _row("nodes_visited", cert.get("nodes_visited")),
        _row("orbit_api_calls", cert.get("orbit_api_calls")),
        _row("cache_hits", cert.get("cache_hits")),
        _row("entrypoint_globs_hash", cert.get("entrypoint_globs_hash")),
    ])

    verdict = str(finding.get("verdict", ""))
    verdict_class = _e(verdict.lower())
    severity = finding.get("severity")
    sev_chip = (
        f'<span class="sev sev-{_e(str(severity).lower())}">{_e(severity)}</span>'
        if severity else ""
    )
    exhibit = _e(entry.get("exhibit", ""))

    return f"""
<article class="entry {verdict_class}">
  <span class="stamp {verdict_class}">{_e(verdict)}</span>
  <header class="entry-head">
    <p class="exhibit-no">Exhibit {exhibit}</p>
    <h3>{_e(finding.get("occurrence_name"))}</h3>
    <div class="entry-tags">
      {sev_chip}
      <span class="basis mono">{_e(finding.get("verdict_basis"))}</span>
      {_reproduced_chip(entry)}
    </div>
  </header>
  <section class="path-panel {verdict_class}">
    <p class="panel-label"><span>attack surface</span>
      <span class="flowtip">walk</span><span>vulnerable definition</span></p>
    {_path_timeline(finding)}
    <p class="score-line">risk score
      <strong>{_e(finding.get("risk_score"))}</strong>
      <span class="mono">{rules}</span></p>
  </section>
  {_unknown_guidance_panel(finding)}
  <details class="evidence">
    <summary><span class="seal">&#9974;</span> certificate &amp; receipt
      <code>{_e(finding.get("fingerprint"))}</code></summary>
    <div class="grid">
      <section class="evidence-panel">
        <h4>Receipt</h4>
        <table>{summary_rows}</table>
      </section>
      <section class="evidence-panel">
        <h4>Evidence flags</h4>
        <table>{evidence_rows}</table>
      </section>
      <section class="evidence-panel">
        <h4>Certificate summary</h4>
        <table>{certificate_rows}</table>
      </section>
    </div>
  </details>
</article>
"""


def _proof_entries(proofs: list[dict]) -> list[dict]:
    entries = []
    artifact_order = {proof["key"]: i for i, proof in enumerate(proofs)}
    for proof in proofs:
        for finding in _findings(proof):
            entries.append({
                "key": proof["key"],
                "order": artifact_order[proof["key"]],
                "label": proof["label"],
                "filename": proof["filename"],
                "finding": finding,
            })
    return entries


def _dedupe_by_fingerprint(entries: list[dict]) -> list[dict]:
    """Collapse identical-fingerprint findings into one card, remembering
    every artifact it came from. MR !2 and MR !3 share a fingerprint by
    design, so this turns a redundant double-render into a single card that
    carries the idempotency story (sources = both runs)."""
    seen: dict[str, dict] = {}
    ordered: list[dict] = []
    for entry in entries:
        fp = str(entry["finding"].get("fingerprint"))
        if fp in seen:
            seen[fp]["sources"].append(entry["key"])
            continue
        entry["sources"] = [entry["key"]]
        seen[fp] = entry
        ordered.append(entry)
    return ordered


def _flip_band(entries: list[dict]) -> str:
    """The headline visual: one merge request, one Orbit graph, opposite
    verdicts. Pulls the live REACHABLE and NOT_REACHABLE finding names."""
    pick = {}
    for entry in entries:
        v = entry["finding"]["verdict"]
        if v in ("REACHABLE", "NOT_REACHABLE") and v not in pick:
            pick[v] = entry["finding"].get("occurrence_name") or v
    if "REACHABLE" not in pick or "NOT_REACHABLE" not in pick:
        return ""
    return f"""
<section class="flip">
  <article class="flip-card reachable">
    <span class="flip-tag">Exhibit A</span>
    <span class="flip-verdict">REACHABLE</span>
    <span class="flip-name">{_e(pick["REACHABLE"])}</span>
    <span class="flip-note">a graph path reaches it &mdash; escalate</span>
  </article>
  <div class="flip-vs">
    <span class="flip-vs-line">same MR</span>
    <span class="flip-vs-line">same graph</span>
    <span class="flip-vs-mark">&#8644;</span>
    <span class="flip-vs-line">opposite verdict</span>
  </div>
  <article class="flip-card not_reachable">
    <span class="flip-tag">Exhibit B</span>
    <span class="flip-verdict">NOT_REACHABLE</span>
    <span class="flip-name">{_e(pick["NOT_REACHABLE"])}</span>
    <span class="flip-note">frontier exhausted, no path &mdash; deprioritize</span>
  </article>
</section>
"""


def _logic_panel(proofs: list[dict]) -> str:
    """The differentiator, stated plainly: when ReachGate commits to a verdict
    and when it refuses to. Pulls the live UNKNOWN reason from the artifacts."""
    by_key = {p["key"]: p for p in proofs}
    unknown_reason = "insufficient evidence"
    for finding in _findings(by_key["unknown"]):
        basis = finding.get("verdict_basis") or ""
        unknown_reason = basis.split(":", 1)[-1] if ":" in basis else basis
        break
    return f"""
<section class="logic">
  <div class="section-head">
    <h2>What it takes to earn each verdict</h2>
    <p>The point is not that ReachGate answers. It is that it refuses to
    answer when the evidence is thin.</p>
  </div>
  <div class="logic-grid">
    <div class="logic-card reachable">
      <span class="lc-verdict">REACHABLE</span>
      <p>A graph path runs from a declared entry point to the vulnerable
      definition <strong>and</strong> the rule score crosses the threshold.</p>
      <span class="lc-foot">evidence: the path itself &mdash; escalate</span>
    </div>
    <div class="logic-card not_reachable">
      <span class="lc-verdict">NOT_REACHABLE</span>
      <p>Every walk emptied its frontier within bounds, with
      <strong>0 bounds hit</strong> and <strong>0 API errors</strong>. An
      exhaustive negative, not a shrug.</p>
      <span class="lc-foot">evidence: a completed search &mdash; deprioritize</span>
    </div>
    <div class="logic-card unknown">
      <span class="lc-verdict">UNKNOWN</span>
      <p>Anything less &mdash; no code location, a hit bound, an API error.
      Here: <code>{_e(unknown_reason)}</code>. Never dressed up as safe.</p>
      <span class="lc-foot">evidence: insufficient &mdash; flag for review</span>
    </div>
  </div>
</section>
"""


def _policy_panel(proofs: list[dict]) -> str:
    """Transparent, deterministic policy: the actual rule weights and the
    threshold, straight from the artifact. No model confidence anywhere."""
    policy = proofs[0]["data"].get("policy") or {}
    rules = policy.get("rules") or []
    threshold = policy.get("threshold")
    rows = "".join(
        f"<tr><td>{_e(r.get('name'))}</td>"
        f"<td class=\"w\">+{_e(r.get('weight'))}</td></tr>"
        for r in rules
    )
    return f"""
<section class="policy">
  <div class="section-head">
    <h2>Transparent policy &mdash; no model score</h2>
    <p><code>risk_score = sum of triggered rule weights</code>. The model never
    decides; it only explains the receipt.</p>
  </div>
  <table class="policy-table">
    <tr><th>rule</th><th class="w">weight</th></tr>
    {rows}
    <tr class="thr"><td>REACHABLE threshold</td><td class="w">&ge; {_e(threshold)}</td></tr>
  </table>
</section>
"""


def _verify_panel(proofs: list[dict]) -> str:
    """One-glance, self-serve trust: the exact assertions the offline verifier
    makes (derived from the artifacts, so they stay honest), plus the live
    GitLab links where a judge can see the receipts in situ."""
    by_key = {p["key"]: p for p in proofs}
    mr2 = _by_occurrence(by_key["mr2"])
    fps = ", ".join(sorted(f["fingerprint"] for f in mr2.values()))
    n_receipts = sum(len(_findings(p)) for p in proofs)
    api_calls = sum(
        int(f["certificate"].get("orbit_api_calls") or 0)
        for p in proofs for f in _findings(p)
    )
    unknown_reason = ""
    for finding in _findings(by_key["unknown"]):
        basis = finding.get("verdict_basis") or ""
        unknown_reason = basis.split(":", 1)[-1] if ":" in basis else basis
        break
    checks = [
        "MR !2: one REACHABLE path and one exhaustive NOT_REACHABLE certificate",
        f"MR !3 rerun: byte-identical fingerprints ({fps})",
        "NOT_REACHABLE: frontier exhausted, 0 bounds hit, 0 API errors",
        f"UNKNOWN: {unknown_reason} — not a fake-green NOT_REACHABLE",
        f"0 API errors across {n_receipts} captured receipts",
    ]
    items = "".join(f'<li><span class="tick">✓</span>{_e(c)}</li>' for c in checks)
    return f"""
<section class="verify">
  <div class="section-head">
    <h2>Verify it yourself</h2>
    <p>Standard library only, no token, offline. These checks run against the
    captured artifacts &mdash; the same files rendered on this page.</p>
  </div>
  <div class="cmd"><span class="caret">&rsaquo;</span> python tools/verify_proof.py</div>
  <ul class="checks">{items}</ul>
  <p class="cost">This proof cost <strong>{api_calls}</strong> live Orbit API
  calls across <strong>{n_receipts}</strong> findings. Live graph, nothing mocked.</p>
  <p class="verify-links">See the receipts in GitLab itself:
    <a href="{MR2_URL}">MR !2</a> &middot; <a href="{MR3_URL}">MR !3</a></p>
</section>
"""


def render_page(proofs: list[dict]) -> str:
    validate_proofs(proofs)
    entries = _proof_entries(proofs)
    entries.sort(key=lambda e: (
        VERDICT_ORDER.index(e["finding"]["verdict"])
        if e["finding"]["verdict"] in VERDICT_ORDER else 99,
        e["order"],
        str(e["finding"].get("occurrence_id")),
        str(e["finding"].get("fingerprint")),
    ))
    entries = _dedupe_by_fingerprint(entries)
    for i, entry in enumerate(entries):
        entry["exhibit"] = chr(ord("A") + i)

    version = _policy_version(proofs[0])
    summary = _summary_strip(proofs)
    flip = _flip_band(entries)
    logic = _logic_panel(proofs)
    policy = _policy_panel(proofs)
    verify = _verify_panel(proofs)
    sections = []
    for verdict in VERDICT_ORDER:
        verdict_entries = [
            entry for entry in entries if entry["finding"]["verdict"] == verdict
        ]
        if not verdict_entries:
            continue
        rendered = "\n".join(_entry_html(entry) for entry in verdict_entries)
        count = len(verdict_entries)
        sections.append(f"""
<section class="verdict {verdict.lower()}">
  <div class="verdict-head">
    <h2><span class="slash">&sect;</span>{_e(verdict)}</h2>
    <div class="verdict-meta">
      <span class="count">{count} exhibit{"s" if count != 1 else ""}</span>
      <strong>{_e(VERDICT_COPY[verdict])}</strong>
    </div>
  </div>
  {rendered}
</section>
""")

    sections_html = "\n".join(sections)
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>ReachGate Judge Proof</title>
  <style>
    /* Self-hosted, offline. Courier Prime (OFL) + Spectral (OFL), latin subset.
       Relative paths under docs/fonts/; system stack is the graceful fallback. */
    @font-face {{ font-family: "Courier Prime"; font-style: normal; font-weight: 400;
      font-display: swap; src: url("fonts/courier-prime-400.woff2") format("woff2"); }}
    @font-face {{ font-family: "Courier Prime"; font-style: normal; font-weight: 700;
      font-display: swap; src: url("fonts/courier-prime-700.woff2") format("woff2"); }}
    @font-face {{ font-family: "Spectral"; font-style: normal; font-weight: 700;
      font-display: swap; src: url("fonts/spectral-700.woff2") format("woff2"); }}
    @font-face {{ font-family: "Spectral"; font-style: normal; font-weight: 800;
      font-display: swap; src: url("fonts/spectral-800.woff2") format("woff2"); }}
    :root {{
      color-scheme: light;
      --paper: #f6f0e1;
      --paper2: #efe6d2;
      --paper3: #e8dcc2;
      --desk: #b3a888;
      --ink: #241d12;
      --ink2: #4a4030;
      --dim: #6c6049;
      --faint: #9a8c6d;
      --rule: #d6c9a9;
      --rule2: #c6b690;
      --red: #ad3320;
      --red2: #8a2616;
      --red-bg: #f0dfd4;
      --green: #3c6a44;
      --green-bg: #dde7d6;
      --amber: #8f6410;
      --amber-bg: #efe4c8;
      --radius: 3px;
      --radius-sm: 2px;
      --serif: "Spectral", "Iowan Old Style", "Palatino Linotype", Palatino, Georgia, "Times New Roman", serif;
      --mono: "Courier Prime", "Courier New", Courier, "Nimbus Mono PS", monospace;
    }}
    * {{ box-sizing: border-box; }}
    html {{ scroll-behavior: smooth; }}
    body {{
      margin: 0;
      font-family: var(--serif);
      color: var(--ink);
      line-height: 1.62;
      background-color: var(--desk);
      background-image:
        radial-gradient(rgba(0,0,0,.05) .5px, transparent .5px),
        radial-gradient(rgba(255,255,255,.06) .5px, transparent .5px);
      background-size: 5px 5px, 5px 5px;
      background-position: 0 0, 2.5px 2.5px;
      -webkit-font-smoothing: antialiased;
      text-rendering: optimizeLegibility;
    }}
    /* faint paper fiber, reused by every sheet via the .sheet mixin */
    .sheet {{
      background-color: var(--paper);
      background-image:
        repeating-linear-gradient(90deg, rgba(120,90,40,.022) 0 1px, transparent 1px 3px),
        repeating-linear-gradient(0deg, rgba(120,90,40,.018) 0 1px, transparent 1px 4px);
      border: 1px solid var(--rule2);
      box-shadow: 0 1px 0 rgba(255,255,255,.5) inset, 0 14px 28px -18px rgba(40,30,12,.7);
    }}
    h1, h2, h3, h4, p {{ margin-top: 0; }}
    a {{ color: var(--red); text-decoration: none; border-bottom: 1px solid rgba(173,51,32,.4); }}
    a:hover {{ border-bottom-color: var(--red); }}
    code, .mono {{ font-family: var(--mono); }}

    @keyframes rise {{ from {{ opacity: 0; transform: translateY(14px); }}
                       to {{ opacity: 1; transform: none; }} }}
    @keyframes stampin {{
      0% {{ opacity: 0; transform: rotate(-7deg) scale(1.6); }}
      70% {{ opacity: 1; transform: rotate(-7deg) scale(.94); }}
      100% {{ opacity: 1; transform: rotate(-7deg) scale(1); }}
    }}

    /* ---- cover sheet / letterhead ---- */
    header.hero {{ padding: 40px 24px 8px; }}
    .hero-inner {{
      max-width: 1040px; margin: 0 auto; position: relative; overflow: hidden;
      background-color: var(--paper);
      background-image:
        repeating-linear-gradient(90deg, rgba(120,90,40,.022) 0 1px, transparent 1px 3px),
        repeating-linear-gradient(0deg, rgba(120,90,40,.018) 0 1px, transparent 1px 4px);
      border: 1px solid var(--rule2);
      box-shadow: 0 1px 0 rgba(255,255,255,.5) inset, 0 22px 44px -22px rgba(40,30,12,.75);
    }}
    .hero-inner::before {{
      content: ""; position: absolute; left: 0; right: 0; top: 0; height: 6px;
      background: var(--red);
    }}
    .letterhead {{
      display: flex; align-items: center; gap: 16px; flex-wrap: wrap;
      padding: 20px 36px 14px; border-bottom: 1px solid var(--rule);
    }}
    .brand {{
      font-family: var(--serif); font-weight: 700; font-size: 1.35rem;
      letter-spacing: .02em; color: var(--ink);
    }}
    .file-meta {{
      font-family: var(--mono); font-size: .72rem; letter-spacing: .06em;
      text-transform: uppercase; color: var(--dim);
    }}
    .filed-stamp {{
      margin-left: auto; transform: rotate(-9deg);
      font-family: var(--mono); font-weight: 700; font-size: .82rem;
      letter-spacing: .16em; text-transform: uppercase; color: var(--red);
      border: 2px solid var(--red); border-radius: 4px; padding: 4px 12px;
      mix-blend-mode: multiply; opacity: .82;
    }}
    .classbar {{
      font-family: var(--mono); font-size: .64rem; letter-spacing: .26em;
      text-transform: uppercase; color: var(--paper);
      background: var(--ink); padding: 6px 36px;
    }}
    .hero-body {{ padding: 34px 36px 38px; }}
    .kicker {{
      font-family: var(--mono); font-size: .72rem; letter-spacing: .12em;
      text-transform: uppercase; color: var(--dim); margin-bottom: 18px;
      font-style: normal;
    }}
    h1 {{
      font-family: var(--serif); font-weight: 800;
      font-size: clamp(2.1rem, 4.8vw, 3.7rem);
      letter-spacing: -.01em; line-height: 1.06; margin-bottom: 18px; color: var(--ink);
    }}
    h1 .em {{ font-style: italic; color: var(--red); }}
    .hero p {{ max-width: 600px; color: var(--ink2); margin-bottom: 5px;
      font-family: var(--mono); font-size: .82rem; line-height: 1.75; }}
    .filed-via {{
      margin-top: 22px !important; padding: 11px 16px; display: inline-block;
      background: var(--paper3); border: 1px dashed var(--rule2);
      font-family: var(--mono); font-size: .82rem; color: var(--ink) !important;
    }}
    .filed-via .caret {{ color: var(--red); font-weight: 700; }}
    .meta {{ display: flex; flex-wrap: wrap; gap: 8px; margin-top: 24px; }}
    .pill {{
      border: 1px solid var(--rule2); background: var(--paper2);
      padding: 6px 13px; color: var(--ink);
      font-family: var(--mono); font-size: .74rem; border-radius: 0;
    }}
    a.pill {{ border-bottom: 1px solid var(--rule2); }}
    .pill.ver {{ color: var(--red); border-color: rgba(173,51,32,.5); }}
    a.pill:hover {{ border-color: var(--red); color: var(--red); }}

    main {{ max-width: 1040px; margin: 0 auto; padding: 24px 24px 24px; }}

    /* ---- summary ledger (docket strip) ---- */
    .summary-strip {{
      display: grid; grid-template-columns: repeat(6, 1fr); list-style: none;
      margin: 0 0 28px; padding: 0; overflow: hidden;
      background-color: var(--paper); border: 1px solid var(--rule2);
      box-shadow: 0 14px 28px -20px rgba(40,30,12,.7);
    }}
    .summary-strip li {{
      padding: 15px 16px 13px; border-right: 1px solid var(--rule);
      display: flex; flex-direction: column; gap: 3px;
    }}
    .summary-strip li:last-child {{ border-right: none; }}
    .metric-label {{
      font-family: var(--mono); font-size: .6rem; letter-spacing: .08em;
      text-transform: uppercase; color: var(--dim);
    }}
    .metric-value {{
      font-family: var(--serif); font-size: 1.95rem; line-height: 1.05;
      color: var(--ink); font-weight: 700;
    }}
    .metric-detail {{ font-size: .74rem; color: var(--ink2); line-height: 1.4; }}

    /* ---- flip exhibits (the contradiction) ---- */
    .flip {{
      display: grid; grid-template-columns: 1fr auto 1fr; gap: 0;
      align-items: stretch; margin: 0 0 34px; overflow: hidden;
      background-color: var(--paper); border: 1px solid var(--rule2);
      box-shadow: 0 16px 30px -20px rgba(40,30,12,.7);
    }}
    .flip-card {{
      padding: 24px 26px; display: flex; flex-direction: column; gap: 8px;
      position: relative;
    }}
    .flip-card.reachable {{ border-top: 5px solid var(--red); }}
    .flip-card.not_reachable {{ border-top: 5px solid var(--green); }}
    .flip-tag {{ font-family: var(--mono); font-size: .64rem; letter-spacing: .14em;
      text-transform: uppercase; color: var(--dim); }}
    .flip-verdict {{ font-family: var(--mono); font-weight: 700; font-size: 1.02rem;
      letter-spacing: .06em; }}
    .reachable .flip-verdict {{ color: var(--red); }}
    .not_reachable .flip-verdict {{ color: var(--green); }}
    .flip-name {{ font-family: var(--serif); font-size: 1.4rem; color: var(--ink);
      line-height: 1.22; font-style: italic; }}
    .flip-note {{ font-size: .85rem; color: var(--ink2); font-family: var(--mono); }}
    .flip-vs {{
      display: flex; flex-direction: column; align-items: center; justify-content: center;
      gap: 3px; padding: 0 20px; background: var(--paper3);
      border-left: 1px solid var(--rule); border-right: 1px solid var(--rule);
      font-family: var(--mono); font-size: .6rem; letter-spacing: .1em;
      text-transform: uppercase; color: var(--dim); text-align: center;
    }}
    .flip-vs-mark {{ font-size: 1.5rem; color: var(--red); margin: 5px 0; }}

    .lede {{
      font-family: var(--mono); font-size: .85rem; line-height: 1.8;
      max-width: 780px; margin: 0 0 36px; color: var(--ink2);
      border-left: 3px solid var(--red); padding: 2px 0 2px 16px;
    }}
    .lede strong {{ color: var(--ink); font-weight: 700; }}

    /* ---- shared section heads ---- */
    .section-head {{ margin: 0 0 16px; }}
    .section-head h2 {{
      font-family: var(--serif); font-size: 1.5rem; font-weight: 700;
      color: var(--ink); margin: 0 0 4px;
    }}
    .section-head p {{
      font-family: var(--mono); font-size: .8rem; color: var(--ink2);
      line-height: 1.6; max-width: 720px; margin: 0;
    }}

    /* ---- verdict-logic / integrity panel ---- */
    .logic {{ margin: 0 0 34px; }}
    .logic-grid {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 14px; }}
    .logic-card {{
      padding: 18px 18px 16px; background: var(--paper); border: 1px solid var(--rule2);
      border-top: 4px solid var(--rule2); display: flex; flex-direction: column; gap: 10px;
      box-shadow: 0 12px 24px -20px rgba(40,30,12,.7);
    }}
    .logic-card.reachable {{ border-top-color: var(--red); }}
    .logic-card.not_reachable {{ border-top-color: var(--green); }}
    .logic-card.unknown {{ border-top-color: var(--amber); }}
    .lc-verdict {{ font-family: var(--mono); font-weight: 700; font-size: .9rem;
      letter-spacing: .06em; }}
    .reachable .lc-verdict {{ color: var(--red); }}
    .not_reachable .lc-verdict {{ color: var(--green); }}
    .unknown .lc-verdict {{ color: var(--amber); }}
    .logic-card p {{ font-size: .92rem; line-height: 1.55; color: var(--ink); margin: 0; }}
    .logic-card code {{ font-family: var(--mono); font-size: .82rem; color: var(--amber);
      background: var(--amber-bg); padding: 1px 5px; }}
    .lc-foot {{ margin-top: auto; font-family: var(--mono); font-size: .66rem;
      letter-spacing: .04em; text-transform: uppercase; color: var(--dim); }}

    /* ---- policy + verify, side by feel ---- */
    .policy, .verify {{
      margin: 0 0 34px; padding: 22px 24px; background: var(--paper);
      border: 1px solid var(--rule2); box-shadow: 0 12px 24px -20px rgba(40,30,12,.7);
    }}
    .policy-table {{ width: 100%; max-width: 460px; border-collapse: collapse;
      margin-top: 14px; font-size: .86rem; }}
    .policy-table th {{ font-family: var(--mono); font-size: .64rem; text-transform: uppercase;
      letter-spacing: .1em; color: var(--dim); text-align: left; padding: 6px 0;
      border-bottom: 2px solid var(--ink); }}
    .policy-table td {{ font-family: var(--mono); font-size: .82rem; color: var(--ink);
      padding: 7px 0; border-bottom: 1px solid var(--rule); }}
    .policy-table .w {{ text-align: right; }}
    .policy-table .thr td {{ font-weight: 700; color: var(--red); border-bottom: none;
      padding-top: 11px; }}

    .cmd {{
      font-family: var(--mono); font-size: .86rem; color: var(--ink);
      background: var(--paper3); border: 1px dashed var(--rule2);
      padding: 11px 14px; margin: 4px 0 16px; display: inline-block;
    }}
    .cmd .caret {{ color: var(--red); font-weight: 700; }}
    .checks {{ list-style: none; margin: 0 0 14px; padding: 0;
      display: grid; gap: 8px; }}
    .checks li {{ font-family: var(--mono); font-size: .82rem; color: var(--ink);
      display: flex; gap: 10px; line-height: 1.5; }}
    .checks .tick {{ color: var(--green); font-weight: 700; flex: 0 0 auto; }}
    .cost {{ font-family: var(--mono); font-size: .82rem; color: var(--ink2);
      margin: 0 0 8px; }}
    .cost strong {{ color: var(--red); }}
    .verify-links {{ font-family: var(--mono); font-size: .82rem; color: var(--ink2); margin: 0; }}

    .exhibits-head {{ margin: 40px 0 18px; padding-top: 18px; border-top: 2px solid var(--ink); }}
    .exhibits-head h2 {{ font-family: var(--serif); font-size: 1.6rem; font-weight: 700;
      color: var(--ink); margin: 0 0 8px; }}
    .exhibits-head .lede {{ margin-bottom: 0; }}

    /* ---- findings section ---- */
    .verdict {{ margin: 0 0 38px; animation: rise .55s ease both; }}
    .verdict.reachable {{ animation-delay: .04s; }}
    .verdict.not_reachable {{ animation-delay: .12s; }}
    .verdict.unknown {{ animation-delay: .2s; }}
    .verdict-head {{
      display: flex; align-items: baseline; justify-content: space-between;
      gap: 16px; flex-wrap: wrap; padding-bottom: 10px; margin-bottom: 18px;
      border-bottom: 2px solid var(--ink);
    }}
    .verdict-head h2 {{
      font-family: var(--serif); font-size: 1.55rem; font-weight: 700;
      letter-spacing: .01em; margin: 0;
    }}
    .verdict-head .slash {{ color: var(--red); margin-right: 12px; font-weight: 700; }}
    .reachable .verdict-head h2 {{ color: var(--red); }}
    .not_reachable .verdict-head h2 {{ color: var(--green); }}
    .unknown .verdict-head h2 {{ color: var(--amber); }}
    .verdict-meta {{ display: flex; align-items: baseline; gap: 14px;
      font-family: var(--mono); font-size: .76rem; color: var(--ink2); }}
    .verdict-meta .count {{ color: var(--dim); }}

    /* ---- exhibit card ---- */
    .entry {{
      position: relative; margin: 0 0 22px; padding: 26px 24px 22px;
      background-color: var(--paper);
      background-image:
        repeating-linear-gradient(90deg, rgba(120,90,40,.02) 0 1px, transparent 1px 3px);
      border: 1px solid var(--rule2);
      box-shadow: 0 14px 26px -20px rgba(40,30,12,.7);
    }}
    .entry::before {{
      content: ""; position: absolute; left: 0; top: 0; bottom: 0; width: 5px;
    }}
    .entry.reachable::before {{ background: var(--red); }}
    .entry.not_reachable::before {{ background: var(--green); }}
    .entry.unknown::before {{ background: var(--amber); }}
    .stamp {{
      position: absolute; top: 20px; right: 20px; transform: rotate(-7deg);
      font-family: var(--mono); font-weight: 700; font-size: .82rem;
      letter-spacing: .1em; padding: 7px 13px; border-radius: 4px;
      border: 2.5px solid; background: transparent;
      mix-blend-mode: multiply; opacity: .85;
      box-shadow: 0 0 0 1px currentColor inset;
      animation: stampin .5s cubic-bezier(.2,1.4,.5,1) both;
    }}
    .stamp.reachable {{ color: var(--red); border-color: var(--red); animation-delay: .25s; }}
    .stamp.not_reachable {{ color: var(--green); border-color: var(--green); animation-delay: .3s; }}
    .stamp.unknown {{ color: var(--amber); border-color: var(--amber); animation-delay: .35s; }}
    .exhibit-no {{
      display: inline-block; font-family: var(--mono); font-size: .64rem;
      letter-spacing: .18em; text-transform: uppercase; color: var(--paper);
      background: var(--ink); padding: 4px 11px; margin-bottom: 14px;
    }}
    .entry-head {{ margin-bottom: 4px; padding-right: 130px; }}
    .entry-head h3 {{ font-family: var(--serif); font-size: 1.5rem; font-weight: 700;
      color: var(--ink); line-height: 1.22; margin: 0 0 13px; }}
    .entry-tags {{ display: flex; flex-wrap: wrap; gap: 8px; align-items: center; }}
    .basis {{ color: var(--dim); font-size: .74rem; }}
    .sev {{
      font-family: var(--mono); font-size: .62rem; font-weight: 700;
      text-transform: uppercase; letter-spacing: .06em; padding: 3px 9px;
      border-radius: 0; border: 1px solid currentColor;
    }}
    .sev-high, .sev-critical {{ color: var(--red); background: var(--red-bg); }}
    .sev-medium {{ color: var(--amber); background: var(--amber-bg); }}
    .sev-low {{ color: var(--green); background: var(--green-bg); }}
    .repro {{
      font-family: var(--mono); font-size: .68rem; color: var(--green);
      background: var(--green-bg); border: 1px solid rgba(60,106,68,.45);
      border-radius: 0; padding: 3px 10px;
    }}

    /* ---- attack-path exhibit ---- */
    .path-panel {{
      margin: 18px 0 4px; padding: 22px 18px 18px; position: relative;
      border: 1px solid var(--rule2); background: var(--paper2);
    }}

    /* ---- UNKNOWN: typed evidence gap, not a shrug ---- */
    .unknown-panel {{
      margin: 14px 0 4px; padding: 16px 18px;
      border: 1.5px dashed var(--amber); background: var(--amber-bg);
    }}
    .unknown-panel .panel-label .flowtip {{ color: var(--amber); }}
    .unknown-meaning {{ margin: 4px 0 10px; font-size: .96rem; }}
    .unknown-action {{ margin: 0; font-size: .92rem; color: var(--ink); }}
    .unknown-action strong {{
      display: inline-block; margin-right: 8px; font-family: var(--mono);
      font-size: .62rem; letter-spacing: .12em; text-transform: uppercase;
      color: var(--amber);
    }}
    .panel-label {{
      display: flex; gap: 10px; align-items: center; flex-wrap: wrap;
      font-family: var(--mono); font-size: .62rem; letter-spacing: .12em;
      text-transform: uppercase; color: var(--dim); margin-bottom: 20px;
    }}
    .panel-label .flowtip {{ color: var(--red); }}
    .panel-label .flowtip::before {{ content: "\\2014 "; }}
    .panel-label .flowtip::after {{ content: " \\2192"; }}
    .path-flow {{
      align-items: stretch; display: flex; flex-wrap: wrap; gap: 0;
      list-style: none; margin: 0; padding: 0;
    }}
    .node {{
      display: flex; flex-direction: column; gap: 8px; justify-content: center;
      padding: 14px 16px; min-width: 158px; background: var(--paper);
      border: 1.5px solid var(--ink); position: relative; z-index: 1;
    }}
    .node-role {{ font-family: var(--mono); font-size: .58rem; letter-spacing: .1em;
      text-transform: uppercase; color: var(--dim); }}
    .node-body {{ display: flex; align-items: center; gap: 9px; }}
    .node-icon {{ font-size: 1rem; line-height: 1; }}
    .node-name {{ font-family: var(--mono); font-size: .84rem; font-weight: 700;
      color: var(--ink); word-break: break-all; }}
    .node.entry {{ border-color: var(--ink); box-shadow: 4px 4px 0 rgba(36,29,18,.14); }}
    .node.entry .node-icon {{ color: var(--ink); }}
    .node.vuln {{ border-color: var(--red); background: var(--red-bg);
      box-shadow: 4px 4px 0 rgba(173,51,32,.18); }}
    .node.vuln .node-icon {{ color: var(--red); }}
    .node.vuln .node-name {{ color: var(--red2); }}
    .node.safe {{ border: 1.5px dashed var(--green); background: var(--green-bg); }}
    .node.safe .node-icon, .node.safe .node-role {{ color: var(--green); }}
    .node.unknown {{ border: 1.5px dashed var(--amber); background: var(--amber-bg); }}
    .node.unknown .node-icon, .node.unknown .node-role {{ color: var(--amber); }}
    .connector {{
      flex: 1 1 84px; min-width: 84px; min-height: 80px;
      display: flex; align-items: center; position: relative;
    }}
    .connector .wire {{ flex: 1; height: 0; border-top: 2px solid var(--ink); }}
    .connector.found .wire {{ border-top-style: solid; border-color: var(--ink); }}
    .connector.found .head {{ color: var(--red); font-size: 1rem; margin-left: -3px; }}
    .connector.severed .wire {{ border-top: 2px dashed var(--ink2); opacity: .6; }}
    .connector.severed .cut {{
      position: absolute; left: 50%; top: 50%; transform: translate(-50%,-50%) rotate(-6deg);
      width: 30px; height: 30px; border-radius: 50%; background: var(--paper);
      border: 2px solid var(--red); color: var(--red); font-weight: 700;
      display: flex; align-items: center; justify-content: center; font-size: .85rem;
      mix-blend-mode: multiply; opacity: .9;
    }}
    .connector-label {{
      position: absolute; left: 50%; top: calc(50% + 24px); transform: translateX(-50%);
      font-family: var(--mono); font-size: .6rem; letter-spacing: .04em;
      text-transform: uppercase; color: var(--red); white-space: nowrap;
    }}
    .score-line {{
      margin: 20px 0 0; font-family: var(--mono); font-size: .76rem; color: var(--ink2);
      display: flex; flex-wrap: wrap; gap: 8px; align-items: baseline;
    }}
    .score-line strong {{ color: var(--ink); font-size: 1.2rem; padding: 0 4px;
      font-family: var(--serif); }}

    /* ---- sealed certificate (collapsible) ---- */
    details.evidence {{
      margin-top: 16px; border: 1px solid var(--rule2); background: var(--paper2);
    }}
    details.evidence > summary {{
      cursor: pointer; padding: 12px 16px; font-family: var(--mono);
      font-size: .78rem; color: var(--ink); text-transform: uppercase; letter-spacing: .04em;
      list-style: none; display: flex; align-items: center; gap: 9px;
    }}
    details.evidence > summary::-webkit-details-marker {{ display: none; }}
    details.evidence > summary::before {{
      content: "[+]"; color: var(--red); font-weight: 700;
    }}
    details.evidence[open] > summary::before {{ content: "[\\2212]"; }}
    .seal {{ color: var(--red); }}
    details.evidence > summary code {{
      margin-left: auto; font-size: .72rem; color: var(--red); text-transform: none;
      background: var(--paper); border: 1px solid var(--rule2);
      padding: 2px 8px;
    }}
    details.evidence .grid {{ padding: 0 16px 16px; }}
    .grid {{
      display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
      gap: 14px; align-items: start;
    }}
    .evidence-panel {{
      border: 1px solid var(--rule); background: var(--paper); padding: 14px 16px;
    }}
    .evidence-panel h4 {{
      font-family: var(--mono); font-size: .62rem; text-transform: uppercase;
      letter-spacing: .1em; color: var(--dim); margin-bottom: 10px;
      border-bottom: 1px solid var(--rule); padding-bottom: 7px;
    }}
    table {{ width: 100%; border-collapse: collapse; font-size: .8rem; }}
    th, td {{ border-top: 1px solid var(--rule); padding: 7px 0; vertical-align: top; }}
    tr:first-child th, tr:first-child td {{ border-top: none; }}
    th {{ width: 42%; color: var(--dim); text-align: left; font-weight: 400;
      font-family: var(--mono); font-size: .7rem; padding-right: 12px; }}
    td {{ font-family: var(--mono); font-size: .74rem; color: var(--ink); word-break: break-word; }}

    footer {{
      max-width: 1040px; margin: 8px auto 0; padding: 18px 24px 56px;
      color: var(--ink2); font-family: var(--mono); font-size: .74rem;
      border-top: 2px solid var(--ink);
    }}

    @media (prefers-reduced-motion: reduce) {{
      * {{ animation: none !important; }}
    }}
    @media (max-width: 920px) {{
      .summary-strip {{ grid-template-columns: repeat(3, 1fr); }}
      .summary-strip li:nth-child(3) {{ border-right: none; }}
      .flip {{ grid-template-columns: 1fr; }}
      .flip-vs {{ flex-direction: row; gap: 10px; padding: 12px;
        border-left: none; border-right: none;
        border-top: 1px solid var(--rule); border-bottom: 1px solid var(--rule); }}
      .flip-vs-mark {{ transform: rotate(90deg); margin: 0; }}
    }}
    @media (max-width: 620px) {{
      .hero-body {{ padding: 26px 22px 28px; }}
      .letterhead, .classbar {{ padding-left: 22px; padding-right: 22px; }}
      .summary-strip {{ grid-template-columns: repeat(2, 1fr); }}
      .summary-strip li {{ border-right: none; border-bottom: 1px solid var(--rule); }}
      .entry-head {{ padding-right: 0; }}
      .logic-grid {{ grid-template-columns: 1fr; }}
      .stamp {{ position: static; display: inline-block; transform: rotate(-3deg); margin-bottom: 14px; }}
      .node, .connector {{ min-width: 100%; }}
      .connector {{ min-height: 50px; }}
    }}
  </style>
</head>
<body>
  <header class="hero">
    <div class="hero-inner">
      <div class="letterhead">
        <span class="brand">ReachGate</span>
        <span class="file-meta">Case File &middot; No. 39037247 &middot; Policy {_e(version)}</span>
        <span class="filed-stamp">Filed</span>
      </div>
      <div class="classbar">Evidence &mdash; reachability triage on GitLab Orbit</div>
      <div class="hero-body">
        <p class="kicker">In the matter of automated vulnerability triage</p>
        <h1>Every verdict is a graph path,<br>or its <span class="em">provable absence</span>.</h1>
        <p>Generated from docs/proof/*.json, not hand-written.</p>
        <p>Each exhibit below is a live receipt: the walk, the certificate, the fingerprint.</p>
        <p class="filed-via"><span class="caret">&rsaquo;</span>
          Verify offline with python tools/verify_proof.py</p>
        <div class="meta">
          <span class="pill ver">policy {_e(version)}</span>
          <a class="pill" href="{MR2_URL}">MR !2 canonical proof</a>
          <a class="pill" href="{MR3_URL}">MR !3 idempotency rerun</a>
        </div>
      </div>
    </div>
  </header>
  <main>
    {summary}
    {flip}
    {logic}
    {policy}
    {verify}
    <div class="exhibits-head">
      <h2>The exhibits</h2>
      <p class="lede"><strong>Read each like a receipt, not a brochure.</strong>
      REACHABLE means a path was found. NOT_REACHABLE means exhaustive within
      configured bounds. UNKNOWN means honest uncertainty, not safe.</p>
    </div>
    {sections_html}
  </main>
  <footer>
    The offline verifier remains the source of truth: python tools/verify_proof.py.
  </footer>
</body>
</html>
"""


def write_atomic(path: Path, content: str) -> None:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    tmp = output.with_name(f".{output.name}.tmp")
    tmp.write_text(content, encoding="utf-8")
    tmp.replace(output)


def generate(output: Path = DEFAULT_OUTPUT, proof_files=PROOF_FILES) -> None:
    proofs = load_proofs(proof_files)
    page = render_page(proofs)
    write_atomic(Path(output), page)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Build docs/judge-proof.html from ReachGate proof JSON.",
    )
    parser.add_argument(
        "--output",
        default=str(DEFAULT_OUTPUT),
        help="Output HTML path (default: docs/judge-proof.html)",
    )
    args = parser.parse_args(argv)
    try:
        generate(Path(args.output))
    except ProofError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"wrote {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
