"""Take GitLab actions based on a PolicyReceipt."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Any

import httpx

from .policy_engine import POLICY_VERSION, REACHABLE_THRESHOLD, PolicyReceipt, Verdict, _RULES

ARTIFACT_SCHEMA_VERSION = "1.0"
MARKER_VERSION = "v1"

# Hidden HTML-comment marker appended to each MR receipt. Carries ONLY the
# stable occurrence_key and the content fingerprint -- never any dynamic
# certificate metric -- so reruns can match and upsert deterministically.
_MARKER_RE = re.compile(
    r"<!--\s*reachgate:receipt:v1\s+"
    r"occurrence_key=(?P<occurrence_key>\S+)\s+"
    r"fingerprint=(?P<fingerprint>\S+)\s*-->"
)


def occurrence_key(receipt: PolicyReceipt) -> str:
    """Stable identity for a finding, independent of verdict/severity/path.

    Primary: sha256(occurrence_id). findings.py guarantees a non-empty
    occurrence_id, so this is the live path. If it is somehow empty, fall
    back to fields that exist on PolicyReceipt (name + vulnerable_file);
    if those are empty too, fail loudly rather than collapse identities.
    """
    occ_id = receipt.occurrence_id
    if occ_id:
        return hashlib.sha256(occ_id.encode()).hexdigest()[:16]
    name = receipt.occurrence_name or ""
    vuln_file = receipt.vulnerable_file or ""
    if not name and not vuln_file:
        raise ValueError("cannot derive occurrence_key: no id, name or file")
    canonical = f"{name}|{vuln_file}"
    return hashlib.sha256(canonical.encode()).hexdigest()[:16]


def build_marker(receipt: PolicyReceipt) -> str:
    return (
        f"<!-- reachgate:receipt:{MARKER_VERSION} "
        f"occurrence_key={occurrence_key(receipt)} "
        f"fingerprint={receipt.fingerprint} -->"
    )


def parse_marker(body: str) -> dict[str, str] | None:
    """Extract {occurrence_key, fingerprint} from a note body, or None."""
    if not body:
        return None
    m = _MARKER_RE.search(body)
    if not m:
        return None
    return {
        "occurrence_key": m.group("occurrence_key"),
        "fingerprint": m.group("fingerprint"),
    }


def render_mr_receipt(receipt: PolicyReceipt) -> str:
    """The Markdown receipt plus the hidden idempotency marker.

    render_receipt() is left untouched; the marker only exists in the MR
    wrapper so existing receipt tests are unaffected.
    """
    return f"{render_receipt(receipt)}\n\n{build_marker(receipt)}"


class GitLabActions:
    def __init__(self, gitlab_url: str, token: str, project_id: int | str):
        self._base = gitlab_url.rstrip("/")
        self._project_id = project_id
        self._headers = {"PRIVATE-TOKEN": token, "Content-Type": "application/json"}

    def _post(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        resp = httpx.post(
            f"{self._base}{path}",
            headers=self._headers,
            json=body,
            timeout=15,
        )
        resp.raise_for_status()
        return resp.json()

    def _get(self, path: str, params: dict[str, Any] | None = None) -> httpx.Response:
        # Returns the Response (not .json()) so callers can read pagination
        # headers like X-Next-Page.
        resp = httpx.get(
            f"{self._base}{path}",
            headers=self._headers,
            params=params,
            timeout=15,
        )
        resp.raise_for_status()
        return resp

    def _put(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        resp = httpx.put(
            f"{self._base}{path}",
            headers=self._headers,
            json=body,
            timeout=15,
        )
        resp.raise_for_status()
        return resp.json()

    def list_mr_notes(self, mr_iid: int) -> list[dict[str, Any]]:
        """All notes on an MR, following X-Next-Page pagination."""
        path = f"/api/v4/projects/{self._project_id}/merge_requests/{mr_iid}/notes"
        notes: list[dict[str, Any]] = []
        page = "1"
        while page:
            resp = self._get(path, params={"per_page": 100, "page": page})
            notes.extend(resp.json())
            page = resp.headers.get("X-Next-Page", "")
        return notes

    def upsert_mr_receipt(
        self, mr_iid: int, receipt: PolicyReceipt
    ) -> dict[str, Any]:
        """Create, update, or skip an MR receipt comment, keyed by the stable
        occurrence_key in the hidden marker. Idempotent across reruns:
        unchanged fingerprint -> no write; changed fingerprint -> update in
        place; multiple matches -> update the newest and warn (never delete).
        """
        key = occurrence_key(receipt)
        fp = receipt.fingerprint
        body = render_mr_receipt(receipt)
        notes_path = f"/api/v4/projects/{self._project_id}/merge_requests/{mr_iid}/notes"

        # Index existing notes by occurrence_key -> [notes] (keep duplicates).
        index: dict[str, list[dict[str, Any]]] = {}
        for note in self.list_mr_notes(mr_iid):
            marker = parse_marker(note.get("body") or "")
            if marker:
                index.setdefault(marker["occurrence_key"], []).append(note)

        matches = index.get(key, [])
        if not matches:
            created = self._post(notes_path, {"body": body})
            return {"action": "created", "occurrence_key": key,
                    "note_id": created.get("id")}

        # Newest match wins (highest note id).
        newest = max(matches, key=lambda n: n.get("id", 0))
        result: dict[str, Any] = {"occurrence_key": key, "note_id": newest.get("id")}
        if len(matches) > 1:
            result["warning"] = (
                f"{len(matches)} notes share occurrence_key {key}; "
                f"updated newest note {newest.get('id')}"
            )

        existing_marker = parse_marker(newest.get("body") or "")
        if existing_marker and existing_marker["fingerprint"] == fp:
            result["action"] = "unchanged"
            return result

        self._put(f"{notes_path}/{newest['id']}", {"body": body})
        result["action"] = "updated"
        return result

    def handle(self, receipt: PolicyReceipt, mr_iid: int | None = None) -> dict[str, Any]:
        if receipt.verdict == Verdict.REACHABLE:
            return self._escalate(receipt, mr_iid)
        elif receipt.verdict == Verdict.UNKNOWN:
            return self._flag_for_review(receipt, mr_iid)
        else:
            return self._deprioritize(receipt, mr_iid)

    def _escalate(self, receipt: PolicyReceipt, mr_iid: int | None) -> dict[str, Any]:
        body = self._receipt_comment(receipt)
        work_item = self._create_work_item(
            title=f"[ReachGate] Reachable: {receipt.occurrence_name}",
            description=body,
            labels=["reachgate::reachable", f"severity::{receipt.severity}"],
        )
        if mr_iid:
            self._post_mr_comment(mr_iid, body)
        return {"action": "escalated", "work_item": work_item}

    def _flag_for_review(self, receipt: PolicyReceipt, mr_iid: int | None) -> dict[str, Any]:
        # Insufficient evidence is not a verdict to act on automatically:
        # comment only, never close or escalate.
        if mr_iid:
            self._post_mr_comment(mr_iid, self._receipt_comment(receipt))
        return {"action": "needs_review"}

    def _deprioritize(self, receipt: PolicyReceipt, mr_iid: int | None) -> dict[str, Any]:
        body = self._receipt_comment(receipt)
        if mr_iid:
            self._post_mr_comment(mr_iid, body)
        return {"action": "deprioritized"}

    def _create_work_item(
        self, title: str, description: str, labels: list[str]
    ) -> dict[str, Any]:
        return self._post(
            f"/api/v4/projects/{self._project_id}/issues",
            {
                "title": title,
                "description": description,
                "labels": ",".join(labels),
            },
        )

    def _post_mr_comment(self, mr_iid: int, body: str) -> dict[str, Any]:
        return self._post(
            f"/api/v4/projects/{self._project_id}/merge_requests/{mr_iid}/notes",
            {"body": body},
        )

    def _receipt_comment(self, receipt: PolicyReceipt) -> str:
        return render_receipt(receipt)


_VERDICT_ICONS = {
    Verdict.REACHABLE: "🔴",
    Verdict.NOT_REACHABLE: "🟢",
    Verdict.UNKNOWN: "🟡",
}


def render_receipt(receipt: PolicyReceipt) -> str:
    """Render a PolicyReceipt as a Markdown comment (also used for previews)."""
    verdict_icon = _VERDICT_ICONS.get(receipt.verdict, "")
    path_str = " -> ".join(receipt.path) if receipt.path else "no path found"
    breakdown = "\n".join(
        f"- `{r.name}` (+{r.weight}): {r.reason}"
        for r in receipt.triggered_rules
    )

    lines = [
        "## ReachGate Triage Receipt",
        "",
        f"**Verdict:** {verdict_icon} `{receipt.verdict.value}`",
        f"**Basis:** `{receipt.verdict_basis}`" if receipt.verdict_basis else None,
        f"**Risk score:** {receipt.risk_score}",
        f"**Finding:** {receipt.occurrence_name} ({receipt.severity})",
        "",
        "### Graph path",
        "",
        render_mermaid_path(receipt),
        "",
        "```",
        path_str,
        "```",
    ]
    lines = [l for l in lines if l is not None]
    if receipt.path:
        lines.append(
            f"({receipt.hops} hop(s) from entry point `{receipt.entry_point}`)"
        )
    lines += [
        "",
        "### Rule breakdown",
        breakdown or "No rules triggered.",
    ]
    cert_block = render_certificate(receipt)
    if cert_block:
        lines += ["", cert_block]
    lines += [
        "",
        "<sub>Generated by ReachGate. "
        "Score = sum of rule weights, not a model confidence score.</sub>",
    ]
    return "\n".join(lines)


def render_certificate(receipt: PolicyReceipt) -> str:
    """Collapsible audit block: how the search ran, not just what it found."""
    cert = receipt.certificate
    if cert is None:
        return ""
    rows = [
        ("policy_version", f"`{cert.policy_version}`"),
        ("strategy", f"`{cert.strategy}` (max_hops={cert.max_hops}, "
                     f"max_visited={cert.max_visited}, max_seconds={cert.max_seconds})"),
        ("entry points checked", str(cert.entrypoints_checked)),
        ("target definitions indexed", str(cert.target_definitions_found)),
        ("nodes visited / API calls / cache hits",
         f"{cert.nodes_visited} / {cert.orbit_api_calls} / {cert.cache_hits}"),
        ("strategies attempted", ", ".join(cert.strategies_attempted) or "none"),
        ("evidence modes", ", ".join(cert.evidence_modes) or "none"),
        ("frontier exhausted", str(cert.frontier_exhausted).lower()),
        ("bounds hit (hops/visited/timeout)",
         f"{str(cert.max_hops_hit).lower()} / {str(cert.visited_cap_hit).lower()}"
         f" / {str(cert.timeout_hit).lower()}"),
        ("API errors", str(cert.api_errors)),
        ("attack surface hash", f"`{cert.entrypoint_globs_hash}`"),
    ]
    table = "\n".join(f"| {k} | {v} |" for k, v in rows)
    return "\n".join([
        f"<details><summary>🔏 Reachability certificate <code>{receipt.fingerprint}</code></summary>",
        "",
        "| field | value |",
        "|---|---|",
        table,
        "",
        "</details>",
    ])


_NODE_ICONS = {"File": "📄", "Definition": "ƒ", "ImportedSymbol": "📦"}


def _mermaid_label(node: str) -> str:
    """Turn a path entry like 'File:src/a.js' into an icon-prefixed label."""
    kind, _, name = node.partition(":")
    if name:
        icon = _NODE_ICONS.get(kind, "")
        label = f"{icon} {name}".strip()
    else:
        label = node
    # Mermaid labels break on quotes; the rest is safe inside quoted labels.
    return label.replace('"', "'")


def render_mermaid_path(receipt: PolicyReceipt) -> str:
    """Render the graph path as a Mermaid flowchart (GitLab renders these inline)."""
    lines = ["```mermaid", "flowchart LR"]
    if receipt.path:
        for i, node in enumerate(receipt.path):
            lines.append(f'    n{i}["{_mermaid_label(node)}"]')
        for i in range(len(receipt.path) - 1):
            lines.append(f"    n{i} --> n{i + 1}")
        last = len(receipt.path) - 1
        lines.append("    classDef entry fill:#1f6feb,color:#fff,stroke:none;")
        lines.append("    classDef vuln fill:#da3633,color:#fff,stroke:none;")
        lines.append("    class n0 entry;")
        if last > 0:
            lines.append(f"    class n{last} vuln;")
    else:
        entry = _mermaid_label(receipt.entry_point or "declared entry points")
        target = _mermaid_label(
            receipt.vulnerable_definition or receipt.vulnerable_file or "finding"
        )
        unknown = receipt.verdict == Verdict.UNKNOWN
        edge_label = "evidence insufficient" if unknown else "no path found"
        lines.append(f'    e["🚪 {entry}"]')
        lines.append(f'    v["ƒ {target}"]')
        lines.append(f"    e -. {edge_label} .- v")
        lines.append("    classDef entry fill:#1f6feb,color:#fff,stroke:none;")
        if unknown:
            lines.append("    classDef unknown fill:#bf8700,color:#fff,stroke:none;")
            lines.append("    class e entry;")
            lines.append("    class v unknown;")
        else:
            lines.append("    classDef safe fill:#2da44e,color:#fff,stroke:none;")
            lines.append("    class e entry;")
            lines.append("    class v safe;")
    lines.append("```")
    return "\n".join(lines)


def build_artifact(receipts: list[PolicyReceipt]) -> dict[str, Any]:
    """Machine-readable artifact: every receipt, full certificate, stable
    fingerprints. generated_at is metadata only and never part of any hash."""
    return {
        "schema_version": ARTIFACT_SCHEMA_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "policy": {
            "version": POLICY_VERSION,
            "threshold": REACHABLE_THRESHOLD,
            "rules": [{"name": r["name"], "weight": r["weight"]} for r in _RULES],
        },
        "findings": [r.as_dict() for r in receipts],
    }


def write_artifact(receipts: list[PolicyReceipt], path: str = "reachgate-receipts.json") -> str:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(build_artifact(receipts), f, indent=2, ensure_ascii=False)
    return path
