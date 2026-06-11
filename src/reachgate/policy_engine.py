"""Deterministic weighted policy engine.

risk_score = sum of triggered rule weights.
The model never decides; it only explains the receipt.

Three verdicts:
  REACHABLE      — a graph path exists and the score crosses the threshold.
  NOT_REACHABLE  — the search ran to completion (frontier exhausted, no API
                   errors) and found no path. An exhaustive negative.
  UNKNOWN        — evidence was insufficient: missing location, nothing
                   indexed, no declared entry points, a search bound cut the
                   walk short, or an API call failed. Claiming NOT_REACHABLE
                   in any of those cases would be dishonest.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from .certificate import SearchCertificate, compute_fingerprint
from .graph_walker import ReachabilityResult


class Verdict(str, Enum):
    REACHABLE = "REACHABLE"
    NOT_REACHABLE = "NOT_REACHABLE"
    UNKNOWN = "UNKNOWN"


@dataclass
class TriggeredRule:
    name: str
    weight: int
    reason: str


@dataclass
class PolicyReceipt:
    verdict: Verdict
    risk_score: int
    triggered_rules: list[TriggeredRule]
    path: list[str]
    hops: int
    entry_point: str | None
    vulnerable_file: str | None
    vulnerable_definition: str | None
    occurrence_id: str | None
    occurrence_name: str | None
    severity: str | None
    verdict_basis: str = ""
    fingerprint: str = ""
    certificate: SearchCertificate | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict.value,
            "verdict_basis": self.verdict_basis,
            "risk_score": self.risk_score,
            "risk_breakdown": [
                {"rule": r.name, "weight": r.weight, "reason": r.reason}
                for r in self.triggered_rules
            ],
            "path": self.path,
            "hops": self.hops,
            "entry_point": self.entry_point,
            "vulnerable_file": self.vulnerable_file,
            "vulnerable_definition": self.vulnerable_definition,
            "occurrence_id": self.occurrence_id,
            "occurrence_name": self.occurrence_name,
            "severity": self.severity,
            "fingerprint": self.fingerprint,
            "certificate": self.certificate.as_dict() if self.certificate else None,
        }


# Rule weights. Adjust here; no code changes needed elsewhere.
_RULES: list[dict[str, Any]] = [
    {
        "name": "path_exists",
        "weight": 50,
        "condition": lambda r, occ: r.reachable,
        "reason": "A graph path exists from a declared entry point to the vulnerable definition.",
    },
    {
        "name": "direct_import",
        "weight": 20,
        "condition": lambda r, occ: r.reachable and r.hops <= 2,
        "reason": "Vulnerable code is directly or nearly directly imported (<=2 hops).",
    },
    {
        "name": "high_severity",
        "weight": 15,
        "condition": lambda r, occ: occ.get("severity") in ("critical", "high"),
        "reason": "Finding severity is critical or high.",
    },
    {
        "name": "medium_severity",
        "weight": 8,
        "condition": lambda r, occ: occ.get("severity") == "medium",
        "reason": "Finding severity is medium.",
    },
]

REACHABLE_THRESHOLD = 50


def _policy_version() -> str:
    """Stable hash of the rule set + threshold. Changes when policy changes."""
    canonical = json.dumps(
        {
            "rules": [{"name": r["name"], "weight": r["weight"]} for r in _RULES],
            "threshold": REACHABLE_THRESHOLD,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode()).hexdigest()[:12]


POLICY_VERSION = _policy_version()


def evaluate(
    result: ReachabilityResult,
    occurrence: dict[str, Any],
) -> PolicyReceipt:
    triggered: list[TriggeredRule] = []

    for rule in _RULES:
        try:
            if rule["condition"](result, occurrence):
                triggered.append(
                    TriggeredRule(
                        name=rule["name"],
                        weight=rule["weight"],
                        reason=rule["reason"] if callable(rule["reason"]) is False
                        else rule["reason"](result, occurrence),
                    )
                )
        except Exception:
            pass

    risk_score = sum(r.weight for r in triggered)

    if result.evidence_reason:
        verdict = Verdict.UNKNOWN
        verdict_basis = f"insufficient_evidence:{result.evidence_reason}"
    elif risk_score >= REACHABLE_THRESHOLD:
        verdict = Verdict.REACHABLE
        verdict_basis = "path_found"
    else:
        verdict = Verdict.NOT_REACHABLE
        verdict_basis = "no_path_search_exhaustive"

    certificate = result.certificate
    entrypoint_globs_hash = ""
    if certificate:
        certificate.policy_version = POLICY_VERSION
        entrypoint_globs_hash = certificate.entrypoint_globs_hash

    occurrence_id = occurrence.get("uuid") or str(occurrence.get("id", ""))
    severity = occurrence.get("severity")

    fingerprint = compute_fingerprint(
        occurrence_uuid=occurrence_id,
        occurrence_name=occurrence.get("name"),
        severity=severity,
        verdict=verdict.value,
        vulnerable_file=result.vulnerable_file,
        vulnerable_definition=result.vulnerable_definition,
        path=result.path,
        policy_version=POLICY_VERSION,
        entrypoint_globs_hash=entrypoint_globs_hash,
    )

    return PolicyReceipt(
        verdict=verdict,
        risk_score=risk_score,
        triggered_rules=triggered,
        path=result.path,
        hops=result.hops,
        entry_point=result.entry_point,
        vulnerable_file=result.vulnerable_file,
        vulnerable_definition=result.vulnerable_definition,
        occurrence_id=occurrence_id,
        occurrence_name=occurrence.get("name"),
        severity=severity,
        verdict_basis=verdict_basis,
        fingerprint=fingerprint,
        certificate=certificate,
    )
