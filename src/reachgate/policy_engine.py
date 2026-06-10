"""Deterministic weighted policy engine.

risk_score = sum of triggered rule weights.
The model never decides; it only explains the receipt.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from .graph_walker import ReachabilityResult


class Verdict(str, Enum):
    REACHABLE = "REACHABLE"
    NOT_REACHABLE = "NOT_REACHABLE"


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

    def as_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict.value,
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
    verdict = Verdict.REACHABLE if risk_score >= REACHABLE_THRESHOLD else Verdict.NOT_REACHABLE

    return PolicyReceipt(
        verdict=verdict,
        risk_score=risk_score,
        triggered_rules=triggered,
        path=result.path,
        hops=result.hops,
        entry_point=result.entry_point,
        vulnerable_file=result.vulnerable_file,
        vulnerable_definition=result.vulnerable_definition,
        occurrence_id=occurrence.get("uuid") or str(occurrence.get("id", "")),
        occurrence_name=occurrence.get("name"),
        severity=occurrence.get("severity"),
    )
