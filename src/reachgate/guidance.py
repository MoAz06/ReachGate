"""Typed guidance for UNKNOWN verdicts.

ReachGate has three verdicts, but UNKNOWN is not a shrug: it is a typed
evidence gap with a deterministic next action. The engine already records WHY
the evidence was insufficient (graph_walker.REASON_*), surfaced on the receipt
as ``verdict_basis = "insufficient_evidence:<reason>"``.

This module is the single, static source of truth that turns that reason into
human-facing ``meaning`` + ``next_action`` copy. It is PRESENTATION ONLY:

  * It adds no engine logic and makes no decision -- the verdict and the reason
    are already fixed by the engine before this is consulted.
  * It is a pure lookup over the existing reason strings, so it never changes a
    verdict, a fingerprint, or the proof artifact schema.

Derive guidance from the receipt's ``verdict_basis`` (no new fields required):

    >>> guidance_for_basis("insufficient_evidence:no_definitions_indexed").meaning
    'Orbit indexed the file but no callable definition to walk to.'
"""

from __future__ import annotations

from dataclasses import dataclass

from .graph_walker import (
    REASON_API_ERROR,
    REASON_BELOW_MIN_HOPS,
    REASON_BOUNDS_HIT,
    REASON_NO_DEFINITIONS,
    REASON_NO_ENTRYPOINTS,
    REASON_NO_LOCATION,
)

INSUFFICIENT_EVIDENCE_PREFIX = "insufficient_evidence:"


@dataclass(frozen=True)
class ReasonGuidance:
    """Static, human-facing explanation of one UNKNOWN reason."""

    reason: str
    meaning: str
    next_action: str


# Single source of truth: every graph_walker.REASON_* must have an entry here.
# Keyed on the exact reason string the engine emits. SCA / dependency-style
# findings (an advisory with no indexed code anchor) deliberately map onto the
# existing no_definitions_indexed / no_location reasons -- we do NOT invent a
# new engine reason for the hackathon.
REASON_GUIDANCE: dict[str, ReasonGuidance] = {
    REASON_NO_LOCATION: ReasonGuidance(
        reason=REASON_NO_LOCATION,
        meaning="The finding carries no parseable code location to anchor a walk.",
        next_action=(
            "Provide a code-level finding with a file location, or treat a "
            "dependency/SCA advisory as advisory-only -- ReachGate will not "
            "call it safe without a code anchor."
        ),
    ),
    REASON_NO_DEFINITIONS: ReasonGuidance(
        reason=REASON_NO_DEFINITIONS,
        meaning="Orbit indexed the file but no callable definition to walk to.",
        next_action=(
            "Check Orbit indexing / language coverage for this file, or supply "
            "a code-level finding. Dependency/SCA findings with no reachable "
            "code definition stay UNKNOWN by design rather than fake-green."
        ),
    ),
    REASON_NO_ENTRYPOINTS: ReasonGuidance(
        reason=REASON_NO_ENTRYPOINTS,
        meaning="No declared entry-point glob resolved to an indexed File node.",
        next_action=(
            "Fix reachgate.yml entrypoints and re-run tools/reachgate_doctor.py; "
            "NOT_REACHABLE cannot be trusted while the attack surface is empty."
        ),
    ),
    REASON_BOUNDS_HIT: ReasonGuidance(
        reason=REASON_BOUNDS_HIT,
        meaning="A search bound (max_hops / node budget / timeout) cut the walk short.",
        next_action=(
            "Raise the relevant bound (policy.max_hops, max_visited, "
            "max_seconds) and re-run; the frontier was not exhausted, so no "
            "negative can be claimed."
        ),
    ),
    REASON_API_ERROR: ReasonGuidance(
        reason=REASON_API_ERROR,
        meaning="An Orbit query failed during the walk, so the evidence is incomplete.",
        next_action=(
            "Re-run once Orbit is healthy and GITLAB_TOKEN has api scope; a "
            "failed query proves nothing about reachability."
        ),
    ),
    REASON_BELOW_MIN_HOPS: ReasonGuidance(
        reason=REASON_BELOW_MIN_HOPS,
        meaning=(
            "A path WAS found but is shorter than the configured policy.min_hops."
        ),
        next_action=(
            "A found path proves reachability; lower policy.min_hops if such "
            "short paths should count as REACHABLE for your project."
        ),
    ),
}


def reason_from_basis(verdict_basis: str | None) -> str | None:
    """Extract the bare reason from a ``verdict_basis`` string.

    Returns the reason for an ``insufficient_evidence:<reason>`` basis, or None
    for any other basis (path_found / no_path_search_exhaustive / empty).
    """
    if not verdict_basis or not verdict_basis.startswith(INSUFFICIENT_EVIDENCE_PREFIX):
        return None
    return verdict_basis[len(INSUFFICIENT_EVIDENCE_PREFIX):]


def guidance_for_reason(reason: str | None) -> ReasonGuidance | None:
    """Static guidance for a bare reason string, or None if unknown."""
    if reason is None:
        return None
    return REASON_GUIDANCE.get(reason)


def guidance_for_basis(verdict_basis: str | None) -> ReasonGuidance | None:
    """Static guidance derived directly from a receipt's ``verdict_basis``."""
    return guidance_for_reason(reason_from_basis(verdict_basis))
