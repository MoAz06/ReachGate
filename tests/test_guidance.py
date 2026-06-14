"""UNKNOWN is a typed evidence gap, not a shrug.

These tests pin the static guidance mapping and its presentation surfaces:
  * every engine REASON_* has guidance (so a future reason cannot ship without
    operator-facing meaning + next_action);
  * guidance is derived from verdict_basis, with no new artifact fields;
  * the Markdown receipt renders a prominent, actionable UNKNOWN block.
"""

import importlib

import pytest

from src.reachgate import graph_walker
from src.reachgate.actions import render_receipt, render_unknown_guidance
from src.reachgate.guidance import (
    REASON_GUIDANCE,
    guidance_for_basis,
    guidance_for_reason,
    reason_from_basis,
)
from src.reachgate.policy_engine import (
    PolicyReceipt,
    TriggeredRule,
    Verdict,
)

# Every constant named REASON_* in graph_walker, discovered dynamically so a
# new engine reason that lacks guidance fails this test loudly.
ALL_REASONS = [
    value
    for name, value in vars(graph_walker).items()
    if name.startswith("REASON_") and isinstance(value, str)
]


def _unknown_receipt(basis):
    return PolicyReceipt(
        verdict=Verdict.UNKNOWN,
        risk_score=0,
        triggered_rules=[TriggeredRule(name="x", weight=0, reason="x")],
        path=[],
        hops=0,
        entry_point="src/a.py",
        vulnerable_file="src/b.py",
        vulnerable_definition=None,
        occurrence_id="occ-1",
        occurrence_name="Dependency advisory",
        severity="high",
        verdict_basis=basis,
        fingerprint="abc123def4567890",
    )


def test_every_engine_reason_has_guidance():
    assert ALL_REASONS, "expected to discover REASON_* constants"
    missing = [r for r in ALL_REASONS if r not in REASON_GUIDANCE]
    assert not missing, f"reasons without guidance: {missing}"


def test_no_stale_guidance_entries():
    # Guidance must not reference reasons the engine no longer emits.
    extra = [r for r in REASON_GUIDANCE if r not in ALL_REASONS]
    assert not extra, f"guidance for unknown reasons: {extra}"


def test_guidance_entries_are_nonempty():
    for reason, g in REASON_GUIDANCE.items():
        assert g.reason == reason
        assert g.meaning.strip()
        assert g.next_action.strip()


def test_reason_from_basis_only_for_insufficient_evidence():
    assert reason_from_basis("insufficient_evidence:no_location") == "no_location"
    assert reason_from_basis("path_found") is None
    assert reason_from_basis("no_path_search_exhaustive") is None
    assert reason_from_basis("") is None
    assert reason_from_basis(None) is None


def test_guidance_for_basis_round_trips():
    basis = "insufficient_evidence:no_definitions_indexed"
    g = guidance_for_basis(basis)
    assert g is not None
    assert g.reason == "no_definitions_indexed"
    assert g is guidance_for_reason("no_definitions_indexed")


def test_guidance_for_unknown_reason_is_none():
    assert guidance_for_basis("insufficient_evidence:made_up_reason") is None


@pytest.mark.parametrize("reason", ALL_REASONS)
def test_receipt_renders_actionable_unknown_block(reason):
    basis = f"insufficient_evidence:{reason}"
    receipt = _unknown_receipt(basis)
    block = render_unknown_guidance(receipt)
    g = REASON_GUIDANCE[reason]
    assert reason in block
    assert g.meaning in block
    assert g.next_action in block
    assert "Next action" in block
    # And it appears in the full receipt.
    md = render_receipt(receipt)
    assert g.next_action in md
    assert "UNKNOWN" in md


def test_non_unknown_receipt_has_no_guidance_block():
    receipt = _unknown_receipt("path_found")
    receipt.verdict = Verdict.REACHABLE
    assert render_unknown_guidance(receipt) == ""


def test_sca_narrative_maps_onto_existing_reasons_not_a_new_one():
    # The dependency/SCA story is carried by the existing reasons, so no new
    # engine reason was introduced for it.
    for reason in ("no_definitions_indexed", "no_location"):
        g = REASON_GUIDANCE[reason]
        assert "advisory" in g.next_action.lower() or "sca" in g.next_action.lower()
    assert "dependency_advisory_without_code_anchor" not in REASON_GUIDANCE
