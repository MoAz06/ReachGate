"""JSON receipt artifact + certificate rendering in the Markdown receipt."""

import json

from src.reachgate.actions import (
    build_artifact,
    render_certificate,
    render_receipt,
    write_artifact,
)
from src.reachgate.certificate import SearchCertificate
from src.reachgate.policy_engine import (
    POLICY_VERSION,
    PolicyReceipt,
    TriggeredRule,
    Verdict,
)


def _receipt(verdict=Verdict.REACHABLE, certificate=None):
    return PolicyReceipt(
        verdict=verdict,
        risk_score=85,
        triggered_rules=[TriggeredRule(name="path_exists", weight=50, reason="x")],
        path=["File:src/a.js", "Definition:f"] if verdict == Verdict.REACHABLE else [],
        hops=1,
        entry_point="src/a.js",
        vulnerable_file="src/b.js",
        vulnerable_definition="f",
        occurrence_id="occ-1",
        occurrence_name="SSRF",
        severity="high",
        verdict_basis="path_found",
        fingerprint="abc123def4567890",
        certificate=certificate,
    )


def _cert():
    return SearchCertificate(
        policy_version=POLICY_VERSION, max_hops=6, max_visited=40,
        max_seconds=60, entrypoints_checked=2, target_definitions_found=27,
        nodes_visited=11, frontier_exhausted=False,
        strategies_attempted=["graph_edges"], evidence_modes=["graph_edges"],
        entrypoint_globs_hash="aabbcc", orbit_api_calls=18, cache_hits=5,
    )


def test_artifact_has_schema_and_policy_block():
    artifact = build_artifact([_receipt()])
    assert artifact["schema_version"] == "1.0"
    assert artifact["policy"]["version"] == POLICY_VERSION
    assert artifact["policy"]["threshold"] == 50
    assert any(r["name"] == "path_exists" for r in artifact["policy"]["rules"])


def test_artifact_contains_full_receipts():
    artifact = build_artifact([_receipt(certificate=_cert())])
    finding = artifact["findings"][0]
    assert finding["verdict"] == "REACHABLE"
    assert finding["fingerprint"] == "abc123def4567890"
    assert finding["certificate"]["bounds"]["max_hops"] == 6


def test_artifact_is_json_serializable_and_writable(tmp_path):
    path = tmp_path / "receipts.json"
    write_artifact([_receipt(certificate=_cert())], str(path))
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["findings"][0]["occurrence_id"] == "occ-1"


def test_render_certificate_collapsible_block():
    block = render_certificate(_receipt(certificate=_cert()))
    assert block.startswith("<details>")
    assert "abc123def4567890" in block
    assert "bounded-bfs-v1" in block
    assert "graph_edges" in block
    assert "strategies attempted" in block


def test_render_certificate_empty_without_certificate():
    assert render_certificate(_receipt()) == ""


def test_receipt_renders_unknown_with_yellow_icon():
    receipt = _receipt(verdict=Verdict.UNKNOWN)
    receipt.verdict_basis = "insufficient_evidence:bounds_hit"
    md = render_receipt(receipt)
    assert "🟡 `UNKNOWN`" in md
    assert "insufficient_evidence:bounds_hit" in md
    assert "evidence insufficient" in md  # mermaid edge label


def test_receipt_renders_basis_line():
    md = render_receipt(_receipt())
    assert "**Basis:** `path_found`" in md


def test_receipt_includes_certificate_block():
    md = render_receipt(_receipt(certificate=_cert()))
    assert "Reachability certificate" in md
