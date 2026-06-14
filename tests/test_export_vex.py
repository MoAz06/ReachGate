import json

import pytest

from tools import export_vex


def _cert(**over):
    base = {
        "frontier_exhausted": False,
        "api_errors": 0,
        "max_hops_hit": False,
        "visited_cap_hit": False,
        "timeout_hit": False,
    }
    base.update(over)
    return base


def _finding(verdict, **over):
    f = {
        "verdict": verdict,
        "verdict_basis": "x",
        "occurrence_id": "occ",
        "occurrence_name": "Some finding",
        "fingerprint": "fp123",
        "path": [],
        "certificate": _cert(),
    }
    f.update(over)
    return f


def test_reachable_maps_to_affected_with_action():
    f = _finding("REACHABLE", path=["File:a.js", "Definition:f"])
    stmt = export_vex.statement_for(f, "prod", "polv")
    assert stmt["status"] == "affected"
    assert "action_statement" in stmt
    assert "graph path" in stmt["action_statement"]


def test_exhaustive_not_reachable_maps_to_not_affected():
    f = _finding("NOT_REACHABLE", certificate=_cert(frontier_exhausted=True))
    stmt = export_vex.statement_for(f, "prod", "polv")
    assert stmt["status"] == "not_affected"
    assert stmt["justification"] == "vulnerable_code_not_in_execute_path"
    assert stmt["status_notes"]


def test_unknown_maps_to_under_investigation():
    f = _finding("UNKNOWN", verdict_basis="insufficient_evidence:no_definitions_indexed")
    stmt = export_vex.statement_for(f, "prod", "polv")
    assert stmt["status"] == "under_investigation"
    assert "not_affected" not in json.dumps(stmt)


@pytest.mark.parametrize("bound", ["max_hops_hit", "visited_cap_hit", "timeout_hit"])
def test_bounded_not_reachable_never_not_affected(bound):
    # The integrity invariant: a NOT_REACHABLE whose search hit a bound must
    # NOT become a clean VEX not_affected.
    f = _finding("NOT_REACHABLE", certificate=_cert(frontier_exhausted=True, **{bound: True}))
    stmt = export_vex.statement_for(f, "prod", "polv")
    assert stmt["status"] == "under_investigation"
    assert "justification" not in stmt


def test_api_error_not_reachable_never_not_affected():
    f = _finding("NOT_REACHABLE", certificate=_cert(frontier_exhausted=True, api_errors=2))
    stmt = export_vex.statement_for(f, "prod", "polv")
    assert stmt["status"] == "under_investigation"


def test_cve_is_extracted_for_vulnerability_name():
    f = _finding("UNKNOWN", vulnerable_file="gem/puma/CVE-2026-47736.yml")
    stmt = export_vex.statement_for(f, "prod", "polv")
    assert stmt["vulnerability"]["name"] == "CVE-2026-47736"


def test_document_has_required_openvex_fields():
    doc = export_vex.build_vex([_finding("REACHABLE")], policy_version="polv")
    for field in ("@context", "@id", "author", "timestamp", "version", "statements"):
        assert field in doc
    assert doc["@context"] == export_vex.OPENVEX_CONTEXT
    assert isinstance(doc["statements"], list) and doc["statements"]


def test_document_id_is_timestamp_independent():
    findings = [_finding("REACHABLE")]
    a = export_vex.build_vex(findings, policy_version="polv", timestamp="2020-01-01T00:00:00+00:00")
    b = export_vex.build_vex(findings, policy_version="polv", timestamp="2026-06-14T00:00:00+00:00")
    assert a["@id"] == b["@id"]
    assert a["timestamp"] != b["timestamp"]


def test_statements_dedupe_on_vuln_product_status():
    f1 = _finding("REACHABLE", occurrence_name="Dup")
    f2 = _finding("REACHABLE", occurrence_name="Dup")
    doc = export_vex.build_vex([f1, f2], policy_version="polv")
    assert len(doc["statements"]) == 1


def test_crosscheck_passes_for_consistent_document():
    findings = [
        _finding("REACHABLE", occurrence_name="R"),
        _finding("NOT_REACHABLE", occurrence_name="N", certificate=_cert(frontier_exhausted=True)),
        _finding("UNKNOWN", occurrence_name="U"),
    ]
    doc = export_vex.build_vex(findings, policy_version="polv")
    assert export_vex.crosscheck(doc, findings) == []


def test_crosscheck_flags_tampered_not_affected():
    findings = [_finding("UNKNOWN", occurrence_name="U")]
    doc = export_vex.build_vex(findings, policy_version="polv")
    doc["statements"][0]["status"] = "not_affected"  # tamper
    problems = export_vex.crosscheck(doc, findings)
    assert problems


def test_document_id_is_a_reachgate_urn():
    doc = export_vex.build_vex([_finding("REACHABLE")], policy_version="polv")
    assert doc["@id"].startswith("urn:reachgate:openvex:")


def test_generate_over_captured_proof_is_consistent(tmp_path):
    out = tmp_path / "reachgate.openvex.json"
    vex = export_vex.generate(output=out)
    assert out.exists()
    statuses = sorted(s["status"] for s in vex["statements"])
    assert statuses == ["affected", "not_affected", "under_investigation"]
    findings, _, _ = export_vex.load_findings(export_vex.DEFAULT_SOURCES)
    assert export_vex.crosscheck(vex, findings) == []


def test_generate_is_byte_stable_across_reruns(tmp_path):
    a = tmp_path / "a.json"
    b = tmp_path / "b.json"
    export_vex.generate(output=a)
    export_vex.generate(output=b)
    assert a.read_bytes() == b.read_bytes()
