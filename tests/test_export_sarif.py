"""SARIF export is a faithful, falsifiable view of the receipts.

These tests pin the SARIF 2.1.0-shaped export: it runs, is valid JSON, covers
all three verdicts, carries receipt fingerprints, turns a REACHABLE path into
a codeFlow, frames UNKNOWN as a typed evidence gap (never safe), keeps the
NOT_REACHABLE configured-bounds wording, and is byte-stable across reruns.
"""

import json

import pytest

from tools import export_sarif


def _load_sources():
    findings, policy_version = export_sarif.load_findings(
        export_sarif.DEFAULT_SOURCES
    )
    return findings, policy_version


def test_exporter_runs_and_writes(tmp_path):
    out = tmp_path / "reachgate.sarif.json"
    assert export_sarif.main(["--output", str(out)]) == 0
    assert out.exists()


def test_output_is_valid_json_and_sarif_shaped(tmp_path):
    out = tmp_path / "reachgate.sarif.json"
    export_sarif.main(["--output", str(out)])
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["version"] == "2.1.0"
    assert "$schema" in doc
    assert isinstance(doc["runs"], list) and doc["runs"]
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "ReachGate"
    assert isinstance(run["results"], list) and run["results"]


def test_contains_all_three_verdicts():
    findings, _ = _load_sources()
    doc = export_sarif.build_sarif(findings)
    levels = {r["level"] for r in doc["runs"][0]["results"]}
    # error=REACHABLE, note=NOT_REACHABLE, warning=UNKNOWN
    assert levels == {"error", "note", "warning"}


def test_contains_receipt_fingerprints():
    findings, _ = _load_sources()
    doc = export_sarif.build_sarif(findings)
    fps_in = {f["fingerprint"] for f in findings}
    fps_out = {
        (r.get("partialFingerprints") or {}).get("reachgateFingerprint")
        for r in doc["runs"][0]["results"]
    }
    assert fps_in <= fps_out


def test_reachable_path_becomes_codeflow():
    findings, _ = _load_sources()
    doc = export_sarif.build_sarif(findings)
    reachable = [
        r for r in doc["runs"][0]["results"] if r["level"] == "error"
    ]
    assert reachable
    for r in reachable:
        assert r.get("codeFlows"), "REACHABLE with a path must have a codeFlow"
        tflows = r["codeFlows"][0]["threadFlows"]
        assert tflows and tflows[0]["locations"]


def test_unknown_includes_typed_guidance():
    findings, _ = _load_sources()
    doc = export_sarif.build_sarif(findings)
    unknown = [r for r in doc["runs"][0]["results"] if r["level"] == "warning"]
    assert unknown
    for r in unknown:
        text = r["message"]["text"]
        assert "UNKNOWN /" in text
        assert "Next action:" in text
        assert "evidence gap" in text


def test_not_reachable_includes_configured_bounds_wording():
    findings, _ = _load_sources()
    doc = export_sarif.build_sarif(findings)
    notes = [r for r in doc["runs"][0]["results"] if r["level"] == "note"]
    assert notes
    for r in notes:
        assert export_sarif.NOT_REACHABLE_WORDING in r["message"]["text"]


def test_no_fake_green_unknown():
    findings, _ = _load_sources()
    doc = export_sarif.build_sarif(findings)
    for r in doc["runs"][0]["results"]:
        if r["level"] == "warning":
            text = r["message"]["text"].lower()
            assert "is safe" not in text
            assert "not_affected" not in text


def test_byte_stable_output(tmp_path):
    a = tmp_path / "a.sarif.json"
    b = tmp_path / "b.sarif.json"
    export_sarif.main(["--output", str(a)])
    export_sarif.main(["--output", str(b)])
    assert a.read_bytes() == b.read_bytes()


def test_crosscheck_is_clean_for_real_receipts():
    findings, _ = _load_sources()
    doc = export_sarif.build_sarif(findings)
    assert export_sarif.crosscheck(doc, findings) == []


def test_no_invented_locations():
    """A finding with no vulnerable_file must not get a primary location."""
    finding = {
        "verdict": "UNKNOWN",
        "verdict_basis": "insufficient_evidence:no_location",
        "fingerprint": "deadbeefdeadbeef",
        "occurrence_name": "loc-less finding",
        "path": [],
        "certificate": {"policy_version": "x"},
    }
    result = export_sarif.result_for(finding)
    assert "locations" not in result
    assert "codeFlows" not in result
