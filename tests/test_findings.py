"""Loading and normalizing findings from GitLab SAST and native JSON.

The engine consumes one occurrence shape; these tests pin the normalization
and the collision-proof identity that idempotent comments depend on.
"""

import json

import pytest

from src.reachgate.findings import (
    FindingsLoadError,
    derive_occurrence_id,
    load_findings,
    parse_findings,
)


def _sast(**kw):
    base = {
        "name": "SQL Injection",
        "severity": "High",
        "location": {"file": "src/db/query.py", "start_line": 12},
    }
    base.update(kw)
    return {"vulnerabilities": [base]}


def test_sast_report_parses_to_occurrence():
    occ = parse_findings(_sast(uuid="abc"))[0]
    assert occ["uuid"] == "abc"
    assert occ["name"] == "SQL Injection"
    # location is a JSON string carrying the file.
    loc = json.loads(occ["location"])
    assert loc["file"] == "src/db/query.py"


def test_native_top_level_list_parses():
    data = [{"uuid": "n1", "name": "XSS", "severity": "low",
             "location": {"file": "a.js"}}]
    occ = parse_findings(data)[0]
    assert occ["uuid"] == "n1"
    assert occ["name"] == "XSS"


def test_native_findings_wrapper_parses():
    data = {"findings": [{"uuid": "n2", "name": "SSRF", "severity": "high",
                          "location": {"file": "b.js"}}]}
    occ = parse_findings(data)[0]
    assert occ["uuid"] == "n2"


def test_location_object_becomes_json_string():
    occ = parse_findings(_sast())[0]
    assert isinstance(occ["location"], str)
    assert json.loads(occ["location"])["file"] == "src/db/query.py"


def test_native_location_json_string_passes_through():
    loc_str = json.dumps({"file": "c.js"})
    data = [{"uuid": "n3", "name": "x", "severity": "medium", "location": loc_str}]
    occ = parse_findings(data)[0]
    assert json.loads(occ["location"])["file"] == "c.js"


def test_severity_is_lowercased():
    occ = parse_findings(_sast(severity="CRITICAL"))[0]
    assert occ["severity"] == "critical"


def test_uuid_fallback_is_deterministic():
    # No uuid/id/fingerprint -> derived id, stable across calls.
    v = {"name": "X", "severity": "low", "location": {"file": "f.py", "start_line": 3}}
    a = parse_findings({"vulnerabilities": [dict(v)]})[0]["uuid"]
    b = parse_findings({"vulnerabilities": [dict(v)]})[0]["uuid"]
    assert a == b
    assert a == derive_occurrence_id("X", "f.py", 3)


def test_same_file_different_findings_get_distinct_ids():
    # HC3: two findings in the SAME file must never collapse to one identity.
    data = {"vulnerabilities": [
        {"name": "A", "severity": "high",
         "location": {"file": "same.py", "start_line": 10}},
        {"name": "B", "severity": "high",
         "location": {"file": "same.py", "start_line": 99}},
    ]}
    occs = parse_findings(data)
    assert occs[0]["uuid"] != occs[1]["uuid"]


def test_invalid_json_raises_findings_load_error(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text("{not valid json", encoding="utf-8")
    with pytest.raises(FindingsLoadError):
        load_findings(str(p))


def test_unknown_shape_raises_findings_load_error():
    with pytest.raises(FindingsLoadError):
        parse_findings({"something_else": 1})


def test_missing_location_is_not_dropped():
    # A finding with no file is kept (engine will return UNKNOWN/no_location),
    # never silently discarded.
    data = [{"uuid": "n4", "name": "no-loc", "severity": "high"}]
    occs = parse_findings(data)
    assert len(occs) == 1
    assert occs[0]["uuid"] == "n4"
    # location has no file -> engine's extract returns None -> no_location.
    loc = json.loads(occs[0]["location"])
    assert "file" not in loc


def test_load_findings_reads_file(tmp_path):
    p = tmp_path / "findings.json"
    p.write_text(json.dumps(_sast(uuid="z")), encoding="utf-8")
    occs = load_findings(str(p))
    assert occs[0]["uuid"] == "z"
