"""Regression blame is a deterministic OVERLAP report, never a causation claim.

These tests pin: path-file extraction from receipt nodes, the set-intersection
with a changed-file list, the honest wording (overlap, never "introduced"),
path normalization, receipt loading, the deterministic git path, and the CLI.
"""

import json

import pytest

from src.reachgate import blame
from src.reachgate import cli


def _finding(verdict="REACHABLE", **over):
    f = {
        "verdict": verdict,
        "occurrence_id": "occ-1",
        "occurrence_name": "SSRF",
        "fingerprint": "fp-1",
        "path": ["File:app/routes/api.js", "Definition:handler"],
        "entry_point": "app/routes/api.js",
        "vulnerable_file": "app/services/fetch.js",
    }
    f.update(over)
    return f


# --- path file extraction --------------------------------------------------

def test_path_files_extracts_file_nodes_entry_and_vuln():
    files = blame.path_files(_finding())
    assert files == ["app/routes/api.js", "app/services/fetch.js"]


def test_path_files_ignores_non_file_nodes():
    f = _finding(path=["Definition:foo", "ImportedSymbol:bar"],
                 entry_point=None, vulnerable_file=None)
    assert blame.path_files(f) == []


def test_path_files_dedupes_and_sorts():
    f = _finding(path=["File:b.js", "File:a.js", "File:a.js"],
                 entry_point="b.js", vulnerable_file="a.js")
    assert blame.path_files(f) == ["a.js", "b.js"]


# --- blame intersection ----------------------------------------------------

def test_reachable_path_touched_when_changed_overlaps():
    report = blame.blame([_finding()], ["app/routes/api.js", "README.md"])
    r = report["findings"][0]
    assert r["touches_path"] is True
    assert r["reachable"] is True
    assert r["touched_files"] == ["app/routes/api.js"]
    assert report["summary"]["reachable_paths_touched"] == 1


def test_no_overlap_means_not_touched():
    report = blame.blame([_finding()], ["docs/CHANGELOG.md"])
    r = report["findings"][0]
    assert r["touches_path"] is False
    assert r["touched_files"] == []
    assert report["summary"]["reachable_paths_touched"] == 0


def test_non_reachable_finding_is_not_a_reachable_touch():
    f = _finding(verdict="NOT_REACHABLE")
    report = blame.blame([f], ["app/routes/api.js"])
    r = report["findings"][0]
    assert r["touches_path"] is True       # overlap still reported
    assert r["reachable"] is False         # but not a reachable-path touch
    assert report["summary"]["reachable_paths_touched"] == 0
    assert report["summary"]["paths_touched"] == 1


def test_changed_file_paths_are_normalized():
    # Backslash paths (Windows diff) still match forward-slash receipt paths.
    report = blame.blame([_finding()], ["app\\routes\\api.js"])
    assert report["findings"][0]["touches_path"] is True


def test_output_is_deterministic():
    findings = [_finding(occurrence_id="b"), _finding(occurrence_id="a")]
    one = blame.blame(findings, ["app/routes/api.js"])
    two = blame.blame(findings, ["app/routes/api.js"])
    assert blame.render_json(one) == blame.render_json(two)
    # sorted by occurrence_id
    ids = [r["occurrence_id"] for r in one["findings"]]
    assert ids == ["a", "b"]


# --- honesty: overlap, never causation -------------------------------------

def test_markdown_disclaims_causation():
    report = blame.blame([_finding()], ["app/routes/api.js"])
    md = blame.render_markdown(report, source="r.json")
    assert "overlap" in md.lower()
    assert "not" in md.lower() and "introduced" in md.lower()
    # The table marks a reachable-path touch, but the prose refuses causation.
    assert "reachable path" in md.lower()


def test_text_points_to_fixcheck_for_introduction():
    report = blame.blame([_finding()], ["app/routes/api.js"])
    txt = blame.render_text(report)
    assert "fixcheck" in txt
    assert "overlap" in txt.lower()


# --- receipt loading -------------------------------------------------------

def test_load_findings_from_receipt_dict(tmp_path):
    p = tmp_path / "r.json"
    p.write_text(json.dumps({"findings": [_finding()]}), encoding="utf-8")
    assert len(blame.load_findings(str(p))) == 1


def test_load_findings_from_bare_list(tmp_path):
    p = tmp_path / "r.json"
    p.write_text(json.dumps([_finding()]), encoding="utf-8")
    assert len(blame.load_findings(str(p))) == 1


def test_load_findings_missing_file_raises():
    with pytest.raises(blame.BlameError):
        blame.load_findings("does-not-exist.json")


def test_load_findings_invalid_json_raises(tmp_path):
    p = tmp_path / "r.json"
    p.write_text("{not json", encoding="utf-8")
    with pytest.raises(blame.BlameError):
        blame.load_findings(str(p))


# --- git path (deterministic: a ref against itself has no diff) -------------

def test_git_changed_files_same_ref_is_empty():
    # HEAD..HEAD is always empty; exercises the git path without depending on
    # working-tree state. Runs in this repo checkout.
    assert blame.git_changed_files("HEAD", "HEAD") == []


def test_git_changed_files_bad_ref_raises():
    with pytest.raises(blame.BlameError):
        blame.git_changed_files("definitely-not-a-ref-xyz", "HEAD")


# --- CLI -------------------------------------------------------------------

def test_cli_blame_with_changed_files(tmp_path, capsys):
    receipt = tmp_path / "r.json"
    receipt.write_text(json.dumps({"findings": [_finding()]}), encoding="utf-8")
    rc = cli.main(["blame", str(receipt), "--changed-files", "app/routes/api.js"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "reachable path" in out.lower()


def test_cli_blame_requires_an_input_source(tmp_path, capsys):
    receipt = tmp_path / "r.json"
    receipt.write_text(json.dumps({"findings": [_finding()]}), encoding="utf-8")
    rc = cli.main(["blame", str(receipt)])
    assert rc == 2
    assert "--changed-files" in capsys.readouterr().err


def test_cli_blame_on_captured_reachable_receipt(capsys):
    # The captured MR !2 REACHABLE finding walks through archives_redirect.js.
    rc = cli.main([
        "blame", "docs/proof/mr2-reachgate-receipts.json",
        "--changed-files", "content/frontend/404/archives_redirect.js",
        "--format", "json",
    ])
    assert rc == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["summary"]["reachable_paths_touched"] >= 1
