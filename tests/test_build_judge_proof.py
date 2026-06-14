import json

import pytest

from tools import build_judge_proof


def test_main_writes_temp_output(tmp_path):
    output = tmp_path / "judge-proof.html"

    assert build_judge_proof.main(["--output", str(output)]) == 0

    html = output.read_text(encoding="utf-8")
    assert "<html" in html
    assert "<body" in html
    assert "</html>" in html
    assert "REACHABLE" in html
    assert "NOT_REACHABLE" in html
    assert "UNKNOWN" in html
    assert "Generated from docs/proof/*.json" in html
    assert "Verify offline with python tools/verify_proof.py" in html
    assert "Verdicts proven" in html
    assert "MR !3 rerun" in html
    assert "path-flow" in html
    assert "configured bounds" in html
    assert "honest uncertainty" in html
    # wow-pass structure: flip band, colored graph nodes, collapsible evidence.
    assert "flip-card" in html
    assert "same MR" in html
    assert 'class="node entry"' in html
    assert 'class="node vuln"' in html
    assert "details class=\"evidence\"" in html
    # MR !2 and MR !3 share a fingerprint and must collapse to one card.
    assert "Reproduced in MR !2 + MR !3" in html
    assert html.count("Reproduced in MR !2 + MR !3") == 2
    # trust panels a judge actually reads first.
    assert "What it takes to earn each verdict" in html
    assert "Transparent policy" in html
    assert "risk_score = sum of triggered rule weights" in html
    assert "Verify it yourself" in html
    assert "nothing mocked" in html
    assert "+50" in html  # path_exists weight, shown in the policy table
    assert "<script src=" not in html
    assert "Mermaid" not in html
    assert "cdn" not in html.lower()


def test_output_contains_proof_fingerprints_and_mr_links(tmp_path):
    output = tmp_path / "judge-proof.html"
    proofs = build_judge_proof.load_proofs()
    fingerprints = {
        finding["fingerprint"]
        for proof in proofs
        for finding in proof["data"]["findings"]
    }

    assert build_judge_proof.main(["--output", str(output)]) == 0

    html = output.read_text(encoding="utf-8")
    for fingerprint in fingerprints:
        assert fingerprint in html
    assert build_judge_proof.MR2_URL in html
    assert build_judge_proof.MR3_URL in html


def _write_json(path, data):
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def test_validation_failure_does_not_write_output(tmp_path):
    output = tmp_path / "judge-proof.html"
    output.write_text("original", encoding="utf-8")
    bad_mr2 = {
        "schema_version": "1.0",
        "policy": {"version": "test-policy"},
        "findings": [],
    }
    proof_files = (
        ("mr2", "bad MR2", _write_json(tmp_path / "mr2.json", bad_mr2)),
        ("mr3", "bad MR3", _write_json(tmp_path / "mr3.json", bad_mr2)),
        ("unknown", "bad UNKNOWN", _write_json(tmp_path / "unknown.json", bad_mr2)),
    )

    with pytest.raises(build_judge_proof.ProofError):
        build_judge_proof.generate(output, proof_files=proof_files)

    assert output.read_text(encoding="utf-8") == "original"


def test_validation_reports_inconsistent_rerun_fingerprints():
    proof = {
        "key": "mr2",
        "label": "MR2",
        "filename": "mr2.json",
        "data": {
            "schema_version": "1.0",
            "policy": {"version": "test-policy"},
            "findings": [
                {
                    "occurrence_id": "one",
                    "verdict": "REACHABLE",
                    "verdict_basis": "path_found",
                    "fingerprint": "aaa",
                    "certificate": {
                        "policy_version": "test-policy",
                        "api_errors": 0,
                        "max_hops_hit": False,
                        "visited_cap_hit": False,
                        "timeout_hit": False,
                        "frontier_exhausted": False,
                    },
                },
                {
                    "occurrence_id": "two",
                    "verdict": "NOT_REACHABLE",
                    "verdict_basis": "no_path_search_exhaustive",
                    "fingerprint": "bbb",
                    "certificate": {
                        "policy_version": "test-policy",
                        "api_errors": 0,
                        "max_hops_hit": False,
                        "visited_cap_hit": False,
                        "timeout_hit": False,
                        "frontier_exhausted": True,
                    },
                },
            ],
        },
    }
    rerun = json.loads(json.dumps(proof))
    rerun["key"] = "mr3"
    rerun["filename"] = "mr3.json"
    rerun["data"]["findings"][0]["fingerprint"] = "changed"
    unknown = {
        "key": "unknown",
        "label": "UNKNOWN",
        "filename": "unknown.json",
        "data": {
            "schema_version": "1.0",
            "policy": {"version": "test-policy"},
            "findings": [
                {
                    "occurrence_id": "three",
                    "verdict": "UNKNOWN",
                    "verdict_basis": "insufficient_evidence",
                    "fingerprint": "ccc",
                    "certificate": {
                        "policy_version": "test-policy",
                        "api_errors": 0,
                        "max_hops_hit": False,
                        "visited_cap_hit": False,
                        "timeout_hit": False,
                        "frontier_exhausted": False,
                    },
                }
            ],
        },
    }

    with pytest.raises(build_judge_proof.ProofError, match="fingerprint"):
        build_judge_proof.validate_proofs([proof, rerun, unknown])
