"""The Evidence Contract is machine-checkable, not just docs.

These tests pin `reachgate contract-check`: the captured receipts pass, a
NOT_REACHABLE that did not run to completion FAILS (it must not overclaim a
safe-within-bounds negative), UNKNOWN always reads as an evidence gap (never
safe), malformed receipts produce a clean diagnostic rather than a traceback,
and the CLI honours text/json/markdown + --output without touching tracked
artifacts.

Synthetic receipts here are SYNTHETIC TEST FIXTURES built in-process; they are
not proof artifacts and never touch docs/proof/.
"""

import json

import pytest

from src.reachgate import cli
from src.reachgate import contract_check as cc


# --- synthetic fixtures ----------------------------------------------------

def _cert(**overrides):
    cert = {
        "strategy": "bounded-bfs-v1",
        "policy_version": "8eae9f21a3e6",
        "bounds": {"max_hops": 6, "max_visited": 40, "max_seconds": 120},
        "max_hops_hit": False,
        "visited_cap_hit": False,
        "timeout_hit": False,
        "frontier_exhausted": False,
        "api_errors": 0,
    }
    cert.update(overrides)
    return cert


def _reachable(occ="r"):
    return {
        "verdict": "REACHABLE",
        "verdict_basis": "path_found",
        "path": ["File:entry.js", "Definition:vuln"],
        "occurrence_id": occ,
        "fingerprint": "fp-r",
        "certificate": _cert(),
    }


def _exhaustive_nr(occ="n"):
    return {
        "verdict": "NOT_REACHABLE",
        "verdict_basis": "no_path_search_exhaustive",
        "path": [],
        "occurrence_id": occ,
        "fingerprint": "fp-n",
        "certificate": _cert(frontier_exhausted=True),
    }


def _unknown(occ="u", basis="insufficient_evidence:no_definitions_indexed"):
    return {
        "verdict": "UNKNOWN",
        "verdict_basis": basis,
        "path": [],
        "occurrence_id": occ,
        "fingerprint": "fp-u",
        "certificate": _cert(),
    }


def _artifact(*findings):
    return {"schema_version": "1.0", "policy": {"version": "8eae9f21a3e6"},
            "findings": list(findings)}


# --- captured artifacts pass -----------------------------------------------

def test_captured_mr2_passes():
    root = cli._find_repo_root()
    assert root is not None
    result = cc.check_file(
        str(root / "docs" / "proof" / "mr2-reachgate-receipts.json")
    )
    assert result.overall == cc.PASS


def test_captured_unknown_passes_as_evidence_gap():
    root = cli._find_repo_root()
    result = cc.check_file(
        str(root / "docs" / "proof" / "unknown-reachgate-receipt.json")
    )
    assert result.overall == cc.PASS
    f = result.findings[0]
    assert f.verdict == "UNKNOWN"
    assert f.status == cc.PASS
    # The UNKNOWN diagnostic must frame it as an evidence gap, never safe.
    text = " ".join(d.message.lower() for d in f.diagnostics)
    assert "evidence gap" in text
    assert "is safe" not in text


# --- NOT_REACHABLE exhaustiveness gate -------------------------------------

def test_non_exhaustive_not_reachable_fails():
    art = _artifact({
        "verdict": "NOT_REACHABLE",
        "verdict_basis": "no_path_search_exhaustive",
        "occurrence_id": "n",
        "certificate": _cert(frontier_exhausted=False),
    })
    result = cc.check_artifact(art)
    assert result.overall == cc.FAIL


def test_not_reachable_with_api_errors_fails():
    art = _artifact({
        "verdict": "NOT_REACHABLE",
        "occurrence_id": "n",
        "certificate": _cert(frontier_exhausted=True, api_errors=2),
    })
    result = cc.check_artifact(art)
    assert result.overall == cc.FAIL


def test_not_reachable_with_timeout_hit_fails():
    art = _artifact({
        "verdict": "NOT_REACHABLE",
        "occurrence_id": "n",
        "certificate": _cert(frontier_exhausted=True, timeout_hit=True),
    })
    result = cc.check_artifact(art)
    assert result.overall == cc.FAIL


def test_not_reachable_with_max_hops_hit_fails():
    art = _artifact({
        "verdict": "NOT_REACHABLE",
        "occurrence_id": "n",
        "certificate": _cert(frontier_exhausted=True, max_hops_hit=True),
    })
    assert cc.check_artifact(art).overall == cc.FAIL


def test_not_reachable_without_certificate_fails():
    art = _artifact({"verdict": "NOT_REACHABLE", "occurrence_id": "n"})
    assert cc.check_artifact(art).overall == cc.FAIL


def test_exhaustive_not_reachable_passes():
    assert cc.check_artifact(_artifact(_exhaustive_nr())).overall == cc.PASS


# --- UNKNOWN is never safe/pass-as-safe ------------------------------------

def test_unknown_is_never_marked_safe():
    result = cc.check_artifact(_artifact(_unknown()))
    f = result.findings[0]
    assert f.status == cc.PASS  # conformant: it does not overclaim
    for d in f.diagnostics:
        assert "is safe" not in d.message.lower()
        # An UNKNOWN must never be reported under a not_reachable safe rule.
        assert not d.rule.startswith("not_reachable")


def test_unknown_without_typed_reason_warns_not_fails():
    result = cc.check_artifact(_artifact(_unknown(basis="")))
    f = result.findings[0]
    assert f.status == cc.WARN
    assert result.overall == cc.WARN


# --- malformed / minimal receipts: clean diagnostics, no traceback ---------

def test_unrecognized_verdict_fails_cleanly():
    art = _artifact({"verdict": "MAYBE", "occurrence_id": "x"})
    result = cc.check_artifact(art)
    assert result.overall == cc.FAIL
    assert any(d.rule == "verdict.value" for d in result.findings[0].diagnostics)


def test_artifact_without_findings_fails_cleanly():
    result = cc.check_artifact({"schema_version": "1.0"})
    assert result.overall == cc.FAIL
    assert result.findings[0].diagnostics[0].rule == "artifact.findings"


def test_non_object_artifact_fails_cleanly():
    result = cc.check_artifact(["not", "an", "object"])
    assert result.overall == cc.FAIL


def test_non_object_finding_fails_cleanly():
    result = cc.check_artifact(_artifact("nope"))
    assert result.overall == cc.FAIL


def test_mixed_artifact_overall_is_worst():
    # One conformant REACHABLE + one overclaiming NOT_REACHABLE => FAIL overall.
    art = _artifact(
        _reachable("a"),
        {"verdict": "NOT_REACHABLE", "occurrence_id": "b",
         "certificate": _cert(frontier_exhausted=False)},
    )
    result = cc.check_artifact(art)
    assert result.overall == cc.FAIL
    by_occ = {f.occurrence_id: f for f in result.findings}
    assert by_occ["a"].status == cc.PASS
    assert by_occ["b"].status == cc.FAIL


# --- determinism -----------------------------------------------------------

def test_findings_sorted_by_identity():
    art = _artifact(_exhaustive_nr("z"), _reachable("a"), _unknown("m"))
    result = cc.check_artifact(art)
    ids = [f.occurrence_id for f in result.findings]
    assert ids == sorted(ids)


def test_json_output_is_byte_stable():
    art = _artifact(_reachable(), _exhaustive_nr(), _unknown())
    a = cc.render_json(cc.check_artifact(art))
    b = cc.render_json(cc.check_artifact(art))
    assert a == b
    assert a.endswith("\n")
    json.loads(a)  # valid


def test_markdown_output_is_ascii_and_stable():
    art = _artifact(_reachable(), _exhaustive_nr(), _unknown())
    md = cc.render_markdown(cc.check_artifact(art), source="x.json")
    assert md.isascii()
    assert "ReachGate contract-check" in md


# --- CLI -------------------------------------------------------------------

def _write(tmp_path, name, artifact):
    p = tmp_path / name
    p.write_text(json.dumps(artifact), encoding="utf-8")
    return str(p)


def test_cli_text_pass_exits_zero(tmp_path, capsys):
    p = _write(tmp_path, "ok.json", _artifact(_exhaustive_nr(), _unknown()))
    assert cli.main(["contract-check", p]) == 0
    out = capsys.readouterr().out
    assert "contract-check" in out


def test_cli_fail_exits_nonzero(tmp_path, capsys):
    bad = _write(tmp_path, "bad.json", _artifact({
        "verdict": "NOT_REACHABLE", "occurrence_id": "n",
        "certificate": _cert(frontier_exhausted=False),
    }))
    assert cli.main(["contract-check", bad]) == 1


def test_cli_warn_only_exits_zero(tmp_path):
    warn = _write(tmp_path, "warn.json", _artifact(_unknown(basis="")))
    assert cli.main(["contract-check", warn]) == 0


def test_cli_json_format(tmp_path, capsys):
    p = _write(tmp_path, "ok.json", _artifact(_exhaustive_nr()))
    assert cli.main(["contract-check", p, "--format", "json"]) == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["overall"] == cc.PASS


def test_cli_markdown_format(tmp_path, capsys):
    p = _write(tmp_path, "ok.json", _artifact(_reachable()))
    assert cli.main(["contract-check", p, "--format", "markdown"]) == 0
    out = capsys.readouterr().out
    assert "## ReachGate contract-check" in out


def test_cli_missing_file_clean_error(tmp_path, capsys):
    assert cli.main(["contract-check", str(tmp_path / "nope.json")]) == 2
    assert "file not found" in capsys.readouterr().err


def test_cli_invalid_json_clean_error(tmp_path, capsys):
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    assert cli.main(["contract-check", str(bad)]) == 2
    assert "invalid JSON" in capsys.readouterr().err


def test_cli_multiple_files(tmp_path, capsys):
    a = _write(tmp_path, "a.json", _artifact(_exhaustive_nr()))
    b = _write(tmp_path, "b.json", _artifact(_reachable()))
    assert cli.main(["contract-check", a, b]) == 0


def test_cli_output_writes_temp_no_tracked_mutation(tmp_path):
    root = cli._find_repo_root()
    tracked = [
        root / "docs" / "proof" / "mr2-reachgate-receipts.json",
        root / "docs" / "judge-proof.html",
    ]
    before = {p: (p.stat().st_mtime_ns if p.exists() else None) for p in tracked}

    p = _write(tmp_path, "ok.json", _artifact(_exhaustive_nr()))
    out = tmp_path / "report.md"
    rc = cli.main(["contract-check", p, "--format", "markdown", "--output", str(out)])
    assert rc == 0
    assert out.exists()

    after = {p: (p.stat().st_mtime_ns if p.exists() else None) for p in tracked}
    assert before == after


def test_real_captured_proof_files_all_pass():
    """Every committed proof receipt must pass its own contract."""
    root = cli._find_repo_root()
    for name in (
        "mr2-reachgate-receipts.json",
        "mr3-reachgate-receipts-rerun.json",
        "unknown-reachgate-receipt.json",
    ):
        result = cc.check_file(str(root / "docs" / "proof" / name))
        assert result.overall == cc.PASS, f"{name} failed its own contract"
