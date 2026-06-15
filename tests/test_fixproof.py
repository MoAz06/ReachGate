"""Fix verification is a derived, offline evidence layer over two receipts.

These tests pin the conservative semantics of `reachgate fixcheck`:

  * reachability_removed is ONLY claimed for REACHABLE -> exhaustive
    NOT_REACHABLE under the same policy;
  * UNKNOWN after is never a fix;
  * a non-exhaustive NOT_REACHABLE after is never a fix;
  * exhaustive-NOT_REACHABLE (or absent) -> REACHABLE is a regression;
  * equivalent verdict + evidence is unchanged;
  * policy mismatch and ambiguous/missing identity are incomparable;
  * JSON output is byte-stable;
  * the CLI honors text/json and --output without touching tracked artifacts.

All receipts below are SYNTHETIC TEST FIXTURES built in-process. They are not
proof artifacts and never touch docs/proof/.
"""

import json

import pytest

from src.reachgate import cli
from src.reachgate import fixproof


POLICY_A = "8eae9f21a3e6"
POLICY_B = "ffffffffffff"


# --- fixture builders (synthetic, test-only) -------------------------------

def _cert(**overrides):
    cert = {
        "strategy": "bounded-bfs-v1",
        "policy_version": POLICY_A,
        "bounds": {"max_hops": 6, "max_visited": 40, "max_seconds": 120},
        "max_hops_hit": False,
        "visited_cap_hit": False,
        "timeout_hit": False,
        "frontier_exhausted": False,
        "api_errors": 0,
    }
    cert.update(overrides)
    return cert


def _finding(occ, verdict, *, basis="", fingerprint="fp", path=None, cert=None):
    return {
        "verdict": verdict,
        "verdict_basis": basis,
        "path": path or [],
        "occurrence_id": occ,
        "fingerprint": fingerprint,
        "certificate": cert if cert is not None else _cert(policy_version=POLICY_A),
    }


def _reachable(occ, fingerprint="fp-reach"):
    return _finding(
        occ, "REACHABLE", basis="path_found", fingerprint=fingerprint,
        path=["File:entry.js", "Definition:vuln"],
        cert=_cert(policy_version=POLICY_A),
    )


def _exhaustive_not_reachable(occ, fingerprint="fp-nr"):
    return _finding(
        occ, "NOT_REACHABLE", basis="no_path_search_exhaustive",
        fingerprint=fingerprint,
        cert=_cert(policy_version=POLICY_A, frontier_exhausted=True),
    )


def _weak_not_reachable(occ, fingerprint="fp-nr-weak"):
    # A bound was hit: NOT exhaustive, must never be treated as a fix.
    return _finding(
        occ, "NOT_REACHABLE", basis="no_path_search_exhaustive",
        fingerprint=fingerprint,
        cert=_cert(
            policy_version=POLICY_A, frontier_exhausted=False, max_hops_hit=True
        ),
    )


def _unknown(occ, fingerprint="fp-unk"):
    return _finding(
        occ, "UNKNOWN", basis="insufficient_evidence:no_definitions_indexed",
        fingerprint=fingerprint,
        cert=_cert(policy_version=POLICY_A, frontier_exhausted=False),
    )


def _artifact(*findings, policy_version=POLICY_A):
    return {
        "schema_version": "1.0",
        "policy": {"version": policy_version},
        "findings": list(findings),
    }


def _classify(before, after, occ="x"):
    proof = fixproof.compare(before, after)
    by_occ = {f["occurrence_id"]: f for f in proof["findings"]}
    return by_occ[occ]["classification"]


# --- core semantics --------------------------------------------------------

def test_reachable_to_exhaustive_not_reachable_is_removed():
    before = _artifact(_reachable("x"))
    after = _artifact(_exhaustive_not_reachable("x"))
    assert _classify(before, after) == fixproof.REACHABILITY_REMOVED


def test_reachable_to_unknown_is_incomparable_not_fixed():
    before = _artifact(_reachable("x"))
    after = _artifact(_unknown("x"))
    cls = _classify(before, after)
    assert cls == fixproof.INCOMPARABLE
    assert cls != fixproof.REACHABILITY_REMOVED


def test_reachable_to_non_exhaustive_not_reachable_is_not_fixed():
    before = _artifact(_reachable("x"))
    after = _artifact(_weak_not_reachable("x"))
    cls = _classify(before, after)
    assert cls == fixproof.INCOMPARABLE
    assert cls != fixproof.REACHABILITY_REMOVED


@pytest.mark.parametrize("cert_override", [
    {"frontier_exhausted": True, "api_errors": 2},
    {"frontier_exhausted": True, "visited_cap_hit": True},
    {"frontier_exhausted": True, "timeout_hit": True},
    {"frontier_exhausted": False},
])
def test_removed_requires_fully_exhaustive_certificate(cert_override):
    before = _artifact(_reachable("x"))
    nr = _finding(
        "x", "NOT_REACHABLE", basis="no_path_search_exhaustive",
        cert=_cert(policy_version=POLICY_A, **cert_override),
    )
    after = _artifact(nr)
    assert _classify(before, after) == fixproof.INCOMPARABLE


def test_exhaustive_not_reachable_to_reachable_is_introduced():
    before = _artifact(_exhaustive_not_reachable("x"))
    after = _artifact(_reachable("x"))
    assert _classify(before, after) == fixproof.REACHABILITY_INTRODUCED


def test_absent_before_to_reachable_is_introduced():
    before = _artifact()
    after = _artifact(_reachable("x"))
    assert _classify(before, after) == fixproof.REACHABILITY_INTRODUCED


def test_weak_not_reachable_to_reachable_is_incomparable():
    # No proven-safe baseline to regress from.
    before = _artifact(_weak_not_reachable("x"))
    after = _artifact(_reachable("x"))
    assert _classify(before, after) == fixproof.INCOMPARABLE


def test_same_verdict_and_evidence_is_unchanged():
    art = _artifact(_reachable("x", fingerprint="same"))
    assert _classify(art, art) == fixproof.UNCHANGED


def test_same_exhaustive_not_reachable_is_unchanged():
    art = _artifact(_exhaustive_not_reachable("x", fingerprint="same"))
    assert _classify(art, art) == fixproof.UNCHANGED


def test_unknown_to_unknown_is_incomparable():
    art = _artifact(_unknown("x"))
    # AFTER UNKNOWN is never a fix; it short-circuits to incomparable.
    assert _classify(art, art) == fixproof.INCOMPARABLE


def test_reachable_absent_after_is_incomparable_not_fixed():
    before = _artifact(_reachable("x"))
    after = _artifact()
    cls = _classify(before, after)
    assert cls == fixproof.INCOMPARABLE
    assert cls != fixproof.REACHABILITY_REMOVED


# --- policy + identity guards ----------------------------------------------

def test_policy_version_mismatch_is_incomparable():
    before = _artifact(_reachable("x"), policy_version=POLICY_A)
    after = _artifact(
        _exhaustive_not_reachable("x"), policy_version=POLICY_B
    )
    proof = fixproof.compare(before, after)
    assert proof["policy"]["match"] is False
    assert _classify(before, after) == fixproof.INCOMPARABLE


def test_per_finding_policy_mismatch_is_incomparable():
    before = _artifact(_reachable("x"))
    nr = _exhaustive_not_reachable("x")
    nr["certificate"]["policy_version"] = POLICY_B  # disagrees with the receipt
    after = _artifact(nr)
    assert _classify(before, after) == fixproof.INCOMPARABLE


def test_duplicate_identity_is_incomparable():
    before = _artifact(_reachable("x"), _exhaustive_not_reachable("x"))
    after = _artifact(_exhaustive_not_reachable("x"))
    proof = fixproof.compare(before, after)
    assert all(
        f["classification"] == fixproof.INCOMPARABLE for f in proof["findings"]
    )


def test_missing_identity_is_incomparable():
    before = {
        "schema_version": "1.0",
        "policy": {"version": POLICY_A},
        "findings": [{"verdict": "REACHABLE", "fingerprint": "a"}],  # no occ id
    }
    after = _artifact(_exhaustive_not_reachable("x"))
    proof = fixproof.compare(before, after)
    assert all(
        f["classification"] == fixproof.INCOMPARABLE for f in proof["findings"]
    )


# --- determinism / serialization ------------------------------------------

def test_json_output_is_byte_stable():
    before = _artifact(_reachable("x"))
    after = _artifact(_exhaustive_not_reachable("x"))
    a = fixproof.render_json(fixproof.compare(before, after))
    b = fixproof.render_json(fixproof.compare(before, after))
    assert a == b
    assert a.endswith("\n")
    # Valid JSON, sorted keys at the top level.
    doc = json.loads(a)
    assert doc["summary"][fixproof.REACHABILITY_REMOVED] == 1


def test_findings_are_sorted_by_identity():
    before = _artifact(_reachable("b"), _reachable("a"))
    after = _artifact(
        _exhaustive_not_reachable("a"), _exhaustive_not_reachable("b")
    )
    proof = fixproof.compare(before, after)
    ids = [f["occurrence_id"] for f in proof["findings"]]
    assert ids == sorted(ids)


def test_summary_counts_match_findings():
    before = _artifact(_reachable("x"), _exhaustive_not_reachable("y"))
    after = _artifact(_exhaustive_not_reachable("x"), _reachable("y"))
    proof = fixproof.compare(before, after)
    assert proof["summary"][fixproof.REACHABILITY_REMOVED] == 1
    assert proof["summary"][fixproof.REACHABILITY_INTRODUCED] == 1


# --- CLI -------------------------------------------------------------------

def _write(tmp_path, name, artifact):
    p = tmp_path / name
    p.write_text(json.dumps(artifact), encoding="utf-8")
    return str(p)


def test_cli_text_output(tmp_path, capsys):
    before = _write(tmp_path, "before.json", _artifact(_reachable("x")))
    after = _write(
        tmp_path, "after.json", _artifact(_exhaustive_not_reachable("x"))
    )
    assert cli.main(["fixcheck", before, after]) == 0
    out = capsys.readouterr().out
    assert "ReachGate fix-proof" in out
    assert "reachability_removed" in out


def test_cli_json_output(tmp_path, capsys):
    before = _write(tmp_path, "before.json", _artifact(_reachable("x")))
    after = _write(
        tmp_path, "after.json", _artifact(_exhaustive_not_reachable("x"))
    )
    assert cli.main(["fixcheck", before, after, "--format", "json"]) == 0
    out = capsys.readouterr().out
    doc = json.loads(out)
    assert doc["findings"][0]["classification"] == fixproof.REACHABILITY_REMOVED


def test_cli_output_writes_to_temp_path(tmp_path, capsys):
    before = _write(tmp_path, "before.json", _artifact(_reachable("x")))
    after = _write(
        tmp_path, "after.json", _artifact(_exhaustive_not_reachable("x"))
    )
    out_path = tmp_path / "proof.json"
    rc = cli.main(
        ["fixcheck", before, after, "--format", "json", "--output", str(out_path)]
    )
    assert rc == 0
    assert out_path.exists()
    doc = json.loads(out_path.read_text(encoding="utf-8"))
    assert doc["findings"][0]["classification"] == fixproof.REACHABILITY_REMOVED


def test_cli_missing_file_is_clean_error(tmp_path, capsys):
    after = _write(tmp_path, "after.json", _artifact())
    rc = cli.main(["fixcheck", str(tmp_path / "nope.json"), after])
    assert rc == 2
    captured = capsys.readouterr()
    assert "file not found" in captured.err


def test_cli_invalid_json_is_clean_error(tmp_path, capsys):
    bad = tmp_path / "bad.json"
    bad.write_text("{not valid json", encoding="utf-8")
    after = _write(tmp_path, "after.json", _artifact())
    rc = cli.main(["fixcheck", str(bad), after])
    assert rc == 2
    assert "invalid JSON" in capsys.readouterr().err


def test_fixcheck_does_not_mutate_tracked_artifacts(tmp_path):
    """fixcheck must never write to docs/proof or docs/judge-proof.html."""
    root = cli._find_repo_root()
    assert root is not None
    tracked = [
        root / "docs" / "proof" / "mr2-reachgate-receipts.json",
        root / "docs" / "proof" / "mr3-reachgate-receipts-rerun.json",
        root / "docs" / "proof" / "unknown-reachgate-receipt.json",
        root / "docs" / "judge-proof.html",
    ]
    before_mtimes = {
        p: (p.stat().st_mtime_ns if p.exists() else None) for p in tracked
    }

    # Run fixcheck against the real captured receipts (read-only), no --output.
    rc = cli.main([
        "fixcheck",
        str(root / "docs" / "proof" / "mr2-reachgate-receipts.json"),
        str(root / "docs" / "proof" / "mr3-reachgate-receipts-rerun.json"),
        "--format", "json",
    ])
    assert rc == 0

    after_mtimes = {
        p: (p.stat().st_mtime_ns if p.exists() else None) for p in tracked
    }
    assert before_mtimes == after_mtimes


def test_real_mr2_vs_mr3_is_all_unchanged():
    """The captured MR !2 / MR !3 receipts are an idempotency rerun, so every
    finding must be unchanged — never a spurious fix or regression."""
    root = cli._find_repo_root()
    assert root is not None
    proof = fixproof.fixcheck(
        str(root / "docs" / "proof" / "mr2-reachgate-receipts.json"),
        str(root / "docs" / "proof" / "mr3-reachgate-receipts-rerun.json"),
    )
    assert proof["summary"][fixproof.REACHABILITY_REMOVED] == 0
    assert proof["summary"][fixproof.REACHABILITY_INTRODUCED] == 0
    for f in proof["findings"]:
        assert f["classification"] == fixproof.UNCHANGED


# --- markdown rendering ----------------------------------------------------

def test_markdown_shows_reachability_removed_and_honesty_note():
    before = _artifact(_reachable("x"))
    after = _artifact(_exhaustive_not_reachable("x"))
    md = fixproof.render_markdown(
        fixproof.compare(before, after),
        before_path="before.json", after_path="after.json",
    )
    assert "## ReachGate fix verification" in md
    assert "reachability_removed" in md
    assert "before.json" in md and "after.json" in md
    # The exhaustive-only honesty sentence must be present verbatim.
    assert fixproof.EXHAUSTIVE_NOTE in md
    assert fixproof.NOT_PROOF_NOTE in md


def _md_classified_removed(proof) -> bool:
    """True if any finding row is actually classified reachability_removed.

    The summary table always lists every status label (with a count), so we
    check the per-finding classification rather than the label's mere presence.
    """
    return any(
        f["classification"] == fixproof.REACHABILITY_REMOVED
        for f in proof["findings"]
    )


def test_markdown_unknown_is_incomparable_never_fixed():
    before = _artifact(_reachable("x"))
    after = _artifact(_unknown("x"))
    proof = fixproof.compare(before, after)
    md = fixproof.render_markdown(proof)
    assert "incomparable" in md
    assert not _md_classified_removed(proof)
    assert proof["summary"][fixproof.REACHABILITY_REMOVED] == 0
    # UNKNOWN must never be framed as fixed/safe; the only "fixed" mention is
    # the honesty note that says it is NOT treated as fixed.
    low = md.lower()
    assert "is safe" not in low
    assert "never treated as fixed" in low


def test_markdown_policy_mismatch_is_incomparable():
    before = _artifact(_reachable("x"), policy_version=POLICY_A)
    after = _artifact(_exhaustive_not_reachable("x"), policy_version=POLICY_B)
    proof = fixproof.compare(before, after)
    md = fixproof.render_markdown(proof)
    assert "incomparable" in md
    assert not _md_classified_removed(proof)
    assert proof["summary"][fixproof.REACHABILITY_REMOVED] == 0


def test_markdown_non_exhaustive_after_is_incomparable():
    before = _artifact(_reachable("x"))
    after = _artifact(_weak_not_reachable("x"))
    proof = fixproof.compare(before, after)
    md = fixproof.render_markdown(proof)
    assert "incomparable" in md
    assert not _md_classified_removed(proof)
    assert proof["summary"][fixproof.REACHABILITY_REMOVED] == 0


def test_markdown_is_byte_stable():
    before = _artifact(_reachable("x"))
    after = _artifact(_exhaustive_not_reachable("x"))
    a = fixproof.render_markdown(fixproof.compare(before, after))
    b = fixproof.render_markdown(fixproof.compare(before, after))
    assert a == b
    assert a.endswith("\n")


# --- demo fixture (honest, synthetic) --------------------------------------

def _fixture_dir():
    root = cli._find_repo_root()
    assert root is not None
    return root / "tests" / "fixtures" / "fixcheck"


def test_demo_fixture_proves_reachability_removed():
    d = _fixture_dir()
    proof = fixproof.fixcheck(
        str(d / "before-reachable.json"),
        str(d / "after-not-reachable-exhaustive.json"),
    )
    assert proof["summary"][fixproof.REACHABILITY_REMOVED] == 1
    by_occ = {f["occurrence_id"]: f for f in proof["findings"]}
    assert by_occ["demo-fix-ssrf"]["classification"] == fixproof.REACHABILITY_REMOVED


def test_demo_fixtures_are_labeled_synthetic():
    d = _fixture_dir()
    for name in ("before-reachable.json", "after-not-reachable-exhaustive.json"):
        data = json.loads((d / name).read_text(encoding="utf-8"))
        assert "_fixture" in data
        assert "SYNTHETIC" in data["_fixture"].upper()


def test_cli_markdown_output_on_demo_fixture(capsys):
    d = _fixture_dir()
    rc = cli.main([
        "fixcheck",
        str(d / "before-reachable.json"),
        str(d / "after-not-reachable-exhaustive.json"),
        "--format", "markdown",
    ])
    assert rc == 0
    out = capsys.readouterr().out
    assert "## ReachGate fix verification" in out
    assert "reachability_removed" in out


def test_cli_markdown_output_to_temp_path_no_tracked_mutation(tmp_path):
    d = _fixture_dir()
    root = cli._find_repo_root()
    tracked = [
        root / "docs" / "proof" / "mr2-reachgate-receipts.json",
        root / "docs" / "judge-proof.html",
    ]
    before_mtimes = {
        p: (p.stat().st_mtime_ns if p.exists() else None) for p in tracked
    }

    out_path = tmp_path / "fix.md"
    rc = cli.main([
        "fixcheck",
        str(d / "before-reachable.json"),
        str(d / "after-not-reachable-exhaustive.json"),
        "--format", "markdown",
        "--output", str(out_path),
    ])
    assert rc == 0
    assert out_path.exists()
    assert "reachability_removed" in out_path.read_text(encoding="utf-8")

    after_mtimes = {
        p: (p.stat().st_mtime_ns if p.exists() else None) for p in tracked
    }
    assert before_mtimes == after_mtimes
