"""The evidence capsule is a portable, deterministic, offline-verifiable bundle.

These tests pin the capsule + the judge/policy/coverage-html CLI surface:
  * the capsule builds, contains the machine-readable evidence + the verifier +
    a HOW_TO_VERIFY, and is byte-stable across rebuilds (deterministic zip);
  * judge-proof.html is bundled but NOT hashed in the manifest;
  * `reachgate policy explain` reports policy from the receipt, with honest
    provenance, and never invents values;
  * `reachgate coverage --format html` emits a self-contained page with no JS,
    no CDN, no external resources;
  * repo-only commands fail loudly outside a checkout;
  * nothing here performs a network call.
"""

import io
import json
import socket
import zipfile
from pathlib import Path

import pytest

from src.reachgate import capsule as capsule_mod
from src.reachgate import cli
from src.reachgate import coverage as coverage_mod


def _repo_root() -> Path:
    root = cli._find_repo_root()
    assert root is not None, "tests must run from a ReachGate checkout"
    return root


# --- capsule ---------------------------------------------------------------

def test_capsule_builds_and_lists_members(tmp_path):
    out = tmp_path / "cap.zip"
    summary = capsule_mod.build_capsule(_repo_root(), out, regenerate=True)
    assert out.exists()
    assert summary["member_count"] >= 8
    names = set(summary["included"])
    # The falsifiable core must be present.
    assert "proof/mr2-reachgate-receipts.json" in names
    assert "proof/reachgate.openvex.json" in names
    assert "proof/reachgate.sarif.json" in names
    assert "proof/reachgate.evidence-manifest.json" in names
    assert "verify/verify_proof.py" in names
    assert "HOW_TO_VERIFY.txt" in names


def test_capsule_includes_judge_proof_html(tmp_path):
    out = tmp_path / "cap.zip"
    capsule_mod.build_capsule(_repo_root(), out, regenerate=True)
    with zipfile.ZipFile(out) as zf:
        assert "judge-proof.html" in zf.namelist()


def test_capsule_judge_proof_not_in_manifest_hashes(tmp_path):
    """judge-proof.html may ride along, but it must never be a hashed artifact
    in the evidence manifest (no circular generated-artifact dependency)."""
    out = tmp_path / "cap.zip"
    capsule_mod.build_capsule(_repo_root(), out, regenerate=True)
    with zipfile.ZipFile(out) as zf:
        manifest = json.loads(zf.read("proof/reachgate.evidence-manifest.json"))
    hashed = {a["filename"] for a in manifest["artifacts"]}
    assert not any(name.endswith("judge-proof.html") for name in hashed)


def test_capsule_is_byte_stable(tmp_path):
    a = tmp_path / "a.zip"
    b = tmp_path / "b.zip"
    capsule_mod.build_capsule(_repo_root(), a, regenerate=False)
    capsule_mod.build_capsule(_repo_root(), b, regenerate=False)
    assert a.read_bytes() == b.read_bytes()


def test_capsule_how_to_verify_is_honest(tmp_path):
    out = tmp_path / "cap.zip"
    capsule_mod.build_capsule(_repo_root(), out, regenerate=False)
    with zipfile.ZipFile(out) as zf:
        text = zf.read("HOW_TO_VERIFY.txt").decode("utf-8")
    low = text.lower()
    assert "offline" in low
    assert "not a certified" in low  # "It is not a certified\ngate" (wraps)
    assert "advisory by default" in low


def test_cmd_capsule_build_writes_to_dist(tmp_path, capsys):
    out = tmp_path / "out.zip"
    rc = cli.main(["capsule", "build", "--output", str(out), "--no-regenerate"])
    assert rc == 0
    assert out.exists()
    printed = capsys.readouterr().out
    assert "members" in printed
    assert "untracked" in printed.lower()


def test_cmd_capsule_outside_repo_fails_loudly(monkeypatch, capsys):
    monkeypatch.setattr(cli, "_find_repo_root", lambda: None)
    rc = cli.main(["capsule", "build"])
    assert rc == 2
    assert "repo checkout" in capsys.readouterr().err


# --- judge -----------------------------------------------------------------

def test_judge_runs_all_steps(capsys):
    rc = cli.main(["judge"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "Verifying receipts" in out
    assert "ReachGate proof verified" in out
    assert "judge-proof.html" in out


def test_judge_outside_repo_fails_loudly(monkeypatch, capsys):
    monkeypatch.setattr(cli, "_find_repo_root", lambda: None)
    assert cli.main(["judge"]) == 2
    assert "repo checkout" in capsys.readouterr().err


# --- policy explain --------------------------------------------------------

def test_policy_explain_from_receipt(capsys):
    rc = cli.main(["policy", "explain"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "policy version:" in out
    assert "REACHABLE threshold:" in out
    assert "+50 path_exists" in out
    # honest provenance statement, not an overclaim.
    assert "Provenance:" in out
    assert "read directly from the receipt" in out


def test_policy_explain_explicit_receipt(tmp_path, capsys):
    receipt = tmp_path / "r.json"
    receipt.write_text(json.dumps({
        "schema_version": "1.0",
        "policy": {"version": "vX", "threshold": 42,
                   "rules": [{"name": "path_exists", "weight": 50}]},
        "findings": [],
    }), encoding="utf-8")
    rc = cli.main(["policy", "explain", "--receipt", str(receipt)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "vX" in out
    assert "42" in out


def test_policy_explain_missing_policy_block(tmp_path, capsys):
    receipt = tmp_path / "r.json"
    receipt.write_text(json.dumps({"schema_version": "1.0", "findings": []}),
                       encoding="utf-8")
    rc = cli.main(["policy", "explain", "--receipt", str(receipt)])
    assert rc == 1
    assert "no policy block" in capsys.readouterr().err


# --- coverage html ---------------------------------------------------------

def test_coverage_html_is_self_contained(tmp_path):
    out = tmp_path / "coverage.html"
    rc = cli.main(["coverage", "--format", "html", "--output", str(out)])
    assert rc == 0
    html = out.read_text(encoding="utf-8")
    assert "<html" in html
    assert "ReachGate coverage" in html
    assert "UNKNOWN reasons" in html
    # No JavaScript, no CDN, no external resources.
    assert "<script" not in html.lower()
    assert "http://" not in html
    assert "https://" not in html
    assert "cdn" not in html.lower()


def test_coverage_html_includes_unknown_next_action(tmp_path):
    out = tmp_path / "coverage.html"
    cli.main(["coverage", "--format", "html", "--output", str(out)])
    html = out.read_text(encoding="utf-8")
    assert "Next action" in html
    assert "no_definitions_indexed" in html


# --- no network ------------------------------------------------------------

def test_no_network_during_capsule_and_policy(monkeypatch, tmp_path):
    def _boom(*a, **k):
        raise AssertionError("network access attempted")

    monkeypatch.setattr(socket, "socket", _boom)
    assert cli.main(["policy", "explain"]) == 0
    out = tmp_path / "c.zip"
    assert cli.main(["capsule", "build", "--output", str(out), "--no-regenerate"]) == 0
