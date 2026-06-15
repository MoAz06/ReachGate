"""The reachgate CLI is a package-safe, offline router.

These tests pin the CLI surface: help works, the offline `coverage` command is
fully package-safe (it never needs tools/ or a live call), repo-delegating
commands fail loudly with a helpful message when run outside a checkout, the
live-only `scan` is refused (never faked), and no command performs a network
call.
"""

import json
import socket

import pytest

from src.reachgate import cli
from src.reachgate import coverage as coverage_mod


# --- help / dispatch -------------------------------------------------------

def test_no_command_prints_help(capsys):
    assert cli.main([]) == 0
    out = capsys.readouterr().out
    assert "reachgate" in out
    assert "coverage" in out
    assert "verify" in out


def test_help_exits_zero():
    # argparse raises SystemExit(0) for --help; assert that explicitly.
    with pytest.raises(SystemExit) as exc:
        cli.main(["--help"])
    assert exc.value.code == 0


# --- coverage (offline, package-safe) --------------------------------------

def test_coverage_text_default_sources(capsys):
    assert cli.main(["coverage"]) == 0
    out = capsys.readouterr().out
    assert "ReachGate coverage / blind-spot report" in out
    assert "verdicts:" in out
    assert "UNKNOWN reasons" in out
    # Typed UNKNOWN guidance must appear: a reason + a next action.
    assert "no_definitions_indexed" in out
    assert "next action:" in out
    assert "blind spots" in out


def test_coverage_json_format(capsys):
    assert cli.main(["coverage", "--format", "json"]) == 0
    out = capsys.readouterr().out
    doc = json.loads(out)
    assert doc["findings_analyzed"] >= 3
    assert "verdict_counts" in doc
    assert "unknown_reasons" in doc
    # UNKNOWN reasons carry counts + next actions, not just labels.
    reasons = doc["unknown_reasons"]
    assert reasons
    for reason, info in reasons.items():
        assert info["count"] >= 1
        assert info["next_action"]


def test_coverage_explicit_receipts(tmp_path, capsys):
    receipt = tmp_path / "r.json"
    receipt.write_text(json.dumps({
        "schema_version": "1.0",
        "findings": [
            {
                "verdict": "UNKNOWN",
                "verdict_basis": "insufficient_evidence:no_location",
                "vulnerable_file": None,
                "path": [],
                "fingerprint": "abc",
            }
        ],
    }), encoding="utf-8")
    assert cli.main(["coverage", "--receipts", str(receipt)]) == 0
    out = capsys.readouterr().out
    assert "no_location" in out
    assert "without code location: 1" in out


def test_coverage_missing_file_is_clean_error(tmp_path, capsys):
    missing = tmp_path / "nope.json"
    assert cli.main(["coverage", "--receipts", str(missing)]) == 1
    err = capsys.readouterr().err
    assert "file not found" in err


# --- repo-delegating commands fail loudly outside a checkout ---------------

def test_verify_outside_repo_fails_loudly(monkeypatch, capsys):
    monkeypatch.setattr(cli, "_find_repo_root", lambda: None)
    rc = cli.main(["verify"])
    assert rc == 2
    err = capsys.readouterr().err
    assert "repo checkout" in err
    assert "pip install" in err


def test_export_sarif_outside_repo_fails_loudly(monkeypatch, capsys):
    monkeypatch.setattr(cli, "_find_repo_root", lambda: None)
    rc = cli.main(["export-sarif"])
    assert rc == 2
    assert "repo checkout" in capsys.readouterr().err


def test_manifest_outside_repo_fails_loudly(monkeypatch, capsys):
    monkeypatch.setattr(cli, "_find_repo_root", lambda: None)
    assert cli.main(["manifest"]) == 2


# --- scan is refused, never faked ------------------------------------------

def test_scan_is_refused_not_faked(capsys):
    rc = cli.main(["scan"])
    assert rc == 2
    err = capsys.readouterr().err
    assert "not available in the offline CLI" in err
    assert "reachgate.agent" in err


# --- verify delegates and stays green (repo checkout) ----------------------

def test_verify_in_repo_passes(capsys):
    # Runs against the captured docs/proof artifacts in this checkout.
    assert cli.main(["verify"]) == 0
    out = capsys.readouterr().out
    assert "ReachGate proof verified" in out


# --- delegating commands accept --output and never touch tracked paths -----

def _tracked_proof_mtimes():
    """Snapshot mtimes of the tracked artifacts the tools default to."""
    root = cli._find_repo_root()
    assert root is not None
    paths = [
        root / "docs" / "proof" / "reachgate.openvex.json",
        root / "docs" / "proof" / "reachgate.sarif.json",
        root / "docs" / "proof" / "reachgate.evidence-manifest.json",
        root / "docs" / "judge-proof.html",
    ]
    return {p: (p.stat().st_mtime_ns if p.exists() else None) for p in paths}


@pytest.mark.parametrize("command,outfile", [
    ("export-vex", "out.openvex.json"),
    ("export-sarif", "out.sarif.json"),
    ("manifest", "out.manifest.json"),
    ("proof", "out.judge-proof.html"),
])
def test_delegating_command_accepts_output(tmp_path, command, outfile):
    out = tmp_path / outfile
    before = _tracked_proof_mtimes()

    rc = cli.main([command, "--output", str(out)])

    assert rc == 0, f"{command} --output failed"
    assert out.exists(), f"{command} did not write the requested --output path"
    # Crucially, none of the tracked default artifacts were rewritten.
    after = _tracked_proof_mtimes()
    assert before == after, (
        f"{command} --output mutated a tracked docs path: "
        f"{[p.name for p in before if before[p] != after[p]]}"
    )


# --- no network: any socket use during offline commands is a failure -------

def test_no_network_during_offline_commands(monkeypatch):
    def _boom(*a, **k):
        raise AssertionError("network access attempted in an offline CLI command")

    monkeypatch.setattr(socket, "socket", _boom)
    # coverage and scan must never touch the network.
    assert cli.main(["coverage"]) == 0
    assert cli.main(["scan"]) == 2
