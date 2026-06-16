"""The adversarial self-proof is a real invariant regression test, not a demo.

These tests pin both halves of the meta-assertion:
  * in this checkout every leg behaves and the keystone exits 0;
  * a PASS leg that unexpectedly FAILS makes the keystone exit non-zero;
  * a FAIL leg that unexpectedly PASSES (a safety regression) makes it exit
    non-zero;
  * a FAIL leg that fails for the WRONG reason (noise) makes it exit non-zero;
  * the signature leg SKIPS cleanly (never fails the keystone) without crypto;
  * the synthesized fake-green input is marked SYNTHETIC and left nowhere
    readable as proof.
"""

import json

from src.reachgate import selftest
from src.reachgate import contract_check
from src.reachgate import verify_proof
from src.reachgate import cli


# --- happy path: every invariant holds in this checkout --------------------

def test_selftest_passes_in_repo():
    report = selftest.run_selftest()
    assert report.exit_code == 0, [l.as_dict() for l in report.legs]
    # Five legs, each OK (signature leg OK when cryptography is installed).
    assert len(report.legs) == 5
    statuses = {l.name: l.status for l in report.legs}
    assert statuses["contract-check:real"] == selftest.OK
    assert statuses["verify:real"] == selftest.OK
    assert statuses["unknown-stays-unknown"] == selftest.OK
    assert statuses["contract-check:fake-green"] == selftest.OK
    assert statuses["signature:tamper"] in (selftest.OK, selftest.SKIPPED)


def test_cli_selftest_exits_zero_and_reports(capsys):
    rc = cli.main(["selftest"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "adversarial self-proof" in out.lower()
    assert "RESULT: PASS" in out
    # every leg is shown with expected + actual
    assert "contract-check:fake-green" in out
    assert "not_reachable.exhaustive" in out


def test_json_format_is_machine_readable(capsys):
    rc = cli.main(["selftest", "--format", "json"])
    assert rc == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["overall"] == "pass"
    assert doc["exit_code"] == 0
    assert len(doc["legs"]) == 5


# --- the meta-assertion bites: FAIL leg goes unexpectedly green ------------

def _result(overall, findings=None):
    return contract_check.ContractCheckResult(
        overall=overall, summary={}, findings=findings or [])


def test_fake_green_passing_is_a_safety_regression(monkeypatch):
    # Force the fake-green receipt to be ACCEPTED -> the FAIL leg must catch it.
    monkeypatch.setattr(contract_check, "check_file",
                        lambda path: _result(contract_check.PASS))
    report = selftest.run_selftest()
    assert report.exit_code == 1
    leg = next(l for l in report.legs if l.name == "contract-check:fake-green")
    assert leg.status == selftest.MISBEHAVED
    assert "not rejected" in leg.detail.lower()


def test_fake_green_failing_for_wrong_reason_is_noise(monkeypatch):
    # Rejected (FAIL) but NOT via the expected rule -> failed for the wrong
    # reason -> not proof of the invariant -> keystone non-zero.
    wrong = contract_check.FindingResult(
        occurrence_id="x", verdict="NOT_REACHABLE", status=contract_check.FAIL,
        diagnostics=[contract_check.Diagnostic(
            contract_check.FAIL, "some.other.rule", "unrelated failure")],
    )
    monkeypatch.setattr(contract_check, "check_file",
                        lambda path: _result(contract_check.FAIL, [wrong]))
    report = selftest.run_selftest()
    assert report.exit_code == 1
    leg = next(l for l in report.legs if l.name == "contract-check:fake-green")
    assert leg.status == selftest.MISBEHAVED
    assert "wrong reason" in leg.detail.lower()


# --- the meta-assertion bites: PASS leg unexpectedly fails -----------------

def test_pass_leg_regression_makes_keystone_fail(monkeypatch):
    # A regression where verify rejects valid proof must also exit non-zero.
    monkeypatch.setattr(verify_proof, "main", lambda: 1)
    report = selftest.run_selftest()
    assert report.exit_code == 1
    leg = next(l for l in report.legs if l.name == "verify:real")
    assert leg.status == selftest.MISBEHAVED


# --- signature leg ---------------------------------------------------------

def test_signature_leg_skips_without_crypto(monkeypatch):
    from src.reachgate import signing
    monkeypatch.setattr(signing, "crypto_available", lambda: False)
    report = selftest.run_selftest()
    leg = next(l for l in report.legs if l.name == "signature:tamper")
    assert leg.status == selftest.SKIPPED
    # A skipped optional leg must NOT fail the keystone.
    assert report.exit_code == 0


def test_tampered_still_verifying_is_a_regression(monkeypatch):
    from src.reachgate import signing
    if not signing.crypto_available():
        import pytest
        pytest.skip("cryptography not installed")
    # Force verify_file to always succeed -> tamper detection broke.
    monkeypatch.setattr(signing, "verify_file", lambda *a, **k: True)
    report = selftest.run_selftest()
    assert report.exit_code == 1
    leg = next(l for l in report.legs if l.name == "signature:tamper")
    assert leg.status == selftest.MISBEHAVED


# --- hygiene: synthetic, marked, left nowhere readable as proof ------------

def test_fake_green_input_is_marked_synthetic():
    assert "_fixture" in selftest._FAKE_GREEN
    marker = selftest._FAKE_GREEN["_fixture"].lower()
    assert "synthetic" in marker
    assert "not live proof" in marker


def test_selftest_leaves_no_artifact_behind(tmp_path, monkeypatch):
    # Run with cwd in a clean tmp dir; the synthesized receipt lives only in the
    # keystone's own TemporaryDirectory and must not appear here or in docs/proof.
    monkeypatch.chdir(tmp_path)
    selftest.run_selftest()
    leftovers = list(tmp_path.rglob("*selftest*")) + list(tmp_path.rglob("*fake-green*"))
    assert leftovers == []
