"""Adversarial self-proof: a living regression test of ReachGate's invariants.

Every other ReachGate command proves one thing. This one keeps the whole system
honest in a single, offline, reproducible run. It does not just show that the
tools work -- any submission claims that. It shows that the safety **invariants**
still hold: the things that must pass, pass; and the things that must fail,
fail. If a fake-green receipt ever slips past ``contract-check``, or a tampered
capsule ever verifies, this command says so and exits non-zero.

It is the executable form of the project's whole thesis -- "don't trust our
marketing, reproduce it yourself" -- in one handle.

Five legs, four invariants:

  PASS legs (must succeed)
    1. contract-check on a real captured receipt        -> accepted (exit 0)
    2. offline verify of the captured proof             -> verified (exit 0)
    3. an UNKNOWN receipt stays UNKNOWN, never "safe"    -> evidence gap, exit 0
  FAIL legs (must fail, for the RIGHT reason)
    4. a freshly synthesized fake-green receipt
       (NOT_REACHABLE while the search timed out)        -> rejected (exit 1),
       with the expected violated rule `not_reachable.exhaustive`
    5. a signed artifact with one byte flipped           -> signature breaks
       (conditional on the optional `cryptography` dep; skipped, never failed,
        when it is absent)

Meta-assertion (symmetric and reason-sensitive):
  selftest exits 0 ONLY if every leg behaved exactly as expected -- PASS legs
  passed AND FAIL legs failed FOR THE EXPECTED REASON. Three ways to exit
  non-zero: a PASS leg unexpectedly fails (a regression rejecting valid
  evidence), a FAIL leg unexpectedly passes (a safety regression), or a FAIL leg
  fails for the wrong reason (noise, not proof of the invariant). A setup error
  exits 2.

Honesty / hygiene:
  * The synthesized fake-green receipt is SYNTHETIC adversarial input. It is
    written only inside a temporary directory, carries the same ``_fixture``
    "not live proof" marker as the committed violation fixtures, and is removed
    when the run ends. It never lands anywhere readable as proof.
  * This command calls the real check logic (the same code paths the CLI runs)
    and asserts the real outcomes; it does not re-implement contract or signing
    semantics. pytest proves the invariants for CI; this proves them, out of
    pytest, for a skeptic.

Standard library only (the signature leg uses the optional ``[sign]`` extra).
"""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from . import _resources
from . import contract_check
from . import verify_proof

# Status of one leg after running.
OK = "ok"
MISBEHAVED = "MISBEHAVED"
ERROR = "ERROR"        # setup/runtime failure -> noise, not a proof
SKIPPED = "skipped"

PASS_LEG = "PASS-leg"
FAIL_LEG = "FAIL-leg"


# The synthesized adversarial receipt: a NOT_REACHABLE that claims safety while
# its search timed out. It MUST be rejected by contract-check. Marked SYNTHETIC
# and written only to a temp dir (see run_selftest).
_FAKE_GREEN = {
    "_fixture": (
        "SYNTHETIC adversarial input (reachgate selftest) - not live proof. "
        "Claims NOT_REACHABLE while timeout_hit=true; MUST fail contract-check."
    ),
    "schema_version": "1.0",
    "policy": {"version": "selftest", "threshold": 50},
    "findings": [
        {
            "verdict": "NOT_REACHABLE",
            "verdict_basis": "no_path_search_exhaustive",
            "path": [],
            "occurrence_id": "selftest-fake-green",
            "occurrence_name": "Overclaiming NOT_REACHABLE (timeout)",
            "severity": "high",
            "fingerprint": "selftest-fake-green-timeout",
            "certificate": {
                "strategy": "bounded-bfs-v1",
                "policy_version": "selftest",
                "bounds": {"max_hops": 6, "max_visited": 40, "max_seconds": 120},
                "frontier_exhausted": False,
                "max_hops_hit": False,
                "visited_cap_hit": False,
                "timeout_hit": True,   # <-- the overclaim: search did not complete
                "api_errors": 0,
            },
        }
    ],
}

# The contract rule the fake-green receipt must trip.
_EXPECTED_FAKE_GREEN_RULE = "not_reachable.exhaustive"


@dataclass
class Leg:
    name: str
    kind: str                 # PASS_LEG | FAIL_LEG
    expected: str             # human-readable expectation
    actual: str = ""          # human-readable observation
    status: str = OK          # OK | MISBEHAVED | ERROR | SKIPPED
    detail: str = ""

    def as_dict(self) -> dict:
        return {
            "leg": self.name, "kind": self.kind, "expected": self.expected,
            "actual": self.actual, "status": self.status, "detail": self.detail,
        }


def _silent(fn, *a, **k):
    """Run fn capturing stdout (legs call noisy CLIs); return its result."""
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        return fn(*a, **k)


def _contract_exit(result) -> int:
    """Mirror the CLI: contract-check exits 1 iff overall is FAIL."""
    return 1 if result.overall == contract_check.FAIL else 0


def _fail_rules(result) -> set[str]:
    return {
        d.rule
        for f in result.findings
        for d in f.diagnostics
        if d.status == contract_check.FAIL
    }


# --- legs ------------------------------------------------------------------

def _leg_contract_real(proof_dir: Path) -> Leg:
    leg = Leg("contract-check:real", PASS_LEG,
              "exit 0 (a real captured receipt is accepted)")
    try:
        data = json.loads((proof_dir / "mr2-reachgate-receipts.json").read_text("utf-8"))
        result = contract_check.check_artifact(data)
        code = _contract_exit(result)
        leg.actual = f"exit {code} (overall={result.overall})"
        leg.status = OK if code == 0 else MISBEHAVED
        if leg.status == MISBEHAVED:
            leg.detail = "a valid captured receipt was rejected by contract-check"
    except Exception as exc:  # noqa: BLE001
        leg.status, leg.actual, leg.detail = ERROR, "exception", str(exc)
    return leg


def _leg_verify_real() -> Leg:
    leg = Leg("verify:real", PASS_LEG,
              "exit 0 (captured proof verifies offline)")
    try:
        code = int(_silent(verify_proof.main) or 0)
        leg.actual = f"exit {code}"
        leg.status = OK if code == 0 else MISBEHAVED
        if leg.status == MISBEHAVED:
            leg.detail = "the captured proof failed offline verification"
    except Exception as exc:  # noqa: BLE001
        leg.status, leg.actual, leg.detail = ERROR, "exception", str(exc)
    return leg


def _leg_unknown_stays_unknown(proof_dir: Path) -> Leg:
    leg = Leg("unknown-stays-unknown", PASS_LEG,
              "exit 0 AND UNKNOWN kept as evidence gap (never safe)")
    try:
        data = json.loads(
            (proof_dir / "unknown-reachgate-receipt.json").read_text("utf-8"))
        result = contract_check.check_artifact(data)
        code = _contract_exit(result)
        verdicts = {f.verdict for f in result.findings}
        gap_rules = {
            d.rule for f in result.findings for d in f.diagnostics
            if d.rule.startswith("unknown.")
        }
        unknown_preserved = verdicts == {"UNKNOWN"} and bool(gap_rules)
        leg.actual = f"exit {code}, verdicts={sorted(verdicts)}"
        if code == 0 and unknown_preserved:
            leg.status = OK
        else:
            leg.status = MISBEHAVED
            leg.detail = ("UNKNOWN was not preserved as a non-safe evidence gap"
                          if code == 0 else "contract-check rejected the UNKNOWN receipt")
    except Exception as exc:  # noqa: BLE001
        leg.status, leg.actual, leg.detail = ERROR, "exception", str(exc)
    return leg


def _leg_fake_green_rejected(tmp: Path) -> Leg:
    leg = Leg("contract-check:fake-green", FAIL_LEG,
              f"exit 1 with rule `{_EXPECTED_FAKE_GREEN_RULE}` "
              "(synthesized overclaim is rejected)")
    try:
        # Synthesize the adversarial receipt in tmp, carrying the SYNTHETIC
        # marker; it is removed with the temp dir and never readable as proof.
        path = tmp / "selftest-fake-green.json"
        path.write_text(json.dumps(_FAKE_GREEN, indent=2), encoding="utf-8")
        result = contract_check.check_file(str(path))
        code = _contract_exit(result)
        rules = _fail_rules(result)
        leg.actual = f"exit {code}, fail-rules={sorted(rules)}"
        if code == 1 and _EXPECTED_FAKE_GREEN_RULE in rules:
            leg.status = OK  # failed, for the right reason
        elif code != 1:
            leg.status = MISBEHAVED
            leg.detail = ("fake-green receipt was NOT rejected (safety "
                          "regression: an overclaim passed contract-check)")
        else:
            leg.status = MISBEHAVED
            leg.detail = (f"rejected, but not via `{_EXPECTED_FAKE_GREEN_RULE}` "
                          "(failed for the wrong reason -- noise, not proof)")
    except Exception as exc:  # noqa: BLE001
        leg.status, leg.actual, leg.detail = ERROR, "exception", str(exc)
    return leg


def _leg_tamper_breaks_signature(tmp: Path) -> Leg:
    leg = Leg("signature:tamper", FAIL_LEG,
              "untampered verifies, one flipped byte breaks the signature")
    from . import signing
    if not signing.crypto_available():
        leg.status = SKIPPED
        leg.actual = "skipped (no 'cryptography'; install reachgate[sign])"
        return leg
    try:
        priv, pub = signing.generate_keypair()
        artifact = tmp / "signed-artifact.bin"
        artifact.write_bytes(b"PK\x03\x04 reachgate signed evidence (selftest)")
        sig = tmp / "signed-artifact.bin.sig"
        signing.sign_file(artifact, priv, sig)

        good = signing.verify_file(artifact, pub, sig)
        artifact.write_bytes(artifact.read_bytes() + b"x")  # flip/append a byte
        bad = signing.verify_file(artifact, pub, sig)

        leg.actual = f"untampered={good}, tampered={bad}"
        if good and not bad:
            leg.status = OK
        elif not good:
            leg.status = ERROR
            leg.detail = "a fresh signature did not verify (setup noise, not proof)"
        else:  # tampered still verified -> the invariant broke
            leg.status = MISBEHAVED
            leg.detail = ("a tampered artifact still verified (signature "
                          "tamper-detection regression)")
    except Exception as exc:  # noqa: BLE001
        leg.status, leg.actual, leg.detail = ERROR, "exception", str(exc)
    return leg


# --- orchestration ---------------------------------------------------------

@dataclass
class SelfTestReport:
    legs: list[Leg] = field(default_factory=list)

    @property
    def exit_code(self) -> int:
        if any(l.status == ERROR for l in self.legs):
            return 2
        if any(l.status == MISBEHAVED for l in self.legs):
            return 1
        return 0

    def as_dict(self) -> dict:
        return {
            "overall": "pass" if self.exit_code == 0 else "fail",
            "exit_code": self.exit_code,
            "legs": [l.as_dict() for l in self.legs],
        }


def run_selftest() -> SelfTestReport:
    """Run all legs and return the report. Self-contained; cleans up its tmp."""
    proof_dir = _resources.proof_dir()
    report = SelfTestReport()
    with tempfile.TemporaryDirectory(prefix="reachgate-selftest-") as td:
        tmp = Path(td)
        report.legs.append(_leg_contract_real(proof_dir))
        report.legs.append(_leg_verify_real())
        report.legs.append(_leg_unknown_stays_unknown(proof_dir))
        report.legs.append(_leg_fake_green_rejected(tmp))
        report.legs.append(_leg_tamper_breaks_signature(tmp))
    # tmp (and the synthesized adversarial receipt) is gone here.
    return report


# --- rendering -------------------------------------------------------------

_MARK = {OK: "OK ", MISBEHAVED: "!! ", ERROR: "ERR", SKIPPED: "-- "}


def render_text(report: SelfTestReport) -> str:
    lines = [
        "ReachGate adversarial self-proof",
        "(invariant regression test: must-pass passes, must-fail fails for the "
        "right reason)",
        "",
    ]
    for leg in report.legs:
        lines.append(f"[{_MARK.get(leg.status, '?')}] {leg.kind}  {leg.name}")
        lines.append(f"      expected: {leg.expected}")
        lines.append(f"      actual:   {leg.actual}")
        if leg.detail:
            lines.append(f"      note:     {leg.detail}")
    lines.append("")
    if report.exit_code == 0:
        lines.append("RESULT: PASS -- every invariant held. Reproduce this "
                     "yourself; nothing here is taken on trust.")
    elif report.exit_code == 1:
        lines.append("RESULT: FAIL -- an invariant was violated (see !! above). "
                     "This is a real regression in the safety guarantees.")
    else:
        lines.append("RESULT: ERROR -- a leg could not run cleanly (see ERR "
                     "above); the invariant was not proven, not disproven.")
    return "\n".join(lines) + "\n"


def render_json(report: SelfTestReport) -> str:
    return json.dumps(report.as_dict(), indent=2, ensure_ascii=False) + "\n"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="reachgate selftest",
        description=(
            "Adversarial self-proof: reproduce ReachGate's safety invariants "
            "offline. Exits non-zero if any invariant is violated."
        ),
    )
    parser.add_argument("--format", choices=("text", "json"), default="text",
                        help="output format (default: text).")
    parser.add_argument("--output", default=None,
                        help="write the report to a file instead of stdout.")
    args = parser.parse_args(argv)

    report = run_selftest()
    rendered = render_json(report) if args.format == "json" else render_text(report)

    if args.output:
        out = Path(args.output)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(rendered, encoding="utf-8")
        print(f"wrote {out}")
    else:
        print(rendered, end="")
    return report.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
