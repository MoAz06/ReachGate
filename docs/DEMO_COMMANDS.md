# ReachGate demo commands

Copy-pastable commands for a judge or a quick demo. Run them from the repo root
after installing the package:

```bash
pip install -e ".[dev]"
```

Everything below is **offline**: no GitLab token, no Orbit, no network.

## The two-minute walkthrough

```bash
# 1. See the offline evidence CLI
reachgate --help

# 2. Verify the captured receipts + cross-check OpenVEX/SARIF (exits 0)
reachgate verify

# 3. Enforce the Evidence Contract on a REAL captured receipt -> PASS (exits 0)
reachgate contract-check docs/proof/mr2-reachgate-receipts.json

# 4. Try to fake green: a synthetic receipt that claims NOT_REACHABLE while its
#    search timed out -> FAIL (exits 1). The contract rejects the overclaim.
reachgate contract-check tests/fixtures/contract_violations/not-reachable-timeout-hit.json

# 5. Verify a fix from before/after receipts -> reachability_removed
reachgate fixcheck \
  tests/fixtures/fixcheck/before-reachable.json \
  tests/fixtures/fixcheck/after-not-reachable-exhaustive.json \
  --format markdown

# 6. Coverage / blind-spot report (verdicts, UNKNOWN reasons, limitations)
reachgate coverage

# 7. Build a portable, offline-verifiable evidence capsule (zip in dist/)
reachgate capsule build
```

If the `reachgate` entry point is not on your PATH, use
`python -m reachgate.cli ...` with the same arguments.

## PASS / FAIL contrast (the point)

This is the differentiator: ReachGate does not ask you to trust its output. The
**same command** accepts honest evidence and rejects fake-green evidence.

| Command | Result | Exit code |
|---|---|---|
| `reachgate verify` | proof verified | `0` |
| `reachgate contract-check docs/proof/mr2-reachgate-receipts.json` | **PASS** | `0` |
| `reachgate contract-check tests/fixtures/contract_violations/not-reachable-timeout-hit.json` | **FAIL** | `1` |
| `reachgate contract-check tests/fixtures/contract_violations/not-reachable-api-errors.json` | **FAIL** | `1` |
| `reachgate contract-check tests/fixtures/contract_violations/not-reachable-frontier-not-exhausted.json` | **FAIL** | `1` |

The real captured receipt passes because its `NOT_REACHABLE` search ran to
completion (frontier exhausted, no bound hit, 0 API errors). Each synthetic
fixture tries to claim a safe-within-bounds `NOT_REACHABLE` while violating
exactly one of those preconditions, so `contract-check` returns FAIL and exits
non-zero. An overclaiming negative cannot pass a gate unnoticed.

## Honesty notes

- The files under `tests/fixtures/contract_violations/` are **synthetic
  overclaiming fixtures**, not live captured proof artifacts. They exist only to
  demonstrate `contract-check` rejecting unsafe claims, and are never included
  in `docs/proof/`, the evidence manifest, the capsule, or the verifier.
- The files under `tests/fixtures/fixcheck/` are a **synthetic demo fixture**
  showing the fix-verification workflow. Real usage compares before/after
  receipts produced by actual ReachGate runs.
- `UNKNOWN` is always treated as an evidence gap, never as safe.
  `NOT_REACHABLE` is safe only within the configured search bounds, and only
  when the search was exhaustive.

See the [Evidence Contract](EVIDENCE_CONTRACT.md) for exactly which claims a
receipt supports, and the [Judge Pack](JUDGE_PACK.md) for the full walkthrough.
