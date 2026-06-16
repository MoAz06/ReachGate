# contract-violation fixtures

These files are **synthetic overclaiming fixtures**. They are:

- **synthetic / test / demo fixtures**, not live captured proof;
- **not** proof artifacts;
- **not** included in `docs/proof/`, the evidence manifest, the capsule, or the
  offline verifier;
- used **only** to demonstrate that `reachgate contract-check` rejects unsafe
  claims.

Each fixture tries to claim `NOT_REACHABLE` (which the Evidence Contract treats
as "safe within configured bounds") while violating exactly one of the
exhaustiveness preconditions from `docs/EVIDENCE_CONTRACT.md`:

- `not-reachable-timeout-hit.json` — `timeout_hit: true`
- `not-reachable-api-errors.json` — `api_errors > 0`
- `not-reachable-frontier-not-exhausted.json` — `frontier_exhausted: false`

All three must be reported as **FAIL** by `reachgate contract-check`. They show
that a receipt cannot fake a safe-within-bounds negative: the contract check
rejects it. They must never be presented as real ReachGate evidence.
