# fixcheck demo fixtures

These two files are **synthetic demo/test fixtures**. They are **not** live
captured proof artifacts and must never be presented as one. They exist only to
demonstrate the `reachgate fixcheck` workflow end to end without a live
GitLab/Orbit dependency.

- `before-reachable.json` — finding `demo-fix-ssrf` is `REACHABLE` (a graph path
  runs from the declared entry point `src/routes/api.js` to the vulnerable
  definition `fetchRemote`).
- `after-not-reachable-exhaustive.json` — the same finding identity
  (`demo-fix-ssrf`) under the **same policy version** is now `NOT_REACHABLE`
  with an **exhaustive** search (`frontier_exhausted: true`, no bounds hit,
  `api_errors: 0`).

Run:

```bash
reachgate fixcheck \
  tests/fixtures/fixcheck/before-reachable.json \
  tests/fixtures/fixcheck/after-not-reachable-exhaustive.json \
  --format markdown
```

Expected classification: **`reachability_removed`** — and only because the
after verdict is an exhaustive `NOT_REACHABLE` under the same policy. An after
`UNKNOWN`, a non-exhaustive `NOT_REACHABLE`, or a different policy version would
be `incomparable`, never "fixed".

Real usage compares before/after receipts produced by actual ReachGate runs;
this fixture only shows the shape of that workflow.
