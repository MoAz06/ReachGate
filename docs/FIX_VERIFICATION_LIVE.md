# Live fix verification — capturing a real before/after artifact

`reachgate fixcheck` proves, deterministically, whether a fix actually removed
reachability: it compares a **BEFORE** receipt (the finding was `REACHABLE`) with
an **AFTER** receipt (the same finding is now an *exhaustive* `NOT_REACHABLE`)
and only then reports `reachability_removed`. See
[`fixproof.py`](../src/reachgate/fixproof.py) for the exact rules.

The shipped demo of this workflow uses a **synthetic fixture**
(`tests/fixtures/fixcheck/before-reachable.json` and
`after-not-reachable-exhaustive.json`), and is honestly labelled as such in
[`DEMO_COMMANDS.md`](DEMO_COMMANDS.md). This document describes how to capture a
**real, live** before/after artifact from GitLab Orbit, so the
`reachability_removed` claim rests on captured production evidence rather than a
hand-written fixture.

> **Status.** A real live capture needs (a) a GitLab PAT with `api` scope, and
> (b) a project that GitLab Orbit has **indexed** and whose code you can
> **change** to break the path. ReachGate's own provisioned project is not in
> the Orbit index (see [PROJECT.md §6](../PROJECT.md)), so the live capture is
> run against a suitable indexed project; the synthetic fixture remains the
> default demo until a real capture is recorded. Nothing half-captured is ever
> committed to `docs/proof/` — an AFTER run that comes back `UNKNOWN` or a
> non-exhaustive `NOT_REACHABLE` is **not** a fix and must not be presented as
> one.

## What "a real fix" must do

The AFTER run only earns `reachability_removed` when the code change genuinely
severs the graph path — not merely edits a line on it. Concretely:

- the BEFORE receipt is `REACHABLE` with a recorded `path`;
- the change removes a `DEFINES` / `IMPORTS` / `CALLS` edge on that path (e.g.
  drops the import/call that reaches the vulnerable definition from the declared
  entry point), so no path remains;
- the AFTER walk runs to completion: `frontier_exhausted = true`, no bound hit,
  `api_errors = 0` → an **exhaustive** `NOT_REACHABLE`.

If the change only edits a file on the path without cutting an edge, the finding
stays `REACHABLE` (use `reachgate blame` to see "this change touches files on
the reachable path" — an overlap, *not* a fix).

## Procedure

Both receipts are produced by the normal live engine and written with
[`actions.write_artifact`](../src/reachgate/actions.py) (the same artifact shape
`fixcheck`, `verify`, and `contract-check` consume).

```bash
export GITLAB_URL="https://gitlab.com"
export GITLAB_TOKEN="glpat-xxxxx"          # api scope
export GITLAB_PROJECT_ID="<indexed project id>"
```

1. **Capture BEFORE (REACHABLE).** Run the engine against the indexed project
   and save the receipt artifact:

   ```bash
   python -m reachgate.agent            # live walk; or tools/demo_e2e.py
   # persist the run's receipts to a file via actions.write_artifact(...),
   # e.g. before-reachable.json
   ```

   Confirm it is genuinely reachable:

   ```bash
   reachgate contract-check before-reachable.json   # REACHABLE is exploitable context
   ```

2. **Make the fix.** In the indexed project, change the code so the path is
   severed (remove the reaching import/call), and let Orbit re-index the new
   commit (push to a branch Orbit indexes).

3. **Capture AFTER (exhaustive NOT_REACHABLE).** Re-run the engine against the
   fixed commit and save the second receipt:

   ```bash
   python -m reachgate.agent
   # persist to after-not-reachable-exhaustive.json
   ```

   Confirm the negative is *earned*, not an evidence gap:

   ```bash
   reachgate contract-check after-not-reachable-exhaustive.json
   # PASS only when NOT_REACHABLE is exhaustive (frontier exhausted, 0 bounds
   # hit, 0 API errors). A non-exhaustive negative or UNKNOWN FAILS here — and
   # must not be promoted to a "fix".
   ```

4. **Prove the fix.**

   ```bash
   reachgate fixcheck before-reachable.json after-not-reachable-exhaustive.json \
     --format markdown
   ```

   This reports `reachability_removed` for the finding **only** because the
   AFTER receipt is an exhaustive `NOT_REACHABLE` under the **same** policy
   version. UNKNOWN is never a fix; a different policy version is incomparable.

## Promoting a capture to committed proof

Only once steps 1–4 produce a clean `reachability_removed` should the two real
receipts be added under `docs/proof/` (and, optionally, wired into the judge
proof / capsule). Until then the synthetic fixture stands in, clearly labelled,
so the repository never overclaims a fix it has not actually captured.
