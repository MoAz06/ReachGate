# ReachGate Evidence Contract

ReachGate is a **portable evidence layer for vulnerability reachability, not a
scanner**. This document is the contract: it states exactly which claims a
downstream tool, developer, or reviewer may draw from a ReachGate receipt, and
which they may not.

Every statement below is enforced by code and cross-checked by the offline
verifier (`tools/verify_proof.py`); this file documents those invariants, it
does not add new ones. The deterministic engine decides; the AI only explains.

---

## What ReachGate evidence means

Each finding produces one **receipt**: a verdict, a `verdict_basis`, the graph
path, a reachability **certificate** (search bounds, counters, flags), and a
stable **fingerprint**. The verdict is one of three values
(`src/reachgate/policy_engine.py`):

- **`REACHABLE`** — a graph path was found from a configured entry point /
  attack surface to the vulnerable definition, and the deterministic rule
  score crossed the policy threshold. `verdict_basis = path_found`.
- **`NOT_REACHABLE`** — no path was found, **only within the configured search
  bounds** and **only when the search ran to completion under those bounds**.
  `verdict_basis = no_path_search_exhaustive`. This is a bounded negative, not
  a global safety claim.
- **`UNKNOWN`** — a typed evidence gap. The search could not earn `REACHABLE`
  *or* an exhaustive `NOT_REACHABLE` (no code location, nothing indexed, no
  entry points resolved, a search bound was hit, or an API call failed).
  `verdict_basis = insufficient_evidence:<reason>`. UNKNOWN is **never** safe
  and is **never** the same as `NOT_REACHABLE`. Every reason carries a
  deterministic next action (`src/reachgate/guidance.py`).

---

## Preconditions for safe (bounded) claims

A `NOT_REACHABLE` verdict may be treated as **safe within the configured
bounds** only when its certificate shows every one of the following
(`is_exhaustive_not_reachable` in `src/reachgate/fixproof.py`,
`is_exhaustive` in `tools/export_vex.py`, and `verify_proof.py`):

- `frontier_exhausted == true`
- `api_errors == 0`
- `max_hops_hit == false`
- `visited_cap_hit == false`
- `timeout_hit == false`
- the policy and bounds are exactly those recorded in the certificate

If any bound was hit or any API call failed, the engine does not emit
`NOT_REACHABLE` at all — it emits `UNKNOWN`. "Safe" here always means
"no path within these declared entry points and these recorded bounds", never
"globally unreachable".

---

## OpenVEX contract

The OpenVEX export (`tools/export_vex.py`) maps receipts conservatively,
because a VEX `not_affected` tells every downstream consumer to ignore a CVE:

- `REACHABLE` → `affected` (with an `action_statement` naming the graph path).
- `NOT_REACHABLE` → `not_affected` **only** when the search was exhaustive (see
  preconditions above), with `justification = vulnerable_code_not_in_execute_path`.
- `UNKNOWN` → `under_investigation`.
- Any `NOT_REACHABLE` whose certificate shows a hit bound or an API error →
  `under_investigation`, **never** `not_affected`.

Incomplete evidence may never become `not_affected`. The verifier
independently re-asserts this invariant (`crosscheck` in `export_vex.py`):
nothing whose search did not complete may read as `not_affected`.

Fit note: VEX is conventionally a CVE/component (SCA) artifact. CVE-bearing
findings map cleanly; SAST/CWE-style findings are carried as statements against
the project as the product — honest, but not canonical SCA-VEX.

---

## SARIF contract

The SARIF 2.1.0 export (`tools/export_sarif.py`) maps receipts to result
levels:

- `REACHABLE` → level `error`, with the real graph path rendered as a SARIF
  `codeFlow`/`threadFlow`.
- `NOT_REACHABLE` → level `note`, with the wording "not reachable within
  configured search bounds" — never "safe".
- `UNKNOWN` → level `warning`, a typed evidence gap with a next action, never
  presented as safe.

Each result carries the receipt fingerprint in `partialFingerprints`. Source
locations are emitted only where the receipt actually carries a file; ReachGate
never invents a location or line.

---

## Fix verification contract

`reachgate fixcheck BEFORE AFTER` (`src/reachgate/fixproof.py`) compares two
receipt artifacts and is a **derived, offline** layer: it never re-decides a
verdict and never calls GitLab/Orbit. ReachGate **verifies fixes from
before/after receipts**; it does not itself fix anything.

`reachability_removed` is claimed **only** when all of the following hold:

- before verdict is `REACHABLE`
- after verdict is `NOT_REACHABLE` and **exhaustive** (frontier exhausted, no
  bound hit, `api_errors == 0`)
- the finding identity (`occurrence_id`) matches before and after
- the policy version is identical (top-level and per-finding certificate)

`reachability_introduced` is claimed when the before is an exhaustive
`NOT_REACHABLE` (or the finding is absent before) and the after is `REACHABLE`.

`incomparable` is used — and the result is **never** called fixed or safe —
when any of the following hold:

- the policy version differs between the two artifacts
- the after receipt is `UNKNOWN`
- the after `NOT_REACHABLE` is not exhaustive
- finding identity is missing or ambiguous (duplicate / absent `occurrence_id`)
- a `REACHABLE` finding is simply dropped in the after artifact (no proof it
  was fixed rather than removed from the input)

Findings are matched by stable `occurrence_id`, not the receipt fingerprint:
the fingerprint folds in the verdict and path, which by design change when a
finding is fixed.

The included demo fixture under `tests/fixtures/fixcheck/` is a **synthetic
demo fixture, not a live captured proof artifact**. Real usage compares
before/after receipts produced by actual ReachGate runs.

---

## Fingerprint contract

The receipt fingerprint (`src/reachgate/certificate.py`) is a hash over the
finding identity, verdict, path, policy version, and declared attack surface —
never timing or call counts. It therefore:

- **proves** stable identity of a receipt/result under the same evidence
  inputs and the same policy (the same finding under the same policy
  fingerprints identically, which is what makes MR triage idempotent);
- is **not** a cryptographic signature, and does not attest authorship;
- does **not** prove the source repository is unchanged since the walk;
- does **not** make an `UNKNOWN` safe, and does not upgrade any verdict.

---

## Verifier contract

`python tools/verify_proof.py` is standard library only — no token, no network.
Against the captured artifacts in `docs/proof/` it checks that:

- the MR !2 receipt has both a `REACHABLE` and a `NOT_REACHABLE` finding with
  the expected `verdict_basis`;
- the MR !3 rerun has the **same fingerprints** for the same findings
  (idempotency);
- every `NOT_REACHABLE` is **exhaustive** (frontier exhausted, no bound hit,
  `api_errors == 0`);
- `UNKNOWN` stays honest: a real indexed file with no definitions yields
  `insufficient_evidence:no_definitions_indexed`, `frontier_exhausted == false`
  — never a fake-green `NOT_REACHABLE`;
- the exported **OpenVEX** cross-checks against the receipts (status mapping
  faithful; nothing non-exhaustive reads as `not_affected`);
- the exported **SARIF** cross-checks against the receipts (levels,
  fingerprints, `NOT_REACHABLE` wording, `UNKNOWN` evidence-gap framing).

It exits `0` only when every check passes. This is what makes every exported
claim falsifiable rather than asserted.

---

## Non-claims

ReachGate explicitly does **not** claim to be any of the following:

- a full exploitability proof — reachability is necessary context, not a
  complete exploit demonstration;
- a production incident-response platform;
- an automated remediation tool — it does **not** fix vulnerabilities; it
  verifies fixes from before/after receipts;
- a source of global unreachability claims — `NOT_REACHABLE` is scoped to the
  configured entry points and recorded search bounds only;
- a tool that ever treats `UNKNOWN` as safe;
- a producer of live proof from its demo fixtures — those are clearly labelled
  synthetic fixtures, not captured evidence.

---

## Downstream consumer rules

For tools and CI integrating ReachGate evidence:

- **Gate only on `REACHABLE` or on newly introduced reachability.** A receipt
  diff turning `NOT_REACHABLE`/absent into `REACHABLE` is the blocking signal
  (`tools/diff_receipts.py --fail-on-new-reachable`).
- **Treat `UNKNOWN` as needs-review, not pass.** UNKNOWN is an evidence gap
  with a next action, not a safe verdict.
- **Treat `NOT_REACHABLE` as scoped to the certificate bounds**, not as global
  safety.
- **Accept `reachability_removed` only under the fix verification contract
  above** — exhaustive after `NOT_REACHABLE`, same identity, same policy.
  Treat `incomparable` as "not proven", never as fixed.
- **Verify receipts before trusting exported evidence.** Run
  `tools/verify_proof.py` (or `reachgate verify`) before relying on the
  OpenVEX, SARIF, or evidence capsule derived from them.
