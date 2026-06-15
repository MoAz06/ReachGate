# Integrations — ReachGate as an evidence router

ReachGate is not just a scanner. It is an **offline-verifiable reachability
evidence layer**: one deterministic source of truth (the receipts) routed into
the standards downstream tooling already understands. The deterministic engine
decides; the AI only explains; every exported claim is cross-checked back
against the receipts.

```text
                       ┌────────────────────────────┐
   live Orbit walk ──▶ │  Receipts (source of truth) │
                       │  verdict · path · cert · fp │
                       └──────────────┬──────────────┘
                                      │  (derived, offline, deterministic)
            ┌─────────────────────────┼─────────────────────────┐
            ▼                         ▼                          ▼
   ┌─────────────────┐      ┌──────────────────┐      ┌────────────────────┐
   │     OpenVEX     │      │   SARIF 2.1.0    │      │  Evidence manifest │
   │  CVE / SCA      │      │  SAST / codeflow │      │  artifact integrity│
   └─────────────────┘      └──────────────────┘      └────────────────────┘
            │                         │                          │
            ▼                         ▼                          ▼
   supply-chain / SCA        code-scanning UIs          reviewers / pipelines
   tooling                                              (sha256 cross-check)
```

All exports are **derived only from the receipts**, deterministic (stable
order, no wall-clock timestamps), and standard library only.

## Receipts — the source of truth

Every verdict is recorded as a receipt: the verdict, the `verdict_basis`, the
graph path, a reachability certificate (search bounds, counters, flags), and a
stable fingerprint. The CI job uploads them as `reachgate-receipts.json`. The
exports below never re-decide anything — they re-shape the same receipts.

```bash
reachgate verify     # cross-checks every export back against the receipts
reachgate coverage   # verdict / UNKNOWN-reason / blind-spot summary
```

## OpenVEX → supply-chain / SCA tooling

[OpenVEX](https://openvex.dev/) tells downstream consumers whether a known CVE
actually affects a product. ReachGate maps conservatively, because a VEX
`not_affected` tells everyone to ignore a CVE:

- `REACHABLE` → `affected` (with an action statement)
- `NOT_REACHABLE` → `not_affected` **only if the search was exhaustive**
  (justification `vulnerable_code_not_in_execute_path`)
- `UNKNOWN`, or any `NOT_REACHABLE` whose certificate shows a hit bound or an
  API error → `under_investigation`, never `not_affected`

```bash
reachgate export-vex     # writes docs/proof/reachgate.openvex.json
```

Fit note: VEX is conventionally a CVE/component (SCA) artifact. CVE-bearing
findings map cleanly; SAST/CWE-style findings are carried as statements against
the project as the product — honest, but not canonical SCA-VEX.

## SARIF → code-scanning tooling

[SARIF 2.1.0](https://sarifweb.azurewebsites.net/) is the standard format for
static-analysis results, consumed by code-scanning UIs.

- `REACHABLE` → result level `error`, with the real graph path rendered as a
  SARIF `codeFlow`/`threadFlow`
- `NOT_REACHABLE` → level `note`, "not reachable within configured search
  bounds" (never "safe")
- `UNKNOWN` → level `warning`, typed evidence gap with a next action, never
  presented as safe

Each result carries the receipt fingerprint in `partialFingerprints`. Source
locations are only emitted where the receipt carries a file — never invented.

```bash
reachgate export-sarif   # writes docs/proof/reachgate.sarif.json
```

## Evidence manifest → artifact integrity

`reachgate manifest` writes a sha256 over the **machine-readable** artifacts
(the receipts, the OpenVEX, the SARIF) so a reviewer — or a downstream pipeline
— can confirm offline they are looking at the exact evidence ReachGate
produced, and re-derive each artifact from the recorded commands.

```bash
reachgate manifest       # writes docs/proof/reachgate.evidence-manifest.json
```

It deliberately does **not** hash `docs/judge-proof.html`: that page is
generated from these same artifacts, so hashing it would be circular. A missing
artifact is reported explicitly (`present: false`, `sha256: null`).

## Coverage / blind spots → triage intelligence

`reachgate coverage` turns ReachGate's own honesty into a report: verdict
counts, UNKNOWN reason counts (each with the typed meaning and next action),
which findings have a code anchor vs. dependency/SCA advisories with none, the
observed entry points and reachable paths, and an explicit blind-spots section.

```bash
reachgate coverage --format json
```

Almost no tool shows you its own uncertainty. ReachGate makes that uncertainty
a structured, actionable surface instead of hiding it.

## Fix verification → before/after receipt delta

`reachgate fixcheck BEFORE AFTER` is a derived, offline layer over two receipt
artifacts: it consumes the receipts from two runs and proves whether
reachability was **removed**, **introduced**, left **unchanged**, or is
**incomparable**. It never re-decides a verdict and never calls Orbit.

ReachGate can compare two receipt artifacts and verify whether reachability was
removed — **only when the after receipt is exhaustive**:

- `reachability_removed` → before `REACHABLE`, after `NOT_REACHABLE` with an
  exhaustive search (frontier exhausted, no bound hit, 0 API errors), same
  policy version
- `reachability_introduced` → before exhaustively `NOT_REACHABLE` (or absent),
  after `REACHABLE`
- `unchanged` → equivalent verdict and evidence on both sides
- `incomparable` → policy version differs, identity cannot be matched, the
  after is `UNKNOWN`, or the after `NOT_REACHABLE` is not exhaustive

```bash
reachgate fixcheck before.json after.json --format json
```

Findings are matched by their stable `occurrence_id`, not the receipt
fingerprint (the fingerprint folds in the verdict and path, which by design
change when a finding is fixed). `UNKNOWN` is never "fixed", and a different
policy version is never a fix or a regression — it is incomparable. By default
it writes no tracked artifact.

## Contract check → enforceable evidence rules

`reachgate contract-check RECEIPT.json` makes the [Evidence
Contract](EVIDENCE_CONTRACT.md) enforceable on arbitrary receipts: a downstream
CI job can validate that a receipt only makes claims the contract allows, and
exit non-zero when one overclaims (for example a non-exhaustive `NOT_REACHABLE`
presented as safe-within-bounds). `UNKNOWN` is always validated as an evidence
gap, never as safe. It re-decides nothing and makes no live calls.

```bash
reachgate contract-check docs/proof/mr2-reachgate-receipts.json --format json
```

## The offline verifier → falsifiability

`reachgate verify` (a.k.a. `python tools/verify_proof.py`) is standard library
only, no token, no network. It verifies the receipts and cross-checks the
OpenVEX and SARIF back against them — so every exported claim is falsifiable,
not just asserted.

## What ReachGate does not claim

- Not production-ready and not certified — it is advisory by default.
- `NOT_REACHABLE` is scoped to the configured search bounds, not a global
  safety guarantee.
- Reachability is only as complete as the declared entry points and Orbit's
  indexing/language coverage.

See the [Evidence Contract](EVIDENCE_CONTRACT.md) for exactly which claims a
receipt supports for downstream consumers, the [Judge Pack](JUDGE_PACK.md) for a
guided walkthrough, and the [GitLab CI setup](GITLAB_CI_SETUP.md) for the live
workflow.
