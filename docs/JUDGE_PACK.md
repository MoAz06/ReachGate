# ReachGate Judge Pack

Everything a judge needs to evaluate ReachGate in a few minutes: what it is,
what to open, what to run, and crisp answers to the questions you are most
likely to ask. Standards-aligned, offline-verifiable, advisory by default.

---

## 60-second pitch

Security scanners drown teams in findings. The hard question is never "is this
a known vuln?" — it is **"can it actually be reached in *our* code?"**

ReachGate answers that question deterministically. For each finding it walks
the GitLab Orbit code graph from declared entry points to the vulnerable
definition and emits one of three verdicts, each backed by an auditable
**receipt** (the walk, a reachability certificate, and a stable fingerprint):

- **REACHABLE** — a graph path exists from an entry point to the vulnerable code. Escalate.
- **NOT_REACHABLE** — every walk emptied its frontier within the configured bounds, with 0 bounds hit and 0 API errors. Deprioritize. (Within configured bounds, *not* a global safety claim.)
- **UNKNOWN** — the evidence was insufficient (no code location, a hit bound, an API error). Flag for review. Never dressed up as safe.

The differentiator: ReachGate is an **evidence layer, not just a scanner**.
The same receipts are exported as **OpenVEX** (CVE/SCA), **SARIF 2.1.0**
(SAST/code-flow), and an **evidence manifest** (artifact integrity), and an
**offline verifier** cross-checks every exported claim back against the
receipts. The deterministic engine decides; the AI only explains.

---

## What to open first

1. **`docs/judge-proof.html`** — the visual case file. Open it in any browser, fully offline (no JS, no CDN). Each verdict is a live exhibit rendered from the captured receipts, with a "Portable evidence" section showing the four downstream evidence pillars.
2. **`docs/JUDGE_REPLAY.md`** — the two-minute replay kit (offline check + live merge requests).
3. **This file (`docs/JUDGE_PACK.md`)** — orientation and Q&A.
4. **`docs/EVIDENCE_CONTRACT.md`** — the contract: exactly which claims a receipt supports (and which it does not), all enforced by the verifier.
5. **`docs/DEMO_COMMANDS.md`** — copy-pastable demo commands, including the "try to fake green" PASS/FAIL contrast.

---

## What to run

From the repo root, standard library only — no install, no token, no network:

```bash
# 1. Verify the captured receipts + cross-check OpenVEX and SARIF (source of truth)
python tools/verify_proof.py

# 2. Regenerate the portable evidence artifacts from the receipts
python tools/export_vex.py
python tools/export_sarif.py
python tools/build_evidence_manifest.py
python tools/build_judge_proof.py

# 3. Full test suite
pytest
```

Or, with the installed CLI (`pip install -e ".[dev]"`), the same offline surface
in one command set:

```bash
reachgate verify                 # verify receipts + cross-check OpenVEX/SARIF
reachgate coverage               # verdict / UNKNOWN-reason / blind-spot report
reachgate coverage --format html --output coverage.html   # same, as static HTML
reachgate policy explain         # the recorded policy, with honest provenance
reachgate contract-check docs/proof/mr2-reachgate-receipts.json   # enforce the Evidence Contract
reachgate judge                  # one command: verify -> exports -> manifest -> proof
reachgate capsule build          # portable evidence capsule -> dist/reachgate-evidence-capsule.zip
```

`reachgate capsule build` produces a deterministic, gitignored zip with the
receipts, OpenVEX, SARIF, evidence manifest, judge-proof HTML, this Judge Pack,
and a `HOW_TO_VERIFY.txt` — a portable bundle a reviewer can verify offline.

Optional (fix verification, offline): `reachgate fixcheck BEFORE AFTER`
compares two receipt artifacts and proves whether reachability was removed,
introduced, unchanged, or incomparable. ReachGate can compare two receipt
artifacts and verify whether reachability was removed **only when the after
receipt is exhaustive** (frontier exhausted, no bound hit, 0 API errors, same
policy version); an after `UNKNOWN`, a non-exhaustive `NOT_REACHABLE`, or a
policy-version change is `incomparable`, never "fixed". Demo idea: run it on the
two captured idempotency-rerun receipts to show every finding is `unchanged`
(no spurious fix or regression):

```bash
reachgate fixcheck docs/proof/mr2-reachgate-receipts.json \
                   docs/proof/mr3-reachgate-receipts-rerun.json
```

### Fix verification demo

Real usage compares before/after receipts produced by **actual** ReachGate
runs (the same finding, scanned before and after a code fix). To show the
workflow without a live dependency, the repo includes a **synthetic demo
fixture** (clearly labelled, not a live captured proof) under
`tests/fixtures/fixcheck/`: a `REACHABLE` before receipt and an **exhaustive**
`NOT_REACHABLE` after receipt for the same finding under the same policy.

```bash
reachgate fixcheck \
  tests/fixtures/fixcheck/before-reachable.json \
  tests/fixtures/fixcheck/after-not-reachable-exhaustive.json \
  --format markdown
```

It reports `reachability_removed` — **only** because the after verdict is an
exhaustive `NOT_REACHABLE` under the same policy version. An after `UNKNOWN`, a
non-exhaustive `NOT_REACHABLE`, or a different policy version is reported as
`incomparable`, never as fixed or safe. The `--format markdown` output is
MR-comment ready (before/after verdicts, status, fingerprints, and the reason),
and `--output PATH` writes it anywhere without touching any tracked artifact.

Expected: `verify_proof.py` (or `reachgate verify`) prints `ReachGate proof
verified` and exits `0`; the test suite passes.

---

## Artifact map

| Artifact | Type | Generated by | Purpose |
|---|---|---|---|
| `docs/proof/mr2-reachgate-receipts.json` | reachability receipt | captured from MR !2 | Canonical proof: one REACHABLE, one exhaustive NOT_REACHABLE. |
| `docs/proof/mr3-reachgate-receipts-rerun.json` | reachability receipt | captured from MR !3 | Idempotency rerun: byte-identical fingerprints. |
| `docs/proof/unknown-reachgate-receipt.json` | reachability receipt | captured UNKNOWN | The honest third verdict (no definitions to walk to). |
| `docs/proof/reachgate.openvex.json` | OpenVEX | `tools/export_vex.py` | CVE/SCA exploitability context for supply-chain tooling. |
| `docs/proof/reachgate.sarif.json` | SARIF 2.1.0 | `tools/export_sarif.py` | SAST/code-flow evidence for code-scanning UIs. |
| `docs/proof/reachgate.evidence-manifest.json` | manifest | `tools/build_evidence_manifest.py` | sha256 over the machine-readable artifacts. |
| `docs/judge-proof.html` | human view | `tools/build_judge_proof.py` | Visual case file (deliberately not hashed in the manifest). |

---

## OpenVEX explanation

[OpenVEX](https://openvex.dev/) is a standard way to tell downstream
supply-chain tooling whether a known CVE actually affects a product. ReachGate
maps its reachability verdicts to OpenVEX statuses conservatively, because a
VEX `not_affected` tells every consumer to ignore a CVE:

- REACHABLE → `affected` (with an action statement)
- NOT_REACHABLE → `not_affected` **only if the search was exhaustive**, with justification `vulnerable_code_not_in_execute_path`
- UNKNOWN → `under_investigation`
- a NOT_REACHABLE whose certificate shows a hit bound or an API error → `under_investigation`, never `not_affected`

That last rule is the point: ReachGate refuses to emit a clean `not_affected`
from a search that did not run to completion. The verifier cross-checks this.

Fit note: VEX is conventionally a CVE/component (SCA) artifact. CVE-bearing
findings map cleanly; SAST/CWE-style findings are carried as statements against
the project as the product — honest, but not canonical SCA-VEX.

---

## SARIF explanation

[SARIF 2.1.0](https://sarifweb.azurewebsites.net/) is the standard format for
static-analysis and code-scanning results. ReachGate exports a
standards-aligned SARIF document so code-scanning UIs can consume the
reachability evidence machine-readably:

- REACHABLE → result level `error`, with the **real graph path rendered as a SARIF `codeFlow`/`threadFlow`** (file nodes carry a physical location; definition nodes are carried as the step message). Source locations are only emitted when the receipt actually carries a file — never invented.
- NOT_REACHABLE → level `note`, message states "not reachable within configured search bounds" (never "safe").
- UNKNOWN → level `warning`, with typed guidance and a next action; never presented as safe.

Each result carries the receipt fingerprint in `partialFingerprints`, so a
SARIF result maps back to its receipt. The verifier cross-checks levels,
fingerprints, the NOT_REACHABLE wording, and the UNKNOWN evidence-gap framing.

---

## Evidence manifest explanation

`tools/build_evidence_manifest.py` produces
`docs/proof/reachgate.evidence-manifest.json`: a sha256 over the
**machine-readable** artifacts only (the three receipt JSONs, the OpenVEX, and
the SARIF). A reviewer — or a downstream pipeline — can confirm offline that
the evidence they are looking at is the exact evidence ReachGate produced, and
re-derive each artifact from the recorded generation and verifier commands.

It deliberately does **not** hash `docs/judge-proof.html`: that page is itself
generated from these same artifacts, so hashing it would create a circular
generated-artifact dependency. A missing artifact is reported explicitly
(`present: false`, `sha256: null`), never silently dropped. Output is
deterministic (fixed order, no wall-clock timestamp). The repo commit SHA is
recorded when git is available, but its absence is never fatal.

---

## UNKNOWN explanation

UNKNOWN is the honesty mechanism, and it is a first-class verdict, not an
error. ReachGate returns UNKNOWN whenever it cannot earn REACHABLE *or* an
exhaustive NOT_REACHABLE — for example a finding with no code location, a
search that hit a configured bound, or an API error. The captured example
(`gem/puma/CVE-2026-47736.yml`) is a file Orbit has indexed but with **zero
code definitions** to walk to, so:

- verdict `UNKNOWN`, basis `insufficient_evidence:no_definitions_indexed`
- `target_definitions_found == 0`, `api_errors == 0`, no bound hit
- `frontier_exhausted == false` — the search never ran to exhaustion, so it is **not** a NOT_REACHABLE

Everywhere UNKNOWN appears — receipt, OpenVEX (`under_investigation`), SARIF
(`warning` + typed guidance), judge page — it is framed as a typed evidence
gap with a next action, and **never** as safe. The verifier asserts this.

---

## NOT_REACHABLE within-bounds explanation

NOT_REACHABLE is a **bounded** claim, never a global safety guarantee.
It means: every walk from the declared entry points emptied its frontier
*within the configured search bounds* (`max_hops`, `max_visited`,
`max_seconds`), with no bound hit and zero API errors. The certificate records
`frontier_exhausted == true`, `max_hops_hit == false`, `visited_cap_hit ==
false`, `timeout_hit == false`, `api_errors == 0`.

If a bound *had* been hit, the verdict would be UNKNOWN, not NOT_REACHABLE.
The OpenVEX export only emits `not_affected` for an exhaustive NOT_REACHABLE,
and the SARIF and judge page consistently say "within configured search
bounds" — never "safe". Reachability is only as complete as the entry points
declared and the bounds configured; ReachGate states that bound rather than
hiding it.

---

## Demo plan

### Plan A — offline, no setup (recommended, ~2 min)

1. Open `docs/judge-proof.html` in a browser. Walk the REACHABLE exhibit (a graph path), the NOT_REACHABLE exhibit (exhausted frontier), and the UNKNOWN exhibit (typed gap). Show the "Portable evidence" section.
2. Run `python tools/verify_proof.py` — show it verifies the receipts and cross-checks OpenVEX + SARIF, exit `0`.
3. Open `docs/proof/reachgate.sarif.json` and `docs/proof/reachgate.openvex.json` to show the same verdicts as standard, machine-readable evidence.
4. Run `python tools/build_evidence_manifest.py` and show the sha256 manifest.

### Plan B — live (if network/Orbit available)

1. Open **[MR !2](https://gitlab.com/gitlab-ai-hackathon/transcend/39037247/-/merge_requests/2)**: live Orbit run, one REACHABLE + one exhaustive NOT_REACHABLE receipt with certificates and an uploaded `reachgate-receipts.json` artifact.
2. Open **[MR !3](https://gitlab.com/gitlab-ai-hackathon/transcend/39037247/-/merge_requests/3)**: re-run the pipeline; the rerun logs `unchanged` for both fingerprints, keeps the comment count at 2, and creates no duplicate work items.
3. Fall back to Plan A for any step that needs a token or network.

---

## 20 judge questions, with crisp answers

1. **What problem does ReachGate solve?**
   Scanner noise. It answers whether a finding is actually reachable in *your* code, deterministically, with an auditable receipt.

2. **Is the verdict produced by an AI model?**
   No. `risk_score = sum of fixed rule weights`; the deterministic engine decides. The AI only explains the receipt.

3. **What does REACHABLE mean exactly?**
   A graph path runs from a declared entry point to the vulnerable definition *and* the rule score crosses the threshold.

4. **What does NOT_REACHABLE mean?**
   Every walk emptied its frontier within the configured bounds, with 0 bounds hit and 0 API errors. It is bounded, not a global safety claim.

5. **Why isn't NOT_REACHABLE just "safe"?**
   Reachability is only as complete as the declared entry points and configured bounds. ReachGate states that bound instead of overclaiming.

6. **What does UNKNOWN mean, and why keep it?**
   Insufficient evidence (no location, a hit bound, an API error). Keeping it is the whole honesty model: missing evidence is never dressed up as safe.

7. **How is UNKNOWN different from NOT_REACHABLE?**
   NOT_REACHABLE requires `frontier_exhausted == true`. UNKNOWN has `frontier_exhausted == false` — the search never ran to completion.

8. **What is a receipt?**
   The per-finding record: verdict, basis, the graph path, a reachability certificate (bounds, counters, flags), and a stable fingerprint.

9. **What is the fingerprint for?**
   Idempotency and regression review. The same finding fingerprints the same way, so reruns update in place and never duplicate.

10. **How do I verify any of this without trusting you?**
    `python tools/verify_proof.py` — standard library only, offline. It cross-checks the OpenVEX and SARIF back against the receipts.

11. **What standards does ReachGate align with?**
    OpenVEX (v0.2.0) for CVE/SCA and SARIF 2.1.0 for SAST/code-flow. "Standards-aligned" — we have not run a full external schema-certification suite.

12. **Why OpenVEX *and* SARIF?**
    Different consumers. OpenVEX speaks to supply-chain/SCA tooling; SARIF speaks to code-scanning UIs. Same receipts, two audiences.

13. **Can OpenVEX `not_affected` be trusted?**
    It is only emitted for an *exhaustive* NOT_REACHABLE; any hit bound or API error downgrades to `under_investigation`. The verifier enforces this.

14. **Does the SARIF show the actual code path?**
    Yes — a REACHABLE path becomes a SARIF `codeFlow`/`threadFlow` over the real graph nodes. Locations are only emitted where the receipt has a file.

15. **What's in the evidence manifest, and why not the HTML?**
    sha256 over the machine-readable artifacts (receipts, OpenVEX, SARIF). The HTML is a generated view of those same artifacts, so hashing it would be circular.

16. **Are any metrics or screenshots faked?**
    No. Every number on the judge page is computed from the captured receipts. Nothing is mocked.

17. **Does it need a GitLab token or network to evaluate?**
    No for Plan A — everything verifies offline from captured artifacts. Plan B (live MRs) is optional.

18. **What are the limits / failure modes?**
    Reachability is bounded by declared entry points and search bounds; SAST findings in OpenVEX are non-canonical; UNKNOWN reasons shown are illustrative, not exhaustive.

19. **Could a clever input make it falsely claim safe?**
    A search that doesn't complete cannot become NOT_REACHABLE or OpenVEX `not_affected` — it falls to UNKNOWN / `under_investigation`. That guard is verifier-checked.

20. **Is this production-ready?**
    No. It is a hackathon project: advisory by default, standards-aligned, offline-verifiable within configured bounds. Treat it as evidence to review, not a certified gate.
