# ReachGate Demo Video Script

Goal: a demo video of at most 3 minutes for the GitLab Transcend Showcase Track.

Hard jury focus:

- Technological Implementation: live Orbit use, deterministic engine, certificates, tests, CI artifact.
- Design and Usability: useful MR comments, no duplicate spam on rerun, reviewers stay in GitLab.
- Potential Impact: scanner triage noise is real; reachability helps teams prioritize what matters.
- Quality of the Idea: Orbit is used as an evidence graph for security reachability, not as a wrapper around an LLM opinion.

## Recommended final recording flow

This is the recommended ~2-minute order for the final recording. It leads with
the evidence story (the part that is strongest and most current). The full
3-minute table and the backup version below now follow the same story. MR !3
idempotency is useful supporting evidence if time remains, not the main act.

Use `docs/DEMO_COMMANDS.md` as the copy-paste command sheet while recording.

1. **Problem (~0:00-0:15).** Scanners flood teams with alerts and ask you to *trust* a verdict. The real question in a merge request is: can this vulnerable code actually be reached from the application's entry points?
2. **SAST flip (~0:15-0:55).** Open `explorer.html` with `docs/proof/mr2-reachgate-receipts.json` already loaded — this is the main act, and it is **offline, token-free, and reliable for recording**. The receipt was captured from a real Orbit run. Show the code-reachability split on findings that have a code location: one finding is `REACHABLE` with a concrete graph path (entry point → vulnerable definition), the other is an exhaustive `NOT_REACHABLE` **within the configured search bounds**. Same graph, opposite triage. (Optional, not the recording route: with a `GITLAB_TOKEN` you can regenerate the same flip live against Orbit via `python tools/demo_e2e.py` — useful as extra proof the receipt is a real run, not a fixture.)
3. **Fake-green rejection (~0:55-1:20).** Show that overclaiming evidence is refused:
   - `reachgate selftest` — an adversarial invariant test (not a formal certification): must-pass evidence passes and must-fail/fake-green evidence is rejected for the right reason; `UNKNOWN` stays an evidence gap; the machine-checkable Evidence Contract is enforced; if a safety rule ever regressed it exits non-zero, **or**
   - `reachgate contract-check tests/fixtures/contract_violations/not-reachable-timeout-hit.json` — a synthetic receipt that claims a safe `NOT_REACHABLE` while its search timed out → FAIL, exit 1.
4. **UNKNOWN honesty (~1:20-1:40).** Dependency/SCA findings without a code anchor (e.g. container/kernel CVEs) become a typed `UNKNOWN` / needs-review with a next action — never a fake safe verdict. On real dependency findings without a code anchor, ReachGate returns UNKNOWN instead of fake-safe. `UNKNOWN` is never treated as safe; it is the mechanism that stops ReachGate from lying when there is no code to walk to.
5. **Offline verification (~1:40-1:55).** `reachgate verify` replays the captured receipts and cross-checks the standards exports **with no token and no network** — a judge can verify the proof offline, even though *generating* the live flip needs a token.
6. **Closing line (~1:55-2:00).** "Most scanners output findings. ReachGate outputs graph-backed, replayable, machine-checkable evidence."

Notes for this flow:

- **Live flip vs. offline proof:** generating the flip needs a token / live Orbit; verifying the captured proof does not. Keep that distinction explicit on screen.
- **The MR !3 idempotency demo is still useful** (reviewers get durable evidence without duplicate comment spam) but it is **no longer the main act** — show it only if time remains, after the evidence story above.
- `blame` (if shown) reports only which changed files **overlap** a reachable path — never a causation or "this change introduced the path" claim. `fixcheck` (if shown) *verifies a fix from before/after receipts*; it does not modify code.

## Hard Review Of The Old Script

The old script was technically strong, but not maximally jury-focused.

- Too weak in the first 20 seconds: the hook explained the problem, but not sharply enough why this is a unique Orbit use case.
- Potential Impact came too late and too implicitly. The jury must hear immediately that this solves scanner noise and MR triage.
- Design and Usability was hidden in the idempotency rerun. Make it explicit: reviewers get evidence in the MR without comment spam.
- The certificate explanation was too long. Show the certificate, state only what it proves.
- The proof gallery was good, but must not become a loose walkthrough. Use it as closing verification evidence.
- Agentic mode is strong, but without clean video proof it can make the demo messy. For these 3 minutes, MR/CI proof wins.

## Best Opening Sentence

Most security tools stop at "this vulnerability exists"; ReachGate answers the question reviewers actually need in a merge request: can this vulnerable code be reached from the application's entry points?

## Final 3-Minute Script

| Time | Screen | Voice-over | Criteria hit | Do not say |
|---|---|---|---|---|
| 0:00-0:15 | README title/tagline or Devpost title | Security scanners tell you a vulnerability exists. They usually do not prove whether application code can actually reach it. That is why teams waste time triaging noise. | Potential Impact, Quality of Idea | Do not say it proves all security risk. |
| 0:15-0:35 | README "What it does", `reachgate.yml`, or architecture line | ReachGate uses GitLab Orbit's code graph to walk from declared entry points to vulnerable code. The AI does not decide the verdict; a deterministic engine does. | Technological Implementation, Quality of Idea | Do not say ReachGate guesses entry points or that the model decides. |
| 0:35-1:05 | `explorer.html` with `docs/proof/mr2-reachgate-receipts.json` loaded | This receipt was captured from a real Orbit run and opened offline. One finding is `REACHABLE`: there is a concrete graph path from an entry file to the vulnerable definition. The other is `NOT_REACHABLE`: the search exhausted the configured bounds, with no API errors. | Technological Implementation, Design and Usability | Do not say globally unreachable. Say within configured bounds. |
| 1:05-1:25 | Explorer/Judge Pack/terminal ready | The third verdict is `UNKNOWN`. That is not a failure. It means ReachGate did not have enough evidence, so it refuses to call something safe. No fake green. | Quality of Idea, Potential Impact | Do not treat UNKNOWN as safe or as a bug. |
| 1:25-1:55 | Terminal: `reachgate selftest` | This is the key: ReachGate tests its own evidence rules. Real evidence passes. Fake-green evidence fails. UNKNOWN stays an evidence gap. The machine-checkable Evidence Contract is enforced; if the tool ever starts overclaiming, this exits non-zero. | Technological Implementation, Quality of Idea | Do not call it formal certification. It is an adversarial invariant self-check. |
| 1:55-2:25 | Terminal: `reachgate verify` | Now the captured proof is verified offline. No token, no network, no trust in my screen recording. The verifier checks the receipts, fingerprints, exhaustive negative proof, UNKNOWN honesty, and standards exports. | Technological Implementation, Design and Usability | Do not imply this regenerates live Orbit data. It verifies captured evidence. |
| 2:25-2:45 | README/Judge Pack portable evidence section | The same evidence can be exported to standard formats and checked in CI, but the important part is that every downstream claim stays tied back to the receipt. | Design and Usability, Potential Impact | Do not rush through a buzzword list of every feature. |
| 2:45-3:00 | Final screen: explorer, judge-proof, or README title | Most scanners output findings. ReachGate outputs graph-backed, replayable, machine-checkable evidence: an offline-verifiable evidence layer built on GitLab Orbit. | Quality of Idea, Potential Impact | Keep it short. Do not add new claims in the final line. |

## Backup 2-Minute Version

| Time | Screen | Voice-over |
|---|---|---|
| 0:00-0:12 | README title/tagline | Most security tools stop at "this vulnerability exists." ReachGate asks whether the vulnerable code is actually reachable from the application's entry points. |
| 0:12-0:28 | `reachgate.yml` or architecture | It uses GitLab Orbit as a code graph: declared entry points, files, definitions, imports and calls. The model never decides; the deterministic engine does. |
| 0:28-0:55 | `explorer.html` with MR2 receipt loaded | One finding is `REACHABLE` with a concrete graph path. One is `NOT_REACHABLE` only because the search exhausted within bounds with zero API errors. |
| 0:55-1:10 | Explorer/Judge Pack | `UNKNOWN` is not a shrug; it is a typed evidence gap. ReachGate refuses to fake a safe result when there is no code anchor or the search is incomplete. |
| 1:10-1:35 | Terminal: `reachgate selftest` | Real evidence passes, fake-green evidence fails, UNKNOWN stays an evidence gap, and the Evidence Contract is enforced. |
| 1:35-1:52 | Terminal: `reachgate verify` | The captured proof verifies offline: no token, no network, no trust in the demo. |
| 1:52-2:00 | README/Judge Pack | Most scanners output findings. ReachGate outputs graph-backed, replayable, machine-checkable evidence. |

## Shot Checklist

Must include:

1. README or Devpost title/tagline.
2. `reachgate.yml` or README architecture showing entrypoints and Orbit graph workflow.
3. `explorer.html` with `docs/proof/mr2-reachgate-receipts.json` loaded.
4. The `REACHABLE` row with a concrete path visible.
5. The `NOT_REACHABLE` row and the phrase "within configured bounds" / exhaustive proof.
6. A clear spoken line that `UNKNOWN` is an evidence gap, never safe.
7. Terminal: `reachgate selftest` exiting 0.
8. Terminal: `reachgate verify` exiting 0.
9. A short final screen: README, Judge Pack, or judge-proof page.

Optional if time remains:

1. MR !3 idempotency proof: rerun logs `unchanged`, comments stay stable.
2. `/reachgate` skill / Orbit MCP signal.
3. JSON artifact opened in a viewer.
4. Devpost draft links section.
5. 422 focused tests at the time of recording (pytest remains the source of truth) line from README.

Cut first if too long:

1. Long certificate field explanation.
2. Proof gallery walkthrough.
3. Artifact JSON internals.
4. Any architecture detail beyond "Orbit graph + deterministic engine".
5. Feature tours of blame, capsule, signing, explorer internals, or CI templates.

## Claims To Make

- ReachGate meaningfully uses GitLab Orbit's graph data for vulnerability reachability.
- The verdict is deterministic; the LLM does not decide.
- `NOT_REACHABLE` means exhaustive within configured bounds.
- Incomplete evidence becomes `UNKNOWN`.
- The machine-checkable Evidence Contract rejects fake-green evidence and keeps `UNKNOWN` reviewable.
- The captured proof can be verified offline: no token, no network.
- MR triage comments are fingerprint-idempotent if you show the MR !3 rerun.
- The CI job uploads a machine-readable JSON receipt artifact.
- "Gate" means a decision/review gate (gate-ready reachability evidence in the MR), not a blocking CI gate: the bundled `reachgate-triage` job is advisory (`allow_failure: true`) and never blocks a merge on its own.
- ReachGate also has a published `/reachgate` skill through Orbit MCP in VS Code Duo Chat.
- Only mention work item #3 if the Duo/VS Code run log or recording is on screen; work item #5 is the CI/action-flow item.
- The live proof is available in MR !2, MR !3, work items #3 and #5, screenshots and artifacts.

## Claims To Avoid

- Do not say ReachGate guarantees no false positives or false negatives.
- Do not say it globally proves code is unreachable.
- Do not say the LLM found or decided the verdict.
- Do not say the agent decides the verdict; it executes the same fixed rules and explains the receipt.
- Do not call work item #5 agent-created; #5 is the CI/action-flow item. Only call #3 agent-created when the run log or recording is shown.
- Do not call the risk score a probability or model confidence score.
- Do not say work items are idempotent.
- Do not call it a blocking CI gate or say it blocks the merge; the bundled job is advisory (`allow_failure: true`).
- Do not claim native GitLab Vulnerability Report integration.
- Do not claim full language, dependency or runtime coverage.
- Do not say it replaces SAST. It prioritizes SAST findings with reachability evidence.

## Screen-By-Screen Notes

- Best main demo screen: `explorer.html` with `docs/proof/mr2-reachgate-receipts.json` loaded and zoomed to 125-150%.
- Best terminal proof command: `reachgate selftest`.
- Best offline replay command: `reachgate verify`.
- Best judge overview page: `docs/JUDGE_PACK.md`.
- Best proof image for red verdict: `docs/img/mr3-reachable-comment-certificate.png`.
- Best proof image for green verdict: `docs/img/mr3-not-reachable-comment-certificate.png`.
- Best optional rerun workflow image: `docs/img/mr3-pipelines-two-passed-runs.png`.
- Best optional idempotency log image: `docs/img/mr3-job-unchanged-ssrf-log.png` plus `docs/img/mr3-job-unchanged-pathtraversal-artifact-log.png`.
- Best proof image for artifact: `docs/img/mr3-artifact-dropdown.png`.
- Best machine-readable proof: `docs/proof/mr3-reachgate-receipts-rerun.json`.
- When recording GitLab, zoom into the receipt, certificate, log lines and artifacts. Do not linger on the "docs-only" MR title; it is proof infrastructure, not the product message.

## Best Closing Sentence

Most scanners output findings. ReachGate outputs graph-backed, replayable,
machine-checkable evidence: an offline-verifiable evidence layer built on
GitLab Orbit.
