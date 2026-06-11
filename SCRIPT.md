# ReachGate Demo Video Script

Doel: een demo-video van maximaal 3 minuten voor GitLab Transcend Showcase Track.

Harde jury-focus:

- Technological Implementation: live Orbit use, deterministic engine, certificates, tests, CI artifact.
- Design and Usability: useful MR comments, no duplicate spam on rerun, reviewers stay in GitLab.
- Potential Impact: scanner triage noise is real; reachability helps teams prioritize what matters.
- Quality of the Idea: Orbit is used as an evidence graph for security reachability, not as a wrapper around an LLM opinion.

## Harde Review Van Het Oude Script

Het oude script was technisch sterk, maar niet maximaal jurygericht.

- Te zwak in de eerste 20 seconden: de hook legde het probleem uit, maar niet scherp genoeg waarom dit een unique Orbit use case is.
- Potential Impact kwam te laat en te impliciet. De jury moet meteen horen dat dit scanner-noise en MR-triage oplost.
- Design and Usability zat verstopt in de idempotency-rerun. Maak dat expliciet: reviewers krijgen bewijs in de MR zonder comment-spam.
- De certificate-uitleg was te lang. Toon het certificaat, noem alleen wat het bewijst.
- De proof gallery was goed, maar mag geen losse rondleiding worden. Gebruik het als afsluitend verificatiebewijs.
- Agentic mode is sterk, maar zonder schone video-proof kan het de demo rommelig maken. Voor deze 3 minuten wint MR/CI-proof.

## Beste Opening Sentence

Most security tools stop at "this vulnerability exists"; ReachGate answers the question reviewers actually need in a merge request: can this vulnerable code be reached from the application's entry points?

## Final 3-Minute Script

| Time | Screen | Voice-over | Criteria hit | Do not say |
|---|---|---|---|---|
| 0:00-0:15 | README title/tagline or Devpost title | Most security tools stop at "this vulnerability exists." ReachGate answers the question reviewers actually need in a merge request: can this vulnerable code be reached from the application's entry points? | Potential Impact, Quality of Idea | Do not say it proves all security risk. |
| 0:15-0:32 | README "What it does", CI section, or `reachgate.yml` entrypoints | For real projects, the CI job can load GitLab SAST or native JSON findings. You declare the attack surface in `reachgate.yml`, then ReachGate walks Orbit's files, definitions, imports and calls from those entry points to the vulnerable definition. | Technological Implementation, Design and Usability | Do not say ReachGate guesses entry points. |
| 0:32-0:45 | README architecture or tests line | The key design choice is that the model never decides the verdict. The engine is deterministic: fixed rules, bounded graph search, 123 tests, and a receipt explaining the result. | Technological Implementation, Quality of Idea | Do not call the score model confidence. |
| 0:45-1:12 | MR !3 reachable receipt with graph path visible | Here is the live MR proof. The SSRF finding is `REACHABLE` because Orbit found a graph path from `content/frontend/404/archives_redirect.js` to `getArchivesVersions`. That path triggers fixed rule weights: path exists, direct import, high severity. | Technological Implementation, Design and Usability | Do not say "the AI found this." |
| 1:12-1:30 | MR !3 reachable certificate opened | Every verdict carries a reachability certificate: policy hash, search bounds, entry points checked, nodes visited, API calls, evidence mode, and whether any bound cut the search short. This makes the comment auditable instead of just persuasive. | Technological Implementation, Design and Usability | Do not read every field slowly. |
| 1:30-1:55 | MR !3 not-reachable receipt and certificate | The second finding is the important contrast. Same pipeline, same Orbit graph, different result: `NOT_REACHABLE`. ReachGate only says that because the frontier was exhausted, no search bound was hit, and there were zero API errors. If evidence is incomplete, it returns `UNKNOWN`, not fake green. | Technological Implementation, Quality of Idea | Do not say globally unreachable. Say within configured bounds. |
| 1:55-2:20 | MR !3 pipelines tab with two passed MR runs | This is not a one-shot demo. MR !3 was run twice. The first pipeline created the receipt comments; the rerun passed again on the same merge request. | Design and Usability, Technological Implementation | Do not imply the blocked branch pipeline matters. Focus on the two passed MR runs. |
| 2:20-2:38 | MR !3 job log showing `unchanged` for both fingerprints | On rerun, ReachGate logs `unchanged` for both stable fingerprints. The comment count stays at two and the MR flow creates no work items. That means reviewers get durable evidence without duplicate noise. | Design and Usability, Potential Impact | Do not claim work-item idempotency. Only MR comments. |
| 2:38-2:48 | MR !3 artifact dropdown or artifact upload log | The CI job still uploads `reachgate-receipts.json` on every run, so automation gets a machine-readable artifact with the verdicts, fingerprints and certificates. | Technological Implementation, Design and Usability | Do not claim native Vulnerability Report integration. |
| 2:48-2:57 | README Proof Gallery | The repo links the live MRs, screenshots, logs and JSON artifacts, so the judges can verify the evidence themselves. | Technological Implementation, Design and Usability | Do not linger; this is verification, not the main demo. |
| 2:57-3:00 | README or Devpost final screen | ReachGate turns Orbit into a deterministic security gate: graph evidence in the merge request, honest unknowns, and no LLM verdicts. | Quality of Idea, Potential Impact | Do not add a new feature claim here. |

## Backup 2-Minute Version

| Time | Screen | Voice-over |
|---|---|---|
| 0:00-0:12 | README title/tagline | Most security tools stop at "this vulnerability exists." ReachGate asks whether the vulnerable code is actually reachable from the application's entry points. |
| 0:12-0:28 | `reachgate.yml` or architecture | It uses GitLab Orbit as a code graph: declared entry points, files, definitions, imports and calls. The model never decides; the deterministic engine does. |
| 0:28-0:55 | MR !3 reachable receipt | This SSRF is `REACHABLE`: Orbit found a concrete graph path from an entry point to the vulnerable definition, and fixed rule weights produce the verdict. |
| 0:55-1:18 | MR !3 not-reachable certificate | This path traversal is `NOT_REACHABLE` only because the search exhausted its frontier within bounds, with zero API errors. Otherwise ReachGate would say `UNKNOWN`. |
| 1:18-1:40 | MR !3 pipelines + `unchanged` job log | Rerunning the MR pipeline logs `unchanged` for both fingerprints, keeps the comments stable, and creates no work item from the MR flow. |
| 1:40-1:52 | Artifact dropdown/log | Every run still uploads `reachgate-receipts.json`, giving automation machine-readable verdicts and certificates. |
| 1:52-2:00 | README Proof Gallery | The proof is in GitLab: live MRs, logs, screenshots and JSON artifacts. ReachGate shows what Orbit can prove, not what a model thinks. |

## Shot Checklist

Must include:

1. README or Devpost title/tagline.
2. `reachgate.yml` or README architecture showing entrypoints and Orbit graph workflow.
3. MR !3 reachable receipt with red `REACHABLE` path visible.
4. MR !3 reachable certificate opened.
5. MR !3 not-reachable receipt with green `NOT_REACHABLE` and certificate opened.
6. MR !3 pipelines tab showing the two passed MR runs.
7. MR !3 job log showing `unchanged` for both fingerprints.
8. MR !3 artifact dropdown or upload log for `reachgate-receipts.json`.
9. README Proof Gallery.

Optional if time remains:

1. MR !2 as older phase-1 proof.
2. JSON artifact opened in a viewer.
3. Devpost draft links section.
4. 123 tests line from README.

Cut first if too long:

1. Long certificate field explanation.
2. Proof gallery walkthrough.
3. Artifact JSON internals.
4. Any architecture detail beyond "Orbit graph + deterministic engine".

## Claims To Make

- ReachGate meaningfully uses GitLab Orbit's graph data for vulnerability reachability.
- The verdict is deterministic; the LLM does not decide.
- `NOT_REACHABLE` means exhaustive within configured bounds.
- Incomplete evidence becomes `UNKNOWN`.
- MR triage comments are fingerprint-idempotent.
- The CI job uploads a machine-readable JSON receipt artifact.
- The live proof is available in MR !2, MR !3, screenshots and artifacts.

## Claims To Avoid

- Do not say ReachGate guarantees no false positives or false negatives.
- Do not say it globally proves code is unreachable.
- Do not say the LLM found or decided the verdict.
- Do not call the risk score a probability or model confidence score.
- Do not say work items are idempotent.
- Do not claim native GitLab Vulnerability Report integration.
- Do not claim full language, dependency or runtime coverage.
- Do not say it replaces SAST. It prioritizes SAST findings with reachability evidence.

## Screen-By-Screen Notes

- Best proof image for red verdict: `docs/img/mr3-reachable-comment-certificate.png`.
- Best proof image for green verdict: `docs/img/mr3-not-reachable-comment-certificate.png`.
- Best proof image for rerun workflow: `docs/img/mr3-pipelines-two-passed-runs.png`.
- Best proof image for idempotency log: `docs/img/mr3-job-unchanged-ssrf-log.png` plus `docs/img/mr3-job-unchanged-pathtraversal-artifact-log.png`.
- Best proof image for artifact: `docs/img/mr3-artifact-dropdown.png`.
- Best machine-readable proof: `docs/proof/mr3-reachgate-receipts-rerun.json`.
- When recording GitLab, zoom into the receipt, certificate, log lines and artifacts. Do not linger on the "docs-only" MR title; it is proof infrastructure, not the product message.

## Beste Closing Sentence

ReachGate shows what GitLab Orbit can prove: deterministic reachability evidence in the merge request, honest unknowns when the graph is incomplete, and no LLM verdicts.
