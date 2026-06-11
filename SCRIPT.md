# ReachGate video script

Doel: een demo-video van maximaal 3 minuten voor GitLab Transcend. De video moet laten zien dat ReachGate technisch echt werkt, GitLab Orbit betekenisvol gebruikt, en geen LLM-wrapper is.

## Korte uitleg in het Nederlands

ReachGate helpt bij securitymeldingen.

Normaal zegt een scanner: "hier zit misschien een kwetsbaarheid." Maar dan weet je nog niet of die code ook echt bereikbaar is voor een aanvaller.

ReachGate kijkt daarom in de code-grafiek van GitLab Orbit:

- waar komt verkeer de app binnen?
- waar zit de kwetsbare code?
- bestaat er een echt pad door files, imports, calls en definitions van een entrypoint naar die kwetsbare code?

Daarna geeft ReachGate een van drie antwoorden:

- `REACHABLE`: ja, er is een pad, dus serieus oppakken.
- `NOT_REACHABLE`: nee, binnen de ingestelde grenzen is geen pad gevonden.
- `UNKNOWN`: we weten het niet zeker, dus ReachGate doet niet alsof het veilig is.

Het belangrijke: een AI beslist dit niet. De engine beslist deterministisch op basis van de GitLab Orbit graph. De AI mag uitvoeren en uitleggen, maar niet het verdict verzinnen.

Kort gezegd:

> ReachGate kijkt of een security finding echt bereikbaar is in je code, en zet bewijs daarvan automatisch in je GitLab merge request.

## One-liner

Most AI security tools tell you what a model thinks. ReachGate shows what GitLab Orbit can prove.

## Video structure

| Time | Screen | Say | Claim |
|---|---|---|---|
| 0:00-0:15 | README top or Devpost title | Security scanners tell you a vulnerability exists. ReachGate answers the missing question: can an attacker actually reach that vulnerable code? | Real SDLC triage problem. |
| 0:15-0:35 | README `What it does`, `reachgate.yml`, or architecture | ReachGate uses GitLab Orbit as a code graph. It starts from declared entry points in `reachgate.yml`, walks files, imports, calls and definitions, and then applies deterministic rules. The model never decides the verdict. | Meaningful Orbit use and deterministic engine. |
| 0:35-1:05 | MR !3 reachable receipt, red path visible | Here is a real MR receipt. This finding is `REACHABLE`: Orbit found a graph path from an entry point to the vulnerable definition. The score is not model confidence. It is fixed rule weights: path exists, direct import, and severity. | Strong technical implementation. |
| 1:05-1:25 | Open reachable certificate | Every verdict carries a reachability certificate: policy version, search bounds, entry points checked, nodes visited, API calls, evidence mode, and whether any bound cut the search short. So the receipt is auditable, not just a comment. | Auditability and proof. |
| 1:25-1:50 | MR !3 not-reachable receipt and certificate | The second finding is the important contrast: same pipeline, different outcome. This one is `NOT_REACHABLE` only because the frontier was exhausted, within bounds, with zero API errors. If the search is incomplete, ReachGate returns `UNKNOWN`, not a fake green result. | Honest bounded claims. |
| 1:50-2:20 | MR !3 pipelines page, then job log with `unchanged` | A demo that only works once is not a workflow. In MR !3, the first pipeline created the receipt comments. Then I reran the same MR pipeline. ReachGate logged `unchanged` for both fingerprints, kept the comment count stable, and did not create work items from the MR flow. | Production-shaped MR workflow. |
| 2:20-2:35 | Artifact dropdown or `reachgate-receipts.json` | Even when comments are unchanged, the CI job still uploads `reachgate-receipts.json`, so automation gets a machine-readable artifact with the verdicts, fingerprints and certificates. | Machine-readable proof. |
| 2:35-2:50 | README Proof Gallery | The repo includes a proof gallery: live MRs, screenshots, job logs and artifact snapshots. This is not just a narrated prototype; the evidence is in GitLab. | Judge can verify quickly. |
| 2:50-3:00 | README or Devpost final screen | ReachGate turns Orbit from a graph you can query into a security gate you can trust: deterministic reachability, auditable receipts, and MR triage that reruns without reviewer spam. | Memorable closing. |

## Shot list

1. README or Devpost title.
2. README architecture or `reachgate.yml`.
3. MR !3 reachable receipt with graph path.
4. MR !3 reachable certificate opened.
5. MR !3 not-reachable receipt with graph path.
6. MR !3 not-reachable certificate opened.
7. MR !3 pipelines tab with two passed runs.
8. MR !3 job log showing `unchanged`.
9. MR !3 artifact dropdown or artifact upload lines.
10. README proof gallery.

## Exact opening

Security scanners tell you that a vulnerability exists. But the question that actually matters in triage is: can an attacker reach that vulnerable code?

ReachGate answers that with GitLab Orbit. It treats Orbit as a code graph, starts from declared entry points, walks files, imports, calls and definitions, and then posts an auditable reachability receipt directly on the merge request.

The model never decides the verdict. The engine does.

## Exact closing

ReachGate is not trying to be another AI scanner. It is a deterministic reachability gate built on GitLab Orbit.

It proves reachable findings with graph paths, earns not-reachable findings with exhaustive bounded search, exposes unknowns honestly, and reruns in merge requests without spamming reviewers.

Most AI security tools tell you what a model thinks. ReachGate shows what GitLab Orbit can prove.

## Claims to avoid

- Do not say ReachGate guarantees no false positives or false negatives.
- Do not say it globally proves a vulnerability is unreachable.
- Say: exhaustive within configured bounds.
- Do not say the LLM decides verdicts.
- Do not say work items are idempotent.
- Say: MR comments are idempotent; work-item creation lives in the agent/action flow.
- Do not claim native GitLab Vulnerability Report integration yet.
- Do not claim full language or dependency vulnerability coverage.

## Best proof files

- `docs/img/mr3-reachable-comment-certificate.png`
- `docs/img/mr3-not-reachable-comment-certificate.png`
- `docs/img/mr3-pipelines-two-passed-runs.png`
- `docs/img/mr3-job-unchanged-ssrf-log.png`
- `docs/img/mr3-job-unchanged-pathtraversal-artifact-log.png`
- `docs/img/mr3-artifact-dropdown.png`
- `docs/proof/mr3-reachgate-receipts-rerun.json`

