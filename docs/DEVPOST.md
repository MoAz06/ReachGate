# Devpost submission — ReachGate

> Copy-paste source for the Devpost form. Tagline + description below.

## Tagline (max ~120 chars)

Scanners tell you a vulnerability exists. ReachGate proves whether it's reachable — with a path from GitLab Orbit's graph.

## Description

### The problem

Security teams drown in scanner output, and most of it does not matter. Datadog's State of DevSecOps 2025 found that only 18% of vulnerabilities with a critical CVSS score remain critical once runtime and reachability context is applied. Four out of five "critical" findings are noise — but today, separating signal from noise is manual triage work that nobody has time for.

The missing question is always the same: **can an attacker actually reach this code?**

### The solution

ReachGate answers that question with evidence. GitLab Orbit indexes the codebase as a knowledge graph of files, definitions, imports, and calls. ReachGate walks that graph from the application's declared attack surface (entry points in `reachgate.yml`) to the vulnerable definition:

- **Path found** → `REACHABLE`: the MR workflow posts a receipt comment with the graph path rendered as a Mermaid diagram, plus a transparent rule-weight breakdown; the action/agent escalation path can create a work item.
- **No path, exhaustive search** → `NOT_REACHABLE`: deprioritized — every walk ran until its frontier was empty, within bounds, with zero API errors. An exhaustive negative, not a shrug.
- **Insufficient evidence** → `UNKNOWN`: no code location, nothing indexed, no entry points, a search bound hit, or an API failure. ReachGate never dresses up a cut-off search as proof of unreachability.

The verdict is deterministic: `risk_score = sum of fixed rule weights` (path exists +50, direct import +20, high severity +15, medium +8; threshold 50). The model never decides — it only executes the steps and explains the receipt.

Every receipt carries a collapsible **reachability certificate** — policy version hash, search bounds, nodes visited, API calls, evidence modes, and whether any bound cut the walk short — plus a stable **fingerprint** computed only from the finding identity, verdict, path, policy version, and declared attack surface (never timing or call counts). The MR CI job uses that fingerprint to upsert comments: reruns skip unchanged receipts instead of posting duplicates, while still uploading `reachgate-receipts.json` with every receipt and full certificate as a pipeline artifact.

### How I built it

Three integrated layers, all running on live Orbit data:

1. **Python engine** (`src/reachgate/`) — Orbit REST client, bounded BFS over `neighbors` queries with termination reporting (why each walk stopped), deterministic policy engine with three verdicts, reachability certificates, GitLab actions (work items, MR comments, JSON artifact). 170+ focused tests.
2. **CI/CD integration** — `.gitlab-ci.yml` runs triage on every merge request, can load findings from a GitLab SAST report or native JSON, and posts fingerprint-idempotent receipt comments.
3. **Agentic mode** — a ReachGate agent published in the GitLab AI Catalog, an Agent Skill (`/reachgate` slash command), and the Orbit MCP server wired into VS Code Duo Chat. The documented live agentic run executes real `query_graph` calls, walks the graph live, applies the same fixed rules, and is linked as work item #3; I only claim that provenance when showing the run log or recording.

### What I discovered about Orbit

Building this surfaced Orbit behavior that is not in the docs:

- **No native pathfinding** — `neighbors` is the traversal primitive. ReachGate implements bounded BFS over it with a shared cache (`max_hops`, `max_visited`, `max_seconds`).
- **Imports are not always edges** — for JavaScript, Orbit indexes import relationships as `ImportedSymbol` nodes rather than IMPORTS/CALLS edges. ReachGate's engine and skill both treat a matching `ImportedSymbol` as first-class path evidence.
- **The Orbit MCP server wraps its tools** — `query_graph` lives inside `invoke_command`, and the VS Code MCP config requires an explicit `"type": "http"` field.

I validated everything against the live API on a real indexed project (the GitLab docs-site) with real SAST findings: an SSRF flagged `REACHABLE` (score 85, 1 hop from an entry point) and a path traversal flagged `NOT_REACHABLE` (score 8, frontier exhausted from every declared entry point — verified with a preflight tool before ReachGate claims it). Same pipeline, same Orbit graph, opposite triage outcomes — that flip is the whole point.

I also live-tested the MR workflow on MR !3: the first pipeline created two ReachGate receipt comments, the rerun logged `unchanged` for both fingerprints, the comment count stayed 2, `reachgate-receipts.json` uploaded again, and the issue count stayed unchanged. That proves the MR flow is not a one-shot demo or a comment spammer.

### Proof gallery

| Proof | Why it matters |
|---|---|
| MR !2 live receipts | Shows the core engine working on live Orbit data: one `REACHABLE` finding with a graph path and one exhaustive `NOT_REACHABLE` finding with a certificate. |
| MR !2 artifact | Shows the same verdicts are machine-readable in `reachgate-receipts.json`, not just prose in a comment. |
| MR !3 first run + rerun | Shows the workflow is production-shaped: first run creates receipt comments, rerun logs `unchanged`, comment count stays 2, artifact uploads again, and no work item is created by the MR flow. |
| MR !3 certificates | Shows idempotency did not remove auditability: reviewers still see the red/green graph receipts and collapsible reachability certificates. |
| UNKNOWN receipt | Shows the honest third verdict, captured live: a real indexed file with no code definitions (`gem/puma/CVE-2026-47736.yml`) yields `UNKNOWN` / `insufficient_evidence:no_definitions_indexed`, not a fake-green NOT_REACHABLE. One UNKNOWN reason, not all. |

Screenshots live in `docs/img/mr2-*.png` and `docs/img/mr3-*.png`; artifact snapshots live in `docs/proof/`. Judges can verify the captured artifacts offline in one command — `python tools/verify_proof.py` (standard library only, no token) — which confirms matching fingerprints across MR !2 and MR !3, an exhaustive `NOT_REACHABLE`, an honest `UNKNOWN`, and zero API errors. See `docs/JUDGE_REPLAY.md`.

### Design choices

- **You declare the attack surface.** `reachgate.yml` entry-point globs are the source of truth. ReachGate never guesses what is externally reachable; an incomplete declaration produces false negatives by design. `python tools/reachgate_doctor.py` pre-flights that declaration against live Orbit so a glob matching zero indexed files is caught before it becomes a silent false negative.
- **Receipts, not scores.** Every verdict ships with the graph path (visual Mermaid diagram + plaintext for audit), the triggered rules, their fixed weights, and a reachability certificate documenting how the search ran.
- **NOT_REACHABLE must be earned.** It is only claimed after an exhaustive walk (frontier empty, no bounds hit, no API errors). Anything less is `UNKNOWN` with the exact reason.
- **MR comments are idempotent.** The CI path is comment-only and keyed by stable receipt fingerprints, so rerunning the same pipeline does not duplicate reviewer noise. Work-item creation remains in the agent/action escalation path.
- **Three-step install.** Copy the CI job, set one token, declare entry points. Agentic mode: open the repo in VS Code, approve the preconfigured MCP server, type `/reachgate`.

### What's next

- Async Orbit client with connection pooling (each BFS step is currently a synchronous HTTPS call)
- Auto-suggest entry points from framework conventions (routes, controllers, handlers) as a starting `reachgate.yml`
- Cover dependency vulnerabilities: walk from entry points into imported package symbols
- Native Vulnerability Report integration: annotate findings with reachability verdicts in place

## Links

- Repo (GitLab, MIT): https://gitlab.com/gitlab-ai-hackathon/transcend/39037247
- Mirror (GitHub): https://github.com/MoAz06/ReachGate
- Live MR with both verdicts posted by CI (the flip on one MR): https://gitlab.com/gitlab-ai-hackathon/transcend/39037247/-/merge_requests/1
- Live MR proving idempotent MR triage reruns: https://gitlab.com/gitlab-ai-hackathon/transcend/39037247/-/merge_requests/3
- MR !3 proof screenshots: `docs/img/mr3-overview-pipeline-passed.png`, `docs/img/mr3-pipelines-two-passed-runs.png`, `docs/img/mr3-job-unchanged-ssrf-log.png`, `docs/img/mr3-job-unchanged-pathtraversal-artifact-log.png`
- MR !3 receipt artifact snapshot: `docs/proof/mr3-reachgate-receipts-rerun.json`
- CI-created work item with Mermaid receipt: https://gitlab.com/gitlab-ai-hackathon/transcend/39037247/-/work_items/5
- Documented agentic-run work item (show the run log or recording when claiming provenance): https://gitlab.com/gitlab-ai-hackathon/transcend/39037247/-/work_items/3
- Demo video: <YOUTUBE_URL_HERE>

## Built with

`python` `gitlab-orbit` `gitlab-ci` `gitlab-duo` `mcp` `agent-skills` `httpx` `mermaid` `pytest`
