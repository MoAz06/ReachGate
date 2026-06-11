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

- **Path found** → `REACHABLE`: a work item is created with the graph path rendered as a Mermaid diagram, plus a transparent rule-weight breakdown.
- **No path, exhaustive search** → `NOT_REACHABLE`: deprioritized — every walk ran until its frontier was empty, within bounds, with zero API errors. An exhaustive negative, not a shrug.
- **Insufficient evidence** → `UNKNOWN`: no code location, nothing indexed, no entry points, a search bound hit, or an API failure. ReachGate never dresses up a cut-off search as proof of unreachability.

The verdict is deterministic: `risk_score = sum of fixed rule weights` (path exists +50, direct import +20, high severity +15, medium +8; threshold 50). The model never decides — it only executes the steps and explains the receipt.

Every receipt carries a collapsible **reachability certificate** — policy version hash, search bounds, nodes visited, API calls, evidence modes, and whether any bound cut the walk short — plus a stable **fingerprint** computed only from the finding identity, verdict, path, policy version, and declared attack surface (never timing or call counts), so verdicts are replayable and receipts can be deduplicated by fingerprint. The CI job uploads `reachgate-receipts.json` with every receipt and full certificate as a pipeline artifact.

### How we built it

Three integrated layers, all running on live Orbit data:

1. **Python engine** (`src/reachgate/`) — Orbit REST client, bounded BFS over `neighbors` queries with termination reporting (why each walk stopped), deterministic policy engine with three verdicts, reachability certificates, GitLab actions (work items, MR comments, JSON artifact). 100 tests.
2. **CI/CD integration** — `.gitlab-ci.yml` runs triage on every merge request and posts the receipt automatically.
3. **Agentic mode** — a ReachGate agent published in the GitLab AI Catalog, an Agent Skill (`/reachgate` slash command), and the Orbit MCP server wired into VS Code Duo Chat. The agent executes real `query_graph` calls, walks the graph live, applies the same fixed rules, and creates the work item itself.

### What we discovered about Orbit

Building this surfaced Orbit behavior that is not in the docs:

- **No native pathfinding** — `neighbors` is the traversal primitive. ReachGate implements bounded BFS over it with a shared cache (`max_hops`, `max_visited`, `max_seconds`).
- **Imports are not always edges** — for JavaScript, Orbit indexes import relationships as `ImportedSymbol` nodes rather than IMPORTS/CALLS edges. ReachGate's engine and skill both treat a matching `ImportedSymbol` as first-class path evidence.
- **The Orbit MCP server wraps its tools** — `query_graph` lives inside `invoke_command`, and the VS Code MCP config requires an explicit `"type": "http"` field.

We validated everything against the live API on a real indexed project (the GitLab docs-site) with real SAST findings: an SSRF flagged `REACHABLE` (score 85, 1 hop from an entry point) and a path traversal flagged `NOT_REACHABLE` (score 8, frontier exhausted from every declared entry point — verified with a preflight tool before we let the engine claim it). Same scanner severity class, opposite triage outcomes — that flip is the whole point.

### Design choices

- **You declare the attack surface.** `reachgate.yml` entry-point globs are the source of truth. ReachGate never guesses what is externally reachable; an incomplete declaration produces false negatives by design.
- **Receipts, not scores.** Every verdict ships with the graph path (visual Mermaid diagram + plaintext for audit), the triggered rules, their fixed weights, and a reachability certificate documenting how the search ran.
- **NOT_REACHABLE must be earned.** It is only claimed after an exhaustive walk (frontier empty, no bounds hit, no API errors). Anything less is `UNKNOWN` with the exact reason.
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
- CI-created work item with Mermaid receipt: https://gitlab.com/gitlab-ai-hackathon/transcend/39037247/-/work_items/5
- Agent-created work item (live agentic run): https://gitlab.com/gitlab-ai-hackathon/transcend/39037247/-/work_items/3
- Demo video: <YOUTUBE_URL_HERE>

## Built with

`python` `gitlab-orbit` `gitlab-ci` `gitlab-duo` `mcp` `agent-skills` `httpx` `mermaid` `pytest`
