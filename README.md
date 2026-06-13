# ReachGate

Agentic vulnerability-reachability triage built on [GitLab Orbit](https://docs.gitlab.com/orbit/).

Security scanners tell you that a vulnerability exists. ReachGate answers whether it matters: it walks Orbit's code graph from a declared application entry point to the vulnerable definition, records the path as evidence, and takes deterministic triage action inside GitLab.

## Why reachability

Security teams drown in scanner output, and most of it does not matter: Datadog's [State of DevSecOps 2025](https://www.datadoghq.com/state-of-devsecops-2025/) found that only 18% of vulnerabilities with a critical CVSS score remain critical once runtime and reachability context is applied. Four out of five "critical" findings are noise. Triage is the bottleneck, and today it is manual.

GitLab already has the missing ingredient: Orbit indexes the codebase as a knowledge graph of files, definitions, imports, and calls. ReachGate turns that graph into a triage engine — every verdict is a concrete graph path (or its provable absence), not a model's opinion.

## What it does

For each security finding, ReachGate:

1. Queries Orbit for the finding's code location (`VulnerabilityOccurrence.location`)
2. Walks the graph (CALLS and IMPORTS edges) from a declared entry point to the vulnerable definition using a bounded BFS over the `neighbors` query
3. A deterministic policy engine (transparent rule weights, no model score) returns a verdict:
   - **REACHABLE** — creates a GitLab work item, attaches the path as an auditable receipt
   - **NOT_REACHABLE** — deprioritizes, with evidence: every walk ran to completion (frontier exhausted) and found no path. An exhaustive negative, not a shrug.
   - **UNKNOWN** — the evidence was insufficient (no code location, nothing indexed, no entry points resolved, search bounds hit, or an API error). ReachGate never dresses up a cut-off search as proof of unreachability.
4. Posts a receipt (graph path + rule breakdown + score + reachability certificate) as a work item or MR comment — including a Mermaid diagram of the path that GitLab renders inline:

```mermaid
flowchart LR
    n0["📄 content/frontend/404/archives_redirect.js"]
    n1["ƒ getArchivesVersions"]
    n0 --> n1
    classDef entry fill:#1f6feb,color:#fff,stroke:none;
    classDef vuln fill:#da3633,color:#fff,stroke:none;
    class n0 entry;
    class n1 vuln;
```

## Entry points are configurable

Declare your application's attack surface in `reachgate.yml`:

```yaml
version: "1"

entrypoints:
  files:
    - "src/routes/**/*"
    - "app/controllers/**/*"
    - "cmd/**/main.*"
```

ReachGate never guesses what is reachable from the outside. You declare the boundary; the engine enforces it.

## Validate your attack surface

A declared entry point that matches **zero** indexed files is the most dangerous failure mode: ReachGate would walk from nowhere and report `NOT_REACHABLE` for everything, a silent false negative caused by a bad glob rather than by safe code. `tools/reachgate_doctor.py` is a one-command pre-flight that catches exactly that before you trust any verdict:

```bash
export GITLAB_TOKEN="glpat-xxxxx"
python tools/reachgate_doctor.py --config reachgate.yml
```

For each `entrypoints.files` pattern it queries live Orbit, confirms the returned paths against the exact glob matcher, and reports how many indexed files match (with sample paths, capped by `--limit`). It exits `0` if at least one entry point matched, `1` if the config loaded but nothing matched (so `NOT_REACHABLE` evidence cannot be trusted yet), and `2` on an auth/config error.

It validates that your declared globs match files Orbit has indexed. It does **not** prove the attack surface is complete and it does not infer or suggest entry points: you still own that definition.

## Every verdict carries a certificate

A verdict without a record of how the search ran is just an assertion. Each receipt ships with a collapsible **reachability certificate**: the policy version (a hash of the rule weights and threshold), the search bounds (`max_hops`, `max_visited`, `max_seconds`), how many entry points were checked, how many nodes were visited, how many Orbit API calls it cost, which evidence modes produced the verdict (graph edges or `ImportedSymbol` fallback), and whether any bound cut the walk short.

Each receipt also carries a stable **fingerprint** — a hash over the finding identity, verdict, path, policy version, and declared attack surface (never timing or call counts). The same finding under the same policy always fingerprints identically. MR triage uses that fingerprint with a hidden per-finding marker to upsert comments: reruns skip unchanged receipts instead of posting duplicates, and changed receipts update in place. Work-item creation remains part of the agent/action escalation flow; the MR CI path is comment-only by design.

The CI job additionally uploads `reachgate-receipts.json`: a machine-readable artifact with every receipt, full certificate, and the active policy, so verdicts can be diffed, audited, and replayed outside GitLab.

## CI/CD integration

Add ReachGate to your pipeline — it runs on every MR and posts a triage receipt automatically.

```yaml
# .gitlab-ci.yml
include:
  - project: 'gitlab-ai-hackathon/transcend/39037247'
    file: '.gitlab-ci.yml'
    ref: main
```

Or copy `.gitlab-ci.yml` from this repo. Set `GITLAB_TOKEN` as a masked CI/CD variable with `api` scope.

By default the CI demo uses the two live GitLab docs-site findings below. For a project-owned run, point the job at a GitLab SAST report or native findings JSON with `REACHGATE_FINDINGS_FILE`; in that mode ReachGate loads the attack surface from `reachgate.yml` (or `REACHGATE_CONFIG`) instead of the demo entry-point discovery.

Live examples:

- [MR !1](https://gitlab.com/gitlab-ai-hackathon/transcend/39037247/-/merge_requests/1) — the pipeline walked the Orbit graph and posted both verdicts as comments: the SSRF is REACHABLE (escalated to a work item in the original demo flow), the path traversal is NOT_REACHABLE. Same scanner severity class, opposite triage outcomes, on one merge request.
- [MR !3](https://gitlab.com/gitlab-ai-hackathon/transcend/39037247/-/merge_requests/3) — live proof that MR triage is fingerprint-idempotent. The first run created two receipt comments; the rerun logged `unchanged` for both fingerprints, kept the comment count at 2, uploaded `reachgate-receipts.json` again, and created no work items from the MR flow.

## Proof gallery

Verify it yourself in one command (standard library only, no token, offline):

```bash
python tools/verify_proof.py
```

It checks the captured receipt artifacts below against the verdicts the MR
comments claim — matching fingerprints across MR !2 and MR !3, exhaustive
`NOT_REACHABLE`, zero API errors. See [docs/JUDGE_REPLAY.md](docs/JUDGE_REPLAY.md) for the two-minute replay.

To compare two receipt artifacts as a security regression review, run `python tools/diff_receipts.py OLD NEW` (optionally with `--fail-on-new-reachable`).

| Evidence | What it proves | Local proof |
|---|---|---|
| [MR !2](https://gitlab.com/gitlab-ai-hackathon/transcend/39037247/-/merge_requests/2) receipts | Phase 1 live engine proof: the CI job posted one `REACHABLE` receipt and one exhaustive `NOT_REACHABLE` receipt, each with a reachability certificate. | `docs/img/mr2-reachable-comment.png`, `docs/img/mr2-not-reachable-comment.png`, `docs/img/mr2-reachable-certificate.png`, `docs/img/mr2-not-reachable-certificate.png` |
| [MR !2](https://gitlab.com/gitlab-ai-hackathon/transcend/39037247/-/merge_requests/2) artifact | The pipeline uploaded a machine-readable `reachgate-receipts.json` artifact with both verdicts and certificates. | `docs/img/mr2-artifact-download.png`, `docs/proof/mr2-reachgate-receipts.json` |
| [MR !3](https://gitlab.com/gitlab-ai-hackathon/transcend/39037247/-/merge_requests/3) rerun | Phase 2 live workflow proof: rerunning MR triage logged `unchanged` for both fingerprints, kept the comment count stable, uploaded the artifact again, and did not create work items from the MR flow. | `docs/img/mr3-pipelines-two-passed-runs.png`, `docs/img/mr3-job-unchanged-ssrf-log.png`, `docs/img/mr3-job-unchanged-pathtraversal-artifact-log.png` |
| [MR !3](https://gitlab.com/gitlab-ai-hackathon/transcend/39037247/-/merge_requests/3) receipts | The idempotent MR flow still leaves reviewers with the same auditable red/green receipts and certificates. | `docs/img/mr3-reachable-comment-certificate.png`, `docs/img/mr3-not-reachable-comment-certificate.png` |
| [MR !3](https://gitlab.com/gitlab-ai-hackathon/transcend/39037247/-/merge_requests/3) artifact | Reruns still publish `reachgate-receipts.json`, so automation gets a fresh artifact even when comments are unchanged. | `docs/img/mr3-artifact-dropdown.png`, `docs/proof/mr3-reachgate-receipts-rerun.json` |
| UNKNOWN receipt | The honest third verdict, captured live: a real indexed file (`gem/puma/CVE-2026-47736.yml`) with no code definitions yields `UNKNOWN` / `insufficient_evidence:no_definitions_indexed` — never a fake-green NOT_REACHABLE. Demonstrates one UNKNOWN reason, not all. | `docs/proof/unknown-reachgate-receipt.json`, `docs/examples/unknown-finding.json` |

## Architecture

```text
reachgate.yml
    |
    v
agent.py          -- orchestration entry point
    |
    +-- orbit_client.py     -- Orbit REST API (traversal + neighbors queries)
    +-- graph_walker.py     -- bounded BFS over DEFINES/IMPORTS/CALLS edges
    +-- path_strategy.py    -- BFS with termination reporting (why each walk stopped)
    +-- certificate.py      -- reachability certificate + stable receipt fingerprint
    +-- policy_engine.py    -- deterministic weighted rules -> verdict + receipt
    +-- actions.py          -- GitLab work items, MR comments, receipts, JSON artifact
```

The policy engine is transparent: `risk_score = sum of triggered rule weights`. The model never decides; it only explains the receipt.

## Setup

```bash
pip install -e ".[dev]"
```

Set environment variables:

```bash
GITLAB_TOKEN=<your-token>     # PAT with api scope
GITLAB_PROJECT_ID=<project>   # your GitLab project ID
```

Run (from the repository root):

```bash
python -m src.reachgate.agent
```

## Live demo

Reproduces the reachability flip on a real indexed project (GitLab docs-site):

```bash
export GITLAB_TOKEN="glpat-xxxxx"
python tools/demo_e2e.py
```

Output:
- **Finding A** (SSRF, high): `REACHABLE` — score 85, 1 hop from `content/frontend/404/archives_redirect.js`, basis `path_found`
- **Finding B** (Path Traversal, medium): `NOT_REACHABLE` — score 8, basis `no_path_search_exhaustive`: both walks exhausted their frontier within bounds (verified with `tools/preflight_bounds.py`)

## Agentic mode (Duo Chat + Orbit MCP)

ReachGate also runs fully agentically inside VS Code: the [Agent Skill](https://docs.gitlab.com/user/duo_agent_platform/customize/agent_skills/) at `skills/reachgate/SKILL.md` publishes `/reachgate` as a slash command, and the Orbit MCP server gives Duo Chat live graph access. Three steps:

1. Install the [GitLab Workflow extension](https://marketplace.visualstudio.com/items?itemName=GitLab.gitlab-workflow) and open this repo
2. The Orbit MCP server is preconfigured in `.gitlab/duo/mcp.json` — approve it in **GitLab: Show MCP Dashboard**
3. Ask Duo Chat to `/reachgate` a finding

The agent executes real `query_graph` calls against Orbit, walks the graph, applies the same fixed rule weights as the Python engine, and creates the work item — live. The ReachGate agent published in the GitLab AI Catalog carries the same workflow.

## Tests

```bash
pytest
```

123 tests covering config loading, findings-file loading (GitLab SAST report + native JSON), policy engine verdicts (including UNKNOWN), rule triggers, glob matching, BFS path strategy and termination reporting, the ImportedSymbol fallback, import path resolution, receipt rendering (including the Mermaid path diagram and certificate block), fingerprint stability, fingerprint-idempotent MR comment upsert, the JSON artifact, and the reachable/unreachable flip.

## What we learned about Orbit

Building ReachGate surfaced Orbit behavior that is not in the docs:

- **No native pathfinding.** The `neighbors` query is the traversal primitive. ReachGate implements BFS over `neighbors` with a shared cache, bounded by `max_hops`, `max_visited`, and `max_seconds`.
- **Imports are not always edges.** For JavaScript, Orbit can index import relationships as `ImportedSymbol` *nodes* (`file_path`, `identifier_name`, `import_path`, `import_type`) rather than IMPORTS/CALLS edges. ReachGate's skill and engine both treat a matching `ImportedSymbol` as first-class path evidence.
- **The Orbit MCP server wraps tools.** `https://gitlab.com/api/v4/orbit/mcp` exposes `list_commands` + `invoke_command`; `query_graph` and `get_graph_schema` live inside `invoke_command`. The config in `.gitlab/duo/mcp.json` requires an explicit `"type": "http"` field.

## Honest scope

Path accuracy depends on Orbit's indexing depth for the target language. The entry-point config is the source of truth for what counts as the attack surface — an incomplete `reachgate.yml` produces false negatives by design: ReachGate never guesses the attack surface.

`NOT_REACHABLE` is only claimed when the search is an exhaustive negative: every walk ran until its frontier was empty, within bounds, with zero API errors. Anything less — a hop limit, a node budget, a timeout, a failed query — is reported as `UNKNOWN` with the exact reason in the receipt.

## License

MIT
