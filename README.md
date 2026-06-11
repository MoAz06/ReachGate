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
   - **NOT_REACHABLE** — deprioritizes, with evidence (no path from any entry point)
4. Posts a receipt (graph path + rule breakdown + score) as a work item or MR comment — including a Mermaid diagram of the path that GitLab renders inline:

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

Live example: [MR !1](https://gitlab.com/gitlab-ai-hackathon/transcend/39037247/-/merge_requests/1) — the pipeline walked the Orbit graph and posted both verdicts as comments: the SSRF is REACHABLE (escalated to a work item by CI), the path traversal is NOT_REACHABLE. Same scanner severity class, opposite triage outcomes, on one merge request.

## Architecture

```text
reachgate.yml
    |
    v
agent.py          -- orchestration entry point
    |
    +-- orbit_client.py     -- Orbit REST API (traversal + neighbors queries)
    +-- graph_walker.py     -- bounded BFS over DEFINES/IMPORTS/CALLS edges
    +-- policy_engine.py    -- deterministic weighted rules -> verdict + receipt
    +-- actions.py          -- GitLab work items, MR comments, receipt rendering
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
- **Finding A** (SSRF, high): `REACHABLE` — score 85, 1 hop from `content/frontend/404/archives_redirect.js`
- **Finding B** (Path Traversal, medium): `NOT_REACHABLE` — score 8, no path from any entry point

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

55 tests covering config loading, policy engine verdicts, rule triggers, glob matching, BFS path strategy, the ImportedSymbol fallback, import path resolution, receipt rendering (including the Mermaid path diagram), and the reachable/unreachable flip.

## What we learned about Orbit

Building ReachGate surfaced Orbit behavior that is not in the docs:

- **No native pathfinding.** The `neighbors` query is the traversal primitive. ReachGate implements BFS over `neighbors` with a shared cache, bounded by `max_hops`, `max_visited`, and `max_seconds`.
- **Imports are not always edges.** For JavaScript, Orbit can index import relationships as `ImportedSymbol` *nodes* (`file_path`, `identifier_name`, `import_path`, `import_type`) rather than IMPORTS/CALLS edges. ReachGate's skill and engine both treat a matching `ImportedSymbol` as first-class path evidence.
- **The Orbit MCP server wraps tools.** `https://gitlab.com/api/v4/orbit/mcp` exposes `list_commands` + `invoke_command`; `query_graph` and `get_graph_schema` live inside `invoke_command`. The config in `.gitlab/duo/mcp.json` requires an explicit `"type": "http"` field.

## Honest scope

Path accuracy depends on Orbit's indexing depth for the target language. The entry-point config is the source of truth for what counts as the attack surface — an incomplete `reachgate.yml` produces false negatives by design: ReachGate never guesses the attack surface.

## License

MIT
