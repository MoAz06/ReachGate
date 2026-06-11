# ReachGate

Agentic vulnerability-reachability triage built on [GitLab Orbit](https://docs.gitlab.com/orbit/).

Security scanners tell you that a vulnerability exists. ReachGate answers whether it matters: it walks Orbit's code graph from a declared application entry point to the vulnerable definition, records the path as evidence, and takes deterministic triage action inside GitLab.

## What it does

For each security finding, ReachGate:

1. Queries Orbit for the finding's code location (`VulnerabilityOccurrence.location`)
2. Walks the graph (CALLS and IMPORTS edges) from a declared entry point to the vulnerable definition using a bounded BFS over the `neighbors` query
3. A deterministic policy engine (transparent rule weights, no model score) returns a verdict:
   - **REACHABLE** — creates a GitLab work item, attaches the path as an auditable receipt
   - **NOT_REACHABLE** — deprioritizes, with evidence (no path from any entry point)
4. Posts a receipt (graph path + rule breakdown + score) as a work item or MR comment

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

Run:

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

## Agent skill

The `skills/reachgate/SKILL.md` publishes `/reachgate` as a slash command for AI coding agents that support the [Agent Skills](https://docs.gitlab.com/user/duo_agent_platform/customize/agent_skills/) specification. The agent in the GitLab AI Catalog runs the same deterministic workflow.

## Tests

```bash
pytest
```

42 tests covering config loading, policy engine verdicts, rule triggers, glob matching, BFS path strategy, and the reachable/unreachable flip.

## Honest scope

Orbit's `neighbors` query is the traversal primitive — there is no native pathfinding endpoint. ReachGate implements BFS over `neighbors` with a shared cache, bounded by `max_hops`, `max_visited`, and `max_seconds`. Path accuracy depends on Orbit's indexing depth for the target language. The entry-point config is the source of truth for what counts as the attack surface.

## License

MIT
