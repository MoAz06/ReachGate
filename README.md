# ReachGate

Agentic vulnerability-reachability triage built on [GitLab Orbit](https://docs.gitlab.com/orbit/).

Security scanners tell you that a vulnerability exists. ReachGate answers whether it matters: it walks Orbit's code graph from a declared application entry point to the vulnerable finding, records the path as evidence, and takes deterministic triage action inside GitLab.

## What it does

For each security finding, ReachGate:

1. Queries Orbit for the finding's code location from the schema-provided finding fields or edges
2. Walks the graph (CALLS and IMPORTS edges) from a declared entry point to the vulnerable definition
3. A deterministic policy engine (transparent rule weights, no model score) returns a verdict:
   - **REACHABLE** - creates or escalates a work item, bumps severity, attaches the path as a receipt
   - **NOT_REACHABLE** - deprioritizes, with the evidence (no path from any entry point)
4. Posts an auditable receipt (graph path + triggered rules + score breakdown) as an MR comment or work item

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

## Architecture

```text
reachgate.yml
    |
    v
agent.py          -- orchestration entry point (GitLab Duo Agent Platform)
    |
    +-- orbit_client.py     -- Orbit REST API queries (traversal, pathfinding)
    +-- graph_walker.py     -- walks CALLS/IMPORTS graph, returns ReachabilityResult
    +-- policy_engine.py    -- deterministic weighted rules -> verdict + receipt
    +-- actions.py          -- create work item, post MR comment
```

The policy engine is transparent: `risk_score = sum of triggered rule weights`. The model never decides; it only explains the receipt.

## Setup

```bash
pip install -e ".[dev]"
```

Set environment variables:

```bash
GITLAB_URL=https://gitlab.com
GITLAB_TOKEN=<your-token>
GITLAB_PROJECT_ID=<your-project-id>
```

Run:

```bash
python -m src.reachgate.agent
```

## Tests

```bash
pytest
```

25 tests covering the config loader, policy engine verdicts, rule triggers, glob matching, and the reachable/unreachable flip.

## Honest scope

This version resolves reachability via Orbit's pathfinding query across CALLS and IMPORTS edges. Path accuracy depends on Orbit's indexing depth for the target language. The entry-point config (`reachgate.yml`) is the source of truth for what counts as the attack surface.

## License

MIT
