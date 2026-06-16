# ReachGate - Project documentation

> Internal reference: status, architecture, what works, what still needs to be done.
> Updated: 11 June 2026.

---

## Table of contents

1. [What is ReachGate](#1-what-is-reachgate)
2. [Hackathon context](#2-hackathon-context)
3. [Directory structure](#3-directory-structure)
4. [Architecture and dataflow](#4-architecture-and-dataflow)
5. [Module by module: what is in place](#5-module-by-module-what-is-in-place)
6. [Orbit API - live-verified facts](#6-orbit-api---live-verified-facts)
7. [Demo data and the flip](#7-demo-data-and-the-flip)
8. [Agent in the AI Catalog](#8-agent-in-the-ai-catalog)
9. [Test coverage](#9-test-coverage)
10. [Known limitations and decisions](#10-known-limitations-and-decisions)
11. [Latest submission status](#11-latest-submission-status)
12. [Environment variables and running](#12-environment-variables-and-running)

---

## 1. What is ReachGate

Security scanners tell you that a vulnerability *exists*. ReachGate answers whether that vulnerability *matters*: is there a demonstrable path in the code from a declared entry point to the vulnerable definition?

**The core idea:**
- You declare your attack surface in `reachgate.yml` (the files reachable from the outside, e.g. routes, controllers).
- ReachGate walks GitLab Orbit's Knowledge Graph (DEFINES / IMPORTS / CALLS edges) from those entry points to the vulnerable code.
- A deterministic policy engine (fixed rule weights, no black-box model score) returns a `REACHABLE` or `NOT_REACHABLE` verdict.
- On `REACHABLE`: create a work item + MR comment with a fully auditable receipt (path + rule breakdown).
- On `NOT_REACHABLE`: deprioritize with evidence (no path from any entry point).

**Differentiation versus competitors:**
Other hackathon submissions (RiskSentry, CodeSheriff, DevGuard) use an LLM as the judge. ReachGate decides deterministically based on a graph fact; the model only writes the explanation. This is exactly the approach the hackathon briefing points to as the right counterpart to the "AI-powered scanner" crowd.

---

## 2. Hackathon context

| Item | Value |
|---|---|
| Hackathon | GitLab Transcend Hackathon (Showcase Track) |
| Deadline | **24 June 2026, 14:00 ET** |
| Target prize | Technological Implementation - 1st place ($2,000) |
| Requirements | MIT license, published in AI Catalog, demo video <= 3 min |
| Max cash prizes | 1 per project (so single-category focus) |
| Devpost | https://gitlab-transcend.devpost.com/ |
| Registration | https://contributors.gitlab.com/transcend-hackathon |

**Provisioned GitLab project:**
- Namespace: `gitlab-ai-hackathon/transcend/39037247`
- Project ID: `83119911`
- Role: Developer + AI
- GitHub repo: https://github.com/MoAz06/ReachGate (MIT, local: this path)

---

## 3. Directory structure

> Internal snapshot; the test list below and in §9 is illustrative, not exhaustive. The source of truth for the count/contents is `pytest` (422 tests as of 16 June 2026; +5 marked `standalone` install-gate, deselected by default).

```
reachgate/
├── src/reachgate/          # The canonical Python engine
│   ├── __init__.py
│   ├── agent.py            # Orchestration entry point
│   ├── orbit_client.py     # Orbit REST API client
│   ├── graph_walker.py     # BFS over the code graph
│   ├── path_strategy.py    # BoundedBFS algorithm
│   ├── policy_engine.py    # Deterministic rule engine + receipt
│   ├── actions.py          # GitLab work items, idempotent MR comments, receipt rendering
│   ├── findings.py         # GitLab SAST/native JSON findings loader
│   ├── config.py           # reachgate.yml loader + glob matcher
│   ├── certificate.py      # Reachability certificate + stable fingerprint
│   ├── coverage.py         # Verdict/UNKNOWN-reason/blind-spot report (text/json/html)
│   ├── fixproof.py         # Fix verification over two receipts (reachability_removed/introduced)
│   ├── contract_check.py   # Machine-checkable Evidence Contract validator
│   ├── capsule.py          # Portable, offline-verifiable evidence capsule (zip)
│   ├── signing.py          # Ed25519 tamper-evidence for the capsule (optional [sign])
│   ├── blame.py            # Regression blame: changed files ∩ reachable path (overlap, no causation)
│   ├── explorer.py         # Self-contained offline evidence explorer (HTML)
│   ├── selftest.py         # Adversarial self-proof: invariant regression test (PASS+FAIL legs)
│   ├── guidance.py         # Textual guidance/explanation helpers
│   ├── _resources.py       # Resolves proof data: docs/proof in checkout, bundled after bare install
│   ├── export_vex.py       # OpenVEX export (canonical; tools/ = shim)
│   ├── export_sarif.py     # SARIF 2.1.0 export (canonical; tools/ = shim)
│   ├── build_evidence_manifest.py # sha256 manifest (canonical; tools/ = shim)
│   ├── build_judge_proof.py # judge-proof HTML generator (canonical; tools/ = shim)
│   ├── verify_proof.py     # Offline verifier (canonical; tools/ = shim)
│   ├── cli.py              # Package-safe `reachgate` CLI entry point
│   └── _data/proof/        # Bundled read-only proof receipts (standalone after pip install)
│
├── agent/
│   └── system_prompt.md    # System prompt for the published AI Catalog agent
│
├── skills/reachgate/       # Agent skill definition (/reachgate slash command)
│
├── tools/
│   ├── demo_e2e.py          # End-to-end demo against live Orbit (the "flip")
│   ├── verify_proof.py      # Shim -> reachgate.verify_proof (compat: python tools/...)
│   ├── export_vex.py        # Shim -> reachgate.export_vex
│   ├── export_sarif.py      # Shim -> reachgate.export_sarif
│   ├── build_evidence_manifest.py # Shim -> reachgate.build_evidence_manifest
│   ├── build_judge_proof.py # Shim -> reachgate.build_judge_proof
│   ├── diff_receipts.py     # Receipt diff (regression: --fail-on-new-reachable)
│   ├── reachgate_doctor.py  # Pre-flight: entrypoint globs vs live Orbit
│   ├── hunt_demo_target.py  # Helper to find demo targets
│   └── smoke_client.py      # Quick smoke test of the Orbit connection
│
├── docs/
│   ├── judge-proof.html    # Offline proof page (generated)
│   ├── fonts/              # Self-hosted OFL fonts (Courier Prime, Spectral)
│   └── proof/              # Captured artifacts incl. OpenVEX, SARIF and evidence manifest
│
├── tests/                  # 422 tests (pytest + respx fixtures)
│   ├── fixtures/           # Captured live Orbit responses (JSON)
│   ├── test_artifact.py
│   ├── test_certificate.py
│   ├── test_config.py
│   ├── test_findings.py
│   ├── test_graph_walker.py
│   ├── test_orbit_client.py
│   ├── test_path_strategy.py
│   ├── test_policy_engine.py
│   ├── test_receipt.py
│   ├── test_search_outcome.py
│   ├── test_unknown_verdict.py
│   └── test_actions_idempotency.py
│
├── examples/demo-app/      # Example app with its own reachgate.yml
├── reachgate.yml           # Default entry-point configuration
├── pyproject.toml
├── README.md
└── PROJECT.md              # This file
```

---

## 4. Architecture and dataflow

```
reachgate.yml
    |
    v
agent.py  (orchestration)
    |
    +-- orbit_client.py
    |       POST /api/v4/orbit/query   (traversal / neighbors)
    |       GET  /api/v4/orbit/schema
    |       GET  /api/v4/orbit/status
    |
    +-- graph_walker.py
    |       - Parses VulnerabilityOccurrence.location (JSON)
    |       - Fetches Definitions for the vulnerable file
    |       - Matches entry-point patterns against File nodes in Orbit
    |       - Deduplicates by path (same file across multiple forks)
    |       - Delegates to BoundedBFS for the actual path
    |
    +-- path_strategy.py (BoundedBFS)
    |       - BFS over DEFINES / IMPORTS / CALLS edges
    |       - Shared neighbor cache across findings (Finding B reuses A's cache)
    |       - Bounded by max_visited, max_seconds, max_hops
    |
    +-- policy_engine.py
    |       - Evaluates 4 fixed rules with weights
    |       - risk_score = sum of triggered weights
    |       - Verdict = REACHABLE / NOT_REACHABLE / UNKNOWN based on score and evidence basis
    |       - Returns PolicyReceipt (auditable, serializable)
    |
    +-- findings.py
    |       - Loads GitLab SAST reports or native JSON into occurrence dicts
    |       - Generates a stable uuid fallback for findings without an id
    |       - Does not silently drop findings with a missing location; the engine returns UNKNOWN
    |
    +-- actions.py
            - Agent/action flow: REACHABLE -> GitLab issue + optional MR comment
            - MR-CI flow: fingerprint-idempotent comment upsert, no work items
            - NOT_REACHABLE/UNKNOWN -> MR comment only (no escalation)
            - render_receipt() -> Markdown with verdict, path, rule breakdown
```

**Data flow per finding:**
```
VulnerabilityOccurrence (Orbit)
    -> location JSON -> file path
    -> Definitions in that file (target_ids)
    -> Entry-point Files (from reachgate.yml)
    -> BoundedBFS: File -> [DEFINES/IMPORTS/CALLS] -> ... -> Definition
    -> ReachabilityResult {reachable, path, hops, entry_point, ...}
    -> PolicyReceipt {verdict, risk_score, triggered_rules, ...}
    -> GitLab action
```

---

## 5. Module by module: what is in place

### `orbit_client.py` - Orbit REST API client

**Status: fully working, live-tested on 10 June 2026.**

The client wraps Orbit's single query endpoint. Each query body is wrapped in `{"query": <inner>, "format": "raw"}`.

**Public methods:**

| Method | What it does |
|---|---|
| `query(inner)` | Raw query, returns the whole response dict |
| `query_nodes(inner)` | Shortcut: returns only the nodes list |
| `query_result(inner)` | Shortcut: returns a `(nodes, edges)` tuple |
| `get_vulnerability_occurrences(severity, limit)` | Fetches VulnerabilityOccurrence nodes, optionally filtered by severity |
| `get_definitions_for_file(file_path)` | All Definition nodes for a file path |
| `get_file_by_path(file_path)` | Look up a File node by exact path |
| `get_files_matching(patterns)` | Files matching `contains` patterns |
| `get_code_neighbors(entity, node_id)` | Neighbors of a node via DEFINES/IMPORTS/CALLS edges |
| `get_graph_schema(expand)` | Schema endpoint |
| `get_status()` | Status endpoint |

**Fixed constants:**
- `CODE_EDGES = {"DEFINES", "IMPORTS", "CALLS"}` - only these edges are relevant for reachability

---

### `path_strategy.py` - BoundedBFS

**Status: working, live-tested.**

`BoundedBFS` implements the `PathStrategy` protocol. There is no native pathfinding query in Orbit; this is built on top of the `neighbors` query.

**Key properties:**
- Shared neighbor cache across the instance: Finding B reuses everything Finding A already fetched.
- Bounded by: `max_hops` (default 10), `max_visited` (optional), `max_seconds` (optional).
- Searches for a *set* of target IDs (all definitions in the vulnerable file) - stops at the first hit.
- Returns a `list[PathNode]` or `None`.

`PathNode` is a frozen dataclass: `entity`, `node_id`, `label`.

---

### `graph_walker.py` - GraphWalker

**Status: working, live-tested.**

`GraphWalker.check_reachability(occurrence)` is the only public method. It:
1. Parses `occurrence["location"]` (JSON string) into a file path.
2. Fetches all Definitions for that file (target IDs).
3. Fetches entry-point Files via `get_files_matching(config.entrypoint_patterns)`.
4. Deduplicates Files by path (the global Orbit graph contains the same file across dozens of forks).
5. Filters on `config.is_entrypoint(path)` (glob match).
6. Calls `BoundedBFS.find_path(entry_file, target_ids, max_hops)` for each entry point.
7. Returns the first `ReachabilityResult` with a path, or `ReachabilityResult(reachable=False)`.

`ReachabilityResult` contains: `reachable`, `path`, `hops`, `entry_point`, `vulnerable_file`, `vulnerable_definition`.

---

### `policy_engine.py` - Deterministic rule engine

**Status: working, 100% deterministic.**

**Rules and weights:**

| Rule | Weight | Condition |
|---|---|---|
| `path_exists` | +50 | A graph path exists from an entry point to the vulnerable definition |
| `direct_import` | +20 | Path is 2 hops or shorter (a direct or near-direct import) |
| `high_severity` | +15 | Severity is `critical` or `high` |
| `medium_severity` | +8 | Severity is `medium` |

**Threshold:** `REACHABLE_THRESHOLD = 50`
- Score >= 50 → `REACHABLE`
- Score < 50 + exhaustive search → `NOT_REACHABLE`
- Insufficient evidence → `UNKNOWN` (no location, no definitions, no entry points, bounds hit, API error)

**Logic:** The `path_exists` rule alone reaches the threshold. That is intentional: a demonstrable path is the primary condition. Without a path, no other combination can reach the threshold.

`PolicyReceipt` contains: `verdict`, `risk_score`, `triggered_rules`, `path`, `hops`, `entry_point`, `vulnerable_file`, `vulnerable_definition`, `occurrence_id`, `occurrence_name`, `severity`, `verdict_basis`, `fingerprint` and `certificate`. It has an `.as_dict()` method for JSON serialization.

---

### `findings.py` - Findings input normalization

**Status: working, unit-tested.** Built for Phase 2 so that ReachGate can process more than just hardcoded demo findings.

`load_findings(path)` and `parse_findings(data)` support:
- GitLab SAST report JSON: `{ "vulnerabilities": [...] }`
- Native ReachGate JSON: a top-level list or `{ "findings": [...] }`

The normalization output is the same occurrence shape that `GraphWalker.check_reachability()` expects: `uuid`, `name`, `severity`, `location` as a JSON string and optionally `start_line`. If the input has no usable `uuid`, `id` or `fingerprint`, `derive_occurrence_id(name, file, start_line)` generates a stable hash. As a result, two findings in the same file do not collapse into the same identity.

A missing `location` is not silently dropped: the finding proceeds to the engine and is honestly returned there as `UNKNOWN/no_location`.

---

### `actions.py` - GitLab actions + receipt rendering

**Status: working, live-tested.** Work items #2-#5 were really created (manual script, agent run and early CI demo); MR !1 has both receipts as comments. Phase 2 proved on MR !3 that MR comments are fingerprint-idempotent: run 1 `created`, rerun `unchanged`, comment count 2 -> 2, artifact re-uploaded, issue count 6 -> 6.

`GitLabActions.handle(receipt, mr_iid)` dispatches on verdict:
- `REACHABLE` → `_escalate()`: creates a GitLab issue with labels `reachgate::reachable` and `severity::<severity>`, optionally an MR comment.
- `NOT_REACHABLE` → `_deprioritize()`: only an optional MR comment, no issue.

For MR-CI, `tools/mr_triage.py` deliberately does not use `handle()`, but `upsert_mr_receipt()`: comment-only, keyed on `occurrence_key` + receipt fingerprint. Reruns post no duplicate comments and create no work items.

`render_receipt(receipt)` generates the Markdown output:
```
## ReachGate Triage Receipt

**Verdict:** 🔴 `REACHABLE`
**Risk score:** 85
**Finding:** Server-side request forgery (SSRF) (high)

### Graph path
```
File:content/frontend/404/archives_redirect.js -> Definition:getArchivesVersions
```
(1 hop(s) from entry point `content/frontend/404/archives_redirect.js`)

### Rule breakdown
- `path_exists` (+50): A graph path exists ...
- `direct_import` (+20): Vulnerable code is directly ...
- `high_severity` (+15): Finding severity is critical or high.

<sub>Generated by ReachGate. Score = sum of rule weights, not a model confidence score.</sub>
```

---

### `config.py` - Configuration

**Status: working.**

`load_config(path)` reads `reachgate.yml` and returns a `ReachGateConfig` with:
- `version: str`
- `entrypoint_patterns: list[str]` - glob patterns for entry-point files
- `policy: PolicyConfig` - `min_hops` (default 1), `max_hops` (default 10)

`ReachGateConfig.is_entrypoint(file_path)` matches a path against all patterns via a custom glob engine with `**` support.

**Default `reachgate.yml`:**
```yaml
version: "1"
entrypoints:
  files:
    - "src/routes/**/*"
    - "app/controllers/**/*"
    - "cmd/**/main.*"
    - "server.ts"
    - "app.py"
policy:
  min_hops: 1
  max_hops: 10
```

---

### `agent.py` - Orchestration entry point

**Status: working as a Python script; runtime limitation of the Duo Agent Platform (see section 10).**

`agent.run(gitlab_url, token, project_id, mr_iid, config_path, severity_filter)` is the full pipeline in one function:
1. Loads configuration
2. Fetches occurrences (default: critical + high + medium)
3. For each occurrence: walker → evaluate → handle
4. Returns a list of results `[{occurrence, verdict, risk_score, action}, ...]`

This is the **escalation/action flow** (`handle()`): on `REACHABLE` a work item can be created, and if `mr_iid`/`GITLAB_MR_IID`/`CI_MERGE_REQUEST_IID` is present, a **plain** MR comment is posted (not the fingerprint-idempotent upsert). For merge-request pipelines, `tools/mr_triage.py` is the right flow: comment-only and idempotent via `upsert_mr_receipt`. So do not use `agent.run()` as the MR-CI flow.

Can also run as a script (after `pip install -e ".[dev]"`): `python -m reachgate.agent`

---

## 6. Orbit API - live-verified facts

**Endpoint:** `POST https://gitlab.com/api/v4/orbit/query`
**Auth:** `Bearer <PAT with api scope>`
**Body:** `{"query": <inner>, "format": "raw"}`
**Response:** `{"result": {"nodes": [...], "edges": []}, "row_count": N}`

**Confirmed query types (4 total):**
- `traversal` (single node): `{"query_type":"traversal","node":{...,"filters":{...}},"limit":N}`
- `traversal` (multi node): `{"query_type":"traversal","nodes":[...],"relationships":[...],"limit":N}`
- `neighbors`: `{"query_type":"neighbors","node":{...},"neighbors":{"node":"<alias>"}}`
- `aggregation` (not used in the engine)
- `pathfinding` does NOT exist - replaced by BoundedBFS over neighbors

**Filter rules:**
- At least 1 filter on at least 1 node is REQUIRED (no full table scans)
- A `contains` filter requires at least 3 characters
- Available operators: `eq`, `contains`, `starts_with`, `in`, `is_not_null`

**Node IDs:** come back as STRING, even when they are really integers.

**Confirmed edges (live):**
- `File -DEFINES-> Definition`
- `File -IMPORTS-> ImportedSymbol`
- `File -ON_BRANCH-> Branch`

**VulnerabilityOccurrence.location shape (SAST):**
```json
{"file": "path/to/file.js", "start_line": 42}
```

**Schema endpoint:** `GET /api/v4/orbit/schema?expand=<NodeType>`
**Status endpoint:** `GET /api/v4/orbit/status`

**Indexing:** The live graph indexes `gitlab-community/*` projects including participant projects. Our provisioned project `gitlab-ai-hackathon/transcend/...` is NOT in the index. The demo therefore runs on the GitLab docs site (see section 7).

---

## 7. Demo data and the flip

**Proven live on 11 June 2026** via `tools/demo_e2e.py`.

**Demo project:** GitLab docs site (indexed in Orbit, real SAST findings, real source code).

### Finding A - REACHABLE (expected and confirmed)

```python
REACHABLE_FINDING = {
    "uuid": "demo-ssrf",
    "name": "Server-side request forgery (SSRF)",
    "severity": "high",
    "location": json.dumps({"file": "content/frontend/services/fetch_versions.js"}),
}
```

**Result:**
- Verdict: REACHABLE
- Score: 85
- Path: `File:content/frontend/404/archives_redirect.js -> Definition:getArchivesVersions`
- Hops: 1
- Time: 7.2 seconds / 4 API calls

### Finding B - NOT_REACHABLE (expected and confirmed)

```python
UNREACHABLE_FINDING = {
    "uuid": "demo-pathtraversal",
    "name": "Improper limitation of a pathname ('Path Traversal')",
    "severity": "medium",
    "location": json.dumps({"file": "scripts/create_issues.js"}),
}
```

**Result:**
- Verdict: NOT_REACHABLE
- Score: 8
- Path: none
- Time: 41.7 seconds / 24 API calls
- Reason: `scripts/` is not in the entry-point patterns; BFS does not reach the definitions

**Total end-to-end:** 50.4 seconds / 29 API calls

**Running the demo:**
```powershell
$env:GITLAB_TOKEN = "glpat-xxxxx"
python tools/demo_e2e.py
```

**Demo parameters (in demo_e2e.py):**
- `MAX_ENTRYPOINTS = 2` - cap on entry points to keep it fast
- `MAX_VISITED = 40` - BFS node cap
- `MAX_SECONDS_PER_WALK = 120` - time limit per finding (per walk; ~30s/walk measured, 2x margin)
- `MAX_HOPS = 6` - both demo walks exhaust their frontier around hop 5, so no-path = exhaustive NOT_REACHABLE (not UNKNOWN)

---

## 8. Agent in the AI Catalog

**Status: published (Stage-1 artifact). Runtime limitation applies (see section 10).**

The published agent in the GitLab AI Catalog (`AI > Agents > ReachGate`) has:
- A system prompt in `agent/system_prompt.md` that describes exactly the workflow of the Python engine
- Tools: Orbit: Query Graph, Orbit: Get Graph Schema
- Visibility: Public

**The system prompt enforces the same deterministic protocol:**
1. Parse location JSON
2. Find Definitions for the vulnerable file
3. Find entry-point Files
4. BFS over DEFINES/IMPORTS/CALLS to the definitions
5. Apply the fixed rule set (path_exists +50, direct_import +20, high_severity +15, medium_severity +8, threshold 50)
6. Take action based on the verdict

**Important for the submission:** The agent publication satisfies the "published in AI Catalog" requirement. The real reachability computations are done by the Python engine (proven live). The submission must be honest about this distinction.

---

## 9. Test coverage

**422 tests, all green** (incl. GitLab SAST/native findings input, fingerprint-idempotent MR comment upsert, ImportedSymbol fallback, import resolution, Mermaid receipt rendering, UNKNOWN verdict, certificate and fingerprint stability, verdict→action routing, doctor and MR-triage error handling, OpenVEX export incl. the never-fake-green guard, the SARIF 2.1.0 export (codeFlow, typed UNKNOWN, byte-stable output), the evidence manifest, the package-safe `reachgate` CLI (incl. `--output` handling), the coverage/blind-spot report (text/json/html), the deterministic evidence capsule, the Ed25519 capsule signing with tamper detection, the regression-blame path overlap (no causation claim), the offline evidence explorer, the adversarial self-proof (`reachgate selftest`: an invariant regression test that returns non-zero if a FAIL leg unexpectedly passes), derived fix-verification proof with markdown output, the machine-checkable Evidence Contract validator, the fake-green rejection demo fixtures, the CI gate templates (contract-check + standalone), and the judge-proof generator). Plus 5 marked `standalone` tests that verify a real bare `pip install` in a clean venv outside the checkout (deselected by default; run with `python -m pytest -m standalone`). Run with:
```bash
python -m pytest
```

| Test file | What it tests |
|---|---|
| `test_config.py` | YAML loading, glob matching (`**`, `*`, `?`), error cases |
| `test_policy_engine.py` | All 4 rules, threshold logic, receipt serialization, the "flip" (same finding, different result) |
| `test_graph_walker.py` | Location parsing, no-location edge case, path extraction from mock responses |
| `test_orbit_client.py` | Query building, response parsing, edge filtering, respx fixtures over live-captured responses |
| `test_path_strategy.py` | BoundedBFS: direct hit, 1-hop, N-hop, no path, max_hops limit, neighbor cache |
| `test_search_outcome.py` | Termination reporting per walk: path_found, frontier_exhausted, max_hops_hit, visited_cap_hit, timeout_hit, API errors |
| `test_unknown_verdict.py` | UNKNOWN for every insufficient-evidence reason; NOT_REACHABLE only on an exhausted frontier; certificate assembly; fingerprint stable across runs |
| `test_certificate.py` | Fingerprint determinism, sensitivity (verdict/severity/policy/surface), globs hash order-independent |
| `test_artifact.py` | JSON artifact schema, serializability, certificate render in Markdown, UNKNOWN render (🟡) |
| `test_receipt.py` | Mermaid rendering, node labels, quote escaping, plaintext path |
| `test_findings.py` | GitLab SAST/native JSON input, location normalization, deterministic uuid fallback, no-location retention |
| `test_actions_idempotency.py` | MR note pagination, marker parsing, created/updated/unchanged upsert, duplicate-key warning, no dynamic metrics in marker |

**Fixtures** in `tests/fixtures/`:
- `orbit_neighbors_*.json` - live-captured neighbors responses
- `orbit_vulnerability_*.json` - live-captured occurrence responses
- `finding_*.json` - test finding data

---

## 10. Known limitations and decisions

### Agent runtime limitation (RESOLVED via MCP, 11 June 2026)

The native Orbit tools of the custom agent work nowhere (neither web Duo Chat nor the VS Code extension executes them). **Breakthrough: the Orbit MCP server in VS Code fully resolves this.**

**Working setup (live-verified 11 June 2026):**
- `C:\Users\moham\AppData\Roaming\GitLab\duo\mcp.json` (user-level) and `.gitlab/duo/mcp.json` (repo) contain:
  ```json
  {
    "mcpServers": {
      "gitlab-orbit": {
        "type": "http",
        "url": "https://gitlab.com/api/v4/orbit/mcp"
      }
    }
  }
  ```
  The `"type": "http"` field is **required** - without this field the MCP Dashboard reports "Invalid configuration".
- The MCP Dashboard ("GitLab: Show MCP Dashboard") shows status **connected**, transport http, 2 tools: `list_commands` and `invoke_command` (a wrapper; `query_graph` and `get_graph_schema` live as commands inside `invoke_command`).
- Tools pre-approved via the dashboard (now stored in `.gitlab/duo/mcp.json` as `approvedTools`).

**Live agent-run evidence (11 June 2026):** Duo Chat agentic mode in VS Code loaded the `/reachgate` skill, ran real Orbit queries via `invoke_command` (query_graph), self-corrected DSL errors via `get_query_dsl`, found the link via an `ImportedSymbol` node (see below), and produced the exact receipt (REACHABLE, score 85). Work item #3 is linked to this documented live agentic run; only claim that provenance together with the run log or recording.

**Important graph finding:** for the docs site (JavaScript), Orbit has **no IMPORTS/CALLS edges** between the relevant nodes; the import relationship lives in `ImportedSymbol` nodes (`file_path`, `identifier_name`, `import_path`, `import_type=NamedImport`). SKILL.md now has a fallback step that describes this. The Python engine did earlier find a path via neighbors - both evidence routes are valid.

**Decision:** The Python engine remains the canonical deterministic implementation (CI/CD, batch). The agent + skill + Orbit MCP is the live agentic demo route. Both run on real Orbit data.

### Demo project indexing

Our provisioned project is not in the Orbit index. Demo data: the GitLab docs-site project, with real SAST findings and real indexed source code. This is a stronger example: real production findings on real code.

### Performance

Finding B (NOT_REACHABLE) takes 41 seconds: each BFS step is 1 synchronous HTTPS call (~1.5s). The shared cache helps when multiple findings are processed. For production: async + connection pooling. For the demo, 50 seconds is acceptable and actually demonstrates authenticity.

### Entry-point dependency

ReachGate is only as good as its `reachgate.yml`. An incomplete declaration of entry points leads to false negatives (NOT_REACHABLE while the code is in fact reachable). This is a deliberate design decision: the user declares the attack surface explicitly.

---

## 11. Latest submission status

### Required for submission (before 24 June 14:00 ET)

- [x] **README.md updated** (11 June) - 170+ tests, Phase 1/2 live proof, CI/CD + live demo + skill sections added.
- [x] **Live actions tested** (10 June) - work item #2 via `tools/live_actions_check.py` (formerly `tools/test_actions.py`); work item #3 linked to the live agent run (only claim provenance with the run log/recording).
- [x] **CI/CD pipeline** (11 June) - `.gitlab-ci.yml`, MR !1/!2/!3 live proof green.
- [x] **Phase 2 MR idempotency proven live** (11 June) - MR !3: run 1 `created`, rerun `unchanged`, comment count 2 -> 2, artifact re-uploaded, issue count 6 -> 6.
- [x] **Phase 2 proof assets saved** - screenshots in `docs/img/mr3-*.png`, artifact snapshot in `docs/proof/mr3-reachgate-receipts-rerun.json`.
- [x] **Agentic E2E working** (11 June) - Orbit MCP in VS Code + skill + agent, see section 10.
- [x] **Feature branch synced** - `origin/ambitious/fix-verification` and `gitlab/ambitious/fix-verification` point at the same submission-ready work. Before final submission, either merge this branch into `main` or make the submitted branch explicit.
- [ ] **Record demo video** (<= 3 minutes) - current `SCRIPT.md`: lead with the problem, show the SAST flip (REACHABLE path + exhaustive NOT_REACHABLE within bounds), show `reachgate selftest` / fake-green rejection, mention UNKNOWN honesty, then close with offline verification. MR !3 idempotency remains useful if time remains, but is no longer the main act.
- [ ] **Finish Devpost submission** - text from `docs/DEVPOST.md`, fill in the real video URL, then submit at https://gitlab-transcend.devpost.com/.

### Private pre-submit cleanup

- [ ] **Clean up the AI Catalog outside the repo** - remove the `reachgate-test` and `schema-probe` throwaway agents if they are still visible. This does not touch product code or proof assets.

### Backlog after submission

- Build out a blocking gate mode on top of the current advisory MR triage (`allow_failure: true`).
- Investigate entry-point auto-suggestions from Orbit as a UX upgrade.
- Async/connection pooling for faster large graph walks.

---

## 12. Environment variables and running

### Required variables

```powershell
$env:GITLAB_URL   = "https://gitlab.com"
$env:GITLAB_TOKEN = "glpat-xxxxx"           # PAT with api scope
$env:GITLAB_PROJECT_ID = "83119911"         # Hackathon project ID
```

### Installation

```bash
pip install -e ".[dev]"
```

### Running the demo (recommended for the video)

```powershell
$env:GITLAB_TOKEN = "glpat-xxxxx"
python tools/demo_e2e.py
```

### Running the full engine

```bash
# after: pip install -e ".[dev]"
python -m reachgate.agent
```

### Tests

```bash
python -m pytest
```

### Diagnostics (extra output about import resolution)

```powershell
$env:REACHGATE_DIAGNOSE = "1"
python tools/demo_e2e.py
```
