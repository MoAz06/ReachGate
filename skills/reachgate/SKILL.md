---
name: reachgate
description: "Triage a security finding by walking the GitLab Orbit code graph from declared entry points to the vulnerable definition. Returns a deterministic REACHABLE or NOT_REACHABLE verdict with an auditable receipt."
metadata:
  slash-command: enabled
---

## ReachGate Skill

Determine whether a security finding is actually reachable from an application's declared attack surface. Every verdict is backed by a concrete graph path or its documented absence — no model guessing.

## When to use this skill

Use `/reachgate` when you have a security finding (from a SAST scan or GitLab vulnerability report) and want to know whether the vulnerable code can actually be reached from outside the application.

## Required inputs

- A `VulnerabilityOccurrence` node ID or a finding with a `location` JSON field (containing `"file"` and optionally `"start_line"`)
- The project's declared entry points (from `reachgate.yml` in the project root, or supplied inline)

If `reachgate.yml` is not present, ask the user to declare entry-point globs before proceeding. Never invent entry points.

## Workflow (follow in order)

### Step 1 — Parse the finding location

Read `VulnerabilityOccurrence.location`. It is a JSON string:
```json
{"file": "path/to/file.js", "start_line": 42}
```
Extract the `file` field. If absent, return `NOT_REACHABLE` with reason `"finding has no code location"`.

### Step 2 — Find vulnerable definitions

Query Orbit for `Definition` nodes in the vulnerable file:
```json
{
  "query_type": "traversal",
  "node": {
    "id": "def",
    "entity": "Definition",
    "columns": ["id", "name", "file_path"],
    "filters": {"file_path": {"op": "eq", "value": "<file>"}}
  },
  "limit": 50
}
```
Collect all returned IDs as `target_ids`. If empty, return `NOT_REACHABLE` with reason `"no indexed definitions in vulnerable file"`.

### Step 3 — Resolve entry points to File nodes

For each glob pattern in `reachgate.yml`, query Orbit for matching `File` nodes:
```json
{
  "query_type": "traversal",
  "node": {
    "id": "f",
    "entity": "File",
    "columns": ["id", "path"],
    "filters": {"path": {"op": "contains", "value": "<literal_prefix>"}}
  },
  "limit": 100
}
```
Filter results against the full glob pattern client-side. Deduplicate on `path`.

### Step 4 — Walk the graph (BFS over CALLS/IMPORTS edges)

For each entry-point File, use the `neighbors` query to walk outward over `DEFINES`, `IMPORTS`, and `CALLS` edges toward `target_ids`. Bound the walk to `max_hops` (default 10).

```json
{
  "query_type": "neighbors",
  "node": {"id": "<node_id>", "entity": "<entity>"},
  "neighbors": {"node": "neighbor"}
}
```

Record the first path found: `[entry_point_file, ..., vulnerable_definition]`.

**Fallback — `ImportedSymbol` nodes.** For some languages (notably JavaScript) Orbit may index imports as `ImportedSymbol` nodes rather than IMPORTS/CALLS edges. If the edge walk returns nothing, query `ImportedSymbol` nodes for each entry-point file:

```json
{
  "query_type": "traversal",
  "node": {
    "id": "imp",
    "entity": "ImportedSymbol",
    "columns": ["*"],
    "filters": {"file_path": {"op": "eq", "value": "<entry_point_file>"}}
  },
  "limit": 100
}
```

A row whose `identifier_name` matches a vulnerable definition name and whose `import_path` resolves to the vulnerable file is a valid 2-hop path: `entry_point_file -[NamedImport]-> vulnerable_definition`. Cite the `ImportedSymbol` node ID as evidence.

### Step 5 — Apply the deterministic policy

These weights are fixed. Do not alter them or invent new rules.

| Rule | Weight | Condition |
|---|---|---|
| `path_exists` | +50 | A path from an entry point to the vulnerable definition was found |
| `direct_import` | +20 | Path is 2 hops or fewer |
| `high_severity` | +15 | Severity is `critical` or `high` |
| `medium_severity` | +8 | Severity is `medium` |

**Threshold:** score >= 50 → `REACHABLE`, score < 50 → `NOT_REACHABLE`.

### Step 6 — Take action

- **REACHABLE**: Create a GitLab work item titled `[ReachGate] Reachable: <finding name>`, labelled `reachgate::reachable` and `severity::<severity>`. If on a merge request, post the receipt as an MR comment.
- **NOT_REACHABLE**: Post the receipt only. No escalation.

## Receipt format (always produce this exactly)

```
## ReachGate Triage Receipt

**Verdict:** [🔴 `REACHABLE` | 🟢 `NOT_REACHABLE`]
**Risk score:** <score>
**Finding:** <name> (<severity>)

### Graph path

```mermaid
flowchart LR
    n0["📄 <entry_point>"]
    n1["ƒ <vulnerable_definition>"]
    n0 --> n1
    classDef entry fill:#1f6feb,color:#fff,stroke:none;
    classDef vuln fill:#da3633,color:#fff,stroke:none;
    class n0 entry;
    class n1 vuln;
```

```
<entry_point> -> <node> -> ... -> <vulnerable_definition>
```
(<N> hop(s) from entry point `<entry_point>`)

For NOT_REACHABLE, render the two nodes disconnected with a dotted link labelled `no path found` and style the target with `fill:#2da44e` (green) instead of red. Add one Mermaid node per intermediate hop when the path is longer.

### Rule breakdown
- `path_exists` (+50): <one line>
- `direct_import` (+20): <one line>       [if triggered]
- `high_severity` (+15): <one line>       [if triggered]
- `medium_severity` (+8): <one line>      [if triggered]

<sub>Generated by ReachGate. Score = sum of fixed rule weights, not a model confidence score.</sub>
```

## Rules of conduct

- Quote real node paths from Orbit. Never fabricate a graph path.
- If Orbit returns no path, the verdict is `NOT_REACHABLE`, full stop.
- The engine decides; you only execute the steps and write the explanation.
- State exactly what each Orbit query returned. If a step returns nothing, say so.
- No em dashes in output.
