# ReachGate

Agentic vulnerability-reachability triage built on [GitLab Orbit](https://docs.gitlab.com/orbit/).

Security scanners tell you that a vulnerability exists. ReachGate answers whether it matters: it walks Orbit's code graph from a declared application entry point to the vulnerable definition, records the path as evidence, and takes deterministic triage action inside GitLab.

## Why reachability

Security teams drown in scanner output, and most of it does not matter: Datadog's [State of DevSecOps 2025](https://www.datadoghq.com/state-of-devsecops-2025/) found that only 18% of vulnerabilities with a critical CVSS score remain critical once runtime and reachability context is applied. Four out of five "critical" findings are noise. Triage is the bottleneck, and today it is manual.

GitLab already has the missing ingredient: Orbit indexes the codebase as a knowledge graph of files, definitions, imports, and calls. ReachGate turns that graph into a triage engine — every verdict is a concrete graph path (or its provable absence), not a model's opinion.

## What it does

For each security finding, ReachGate:

1. Queries Orbit for the finding's code location (`VulnerabilityOccurrence.location`)
2. Walks the graph (DEFINES, IMPORTS, and CALLS edges) from a declared entry point to the vulnerable definition using a bounded BFS over the `neighbors` query
3. A deterministic policy engine (transparent rule weights, no model score) returns a verdict:
   - **REACHABLE** — posts an auditable receipt with the graph path; in MR triage this is a comment, while action/agent escalation can create a work item
   - **NOT_REACHABLE** — deprioritizes, with evidence: every walk ran to completion (frontier exhausted) and found no path. An exhaustive negative, not a shrug.
   - **UNKNOWN** — the evidence was insufficient (no code location, nothing indexed, no entry points resolved, search bounds hit, or an API error). ReachGate never dresses up a cut-off search as proof of unreachability.

   UNKNOWN is not a shrug: every UNKNOWN carries a typed evidence reason and a deterministic next action, so dependency/SCA findings without a code anchor stay reviewable instead of being fake-greened.
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

## Standards-aligned VEX export

Most reachability tools ask you to trust a verdict. ReachGate makes the verdict portable: `tools/export_vex.py` turns the receipts into a standards-aligned [OpenVEX](https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md) document so downstream supply-chain tooling can consume the exploitability context machine-readably — not just as an MR comment.

```bash
python tools/export_vex.py   # writes docs/proof/reachgate.openvex.json
```

The mapping is deliberately conservative, because a VEX `not_affected` tells every downstream consumer to ignore a CVE:

- **REACHABLE** → `affected` (with an `action_statement` naming the graph path)
- **NOT_REACHABLE** → `not_affected` with justification `vulnerable_code_not_in_execute_path` — **only** when the search was genuinely exhaustive (frontier exhausted, 0 bounds hit, 0 API errors)
- **UNKNOWN**, or any `NOT_REACHABLE` whose certificate shows a hit bound or API error → `under_investigation`, never `not_affected`

That last rule is the point: ReachGate refuses to emit a clean VEX `not_affected` from a search that did not actually run to completion. VEX is conventionally a CVE/component (SCA) artifact, so CVE-bearing findings map cleanly while SAST/CWE-style findings are carried honestly as statements against the project as the product. `tools/verify_proof.py` cross-checks the exported VEX against the same receipts, so the VEX claim is falsifiable too.

## Portable evidence layer — not just a scanner

ReachGate is designed as an **offline-verifiable evidence layer**: the same receipts are emitted as replayable, standards-aligned evidence that downstream tooling consumes directly. The deterministic engine decides, the AI only explains, and every exported claim is cross-checked back against the receipts. The [Evidence Contract](docs/EVIDENCE_CONTRACT.md) states exactly which claims downstream tools may draw from a receipt, and which they may not.

- **OpenVEX** (`tools/export_vex.py` → `docs/proof/reachgate.openvex.json`) — CVE/SCA exploitability context (see above).
- **SARIF 2.1.0** (`tools/export_sarif.py` → `docs/proof/reachgate.sarif.json`) — SAST/code-flow evidence: a REACHABLE path becomes a SARIF `codeFlow`/`threadFlow` over the real graph, NOT_REACHABLE stays "within configured search bounds", and UNKNOWN is a typed evidence gap, never presented as safe. Source locations are only emitted where the receipt carries a file — never invented.
- **Evidence manifest** (`tools/build_evidence_manifest.py` → `docs/proof/reachgate.evidence-manifest.json`) — sha256 over the machine-readable artifacts (receipts, OpenVEX, SARIF) so a reviewer can confirm offline they are looking at the exact evidence ReachGate produced.
- **Offline verifier** (`tools/verify_proof.py`) — standard library only, no token, no network; cross-checks the OpenVEX and SARIF back against the receipts, so the evidence is falsifiable.

```bash
python tools/export_vex.py
python tools/export_sarif.py
python tools/build_evidence_manifest.py
python tools/verify_proof.py
```

For a guided walkthrough, see the [Judge Pack](docs/JUDGE_PACK.md). All claims are advisory by default and scoped to the configured search bounds; this is standards-aligned, not a certified gate.

## Command line

Once installed (`pip install -e ".[dev]"`; add `".[dev,sign]"` for the optional signature/tamper check), the offline, deterministic surface is one `reachgate` command:

```bash
reachgate --help                  # show the full offline evidence CLI
reachgate selftest                # adversarial invariant test: real passes, fake-green fails
reachgate coverage                 # verdict / UNKNOWN-reason / blind-spot report
reachgate coverage --format html --output coverage.html  # same report as static HTML
reachgate verify                   # verify receipts + cross-check OpenVEX/SARIF
reachgate export-vex               # OpenVEX from receipts
reachgate export-sarif             # SARIF 2.1.0 from receipts
reachgate manifest                 # sha256 evidence manifest
reachgate proof                    # offline judge-proof HTML page
reachgate policy explain           # read-only view of the recorded policy
reachgate fixcheck BEFORE AFTER    # prove the reachability delta between two receipts
reachgate contract-check RECEIPT.json   # enforce the Evidence Contract on receipts
reachgate blame RECEIPTS.json --changed-files FILE  # path overlap only, never causation
reachgate explorer --output explorer.html  # self-contained offline evidence explorer
reachgate judge                    # one command: verify -> exports -> manifest -> proof
reachgate capsule build            # portable evidence capsule (zip) in dist/
```

`reachgate selftest` is the quickest "do not trust us, prove it" check: it accepts real evidence, rejects fake-green evidence, keeps `UNKNOWN` as an evidence gap, and runs the optional signature/tamper leg when installed with the `sign` extra (otherwise that leg is skipped honestly). `reachgate coverage` is the blind-spot report: verdict counts, UNKNOWN reasons with their typed next actions (from `guidance.py`), which findings lack a code anchor, and an honest limitations section — all derived from the captured receipts, offline (`--format json|html` and `--output` are supported). `reachgate judge` runs the whole offline pipeline end to end and prints the path to the judge-proof page (it never opens a browser). `reachgate capsule build` writes `dist/reachgate-evidence-capsule.zip`: a portable, offline-verifiable bundle (receipts, OpenVEX, SARIF, manifest, judge-proof HTML, Judge Pack, and a `HOW_TO_VERIFY.txt`) — deterministic and gitignored. `reachgate policy explain` prints the recorded policy version, threshold, rule weights, and search bounds straight from a receipt, with honest provenance. `reachgate blame` reports changed-file/path overlap only, never causation. `export-vex`/`export-sarif`/`manifest`/`proof` accept `--output` to write anywhere; with no `--output` they write the tracked defaults under `docs/proof/` in a checkout. The core offline CLI can also use bundled read-only proof receipts after a bare install, so `verify`, `coverage`, exports, `contract-check`, and the explorer stay useful outside the repo. `reachgate scan` is intentionally **not** offline: a real scan needs live Orbit and a token, so it is documented as a live workflow via `python -m reachgate.agent` and the CI job (see [GitLab CI setup](docs/GITLAB_CI_SETUP.md)). See [Integrations](docs/INTEGRATIONS.md) for the evidence-router story.

## CI/CD integration

Add ReachGate to your pipeline as an advisory MR triage job — it runs on every merge request and posts a deterministic triage receipt automatically. The bundled job is non-blocking (`allow_failure: true`) so it never blocks a merge on its own. The receipts and `reachgate-receipts.json` artifact are gate-ready evidence: `tools/diff_receipts.py --fail-on-new-reachable` can turn a receipt diff into a blocking check when you choose to enforce it. Any `NOT_REACHABLE` verdict remains scoped to the configured search bounds recorded in the certificate.

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

- [MR !2](https://gitlab.com/gitlab-ai-hackathon/transcend/39037247/-/merge_requests/2) — Phase 1 live engine proof: the pipeline walked the Orbit graph and posted both verdicts as comments, each with a reachability certificate. The SSRF is REACHABLE, the path traversal is exhaustively NOT_REACHABLE, and the run uploaded `reachgate-receipts.json` (captured in `docs/proof/mr2-reachgate-receipts.json`). Same pipeline, same Orbit graph, opposite triage outcomes, on one merge request.
- [MR !3](https://gitlab.com/gitlab-ai-hackathon/transcend/39037247/-/merge_requests/3) — live proof that MR triage is fingerprint-idempotent. The first run created two receipt comments; the rerun logged `unchanged` for both fingerprints, kept the comment count at 2, uploaded `reachgate-receipts.json` again, and created no work items from the MR flow.

(MR !1 was the original early demo run; the canonical, verifiable proof lives in MR !2 and MR !3 above, which the offline verifier and `docs/proof/` are built on.)

## Proof gallery

Verify it yourself in one command (standard library only, no token, offline):

```bash
python tools/verify_proof.py
```

It checks the captured receipt artifacts below against the verdicts the MR
comments claim — matching fingerprints across MR !2 and MR !3, exhaustive
`NOT_REACHABLE`, honest `UNKNOWN`, and zero API errors — and, when present,
cross-checks the exported OpenVEX and SARIF back against those receipts. See
[docs/JUDGE_REPLAY.md](docs/JUDGE_REPLAY.md) for the two-minute replay,
[docs/JUDGE_PACK.md](docs/JUDGE_PACK.md) for the full judge walkthrough, and
[docs/DEMO_COMMANDS.md](docs/DEMO_COMMANDS.md) for copy-pastable demo commands
(including the "try to fake green" PASS/FAIL contrast).

To compare two receipt artifacts as a security regression review, run `python tools/diff_receipts.py OLD NEW` (optionally with `--fail-on-new-reachable`).

### Fix verification

`reachgate fixcheck BEFORE.json AFTER.json` is a derived, offline layer that compares two receipt artifacts and proves whether reachability was **removed**, **introduced**, left **unchanged**, or is **incomparable**. It re-uses existing receipts and never re-decides a verdict or calls Orbit.

It is deliberately conservative: ReachGate can compare two receipt artifacts and verify whether reachability was removed **only when the after receipt is exhaustive**. `reachability_removed` is claimed only when the before verdict is `REACHABLE`, the after verdict is `NOT_REACHABLE` with an exhaustive search (frontier exhausted, no bounds hit, 0 API errors), and the policy version is identical. An after `UNKNOWN`, a non-exhaustive `NOT_REACHABLE`, a different policy version, or an unmatched finding identity is `incomparable` — never "fixed".

```bash
reachgate fixcheck before.json after.json                 # text delta
reachgate fixcheck before.json after.json --format json --output delta.json
reachgate fixcheck before.json after.json --format markdown   # MR-comment ready
```

By default it writes nothing to the tracked proof artifacts; output goes to stdout unless `--output` is given. The `markdown` format renders an MR-comment-ready delta (before/after verdicts, status, fingerprints, and the reason). A clearly-labelled **synthetic demo fixture** under `tests/fixtures/fixcheck/` shows the `REACHABLE -> exhaustive NOT_REACHABLE = reachability_removed` workflow without a live dependency; real usage compares before/after receipts from actual runs.

Open `docs/judge-proof.html` or regenerate it with `python tools/build_judge_proof.py`.

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

Set environment variables (`GITLAB_TOKEN` is a PAT with `api` scope, `GITLAB_PROJECT_ID` is your project ID):

```bash
# bash
export GITLAB_TOKEN="glpat-xxxxx"
export GITLAB_PROJECT_ID="<project>"
```

```powershell
# PowerShell
$env:GITLAB_TOKEN = "glpat-xxxxx"
$env:GITLAB_PROJECT_ID = "<project>"
```

Run (after `pip install -e ".[dev]"`):

```bash
python -m reachgate.agent
```

`python -m reachgate.agent` runs the escalation / action flow: a `REACHABLE` finding can create a GitLab work item, and in MR context it posts a plain (non-idempotent) MR comment. For merge-request pipelines use the comment-only, fingerprint-idempotent flow in `tools/mr_triage.py` (the bundled CI job already does this).

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

The agent executes real `query_graph` calls against Orbit, walks the graph, and applies the same fixed rule weights as the Python engine. If the Duo/VS Code run log or recording is on screen, work item #3 can be shown as the documented agentic-run output; otherwise keep the claim to the `/reachgate` skill plus Orbit MCP workflow.

## Tests

```bash
python -m pytest
```

422 focused tests passing (plus 5 marked `standalone` install-gate tests deselected by default), covering config loading, findings-file loading (GitLab SAST report + native JSON), policy engine verdicts (including UNKNOWN), rule triggers, glob matching, BFS path strategy and termination reporting, the ImportedSymbol fallback, import path resolution, receipt rendering (including the Mermaid path diagram and certificate block), fingerprint stability, fingerprint-idempotent MR comment upsert, the JSON artifact, the reachable/unreachable flip, the OpenVEX export (including the never-fake-green guard), the SARIF 2.1.0 export (codeFlow, typed UNKNOWN, byte-stable output), the evidence manifest, the package-safe `reachgate` CLI (including `--output` handling and bundled proof data), the coverage/blind-spot report (text/json/html), the deterministic evidence capsule, optional Ed25519 capsule signing with tamper detection, regression-blame path overlap (no causation claim), the offline evidence explorer, adversarial `reachgate selftest`, derived fix-verification proof with markdown output, the machine-checkable Evidence Contract validator, the fake-green rejection demo fixtures, CI gate templates, and the judge-proof page generator. Run the standalone install gate separately with `python -m pytest -m standalone`.

## Orbit Notes

Building ReachGate surfaced Orbit behavior that is not in the docs:

- **No native pathfinding.** The `neighbors` query is the traversal primitive. ReachGate implements BFS over `neighbors` with a shared cache, bounded by `max_hops`, `max_visited`, and `max_seconds`.
- **Imports are not always edges.** For JavaScript, Orbit can index import relationships as `ImportedSymbol` *nodes* (`file_path`, `identifier_name`, `import_path`, `import_type`) rather than IMPORTS/CALLS edges. ReachGate's skill and engine both treat a matching `ImportedSymbol` as first-class path evidence.
- **The Orbit MCP server wraps tools.** `https://gitlab.com/api/v4/orbit/mcp` exposes `list_commands` + `invoke_command`; `query_graph` and `get_graph_schema` live inside `invoke_command`. The config in `.gitlab/duo/mcp.json` requires an explicit `"type": "http"` field.

## Scope & limits

- The attack surface comes from `reachgate.yml`. ReachGate never guesses what is externally reachable, so incomplete entry-point globs can produce false negatives; run `tools/reachgate_doctor.py` before trusting verdicts on a new project.
- Path accuracy depends on Orbit's indexing depth and language coverage for the target repository. The `ImportedSymbol` fallback handles import relationships that Orbit exposes as nodes, but language coverage still depends on what Orbit indexes.
- `NOT_REACHABLE` is only claimed within the configured search bounds recorded in the certificate: every walk ran until its frontier was empty, within bounds, with zero API errors. Anything less — a hop limit, a node budget, a timeout, a failed query — is reported as `UNKNOWN` with the exact reason in the receipt.
- The current Orbit client is synchronous; async requests and connection pooling are future work for larger deployments.


## License

MIT. Copyright (c) 2026 Mohamed Azahrioui.
