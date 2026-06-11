# ReachGate - Projectdocumentatie

> Interne referentie: status, architectuur, wat werkt, wat nog gedaan moet worden.
> Bijgewerkt: 11 juni 2026.

---

## Inhoudsopgave

1. [Wat is ReachGate](#1-wat-is-reachgate)
2. [Hackathon context](#2-hackathon-context)
3. [Directorystructuur](#3-directorystructuur)
4. [Architectuur en dataflow](#4-architectuur-en-dataflow)
5. [Module-voor-module: wat er staat](#5-module-voor-module-wat-er-staat)
6. [Orbit API - live-geverifieerde feiten](#6-orbit-api---live-geverifieerde-feiten)
7. [Demo data en de flip](#7-demo-data-en-de-flip)
8. [Agent in de AI Catalog](#8-agent-in-de-ai-catalog)
9. [Testdekking](#9-testdekking)
10. [Bekende beperkingen en beslissingen](#10-bekende-beperkingen-en-beslissingen)
11. [Wat nog gedaan moet worden](#11-wat-nog-gedaan-moet-worden)
12. [Omgevingsvariabelen en draaien](#12-omgevingsvariabelen-en-draaien)

---

## 1. Wat is ReachGate

Beveiligingsscanners vertellen je dat een kwetsbaarheid *bestaat*. ReachGate beantwoordt of die kwetsbaarheid *uitmaakt*: is er een aantoonbaar pad in de code van een gedeclareerd entry-point naar de kwetsbare definitie?

**De kerngedachte:**
- Je declareert je attack surface in `reachgate.yml` (de files die van buiten bereikbaar zijn, bijv. routes, controllers).
- ReachGate loopt via GitLab Orbit's Knowledge Graph (DEFINES / IMPORTS / CALLS edges) van die entry points naar de kwetsbare code.
- Een deterministisch policy-engine (vaste regelgewichten, geen black-box model-score) geeft een `REACHABLE` of `NOT_REACHABLE` verdict.
- Bij `REACHABLE`: een work item aanmaken + MR-comment met een volledig auditeerbaar receipt (pad + regeluitsplitsing).
- Bij `NOT_REACHABLE`: deprioriteren met bewijs (geen pad van geen enkel entry point).

**Differentiatie ten opzichte van concurrenten:**
Andere hackathon-inzendingen (RiskSentry, CodeSheriff, DevGuard) gebruiken een LLM als rechter. ReachGate beslist deterministisch op basis van een graph-feit; het model schrijft alleen de toelichting. Dit is exact de aanpak die de hackathon-briefing aanwijst als de juiste tegenhanger voor de "AI-powered scanner" menigte.

---

## 2. Hackathon context

| Gegeven | Waarde |
|---|---|
| Hackathon | GitLab Transcend Hackathon (Showcase Track) |
| Deadline | **24 juni 2026, 14:00 ET** |
| Doelprijs | Technological Implementation - 1e plaats ($2.000) |
| Vereisten | MIT-licentie, gepubliceerd in AI Catalog, demo-video <= 3 min |
| Max cashprijzen | 1 per project (dus single-categorie focus) |
| Devpost | https://gitlab-transcend.devpost.com/ |
| Registratie | https://contributors.gitlab.com/transcend-hackathon |

**Provisioned GitLab project:**
- Namespace: `gitlab-ai-hackathon/transcend/39037247`
- Project ID: `83119911`
- Rol: Developer + AI
- GitHub repo: https://github.com/MoAz06/reachgate (MIT, lokaal: dit pad)

---

## 3. Directorystructuur

```
reachgate/
├── src/reachgate/          # De canonieke Python-engine
│   ├── __init__.py
│   ├── agent.py            # Orchestratie entry point
│   ├── orbit_client.py     # Orbit REST API client
│   ├── graph_walker.py     # BFS over de code-graph
│   ├── path_strategy.py    # BoundedBFS algoritme
│   ├── policy_engine.py    # Deterministische regelengine + receipt
│   ├── actions.py          # GitLab work items, MR-comments, receipt-rendering
│   └── config.py           # reachgate.yml loader + glob matcher
│
├── agent/
│   ├── system_prompt.md    # Systeem-prompt voor de gepubliceerde AI Catalog-agent
│   └── skills/reachgate/   # Agent-skills definitie
│
├── tools/
│   ├── demo_e2e.py         # End-to-end demo tegen live Orbit (de "flip")
│   ├── hunt_demo_target.py # Helper om demo-targets te vinden
│   └── smoke_client.py     # Snelle smoke-test van de Orbit-verbinding
│
├── tests/                  # 42 tests (pytest + respx fixtures)
│   ├── fixtures/           # Vastgelegde live Orbit-responses (JSON)
│   ├── test_config.py
│   ├── test_graph_walker.py
│   ├── test_orbit_client.py
│   ├── test_path_strategy.py
│   └── test_policy_engine.py
│
├── examples/demo-app/      # Voorbeeldapp met eigen reachgate.yml
├── reachgate.yml           # Standaard entry-point configuratie
├── pyproject.toml
├── README.md
└── PROJECT.md              # Dit bestand
```

---

## 4. Architectuur en dataflow

```
reachgate.yml
    |
    v
agent.py  (orchestratie)
    |
    +-- orbit_client.py
    |       POST /api/v4/orbit/query   (traversal / neighbors)
    |       GET  /api/v4/orbit/schema
    |       GET  /api/v4/orbit/status
    |
    +-- graph_walker.py
    |       - Parseert VulnerabilityOccurrence.location (JSON)
    |       - Haalt Definitions op voor het kwetsbare bestand
    |       - Matcht entry-point-patronen tegen File-nodes in Orbit
    |       - Dedupliceert op pad (zelfde bestand in meerdere forks)
    |       - Delegeert aan BoundedBFS voor het eigenlijke pad
    |
    +-- path_strategy.py (BoundedBFS)
    |       - BFS over DEFINES / IMPORTS / CALLS edges
    |       - Gedeelde neighbor-cache over findings (Finding B hergebruikt A's cache)
    |       - Begrensd door max_visited, max_seconds, max_hops
    |
    +-- policy_engine.py
    |       - Evalueert 4 vaste regels met gewichten
    |       - risk_score = som van getriggerde gewichten
    |       - Verdict = REACHABLE als score >= 50, anders NOT_REACHABLE
    |       - Retourneert PolicyReceipt (auditeerbaar, serialiseerbaar)
    |
    +-- actions.py
            - REACHABLE -> create GitLab issue + optioneel MR-comment
            - NOT_REACHABLE -> alleen MR-comment (geen escalatie)
            - render_receipt() -> Markdown met verdict, pad, regeluitsplitsing
```

**Datastroom per finding:**
```
VulnerabilityOccurrence (Orbit)
    -> location JSON -> bestandspad
    -> Definitions in dat bestand (target_ids)
    -> Entry-point Files (van reachgate.yml)
    -> BoundedBFS: File -> [DEFINES/IMPORTS/CALLS] -> ... -> Definition
    -> ReachabilityResult {reachable, path, hops, entry_point, ...}
    -> PolicyReceipt {verdict, risk_score, triggered_rules, ...}
    -> GitLab action
```

---

## 5. Module-voor-module: wat er staat

### `orbit_client.py` - Orbit REST API client

**Status: volledig werkend, live-getest op 10 juni 2026.**

De client wrappet de enige query-endpoint van Orbit. Elke query-body wordt gewrapped in `{"query": <inner>, "format": "raw"}`.

**Publieke methoden:**

| Methode | Wat het doet |
|---|---|
| `query(inner)` | Ruwe query, retourneert hele response dict |
| `query_nodes(inner)` | Shortcut: retourneert alleen nodes-lijst |
| `query_result(inner)` | Shortcut: retourneert `(nodes, edges)` tuple |
| `get_vulnerability_occurrences(severity, limit)` | Haalt VulnerabilityOccurrence-nodes op, optioneel gefilterd op severity |
| `get_definitions_for_file(file_path)` | Alle Definition-nodes voor een bestandspad |
| `get_file_by_path(file_path)` | Zoek een File-node op exact pad |
| `get_files_matching(patterns)` | Bestanden die matchen op `contains`-patronen |
| `get_code_neighbors(entity, node_id)` | Buren van een node via DEFINES/IMPORTS/CALLS edges |
| `get_graph_schema(expand)` | Schema-endpoint |
| `get_status()` | Status-endpoint |

**Vaste constanten:**
- `CODE_EDGES = {"DEFINES", "IMPORTS", "CALLS"}` - alleen deze edges zijn relevant voor reachability

---

### `path_strategy.py` - BoundedBFS

**Status: werkend, live-getest.**

`BoundedBFS` implementeert de `PathStrategy` protocol. Er is geen native pathfinding query in Orbit; dit is gebouwd over de `neighbors` query.

**Sleuteleigenschappen:**
- Shared neighbor cache over instantie: Finding B hergebruikt alles wat Finding A al heeft opgehaald.
- Begrensd door: `max_hops` (standaard 10), `max_visited` (optioneel), `max_seconds` (optioneel).
- Zoekt naar een *set* target-IDs (alle definities in het kwetsbare bestand) - stopt bij de eerste hit.
- Retourneert een `list[PathNode]` of `None`.

`PathNode` is een frozen dataclass: `entity`, `node_id`, `label`.

---

### `graph_walker.py` - GraphWalker

**Status: werkend, live-getest.**

`GraphWalker.check_reachability(occurrence)` is de enige publieke methode. Het:
1. Parseert `occurrence["location"]` (JSON string) naar een bestandspad.
2. Haalt alle Definitions op voor dat bestand (target IDs).
3. Haalt entry-point Files op via `get_files_matching(config.entrypoint_patterns)`.
4. Dedupliceert Files op pad (het globale Orbit-graph bevat hetzelfde bestand in tientallen forks).
5. Filtert op `config.is_entrypoint(path)` (glob match).
6. Roept `BoundedBFS.find_path(entry_file, target_ids, max_hops)` aan voor elk entry point.
7. Retourneert de eerste `ReachabilityResult` met een pad, of `ReachabilityResult(reachable=False)`.

`ReachabilityResult` bevat: `reachable`, `path`, `hops`, `entry_point`, `vulnerable_file`, `vulnerable_definition`.

---

### `policy_engine.py` - Deterministische regelengine

**Status: werkend, 100% deterministisch.**

**Regels en gewichten:**

| Regel | Gewicht | Conditie |
|---|---|---|
| `path_exists` | +50 | Er bestaat een graph-pad van een entry point naar de kwetsbare definitie |
| `direct_import` | +20 | Pad is 2 hops of korter (directe of bijna-directe import) |
| `high_severity` | +15 | Severity is `critical` of `high` |
| `medium_severity` | +8 | Severity is `medium` |

**Drempel:** `REACHABLE_THRESHOLD = 50`
- Score >= 50 → `REACHABLE`
- Score < 50 → `NOT_REACHABLE`

**Logica:** De `path_exists`-regel alleen al haalt de drempel. Dat is bewust: een aantoonbaar pad is de primaire voorwaarde. Zonder pad kan geen enkele andere combinatie de drempel halen.

`PolicyReceipt` bevat: `verdict`, `risk_score`, `triggered_rules`, `path`, `hops`, `entry_point`, `vulnerable_file`, `vulnerable_definition`, `occurrence_id`, `occurrence_name`, `severity`. Heeft een `.as_dict()` methode voor JSON-serialisatie.

---

### `actions.py` - GitLab acties + receipt rendering

**Status: code klaar; live acties (work item aanmaken) nog niet getest tegen het hackathon-project.**

`GitLabActions.handle(receipt, mr_iid)` dispatcht op verdict:
- `REACHABLE` → `_escalate()`: maakt een GitLab issue aan met labels `reachgate::reachable` en `severity::<severity>`, optioneel een MR-comment.
- `NOT_REACHABLE` → `_deprioritize()`: alleen optioneel MR-comment, geen issue.

`render_receipt(receipt)` genereert de Markdown-output:
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

### `config.py` - Configuratie

**Status: werkend.**

`load_config(path)` leest `reachgate.yml` en retourneert een `ReachGateConfig` met:
- `version: str`
- `entrypoint_patterns: list[str]` - glob-patronen voor entry-point bestanden
- `policy: PolicyConfig` - `min_hops` (standaard 1), `max_hops` (standaard 10)

`ReachGateConfig.is_entrypoint(file_path)` matcht een pad tegen alle patronen via een eigen glob-engine met `**`-ondersteuning.

**Standaard `reachgate.yml`:**
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

### `agent.py` - Orchestratie entry point

**Status: werkend als Python-script; runtime-beperking van het Duo Agent Platform (zie sectie 10).**

`agent.run(gitlab_url, token, project_id, mr_iid, config_path, severity_filter)` is de volledige pipeline in één functie:
1. Laadt configuratie
2. Haalt occurrences op (standaard: critical + high + medium)
3. Voor elke occurrence: walker → evaluate → handle
4. Retourneert een lijst met resultaten `[{occurrence, verdict, risk_score, action}, ...]`

Kan ook als script: `python -m src.reachgate.agent`

---

## 6. Orbit API - live-geverifieerde feiten

**Endpoint:** `POST https://gitlab.com/api/v4/orbit/query`
**Auth:** `Bearer <PAT met api-scope>`
**Body:** `{"query": <inner>, "format": "raw"}`
**Response:** `{"result": {"nodes": [...], "edges": []}, "row_count": N}`

**Bevestigde query-types (4 totaal):**
- `traversal` (single node): `{"query_type":"traversal","node":{...,"filters":{...}},"limit":N}`
- `traversal` (multi node): `{"query_type":"traversal","nodes":[...],"relationships":[...],"limit":N}`
- `neighbors`: `{"query_type":"neighbors","node":{...},"neighbors":{"node":"<alias>"}}`
- `aggregation` (niet gebruikt in engine)
- `pathfinding` bestaat NIET - vervangen door BoundedBFS over neighbors

**Filterregels:**
- Minimaal 1 filter op minimaal 1 node is VEREIST (geen full table scans)
- `contains`-filter vereist minimaal 3 tekens
- Beschikbare operators: `eq`, `contains`, `starts_with`, `in`, `is_not_null`

**Node-IDs:** komen terug als STRING, ook als het eigenlijk integers zijn.

**Bevestigde edges (live):**
- `File -DEFINES-> Definition`
- `File -IMPORTS-> ImportedSymbol`
- `File -ON_BRANCH-> Branch`

**VulnerabilityOccurrence.location shape (SAST):**
```json
{"file": "path/to/file.js", "start_line": 42}
```

**Schema-endpoint:** `GET /api/v4/orbit/schema?expand=<NodeType>`
**Status-endpoint:** `GET /api/v4/orbit/status`

**Indexering:** Het live graph indexeert `gitlab-community/*` projecten inclusief deelnemerprojecten. Ons provisioned project `gitlab-ai-hackathon/transcend/...` staat NIET in de index. Demo draait daarom op de GitLab docs-site (zie sectie 7).

---

## 7. Demo data en de flip

**Bewezen live op 11 juni 2026** via `tools/demo_e2e.py`.

**Demo-project:** GitLab docs-site (geïndexeerd in Orbit, echte SAST findings, echte broncode).

### Finding A - REACHABLE (verwacht en bevestigd)

```python
REACHABLE_FINDING = {
    "uuid": "demo-ssrf",
    "name": "Server-side request forgery (SSRF)",
    "severity": "high",
    "location": json.dumps({"file": "content/frontend/services/fetch_versions.js"}),
}
```

**Resultaat:**
- Verdict: REACHABLE
- Score: 85
- Pad: `File:content/frontend/404/archives_redirect.js -> Definition:getArchivesVersions`
- Hops: 1
- Tijd: 7,2 seconden / 4 API-calls

### Finding B - NOT_REACHABLE (verwacht en bevestigd)

```python
UNREACHABLE_FINDING = {
    "uuid": "demo-pathtraversal",
    "name": "Improper limitation of a pathname ('Path Traversal')",
    "severity": "medium",
    "location": json.dumps({"file": "scripts/create_issues.js"}),
}
```

**Resultaat:**
- Verdict: NOT_REACHABLE
- Score: 8
- Pad: geen
- Tijd: 41,7 seconden / 24 API-calls
- Reden: `scripts/` staat niet in de entry-point-patronen; BFS bereikt de definities niet

**Totaal end-to-end:** 50,4 seconden / 29 API-calls

**Demo draaien:**
```powershell
$env:GITLAB_TOKEN = "glpat-xxxxx"
python tools/demo_e2e.py
```

**Demo-parameters (in demo_e2e.py):**
- `MAX_ENTRYPOINTS = 2` - cap op entry points om het snel te houden
- `MAX_VISITED = 40` - BFS-knopen cap
- `MAX_SECONDS_PER_WALK = 60` - tijdslimiet per finding
- `MAX_HOPS = 4` - beperkt voor de demo

---

## 8. Agent in de AI Catalog

**Status: gepubliceerd (Stage-1 artifact). Runtime-beperking van toepassing (zie sectie 10).**

De gepubliceerde agent in de GitLab AI Catalog (`AI > Agents > ReachGate`) heeft:
- Een systeem-prompt in `agent/system_prompt.md` die exact de workflow van de Python-engine beschrijft
- Tools: Orbit: Query Graph, Orbit: Get Graph Schema
- Visibility: Public

**De systeem-prompt dwingt het zelfde deterministische protocol af:**
1. Parseer location JSON
2. Zoek Definitions voor het kwetsbare bestand
3. Zoek entry-point Files
4. BFS over DEFINES/IMPORTS/CALLS naar de definitions
5. Pas de vaste regelset toe (pad_exists +50, direct_import +20, high_severity +15, medium_severity +8, drempel 50)
6. Neem actie op basis van verdict

**Belangrijk voor de inzending:** De agent-publicatie voldoet aan het "gepubliceerd in AI Catalog"-vereiste. De echte reachability-berekeningen worden gedaan door de Python-engine (live bewezen). De inzending moet eerlijk zijn over dit onderscheid.

---

## 9. Testdekking

**42 tests, allemaal groen.** Draaien met:
```bash
pytest
```

| Testbestand | Wat het test |
|---|---|
| `test_config.py` | YAML-laden, glob matching (`**`, `*`, `?`), foutgevallen |
| `test_policy_engine.py` | Alle 4 regels, drempellogica, receipt-serialisatie, de "flip" (zelfde finding, ander resultaat) |
| `test_graph_walker.py` | Location-parsing, no-location edge case, path-extractie uit mock-responses |
| `test_orbit_client.py` | Query-bouw, response-parsing, edge-filtering, respx-fixtures over live-captured responses |
| `test_path_strategy.py` | BoundedBFS: direct hit, 1-hop, N-hop, geen pad, max_hops limiet, neighbor-cache |

**Fixtures** in `tests/fixtures/`:
- `orbit_neighbors_*.json` - live-captured neighbors-responses
- `orbit_vulnerability_*.json` - live-captured occurrence-responses
- `finding_*.json` - testfinding data

---

## 10. Bekende beperkingen en beslissingen

### Agent runtime beperking (OPGELOST, niet meer onderzoeken)

Noch de web Duo Chat, noch de VS Code GitLab Workflow extension (v6.83) voert de Orbit-tools van de custom agent daadwerkelijk uit:
- **Web Duo Chat** in het project toont nep `<tool_use>` tekst maar maakt nooit een agent-sessie aan.
- **VS Code extension** koppelt wel aan project 39037247 (via git remote) maar heeft alleen generieke GitLab-tools (read file, grep, MRs) - geen Orbit-tools.

**Beslissing (definitief):** De Python-engine in `src/reachgate/` is de canonieke implementatie die reachability echt berekent op live Orbit-data. De gepubliceerde agent is het Stage-1 AI Catalog artifact (satisfies het "publish to AI Catalog" vereiste). De inzending is eerlijk over dit onderscheid.

### Demo-project indexering

Ons provisioned project staat niet in de Orbit-index. Demo-data: GitLab docs-site project, met echte SAST findings en echte geïndexeerde broncode. Dit is een sterker voorbeeld: echte productie findings op echte code.

### Prestaties

Finding B (NOT_REACHABLE) kost 41 seconden: elke BFS-stap is 1 synchrone HTTPS-call (~1,5s). De shared cache helpt als meerdere findings worden verwerkt. Voor productie: async + connection pooling. Voor de demo is 50 seconden acceptabel en toont juist de echtheid.

### Entry-point afhankelijkheid

ReachGate is zo goed als zijn `reachgate.yml`. Een onvolledige declaratie van entry points leidt tot false negatives (NOT_REACHABLE terwijl de code wel bereikbaar is). Dit is een bewuste designbeslissing: de gebruiker verklaart de attack surface expliciet.

---

## 11. Wat nog gedaan moet worden

### Verplicht voor inzending (voor 24 juni 14:00 ET)

- [ ] **README.md bijwerken** - eerlijk over de scope: Python-engine draait echt, agent is catalog artifact. Huidige README klopt niet (zegt "25 tests" terwijl er 42 zijn; noemt pathfinding query die niet bestaat).
- [ ] **Demo-video opnemen** (<= 3 minuten) - beginnen met de live Python-run (`tools/demo_e2e.py`), daarna de agent tonen in de catalog. Toon de flip: Finding A REACHABLE (work item aangemaakt), Finding B NOT_REACHABLE (bewijs zonder pad).
- [ ] **Devpost-inzending** tekst schrijven en indienen op https://gitlab-transcend.devpost.com/
- [ ] **`reachgate-test` agent verwijderen** uit de AI Catalog voor de inzending (is een throwaway-testobject).
- [ ] **GitHub repo bijwerken** - pushen van de huidige staat naar https://github.com/MoAz06/reachgate

### Optioneel / nice-to-have

- [ ] `actions.py` live testen: werk item aanmaken in het hackathon-project om te bevestigen dat de labels en titels correct zijn.
- [ ] `reachgate.yml` voor de demo-app bijwerken zodat de entry points matchen op de GitLab docs-site structuur.
- [ ] `examples/demo-app/` uitbreiden met een echt voorbeeld van een `reachgate.yml` voor de docs-site.

---

## 12. Omgevingsvariabelen en draaien

### Vereiste variabelen

```powershell
$env:GITLAB_URL   = "https://gitlab.com"
$env:GITLAB_TOKEN = "glpat-xxxxx"           # PAT met api-scope
$env:GITLAB_PROJECT_ID = "83119911"         # Hackathon project ID
```

### Installatie

```bash
pip install -e ".[dev]"
```

### Demo draaien (aanbevolen voor video)

```powershell
$env:GITLAB_TOKEN = "glpat-xxxxx"
python tools/demo_e2e.py
```

### Volledige engine draaien

```bash
python -m src.reachgate.agent
```

### Tests

```bash
pytest
```

### Diagnostiek (extra output over import-resolutie)

```powershell
$env:REACHGATE_DIAGNOSE = "1"
python tools/demo_e2e.py
```
