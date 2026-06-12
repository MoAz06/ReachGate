# Judge Replay Kit

Verify ReachGate in about two minutes. Two ways: a one-command offline check
of the captured artifacts, and the live merge requests you can re-run yourself.

## 1. Offline: verify the captured artifacts (no setup, no token)

```bash
python tools/verify_proof.py
```

Standard library only — no install, no network, no GitLab token. It reads the
two receipt artifacts committed in this repo and checks they say exactly what
the merge-request comments claim:

- `docs/proof/mr2-reachgate-receipts.json` — the Phase 1 run (MR !2)
- `docs/proof/mr3-reachgate-receipts-rerun.json` — the Phase 2 rerun (MR !3)

Expected output:

```text
ReachGate proof verified
- MR2: REACHABLE + NOT_REACHABLE receipts valid
- MR3: same fingerprints on rerun (8c2aeb6e2457adc7, d457ba33eef89e2e)
- NOT_REACHABLE is exhaustive: frontier exhausted, no bounds hit, API errors 0
- verifies captured artifacts offline; rerun the linked MRs for live proof
```

Exit code is `0` on success, non-zero if any check fails.

### What each check proves

| Check | Why it matters |
|---|---|
| `schema_version == 1.0`, exactly 2 findings | The artifact is the real machine-readable receipt, not prose. |
| Verdicts are `REACHABLE` + `NOT_REACHABLE` | Same scanner severity class, opposite triage outcomes — the core idea. |
| `verdict_basis` is `path_found` / `no_path_search_exhaustive` | The verdict carries its reason; `no_path_search_exhaustive` is the honesty claim. |
| `api_errors == 0`, no bound hit, `frontier_exhausted == true` | `NOT_REACHABLE` is an exhaustive negative within bounds, not a cut-off search dressed up as proof. |
| Fingerprints identical across MR !2 and MR !3 | The same finding fingerprints the same way, which is what makes MR triage idempotent (reruns update in place, never duplicate). |

This checks the **captured** artifacts offline. It does not re-query GitLab.
For live proof, re-run the pipelines on the merge requests below.

## 2. Live: the merge requests

- **[MR !2](https://gitlab.com/gitlab-ai-hackathon/transcend/39037247/-/merge_requests/2)** — Phase 1 engine on live Orbit data: one `REACHABLE` receipt and one exhaustive `NOT_REACHABLE` receipt, each with a reachability certificate, plus the uploaded `reachgate-receipts.json` artifact.
- **[MR !3](https://gitlab.com/gitlab-ai-hackathon/transcend/39037247/-/merge_requests/3)** — Phase 2 idempotency: the first run created two receipt comments; the rerun logged `unchanged` for both fingerprints, kept the comment count at 2, uploaded the artifact again, and created no work item from the MR flow.

Screenshots are in `docs/img/mr2-*.png` and `docs/img/mr3-*.png`; the artifact
snapshots are in `docs/proof/`.

## 3. Work items

- **[Work item #5](https://gitlab.com/gitlab-ai-hackathon/transcend/39037247/-/work_items/5)** — created by the CI / action-escalation flow (`actions.py`), labeled `reachgate::reachable` / `severity::high`.
- **[Work item #3](https://gitlab.com/gitlab-ai-hackathon/transcend/39037247/-/work_items/3)** — the documented live agentic run (`/reachgate` skill on the Orbit MCP server in VS Code Duo Chat); see PROJECT.md for the run narrative. Treat this as agentic proof only together with the run log/recording.

## 4. The claims, exactly

- The verdict is **deterministic**: `risk_score = sum of fixed rule weights`. The model never decides.
- `NOT_REACHABLE` means **exhaustive within configured bounds** (frontier empty, no bound hit, zero API errors). Anything less is `UNKNOWN`.
- MR triage comments are **fingerprint-idempotent**; the CI path is comment-only and creates no work items.
- Every run uploads a **machine-readable** `reachgate-receipts.json` with verdicts, bases, fingerprints, and full certificates.
