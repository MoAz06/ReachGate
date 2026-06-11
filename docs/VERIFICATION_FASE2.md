# Fase 2 live verification (idempotent MR triage)

Docs-only MR to exercise the merge-request pipeline and prove the Fase 2
idempotency behaviour. No feature work — verification only.

| # | Check | Expected |
|---|-------|----------|
| 1 | `reachgate-triage` runs on `merge_request_event` | green |
| 2 | First run: receipt comments created | comments with hidden marker |
| 3 | Rerun: each receipt `unchanged` (occ + fp logged) | no duplicate writes |
| 4 | Comment count stable across reruns | unchanged |
| 5 | `reachgate-receipts.json` uploaded each run | artifact present |
| 6 | No new work item / issue created (MR flow is comment-only) | issue count unchanged |

Results recorded in the MR discussion.
