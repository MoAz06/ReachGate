# Fase 1 live verification (MR pipeline)

Verification MR for the Fase 1 engine upgrade. No code changes — this MR
exists to prove the merge-request pipeline path end to end:

| # | Check | Expected |
|---|-------|----------|
| 1 | `reachgate-triage` job runs on `merge_request_event` | job present and green |
| 2 | MR receives both receipt comments | 2 comments |
| 3 | Finding A (SSRF) | 🔴 `REACHABLE`, basis `path_found` |
| 4 | Finding B (path traversal) | 🟢 `NOT_REACHABLE`, basis `no_path_search_exhaustive` |
| 5 | Certificate block renders | collapsible 🔏 table per receipt |
| 6 | `reachgate-receipts.json` uploaded | CI artifact, schema_version 1.0 |
| 7 | API errors | 0 in both certificates |
| 8 | Pipeline | green |

Results are recorded in the MR discussion.
