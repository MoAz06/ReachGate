"""Verdict -> action routing for GitLabActions.handle().

This is the agent/action flow (actions.handle), distinct from the MR triage
flow (tools/mr_triage.py -> upsert_mr_receipt), which is comment-only.

Claims pinned here:
  * REACHABLE      -> creates an issue (work item) via /issues, and an MR
                      comment when mr_iid is given; labels carry the verdict
                      and severity.
  * UNKNOWN        -> never creates an issue; MR comment only; needs_review.
  * NOT_REACHABLE  -> never creates an issue; MR comment only; deprioritized.
"""

import httpx
import respx

from src.reachgate.actions import GitLabActions
from src.reachgate.policy_engine import PolicyReceipt, TriggeredRule, Verdict

BASE = "https://gitlab.com"
PID = 42
MR = 7
ISSUES = f"{BASE}/api/v4/projects/{PID}/issues"
NOTES = f"{BASE}/api/v4/projects/{PID}/merge_requests/{MR}/notes"


def _receipt(verdict, severity="high"):
    return PolicyReceipt(
        verdict=verdict,
        risk_score=85 if verdict == Verdict.REACHABLE else 8,
        triggered_rules=[TriggeredRule(name="path_exists", weight=50, reason="x")],
        path=["File:src/a.js", "Definition:f"] if verdict == Verdict.REACHABLE else [],
        hops=1,
        entry_point="src/a.js",
        vulnerable_file="src/b.js",
        vulnerable_definition="f",
        occurrence_id="occ-1",
        occurrence_name="SSRF",
        severity=severity,
        verdict_basis="path_found" if verdict == Verdict.REACHABLE else "x",
    )


def _actions():
    return GitLabActions(BASE, "glpat-test", PID)


def _methods_used():
    """All HTTP methods issued across the recorded respx calls."""
    return {call.request.method for call in respx.calls}


# --- REACHABLE --------------------------------------------------------------

@respx.mock
def test_reachable_creates_issue_and_mr_comment():
    issues = respx.post(ISSUES).mock(return_value=httpx.Response(201, json={"id": 500}))
    notes = respx.post(NOTES).mock(return_value=httpx.Response(201, json={"id": 900}))

    res = _actions().handle(_receipt(Verdict.REACHABLE), mr_iid=MR)

    assert res["action"] == "escalated"
    assert issues.called
    assert notes.called
    assert res["work_item"] == {"id": 500}


@respx.mock
def test_reachable_creates_issue_without_mr_when_no_iid():
    issues = respx.post(ISSUES).mock(return_value=httpx.Response(201, json={"id": 500}))
    notes = respx.post(NOTES).mock(return_value=httpx.Response(201, json={"id": 900}))

    res = _actions().handle(_receipt(Verdict.REACHABLE), mr_iid=None)

    assert res["action"] == "escalated"
    assert issues.called
    assert not notes.called  # no MR comment without an MR iid


@respx.mock
def test_reachable_labels_carry_verdict_and_severity():
    issues = respx.post(ISSUES).mock(return_value=httpx.Response(201, json={"id": 1}))

    _actions().handle(_receipt(Verdict.REACHABLE, severity="critical"), mr_iid=None)

    import json
    body = json.loads(issues.calls.last.request.content)
    labels = body["labels"]
    assert "reachgate::reachable" in labels
    assert "severity::critical" in labels


# --- UNKNOWN ----------------------------------------------------------------

@respx.mock
def test_unknown_comments_only_never_creates_issue():
    issues = respx.post(ISSUES).mock(return_value=httpx.Response(201, json={"id": 1}))
    notes = respx.post(NOTES).mock(return_value=httpx.Response(201, json={"id": 2}))

    res = _actions().handle(_receipt(Verdict.UNKNOWN), mr_iid=MR)

    assert res["action"] == "needs_review"
    assert notes.called
    assert not issues.called


@respx.mock
def test_unknown_without_mr_does_nothing_remote():
    issues = respx.post(ISSUES).mock(return_value=httpx.Response(201, json={"id": 1}))
    notes = respx.post(NOTES).mock(return_value=httpx.Response(201, json={"id": 2}))

    res = _actions().handle(_receipt(Verdict.UNKNOWN), mr_iid=None)

    assert res["action"] == "needs_review"
    assert not issues.called
    assert not notes.called


# --- NOT_REACHABLE ----------------------------------------------------------

@respx.mock
def test_not_reachable_comments_only_never_creates_issue():
    issues = respx.post(ISSUES).mock(return_value=httpx.Response(201, json={"id": 1}))
    notes = respx.post(NOTES).mock(return_value=httpx.Response(201, json={"id": 2}))

    res = _actions().handle(_receipt(Verdict.NOT_REACHABLE), mr_iid=MR)

    assert res["action"] == "deprioritized"
    assert notes.called
    assert not issues.called


@respx.mock
def test_not_reachable_without_mr_does_nothing_remote():
    issues = respx.post(ISSUES).mock(return_value=httpx.Response(201, json={"id": 1}))
    notes = respx.post(NOTES).mock(return_value=httpx.Response(201, json={"id": 2}))

    res = _actions().handle(_receipt(Verdict.NOT_REACHABLE), mr_iid=None)

    assert res["action"] == "deprioritized"
    assert not issues.called
    assert not notes.called


# --- no destructive calls in any verdict path -------------------------------

@respx.mock
def test_handle_never_issues_a_delete_for_any_verdict():
    respx.post(ISSUES).mock(return_value=httpx.Response(201, json={"id": 1}))
    respx.post(NOTES).mock(return_value=httpx.Response(201, json={"id": 2}))
    for verdict in (Verdict.REACHABLE, Verdict.UNKNOWN, Verdict.NOT_REACHABLE):
        _actions().handle(_receipt(verdict), mr_iid=MR)
    assert "DELETE" not in _methods_used()
