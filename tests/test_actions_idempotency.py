"""Fingerprint-idempotent MR receipt upsert.

A rerun on the same MR must not duplicate comments: same finding + same
fingerprint -> no write; changed fingerprint -> in-place update; multiple
stray matches -> update newest and warn, never delete.
"""

import httpx
import pytest
import respx

from src.reachgate.actions import (
    GitLabActions,
    build_marker,
    occurrence_key,
    parse_marker,
    render_mr_receipt,
)
from src.reachgate.policy_engine import PolicyReceipt, TriggeredRule, Verdict

BASE = "https://gitlab.com"
PID = 42
MR = 7
NOTES = f"{BASE}/api/v4/projects/{PID}/merge_requests/{MR}/notes"


def _receipt(occurrence_id="occ-1", fingerprint="fp-aaaa", vuln_file="src/b.js"):
    return PolicyReceipt(
        verdict=Verdict.REACHABLE,
        risk_score=85,
        triggered_rules=[TriggeredRule(name="path_exists", weight=50, reason="x")],
        path=["File:src/a.js", "Definition:f"],
        hops=1,
        entry_point="src/a.js",
        vulnerable_file=vuln_file,
        vulnerable_definition="f",
        occurrence_id=occurrence_id,
        occurrence_name="SSRF",
        severity="high",
        verdict_basis="path_found",
        fingerprint=fingerprint,
    )


def _actions():
    return GitLabActions(BASE, "glpat-test", PID)


def _note(note_id, receipt=None, body=None):
    if body is None:
        body = render_mr_receipt(receipt)
    return {"id": note_id, "body": body}


# --- marker helpers ---------------------------------------------------------

def test_occurrence_key_is_independent_of_vulnerable_file():
    # Delta4: a finding that gains/loses a file must keep the same identity.
    a = occurrence_key(_receipt(vuln_file="src/b.js"))
    b = occurrence_key(_receipt(vuln_file=None))
    assert a == b


def test_occurrence_key_empty_id_falls_back_to_name_file():
    key = occurrence_key(_receipt(occurrence_id=""))
    assert key  # derived from name|vulnerable_file, not a crash


def test_occurrence_key_empty_everything_raises():
    r = _receipt(occurrence_id="", vuln_file=None)
    r.occurrence_name = ""
    with pytest.raises(ValueError):
        occurrence_key(r)


def test_marker_contains_no_dynamic_metrics():
    marker = build_marker(_receipt())
    for forbidden in ("api_calls", "nodes_visited", "generated_at",
                      "orbit_api_calls", "cache_hits"):
        assert forbidden not in marker
    parsed = parse_marker(marker)
    assert parsed["fingerprint"] == "fp-aaaa"
    assert parsed["occurrence_key"] == occurrence_key(_receipt())


# --- upsert behaviour -------------------------------------------------------

@respx.mock
def test_no_existing_note_posts():
    respx.get(NOTES).mock(return_value=httpx.Response(200, json=[]))
    post = respx.post(NOTES).mock(
        return_value=httpx.Response(201, json={"id": 100}))
    res = _actions().upsert_mr_receipt(MR, _receipt())
    assert res["action"] == "created"
    assert post.called


@respx.mock
def test_same_key_same_fingerprint_is_unchanged():
    existing = _note(100, _receipt(fingerprint="fp-same"))
    respx.get(NOTES).mock(return_value=httpx.Response(200, json=[existing]))
    post = respx.post(NOTES).mock(return_value=httpx.Response(201, json={"id": 1}))
    put = respx.put(f"{NOTES}/100").mock(return_value=httpx.Response(200, json={"id": 100}))

    res = _actions().upsert_mr_receipt(MR, _receipt(fingerprint="fp-same"))
    assert res["action"] == "unchanged"
    assert not post.called
    assert not put.called


@respx.mock
def test_same_key_different_fingerprint_updates():
    existing = _note(100, _receipt(fingerprint="fp-old"))
    respx.get(NOTES).mock(return_value=httpx.Response(200, json=[existing]))
    put = respx.put(f"{NOTES}/100").mock(
        return_value=httpx.Response(200, json={"id": 100}))

    res = _actions().upsert_mr_receipt(MR, _receipt(fingerprint="fp-new"))
    assert res["action"] == "updated"
    assert put.called


@respx.mock
def test_multiple_matches_updates_newest_with_warning():
    # Two notes share the same occurrence_key; the newest (highest id) wins.
    old = _note(100, _receipt(fingerprint="fp-old"))
    new = _note(200, _receipt(fingerprint="fp-old"))
    respx.get(NOTES).mock(return_value=httpx.Response(200, json=[old, new]))
    put_new = respx.put(f"{NOTES}/200").mock(
        return_value=httpx.Response(200, json={"id": 200}))
    delete = respx.delete(f"{NOTES}/100").mock(
        return_value=httpx.Response(200, json={}))

    res = _actions().upsert_mr_receipt(MR, _receipt(fingerprint="fp-new"))
    assert res["action"] == "updated"
    assert res["note_id"] == 200
    assert "warning" in res
    assert put_new.called
    assert not delete.called  # never delete duplicates


@respx.mock
def test_pagination_finds_marker_on_second_page():
    # Page 1 empty with X-Next-Page; the matching note is on page 2.
    existing = _note(300, _receipt(fingerprint="fp-same"))

    def handler(request):
        page = request.url.params.get("page")
        if page == "1":
            return httpx.Response(200, json=[], headers={"X-Next-Page": "2"})
        return httpx.Response(200, json=[existing], headers={"X-Next-Page": ""})

    respx.get(NOTES).mock(side_effect=handler)
    post = respx.post(NOTES).mock(return_value=httpx.Response(201, json={"id": 1}))

    res = _actions().upsert_mr_receipt(MR, _receipt(fingerprint="fp-same"))
    assert res["action"] == "unchanged"
    assert not post.called


@respx.mock
def test_malformed_marker_is_ignored():
    bad = _note(100, body="## ReachGate Triage Receipt\n<!-- reachgate:receipt:v1 broken -->")
    respx.get(NOTES).mock(return_value=httpx.Response(200, json=[bad]))
    post = respx.post(NOTES).mock(return_value=httpx.Response(201, json={"id": 101}))

    res = _actions().upsert_mr_receipt(MR, _receipt())
    assert res["action"] == "created"
    assert post.called


@respx.mock
def test_distinct_findings_same_file_post_separately():
    # Different occurrence ids -> different keys -> independent comments.
    respx.get(NOTES).mock(return_value=httpx.Response(200, json=[]))
    posts = respx.post(NOTES).mock(return_value=httpx.Response(201, json={"id": 1}))

    a = _actions().upsert_mr_receipt(MR, _receipt(occurrence_id="occ-A"))
    b = _actions().upsert_mr_receipt(MR, _receipt(occurrence_id="occ-B"))
    assert a["occurrence_key"] != b["occurrence_key"]
    assert posts.call_count == 2
