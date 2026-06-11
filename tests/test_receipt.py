from src.reachgate.actions import render_mermaid_path, render_receipt
from src.reachgate.policy_engine import PolicyReceipt, TriggeredRule, Verdict


def _reachable_receipt():
    return PolicyReceipt(
        verdict=Verdict.REACHABLE,
        risk_score=85,
        triggered_rules=[
            TriggeredRule("path_exists", 50, "A path exists."),
            TriggeredRule("direct_import", 20, "Within 2 hops."),
            TriggeredRule("high_severity", 15, "High severity."),
        ],
        path=["File:content/frontend/404/archives_redirect.js", "Definition:getArchivesVersions"],
        hops=1,
        entry_point="content/frontend/404/archives_redirect.js",
        vulnerable_file="content/frontend/services/fetch_versions.js",
        vulnerable_definition="getArchivesVersions",
        occurrence_id="demo-ssrf",
        occurrence_name="Server-side request forgery (SSRF)",
        severity="high",
    )


def _not_reachable_receipt():
    return PolicyReceipt(
        verdict=Verdict.NOT_REACHABLE,
        risk_score=8,
        triggered_rules=[TriggeredRule("medium_severity", 8, "Medium severity.")],
        path=[],
        hops=0,
        entry_point=None,
        vulnerable_file="scripts/create_issues.js",
        vulnerable_definition="createIssue",
        occurrence_id="demo-traversal",
        occurrence_name="Path Traversal",
        severity="medium",
    )


def test_receipt_contains_mermaid_block():
    out = render_receipt(_reachable_receipt())
    assert "```mermaid" in out
    assert "flowchart LR" in out


def test_mermaid_reachable_has_edge_and_styles():
    out = render_mermaid_path(_reachable_receipt())
    assert "n0 --> n1" in out
    assert "class n0 entry;" in out
    assert "class n1 vuln;" in out


def test_mermaid_node_labels_strip_kind_prefix():
    out = render_mermaid_path(_reachable_receipt())
    assert "getArchivesVersions" in out
    assert '"Definition:getArchivesVersions"' not in out


def test_mermaid_not_reachable_shows_disconnected_nodes():
    out = render_mermaid_path(_not_reachable_receipt())
    assert "no path found" in out
    assert "-->" not in out
    assert "class v safe;" in out


def test_mermaid_escapes_double_quotes():
    receipt = _reachable_receipt()
    receipt.path = ['File:weird"name.js', "Definition:fn"]
    out = render_mermaid_path(receipt)
    assert '""' not in out.replace('["', "").replace('"]', "")
    assert "weird'name.js" in out


def test_receipt_keeps_plaintext_path_for_audit():
    out = render_receipt(_reachable_receipt())
    assert "File:content/frontend/404/archives_redirect.js -> Definition:getArchivesVersions" in out


def test_receipt_not_reachable_says_no_path():
    out = render_receipt(_not_reachable_receipt())
    assert "no path found" in out
    assert "NOT_REACHABLE" in out
