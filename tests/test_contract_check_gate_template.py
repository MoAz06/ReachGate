"""The contract-check CI gate template is a real, downstream-usable artifact.

These tests pin `templates/gitlab/reachgate-contract-check.yml`: it exists, it
defines the gate job, it is configurable via REACHGATE_RECEIPTS_FILE, it runs
`reachgate contract-check`, it writes and uploads the markdown report, and it
documents advisory vs. strict mode. They also assert that the gate stays
OFFLINE (no Orbit/GitLab API call wired in) and that adding this template did
not touch the submission root `.gitlab-ci.yml`.

Pure text/asserts over the template and docs; no GitLab CI is executed.
"""

from pathlib import Path

from src.reachgate import cli


def _root() -> Path:
    root = cli._find_repo_root()
    assert root is not None
    return root


def _template_text() -> str:
    p = _root() / "templates" / "gitlab" / "reachgate-contract-check.yml"
    assert p.exists(), "contract-check gate template is missing"
    return p.read_text(encoding="utf-8")


# --- template exists and defines the gate job ------------------------------

def test_template_file_exists():
    assert (
        _root() / "templates" / "gitlab" / "reachgate-contract-check.yml"
    ).exists()


def test_template_defines_gate_job():
    text = _template_text()
    assert "reachgate-contract-check:" in text


def test_template_uses_configurable_receipts_file():
    text = _template_text()
    assert "REACHGATE_RECEIPTS_FILE" in text
    # Has the documented default fallback.
    assert "reachgate-receipts.json" in text


def test_template_runs_contract_check():
    text = _template_text()
    assert "reachgate contract-check" in text
    # It validates the configurable receipt path, not a hardcoded one.
    assert 'reachgate contract-check "$REACHGATE_RECEIPTS_FILE"' in text


def test_template_writes_and_uploads_markdown_report():
    text = _template_text()
    assert "reachgate-contract-report.md" in text
    # Written via --output and uploaded as an artifact.
    assert "--output reachgate-contract-report.md" in text
    assert "artifacts:" in text
    assert "when: always" in text


def test_template_documents_advisory_and_strict_mode():
    text = _template_text()
    lower = text.lower()
    assert "advisory" in lower
    assert "strict" in lower
    assert "allow_failure: true" in text
    assert "allow_failure: false" in text


# --- the gate stays offline ------------------------------------------------

def test_template_is_offline_no_api_calls():
    """The contract-check gate must not perform a live scan or API call."""
    text = _template_text()
    lower = text.lower()
    # It does not run the live MR triage / scan entrypoints.
    assert "mr_triage.py" not in lower
    assert "demo_e2e.py" not in lower
    assert "reachgate scan" not in lower
    # It does not wire in tokens / live Orbit endpoints for this job.
    assert "GITLAB_TOKEN" not in text
    assert "api/v4/orbit" not in lower
    assert "orbit/query" not in lower
    assert "orbit/mcp" not in lower
    # It states explicitly that it does not call Orbit/GitLab.
    assert "does not call" in lower or "not call" in lower


def test_template_documents_install_requirement_honestly():
    """No fake 'fully standalone' claim: the CLI needs the package installed."""
    text = _template_text()
    lower = text.lower()
    assert "pip install" in lower
    # Honest about needing ReachGate available in the job.
    assert "vendor" in lower or "install" in lower


# --- docs mention the gate -------------------------------------------------

def test_ci_setup_docs_mention_contract_check_gate():
    text = (_root() / "docs" / "GITLAB_CI_SETUP.md").read_text(encoding="utf-8")
    assert "Contract-check gate" in text
    assert "reachgate-contract-check.yml" in text
    assert "REACHGATE_RECEIPTS_FILE" in text
    lower = text.lower()
    assert "advisory" in lower and "strict" in lower
    # The honest "does not call Orbit" framing.
    assert "does not call orbit" in lower


def test_demo_commands_mention_the_gate():
    text = (_root() / "docs" / "DEMO_COMMANDS.md").read_text(encoding="utf-8")
    assert "reachgate-contract-check.yml" in text


def test_judge_pack_references_the_gate():
    text = (_root() / "docs" / "JUDGE_PACK.md").read_text(encoding="utf-8")
    assert "reachgate-contract-check.yml" in text


# --- the submission root pipeline is untouched -----------------------------

def test_root_ci_does_not_include_contract_check_template():
    """Adding the template must not modify the submission root .gitlab-ci.yml."""
    root_ci = (_root() / ".gitlab-ci.yml").read_text(encoding="utf-8")
    # The root pipeline keeps exactly its two existing jobs.
    assert "reachgate-triage:" in root_ci
    assert "reachgate-live-demo:" in root_ci
    # It does NOT pull in the new gate (default: leave the root untouched).
    assert "reachgate-contract-check" not in root_ci
    assert "reachgate-contract-check.yml" not in root_ci
