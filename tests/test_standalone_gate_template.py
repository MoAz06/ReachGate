"""The standalone-gate CI template is a real, opt-in, downstream-usable artifact.

These tests pin `templates/gitlab/reachgate-standalone-gate.yml`: it exists, it
defines the gate job, it runs the marked `standalone` test, and -- crucially --
adding it did NOT modify the submission root `.gitlab-ci.yml` (the template is
opt-in via `include`, never wired into the root pipeline).

Pure text/asserts over the template; no GitLab CI is executed.
"""

from pathlib import Path

from src.reachgate import cli


def _root() -> Path:
    root = cli._find_repo_root()
    assert root is not None
    return root


def _template_text() -> str:
    p = _root() / "templates" / "gitlab" / "reachgate-standalone-gate.yml"
    assert p.exists(), "standalone-gate template is missing"
    return p.read_text(encoding="utf-8")


def test_template_exists_and_defines_job():
    text = _template_text()
    assert "reachgate-standalone-gate:" in text


def test_template_runs_the_marked_standalone_test():
    text = _template_text()
    assert "pytest -m standalone" in text


def test_template_documents_enforce_and_advisory():
    lower = _template_text().lower()
    assert "allow_failure: true" in lower   # advisory option documented
    assert "opt-in" in lower


def test_template_is_offline_no_token():
    text = _template_text()
    # The standalone gate installs + runs the offline CLI; it wires in no token.
    assert "GITLAB_TOKEN" not in text
    assert "orbit/query" not in text.lower()


def test_root_ci_does_not_include_standalone_gate():
    """Adding the template must not modify the submission root .gitlab-ci.yml."""
    root_ci = (_root() / ".gitlab-ci.yml").read_text(encoding="utf-8")
    # Root keeps its existing jobs and does NOT pull in the new gate.
    assert "reachgate-triage:" in root_ci
    assert "reachgate-standalone-gate" not in root_ci
    assert "reachgate-standalone-gate.yml" not in root_ci
