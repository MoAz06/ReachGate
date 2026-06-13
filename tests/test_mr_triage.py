"""Judge-facing error handling for the MR triage CLI.

These tests assert that live Orbit/GitLab failures and BYO input/config errors
surface as one clean stderr line with exit code 2 -- never a Python traceback.
They do not touch receipt rendering, the artifact schema, the marker format,
or the idempotent upsert behavior (covered by test_actions_idempotency.py).
"""

import httpx
import pytest

import tools.mr_triage as triage


def _set_env(monkeypatch):
    monkeypatch.setenv("GITLAB_TOKEN", "fake-token")
    monkeypatch.setenv("CI_PROJECT_ID", "123")
    monkeypatch.setenv("CI_MERGE_REQUEST_IID", "7")


def _http_status_error(code):
    request = httpx.Request("POST", "https://gitlab.com/api/v4/orbit/query")
    response = httpx.Response(code, request=request)
    return httpx.HTTPStatusError(f"HTTP {code}", request=request, response=response)


def test_missing_env_exits_one(monkeypatch, capsys):
    # Preserved legacy behavior: missing CI env -> exit 1 (not 2).
    monkeypatch.delenv("GITLAB_TOKEN", raising=False)
    monkeypatch.delenv("CI_PROJECT_ID", raising=False)
    monkeypatch.delenv("GITLAB_PROJECT_ID", raising=False)
    monkeypatch.delenv("CI_MERGE_REQUEST_IID", raising=False)
    monkeypatch.delenv("GITLAB_MR_IID", raising=False)
    assert triage.main([]) == 1


def test_http_status_error_exits_two_clean(monkeypatch, capsys):
    _set_env(monkeypatch)

    def boom(*args, **kwargs):
        raise _http_status_error(401)

    # The first live call _run_triage makes is OrbitClient(...); make its
    # construction fine but any query raise. Simplest: patch _run_triage's
    # entry by raising from the client constructor's discover step.
    monkeypatch.setattr(triage, "_run_triage",
                        lambda *a, **k: (_ for _ in ()).throw(_http_status_error(401)))
    rc = triage.main([])
    captured = capsys.readouterr()
    assert rc == 2
    assert "HTTP 401" in captured.err
    assert "Traceback" not in captured.err


def test_network_error_exits_two_clean(monkeypatch, capsys):
    _set_env(monkeypatch)
    monkeypatch.setattr(triage, "_run_triage",
                        lambda *a, **k: (_ for _ in ()).throw(httpx.ConnectError("refused")))
    rc = triage.main([])
    captured = capsys.readouterr()
    assert rc == 2
    assert "ConnectError" in captured.err
    assert "Traceback" not in captured.err


def test_byo_findings_load_error_exits_two_clean(monkeypatch, capsys):
    _set_env(monkeypatch)
    from reachgate.findings import FindingsLoadError
    monkeypatch.setattr(triage, "_run_triage",
                        lambda *a, **k: (_ for _ in ()).throw(
                            FindingsLoadError("Findings file not found: nope.json")))
    rc = triage.main([])
    captured = capsys.readouterr()
    assert rc == 2
    assert "could not load findings" in captured.err
    assert "Traceback" not in captured.err


def test_byo_config_error_exits_two_clean(monkeypatch, capsys):
    _set_env(monkeypatch)
    monkeypatch.setattr(triage, "_run_triage",
                        lambda *a, **k: (_ for _ in ()).throw(
                            ValueError("reachgate.yml must define at least one entrypoints.files pattern")))
    rc = triage.main([])
    captured = capsys.readouterr()
    assert rc == 2
    assert "configuration error" in captured.err
    assert "Traceback" not in captured.err
