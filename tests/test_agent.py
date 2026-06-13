"""Agent entry-point UX tests."""

import pytest

from src.reachgate import agent


def test_run_missing_token_raises_clean_error_not_keyerror(monkeypatch):
    # No GITLAB_TOKEN in the environment and none passed in.
    monkeypatch.delenv("GITLAB_TOKEN", raising=False)

    with pytest.raises(RuntimeError) as exc:
        agent.run(gitlab_url="https://gitlab.com", token=None, project_id="1")

    # Clean, actionable message - not a raw KeyError traceback.
    assert "GITLAB_TOKEN" in str(exc.value)
    assert not isinstance(exc.value, KeyError)
