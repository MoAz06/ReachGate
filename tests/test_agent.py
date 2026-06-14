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


def test_run_uses_bounded_bfs_with_time_only_cap(monkeypatch):
    """M3: agent.run() builds a BoundedBFS bounded by time (120.0s) only.

    No network: OrbitClient/GitLabActions/load_config are stubbed and the
    occurrence list is empty, so the run just wires up the walker and returns.
    The walker's strategy must be a BoundedBFS with max_seconds == 120.0 and
    max_visited left as None (no node-visit cap).
    """
    from src.reachgate.path_strategy import BoundedBFS

    captured = {}

    class _FakeClient:
        def __init__(self, *a, **k):
            pass

        def get_vulnerability_occurrences(self, *a, **k):
            return []

    class _FakeActions:
        def __init__(self, *a, **k):
            pass

    def _fake_walker(client, config, strategy=None):
        captured["strategy"] = strategy
        return object()

    monkeypatch.setattr(agent, "OrbitClient", _FakeClient)
    monkeypatch.setattr(agent, "GitLabActions", _FakeActions)
    monkeypatch.setattr(agent, "load_config", lambda path: object())
    monkeypatch.setattr(agent, "GraphWalker", _fake_walker)

    result = agent.run(gitlab_url="https://gitlab.com", token="glpat-x", project_id="1")

    assert result == []
    strategy = captured["strategy"]
    assert isinstance(strategy, BoundedBFS)
    assert strategy.max_seconds == 120.0
    assert strategy.max_visited is None


def test_run_allows_disabling_walk_timeout(monkeypatch):
    """Passing max_seconds_per_walk=None disables the timeout (power-user path)."""
    from src.reachgate.path_strategy import BoundedBFS

    captured = {}

    class _FakeClient:
        def __init__(self, *a, **k):
            pass

        def get_vulnerability_occurrences(self, *a, **k):
            return []

    class _FakeActions:
        def __init__(self, *a, **k):
            pass

    def _fake_walker(client, config, strategy=None):
        captured["strategy"] = strategy
        return object()

    monkeypatch.setattr(agent, "OrbitClient", _FakeClient)
    monkeypatch.setattr(agent, "GitLabActions", _FakeActions)
    monkeypatch.setattr(agent, "load_config", lambda path: object())
    monkeypatch.setattr(agent, "GraphWalker", _fake_walker)

    agent.run(
        gitlab_url="https://gitlab.com",
        token="glpat-x",
        project_id="1",
        max_seconds_per_walk=None,
    )

    strategy = captured["strategy"]
    assert isinstance(strategy, BoundedBFS)
    assert strategy.max_seconds is None
    assert strategy.max_visited is None
