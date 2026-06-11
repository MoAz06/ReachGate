import pytest
from pathlib import Path
from src.reachgate.config import load_config, ReachGateConfig

FIXTURE_CONFIG = Path(__file__).parent.parent / "reachgate.yml"


def test_load_config_returns_reachgate_config():
    cfg = load_config(FIXTURE_CONFIG)
    assert isinstance(cfg, ReachGateConfig)


def test_load_config_has_patterns():
    cfg = load_config(FIXTURE_CONFIG)
    assert len(cfg.entrypoint_patterns) > 0


def test_is_entrypoint_matches_route():
    cfg = load_config(FIXTURE_CONFIG)
    assert cfg.is_entrypoint("src/routes/users.py")


def test_is_entrypoint_does_not_match_internal():
    cfg = load_config(FIXTURE_CONFIG)
    assert not cfg.is_entrypoint("src/db/query_builder.py")


def test_policy_defaults():
    cfg = load_config(FIXTURE_CONFIG)
    assert cfg.policy.min_hops >= 1
    assert cfg.policy.max_hops >= cfg.policy.min_hops


def test_missing_entrypoints_raises():
    import yaml, tempfile, os
    bad = {"version": "1", "entrypoints": {"files": []}}
    with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as f:
        yaml.dump(bad, f)
        name = f.name
    try:
        with pytest.raises(ValueError):
            load_config(name)
    finally:
        os.unlink(name)
