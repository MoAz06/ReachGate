import pytest
from pathlib import Path
from src.reachgate.config import load_config, ReachGateConfig, _glob_match

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


# --- Glob matching ---------------------------------------------------------
#
# `**/` means "zero or more directory components", so it MUST also match zero
# directories. Regression for the bug where `cmd/**/main.*` matched
# `cmd/x/main.go` but not `cmd/main.go`, which could surface a real entry point
# as unmatched and produce a false NOT_REACHABLE.


@pytest.mark.parametrize(
    "path, pattern",
    [
        # The bug case: ** must collapse to zero directories.
        ("cmd/main.go", "cmd/**/main.*"),
        ("cmd/x/main.go", "cmd/**/main.*"),
        ("cmd/x/y/main.py", "cmd/**/main.*"),
        # `**/` as its own segment, zero and many directories.
        ("src/routes/b.js", "src/routes/**/*"),
        ("src/routes/a/b.js", "src/routes/**/*"),
        # Plain literals and single-star.
        ("app.py", "app.py"),
        ("server.ts", "server.ts"),
    ],
)
def test_glob_matches(path, pattern):
    assert _glob_match(path, pattern)


@pytest.mark.parametrize(
    "path, pattern",
    [
        # Different top-level directory must not match.
        ("src/main.go", "cmd/**/main.*"),
        # The trailing literal still has to match.
        ("cmd/notmain.go", "cmd/**/main.*"),
        # `*` must not cross a directory separator.
        ("a/app.py", "app.py"),
        ("src/routes/a/b.js", "src/routes/*"),
    ],
)
def test_glob_non_matches(path, pattern):
    assert not _glob_match(path, pattern)


def test_default_config_matches_cmd_main_without_subdir():
    """The shipped reachgate.yml must match `cmd/main.go` via `cmd/**/main.*`."""
    cfg = load_config(FIXTURE_CONFIG)
    assert cfg.is_entrypoint("cmd/main.go")
    assert cfg.is_entrypoint("cmd/server/main.go")


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
