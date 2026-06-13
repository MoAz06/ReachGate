import json

import httpx
import pytest

from src.reachgate.config import ReachGateConfig
from src.reachgate.orbit_client import OrbitClient
from tools.reachgate_doctor import (
    DoctorError,
    _needle,
    check_pattern,
    main,
    render,
    run_checks,
)


class FakeClient:
    """Minimal stand-in for OrbitClient.get_files_matching (no token, no net)."""

    def __init__(self, by_pattern):
        # by_pattern: dict[pattern -> list[path]]
        self._by_pattern = by_pattern
        self.calls = []

    def get_files_matching(self, patterns):
        self.calls.append(patterns)
        out = []
        for p in patterns:
            out.extend({"path": path} for path in self._by_pattern.get(p, []))
        return out


class RaisingClient:
    """Stand-in whose Orbit query raises, like a live auth/network failure."""

    def __init__(self, exc):
        self._exc = exc

    def get_files_matching(self, patterns):
        raise self._exc


def _http_status_error(code):
    request = httpx.Request("POST", "https://gitlab.com/api/v4/orbit/query")
    response = httpx.Response(code, request=request)
    return httpx.HTTPStatusError(
        f"HTTP {code}", request=request, response=response
    )


def _config(patterns):
    return ReachGateConfig(version="1", entrypoint_patterns=patterns)


@pytest.mark.parametrize("pattern", [
    "cmd/**/main.*",
    "src/routes/**/*",
    "app/controllers/**/*",
    "app.py",
    "server.ts",
])
def test_doctor_needle_matches_engine_literal_needle(pattern):
    # The doctor's queryable gate and the engine's Orbit query MUST derive the
    # same needle from a pattern; otherwise the doctor can claim a pattern is
    # (un)queryable while get_files_matching does the opposite.
    assert _needle(pattern) == OrbitClient._literal_needle(pattern)


def test_check_pattern_confirms_against_glob_matcher():
    # Orbit's coarse `contains` returns an off-target path; the exact glob
    # matcher must drop it so the count is honest.
    config = _config(["src/routes/**/*"])
    client = FakeClient({
        "src/routes/**/*": [
            "src/routes/users.js",      # matches glob
            "src/routes/admin/auth.js",  # matches glob
            "docs/routes-guide.md",      # contains 'routes' but NOT the glob
        ],
    })
    r = check_pattern(client, config, "src/routes/**/*", limit=20)
    assert r["queryable"] is True
    assert r["match_count"] == 2
    assert "docs/routes-guide.md" not in r["paths"]


def test_check_pattern_short_needle_is_not_queryable():
    config = _config(["a*"])
    client = FakeClient({})
    r = check_pattern(client, config, "a*", limit=20)
    assert r["queryable"] is False
    assert r["match_count"] == 0
    assert client.calls == []  # never queried Orbit


def test_check_pattern_respects_limit_on_samples():
    config = _config(["src/routes/**/*"])
    paths = [f"src/routes/r{i}.js" for i in range(10)]
    client = FakeClient({"src/routes/**/*": paths})
    r = check_pattern(client, config, "src/routes/**/*", limit=3)
    assert r["match_count"] == 10
    assert len(r["paths"]) == 3


def test_render_total_files_and_zero_match_warning():
    results = [
        {"pattern": "src/routes/**/*", "queryable": True,
         "paths": ["src/routes/a.js"], "match_count": 1},
        {"pattern": "app/controllers/**/*", "queryable": True,
         "paths": [], "match_count": 0},
    ]
    lines, total = render(results, limit=20)
    assert total == 1
    text = "\n".join(lines)
    assert "patterns with matches:  1" in text
    assert "you still own" in text  # honesty disclaimer present


def test_render_all_zero_emits_false_negative_warning():
    results = [
        {"pattern": "src/routes/**/*", "queryable": True,
         "paths": [], "match_count": 0},
    ]
    lines, total = render(results, limit=20)
    assert total == 0
    assert "cannot be trusted" in "\n".join(lines)


def test_run_checks_one_per_pattern():
    config = _config(["src/routes/**/*", "app/controllers/**/*"])
    client = FakeClient({"src/routes/**/*": ["src/routes/a.js"]})
    results = run_checks(client, config, limit=20)
    assert [r["pattern"] for r in results] == config.entrypoint_patterns


def test_main_missing_token_exits_two(monkeypatch, capsys):
    monkeypatch.delenv("GITLAB_TOKEN", raising=False)
    assert main(["--config", "reachgate.yml"]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "GITLAB_TOKEN" in captured.err


def test_main_missing_config_exits_two(monkeypatch, capsys, tmp_path):
    monkeypatch.setenv("GITLAB_TOKEN", "fake-token")
    missing = str(tmp_path / "nope.yml")
    assert main(["--config", missing]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "config not found" in captured.err


def test_main_invalid_config_exits_two(monkeypatch, capsys, tmp_path):
    monkeypatch.setenv("GITLAB_TOKEN", "fake-token")
    bad = tmp_path / "bad.yml"
    # Valid YAML, but no entrypoints.files -> load_config raises ValueError.
    bad.write_text("version: '1'\nentrypoints:\n  files: []\n", encoding="utf-8")
    assert main(["--config", str(bad)]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "invalid config" in captured.err


def _patch_client(monkeypatch, fake):
    import tools.reachgate_doctor as doctor
    monkeypatch.setattr(doctor, "OrbitClient", lambda url, token: fake)


def test_main_with_matches_exits_zero(monkeypatch, tmp_path):
    monkeypatch.setenv("GITLAB_TOKEN", "fake-token")
    cfg = tmp_path / "rg.yml"
    cfg.write_text(
        "version: '1'\nentrypoints:\n  files:\n    - 'src/routes/**/*'\n",
        encoding="utf-8",
    )
    _patch_client(monkeypatch, FakeClient({"src/routes/**/*": ["src/routes/a.js"]}))
    assert main(["--config", str(cfg)]) == 0


def test_main_zero_matches_exits_one(monkeypatch, tmp_path):
    monkeypatch.setenv("GITLAB_TOKEN", "fake-token")
    cfg = tmp_path / "rg.yml"
    cfg.write_text(
        "version: '1'\nentrypoints:\n  files:\n    - 'src/routes/**/*'\n",
        encoding="utf-8",
    )
    _patch_client(monkeypatch, FakeClient({}))  # Orbit returns nothing
    assert main(["--config", str(cfg)]) == 1


def test_run_checks_translates_http_status_error():
    config = _config(["src/routes/**/*"])
    client = RaisingClient(_http_status_error(401))
    with pytest.raises(DoctorError) as exc:
        run_checks(client, config, limit=20)
    assert "401" in str(exc.value)


def test_run_checks_translates_transport_error():
    config = _config(["src/routes/**/*"])
    client = RaisingClient(httpx.ConnectError("connection refused"))
    with pytest.raises(DoctorError):
        run_checks(client, config, limit=20)


def _cfg_file(tmp_path):
    cfg = tmp_path / "rg.yml"
    cfg.write_text(
        "version: '1'\nentrypoints:\n  files:\n    - 'src/routes/**/*'\n",
        encoding="utf-8",
    )
    return str(cfg)


def test_main_unauthorized_token_exits_two_clean(monkeypatch, capsys, tmp_path):
    monkeypatch.setenv("GITLAB_TOKEN", "bad-token")
    _patch_client(monkeypatch, RaisingClient(_http_status_error(401)))
    assert main(["--config", _cfg_file(tmp_path)]) == 2
    captured = capsys.readouterr()
    # No traceback, clean stderr, and no misleading partial success on stdout.
    assert captured.out == ""
    assert "Orbit query failed" in captured.err
    assert "401" in captured.err


def test_main_forbidden_token_exits_two_clean(monkeypatch, capsys, tmp_path):
    monkeypatch.setenv("GITLAB_TOKEN", "bad-token")
    _patch_client(monkeypatch, RaisingClient(_http_status_error(403)))
    assert main(["--config", _cfg_file(tmp_path)]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "403" in captured.err


def test_main_network_error_exits_two_clean(monkeypatch, capsys, tmp_path):
    monkeypatch.setenv("GITLAB_TOKEN", "fake-token")
    _patch_client(monkeypatch, RaisingClient(httpx.ConnectError("refused")))
    assert main(["--config", _cfg_file(tmp_path)]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "Orbit query failed" in captured.err
