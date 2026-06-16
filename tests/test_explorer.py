"""The evidence explorer is a self-contained, offline, honest HTML page.

These tests pin: it generates valid HTML with a local file picker, it carries
the client-side renderers for every ReachGate artifact type, it repeats the
honesty framing (bounded / evidence gap / overlap-not-causation), it has NO
external resources (no CDN, no remote script/font, no network), and the CLI
writes it.
"""

from src.reachgate import explorer
from src.reachgate import cli


def test_render_page_is_valid_self_contained_html():
    html = explorer.render_page()
    assert "<!doctype html>" in html
    assert "<html" in html and "</html>" in html
    assert "ReachGate Evidence Explorer" in html
    # local file picker + drag/drop = the "explorer" interactivity.
    assert 'type="file"' in html
    assert "FileReader" in html


def test_no_external_resources():
    html = explorer.render_page()
    low = html.lower()
    # Offline: no network of any kind.
    assert "http://" not in low
    assert "https://" not in low
    assert "cdn" not in low
    # Inline script only -- never a remote script/stylesheet.
    assert "<script src=" not in low
    assert "src=\"http" not in low
    assert "<link" not in low


def test_carries_renderers_for_each_artifact_type():
    html = explorer.render_page()
    for marker in ("renderReceipt", "renderFixcheck", "renderContract", "renderBlame"):
        assert marker in html
    # detection of the four artifact shapes
    assert "classification" in html  # fixcheck detection
    assert "touches_path" in html    # blame detection


def test_repeats_honesty_framing():
    html = explorer.render_page()
    low = html.lower()
    assert "evidence gap" in low          # UNKNOWN
    assert "bounded" in low               # NOT_REACHABLE
    assert "overlap" in low and "not a" in low  # blame is not causation
    # never re-decides a verdict (text may wrap across lines)
    assert "re-decides a verdict" in low


def test_no_overclaiming_language():
    low = explorer.render_page().lower()
    assert "production-ready" not in low
    assert "certified" not in low


def test_generate_is_deterministic(tmp_path):
    a = tmp_path / "a.html"
    b = tmp_path / "b.html"
    explorer.generate(a)
    explorer.generate(b)
    assert a.read_bytes() == b.read_bytes()


def test_cli_explorer_writes_file(tmp_path, capsys):
    out = tmp_path / "explorer.html"
    rc = cli.main(["explorer", "--output", str(out)])
    assert rc == 0
    assert out.exists()
    assert "Evidence Explorer" in out.read_text(encoding="utf-8")
    assert "wrote" in capsys.readouterr().out
