"""Generate a self-contained, offline ReachGate evidence explorer (HTML).

The judge-proof page (``build_judge_proof.py``) renders ONE curated, validated
case file. The explorer is the complementary tool: a single static HTML page
that lets a reviewer **load any ReachGate artifact from their own machine** --
a receipt, a ``fixcheck`` result, a ``contract-check`` report, or a ``blame``
overlap -- and inspect it in the browser, with zero network access.

Hard constraints (the same honesty bar as the judge proof):
  * No network. No CDN, no external scripts, no remote fonts. Everything is
    inline in the one file.
  * No data is baked in. The page reads files the user picks locally
    (``<input type=file>`` + the FileReader API); nothing is uploaded anywhere.
  * The page only *displays* what an artifact already says. It never re-decides
    a verdict, and it repeats ReachGate's honesty framing: NOT_REACHABLE is
    bounded, UNKNOWN is an evidence gap, ``blame`` is overlap not causation.

The interactivity (file picker + client-side rendering) is the whole point of an
"explorer", so this page DOES use a small inline ``<script>``. That is fine: it
is local, dependency-free, and touches no network -- unlike ``judge-proof.html``
which is a static rendered artifact and forbids script entirely.

Standard library only. No network, no token, no dependencies.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

DEFAULT_OUTPUT = "reachgate-explorer.html"

# The inline client-side script. Kept as a plain string (not an f-string) so the
# JavaScript braces need no escaping. Detection keys mirror the artifact shapes
# produced by reachgate (receipt: schema_version + findings with verdict;
# fixcheck: findings with classification; contract-check: results/overall;
# blame: findings with touches_path).
_SCRIPT = r"""
const drop = document.getElementById('drop');
const fileInput = document.getElementById('file');
const out = document.getElementById('out');

function esc(v){
  if (v === null || v === undefined) return 'n/a';
  return String(v).replace(/[&<>"]/g, c => (
    {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
}

function badge(verdict){
  const v = String(verdict || '').toUpperCase();
  const cls = v === 'REACHABLE' ? 'b-red'
    : v === 'NOT_REACHABLE' ? 'b-green'
    : v === 'UNKNOWN' ? 'b-amber' : 'b-grey';
  return '<span class="badge ' + cls + '">' + esc(v || '?') + '</span>';
}

function detect(data){
  if (Array.isArray(data)) return 'receipt';
  if (data && typeof data === 'object'){
    if ('overall' in data || (data.results && Array.isArray(data.results))) return 'contract';
    const f = data.findings;
    if (Array.isArray(f) && f.length){
      const k = f[0] || {};
      if ('classification' in k) return 'fixcheck';
      if ('touches_path' in k) return 'blame';
      if ('verdict' in k) return 'receipt';
    }
    if ('summary' in data && data.summary && 'reachable_paths_touched' in data.summary) return 'blame';
  }
  return 'unknown';
}

function table(rows, headers){
  let h = '<table><tr>' + headers.map(x => '<th>' + esc(x) + '</th>').join('') + '</tr>';
  h += rows.map(r => '<tr>' + r.map(c => '<td>' + c + '</td>').join('') + '</tr>').join('');
  return h + '</table>';
}

function renderReceipt(name, data){
  const findings = Array.isArray(data) ? data : (data.findings || []);
  const rows = findings.map(f => [
    badge(f.verdict),
    esc(f.occurrence_name || f.occurrence_id),
    esc(f.verdict_basis),
    esc(f.fingerprint),
    esc((f.path || []).join(' -> '))
  ]);
  return section(name, 'receipt', table(rows,
    ['verdict','finding','basis','fingerprint','path']),
    'NOT_REACHABLE is bounded (within the configured search). UNKNOWN is an '
    + 'evidence gap, never "safe".');
}

function renderFixcheck(name, data){
  const rows = (data.findings || []).map(f => [
    esc(f.occurrence_id),
    esc(f.before_verdict) + ' &rarr; ' + esc(f.after_verdict),
    '<strong>' + esc(f.classification) + '</strong>',
    esc(f.reason)
  ]);
  return section(name, 'fixcheck', table(rows,
    ['finding','before -> after','classification','reason']),
    'reachability_removed requires an EXHAUSTIVE after NOT_REACHABLE under the '
    + 'same policy. UNKNOWN is never a fix.');
}

function renderContract(name, data){
  const results = data.results || (Array.isArray(data) ? data : []);
  const rows = (results.length ? results : [data]).map(r => [
    '<strong>' + esc(r.overall || r.status) + '</strong>',
    esc(r.occurrence_id || r.source || ''),
    esc((r.problems || r.messages || []).join('; '))
  ]);
  return section(name, 'contract-check', table(rows,
    ['result','finding/source','notes']),
    'A non-exhaustive NOT_REACHABLE claimed as safe is a contract FAIL. '
    + 'UNKNOWN is review, never pass-as-safe.');
}

function renderBlame(name, data){
  const rows = (data.findings || []).map(f => [
    badge(f.verdict),
    esc(f.occurrence_id),
    (f.reachable && f.touches_path) ? '<strong>yes (reachable path)</strong>'
      : (f.touches_path ? 'yes' : 'no'),
    esc((f.touched_files || []).join(', '))
  ]);
  return section(name, 'blame (overlap)', table(rows,
    ['verdict','finding','touches path?','files on path touched']),
    'OVERLAP only: the change touches files on a reachable path. This is NOT a '
    + 'claim that it introduced reachability.');
}

function section(name, kind, body, note){
  return '<section class="card"><h2>' + esc(name)
    + ' <span class="kind">' + esc(kind) + '</span></h2>'
    + body + '<p class="note">' + esc(note) + '</p></section>';
}

function render(name, data){
  const kind = detect(data);
  if (kind === 'receipt') return renderReceipt(name, data);
  if (kind === 'fixcheck') return renderFixcheck(name, data);
  if (kind === 'contract') return renderContract(name, data);
  if (kind === 'blame') return renderBlame(name, data);
  return section(name, 'unrecognized',
    '<pre>' + esc(JSON.stringify(data, null, 2)) + '</pre>',
    'Not a recognized ReachGate artifact; showing raw JSON.');
}

function handleFiles(files){
  out.innerHTML = '';
  [...files].forEach(file => {
    const reader = new FileReader();
    reader.onload = e => {
      let html;
      try { html = render(file.name, JSON.parse(e.target.result)); }
      catch (err) {
        html = section(file.name, 'error', '<pre>' + esc(err) + '</pre>',
          'Could not parse as JSON.');
      }
      out.insertAdjacentHTML('beforeend', html);
    };
    reader.readAsText(file);
  });
}

fileInput.addEventListener('change', e => handleFiles(e.target.files));
drop.addEventListener('dragover', e => { e.preventDefault(); drop.classList.add('over'); });
drop.addEventListener('dragleave', () => drop.classList.remove('over'));
drop.addEventListener('drop', e => {
  e.preventDefault(); drop.classList.remove('over'); handleFiles(e.dataTransfer.files);
});
"""

_STYLE = """
:root{--ink:#241d12;--paper:#f6f0e1;--rule:#d6c9a9;--red:#ad3320;
--green:#3c6a44;--amber:#8f6410;--dim:#6c6049;}
*{box-sizing:border-box}
body{margin:0;background:#b3a888;color:var(--ink);
font-family:"Iowan Old Style",Palatino,Georgia,serif;line-height:1.55}
header{background:var(--paper);border-bottom:3px solid var(--red);padding:28px 24px}
.wrap{max-width:1000px;margin:0 auto;padding:24px}
h1{margin:0 0 6px;font-size:1.8rem}
.lead{color:var(--dim);font-family:"Courier New",monospace;font-size:.85rem;margin:0}
#drop{border:2px dashed var(--rule);background:var(--paper);padding:30px;
text-align:center;margin:24px 0;font-family:"Courier New",monospace}
#drop.over{border-color:var(--red);background:#efe6d2}
input[type=file]{margin-top:10px}
.card{background:var(--paper);border:1px solid var(--rule);margin:0 0 20px;
padding:18px 20px;box-shadow:0 10px 22px -18px rgba(40,30,12,.7)}
.card h2{font-size:1.15rem;margin:0 0 12px}
.kind{font-family:"Courier New",monospace;font-size:.7rem;text-transform:uppercase;
letter-spacing:.08em;color:var(--dim);border:1px solid var(--rule);padding:2px 7px;margin-left:8px}
table{width:100%;border-collapse:collapse;font-size:.85rem}
th{text-align:left;border-bottom:2px solid var(--ink);padding:6px 8px;
font-family:"Courier New",monospace;font-size:.66rem;text-transform:uppercase;color:var(--dim)}
td{border-bottom:1px solid var(--rule);padding:6px 8px;vertical-align:top}
.badge{font-family:"Courier New",monospace;font-weight:700;font-size:.7rem;
padding:2px 8px;border:1px solid currentColor}
.b-red{color:var(--red)}.b-green{color:var(--green)}.b-amber{color:var(--amber)}.b-grey{color:var(--dim)}
.note{font-family:"Courier New",monospace;font-size:.74rem;color:var(--dim);
border-left:3px solid var(--rule);padding-left:10px;margin:12px 0 0}
pre{white-space:pre-wrap;font-size:.78rem;background:#efe6d2;padding:10px;overflow:auto}
footer{max-width:1000px;margin:0 auto;padding:0 24px 40px;
font-family:"Courier New",monospace;font-size:.74rem;color:#4a4030}
"""


def render_page() -> str:
    """Return the complete self-contained explorer HTML (no external resources)."""
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>ReachGate Evidence Explorer</title>
  <style>{_STYLE}</style>
</head>
<body>
  <header>
    <div class="wrap" style="padding:0">
      <h1>ReachGate Evidence Explorer</h1>
      <p class="lead">Open any ReachGate artifact locally &mdash; receipt,
        fixcheck, contract-check, or blame. Offline; nothing is uploaded.</p>
    </div>
  </header>
  <div class="wrap">
    <div id="drop">
      Drop ReachGate JSON artifact(s) here, or pick a file:
      <div><input id="file" type="file" accept="application/json,.json" multiple></div>
    </div>
    <div id="out"></div>
  </div>
  <footer>
    The explorer only displays what an artifact already states; it never
    re-decides a verdict. NOT_REACHABLE is bounded, UNKNOWN is an evidence gap,
    and blame is overlap &mdash; not a causation claim. Verify the artifacts
    themselves offline with <code>reachgate verify</code> /
    <code>reachgate contract-check</code>.
  </footer>
  <script>{_SCRIPT}</script>
</body>
</html>
"""


def generate(output: Path) -> Path:
    out = Path(output)
    out.parent.mkdir(parents=True, exist_ok=True)
    tmp = out.with_name(f".{out.name}.tmp")
    tmp.write_text(render_page(), encoding="utf-8")
    tmp.replace(out)
    return out


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="reachgate explorer",
        description="Generate a self-contained, offline evidence explorer page.",
    )
    parser.add_argument("--output", default=DEFAULT_OUTPUT,
                        help=f"output HTML path (default: {DEFAULT_OUTPUT}).")
    args = parser.parse_args(argv)
    out = generate(Path(args.output))
    print(f"wrote {out}")
    print("Open it in a browser and load any ReachGate artifact (offline).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
