"""Compatibility shim. The canonical evidence-manifest builder now lives in the
package at ``reachgate.build_evidence_manifest`` so it ships with a bare
``pip install`` (see that module's docstring).

This shim makes ``tools.build_evidence_manifest`` resolve to the exact same
module object as the package one (via ``sys.modules``), so existing callers,
``python tools/build_evidence_manifest.py``, and tests that monkeypatch module
attributes all act on the real implementation -- no drifting alias copy.
"""

import sys
from pathlib import Path

_SRC = Path(__file__).resolve().parents[1] / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from reachgate import build_evidence_manifest as _impl  # noqa: E402

# Make `from tools import build_evidence_manifest` return the package module
# itself, so monkeypatching it patches the real implementation.
sys.modules[__name__] = _impl

if __name__ == "__main__":
    raise SystemExit(_impl.main())
