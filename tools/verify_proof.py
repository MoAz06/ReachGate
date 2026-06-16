"""Compatibility shim. The canonical offline verifier now lives in the package
at ``reachgate.verify_proof`` so it ships with a bare ``pip install`` (see that
module's docstring).

This shim makes ``tools.verify_proof`` resolve to the exact same module object
as the package one (via ``sys.modules``), so existing callers,
``python tools/verify_proof.py``, and tests that monkeypatch module attributes
all act on the real implementation -- no drifting alias copy.
"""

import sys
from pathlib import Path

_SRC = Path(__file__).resolve().parents[1] / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from reachgate import verify_proof as _impl  # noqa: E402

sys.modules[__name__] = _impl

if __name__ == "__main__":
    raise SystemExit(_impl.main())
