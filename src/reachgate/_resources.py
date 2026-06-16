"""Locate ReachGate's evidence artifacts whether running from a repo checkout
or from a bare ``pip install``.

The captured proof receipts live under ``docs/proof/`` in a checkout, but that
directory is NOT shipped by ``pip`` (only the ``reachgate`` package under
``src/`` is). To make the offline CLI work after a bare install, a byte-identical
copy of the read-only receipts is bundled as package data under
``reachgate/_data/proof/``.

Resolution rule (single source of truth, used by every offline tool):

  * If a ReachGate repo checkout is found (it has ``tools/`` and ``docs/proof/``),
    use the live ``docs/proof/`` there. This keeps in-checkout behaviour and the
    byte-stable proof artifacts exactly as before -- the bundled copy is never
    consulted inside a checkout.
  * Otherwise (bare install, any working directory), fall back to the bundled
    package-data copy, so ``reachgate verify`` / ``coverage`` still work.

Standard library only. No network, no token.
"""

from __future__ import annotations

from importlib import resources
from pathlib import Path


def repo_root() -> Path | None:
    """Locate a ReachGate repo checkout, else None.

    Walks up from the current working directory (so the CLI works from any
    subdirectory of a checkout), then also considers the installed package's own
    location in case the package itself lives inside a checkout. A directory is a
    checkout when it has both ``tools/`` and ``docs/proof/``.
    """
    here = Path.cwd().resolve()
    candidates = [here, *here.parents]
    pkg_root = Path(__file__).resolve().parents[2]
    candidates.append(pkg_root)
    for base in candidates:
        if (base / "tools").is_dir() and (base / "docs" / "proof").is_dir():
            return base
    return None


def proof_dir() -> Path:
    """The directory holding the captured proof receipts.

    ``docs/proof/`` in a checkout, else the bundled package-data copy. Always a
    real filesystem ``Path`` (ReachGate is installed unzipped), so callers can
    read files from it directly.
    """
    root = repo_root()
    if root is not None:
        return root / "docs" / "proof"
    bundled = resources.files("reachgate").joinpath("_data", "proof")
    return Path(str(bundled))


def bundled_proof_dir() -> Path:
    """The bundled package-data proof dir, regardless of any checkout.

    Used only where the bundled copy is explicitly wanted (e.g. a standalone
    self-test); normal callers use :func:`proof_dir`.
    """
    bundled = resources.files("reachgate").joinpath("_data", "proof")
    return Path(str(bundled))
