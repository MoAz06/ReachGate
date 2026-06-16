"""Standalone bare-install gate (the Phase 1 green-gate, automated).

This is the test that proves "works after a bare ``pip install``" is real, not
just on paper. It is deliberately strict about HOW it checks:

  * a fresh virtual environment (not the dev venv);
  * a NON-editable install (``pip install .``, never ``-e``), so nothing
    resolves back to ``src/`` in the checkout;
  * every command is run from a temp directory OUTSIDE the repo, so neither the
    current working directory nor any parent is a checkout -- the only way the
    proof receipts can be found is the bundled package data.

Pass/fail matrix (the locked Phase 1 gate):

  * ``reachgate verify``                         -> exit 0 on bundled data
  * ``reachgate contract-check <receipt>``       -> exit 0
  * ``reachgate coverage`` (no --receipts)       -> exit 0 on bundled defaults
  * ``reachgate scan``                           -> exit 2, clean message,
                                                    no traceback

It is SLOW (it builds a venv and installs the package), so it is marked
``standalone`` and excluded from the default run (see pyproject ``addopts``).
Run it explicitly with::

    pytest -m standalone

The venv is created with ``--system-site-packages`` and the install uses
``--no-deps`` so httpx/pyyaml come from the host -- the thing under test is the
reachgate package and its bundled data resolution at RUNTIME, not dependency
downloading. The build backend (setuptools/wheel) is fetched by pip's build
isolation, so ``pip install`` itself may touch the network. If the install
cannot complete (no network / no build backend available), the gate SKIPS with
the captured reason rather than reporting a false failure -- the skip is an
infrastructure signal, never used to paper over a reachgate bug.
"""

from __future__ import annotations

import json
import subprocess
import sys
import venv
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]

pytestmark = pytest.mark.standalone


def _venv_python(venv_dir: Path) -> Path:
    if sys.platform == "win32":
        return venv_dir / "Scripts" / "python.exe"
    return venv_dir / "bin" / "python"


def _reachgate_exe(venv_dir: Path) -> Path:
    if sys.platform == "win32":
        return venv_dir / "Scripts" / "reachgate.exe"
    return venv_dir / "bin" / "reachgate"


def _run(cmd, cwd):
    return subprocess.run(
        [str(c) for c in cmd],
        cwd=str(cwd),
        capture_output=True,
        text=True,
        timeout=300,
    )


@pytest.fixture(scope="module")
def installed(tmp_path_factory):
    """Build a venv, install ReachGate non-editably, return (venv_dir, exe)."""
    base = tmp_path_factory.mktemp("rg_standalone")
    venv_dir = base / "venv"
    # --system-site-packages: host provides httpx/pyyaml/setuptools so the test
    # is network-free; we still install reachgate itself into the venv.
    venv.create(venv_dir, with_pip=True, system_site_packages=True)
    py = _venv_python(venv_dir)
    assert py.exists(), f"venv python missing at {py}"

    # --no-deps: httpx/pyyaml come from the host (system-site-packages); we
    # install only reachgate. Build isolation (default) fetches setuptools/wheel
    # to build the package, so this step may need the network.
    install = _run(
        [py, "-m", "pip", "install", "--no-deps", str(REPO_ROOT)],
        cwd=base,
    )
    if install.returncode != 0:
        pytest.skip(
            "could not build/install reachgate in a clean venv (no network or "
            "no build backend available); standalone runtime gate not exercised. "
            f"pip stderr tail:\n{install.stderr[-800:]}"
        )
    exe = _reachgate_exe(venv_dir)
    assert exe.exists(), f"reachgate console script missing at {exe}"
    return venv_dir, exe, base


def test_import_resolves_to_installed_not_checkout(installed):
    """The venv must import the INSTALLED reachgate, not the repo src/."""
    venv_dir, _exe, base = installed
    py = _venv_python(venv_dir)
    # Run from a dir outside the repo so cwd is not a checkout.
    out = _run([py, "-c", "import reachgate, sys; print(reachgate.__file__)"], cwd=base)
    assert out.returncode == 0, out.stderr
    location = out.stdout.strip()
    assert str(REPO_ROOT / "src") not in location, (
        f"import resolved to the checkout, not the install: {location}"
    )


def test_verify_works_standalone(installed):
    venv_dir, exe, base = installed
    out = _run([exe, "verify"], cwd=base)
    assert out.returncode == 0, f"verify failed:\n{out.stdout}\n{out.stderr}"
    assert "ReachGate proof verified" in out.stdout


def test_coverage_works_standalone_on_bundled_defaults(installed):
    venv_dir, exe, base = installed
    out = _run([exe, "coverage"], cwd=base)
    assert out.returncode == 0, f"coverage failed:\n{out.stdout}\n{out.stderr}"
    assert "ReachGate coverage" in out.stdout


def test_contract_check_works_standalone(installed, tmp_path):
    venv_dir, exe, base = installed
    # A real, contract-conformant receipt copied from the repo's captured proof.
    receipt_src = REPO_ROOT / "docs" / "proof" / "mr2-reachgate-receipts.json"
    receipt = base / "receipt.json"
    receipt.write_text(receipt_src.read_text(encoding="utf-8"), encoding="utf-8")
    out = _run([exe, "contract-check", str(receipt)], cwd=base)
    assert out.returncode == 0, (
        f"contract-check should pass a conformant receipt:\n{out.stdout}\n{out.stderr}"
    )


def test_scan_is_refused_cleanly_standalone(installed):
    venv_dir, exe, base = installed
    out = _run([exe, "scan"], cwd=base)
    assert out.returncode == 2, f"scan should exit 2, got {out.returncode}"
    # Clean, helpful message -- never a traceback.
    assert "Traceback" not in out.stderr
    assert "offline CLI" in out.stderr
