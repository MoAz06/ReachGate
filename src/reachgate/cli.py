"""ReachGate command-line interface.

A single ``reachgate`` entry point over the offline, deterministic surface of
the project. Installed via:

    [project.scripts]
    reachgate = "reachgate.cli:main"

Packaging note (important):
  Only the ``reachgate`` package under ``src/`` is installed by ``pip``; the
  top-level ``tools/`` directory and ``docs/proof/`` artifacts are NOT shipped.
  So this CLI is split into two honest tiers:

    * ``coverage`` is implemented entirely inside the package
      (``reachgate.coverage``) and works wherever its input receipts are.
    * ``verify`` / ``export-vex`` / ``export-sarif`` / ``manifest`` / ``proof``
      delegate to the repo's ``tools/*.py`` and the captured ``docs/proof/``
      artifacts. When run outside a repo checkout (e.g. after a bare
      ``pip install``), they FAIL LOUDLY with a helpful message rather than
      producing nothing or crashing obscurely.

  ``scan`` is intentionally NOT implemented here: a real scan needs live Orbit
  and a token, which is out of scope for the offline CLI. It is documented as a
  live-only workflow via ``python -m reachgate.agent`` and the CI job.

Standard library only. No network, no token. The deterministic engine decides;
this CLI only routes and explains.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def _find_repo_root() -> Path | None:
    """Locate a ReachGate repo checkout by walking up for tools/ + docs/proof/.

    Returns the repo root when found, else None. This is what lets the CLI work
    from any subdirectory of a checkout, and detect when it is running outside
    one (after a bare pip install) so it can fail loudly instead of guessing.
    """
    here = Path.cwd().resolve()
    candidates = [here, *here.parents]
    # Also consider the installed package's own location, in case the CLI is
    # invoked from elsewhere but lives inside a checkout.
    pkg_root = Path(__file__).resolve().parents[2]
    candidates.append(pkg_root)
    for base in candidates:
        if (base / "tools").is_dir() and (base / "docs" / "proof").is_dir():
            return base
    return None


class _RepoUnavailable(RuntimeError):
    """Raised when a repo-only command is run outside a repo checkout."""


def _require_repo() -> Path:
    root = _find_repo_root()
    if root is None:
        raise _RepoUnavailable(
            "this command needs a ReachGate repo checkout (it reads tools/ and "
            "docs/proof/), which is not present here.\n"
            "  - Run it from a clone of the ReachGate repository, or\n"
            "  - use `reachgate coverage --receipts <file.json>` which works "
            "standalone.\n"
            "A bare `pip install` does not ship tools/ or docs/proof/."
        )
    return root


def _load_tool(root: Path, module_name: str):
    """Import a tools/*.py module from a repo checkout, package-safely.

    We never rely on `import tools...` resolving on sys.path (it does not after
    a package install); instead we load the file by path from the located repo
    root. Raises _RepoUnavailable with a clear message if the file is missing.
    """
    import importlib.util

    tool_path = root / "tools" / f"{module_name}.py"
    if not tool_path.is_file():
        raise _RepoUnavailable(
            f"expected {tool_path} in the repo checkout but it was not found."
        )
    # Make src/ importable so the tool's own `import reachgate...` works, and
    # the repo root so any `from tools import ...` inside the tool resolves.
    for extra in (str(root), str(root / "src")):
        if extra not in sys.path:
            sys.path.insert(0, extra)
    spec = importlib.util.spec_from_file_location(f"_reachgate_tool_{module_name}", tool_path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


# --- offline, package-safe command: coverage -------------------------------

def _default_receipt_sources(root: Path) -> list[Path]:
    proof = root / "docs" / "proof"
    names = (
        "mr2-reachgate-receipts.json",
        "unknown-reachgate-receipt.json",
    )
    return [proof / n for n in names]


def cmd_coverage(args) -> int:
    from . import coverage as coverage_mod

    if args.receipts:
        sources = [Path(p) for p in args.receipts]
    else:
        root = _find_repo_root()
        if root is None:
            print(
                "error: no --receipts given and no repo checkout found.\n"
                "  Pass receipt files explicitly: "
                "reachgate coverage --receipts <file.json> [...]",
                file=sys.stderr,
            )
            return 2
        sources = _default_receipt_sources(root)

    try:
        report = coverage_mod.build_coverage(sources)
    except coverage_mod.CoverageError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if args.format == "json":
        print(json.dumps(coverage_mod.render_json(report), indent=2, ensure_ascii=False))
    else:
        print(coverage_mod.render_text(report), end="")
    return 0


# --- repo-delegating commands ----------------------------------------------

def _run_tool_main(module_name: str, argv: list[str]) -> int:
    """Locate the repo, load the tool module, and run its main(argv)."""
    try:
        root = _require_repo()
        module = _load_tool(root, module_name)
    except _RepoUnavailable as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    main_fn = getattr(module, "main", None)
    if main_fn is None:
        print(f"error: {module_name} has no main() to run", file=sys.stderr)
        return 1
    return int(main_fn(argv) or 0)


def cmd_verify(args) -> int:
    # verify_proof.main() takes no argv; call it via the located repo.
    try:
        root = _require_repo()
        module = _load_tool(root, "verify_proof")
    except _RepoUnavailable as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return int(module.main() or 0)


def cmd_export_vex(args) -> int:
    return _run_tool_main("export_vex", args.tool_args)


def cmd_export_sarif(args) -> int:
    return _run_tool_main("export_sarif", args.tool_args)


def cmd_manifest(args) -> int:
    return _run_tool_main("build_evidence_manifest", args.tool_args)


def cmd_proof(args) -> int:
    return _run_tool_main("build_judge_proof", args.tool_args)


def cmd_scan(args) -> int:
    print(
        "error: `reachgate scan` is intentionally not available in the offline "
        "CLI.\n"
        "A real scan walks the live Orbit graph and needs GITLAB_TOKEN + "
        "network access.\n"
        "Run the live workflow instead:\n"
        "  - python -m reachgate.agent            (escalation / action flow)\n"
        "  - the bundled GitLab CI MR triage job  (see docs/GITLAB_CI_SETUP.md)\n"
        "Then verify the captured evidence offline with `reachgate verify`.",
        file=sys.stderr,
    )
    return 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="reachgate",
        description=(
            "ReachGate: offline-verifiable reachability evidence. Scans (live), "
            "explains, exports OpenVEX/SARIF, shows blind spots. Advisory by "
            "default; the deterministic engine decides, the AI only explains."
        ),
    )
    sub = parser.add_subparsers(dest="command", metavar="<command>")

    p_cov = sub.add_parser(
        "coverage",
        help="Coverage / blind-spot report from receipts (offline).",
    )
    p_cov.add_argument(
        "--receipts", nargs="*", default=None,
        help="Receipt JSON files. Defaults to the captured docs/proof receipts.",
    )
    p_cov.add_argument(
        "--format", choices=("text", "json"), default="text",
        help="Output format (default: text).",
    )
    p_cov.set_defaults(func=cmd_coverage)

    p_verify = sub.add_parser(
        "verify", help="Verify captured proof + cross-check OpenVEX/SARIF (offline).")
    p_verify.set_defaults(func=cmd_verify)

    p_vex = sub.add_parser(
        "export-vex", help="Export OpenVEX from receipts (repo checkout).")
    p_vex.add_argument("tool_args", nargs=argparse.REMAINDER,
                       help="Args passed through to tools/export_vex.py.")
    p_vex.set_defaults(func=cmd_export_vex)

    p_sarif = sub.add_parser(
        "export-sarif", help="Export SARIF 2.1.0 from receipts (repo checkout).")
    p_sarif.add_argument("tool_args", nargs=argparse.REMAINDER,
                         help="Args passed through to tools/export_sarif.py.")
    p_sarif.set_defaults(func=cmd_export_sarif)

    p_man = sub.add_parser(
        "manifest", help="Build the sha256 evidence manifest (repo checkout).")
    p_man.add_argument("tool_args", nargs=argparse.REMAINDER,
                       help="Args passed through to tools/build_evidence_manifest.py.")
    p_man.set_defaults(func=cmd_manifest)

    p_proof = sub.add_parser(
        "proof", help="Build the offline judge-proof HTML page (repo checkout).")
    p_proof.add_argument("tool_args", nargs=argparse.REMAINDER,
                         help="Args passed through to tools/build_judge_proof.py.")
    p_proof.set_defaults(func=cmd_proof)

    p_scan = sub.add_parser(
        "scan", help="(live-only) Walk Orbit for findings. Not in the offline CLI.")
    p_scan.add_argument("tool_args", nargs=argparse.REMAINDER, help=argparse.SUPPRESS)
    p_scan.set_defaults(func=cmd_scan)

    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help()
        return 0
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
