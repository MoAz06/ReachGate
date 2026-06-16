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
    from . import _resources

    if args.receipts:
        sources = [Path(p) for p in args.receipts]
    else:
        # Default to the captured receipts: docs/proof in a checkout, the
        # bundled package-data copy after a bare install. Works standalone.
        proof = _resources.proof_dir()
        sources = [
            proof / "mr2-reachgate-receipts.json",
            proof / "unknown-reachgate-receipt.json",
        ]

    try:
        report = coverage_mod.build_coverage(sources)
    except coverage_mod.CoverageError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if args.format == "json":
        rendered = json.dumps(coverage_mod.render_json(report), indent=2, ensure_ascii=False) + "\n"
    elif args.format == "html":
        rendered = coverage_mod.render_html(report)
    else:
        rendered = coverage_mod.render_text(report)

    if args.output:
        out = Path(args.output)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(rendered, encoding="utf-8")
        print(f"wrote {out}")
    else:
        print(rendered, end="")
    return 0


# --- package-native offline commands (work standalone) ---------------------

# These used to delegate to tools/*.py and require a repo checkout. The logic
# now lives in the package (reachgate.export_vex, .export_sarif,
# .build_evidence_manifest, .build_judge_proof, .verify_proof), so they run
# after a bare `pip install`: their default sources resolve via
# reachgate._resources (the bundled receipts when there is no checkout).


def cmd_verify(args) -> int:
    # verify_proof.main() takes no argv; it resolves the proof dir itself.
    from . import verify_proof
    return int(verify_proof.main() or 0)


def _tool_argv(args) -> list[str]:
    """Build the argv passed to a delegated tool.

    Maps the CLI's own ``--output`` to the tool's ``--output`` and forwards any
    extra pass-through ``tool_args`` after it. The tools all accept ``--output``,
    so a temp/explicit output path works without writing the tracked defaults.
    """
    argv: list[str] = []
    if getattr(args, "output", None):
        argv += ["--output", args.output]
    argv += list(getattr(args, "tool_args", None) or [])
    return argv


def cmd_export_vex(args) -> int:
    from . import export_vex
    return int(export_vex.main(_tool_argv(args)) or 0)


def cmd_export_sarif(args) -> int:
    from . import export_sarif
    return int(export_sarif.main(_tool_argv(args)) or 0)


def cmd_manifest(args) -> int:
    from . import build_evidence_manifest
    return int(build_evidence_manifest.main(_tool_argv(args)) or 0)


def cmd_proof(args) -> int:
    from . import build_judge_proof
    return int(build_judge_proof.main(_tool_argv(args)) or 0)


def cmd_capsule(args) -> int:
    command = args.capsule_command
    if command == "build":
        return _capsule_build(args)
    if command == "keygen":
        return _capsule_keygen(args)
    if command == "sign":
        return _capsule_sign(args)
    if command == "verify":
        return _capsule_verify(args)
    print("error: unknown capsule command (build | keygen | sign | verify)",
          file=sys.stderr)
    return 2


def _capsule_build(args) -> int:
    from . import capsule as capsule_mod

    try:
        root = _require_repo()
    except _RepoUnavailable as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    output = Path(args.output) if args.output else root / "dist" / capsule_mod.DEFAULT_CAPSULE_NAME
    try:
        summary = capsule_mod.build_capsule(
            root, output, regenerate=not args.no_regenerate
        )
    except capsule_mod.CapsuleError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(f"wrote {summary['output']} ({summary['member_count']} members)")
    for arc in summary["included"]:
        print(f"  + {arc}")
    for arc in summary["skipped"]:
        print(f"  - skipped (absent): {arc}")
    print("This capsule is generated and untracked (dist/ is gitignored).")
    return 0


def _capsule_keygen(args) -> int:
    """Generate an Ed25519 keypair for signing capsules."""
    from . import signing

    out_dir = Path(args.out_dir) if args.out_dir else Path.cwd()
    try:
        private_pem, public_pem = signing.generate_keypair()
    except signing.SigningError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    out_dir.mkdir(parents=True, exist_ok=True)
    key_path = out_dir / "reachgate-signing.key"
    pub_path = out_dir / "reachgate-signing.pub"
    key_path.write_bytes(private_pem)
    pub_path.write_bytes(public_pem)
    print(f"wrote private key: {key_path}")
    print(f"wrote public key:  {pub_path}")
    print("KEEP THE PRIVATE KEY SECRET. Publish only the .pub so others can "
          "verify your signed capsules.")
    return 0


def _default_capsule_path(args) -> Path | None:
    """Resolve the capsule the sign/verify command operates on."""
    if getattr(args, "target", None):
        return Path(args.target)
    from . import capsule as capsule_mod
    root = _find_repo_root()
    if root is not None:
        return root / "dist" / capsule_mod.DEFAULT_CAPSULE_NAME
    return None


def _capsule_sign(args) -> int:
    from . import signing

    target = _default_capsule_path(args)
    if target is None:
        print("error: no capsule given. Pass the capsule path: "
              "reachgate capsule sign <capsule.zip> --key <private.key>",
              file=sys.stderr)
        return 2
    if not args.key:
        print("error: --key <private.key> is required to sign", file=sys.stderr)
        return 2
    try:
        private_pem = Path(args.key).read_bytes()
    except FileNotFoundError:
        print(f"error: private key not found: {args.key}", file=sys.stderr)
        return 2
    sig_path = Path(args.output) if args.output else target.with_name(target.name + ".sig")
    try:
        signing.sign_file(target, private_pem, sig_path)
        # Emit the public key sidecar for the verifier's convenience. Trust
        # still comes from the public key being published out-of-band, not from
        # this copy; it is only there to make verification one command.
        public_pem = signing.public_from_private(private_pem)
        pub_path = target.with_name(target.name + ".pub")
        pub_path.write_bytes(public_pem)
    except signing.SigningError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(f"signed {target}")
    print(f"  signature:  {sig_path}")
    print(f"  public key: {pub_path}")
    print("Verify with: reachgate capsule verify "
          f"{target.name} --sig {sig_path.name} --pubkey {pub_path.name}")
    return 0


def _capsule_verify(args) -> int:
    from . import signing

    target = _default_capsule_path(args)
    if target is None:
        print("error: no capsule given. Pass the capsule path: "
              "reachgate capsule verify <capsule.zip> --pubkey <key.pub>",
              file=sys.stderr)
        return 2
    sig_path = Path(args.sig) if args.sig else target.with_name(target.name + ".sig")
    pub_arg = args.pubkey or str(target.with_name(target.name + ".pub"))
    try:
        public_pem = Path(pub_arg).read_bytes()
    except FileNotFoundError:
        print(f"error: public key not found: {pub_arg}", file=sys.stderr)
        return 2
    try:
        ok = signing.verify_file(target, public_pem, sig_path)
    except signing.SigningError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if ok:
        print(f"OK: signature valid for {target}")
        print("The capsule is authentic and unmodified (Ed25519, byte-exact).")
        return 0
    print(f"FAIL: signature does NOT match {target}", file=sys.stderr)
    print("The capsule was modified, or signed with a different key.",
          file=sys.stderr)
    return 1


def cmd_judge(args) -> int:
    """One-command judge demo: verify -> exports -> manifest -> proof page.

    Pure orchestration of the existing offline commands; prints each step and
    ends with the path to the judge-proof HTML (it never opens a browser).
    """
    try:
        root = _require_repo()
    except _RepoUnavailable as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    from . import (
        verify_proof,
        export_vex,
        export_sarif,
        build_evidence_manifest,
        build_judge_proof,
    )
    steps = [
        ("Verifying receipts + cross-checking OpenVEX/SARIF", verify_proof, None),
        ("Exporting OpenVEX (CVE/SCA)", export_vex, []),
        ("Exporting SARIF 2.1.0 (SAST/code-flow)", export_sarif, []),
        ("Building sha256 evidence manifest", build_evidence_manifest, []),
        ("Building offline judge-proof HTML", build_judge_proof, []),
    ]
    for i, (label, module, argv) in enumerate(steps, 1):
        print(f"{i}. {label}...")
        rc = int(module.main() or 0) if argv is None else int(module.main(argv) or 0)
        if rc != 0:
            print(f"   step failed (exit {rc})", file=sys.stderr)
            return rc

    proof_path = root / "docs" / "judge-proof.html"
    print(f"{len(steps) + 1}. Done. Open the judge proof in a browser:")
    print(f"   {proof_path}")
    print("   (no browser is opened automatically; verify offline with "
          "`reachgate verify`)")
    return 0


def cmd_policy(args) -> int:
    if args.policy_command != "explain":
        print("error: unknown policy command (try `reachgate policy explain`)",
              file=sys.stderr)
        return 2
    from . import coverage as coverage_mod  # reuse its loader (CoverageError)

    # Resolve a receipt to read the policy from.
    if args.receipt:
        receipt_path = Path(args.receipt)
    else:
        root = _find_repo_root()
        if root is None:
            print(
                "error: no --receipt given and no repo checkout found.\n"
                "  Pass a receipt: reachgate policy explain --receipt <file.json>",
                file=sys.stderr,
            )
            return 2
        receipt_path = root / "docs" / "proof" / "mr2-reachgate-receipts.json"

    import json as _json
    try:
        data = _json.loads(receipt_path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        print(f"error: {receipt_path.name}: file not found", file=sys.stderr)
        return 1
    except _json.JSONDecodeError as exc:
        print(f"error: {receipt_path.name}: invalid JSON ({exc})", file=sys.stderr)
        return 1

    policy = data.get("policy")
    if not isinstance(policy, dict):
        print(f"error: {receipt_path.name}: no policy block in receipt",
              file=sys.stderr)
        return 1

    print("ReachGate policy (from receipt)")
    print(f"  source receipt: {receipt_path.name}")
    print(f"  policy version: {policy.get('version', 'n/a')}")
    print(f"  REACHABLE threshold: {policy.get('threshold', 'n/a')}")
    rules = policy.get("rules") or []
    if rules:
        print("  rules (weights from the receipt's recorded policy):")
        for rule in rules:
            print(f"    +{rule.get('weight', '?')} {rule.get('name', '?')}")
    # Search bounds are recorded per-finding in the certificate, not in the
    # policy block -- be explicit about provenance instead of overclaiming.
    bounds = None
    for finding in data.get("findings") or []:
        cert = finding.get("certificate") or {}
        if isinstance(cert.get("bounds"), dict):
            bounds = cert["bounds"]
            break
    if bounds:
        print("  search bounds (from a finding certificate in this receipt):")
        for key in ("max_hops", "max_visited", "max_seconds"):
            if key in bounds:
                print(f"    {key} = {bounds[key]}")
    print("")
    print("Provenance: version, threshold, and rule weights above are read "
          "directly from the receipt's recorded policy block. Search bounds "
          "are read from a finding's certificate in the same receipt. Values "
          "not present in the receipt are shown as n/a rather than guessed; "
          "the live engine/config may differ if it has since changed.")
    return 0


def cmd_fixcheck(args) -> int:
    """Compare two receipt artifacts and prove the reachability delta.

    A derived, offline layer over existing receipts: it never re-decides a
    verdict and never calls GitLab/Orbit. By default it writes nothing to the
    tracked proof artifacts; output goes to stdout unless --output is given.
    """
    from . import fixproof as fixproof_mod

    try:
        proof = fixproof_mod.fixcheck(args.before, args.after)
    except fixproof_mod.FixProofError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.format == "json":
        rendered = fixproof_mod.render_json(proof)
    elif args.format == "markdown":
        rendered = fixproof_mod.render_markdown(
            proof, before_path=args.before, after_path=args.after
        )
    else:
        rendered = fixproof_mod.render_text(proof)

    if args.output:
        out = Path(args.output)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(rendered, encoding="utf-8")
        print(f"wrote {out}")
    else:
        print(rendered, end="")
    return 0


def cmd_contract_check(args) -> int:
    """Validate receipt artifacts against the Evidence Contract (offline).

    Makes docs/EVIDENCE_CONTRACT.md enforceable: it checks that the claims a
    receipt already carries are allowed by the contract. It never re-decides a
    verdict and never calls GitLab/Orbit. Exit code is non-zero only when a
    receipt overclaims (contract FAIL); warnings alone exit 0.
    """
    from . import contract_check as cc

    overall_fail = False
    chunks: list[str] = []
    multi = len(args.receipts) > 1
    for path in args.receipts:
        try:
            result = cc.check_file(path)
        except cc.ContractCheckError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

        if result.overall == cc.FAIL:
            overall_fail = True

        if args.format == "json":
            chunks.append(cc.render_json(result))
        elif args.format == "markdown":
            chunks.append(cc.render_markdown(result, source=path))
        else:
            chunks.append(cc.render_text(result, source=path))

    rendered = ("\n" if multi else "").join(chunks)

    if args.output:
        out = Path(args.output)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(rendered, encoding="utf-8")
        print(f"wrote {out}")
    else:
        print(rendered, end="")

    return 1 if overall_fail else 0


def cmd_selftest(args) -> int:
    """Adversarial self-proof of the safety invariants (exit non-zero on breach)."""
    from . import selftest
    argv: list[str] = ["--format", args.format]
    if args.output:
        argv += ["--output", args.output]
    return int(selftest.main(argv))


def cmd_explorer(args) -> int:
    """Generate a self-contained, offline evidence explorer HTML page."""
    from . import explorer
    return int(explorer.main(["--output", args.output] if args.output else []) or 0)


def cmd_blame(args) -> int:
    """Report which changed files lie on a finding's reachable path (overlap)."""
    from . import blame as blame_mod

    argv: list[str] = [args.receipt]
    if args.changed_files is not None:
        argv += ["--changed-files", *args.changed_files]
    if args.base is not None:
        argv += ["--base", args.base, "--head", args.head]
    if args.repo:
        argv += ["--repo", args.repo]
    argv += ["--format", args.format]
    if args.output:
        argv += ["--output", args.output]
    return int(blame_mod.main(argv) or 0)


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
        "--format", choices=("text", "json", "html"), default="text",
        help="Output format (default: text).",
    )
    p_cov.add_argument(
        "--output", default=None,
        help="Write to a file instead of stdout (recommended for html).",
    )
    p_cov.set_defaults(func=cmd_coverage)

    p_verify = sub.add_parser(
        "verify", help="Verify captured proof + cross-check OpenVEX/SARIF (offline).")
    p_verify.set_defaults(func=cmd_verify)

    p_vex = sub.add_parser(
        "export-vex", help="Export OpenVEX from receipts (repo checkout).")
    p_vex.add_argument("--output", default=None,
                       help="Output path (default: docs/proof/reachgate.openvex.json).")
    p_vex.add_argument("tool_args", nargs=argparse.REMAINDER,
                       help="Extra args passed through to tools/export_vex.py.")
    p_vex.set_defaults(func=cmd_export_vex)

    p_sarif = sub.add_parser(
        "export-sarif", help="Export SARIF 2.1.0 from receipts (repo checkout).")
    p_sarif.add_argument("--output", default=None,
                         help="Output path (default: docs/proof/reachgate.sarif.json).")
    p_sarif.add_argument("tool_args", nargs=argparse.REMAINDER,
                         help="Extra args passed through to tools/export_sarif.py.")
    p_sarif.set_defaults(func=cmd_export_sarif)

    p_man = sub.add_parser(
        "manifest", help="Build the sha256 evidence manifest (repo checkout).")
    p_man.add_argument("--output", default=None,
                       help="Output path (default: docs/proof/reachgate.evidence-manifest.json).")
    p_man.add_argument("tool_args", nargs=argparse.REMAINDER,
                       help="Extra args passed through to tools/build_evidence_manifest.py.")
    p_man.set_defaults(func=cmd_manifest)

    p_proof = sub.add_parser(
        "proof", help="Build the offline judge-proof HTML page (repo checkout).")
    p_proof.add_argument("--output", default=None,
                         help="Output path (default: docs/judge-proof.html).")
    p_proof.add_argument("tool_args", nargs=argparse.REMAINDER,
                         help="Extra args passed through to tools/build_judge_proof.py.")
    p_proof.set_defaults(func=cmd_proof)

    p_cap = sub.add_parser(
        "capsule",
        help="Build / sign / verify a portable, offline-verifiable evidence "
             "capsule (zip).")
    p_cap.add_argument(
        "capsule_command", choices=("build", "keygen", "sign", "verify"),
        metavar="{build,keygen,sign,verify}",
        help="build a capsule, generate a signing keypair, sign a capsule, or "
             "verify a signed capsule.")
    p_cap.add_argument("target", nargs="?", default=None,
                       help="Capsule path for sign/verify "
                            "(default: dist/reachgate-evidence-capsule.zip).")
    p_cap.add_argument("--output", default=None,
                       help="build: output zip path; sign: signature output path.")
    p_cap.add_argument("--no-regenerate", action="store_true",
                       help="build: bundle artifacts as-is instead of rebuilding "
                            "them from receipts.")
    p_cap.add_argument("--out-dir", default=None,
                       help="keygen: directory to write the keypair into "
                            "(default: current directory).")
    p_cap.add_argument("--key", default=None,
                       help="sign: path to the Ed25519 private key (PEM).")
    p_cap.add_argument("--pubkey", default=None,
                       help="verify: path to the Ed25519 public key (PEM); "
                            "defaults to <capsule>.pub.")
    p_cap.add_argument("--sig", default=None,
                       help="verify: path to the detached signature; "
                            "defaults to <capsule>.sig.")
    p_cap.set_defaults(func=cmd_capsule)

    p_judge = sub.add_parser(
        "judge",
        help="One-command judge demo: verify -> exports -> manifest -> proof.")
    p_judge.set_defaults(func=cmd_judge)

    p_pol = sub.add_parser(
        "policy", help="Inspect the recorded policy (read-only).")
    p_pol.add_argument("policy_command", choices=("explain",), metavar="explain",
                       help="Policy sub-command (currently: explain).")
    p_pol.add_argument("--receipt", default=None,
                       help="Receipt JSON to read the policy from "
                            "(default: the captured MR !2 receipt).")
    p_pol.set_defaults(func=cmd_policy)

    p_fix = sub.add_parser(
        "fixcheck",
        help="Compare two receipt artifacts; prove if reachability was "
             "removed/introduced/unchanged (offline).",
    )
    p_fix.add_argument("before", help="path to the BEFORE receipts JSON")
    p_fix.add_argument("after", help="path to the AFTER receipts JSON")
    p_fix.add_argument(
        "--format", choices=("text", "json", "markdown"), default="text",
        help="Output format (default: text). markdown is MR-comment ready.",
    )
    p_fix.add_argument(
        "--output", default=None,
        help="Write to a file instead of stdout (writes no tracked artifact by default).",
    )
    p_fix.set_defaults(func=cmd_fixcheck)

    p_cc = sub.add_parser(
        "contract-check",
        help="Validate receipt artifacts against the Evidence Contract (offline).",
    )
    p_cc.add_argument("receipts", nargs="+",
                      help="one or more receipt JSON files to validate")
    p_cc.add_argument(
        "--format", choices=("text", "json", "markdown"), default="text",
        help="Output format (default: text).",
    )
    p_cc.add_argument(
        "--output", default=None,
        help="Write to a file instead of stdout (writes no tracked artifact by default).",
    )
    p_cc.set_defaults(func=cmd_contract_check)

    p_self = sub.add_parser(
        "selftest",
        help="Adversarial self-proof: reproduce the safety invariants offline "
             "(exits non-zero if any invariant is violated).")
    p_self.add_argument("--format", choices=("text", "json"), default="text",
                        help="output format (default: text).")
    p_self.add_argument("--output", default=None,
                        help="write the report to a file instead of stdout.")
    p_self.set_defaults(func=cmd_selftest)

    p_expl = sub.add_parser(
        "explorer",
        help="Generate a self-contained, offline evidence explorer (HTML).")
    p_expl.add_argument("--output", default=None,
                        help="output HTML path (default: reachgate-explorer.html).")
    p_expl.set_defaults(func=cmd_explorer)

    p_blame = sub.add_parser(
        "blame",
        help="Which changed files lie on a finding's reachable path "
             "(deterministic overlap; never a causation claim).",
    )
    p_blame.add_argument("receipt", help="path to a ReachGate receipt JSON")
    p_blame.add_argument(
        "--changed-files", nargs="*", default=None,
        help="explicit list of changed files (from the receipt's repository).")
    p_blame.add_argument(
        "--base", default=None,
        help="git base ref; with --head, changed files = git diff base..head.")
    p_blame.add_argument(
        "--head", default="HEAD",
        help="git head ref (default: HEAD); used with --base.")
    p_blame.add_argument(
        "--repo", default=None,
        help="run git in this directory (default: current directory).")
    p_blame.add_argument(
        "--format", choices=("text", "json", "markdown"), default="text",
        help="output format (default: text).")
    p_blame.add_argument(
        "--output", default=None, help="write to a file instead of stdout.")
    p_blame.set_defaults(func=cmd_blame)

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
