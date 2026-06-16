"""Build an evidence manifest for ReachGate's machine-readable artifacts.

ReachGate emits replayable reachability evidence: per-finding receipts, an
OpenVEX (SCA) document, and a SARIF (SAST/code-flow) document. This tool ties
those artifacts together with content hashes so a reviewer -- or a downstream
pipeline -- can confirm offline that the evidence they are looking at is the
exact evidence ReachGate produced, and re-derive it from the recorded commands.

What it hashes (machine-readable artifacts only):
  * the receipt JSON files under docs/proof/ (MR !2, MR !3 rerun, UNKNOWN),
  * the OpenVEX JSON,
  * the SARIF JSON.

What it deliberately does NOT hash:
  * docs/judge-proof.html -- that page is itself generated from these same
    artifacts, so hashing it here would create a circular generated-artifact
    dependency (regenerate the page -> manifest changes -> page changes ...).
    The HTML is a human view, not a source of evidence.

Honesty / determinism rules:
  * Output is deterministic: artifacts in a fixed order, sha256 over exact
    file bytes, no wall-clock timestamp in the document.
  * A missing artifact is reported explicitly (present=false, sha256=null)
    rather than silently dropped, so a gap in the evidence set is visible.
  * The repo commit SHA is recorded when git is available, but its absence is
    never fatal -- the manifest still builds outside a git checkout.

Packaging note:
  Canonical home of the manifest builder; ``tools/build_evidence_manifest.py``
  is a thin shim re-exporting from here. ``REPO_ROOT`` / ``PROOF_DIR`` resolve
  via :mod:`reachgate._resources` (the checkout in a repo, the bundled
  package-data copy otherwise).

Standard library only. No network, no token, no dependencies.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

from . import _resources

REPO_ROOT = _resources.repo_root() or Path(__file__).resolve().parents[2]
PROOF_DIR = _resources.proof_dir()

MANIFEST_VERSION = "1.0"
DEFAULT_OUTPUT = PROOF_DIR / "reachgate.evidence-manifest.json"

# Fixed, ordered set of machine-readable artifacts. Each entry pins the file,
# its evidence type, and the exact commands that produce and verify it, so the
# manifest doubles as a replay recipe. judge-proof.html is intentionally absent
# (see module docstring: it is a generated human view, not evidence).
ARTIFACTS = (
    {
        "path": PROOF_DIR / "mr2-reachgate-receipts.json",
        "type": "reachability-receipt",
        "generation_command": "see docs/JUDGE_REPLAY.md (captured from MR !2)",
        "verifier_command": "python tools/verify_proof.py",
    },
    {
        "path": PROOF_DIR / "mr3-reachgate-receipts-rerun.json",
        "type": "reachability-receipt",
        "generation_command": "see docs/JUDGE_REPLAY.md (captured from MR !3 rerun)",
        "verifier_command": "python tools/verify_proof.py",
    },
    {
        "path": PROOF_DIR / "unknown-reachgate-receipt.json",
        "type": "reachability-receipt",
        "generation_command": "see docs/JUDGE_REPLAY.md (captured UNKNOWN receipt)",
        "verifier_command": "python tools/verify_proof.py",
    },
    {
        "path": PROOF_DIR / "reachgate.openvex.json",
        "type": "openvex",
        "generation_command": "python tools/export_vex.py",
        "verifier_command": "python tools/verify_proof.py",
    },
    {
        "path": PROOF_DIR / "reachgate.sarif.json",
        "type": "sarif",
        "generation_command": "python tools/export_sarif.py",
        "verifier_command": "python tools/verify_proof.py",
    },
)


class ManifestError(ValueError):
    """Raised when the manifest cannot be built."""


def sha256_file(path: Path) -> str | None:
    """sha256 over the exact file bytes, or None if the file is absent."""
    try:
        data = Path(path).read_bytes()
    except FileNotFoundError:
        return None
    return hashlib.sha256(data).hexdigest()


def _rel(path: Path) -> str:
    """POSIX-style path relative to the repo root for stable output."""
    try:
        return Path(path).resolve().relative_to(REPO_ROOT).as_posix()
    except ValueError:
        return Path(path).name


def _policy_versions() -> list[str]:
    """Distinct policy versions referenced by the receipt artifacts, sorted.

    Read from the existing receipts only; never invented. A receipt that is
    absent or malformed simply contributes nothing here.
    """
    versions: set[str] = set()
    for entry in ARTIFACTS:
        if entry["type"] != "reachability-receipt":
            continue
        try:
            data = json.loads(Path(entry["path"]).read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError):
            continue
        version = (data.get("policy") or {}).get("version")
        if isinstance(version, str) and version:
            versions.add(version)
    return sorted(versions)


def _repo_commit_sha() -> str | None:
    """Current commit SHA when git is available, else None (never fatal)."""
    try:
        out = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if out.returncode != 0:
        return None
    sha = out.stdout.strip()
    return sha or None


def build_manifest(*, repo_commit_sha: str | None = None) -> dict:
    """Build the evidence manifest (deterministic, no wall-clock timestamp).

    ``repo_commit_sha`` is injectable so tests can pin it; by default it is
    resolved from git when available.
    """
    if repo_commit_sha is None:
        repo_commit_sha = _repo_commit_sha()

    artifacts = []
    missing = 0
    for entry in ARTIFACTS:
        path = Path(entry["path"])
        digest = sha256_file(path)
        present = digest is not None
        if not present:
            missing += 1
        artifacts.append(
            {
                "filename": _rel(path),
                "type": entry["type"],
                "present": present,
                "sha256": digest,
                "generation_command": entry["generation_command"],
                "verifier_command": entry["verifier_command"],
            }
        )

    return {
        "manifest_version": MANIFEST_VERSION,
        "description": (
            "sha256 over ReachGate's machine-readable evidence artifacts "
            "(receipts, OpenVEX, SARIF). Standards-aligned, offline-verifiable. "
            "Excludes generated human views (e.g. judge-proof.html)."
        ),
        "repo_commit_sha": repo_commit_sha,
        "policy_versions": _policy_versions(),
        "hash_algorithm": "sha256",
        "artifact_count": len(artifacts),
        "missing_count": missing,
        "artifacts": artifacts,
    }


def generate(output: Path = DEFAULT_OUTPUT, *,
             repo_commit_sha: str | None = None) -> dict:
    manifest = build_manifest(repo_commit_sha=repo_commit_sha)
    out = Path(output)
    out.parent.mkdir(parents=True, exist_ok=True)
    tmp = out.with_name(f".{out.name}.tmp")
    tmp.write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    tmp.replace(out)
    return manifest


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Build the ReachGate evidence manifest.",
    )
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT),
                        help="Output manifest JSON path.")
    args = parser.parse_args(argv)
    try:
        manifest = generate(output=Path(args.output))
    except ManifestError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    present = manifest["artifact_count"] - manifest["missing_count"]
    print(
        f"wrote {args.output} "
        f"({present}/{manifest['artifact_count']} artifacts hashed"
        + (f", {manifest['missing_count']} missing" if manifest["missing_count"] else "")
        + ")"
    )
    if manifest["missing_count"]:
        for a in manifest["artifacts"]:
            if not a["present"]:
                print(f"  ! missing: {a['filename']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
