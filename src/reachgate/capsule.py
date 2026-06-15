"""Build a portable ReachGate evidence capsule.

Most scanners output findings. ReachGate outputs a portable, offline-verifiable
evidence capsule: the receipts (source of truth), the OpenVEX and SARIF exports
derived from them, the sha256 evidence manifest, the human-readable judge proof
and judge pack, the offline verifier, and a HOW_TO_VERIFY.txt telling a reviewer
exactly how to check it all with no token and no network.

A judge can take the capsule away and verify the evidence offline, on their own
machine, against the hashes in the manifest. That is the whole point: the
verdict is not "trust us", it is "here is the evidence, and here is how to check
it yourself".

Determinism:
  The zip is written with sorted entries and a fixed timestamp, so building the
  capsule twice from the same artifacts yields a byte-identical archive.

Honesty / hard rules carried here:
  * The capsule only *bundles* existing artifacts; it never re-decides anything.
  * The machine-readable artifacts are (re)generated from the receipts via the
    existing tools, so the capsule is always fresh and self-consistent.
  * docs/judge-proof.html is included as a human view but stays OUTSIDE the
    evidence-manifest hashes (no circular generated-artifact dependency).

Standard library only. No network, no token, no dependencies.
"""

from __future__ import annotations

import zipfile
from dataclasses import dataclass
from pathlib import Path

# Fixed timestamp for every zip entry -> deterministic, byte-stable archives.
# (1980-01-01 00:00:00 is the minimum a ZIP DOS timestamp can represent.)
_FIXED_ZIP_TIME = (1980, 1, 1, 0, 0, 0)

DEFAULT_CAPSULE_NAME = "reachgate-evidence-capsule.zip"


class CapsuleError(RuntimeError):
    """Raised when the capsule cannot be assembled."""


@dataclass(frozen=True)
class CapsuleMember:
    """One file to place in the capsule.

    ``arcname`` is the path inside the zip. ``required`` members must exist or
    the build fails loudly; optional members are skipped with a note.
    """

    source: Path
    arcname: str
    required: bool = True


def _members(root: Path) -> list[CapsuleMember]:
    """The fixed, ordered manifest of what goes into the capsule.

    Machine-readable evidence first (the falsifiable core), then the human
    views, then the verifier and the how-to. Order is stable for determinism.
    """
    proof = root / "docs" / "proof"
    return [
        # --- machine-readable evidence (the source of truth + exports) ---
        CapsuleMember(proof / "mr2-reachgate-receipts.json",
                      "proof/mr2-reachgate-receipts.json"),
        CapsuleMember(proof / "mr3-reachgate-receipts-rerun.json",
                      "proof/mr3-reachgate-receipts-rerun.json"),
        CapsuleMember(proof / "unknown-reachgate-receipt.json",
                      "proof/unknown-reachgate-receipt.json"),
        CapsuleMember(proof / "reachgate.openvex.json",
                      "proof/reachgate.openvex.json"),
        CapsuleMember(proof / "reachgate.sarif.json",
                      "proof/reachgate.sarif.json"),
        CapsuleMember(proof / "reachgate.evidence-manifest.json",
                      "proof/reachgate.evidence-manifest.json"),
        # --- human views (NOT hashed in the manifest) ---
        CapsuleMember(root / "docs" / "judge-proof.html",
                      "judge-proof.html"),
        CapsuleMember(root / "docs" / "JUDGE_PACK.md",
                      "JUDGE_PACK.md"),
        CapsuleMember(root / "docs" / "JUDGE_REPLAY.md",
                      "JUDGE_REPLAY.md", required=False),
        # --- the offline verifier so the capsule is self-checking ---
        CapsuleMember(root / "tools" / "verify_proof.py",
                      "verify/verify_proof.py"),
        CapsuleMember(root / "tools" / "export_vex.py",
                      "verify/export_vex.py", required=False),
        CapsuleMember(root / "tools" / "export_sarif.py",
                      "verify/export_sarif.py", required=False),
    ]


HOW_TO_VERIFY = """\
ReachGate evidence capsule -- how to verify, offline
====================================================

This capsule is a portable, offline-verifiable package of reachability
evidence. You do NOT need a GitLab token or network access to check it.

What is inside
--------------
  proof/                          machine-readable evidence
    *-reachgate-receipts.json     the receipts (ReachGate's source of truth)
    unknown-reachgate-receipt.json the honest UNKNOWN verdict
    reachgate.openvex.json        OpenVEX (CVE/SCA), derived from the receipts
    reachgate.sarif.json          SARIF 2.1.0 (SAST/code-flow), derived likewise
    reachgate.evidence-manifest.json  sha256 over the machine-readable files
  judge-proof.html                human-readable case file (open in a browser)
  JUDGE_PACK.md / JUDGE_REPLAY.md guided walkthrough for reviewers
  verify/                         the offline verifier (standard library only)

How to verify the hashes
------------------------
The manifest lists a sha256 for each machine-readable artifact. Confirm any of
them on your own machine, for example:

  python -c "import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],'rb').read()).hexdigest())" proof/reachgate.sarif.json

then compare it against the value in proof/reachgate.evidence-manifest.json.

Note: judge-proof.html is a generated human view of the same artifacts and is
deliberately NOT hashed in the manifest (hashing a file generated from the
hashed files would be circular).

How to verify the evidence (from a full repo checkout)
------------------------------------------------------
The verifier in verify/ cross-checks the OpenVEX and SARIF back against the
receipts. It is designed to run from a ReachGate repo checkout (it imports the
export modules). From a checkout:

  python tools/verify_proof.py      # or: reachgate verify

It verifies the captured artifacts offline and exits 0 on success.

What the verdicts mean (honest by design)
-----------------------------------------
  REACHABLE       a graph path reaches the vulnerable code -> escalate.
  NOT_REACHABLE   exhausted within the CONFIGURED search bounds -> deprioritize.
                  This is bounded, not a global safety claim.
  UNKNOWN         insufficient evidence -> review. Never presented as safe.

ReachGate is advisory by default and standards-aligned. It is not a certified
gate, and NOT_REACHABLE is scoped to the configured bounds. The deterministic
engine decides; the AI only explains.
"""


def _regenerate_artifacts(root: Path) -> None:
    """Rebuild the derived artifacts from the receipts so the capsule is fresh.

    Loads the existing tools by file path (package-safe) and runs each one. The
    receipts themselves are never written. Raises CapsuleError on any failure.
    """
    from .cli import _load_tool  # local import to avoid a cycle at module load

    try:
        export_vex = _load_tool(root, "export_vex")
        export_sarif = _load_tool(root, "export_sarif")
        build_manifest = _load_tool(root, "build_evidence_manifest")
        build_proof = _load_tool(root, "build_judge_proof")
    except Exception as exc:  # _RepoUnavailable or import failure
        raise CapsuleError(f"could not load build tools: {exc}") from exc

    # VEX and SARIF first (the manifest hashes them), then the manifest, then
    # the human proof page (not hashed). Each tool writes to docs/proof or docs.
    for name, tool in (
        ("export_vex", export_vex),
        ("export_sarif", export_sarif),
        ("build_evidence_manifest", build_manifest),
        ("build_judge_proof", build_proof),
    ):
        rc = int(tool.main([]) or 0)
        if rc != 0:
            raise CapsuleError(f"{name} failed (exit {rc})")


def build_capsule(root: Path, output: Path, *, regenerate: bool = True) -> dict:
    """Assemble the evidence capsule zip. Returns a summary dict.

    ``regenerate`` rebuilds the derived artifacts from the receipts first, so
    the capsule always reflects the current receipts. Set False to bundle the
    artifacts exactly as they are on disk.
    """
    root = Path(root)
    if regenerate:
        _regenerate_artifacts(root)

    members = _members(root)
    missing_required = [m.arcname for m in members
                        if m.required and not m.source.is_file()]
    if missing_required:
        raise CapsuleError(
            "missing required artifact(s): " + ", ".join(missing_required)
            + ". Run `reachgate judge` or the export tools first."
        )

    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    tmp = output.with_name(f".{output.name}.tmp")

    included: list[str] = []
    skipped: list[str] = []
    with zipfile.ZipFile(tmp, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for member in members:
            if not member.source.is_file():
                skipped.append(member.arcname)
                continue
            info = zipfile.ZipInfo(member.arcname, date_time=_FIXED_ZIP_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            zf.writestr(info, member.source.read_bytes())
            included.append(member.arcname)
        # The how-to is generated text, written deterministically.
        info = zipfile.ZipInfo("HOW_TO_VERIFY.txt", date_time=_FIXED_ZIP_TIME)
        info.compress_type = zipfile.ZIP_DEFLATED
        info.external_attr = 0o644 << 16
        zf.writestr(info, HOW_TO_VERIFY.encode("utf-8"))
        included.append("HOW_TO_VERIFY.txt")

    tmp.replace(output)
    return {
        "output": str(output),
        "included": included,
        "skipped": skipped,
        "member_count": len(included),
    }
