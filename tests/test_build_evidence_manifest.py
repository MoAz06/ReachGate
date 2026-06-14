"""The evidence manifest is a faithful, deterministic index of the artifacts.

These tests pin the manifest: it builds, its sha256 values match the real
files on disk, its output is byte-stable across reruns, and a missing artifact
is reported explicitly (present=false, sha256=null) rather than silently
dropped.
"""

import hashlib
import json

from tools import build_evidence_manifest as bem


def test_manifest_builds_and_writes(tmp_path):
    out = tmp_path / "reachgate.evidence-manifest.json"
    assert bem.main(["--output", str(out)]) == 0
    assert out.exists()
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["manifest_version"] == bem.MANIFEST_VERSION
    assert doc["hash_algorithm"] == "sha256"
    assert isinstance(doc["artifacts"], list) and doc["artifacts"]


def test_hashes_match_files_on_disk():
    manifest = bem.build_manifest(repo_commit_sha="pinned")
    for a in manifest["artifacts"]:
        if not a["present"]:
            continue
        path = bem.REPO_ROOT / a["filename"]
        expected = hashlib.sha256(path.read_bytes()).hexdigest()
        assert a["sha256"] == expected, a["filename"]


def test_machine_readable_artifacts_present_and_typed():
    manifest = bem.build_manifest(repo_commit_sha="pinned")
    types = {a["type"] for a in manifest["artifacts"]}
    # Receipts, OpenVEX, and SARIF are all indexed.
    assert "reachability-receipt" in types
    assert "openvex" in types
    assert "sarif" in types


def test_does_not_hash_judge_proof_html():
    """The generated human view must never be in the manifest (no circular
    generated-artifact dependency)."""
    manifest = bem.build_manifest(repo_commit_sha="pinned")
    names = {a["filename"] for a in manifest["artifacts"]}
    assert not any(n.endswith("judge-proof.html") for n in names)


def test_deterministic_output(tmp_path):
    a = tmp_path / "a.json"
    b = tmp_path / "b.json"
    # Pin the commit SHA so the only variable (git state) is removed; the
    # generate() default still resolves it from git in real runs.
    bem.generate(output=a, repo_commit_sha="deadbeef")
    bem.generate(output=b, repo_commit_sha="deadbeef")
    assert a.read_bytes() == b.read_bytes()


def test_build_manifest_is_stable_in_memory():
    one = bem.build_manifest(repo_commit_sha="x")
    two = bem.build_manifest(repo_commit_sha="x")
    assert json.dumps(one, sort_keys=True) == json.dumps(two, sort_keys=True)


def test_policy_versions_come_from_receipts():
    manifest = bem.build_manifest(repo_commit_sha="x")
    # The captured receipts are policy 8eae9f21a3e6; never invented.
    assert manifest["policy_versions"] == ["8eae9f21a3e6"]


def test_missing_artifact_is_explicit(tmp_path, monkeypatch):
    """A missing artifact is reported, not silently dropped."""
    ghost = tmp_path / "does-not-exist.json"
    fake_artifacts = (
        {
            "path": ghost,
            "type": "sarif",
            "generation_command": "python tools/export_sarif.py",
            "verifier_command": "python tools/verify_proof.py",
        },
    )
    monkeypatch.setattr(bem, "ARTIFACTS", fake_artifacts)
    manifest = bem.build_manifest(repo_commit_sha="x")
    assert manifest["missing_count"] == 1
    entry = manifest["artifacts"][0]
    assert entry["present"] is False
    assert entry["sha256"] is None


def test_sha256_file_returns_none_for_missing(tmp_path):
    assert bem.sha256_file(tmp_path / "nope.json") is None


def test_repo_commit_sha_absent_is_not_fatal(monkeypatch, tmp_path):
    """Outside git, the manifest still builds with repo_commit_sha = null."""
    monkeypatch.setattr(bem, "_repo_commit_sha", lambda: None)
    out = tmp_path / "m.json"
    assert bem.main(["--output", str(out)]) == 0
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["repo_commit_sha"] is None
