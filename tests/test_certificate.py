from src.reachgate.certificate import (
    SearchCertificate,
    compute_fingerprint,
    hash_entrypoint_globs,
)


def _fingerprint(**overrides):
    base = dict(
        occurrence_uuid="demo-ssrf",
        occurrence_name="SSRF",
        severity="high",
        verdict="REACHABLE",
        vulnerable_file="src/services/fetch.js",
        vulnerable_definition="getVersions",
        path=["File:src/a.js", "Definition:getVersions"],
        policy_version="abc123",
        entrypoint_globs_hash="def456",
    )
    base.update(overrides)
    return compute_fingerprint(**base)


def test_fingerprint_is_deterministic():
    assert _fingerprint() == _fingerprint()


def test_fingerprint_changes_with_verdict():
    assert _fingerprint() != _fingerprint(verdict="UNKNOWN")


def test_fingerprint_changes_with_severity():
    # Scanner upgrades severity -> receipt must update, not be skipped.
    assert _fingerprint() != _fingerprint(severity="critical")


def test_fingerprint_changes_with_policy_version():
    assert _fingerprint() != _fingerprint(policy_version="other")


def test_fingerprint_changes_with_attack_surface():
    assert _fingerprint() != _fingerprint(entrypoint_globs_hash="other")


def test_fingerprint_is_short_hex():
    fp = _fingerprint()
    assert len(fp) == 16
    int(fp, 16)  # raises if not hex


def test_globs_hash_is_order_independent():
    assert hash_entrypoint_globs(["a/**", "b/**"]) == hash_entrypoint_globs(["b/**", "a/**"])


def test_globs_hash_changes_with_content():
    assert hash_entrypoint_globs(["a/**"]) != hash_entrypoint_globs(["a/**", "b/**"])


def test_certificate_bounds_hit_property():
    cert = SearchCertificate()
    assert not cert.bounds_hit
    cert.max_hops_hit = True
    assert cert.bounds_hit


def test_certificate_as_dict_round_trip():
    cert = SearchCertificate(
        max_hops=6, max_visited=40, max_seconds=60,
        entrypoints_checked=2, target_definitions_found=30,
        nodes_visited=23, frontier_exhausted=True,
        evidence_modes=["graph_edges"], entrypoint_globs_hash="abc",
    )
    d = cert.as_dict()
    assert d["bounds"] == {"max_hops": 6, "max_visited": 40, "max_seconds": 60}
    assert d["frontier_exhausted"] is True
    assert d["evidence_modes"] == ["graph_edges"]
