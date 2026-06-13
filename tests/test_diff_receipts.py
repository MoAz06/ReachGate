import json

from tools.diff_receipts import classify, gate_failures, main


def _finding(occ, verdict, basis, fingerprint):
    return {
        "occurrence_id": occ,
        "verdict": verdict,
        "verdict_basis": basis,
        "fingerprint": fingerprint,
    }


def _artifact(*findings):
    return {"schema_version": "1.0", "findings": list(findings)}


def _index(*findings):
    return {f["occurrence_id"]: f for f in findings}


def test_classify_buckets_by_occurrence_and_fingerprint():
    old = _index(
        _finding("same", "NOT_REACHABLE", "no_path_search_exhaustive", "aaa"),
        _finding("moved", "NOT_REACHABLE", "no_path_search_exhaustive", "bbb"),
        _finding("gone", "UNKNOWN", "insufficient_evidence", "ccc"),
    )
    new = _index(
        _finding("same", "NOT_REACHABLE", "no_path_search_exhaustive", "aaa"),
        _finding("moved", "REACHABLE", "path_found", "bbb2"),
        _finding("fresh", "REACHABLE", "path_found", "ddd"),
    )

    buckets = classify(old, new)

    assert buckets["UNCHANGED"] == ["same"]
    assert buckets["CHANGED"] == ["moved"]
    assert buckets["NEW"] == ["fresh"]
    assert buckets["REMOVED"] == ["gone"]


def test_gate_flags_new_reachable():
    old = _index()
    new = _index(_finding("fresh", "REACHABLE", "path_found", "ddd"))
    buckets = classify(old, new)
    assert gate_failures(buckets, old, new) == ["fresh"]


def test_gate_flags_changed_to_reachable():
    old = _index(_finding("x", "NOT_REACHABLE", "no_path_search_exhaustive", "a"))
    new = _index(_finding("x", "REACHABLE", "path_found", "b"))
    buckets = classify(old, new)
    assert gate_failures(buckets, old, new) == ["x"]


def test_gate_ignores_unknown_and_not_reachable():
    old = _index()
    new = _index(
        _finding("u", "UNKNOWN", "insufficient_evidence", "a"),
        _finding("n", "NOT_REACHABLE", "no_path_search_exhaustive", "b"),
    )
    buckets = classify(old, new)
    assert gate_failures(buckets, old, new) == []


def test_gate_ignores_already_reachable_unchanged():
    # Reachable in both, same fingerprint -> not a regression.
    fr = _finding("x", "REACHABLE", "path_found", "a")
    old = _index(fr)
    new = _index(dict(fr))
    buckets = classify(old, new)
    assert gate_failures(buckets, old, new) == []


def _write(tmp_path, name, artifact):
    p = tmp_path / name
    p.write_text(json.dumps(artifact), encoding="utf-8")
    return str(p)


def test_main_exit_zero_by_default_even_with_new_reachable(tmp_path):
    old = _write(tmp_path, "old.json", _artifact())
    new = _write(
        tmp_path, "new.json",
        _artifact(_finding("fresh", "REACHABLE", "path_found", "d")),
    )
    assert main([old, new]) == 0


def test_main_exit_one_on_new_reachable_with_flag(tmp_path):
    old = _write(tmp_path, "old.json", _artifact())
    new = _write(
        tmp_path, "new.json",
        _artifact(_finding("fresh", "REACHABLE", "path_found", "d")),
    )
    assert main([old, new, "--fail-on-new-reachable"]) == 1


def test_main_exit_zero_on_unchanged_with_flag(tmp_path):
    art = _artifact(
        _finding("x", "REACHABLE", "path_found", "a"),
        _finding("y", "NOT_REACHABLE", "no_path_search_exhaustive", "b"),
    )
    old = _write(tmp_path, "old.json", art)
    new = _write(tmp_path, "new.json", art)
    assert main([old, new, "--fail-on-new-reachable"]) == 0
