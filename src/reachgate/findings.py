"""Load security findings from disk and normalize them for the engine.

ReachGate's engine (`GraphWalker.check_reachability`) consumes a single
occurrence dict shape:

    {"uuid": str, "name": str|None, "severity": str|None,
     "location": <json-string with at least {"file": ...}>,
     "start_line": int (optional)}

This module turns two real input formats into that shape:

  1. GitLab SAST report:   {"vulnerabilities": [...]}
  2. Native ReachGate JSON: a top-level list, or {"findings": [...]}

Design rules:
  - Findings are never silently dropped. A finding without a file/location
    is passed through with whatever location it has (possibly empty), so the
    engine returns an honest UNKNOWN/no_location instead of vanishing.
  - Every occurrence gets a non-empty, deterministic `uuid`. When the input
    carries no id, one is derived from name + file + start_line so that two
    findings in the same file never collapse to the same identity.
  - Invalid JSON or an unrecognized top-level shape raises FindingsLoadError.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any


class FindingsLoadError(Exception):
    """Raised when a findings file is invalid JSON or an unknown shape."""


def derive_occurrence_id(
    name: str | None, file: str | None, start_line: int | None
) -> str:
    """Deterministic id for findings that carry no usable uuid/id/fingerprint.

    Includes start_line so that two findings in the same file with different
    locations never collapse to the same occurrence identity.
    """
    canonical = f"{name}|{file}|{start_line}"
    return hashlib.sha256(canonical.encode()).hexdigest()[:16]


def _location_to_json(location: Any, start_line: int | None) -> str:
    """Return a JSON-string location with at least {"file": ...} when known.

    Accepts an object (dict) or an already-encoded JSON string. A string is
    passed through unchanged so the engine can parse it (or fail to, yielding
    a clean no_location). A dict is canonicalized to a JSON string.
    """
    if isinstance(location, str):
        return location
    if isinstance(location, dict):
        return json.dumps(location)
    # No structured location: build the minimal shape the engine expects.
    payload: dict[str, Any] = {}
    if start_line is not None:
        payload["start_line"] = start_line
    return json.dumps(payload)


def _file_of(location: Any) -> str | None:
    if isinstance(location, dict):
        f = location.get("file") or location.get("path")
        return f if isinstance(f, str) else None
    if isinstance(location, str):
        try:
            loc = json.loads(location)
        except (json.JSONDecodeError, TypeError):
            return None
        if isinstance(loc, dict):
            f = loc.get("file") or loc.get("path")
            return f if isinstance(f, str) else None
    return None


def _normalize_sast(vuln: dict[str, Any]) -> dict[str, Any]:
    """One GitLab SAST vulnerability -> occurrence dict."""
    location = vuln.get("location") or {}
    start_line = location.get("start_line") if isinstance(location, dict) else None
    name = vuln.get("name") or vuln.get("message")
    file = _file_of(location)

    uuid = (
        vuln.get("uuid")
        or vuln.get("id")
        or vuln.get("fingerprint")
        or derive_occurrence_id(name, file, start_line)
    )
    severity = vuln.get("severity")
    occ: dict[str, Any] = {
        "uuid": str(uuid),
        "name": name,
        "severity": severity.lower() if isinstance(severity, str) else severity,
        "location": _location_to_json(location, start_line),
    }
    if start_line is not None:
        occ["start_line"] = start_line
    return occ


def _normalize_native(finding: dict[str, Any]) -> dict[str, Any]:
    """One native ReachGate finding -> occurrence dict.

    `location` may be an object or an already-encoded JSON string.
    """
    location = finding.get("location") or {}
    start_line = finding.get("start_line")
    if start_line is None and isinstance(location, dict):
        start_line = location.get("start_line")
    name = finding.get("name") or finding.get("message")
    file = _file_of(location)

    uuid = (
        finding.get("uuid")
        or finding.get("id")
        or finding.get("fingerprint")
        or derive_occurrence_id(name, file, start_line)
    )
    severity = finding.get("severity")
    occ: dict[str, Any] = {
        "uuid": str(uuid),
        "name": name,
        "severity": severity.lower() if isinstance(severity, str) else severity,
        "location": _location_to_json(location, start_line),
    }
    if start_line is not None:
        occ["start_line"] = start_line
    return occ


def parse_findings(data: Any) -> list[dict[str, Any]]:
    """Normalize already-decoded JSON into occurrence dicts.

    Autodetects shape:
      - {"vulnerabilities": [...]}  -> GitLab SAST report
      - {"findings": [...]}         -> native
      - [...]                       -> native list
    """
    if isinstance(data, dict) and "vulnerabilities" in data:
        items = data["vulnerabilities"]
        if not isinstance(items, list):
            raise FindingsLoadError("'vulnerabilities' must be a list")
        return [_normalize_sast(v) for v in items if isinstance(v, dict)]

    if isinstance(data, dict) and "findings" in data:
        items = data["findings"]
        if not isinstance(items, list):
            raise FindingsLoadError("'findings' must be a list")
        return [_normalize_native(f) for f in items if isinstance(f, dict)]

    if isinstance(data, list):
        return [_normalize_native(f) for f in data if isinstance(f, dict)]

    raise FindingsLoadError(
        "Unrecognized findings shape: expected a list, "
        "{'findings': [...]} or {'vulnerabilities': [...]}"
    )


def load_findings(path: str) -> list[dict[str, Any]]:
    """Read a findings file from disk and normalize it. Raises FindingsLoadError."""
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        raise FindingsLoadError(f"Findings file not found: {path}")
    except json.JSONDecodeError as e:
        raise FindingsLoadError(f"Invalid JSON in {path}: {e}")
    return parse_findings(data)
