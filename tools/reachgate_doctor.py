"""ReachGate doctor: validate your declared attack surface against Orbit.

Reachability is only as honest as the attack surface you declare in
`reachgate.yml`. If an entrypoint glob matches zero indexed files, ReachGate
will walk from nowhere and report NOT_REACHABLE for everything -- a silent
false negative caused by config, not by the code being safe.

This tool closes that gap. For each `entrypoints.files` pattern it asks live
GitLab Orbit which indexed files match, and tells you how many. It is a
pre-flight check for onboarding, not a verdict engine.

What it does and does NOT claim:
  * It validates that your declared globs match files Orbit has indexed.
  * It does NOT prove your entrypoints are the *right* attack surface --
    you still own that definition.
  * It does NOT infer or suggest entrypoints.
  * If a pattern matches zero files, NOT_REACHABLE evidence derived from it
    cannot be trusted until the config is fixed.

Requires GITLAB_TOKEN for the live Orbit query. Uses only the standard
library plus the existing reachgate modules -- no new dependency.

Exit codes:
  0  at least one entrypoint file matched
  1  config loaded but zero entrypoint files matched (false-negative risk)
  2  usage / input / auth / config error
"""

from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from reachgate.config import ReachGateConfig, load_config  # noqa: E402
from reachgate.orbit_client import OrbitClient  # noqa: E402

# get_files_matching strips '*' and '/' then needs a >=3 char needle to query
# Orbit's `contains` filter; anything shorter is silently skipped server-side.
MIN_QUERYABLE_NEEDLE = 3


class DoctorError(Exception):
    """A user-facing problem (auth / config / input)."""


def _needle(pattern: str) -> str:
    return pattern.strip("*/")


def check_pattern(
    client: OrbitClient,
    config: ReachGateConfig,
    pattern: str,
    limit: int,
) -> dict:
    """Validate one entrypoint pattern against indexed Orbit files.

    Orbit's `contains` query is a coarse prefilter, so we re-confirm every
    returned path against the exact glob matcher from reachgate.yml. That way
    the count reflects real glob matches, not the loose server-side search.
    """
    if len(_needle(pattern)) < MIN_QUERYABLE_NEEDLE:
        return {
            "pattern": pattern,
            "queryable": False,
            "paths": [],
            "match_count": 0,
        }

    raw = client.get_files_matching([pattern])
    seen = set()
    matched = []
    for node in raw:
        path = node.get("path")
        if not path or path in seen:
            continue
        seen.add(path)
        if config.is_entrypoint(path):
            matched.append(path)

    matched.sort()
    return {
        "pattern": pattern,
        "queryable": True,
        "paths": matched[:limit],
        "match_count": len(matched),
    }


def run_checks(
    client: OrbitClient,
    config: ReachGateConfig,
    limit: int,
) -> list[dict]:
    return [
        check_pattern(client, config, pattern, limit)
        for pattern in config.entrypoint_patterns
    ]


def render(results: list[dict], limit: int) -> tuple[list[str], int]:
    """Build human-readable output lines and the total matched file count."""
    lines: list[str] = []
    total_patterns = len(results)
    with_matches = 0
    not_queryable = 0
    total_files = 0

    for r in results:
        pattern = r["pattern"]
        if not r["queryable"]:
            not_queryable += 1
            lines.append(f"  [skip] {pattern}")
            lines.append(
                f"         not queryable: needle under {MIN_QUERYABLE_NEEDLE} "
                "chars, Orbit cannot search it"
            )
            continue

        count = r["match_count"]
        total_files += count
        if count > 0:
            with_matches += 1
            lines.append(f"  [ ok ] {pattern}  ({count} indexed file(s))")
            for path in r["paths"]:
                lines.append(f"           - {path}")
            if count > len(r["paths"]):
                lines.append(f"           ... and {count - len(r['paths'])} more")
        else:
            lines.append(f"  [warn] {pattern}  (0 indexed files matched)")

    zero_match = total_patterns - with_matches

    summary = [
        "",
        "Summary",
        f"  patterns declared:      {total_patterns}",
        f"  patterns with matches:  {with_matches}",
        f"  patterns with 0 matches:{zero_match}"
        + (f" (incl. {not_queryable} not queryable)" if not_queryable else ""),
        f"  total matched files:    {total_files}",
    ]

    if total_files == 0:
        summary.append("")
        summary.append(
            "  WARNING: no declared entrypoint matched any indexed file. "
            "ReachGate would walk from nowhere, so NOT_REACHABLE evidence "
            "cannot be trusted until reachgate.yml is fixed."
        )
    elif zero_match > 0:
        summary.append("")
        summary.append(
            "  Note: some patterns matched nothing. Findings only reachable "
            "via those patterns may be reported NOT_REACHABLE for the wrong "
            "reason."
        )

    summary.append("")
    summary.append(
        "  This validates that declared globs match indexed Orbit files. "
        "It does not prove the attack surface is complete -- you still own "
        "that definition."
    )

    return lines + summary, total_files


def _load_config_or_raise(path: str) -> ReachGateConfig:
    try:
        return load_config(path)
    except FileNotFoundError:
        raise DoctorError(f"config not found: {path}")
    except (ValueError, KeyError, TypeError) as e:
        raise DoctorError(f"invalid config {path}: {e}")
    except Exception as e:  # noqa: BLE001 - yaml/parse errors surface cleanly
        raise DoctorError(f"could not load config {path}: {e}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate reachgate.yml entrypoints against live Orbit.",
    )
    parser.add_argument("--config", default="reachgate.yml",
                        help="path to reachgate.yml (default: reachgate.yml)")
    parser.add_argument("--gitlab-url", default="https://gitlab.com",
                        help="GitLab base URL (default: https://gitlab.com)")
    parser.add_argument("--limit", type=int, default=20,
                        help="max sample paths printed per pattern (default: 20)")
    args = parser.parse_args(argv)

    try:
        token = os.environ.get("GITLAB_TOKEN")
        if not token:
            raise DoctorError("GITLAB_TOKEN is not set; required for live Orbit query")
        if args.limit < 0:
            raise DoctorError("--limit must be >= 0")

        config = _load_config_or_raise(args.config)
    except DoctorError as e:
        print(f"reachgate-doctor: {e}", file=sys.stderr)
        return 2

    client = OrbitClient(args.gitlab_url, token)

    print(f"ReachGate doctor: checking {len(config.entrypoint_patterns)} "
          f"entrypoint pattern(s) against Orbit at {args.gitlab_url}")
    results = run_checks(client, config, args.limit)
    lines, total_files = render(results, args.limit)
    for line in lines:
        print(line)

    return 0 if total_files > 0 else 1


if __name__ == "__main__":
    sys.exit(main())
