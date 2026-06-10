"""Load and validate reachgate.yml."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml


@dataclass
class PolicyConfig:
    min_hops: int = 1
    max_hops: int = 10


@dataclass
class ReachGateConfig:
    version: str
    entrypoint_patterns: list[str]
    policy: PolicyConfig = field(default_factory=PolicyConfig)

    def is_entrypoint(self, file_path: str) -> bool:
        return any(_glob_match(file_path, p) for p in self.entrypoint_patterns)


def _glob_match(path: str, pattern: str) -> bool:
    """Match a file path against a glob pattern with ** support."""
    parts = re.split(r"(\*\*|\*|\?)", pattern)
    regex = "^"
    i = 0
    while i < len(parts):
        part = parts[i]
        if part == "**":
            # **/  means zero or more directory components (absorb trailing slash)
            if i + 1 < len(parts) and parts[i + 1] == "/":
                regex += "(?:.*/)??"
                i += 2
            else:
                regex += ".*"
                i += 1
        elif part == "*":
            regex += "[^/]*"
            i += 1
        elif part == "?":
            regex += "[^/]"
            i += 1
        else:
            regex += re.escape(part)
            i += 1
    regex += "$"
    return bool(re.match(regex, path))


def load_config(path: str | Path = "reachgate.yml") -> ReachGateConfig:
    with open(path) as f:
        raw = yaml.safe_load(f)

    version = str(raw.get("version", "1"))
    patterns = raw.get("entrypoints", {}).get("files", [])
    if not patterns:
        raise ValueError("reachgate.yml must define at least one entrypoints.files pattern")

    policy_raw = raw.get("policy", {})
    policy = PolicyConfig(
        min_hops=int(policy_raw.get("min_hops", 1)),
        max_hops=int(policy_raw.get("max_hops", 10)),
    )

    return ReachGateConfig(
        version=version,
        entrypoint_patterns=patterns,
        policy=policy,
    )
