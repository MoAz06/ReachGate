"""Legacy settings migration tool.

FINDING B (planted, NOT REACHABLE): same vuln class as Finding A,
but this module is imported by nothing. No path from any entry point.
"""

import yaml


def migrate_settings(raw: str):
    return yaml.load(raw)  # same unsafe pattern, dead code


if __name__ == "__main__":
    print("This script was retired in 2024. Do not run.")
