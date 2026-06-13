"""Legacy migration script (Finding B).

NOT_REACHABLE: this module is imported by nothing in the declared attack
surface (app.py and its transitive imports), so no graph path reaches it.
It carries the same unsafe yaml.load as Finding A on purpose -- same scanner
output, opposite reachability verdict.
"""

import sys

import yaml


def migrate(path: str):
    with open(path) as f:
        # Same planted vulnerability as utils/config_loader, but unreachable.
        return yaml.load(f.read())  # noqa: S506 - intentional demo vulnerability


if __name__ == "__main__":
    migrate(sys.argv[1])
