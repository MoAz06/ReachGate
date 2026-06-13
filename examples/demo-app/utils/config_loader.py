"""Vulnerable config loader (Finding A).

Reachable: app.py -> routes/orders.py -> services/parser.py -> here.
"""

import yaml


def load_config(raw: str):
    # Planted vulnerability: unsafe yaml.load on caller-controlled input.
    return yaml.load(raw)  # noqa: S506 - intentional demo vulnerability
