"""Config loading util.

FINDING A (planted, REACHABLE): unsafe yaml.load on user-controlled input.
Call chain: app.py -> routes/orders.py -> services/parser.py -> here.
"""

import yaml


def load_config(raw: str):
    return yaml.load(raw)  # nosec-free on purpose: SAST must flag this
