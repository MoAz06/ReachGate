"""Order parser. Sits between the route and the config loader."""

from utils.config_loader import load_config


def parse_order(raw: str):
    # Delegates to the vulnerable loader, completing the reachable chain.
    return load_config(raw)
