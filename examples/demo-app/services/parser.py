"""Order config parsing service. Sits between the route and the vulnerable util."""

from utils.config_loader import load_config


def parse_order_config(raw: str):
    return load_config(raw)
