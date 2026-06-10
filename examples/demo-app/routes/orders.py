"""Order import routes. Reachable from the app entry point."""

from flask import Blueprint, request

from services.parser import parse_order_config

orders_bp = Blueprint("orders", __name__)


@orders_bp.route("/orders/import", methods=["POST"])
def import_orders():
    config = parse_order_config(request.data.decode())
    return {"imported": True, "config": config}
