"""Orders route. Reachable from app.py (registered blueprint)."""

from flask import Blueprint, request

from services.parser import parse_order

orders_bp = Blueprint("orders", __name__)


@orders_bp.route("/orders", methods=["POST"])
def create_order():
    # Entry point -> parser -> config_loader (the REACHABLE chain).
    return parse_order(request.get_data(as_text=True))
