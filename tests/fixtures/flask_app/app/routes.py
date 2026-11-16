import requests
from flask import Blueprint, request, jsonify
from flask_login import login_required
from app import db
from app.models import Customer

bp = Blueprint("main", __name__)


@bp.route("/customers/<int:cid>", methods=["GET", "DELETE"])
@login_required
def customer(cid):
    c = db.session.get(Customer, cid)
    if request.method == "DELETE":
        db.session.delete(c)
    return jsonify(id=c.id)


@bp.route("/customers", methods=["POST"])
def create_customer():
    c = Customer(email=request.json["email"], card_number=request.json["card_number"])
    db.session.add(c)
    requests.post("https://hooks.example.com/notify", json={"email": c.email}, timeout=5)
    return jsonify(id=c.id)


@bp.route("/health")
def health():
    return "ok"
