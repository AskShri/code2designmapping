from flask import Flask, Blueprint, abort, request
from django.views.decorators.csrf import csrf_exempt
app = Flask(__name__)
bp = Blueprint("admin", __name__)

@bp.before_request
def guard():
    if not request.headers.get("X-Token"):
        abort(401)

@bp.route("/users")
def users():
    return "x"

@app.route("/open")
@csrf_exempt
def open_():
    return "y"

app.register_blueprint(bp, url_prefix="/admin")
