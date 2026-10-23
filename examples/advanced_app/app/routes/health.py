from flask import Blueprint, jsonify
from flask.typing import ResponseReturnValue

from app.models import health_response

bp = Blueprint("health", __name__)


@bp.route("/health")
def health_check() -> ResponseReturnValue:
    return jsonify(health_response("healthy"))


@bp.route("/ready")
def readiness_check() -> ResponseReturnValue:
    return jsonify(health_response("ready"))
