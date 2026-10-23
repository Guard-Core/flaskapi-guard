from flask import Blueprint, Response, jsonify, request
from flask.typing import ResponseReturnValue

from app.models import message_response
from app.security import guard
from flaskapi_guard import FlaskGuardResponse, GuardRequest, GuardResponse

bp = Blueprint("content", __name__, url_prefix="/content")


@bp.route("/no-bots")
@guard.block_user_agents(["bot", "crawler", "spider", "scraper"])
def block_bots() -> ResponseReturnValue:
    return jsonify(message_response("Human users only - bots blocked"))


@bp.route("/json-only", methods=["POST"])
@guard.content_type_filter(["application/json"])
def json_content_only() -> ResponseReturnValue:
    data = request.get_json(silent=True) or {}
    return jsonify(
        message_response(
            "JSON content received",
            details={"data": data},
        )
    )


@bp.route("/size-limit", methods=["POST"])
@guard.max_request_size(1024 * 100)
def limited_upload_size() -> ResponseReturnValue:
    return jsonify(
        message_response(
            "Data received within size limit",
            details={"size_limit": "100KB"},
        )
    )


@bp.route("/referrer-check")
@guard.require_referrer(["https://example.com", "https://app.example.com"])
def check_referrer() -> ResponseReturnValue:
    referrer = request.headers.get("referer", "No referrer")
    return jsonify(
        message_response(
            "Valid referrer",
            details={"referrer": referrer},
        )
    )


def custom_validator(req: GuardRequest) -> GuardResponse | None:
    user_agent = req.headers.get("user-agent", "").lower()
    if "suspicious-pattern" in user_agent:
        return FlaskGuardResponse(
            Response(
                response='{"detail": "Suspicious user agent"}',
                status=403,
                content_type="application/json",
            )
        )
    return None


@bp.route("/custom-validation")
@guard.custom_validation(custom_validator)
def custom_content_validation() -> ResponseReturnValue:
    return jsonify(
        message_response(
            "Custom validation passed",
            details={"validator": "custom_validator"},
        )
    )
