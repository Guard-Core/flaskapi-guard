import pytest
from flask import Blueprint, Flask
from werkzeug.test import TestResponse

from flaskapi_guard import FlaskAPIGuard, SecurityConfig


def _allowed(response: TestResponse) -> set[str]:
    return {m.strip() for m in response.headers["Allow"].split(",")}


def _app(guarded: bool, host_matching: bool) -> Flask:
    app = Flask(
        __name__,
        host_matching=host_matching,
        static_host="example.com" if host_matching else None,
        subdomain_matching=not host_matching,
    )
    if not host_matching:
        app.config["SERVER_NAME"] = "example.com"
    blueprint = Blueprint(
        "admin", __name__, subdomain=None if host_matching else "admin"
    )
    host = {"host": "admin.example.com"} if host_matching else {}

    @blueprint.route("/x", methods=["POST"], **host)
    def x() -> str:
        return "ok"

    app.register_blueprint(blueprint)
    if guarded:
        FlaskAPIGuard(
            app,
            config=SecurityConfig(
                enable_redis=False,
                route_resolution_strict=True,
                enable_rate_limiting=False,
                enable_penetration_detection=False,
                passive_mode=False,
                ban_on_hostile_signals=False,
                fail_on_misconfiguration=False,
                rate_limit=1000,
            ),
        )
    return app


@pytest.mark.parametrize("host_matching", [False, True])
def test_a_wrong_method_on_a_subdomain_or_host_route_answers_405_with_allow(
    host_matching: bool,
) -> None:
    unguarded = _app(False, host_matching).test_client()
    guarded = _app(True, host_matching).test_client()

    expected = unguarded.get("/x", base_url="http://admin.example.com")
    answered = guarded.get("/x", base_url="http://admin.example.com")

    assert expected.status_code == 405
    assert answered.status_code == 405
    assert _allowed(answered) == _allowed(expected)
