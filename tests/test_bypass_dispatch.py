from typing import Any

from flask import Flask
from guard_core.sync.protocols.request_protocol import SyncGuardRequest

from flaskapi_guard import FlaskAPIGuard, SecurityConfig, SecurityDecorator

PEER = {"X-Forwarded-For": "203.0.113.9"}
NO_PEER = {"REMOTE_ADDR": ""}


def _config(**overrides: Any) -> SecurityConfig[SyncGuardRequest]:
    fields: dict[str, Any] = {
        "enable_redis": False,
        "enable_agent": False,
        "enable_penetration_detection": False,
        "fail_on_misconfiguration": False,
        "rate_limit": 1000,
        "trusted_proxies": ["127.0.0.1"],
    }
    fields.update(overrides)
    return SecurityConfig[SyncGuardRequest](**fields)


def _app(
    config: SecurityConfig[SyncGuardRequest],
    decorator: SecurityDecorator | None = None,
) -> tuple[Flask, list[str]]:
    app = Flask(__name__)
    app.config["TESTING"] = True
    called: list[str] = []

    def get_only() -> str:
        called.append("get-only")
        return "ok"

    guarded = decorator.bypass(["all"])(get_only) if decorator else get_only
    app.add_url_rule("/get-only", endpoint="get_only", view_func=guarded)

    @app.route("/post-only", methods=["POST"])
    def post_only() -> str:
        called.append("post-only")
        return "ok"

    return app, called


def test_a_bypassed_route_answers_the_automatic_options_as_flask_does() -> None:
    config = _config()
    decorator = SecurityDecorator(config)
    app, called = _app(config, decorator)
    FlaskAPIGuard(app, config=config).set_decorator_handler(decorator)

    response = app.test_client().options("/get-only", headers=PEER)

    assert response.status_code == 200
    assert {"GET", "HEAD", "OPTIONS"} <= set(response.headers["Allow"].split(", "))
    assert called == []


def test_a_passthrough_request_no_route_matches_answers_404() -> None:
    config = _config(fail_secure=False)
    app, called = _app(config)
    FlaskAPIGuard(app, config=config)

    response = app.test_client().get("/nowhere", environ_overrides=NO_PEER)

    assert response.status_code == 404
    assert called == []


def test_a_passthrough_request_the_method_does_not_allow_answers_405() -> None:
    config = _config(fail_secure=False)
    app, called = _app(config)
    FlaskAPIGuard(app, config=config)

    response = app.test_client().get("/post-only", environ_overrides=NO_PEER)

    assert response.status_code == 405
    assert called == []


def test_a_passthrough_request_still_reaches_its_view() -> None:
    config = _config(fail_secure=False)
    app, called = _app(config)
    FlaskAPIGuard(app, config=config)

    response = app.test_client().get("/get-only", environ_overrides=NO_PEER)

    assert response.status_code == 200
    assert called == ["get-only"]
