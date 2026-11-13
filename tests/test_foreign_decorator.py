"""A view stamped by a SecurityDecorator other than the one the extension uses is
reported at the first request: refused with the flag on, served with one report
with it off."""

import logging

import pytest
from flask import Blueprint, Flask
from guard_core._utils.route_gate import route_unknown_to_decorator_problem
from guard_core.sync.protocols.request_protocol import SyncGuardRequest

from flaskapi_guard import FlaskAPIGuard, SecurityConfig, SecurityDecorator

KIND = route_unknown_to_decorator_problem("x").kind
NEED = {"X-Need": "1"}


def _config(flag: bool) -> SecurityConfig[SyncGuardRequest]:
    return SecurityConfig[SyncGuardRequest](
        enable_redis=False, rate_limit=100000, fail_on_misconfiguration=flag
    )


def _app(flag: bool) -> tuple[Flask, SecurityDecorator]:
    config = _config(flag)
    app = Flask(__name__)
    guard = FlaskAPIGuard(app, config=config)
    root = SecurityDecorator(config)
    guard.set_decorator_handler(root)

    @app.get("/hello")
    @root.require_headers({"X-Root": "required"})
    def hello() -> str:
        return "ok"

    return app, root


def _package(decorator: SecurityDecorator | None) -> Blueprint:
    blueprint = Blueprint("pkg", __name__, url_prefix="/pkg")

    if decorator is None:

        @blueprint.get("/admin")
        def open_admin() -> str:
            return "ok"

        return blueprint

    @blueprint.get("/admin")
    @decorator.require_headers({"X-Need": "required"})
    def admin() -> str:
        return "ok"

    return blueprint


def _foreign(caplog: pytest.LogCaptureFixture) -> list[logging.LogRecord]:
    return [
        r
        for r in caplog.records
        if any(kind == KIND for kind, _ in r.__dict__.get("problems", ()))
    ]


def test_a_foreign_view_refuses_every_request_by_default() -> None:
    app, _ = _app(True)
    app.register_blueprint(_package(SecurityDecorator(_config(True))))
    client = app.test_client()

    assert client.get("/pkg/admin", headers=NEED).status_code == 500
    assert client.get("/hello", headers={"X-Root": "1"}).status_code == 500


def test_a_foreign_view_is_served_and_reported_once_with_the_flag_off(
    caplog: pytest.LogCaptureFixture,
) -> None:
    app, _ = _app(False)
    app.register_blueprint(_package(SecurityDecorator(_config(False))))
    caplog.set_level(logging.WARNING)
    client = app.test_client()

    assert [client.get("/pkg/admin", headers=NEED).status_code for _ in range(3)] == [
        200,
        200,
        200,
    ]
    assert client.get("/hello").status_code == 400
    assert client.get("/hello", headers={"X-Root": "1"}).status_code == 200
    (record,) = _foreign(caplog)
    label = record.__dict__["problems"][0][1]
    assert str(route_unknown_to_decorator_problem(label)) in record.getMessage()


def test_a_package_sharing_the_root_decorator_is_not_reported(
    caplog: pytest.LogCaptureFixture,
) -> None:
    app, root = _app(True)
    app.register_blueprint(_package(root))
    caplog.set_level(logging.WARNING)
    client = app.test_client()

    assert client.get("/pkg/admin").status_code == 400
    assert client.get("/pkg/admin", headers=NEED).status_code == 200
    assert _foreign(caplog) == []


def test_a_decorator_created_and_never_used_is_not_reported(
    caplog: pytest.LogCaptureFixture,
) -> None:
    app, _ = _app(True)
    SecurityDecorator(_config(True))
    app.register_blueprint(_package(None))
    caplog.set_level(logging.WARNING)

    assert app.test_client().get("/pkg/admin").status_code == 200
    assert _foreign(caplog) == []


def test_one_view_on_two_rules_is_reported_once(
    caplog: pytest.LogCaptureFixture,
) -> None:
    app, _ = _app(False)
    other = SecurityDecorator(_config(False))

    @app.get("/a")
    @app.get("/b")
    @other.require_headers({"X-Need": "required"})
    def both() -> str:
        return "ok"

    caplog.set_level(logging.WARNING)

    assert app.test_client().get("/a", headers=NEED).status_code == 200
    assert len(_foreign(caplog)) == 1
