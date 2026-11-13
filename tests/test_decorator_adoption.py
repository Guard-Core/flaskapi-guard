import logging
from typing import Any

import pytest
from flask import Flask
from guard_core.sync.protocols.request_protocol import SyncGuardRequest

from flaskapi_guard import FlaskAPIGuard, SecurityConfig, SecurityDecorator

PEER = {"X-Forwarded-For": "203.0.113.9"}


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


def _limited_app(decorator: SecurityDecorator, path: str = "/limited") -> Flask:
    app = Flask(__name__)
    app.config["TESTING"] = True

    @app.route(path)
    @decorator.rate_limit(requests=1, window=60)
    def limited() -> str:
        return "ok"

    return app


def _statuses(app: Flask, path: str = "/limited") -> list[int]:
    client = app.test_client()
    return [client.get(path, headers=PEER).status_code for _ in range(2)]


def test_a_route_decorator_is_enforced_without_set_decorator_handler() -> None:
    config = _config()
    decorator = SecurityDecorator(config)
    app = _limited_app(decorator)
    FlaskAPIGuard(app, config=config)

    assert _statuses(app) == [200, 429]


def test_the_adopted_decorator_is_the_one_the_extension_reports() -> None:
    config = _config()
    decorator = SecurityDecorator(config)
    app = _limited_app(decorator)
    guard = FlaskAPIGuard(app, config=config)

    app.test_client().get("/limited", headers=PEER)

    assert guard.guard_decorator is decorator
    assert app.extensions["flaskapi_guard"]["guard_decorator"] is decorator


def test_a_decorator_the_app_unbound_is_never_adopted() -> None:
    config = _config()
    decorator = SecurityDecorator(config)
    app = _limited_app(decorator)
    guard = FlaskAPIGuard(app, config=config)
    guard.set_decorator_handler(None)

    assert _statuses(app) == [200, 200]


def test_two_decorators_on_the_apps_routes_are_refused_when_the_flag_is_on() -> None:
    config = _config(fail_on_misconfiguration=True)
    first, second = SecurityDecorator(config), SecurityDecorator(config)
    app = _limited_app(first)

    @app.route("/other")
    @second.rate_limit(requests=1, window=60)
    def other() -> str:
        return "other"

    FlaskAPIGuard(app, config=config)

    with pytest.raises(RuntimeError, match="2 SecurityDecorator instances"):
        app.test_client().get("/limited", headers=PEER)


def test_two_decorators_on_the_apps_routes_are_reported_when_the_flag_is_off(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = _config()
    first, second = SecurityDecorator(config), SecurityDecorator(config)
    app = _limited_app(first)

    @app.route("/other")
    @second.rate_limit(requests=1, window=60)
    def other() -> str:
        return "other"

    FlaskAPIGuard(app, config=config)

    with caplog.at_level(logging.ERROR):
        assert _statuses(app) == [200, 200]

    assert sum("2 SecurityDecorator instances" in m for m in caplog.messages) == 1


def test_a_decorator_of_another_app_is_not_a_candidate() -> None:
    config = _config(fail_on_misconfiguration=True)
    other_apps_decorator = SecurityDecorator(config)
    _limited_app(other_apps_decorator, "/elsewhere")
    decorator = SecurityDecorator(config)
    app = _limited_app(decorator)
    guard = FlaskAPIGuard(app, config=config)

    assert _statuses(app) == [200, 429]
    assert guard.guard_decorator is decorator


def test_a_decorated_route_without_a_bound_decorator_warns_once(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = _config()
    decorator = SecurityDecorator(config)
    app = _limited_app(decorator)
    guard = FlaskAPIGuard(app, config=config)
    guard.set_decorator_handler(None)

    with caplog.at_level(logging.WARNING):
        _statuses(app)
        _statuses(app)

    warnings = [m for m in caplog.messages if "no decorator is registered" in m]
    assert len(warnings) == 1
