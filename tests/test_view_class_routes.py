import logging
from typing import Any

import pytest
from flask import Flask
from flask.views import MethodView, View
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


def _app() -> tuple[Flask, SecurityDecorator]:
    config = _config()
    decorator = SecurityDecorator(config)
    app = Flask(__name__)
    app.config["TESTING"] = True
    app.extensions["wp792_keep_alive"] = decorator
    app.extensions["wp792_config"] = config
    return app, decorator


def _guarded(app: Flask) -> Flask:
    FlaskAPIGuard(app, config=app.extensions["wp792_config"])
    return app


def _codes(app: Flask, method: str, path: str, times: int = 2) -> list[int]:
    client = app.test_client()
    return [
        client.open(path, method=method, headers=PEER).status_code for _ in range(times)
    ]


def test_a_decorated_method_of_a_method_view_is_enforced() -> None:
    app, decorator = _app()

    class Items(MethodView):
        @decorator.rate_limit(requests=1, window=60)
        def get(self) -> str:
            return "got"

        def post(self) -> str:
            return "posted"

    app.add_url_rule("/items", view_func=Items.as_view("items"))
    _guarded(app)

    assert _codes(app, "GET", "/items") == [200, 429]
    assert _codes(app, "POST", "/items", times=3) == [200, 200, 200]


def test_head_on_a_view_with_only_get_runs_the_get_rules() -> None:
    app, decorator = _app()

    class Items(MethodView):
        @decorator.rate_limit(requests=1, window=60)
        def get(self) -> str:
            return "got"

    app.add_url_rule("/items", view_func=Items.as_view("items"))
    _guarded(app)

    assert _codes(app, "HEAD", "/items") == [200, 429]


def test_a_head_method_of_its_own_is_the_one_that_runs_for_head() -> None:
    app, decorator = _app()

    class Items(MethodView):
        @decorator.rate_limit(requests=1, window=60)
        def get(self) -> str:
            return "got"

        def head(self) -> str:
            return ""

    app.add_url_rule("/items", view_func=Items.as_view("items"))
    _guarded(app)

    assert _codes(app, "HEAD", "/items", times=3) == [200, 200, 200]


def test_a_decorated_method_view_class_is_enforced() -> None:
    app, decorator = _app()

    @decorator.rate_limit(requests=1, window=60)
    class Items(MethodView):
        def get(self) -> str:
            return "got"

    app.add_url_rule("/items", view_func=Items.as_view("items"))
    _guarded(app)

    assert _codes(app, "GET", "/items") == [200, 429]


def test_a_decorated_dispatch_request_of_a_view_is_enforced() -> None:
    app, decorator = _app()

    class Page(View):
        @decorator.rate_limit(requests=1, window=60)
        def dispatch_request(self) -> str:
            return "page"

    app.add_url_rule("/page", view_func=Page.as_view("page"))
    _guarded(app)

    assert _codes(app, "GET", "/page") == [200, 429]


def test_a_decorated_view_class_of_a_view_is_enforced() -> None:
    app, decorator = _app()

    @decorator.rate_limit(requests=1, window=60)
    class Page(View):
        def dispatch_request(self) -> str:
            return "page"

    app.add_url_rule("/page", view_func=Page.as_view("page"))
    _guarded(app)

    assert _codes(app, "GET", "/page") == [200, 429]


def test_a_decorated_method_of_a_method_view_with_init_every_request_off() -> None:
    app, decorator = _app()

    class Items(MethodView):
        init_every_request = False

        @decorator.rate_limit(requests=1, window=60)
        def get(self) -> str:
            return "got"

    app.add_url_rule("/items", view_func=Items.as_view("items"))
    _guarded(app)

    assert _codes(app, "GET", "/items") == [200, 429]


def test_decorators_in_several_places_of_a_view_are_logged_once(
    caplog: pytest.LogCaptureFixture,
) -> None:
    app, decorator = _app()

    @decorator.rate_limit(requests=5, window=60)
    class Items(MethodView):
        @decorator.rate_limit(requests=1, window=60)
        def get(self) -> str:
            return "got"

    app.add_url_rule("/items", view_func=Items.as_view("items"))
    _guarded(app)

    with caplog.at_level(logging.WARNING):
        _codes(app, "GET", "/items", times=3)

    warned = [m for m in caplog.messages if "applied to the class, its get" in m]
    assert len(warned) == 1
