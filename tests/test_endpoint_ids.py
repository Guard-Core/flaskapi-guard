import functools
from typing import Any

import pytest
from flask import Flask, g
from flask.views import MethodView
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


def _show(tag: str = "") -> str:
    return str(g.guard_endpoint_id)


class _Callable:
    def __call__(self) -> str:
        return str(g.guard_endpoint_id)


class _First(MethodView):
    def get(self) -> str:
        return str(g.guard_endpoint_id)


class _Second(MethodView):
    def get(self) -> str:
        return str(g.guard_endpoint_id)


def _get(app: Flask, path: str) -> str:
    response = app.test_client().get(path, headers=PEER)
    assert response.status_code == 200
    return response.get_data(as_text=True)


def _app() -> Flask:
    app = Flask(__name__)
    app.config["TESTING"] = True
    return app


def test_a_plain_function_keeps_its_module_and_qualname_id() -> None:
    app = _app()
    app.add_url_rule("/f", endpoint="f", view_func=_show)
    FlaskAPIGuard(app, config=_config())

    assert _get(app, "/f") == f"{_show.__module__}._show"


def test_an_undecorated_partial_does_not_crash() -> None:
    app = _app()
    app.add_url_rule("/p", endpoint="p", view_func=functools.partial(_show, "a"))
    FlaskAPIGuard(app, config=_config())

    assert _get(app, "/p") == "functools.partial@p"


def test_an_undecorated_callable_instance_does_not_crash() -> None:
    app = _app()
    app.add_url_rule("/c", endpoint="c", view_func=_Callable())
    FlaskAPIGuard(app, config=_config())

    assert _get(app, "/c") == f"{_Callable.__module__}._Callable@c"


def test_two_partials_of_one_function_get_distinct_ids() -> None:
    app = _app()
    app.add_url_rule("/a", endpoint="a", view_func=functools.partial(_show, "a"))
    app.add_url_rule("/b", endpoint="b", view_func=functools.partial(_show, "b"))
    FlaskAPIGuard(app, config=_config())

    assert _get(app, "/a") != _get(app, "/b")


@pytest.mark.parametrize("make", [lambda: functools.partial(_show, "a"), _Callable])
def test_a_stamped_callable_uses_the_id_the_engine_stamped(
    make: Any,
) -> None:
    config = _config()
    decorator = SecurityDecorator(config)
    view = decorator.rate_limit(requests=100, window=60)(make())
    app = _app()
    app.add_url_rule("/s", endpoint="s", view_func=view)
    FlaskAPIGuard(app, config=config)

    assert _get(app, "/s") == vars(view)["_guard_route_id"]


def test_two_stamped_partials_of_one_function_get_distinct_ids() -> None:
    config = _config()
    decorator = SecurityDecorator(config)
    first = decorator.rate_limit(requests=100, window=60)(functools.partial(_show, "a"))
    second = decorator.rate_limit(requests=100, window=60)(
        functools.partial(_show, "b")
    )
    app = _app()
    app.add_url_rule("/a", endpoint="a", view_func=first)
    app.add_url_rule("/b", endpoint="b", view_func=second)
    FlaskAPIGuard(app, config=config)

    assert _get(app, "/a") != _get(app, "/b")


def test_two_method_views_of_one_module_get_distinct_ids() -> None:
    app = _app()
    app.add_url_rule("/one", view_func=_First.as_view("one"))
    app.add_url_rule("/two", view_func=_Second.as_view("two"))
    FlaskAPIGuard(app, config=_config())

    assert _get(app, "/one") == f"{_First.__module__}._First"
    assert _get(app, "/two") == f"{_Second.__module__}._Second"
