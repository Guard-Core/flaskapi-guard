from typing import Any

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


def _app(decorator: SecurityDecorator | None = None) -> Flask:
    app = Flask(__name__)
    app.config["TESTING"] = True

    def index() -> str:
        return "ok"

    limited = decorator.rate_limit(requests=1, window=60)(index) if decorator else index
    app.add_url_rule("/", endpoint="index", view_func=limited)
    return app


def _codes(app: Flask, times: int) -> list[int]:
    client = app.test_client()
    return [client.get("/", headers=PEER).status_code for _ in range(times)]


def test_a_second_init_app_does_not_reset_the_first_apps_config() -> None:
    guard = FlaskAPIGuard()
    strict, lax = _config(rate_limit=2), _config(rate_limit=1000)
    first, second = _app(), _app()

    guard.init_app(first, config=strict)
    guard.init_app(second, config=lax)

    assert _codes(first, 3) == [200, 200, 429]
    assert _codes(second, 3) == [200, 200, 200]


def test_each_app_holds_the_guard_built_for_its_own_config() -> None:
    guard = FlaskAPIGuard()
    strict, lax = _config(rate_limit=2), _config(rate_limit=1000)
    first, second = _app(), _app()

    guard.init_app(first, config=strict)
    guard.init_app(second, config=lax)

    assert first.extensions["flaskapi_guard"]["config"] is strict
    assert second.extensions["flaskapi_guard"]["config"] is lax
    assert guard.config is strict


def test_a_second_app_without_a_config_takes_the_extensions_config() -> None:
    config = _config(rate_limit=2)
    guard = FlaskAPIGuard(config=config)
    first, second = _app(), _app()

    guard.init_app(first)
    guard.init_app(second)

    assert _codes(first, 3) == [200, 200, 429]
    assert second.extensions["flaskapi_guard"]["config"] is config


def test_the_extensions_decorator_setter_reaches_every_app() -> None:
    config = _config()
    decorator = SecurityDecorator(config)
    guard = FlaskAPIGuard()
    apps = (_app(decorator), _app(decorator))
    for app in apps:
        guard.init_app(app, config=config)
    guard.set_decorator_handler(decorator)

    assert [_codes(app, 2) for app in apps] == [[200, 429], [200, 429]]
