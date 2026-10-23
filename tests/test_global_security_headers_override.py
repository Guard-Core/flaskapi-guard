import os
from collections.abc import Generator

import pytest
from flask import Flask
from guard_core.sync.handlers.security_headers_handler import security_headers_manager
from guard_core.sync.protocols.request_protocol import SyncGuardRequest

from flaskapi_guard import FlaskAPIGuard, SecurityConfig

APP_CSP = {"default-src": ["'self'", "https://app.example"]}
GLOBAL_CSP = {"default-src": ["'self'", "https://global.example"]}
REDIS_URL = os.getenv("REDIS_URL") or "redis://localhost:6379"


@pytest.fixture(autouse=True)
def _clean_global_manager() -> Generator[None, None, None]:
    security_headers_manager.reset()
    yield
    security_headers_manager.reset()


def _config(**overrides: object) -> SecurityConfig[SyncGuardRequest]:
    values: dict[str, object] = {
        "enable_redis": False,
        "enable_rate_limiting": False,
        "enable_ip_banning": False,
        "security_headers": {
            "enabled": True,
            "csp": APP_CSP,
            "frame_options": "DENY",
        },
    }
    values.update(overrides)
    return SecurityConfig[SyncGuardRequest](**values)  # type: ignore[arg-type]


def _app(config: SecurityConfig[SyncGuardRequest]) -> tuple[Flask, FlaskAPIGuard]:
    app = Flask(__name__)
    guard = FlaskAPIGuard(app, config=config)

    @app.route("/x")
    def x() -> dict[str, bool]:
        return {"ok": True}

    @app.route("/y")
    def y() -> dict[str, bool]:
        return {"ok": True}

    return app, guard


def test_the_global_configure_reaches_a_guarded_app() -> None:
    app, _ = _app(_config())
    client = app.test_client()
    assert client.get("/x").headers["Content-Security-Policy"].endswith("app.example")

    security_headers_manager.configure(csp=GLOBAL_CSP, override_apps=True)

    for path in ("/x", "/y"):
        response = client.get(path)
        assert response.headers["Content-Security-Policy"] == (
            "default-src 'self' https://global.example"
        )
        assert response.headers["X-Frame-Options"] == "DENY"


def test_without_a_global_call_the_app_keeps_its_own_config() -> None:
    app, _ = _app(_config())

    response = app.test_client().get("/x")

    assert response.headers["Content-Security-Policy"].endswith("app.example")


def test_the_response_manager_reaches_the_redis_of_its_app() -> None:
    _, guard = _app(_config(enable_redis=True, redis_url=REDIS_URL))

    assert guard.redis_handler is not None
    assert guard.response_factory is not None
    assert guard.response_factory.security_headers_manager.redis_handler is (
        guard.redis_handler
    )


def test_building_a_second_app_does_not_override_the_first() -> None:
    first, _ = _app(_config())
    second, _ = _app(_config(security_headers={"enabled": True, "csp": GLOBAL_CSP}))
    first_client, second_client = first.test_client(), second.test_client()
    first_client.get("/x")
    second_client.get("/x")

    assert (
        first_client.get("/x")
        .headers["Content-Security-Policy"]
        .endswith("app.example")
    )
    assert (
        second_client.get("/x")
        .headers["Content-Security-Policy"]
        .endswith("global.example")
    )


def test_a_call_without_override_apps_does_not_reach_a_guarded_app() -> None:
    app, _ = _app(_config())
    client = app.test_client()
    client.get("/x")

    security_headers_manager.configure(csp=GLOBAL_CSP)

    assert client.get("/x").headers["Content-Security-Policy"].endswith("app.example")
