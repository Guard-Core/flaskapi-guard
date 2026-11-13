import logging

import pytest
from flask import Flask
from guard_core.sync.protocols.request_protocol import SyncGuardRequest

from flaskapi_guard import SecurityConfig, SecurityDecorator
from flaskapi_guard.extension import FlaskAPIGuard


def test_decorator_false_under_middleware_true_starts_and_answers(
    caplog: pytest.LogCaptureFixture,
) -> None:
    middleware_config = SecurityConfig[SyncGuardRequest](
        enable_redis=False,
        enable_penetration_detection=False,
        fail_on_misconfiguration=True,
        trusted_proxies=("127.0.0.1",),
    )
    decorator = SecurityDecorator(
        SecurityConfig[SyncGuardRequest](
            enable_redis=False, fail_on_misconfiguration=False
        )
    )
    app = Flask(__name__)

    @app.route("/geo")
    @decorator.block_countries(["CN"])
    def geo_endpoint() -> dict[str, str]:
        return {"route": "ok"}

    with caplog.at_level(logging.WARNING, logger="guard_core"):
        guard = FlaskAPIGuard(app, config=middleware_config)
        guard.set_decorator_handler(decorator)
        reported_before_any_request = caplog.text.count("no GeoIP database")
        with app.test_client() as client:
            headers = {"X-Forwarded-For": "203.0.113.5"}
            first = client.get("/geo", headers=headers)
            second = client.get("/geo", headers=headers)

    assert (first.status_code, second.status_code) == (200, 200)
    assert reported_before_any_request == 1
    assert caplog.text.count("no GeoIP database") == 1
