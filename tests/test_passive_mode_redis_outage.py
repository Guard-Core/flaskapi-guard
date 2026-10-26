import logging
from collections.abc import Generator
from unittest.mock import patch

import pytest
from flask import Flask
from guard_core.exceptions import GuardRedisError
from guard_core.models import SecurityConfig
from guard_core.sync.handlers.redis_handler import RedisManager
from guard_core.sync.protocols.request_protocol import SyncGuardRequest

from flaskapi_guard import FlaskAPIGuard
from flaskapi_guard import extension as extension_module

INIT_OUTAGE_LINE = "Redis unavailable during initialization"


@pytest.fixture(autouse=True)
def _reset_outage_samples() -> Generator[None, None, None]:
    extension_module._init_outage_samples.clear()
    yield
    extension_module._init_outage_samples.clear()


def _app(passive_mode: bool) -> Flask:
    config = SecurityConfig[SyncGuardRequest](
        enable_redis=True,
        enable_penetration_detection=False,
        passive_mode=passive_mode,
    )
    app = Flask(__name__)

    @app.route("/")
    def read_root() -> dict[str, str]:
        return {"message": "Hello World"}

    FlaskAPIGuard(app, config=config)
    return app


def _dead_initialize(self: RedisManager) -> None:
    raise GuardRedisError(503, "Redis connection failed")


def test_passive_cold_start_with_redis_down_admits_http_and_logs_once(
    caplog: pytest.LogCaptureFixture,
) -> None:
    app = _app(passive_mode=True)

    with patch.object(RedisManager, "initialize", _dead_initialize):
        with caplog.at_level(logging.ERROR):
            with app.test_client() as client:
                responses = [client.get("/") for _ in range(3)]

    assert [r.status_code for r in responses] == [200, 200, 200]
    assert "Retry-After" not in responses[0].headers
    lines = [
        r
        for r in caplog.records
        if INIT_OUTAGE_LINE in r.getMessage() and "passive_mode" in r.getMessage()
    ]
    assert len(lines) == 1


def test_not_passive_cold_start_with_redis_down_keeps_503_with_retry_after() -> None:
    app = _app(passive_mode=False)

    with patch.object(RedisManager, "initialize", _dead_initialize):
        with app.test_client() as client:
            response = client.get("/")

    assert response.status_code == 503
    assert response.headers["Retry-After"] == "5"
