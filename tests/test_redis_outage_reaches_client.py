"""D-188 end to end: a runtime Redis outage reaches the Flask client as 503
with Retry-After.

Real Flask test client and the real engine. Only the Redis client the engine
holds is replaced, by one whose commands raise redis' own ConnectionError.
"""

from typing import Any

import pytest
from flask import Flask
from flask.testing import FlaskClient
from guard_core.sync.protocols.request_protocol import SyncGuardRequest
from redis.exceptions import ConnectionError as RedisConnectionError

from flaskapi_guard import SecurityConfig
from flaskapi_guard.extension import FlaskAPIGuard
from tests.redis_isolation import REDIS_PREFIX, REDIS_URL


class _DeadRedis:
    def __getattr__(self, name: str) -> Any:
        def command(*args: Any, **kwargs: Any) -> Any:
            raise RedisConnectionError("Redis went away")

        return command


def _client_after_redis_died(**overrides: Any) -> FlaskClient:
    settings: dict[str, Any] = {
        "enable_redis": True,
        "redis_url": REDIS_URL,
        "redis_prefix": f"{REDIS_PREFIX}wp192:",
        "fail_secure": True,
        "redis_fail_open": False,
        "enable_penetration_detection": False,
        "exclude_paths": ["/health"],
    }
    settings.update(overrides)
    config = SecurityConfig[SyncGuardRequest](**settings)
    app = Flask(__name__)
    app.config["TESTING"] = True
    guard = FlaskAPIGuard(app, config=config)

    @app.route("/open")
    def open_() -> dict[str, str]:
        return {"message": "ok"}

    @app.route("/health")
    def health() -> dict[str, str]:
        return {"message": "ok"}

    client = app.test_client()
    assert client.get("/open").status_code == 200
    assert guard.redis_handler is not None
    guard.redis_handler._redis = _DeadRedis()
    return client


@pytest.mark.parametrize("path", ["/open", "/health"])
def test_runtime_outage_answers_503_with_retry_after(path: str) -> None:
    response = _client_after_redis_died().get(path)
    assert response.status_code == 503
    assert response.headers.get("Retry-After") == "5"


@pytest.mark.parametrize("path", ["/open", "/health"])
def test_passive_mode_admits_during_a_runtime_outage(path: str) -> None:
    assert _client_after_redis_died(passive_mode=True).get(path).status_code == 200


@pytest.mark.parametrize("path", ["/open", "/health"])
def test_redis_fail_open_admits_during_a_runtime_outage(path: str) -> None:
    assert _client_after_redis_died(redis_fail_open=True).get(path).status_code == 200
