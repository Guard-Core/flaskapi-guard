"""LEDGER 6.793 / D-317 amendment 2: a request on an app that was released rebinds
and initializes it before it decides, once, whatever the number of first requests."""

import threading
import time
import uuid
from typing import Any

import pytest
from flask import Flask
from guard_core.models import SecurityConfig
from guard_core.sync.core.checks.implementations.rate_limit import RateLimitCheck
from guard_core.sync.handlers import ipban_handler as ipban_module
from guard_core.sync.handlers._ipban_bans import _VERSION_PAIR
from guard_core.sync.handlers.ipban_handler import ip_ban_manager_for
from guard_core.sync.handlers.redis_handler import RedisManager
from guard_core.sync.protocols.request_protocol import SyncGuardRequest

from flaskapi_guard import FlaskAPIGuard, release_app
from tests.redis_isolation import REDIS_PREFIX, REDIS_URL

CLIENT_IP = "203.0.113.9"


def _config(**overrides: Any) -> SecurityConfig[SyncGuardRequest]:
    settings: dict[str, Any] = {"enable_redis": False, "enable_agent": False}
    settings.update(overrides)
    return SecurityConfig[SyncGuardRequest](**settings)


def _app(config: SecurityConfig[SyncGuardRequest]) -> tuple[Flask, FlaskAPIGuard]:
    app = Flask(__name__)
    guard = FlaskAPIGuard(app, config=config)

    @app.route("/")
    def root() -> dict[str, bool]:
        return {"ok": True}

    return app, guard


def _get(app: Flask) -> int:
    return (
        app.test_client().get("/", environ_base={"REMOTE_ADDR": CLIENT_IP}).status_code
    )


def _limiter_managers(guard: FlaskAPIGuard) -> list[Any]:
    assert guard.security_pipeline is not None
    return [
        check.ip_ban_manager
        for check in guard.security_pipeline.checks
        if isinstance(check, RateLimitCheck)
    ]


def test_a_late_request_rebinds_and_its_ban_lands_on_its_own_manager() -> None:
    config = _config()
    app, guard = _app(config)
    other_config = _config()
    assert _get(app) == 200
    release_app(config)
    assert ip_ban_manager_for(other_config, bind=True) is ipban_module.ip_ban_manager
    try:
        assert _get(app) == 200
        own = ip_ban_manager_for(config)
        assert own is not ipban_module.ip_ban_manager
        managers = _limiter_managers(guard)
        assert managers
        assert all(manager is own for manager in managers)
        managers[0].ban_ip("198.51.100.7", 60, "pin")
        assert own.is_ip_banned("198.51.100.7")
        assert not ipban_module.ip_ban_manager.is_ip_banned("198.51.100.7")
    finally:
        release_app(other_config)


def test_two_concurrent_first_requests_after_a_release_initialize_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config()
    app, guard = _app(config)
    assert _get(app) == 200
    assert guard.handler_initializer is not None
    calls: list[float] = []

    def counted_initialize() -> None:
        calls.append(time.monotonic())
        time.sleep(0.1)

    monkeypatch.setattr(
        guard.handler_initializer, "initialize_redis_handlers", counted_initialize
    )
    release_app(config)
    barrier = threading.Barrier(2)
    statuses: list[int] = []

    def first_request() -> None:
        barrier.wait()
        statuses.append(_get(app))

    threads = [threading.Thread(target=first_request) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert statuses == [200, 200]
    assert len(calls) == 1


def test_a_ban_another_worker_wrote_in_redis_is_refused_after_a_release() -> None:
    prefix = f"{REDIS_PREFIX}wp620r3:{uuid.uuid4().hex[:8]}:"
    config = _config(enable_redis=True, redis_url=REDIS_URL, redis_prefix=prefix)
    app, _guard = _app(config)
    assert _get(app) == 200
    release_app(config)
    worker = RedisManager(
        SecurityConfig[SyncGuardRequest](
            enable_redis=True,
            redis_url=REDIS_URL,
            redis_prefix=prefix,
            enable_agent=False,
        )
    )
    worker.initialize()
    try:
        worker.write_ban_extending_only(
            "banned_ips", CLIENT_IP, str(time.time() + 300), 300, version=_VERSION_PAIR
        )
        assert _get(app) == 403
        assert ip_ban_manager_for(config).redis_handler is not None
    finally:
        worker.close()
