import gc
from collections.abc import Iterator

import pytest
from flask import Flask
from guard_core.models import SecurityConfig
from guard_core.sync.core.checks.implementations.rate_limit import RateLimitCheck
from guard_core.sync.handlers import ipban_handler as ipban_module
from guard_core.sync.handlers.ipban_handler import ip_ban_manager_for
from guard_core.sync.protocols.request_protocol import SyncGuardRequest

import flaskapi_guard
from flaskapi_guard import FlaskAPIGuard, release_app

_REQUESTS = 25


def _config() -> SecurityConfig[SyncGuardRequest]:
    return SecurityConfig[SyncGuardRequest](enable_redis=False)


def _app(config: SecurityConfig[SyncGuardRequest]) -> Flask:
    app = Flask(__name__)
    FlaskAPIGuard(app, config=config)

    @app.route("/")
    def root() -> dict[str, bool]:
        return {"ok": True}

    return app


def _default_ban_manager_serves_a_new_app() -> bool:
    return ip_ban_manager_for(_config(), bind=True) is ipban_module.ip_ban_manager


@pytest.fixture
def collector_off() -> Iterator[None]:
    was_enabled = gc.isenabled()
    gc.disable()
    try:
        yield
    finally:
        if was_enabled:
            gc.enable()


def test_release_app_is_the_engines_function_for_a_host_to_call() -> None:
    import guard_core.sync

    assert "release_app" in flaskapi_guard.__all__
    assert release_app is guard_core.sync.release_app


@pytest.mark.usefixtures("collector_off")
def test_requests_through_an_app_leave_the_default_binding_unchanged() -> None:
    config = _config()
    app = _app(config)
    assert ip_ban_manager_for(config) is ipban_module.ip_ban_manager
    with app.test_client() as client:
        for _ in range(_REQUESTS):
            client.get("/")
    assert ip_ban_manager_for(config) is ipban_module.ip_ban_manager
    assert not _default_ban_manager_serves_a_new_app()


@pytest.mark.usefixtures("collector_off")
def test_a_host_release_hands_the_default_to_the_next_app() -> None:
    config = _config()
    app = _app(config)
    with app.test_client() as client:
        client.get("/")
    release_app(config)
    assert _default_ban_manager_serves_a_new_app()


@pytest.mark.usefixtures("collector_off")
def test_an_app_that_is_never_released_keeps_its_default_until_it_is_collected() -> (
    None
):
    app = _app(_config())
    with app.test_client() as client:
        client.get("/")
    assert not _default_ban_manager_serves_a_new_app()
    assert app is not None


def test_the_config_is_bound_before_the_pipeline_is_built() -> None:
    _app(_config())
    second_config = _config()
    second = Flask(__name__)
    guard = FlaskAPIGuard(second, config=second_config)
    assert guard.security_pipeline is not None
    limiters = [
        check
        for check in guard.security_pipeline.checks
        if isinstance(check, RateLimitCheck)
    ]
    own = ip_ban_manager_for(second_config)
    assert own is not ipban_module.ip_ban_manager
    assert limiters
    assert all(limiter.ip_ban_manager is own for limiter in limiters)
