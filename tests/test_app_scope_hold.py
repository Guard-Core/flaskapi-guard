import os
from collections.abc import Iterator
from typing import Any

import pytest
from flask import Flask
from guard_core.sync._utils.app_scope import _current_app_scope, app_scope_of
from guard_core.sync.handlers.ipban_handler import ip_ban_manager_for
from guard_core.sync.protocols.request_protocol import SyncGuardRequest

from flaskapi_guard import FlaskAPIGuard, SecurityConfig

REDIS_URL = os.getenv("REDIS_URL") or "redis://localhost:6379"
PROXY = "10.0.0.1"


def _config(prefix: str, proxies: tuple[str, ...]) -> SecurityConfig[SyncGuardRequest]:
    return SecurityConfig[SyncGuardRequest](
        enable_redis=True,
        redis_url=REDIS_URL,
        redis_prefix=prefix,
        trusted_proxies=proxies,
        enable_rate_limiting=False,
        enable_penetration_detection=False,
    )


def _app(config: SecurityConfig[SyncGuardRequest], seen: dict[str, Any]) -> Flask:
    app = Flask(__name__)
    FlaskAPIGuard(app, config=config)

    @app.get("/ban")
    def ban() -> dict[str, bool]:
        seen["scope"] = _current_app_scope.get()
        seen["banned"] = ip_ban_manager_for(config).ban_ip(PROXY, 60)
        return {"ok": True}

    @app.get("/boom")
    def boom() -> dict[str, bool]:
        raise RuntimeError("view failed")

    return app


@pytest.fixture
def cleanup() -> Iterator[list[SecurityConfig[SyncGuardRequest]]]:
    configs: list[SecurityConfig[SyncGuardRequest]] = []
    yield configs
    for config in configs:
        ip_ban_manager_for(config).unban_ip(PROXY, config=config)


def test_a_ban_in_a_route_handler_goes_through_the_routes_own_app(
    cleanup: list[SecurityConfig[SyncGuardRequest]],
) -> None:
    config_a, config_b = _config("wp136-hold:", (PROXY,)), _config("wp136-hold:", ())
    cleanup.extend([config_a, config_b])
    seen_a: dict[str, Any] = {}
    seen_b: dict[str, Any] = {}
    app_a, app_b = _app(config_a, seen_a), _app(config_b, seen_b)

    assert app_a.test_client().get("/ban").status_code == 200
    assert app_b.test_client().get("/ban").status_code == 200
    assert app_a.test_client().get("/ban").status_code == 200

    assert seen_a["scope"] is app_scope_of(config_a)
    assert seen_b["scope"] is app_scope_of(config_b)
    assert seen_a["banned"] is False
    assert seen_b["banned"] is True
    assert _current_app_scope.get() is None


def test_a_raising_view_leaves_no_scope_for_the_next_request_on_the_thread() -> None:
    app = _app(_config("wp136-boom:", ()), {})
    app.config["PROPAGATE_EXCEPTIONS"] = True

    with pytest.raises(RuntimeError, match="view failed"):
        app.test_client().get("/boom")

    assert _current_app_scope.get() is None


def test_a_nested_app_request_hands_back_the_outer_apps_scope(
    cleanup: list[SecurityConfig[SyncGuardRequest]],
) -> None:
    config_outer, config_inner = (
        _config("wp136-nest:", (PROXY,)),
        _config("wp136-nest:", ()),
    )
    cleanup.extend([config_outer, config_inner])
    inner = _app(config_inner, {})
    seen: dict[str, Any] = {}
    outer = Flask(__name__)
    FlaskAPIGuard(outer, config=config_outer)

    @outer.get("/outer")
    def outer_view() -> dict[str, bool]:
        assert inner.test_client().get("/ban").status_code == 200
        seen["after"] = _current_app_scope.get()
        return {"ok": True}

    assert outer.test_client().get("/outer").status_code == 200

    assert seen["after"] is app_scope_of(config_outer)
    assert _current_app_scope.get() is None
