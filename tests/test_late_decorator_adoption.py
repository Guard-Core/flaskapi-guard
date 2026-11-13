import uuid
from typing import Any

import pytest
from flask import Flask
from guard_core.exceptions import MisconfigurationError
from guard_core.sync.handlers.ipban_handler import ip_ban_manager, ip_ban_manager_for
from guard_core.sync.protocols.request_protocol import SyncGuardRequest

from flaskapi_guard import SecurityConfig, SecurityDecorator
from flaskapi_guard.extension import FlaskAPIGuard
from tests.redis_isolation import REDIS_PREFIX, REDIS_URL

PEER = "203.0.113.9"
HEADERS = {"X-Forwarded-For": PEER}


def _config(**overrides: Any) -> SecurityConfig[SyncGuardRequest]:
    fields: dict[str, Any] = {
        "enable_redis": False,
        "enable_agent": False,
        "enable_penetration_detection": False,
        "rate_limit": 1000,
        "trusted_proxies": ["127.0.0.1"],
    }
    fields.update(overrides)
    return SecurityConfig[SyncGuardRequest](**fields)


def _app(
    config: SecurityConfig[SyncGuardRequest], decorator: SecurityDecorator
) -> tuple[Flask, FlaskAPIGuard]:
    app = Flask(__name__)
    app.config["TESTING"] = True

    @app.route("/plain")
    def plain() -> dict[str, str]:
        return {"ok": "plain"}

    @app.route("/counted")
    @decorator.usage_monitor(max_calls=1, window=60, action="ban")
    def counted() -> dict[str, str]:
        return {"ok": "counted"}

    @app.route("/by-country")
    @decorator.block_countries(["XX"])
    def by_country() -> dict[str, str]:
        return {"ok": "country"}

    return app, FlaskAPIGuard(app, config=config)


def _started(
    config: SecurityConfig[SyncGuardRequest], decorator: SecurityDecorator
) -> tuple[Any, FlaskAPIGuard]:
    app, guard = _app(config, decorator)
    client = app.test_client()
    assert client.get("/plain", headers=HEADERS).status_code == 200
    return client, guard


def _quiet_decorator() -> SecurityDecorator:
    return SecurityDecorator(SecurityConfig(fail_on_misconfiguration=False))


def test_a_ban_rule_of_a_late_decorator_bans_on_the_apps_ban_manager() -> None:
    decorator = SecurityDecorator(SecurityConfig(fail_on_misconfiguration=False))
    first = _config()
    _started(first, _quiet_decorator())
    config = _config()
    client, guard = _started(config, decorator)
    apps_manager = ip_ban_manager_for(config)
    assert apps_manager is not ip_ban_manager

    guard.set_decorator_handler(decorator)
    statuses = [client.get("/counted", headers=HEADERS).status_code for _ in range(3)]

    assert statuses[0] == 200
    assert apps_manager.is_ip_banned(PEER)
    assert decorator.behavior_tracker.bound_ban_manager is apps_manager


def test_a_late_decorators_rule_counts_on_the_decorators_tracker_only() -> None:
    decorator = _quiet_decorator()
    client, guard = _started(_config(), decorator)

    guard.set_decorator_handler(decorator)
    assert client.get("/counted", headers=HEADERS).status_code == 200

    initializer = guard.handler_initializer
    assert initializer is not None
    assert guard.behavioral_processor is not None
    held = guard.behavioral_processor.context.behavior_tracker
    assert held in (None, decorator.behavior_tracker)
    assert initializer.behavior_tracker in (None, decorator.behavior_tracker)
    assert any(decorator.behavior_tracker.usage_counts.values())


def test_a_late_decorators_tracker_gets_redis_once_adoption_completed() -> None:
    config = _config(
        enable_redis=True,
        redis_url=REDIS_URL,
        redis_prefix=f"{REDIS_PREFIX}wp779{uuid.uuid4().hex[:8]}:",
    )
    decorator = _quiet_decorator()
    client, guard = _started(config, decorator)

    guard.set_decorator_handler(decorator)
    assert client.get("/plain", headers=HEADERS).status_code == 200

    initializer = guard.handler_initializer
    assert initializer is not None
    assert decorator.behavior_tracker.redis_handler is initializer.redis_handler
    assert decorator.behavior_tracker.redis_handler is not None


def test_a_route_country_rule_of_a_late_decorator_builds_the_geo_handler() -> None:
    decorator = _quiet_decorator()
    app, guard = _app(_config(ipinfo_token="test_token"), decorator)
    guard.set_decorator_handler(None)
    assert app.test_client().get("/plain", headers=HEADERS).status_code == 200
    before = guard.geo_ip_handler

    guard.set_decorator_handler(decorator)

    initializer = guard.handler_initializer
    assert initializer is not None
    assert before is None
    assert guard.geo_ip_handler is initializer.geo_ip_handler
    assert guard.geo_ip_handler is not None


def test_a_raise_in_the_adoption_leaves_the_previous_decorator_bound() -> None:
    candidate = _quiet_decorator()
    _, guard = _started(_config(), candidate)
    previous = SecurityDecorator(SecurityConfig())
    guard.set_decorator_handler(previous)
    candidate.config.fail_on_misconfiguration = True

    with pytest.raises(MisconfigurationError):
        guard.set_decorator_handler(candidate)

    initializer = guard.handler_initializer
    assert initializer is not None
    assert guard.guard_decorator is previous
    assert initializer.guard_decorator is previous
    assert guard.route_resolver is not None
    assert guard.route_resolver.context.guard_decorator is previous
    assert guard.response_factory is not None
    assert guard.response_factory.context.guard_decorator is previous
    assert guard.behavioral_processor is not None
    assert guard.behavioral_processor.context.guard_decorator is previous
    assert guard._app is not None
    assert guard._app.extensions["flaskapi_guard"]["guard_decorator"] is previous
