import itertools
from typing import Any
from unittest.mock import Mock

import pytest
from flask import Flask
from guard_core.models import BehaviorRuleConfig
from guard_core.sync.handlers.behavior_handler import BehaviorRule
from guard_core.sync.protocols.request_protocol import SyncGuardRequest

from flaskapi_guard import SecurityConfig, SecurityDecorator
from flaskapi_guard.extension import FlaskAPIGuard

_IPS = itertools.count(1)


def _config(**overrides: Any) -> SecurityConfig[SyncGuardRequest]:
    fields: dict[str, Any] = {
        "enable_redis": False,
        "enable_penetration_detection": False,
        "enable_rate_limiting": False,
        "enable_ip_banning": True,
        "trusted_proxies": ["127.0.0.1"],
        "ban_on_hostile_signals": False,
    }
    fields.update(overrides)
    return SecurityConfig[SyncGuardRequest](**fields)


def _app(config: SecurityConfig[SyncGuardRequest]) -> Flask:
    app = Flask(__name__)
    app.config["TESTING"] = True
    decorator = SecurityDecorator(config)

    @app.route("/limited")
    @decorator.usage_monitor(max_calls=2, window=60, action="throttle")
    def limited() -> dict[str, bool]:
        return {"ok": True}

    @app.route("/missing")
    def missing() -> tuple[dict[str, str], int]:
        return {"error": "gone"}, 404

    @app.route("/ping")
    def ping() -> dict[str, bool]:
        return {"ok": True}

    guard = FlaskAPIGuard(app, config=config)
    guard.set_decorator_handler(decorator)
    return app


def _responses(
    config: SecurityConfig[SyncGuardRequest], paths: list[str]
) -> list[tuple[int, Any]]:
    client = _app(config).test_client()
    ip = f"198.51.100.{next(_IPS)}"
    responses = [client.get(path, headers={"X-Forwarded-For": ip}) for path in paths]
    return [(r.status_code, r.headers.get("Retry-After")) for r in responses]


def test_route_throttle_answers_429_with_retry_after() -> None:
    responses = _responses(_config(), ["/limited"] * 4)
    assert [status for status, _ in responses] == [200, 200, 429, 429]
    assert [retry is None for _, retry in responses] == [True, True, False, False]
    assert all(1 <= int(retry) <= 60 for _, retry in responses[2:])


def test_global_throttle_covers_unrouted_paths() -> None:
    config = _config(
        global_behavior_rules=(
            BehaviorRuleConfig(
                rule_type="usage", threshold=2, window=60, action="throttle"
            ),
        )
    )
    responses = _responses(config, ["/nope-1", "/nope-2", "/nope-3"])
    assert [status for status, _ in responses] == [404, 404, 429]


def test_throttled_requests_still_count_toward_a_global_ban_rule() -> None:
    config = _config(
        global_behavior_rules=(
            BehaviorRuleConfig(rule_type="usage", threshold=3, window=60, action="ban"),
        )
    )
    statuses = [status for status, _ in _responses(config, ["/limited"] * 5)]
    assert statuses == [200, 200, 429, 429, 403]


def test_global_return_rule_halves_its_threshold_after_a_detection_hit() -> None:
    config = _config(
        enable_penetration_detection=True,
        global_behavior_rules=(
            BehaviorRuleConfig(
                rule_type="return_pattern",
                threshold=4,
                window=60,
                pattern="status:404",
                action="ban",
                correlate_with_detection=True,
            ),
        ),
    )
    paths = ["/ping?q=<script>alert(1)</script>"] + ["/missing"] * 4 + ["/ping"]
    statuses = [status for status, _ in _responses(config, paths)]
    assert statuses[1:] == [404, 404, 404, 403, 403]


def test_decorator_usage_rules_wrapper_returns_the_throttle_response() -> None:
    app = Flask(__name__)
    guard = FlaskAPIGuard(app, config=_config())
    request = Mock()
    request.method = "GET"
    request.state.guard_decorator = None
    request.state.guard_route_id = "test.throttled"
    request.state.guard_exclusion_scoped = False
    route_config = Mock()
    route_config.behavior_rules = [
        BehaviorRule("usage", threshold=1, window=60, action="throttle")
    ]
    statuses = []
    for _ in range(2):
        with app.app_context():
            response = guard._process_decorator_usage_rules(
                request, "127.0.0.1", route_config
            )
        statuses.append(None if response is None else response.status_code)
    assert statuses == [None, 429]


@pytest.mark.parametrize("client_ip", ["", "127.0.0.1"])
def test_requests_without_rules_skip_the_usage_call(
    client_ip: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    app = Flask(__name__)
    guard = FlaskAPIGuard(app, config=_config())
    usage = Mock()
    monkeypatch.setattr(guard.behavioral_processor, "process_usage_rules", usage)
    assert guard._process_behavioral_usage(Mock(), client_ip, None) is None
    usage.assert_not_called()


def test_usage_call_refusal_is_answered_with_cors_headers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from flask import Response

    from flaskapi_guard.adapters import FlaskGuardResponse

    app = Flask(__name__)
    decorator = SecurityDecorator(_config())

    @app.route("/limited")
    @decorator.usage_monitor(max_calls=2, window=60, action="throttle")
    def limited() -> dict[str, bool]:
        return {"ok": True}

    guard = FlaskAPIGuard(
        app,
        config=_config(enable_cors=True, cors_allow_origins=["https://example.com"]),
    )
    guard.set_decorator_handler(decorator)
    refusal = FlaskGuardResponse(Response("slow down", status=429))
    usage = Mock(return_value=refusal)
    monkeypatch.setattr(guard.behavioral_processor, "process_usage_rules", usage)

    response = app.test_client().get(
        "/limited", headers={"Origin": "https://example.com"}
    )

    assert response.status_code == 429
    assert response.get_data() == b"slow down"
    assert response.headers["Access-Control-Allow-Origin"] == "https://example.com"
    usage.assert_called_once()
