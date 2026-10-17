import itertools
from typing import Any

from flask import Flask
from guard_core.models import BehaviorRuleConfig

from flaskapi_guard import SecurityConfig, SecurityDecorator
from flaskapi_guard.extension import FlaskAPIGuard

_IPS = itertools.count(1)


def _config(**overrides: Any) -> SecurityConfig:
    fields: dict[str, Any] = {
        "enable_redis": False,
        "enable_penetration_detection": False,
        "enable_rate_limiting": False,
        "enable_ip_banning": True,
        "trusted_proxies": ["127.0.0.1"],
        "ban_on_hostile_signals": False,
    }
    fields.update(overrides)
    return SecurityConfig(**fields)


def _app(config: SecurityConfig) -> Flask:
    app = Flask(__name__)
    app.config["TESTING"] = True
    decorator = SecurityDecorator(config)

    @app.route("/missing")
    def missing() -> tuple[dict[str, str], int]:
        return {"error": "gone"}, 404

    @app.route("/ping")
    def ping() -> dict[str, bool]:
        return {"ok": True}

    guard = FlaskAPIGuard(app, config=config)
    guard.set_decorator_handler(decorator)
    return app


def _responses(config: SecurityConfig, paths: list[str]) -> list[tuple[int, Any]]:
    client = _app(config).test_client()
    ip = f"198.51.100.{next(_IPS)}"
    responses = [client.get(path, headers={"X-Forwarded-For": ip}) for path in paths]
    return [(r.status_code, r.headers.get("Retry-After")) for r in responses]


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
