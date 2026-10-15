"""Engine parity: the adapter routes through the engine exactly like fastapi-guard.

Real Flask test client, real engine bypass handler and response factory. The
metrics collector is spied on (it still runs) to prove which responses reach
the engine response pass.
"""

from typing import Any

from flask import Flask
from guard_core.protocols.response_protocol import GuardResponse
from guard_core.sync.handlers.ipban_handler import reset_global_state

from flaskapi_guard import SecurityConfig, SecurityDecorator
from flaskapi_guard.extension import FlaskAPIGuard

NO_CLIENT: dict[str, Any] = {"REMOTE_ADDR": None}


def _build(
    **overrides: Any,
) -> tuple[Flask, FlaskAPIGuard, list[str]]:
    base: dict[str, Any] = {
        "enable_redis": False,
        "enable_penetration_detection": False,
        "whitelist": None,
        "blacklist": [],
        "exclude_paths": ["/health"],
        "security_headers": {"enabled": True},
    }
    base.update(overrides)
    config = SecurityConfig(**base)
    app = Flask(__name__)
    app.config["TESTING"] = True
    guard = FlaskAPIGuard(app, config=config)
    sec = SecurityDecorator(config)
    guard.set_decorator_handler(sec)
    metrics: list[str] = []
    assert guard.metrics_collector is not None
    real = guard.metrics_collector.collect_request_metrics

    def spy(request: Any, response_time: float, status_code: int) -> None:
        metrics.append(request.url_path)
        real(request, response_time, status_code)

    guard.metrics_collector.collect_request_metrics = spy  # type: ignore[method-assign]

    @app.route("/health")
    def health() -> dict[str, str]:
        return {"message": "ok"}

    @app.route("/open")
    def open_() -> dict[str, str]:
        return {"message": "Echo response"}

    @app.route("/bypassed")
    @sec.bypass(["all"])
    def bypassed() -> dict[str, str]:
        return {"message": "real view"}

    return app, guard, metrics


def test_excluded_path_reaches_view_with_scoped_checks_and_response_pass() -> None:
    app, _guard, metrics = _build(blacklist=["10.9.9.9"])
    client = app.test_client()

    ok = client.get("/health")
    assert ok.status_code == 200
    assert ok.get_json() == {"message": "ok"}
    assert ok.headers.get("X-Content-Type-Options") == "nosniff"
    assert metrics == ["/health"]

    blocked = client.get("/health", environ_overrides={"REMOTE_ADDR": "10.9.9.9"})
    assert blocked.status_code == 403
    assert metrics == ["/health"]


def test_no_client_address_gets_fail_secure_403_by_default() -> None:
    app, _guard, metrics = _build()
    client = app.test_client()

    resp = client.get("/open", environ_overrides=NO_CLIENT)

    assert resp.status_code == 403
    assert "Client address could not be determined" in resp.get_data(as_text=True)
    assert metrics == []


def test_no_client_address_on_excluded_path_is_scoped_not_bypassed() -> None:
    app, _guard, metrics = _build()
    client = app.test_client()

    resp = client.get("/health", environ_overrides=NO_CLIENT)

    assert resp.status_code == 200
    assert metrics == ["/health"]


def test_no_client_address_fail_secure_false_runs_the_pipeline() -> None:
    app, _guard, metrics = _build(fail_secure=False)
    client = app.test_client()

    resp = client.get("/open", environ_overrides=NO_CLIENT)

    assert resp.status_code == 200
    assert metrics == ["/open"]


def test_route_bypass_reaches_real_view_and_skips_response_pass() -> None:
    seen: list[int] = []

    def modifier(response: GuardResponse) -> GuardResponse:
        seen.append(response.status_code)
        response.headers["X-Modified"] = "1"
        return response

    app, _guard, metrics = _build(custom_response_modifier=modifier)
    client = app.test_client()

    resp = client.get("/bypassed")

    assert resp.status_code == 200
    assert resp.get_json() == {"message": "real view"}
    assert resp.headers["X-Modified"] == "1"
    assert seen == [200]
    assert metrics == []
    assert "X-Content-Type-Options" not in resp.headers


def test_blocked_request_emits_no_request_metrics() -> None:
    app, _guard, metrics = _build(blacklist=["10.9.9.9"])
    client = app.test_client()

    blocked = client.get("/open", environ_overrides={"REMOTE_ADDR": "10.9.9.9"})
    assert blocked.status_code == 403
    assert metrics == []

    allowed = client.get("/open")
    assert allowed.status_code == 200
    assert metrics == ["/open"]


def test_preflight_emits_no_request_metrics() -> None:
    app, _guard, metrics = _build(
        enable_cors=True, cors_allow_origins=["https://example.com"]
    )
    client = app.test_client()

    resp = client.options(
        "/open",
        headers={
            "Origin": "https://example.com",
            "Access-Control-Request-Method": "GET",
        },
    )

    assert resp.status_code == 200
    assert resp.headers["Access-Control-Allow-Origin"] == "https://example.com"
    assert metrics == []


def test_global_behavior_return_rule_fires() -> None:
    reset_global_state()
    app, _guard, _metrics = _build(
        behavior_scan_response_body=True,
        global_behavior_rules=[
            {
                "rule_type": "return_pattern",
                "threshold": 2,
                "window": 60,
                "pattern": "json:message==Echo response",
                "action": "ban",
                "ban_duration": 30,
            }
        ],
    )
    client = app.test_client()

    remote = {"REMOTE_ADDR": "203.0.113.9"}
    codes: list[int] = [
        client.get("/open", environ_overrides=remote).status_code for _ in range(5)
    ]

    assert codes[0] == 200
    assert 403 in codes
