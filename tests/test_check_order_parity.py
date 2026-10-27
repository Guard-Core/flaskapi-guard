import pytest
from flask import Flask
from guard_core.sync.core.checks import DEFAULT_CHECK_CLASSES
from guard_core.sync.handlers.ratelimit_handler import _managers, _managers_lock
from guard_core.sync.protocols.request_protocol import SyncGuardRequest

from flaskapi_guard import FlaskAPIGuard, SecurityConfig, SecurityDecorator
from flaskapi_guard.extension import _config_and_logger_resolved

BANNED_IP = "10.0.0.99"
OTHER_IP = "10.0.0.7"
PROXY = "127.0.0.1"


@pytest.fixture(autouse=True)
def reset_rate_limit_singleton() -> None:
    with _managers_lock:
        _managers.clear()


def _guarded_app() -> tuple[Flask, FlaskAPIGuard]:
    config = SecurityConfig[SyncGuardRequest](
        blacklist=(BANNED_IP,),
        trusted_proxies=(PROXY,),
        enable_redis=False,
        enable_penetration_detection=False,
        enable_cors=True,
        cors_allow_origins=["https://app.example.com"],
    )
    decorator = SecurityDecorator(config)
    app = Flask(__name__)

    @app.route("/needs-header")
    @decorator.require_headers({"X-Client-ID": "required"})
    def needs_header() -> dict[str, str]:
        return {"ok": "yes"}

    @app.route("/limited-and-authed")
    @decorator.rate_limit(requests=1, window=60)
    @decorator.require_auth()
    def limited_and_authed() -> dict[str, str]:
        return {"ok": "yes"}

    guard = FlaskAPIGuard(app, config=config)
    guard.set_decorator_handler(decorator)
    return app, guard


def test_a_banned_ip_without_a_required_header_gets_the_ban_answer() -> None:
    app, _ = _guarded_app()
    client = app.test_client()

    banned = client.get("/needs-header", headers={"X-Forwarded-For": BANNED_IP})
    missing_header = client.get("/needs-header", headers={"X-Forwarded-For": OTHER_IP})

    assert banned.status_code == 403
    assert missing_header.status_code == 400


def test_a_request_over_the_rate_limit_that_fails_authentication_gets_429() -> None:
    app, _ = _guarded_app()
    client = app.test_client()
    headers = {"X-Forwarded-For": OTHER_IP}

    first = client.get("/limited-and-authed", headers=headers)
    second = client.get("/limited-and-authed", headers=headers)

    assert first.status_code == 401
    assert second.status_code == 429


def test_the_pipeline_keeps_the_engine_default_order_and_cors_preflight() -> None:
    _, guard = _guarded_app()
    middleware = guard
    assert _config_and_logger_resolved(middleware)
    engine_order = [cls(middleware).check_name for cls in DEFAULT_CHECK_CLASSES]

    assert guard.security_pipeline is not None
    names = guard.security_pipeline.get_check_names()
    assert "cors_preflight" in names
    assert names == [name for name in engine_order if name in names]
