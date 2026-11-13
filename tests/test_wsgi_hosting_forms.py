from typing import Any

from flask import Flask
from guard_core.sync.protocols.request_protocol import SyncGuardRequest
from werkzeug.middleware.dispatcher import DispatcherMiddleware
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.test import Client

from flaskapi_guard import FlaskAPIGuard, SecurityConfig


def _config(**overrides: Any) -> SecurityConfig[SyncGuardRequest]:
    fields: dict[str, Any] = {
        "enable_redis": False,
        "enable_agent": False,
        "enable_penetration_detection": False,
        "fail_on_misconfiguration": False,
        "rate_limit": 1000,
        "trusted_proxies": [],
    }
    fields.update(overrides)
    return SecurityConfig[SyncGuardRequest](**fields)


def _app(config: SecurityConfig[SyncGuardRequest]) -> Flask:
    app = Flask(__name__)
    app.config["TESTING"] = True

    @app.route("/ok")
    def ok() -> str:
        return "ok"

    FlaskAPIGuard(app, config=config)
    return app


def test_head_is_guarded_and_answers_without_a_body() -> None:
    app = _app(_config(blacklist=["203.0.113.9"]))
    client = app.test_client()

    allowed = client.head("/ok", environ_overrides={"REMOTE_ADDR": "198.51.100.4"})
    blocked = client.head("/ok", environ_overrides={"REMOTE_ADDR": "203.0.113.9"})

    assert (allowed.status_code, allowed.data) == (200, b"")
    assert (blocked.status_code, blocked.data) == (403, b"")


def test_the_client_ip_proxyfix_resolved_is_the_one_the_guard_checks() -> None:
    app = _app(_config(blacklist=["203.0.113.9"]))
    client = Client(ProxyFix(app.wsgi_app, x_for=1))

    blocked = client.get(
        "/ok",
        headers={"X-Forwarded-For": "203.0.113.9"},
        environ_overrides={"REMOTE_ADDR": "10.0.0.1"},
    )
    allowed = client.get(
        "/ok",
        headers={"X-Forwarded-For": "198.51.100.4"},
        environ_overrides={"REMOTE_ADDR": "10.0.0.1"},
    )

    assert (blocked.status_code, allowed.status_code) == (403, 200)


def test_an_app_mounted_under_a_prefix_is_guarded_and_routed() -> None:
    app = _app(_config(blacklist=["203.0.113.9"]))
    root = Flask("root")
    mounted = Client(DispatcherMiddleware(root, {"/api": app}))

    allowed = mounted.get("/api/ok", environ_overrides={"REMOTE_ADDR": "198.51.100.4"})
    blocked = mounted.get("/api/ok", environ_overrides={"REMOTE_ADDR": "203.0.113.9"})

    assert (allowed.status_code, blocked.status_code) == (200, 403)
