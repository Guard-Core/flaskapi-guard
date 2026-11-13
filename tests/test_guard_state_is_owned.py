from typing import Any

import pytest
from flask import Flask, g, request
from guard_core.sync.protocols.request_protocol import SyncGuardRequest

from flaskapi_guard import FlaskAPIGuard, SecurityConfig
from flaskapi_guard.adapters import FlaskGuardRequest

PEER = {"X-Forwarded-For": "203.0.113.9"}


def _config(**overrides: Any) -> SecurityConfig[SyncGuardRequest]:
    fields: dict[str, Any] = {
        "enable_redis": False,
        "enable_agent": False,
        "enable_penetration_detection": False,
        "fail_on_misconfiguration": False,
        "rate_limit": 1000,
        "trusted_proxies": ["127.0.0.1"],
    }
    fields.update(overrides)
    return SecurityConfig[SyncGuardRequest](**fields)


def _app(config: SecurityConfig[SyncGuardRequest], **foreign: Any) -> Flask:
    app = Flask(__name__)
    app.config["TESTING"] = True

    @app.before_request
    def another_middleware() -> None:
        for name, value in foreign.items():
            setattr(g, name, value)

    @app.route("/")
    def index() -> str:
        return "ok"

    FlaskAPIGuard(app, config=config)
    return app


def test_a_client_ip_another_hook_put_on_g_does_not_replace_the_resolved_one() -> None:
    config = _config(blacklist=["203.0.113.9"])
    app = _app(config, client_ip="198.51.100.1")

    assert app.test_client().get("/", headers=PEER).status_code == 403


def test_the_resolved_client_ip_is_still_readable_on_g_in_the_view() -> None:
    config = _config()
    app = _app(config, client_ip="198.51.100.1")

    @app.route("/who")
    def who() -> str:
        return str(g.client_ip)

    assert app.test_client().get("/who", headers=PEER).get_data(as_text=True) == (
        "203.0.113.9"
    )


def test_what_the_guard_records_on_the_state_is_mirrored_on_g() -> None:
    app = Flask(__name__)
    with app.test_request_context("/"):
        FlaskGuardRequest(request).state.guard_route_template = "/x"

        assert g.guard_route_template == "/x"
        assert FlaskGuardRequest(request).state.guard_route_template == "/x"


def test_a_state_value_can_be_deleted_from_the_state_and_from_g() -> None:
    app = Flask(__name__)
    with app.test_request_context("/"):
        state = FlaskGuardRequest(request).state
        state.guard_route_id = "x"

        del state.guard_route_id

        assert getattr(state, "guard_route_id", None) is None
        assert "guard_route_id" not in g
        with pytest.raises(AttributeError):
            del state.guard_route_id
