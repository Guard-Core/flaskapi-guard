from flask import Flask
from guard_core.sync._utils.app_scope import _current_app_scope, app_scope_of
from guard_core.sync.protocols.request_protocol import SyncGuardRequest

from flaskapi_guard import FlaskAPIGuard, SecurityConfig, SecurityDecorator


def _config() -> SecurityConfig[SyncGuardRequest]:
    return SecurityConfig[SyncGuardRequest](enable_redis=False, rate_limit=100000)


def test_a_bypass_view_runs_inside_its_own_apps_scope() -> None:
    seen: dict[str, object] = {}

    def make(name: str) -> tuple[Flask, SecurityConfig[SyncGuardRequest]]:
        app = Flask(name)
        config = _config()
        decorator = SecurityDecorator(config)
        guard = FlaskAPIGuard(app, config=config)
        guard.set_decorator_handler(decorator)

        @app.get("/bypassed")
        @decorator.bypass(["all"])
        def bypassed() -> str:
            seen[name] = _current_app_scope.get()
            return "ok"

        return app, config

    app_a, config_a = make("a")
    app_b, config_b = make("b")

    assert app_a.test_client().get("/bypassed").status_code == 200
    assert app_b.test_client().get("/bypassed").status_code == 200

    assert seen["a"] is app_scope_of(config_a)
    assert seen["b"] is app_scope_of(config_b)
    assert _current_app_scope.get() is None
