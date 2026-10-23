from typing import Any

import pytest
from flask import Flask
from flask import request as flask_request
from guard_core.sync.protocols.request_protocol import SyncGuardRequest

from flaskapi_guard import FlaskAPIGuard, SecurityConfig
from flaskapi_guard.adapters import FlaskGuardRequest


def _app_and_extension(
    limits: dict[str, tuple[int, int]],
    config_options: dict[str, Any] | None = None,
    **login_options: Any,
) -> tuple[Flask, FlaskAPIGuard]:
    app = Flask(__name__)
    config = SecurityConfig[SyncGuardRequest](
        enable_redis=False,
        enable_rate_limiting=True,
        rate_limit=1000,
        endpoint_rate_limits=limits,
        passive_mode=False,
        **(config_options or {}),
    )
    extension = FlaskAPIGuard(app, config=config)

    @app.route("/login", methods=["GET", "POST"], **login_options)
    def login() -> str:
        return "login"

    @app.get("/users/<int:user_id>")
    def user(user_id: int) -> str:
        return f"user {user_id}"

    @app.get("/strict/")
    def strict() -> str:
        return "strict"

    return app, extension


def _app(
    limits: dict[str, tuple[int, int]],
    config_options: dict[str, Any] | None = None,
    **login_options: Any,
) -> Flask:
    return _app_and_extension(limits, config_options, **login_options)[0]


def _statuses(app: Flask, paths: list[str]) -> list[int]:
    client = app.test_client()
    return [client.get(path).status_code for path in paths]


def test_strict_slashes_false_login_and_slash_share_one_limit() -> None:
    app = _app({"/login": (2, 60)}, strict_slashes=False)

    assert _statuses(app, ["/login", "/login/", "/login", "/login/"]) == [
        200,
        200,
        429,
        429,
    ]


def test_concrete_id_key_stays_per_resource() -> None:
    app = _app({"/users/42": (1, 60)})

    assert _statuses(app, ["/users/42", "/users/7", "/users/7", "/users/42"]) == [
        200,
        200,
        200,
        429,
    ]


def test_int_converted_parameters_compare_after_conversion() -> None:
    app = _app({"/users/42": (1, 60)})

    assert _statuses(app, ["/users/042", "/users/42"]) == [200, 429]


def test_login_and_login_slash_keys_are_both_enforced() -> None:
    app = _app({"/login": (3, 60), "/login/": (1, 60)}, strict_slashes=False)

    assert _statuses(app, ["/login", "/login", "/login"]) == [200, 429, 429]


def test_key_the_router_cannot_resolve_still_limits_through_the_fallback() -> None:
    app = _app({"/login/.": (1, 60)}, {"fail_on_misconfiguration": False})

    assert _statuses(app, ["/login", "/login"]) == [200, 429]


def test_key_the_router_cannot_resolve_refuses_to_start_by_default() -> None:
    with pytest.raises(ValueError, match="has a dot segment"):
        _app({"/login/.": (1, 60)})


def test_resolve_route_returns_each_handler_once_across_methods() -> None:
    app, extension = _app_and_extension({"/login": (5, 60)})

    with app.test_request_context("/login"):
        assert extension.resolve_route("/login") == ((app.view_functions["login"], ()),)


def test_resolve_route_reports_converted_path_parameters() -> None:
    app, extension = _app_and_extension({"/login": (5, 60)})

    with app.test_request_context("/"):
        assert extension.resolve_route("/users/042") == (
            (app.view_functions["user"], (("user_id", "42"),)),
        )


@pytest.mark.parametrize("path", ["/nope", "/strict", "/users/x"])
def test_resolve_route_returns_nothing_for_unrouted_paths(path: str) -> None:
    app, extension = _app_and_extension({"/login": (5, 60)})

    with app.test_request_context("/"):
        assert extension.resolve_route(path) == ()


def test_request_identity_equals_the_identity_resolve_route_returns() -> None:
    app, extension = _app_and_extension({"/users/5": (5, 60)})

    with app.test_request_context("/users/5"):
        guard_request = FlaskGuardRequest(flask_request)
        extension._populate_guard_state(guard_request)

        identity = guard_request.state.guard_route_identity
        assert identity in extension.resolve_route("/users/5")


def test_request_identity_is_not_built_without_endpoint_limits() -> None:
    app, extension = _app_and_extension({})

    with app.test_request_context("/users/5"):
        guard_request = FlaskGuardRequest(flask_request)
        extension._populate_guard_state(guard_request)

        assert not hasattr(guard_request.state, "guard_route_identity")


def test_separate_slash_and_no_slash_routes_count_against_their_own_key() -> None:
    app = Flask(__name__)
    config = SecurityConfig[SyncGuardRequest](
        enable_redis=False,
        enable_rate_limiting=True,
        rate_limit=1000,
        endpoint_rate_limits={"/a": (1, 60), "/a/": (5, 60)},
        passive_mode=False,
    )
    FlaskAPIGuard(app, config=config)

    @app.get("/a")
    def plain() -> str:
        return "plain"

    @app.get("/a/")
    def slashed() -> str:
        return "slashed"

    assert _statuses(app, ["/a/", "/a/", "/a", "/a"]) == [200, 200, 200, 429]
