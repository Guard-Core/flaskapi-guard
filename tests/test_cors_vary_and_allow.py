from flask import Flask, Response, make_response
from guard_core.sync.protocols.request_protocol import SyncGuardRequest

from flaskapi_guard import FlaskAPIGuard, SecurityConfig

ORIGIN = {"Origin": "https://app.example.com"}


def _app(**overrides: object) -> Flask:
    app = Flask(__name__)
    FlaskAPIGuard(
        app,
        config=SecurityConfig[SyncGuardRequest](
            enable_cors=True,
            cors_allow_origins=["https://app.example.com"],
            enable_redis=False,
            enable_rate_limiting=False,
            enable_ip_banning=False,
            **overrides,  # type: ignore[arg-type]
        ),
    )

    def with_vary(value: str) -> Response:
        response = make_response({"ok": "yes"})
        response.headers["Vary"] = value
        return response

    @app.route("/items")
    def items() -> Response:
        return with_vary("Accept-Encoding")

    @app.route("/origin-vary")
    def origin_vary() -> Response:
        return with_vary("origin")

    @app.route("/star-vary")
    def star_vary() -> Response:
        return with_vary("*")

    return app


def test_cors_vary_is_merged_into_the_vary_of_the_application() -> None:
    response = _app().test_client().get("/items", headers=ORIGIN)

    assert response.headers.getlist("Vary") == ["Accept-Encoding, Origin"]


def test_an_application_vary_that_already_lists_origin_is_kept_once() -> None:
    response = _app().test_client().get("/origin-vary", headers=ORIGIN)

    assert response.headers.getlist("Vary") == ["origin"]


def test_an_application_vary_star_stays_alone() -> None:
    response = _app().test_client().get("/star-vary", headers=ORIGIN)

    assert response.headers.getlist("Vary") == ["*"]


def test_a_wrong_method_in_strict_mode_is_a_405_listing_the_allowed_methods() -> None:
    client = _app(route_resolution_strict=True).test_client()

    response = client.post("/items")

    assert response.status_code == 405
    assert response.headers["Allow"] == "GET, HEAD, OPTIONS"


def test_a_path_no_route_serves_is_a_404_without_allow_in_strict_mode() -> None:
    response = _app(route_resolution_strict=True).test_client().get("/nothing")

    assert response.status_code == 404
    assert "Allow" not in response.headers
