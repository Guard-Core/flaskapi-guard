"""LEDGER 6.851: a declared detection_exclusion path param the route does not have is
logged once as a WARNING at the first request, from the URL map, and never raises."""

import logging
from collections.abc import Callable

import pytest
from flask import Blueprint, Flask
from guard_core.sync.protocols.request_protocol import SyncGuardRequest

from flaskapi_guard import FlaskAPIGuard, SecurityConfig, SecurityDecorator

LOGGER = "guard_core.models"
Declare = Callable[[Flask, SecurityDecorator], None]


def _missing(template: str, name: str = "ghost") -> str:
    return (
        f"declares {name!r}, which is not in the route template {template!r}, so it "
        "exempts nothing."
    )


def _rootless(template: str, name: str = "tail") -> str:
    return (
        f"declares {name!r}, which has no literal segment before it in the route "
        f"template {template!r}: it would exempt the whole path from the probe rows, "
        "so the whole path is scanned."
    )


def _app(declare: Declare, *, flag: bool = True) -> Flask:
    config = SecurityConfig[SyncGuardRequest](
        enable_redis=False, rate_limit=100000, fail_on_misconfiguration=flag
    )
    app = Flask(__name__)
    guard = FlaskAPIGuard(app, config=config)
    decorator = SecurityDecorator(config)
    guard.set_decorator_handler(decorator)
    declare(app, decorator)
    return app


def declare_missing(app: Flask, decorator: SecurityDecorator) -> None:
    @app.get("/items/<int:item_id>")
    @decorator.detection_exclusion(path_params={"ghost"})
    def item(item_id: int) -> str:
        return "ok"


def declare_rootless(app: Flask, decorator: SecurityDecorator) -> None:
    @app.get("/<path:tail>")
    @decorator.detection_exclusion(path_params={"tail"})
    def catch_all(tail: str) -> str:
        return "ok"


def declare_valid(app: Flask, decorator: SecurityDecorator) -> None:
    @app.get("/items/<int:item_id>")
    @decorator.detection_exclusion(path_params={"item_id"})
    def item(item_id: int) -> str:
        return "ok"


def declare_unguarded_and_empty(app: Flask, decorator: SecurityDecorator) -> None:
    @app.get("/plain/<x>")
    def plain(x: str) -> str:
        return "ok"

    @app.get("/headers/<y>")
    @decorator.detection_exclusion(headers={"x-trace"})
    def headers(y: str) -> str:
        return "ok"


def declare_in_a_blueprint(app: Flask, decorator: SecurityDecorator) -> None:
    blueprint = Blueprint("things", __name__, url_prefix="/things")

    @blueprint.get("/<thing_id>")
    @decorator.detection_exclusion(path_params={"ghost"})
    def thing(thing_id: str) -> str:
        return "ok"

    app.register_blueprint(blueprint)


def declare_one_view_on_two_rules(app: Flask, decorator: SecurityDecorator) -> None:
    @app.get("/a/<x>", defaults={"y": ""})
    @app.get("/b/<y>", defaults={"x": ""})
    @decorator.detection_exclusion(path_params={"ghost"})
    def view(x: str, y: str) -> str:
        return "ok"


def _problems(caplog: pytest.LogCaptureFixture) -> list[str]:
    return [
        r.getMessage()
        for r in caplog.records
        if r.name == LOGGER and "@detection_exclusion" in r.getMessage()
    ]


@pytest.mark.parametrize("flag", [True, False])
@pytest.mark.parametrize(
    ("declare", "path", "tail"),
    [
        (declare_missing, "/items/7", _missing("/items/<int:item_id>")),
        (declare_rootless, "/anything", _rootless("/<path:tail>")),
        (declare_in_a_blueprint, "/things/7", _missing("/things/<thing_id>")),
    ],
)
def test_the_first_request_warns_once_and_never_raises(
    flag: bool,
    declare: Declare,
    path: str,
    tail: str,
    caplog: pytest.LogCaptureFixture,
) -> None:
    app = _app(declare, flag=flag)
    caplog.set_level(logging.WARNING, logger=LOGGER)

    assert app.test_client().get(path).status_code == 200
    assert app.test_client().get(path).status_code == 200

    (problem,) = _problems(caplog)
    assert tail in problem


def test_one_view_on_two_rules_is_checked_per_rule(
    caplog: pytest.LogCaptureFixture,
) -> None:
    app = _app(declare_one_view_on_two_rules)
    caplog.set_level(logging.WARNING, logger=LOGGER)

    assert app.test_client().get("/a/1").status_code == 200

    problems = _problems(caplog)
    assert len(problems) == 2
    assert any(_missing("/a/<x>") in problem for problem in problems)
    assert any(_missing("/b/<y>") in problem for problem in problems)


@pytest.mark.parametrize("declare", [declare_valid, declare_unguarded_and_empty])
def test_a_sound_declaration_reports_nothing(
    declare: Declare, caplog: pytest.LogCaptureFixture
) -> None:
    app = _app(declare)
    caplog.set_level(logging.WARNING, logger=LOGGER)

    assert app.test_client().get("/items/7").status_code in (200, 404)

    assert _problems(caplog) == []
