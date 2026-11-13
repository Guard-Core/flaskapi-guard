"""fail_on_misconfiguration governs the first-request report of a declared
detection_exclusion path param, and the kind travels with every report."""

import logging
import pathlib
from collections.abc import Iterator

import pytest
from flask import Flask
from guard_core._misconfiguration_kinds import MisconfigurationError
from werkzeug.routing import Rule

import flaskapi_guard
from flaskapi_guard import FlaskAPIGuard
from tests.test_declared_path_params import (
    LOGGER,
    Declare,
    _app,
    _missing,
    _rootless,
    declare_in_a_blueprint,
    declare_missing,
    declare_rootless,
)

CASES = [
    (declare_missing, "/items/7", _missing("/items/<int:item_id>")),
    (declare_rootless, "/anything", _rootless("/<path:tail>")),
    (declare_in_a_blueprint, "/things/7", _missing("/things/<thing_id>")),
]


@pytest.mark.parametrize(("declare", "path", "tail"), CASES)
def test_with_the_flag_on_the_first_request_refuses_instead_of_warning(
    declare: Declare, path: str, tail: str
) -> None:
    app = _app(declare, flag=True)
    app.config["PROPAGATE_EXCEPTIONS"] = True

    with pytest.raises(MisconfigurationError) as refused:
        app.test_client().get(path)

    assert tail in str(refused.value)


def test_with_the_flag_on_every_request_refuses_until_the_process_restarts() -> None:
    app = _app(declare_missing, flag=True)
    app.config["PROPAGATE_EXCEPTIONS"] = True

    for _ in range(2):
        with pytest.raises(MisconfigurationError):
            app.test_client().get("/items/7")


def test_the_refused_request_is_a_500_when_exceptions_do_not_propagate() -> None:
    app = _app(declare_missing, flag=True)
    app.config["PROPAGATE_EXCEPTIONS"] = False

    assert app.test_client().get("/items/7").status_code == 500


@pytest.mark.parametrize(
    ("declare", "path", "kind", "subject"),
    [
        (
            declare_missing,
            "/items/7",
            "decorator.detection_exclusion.param_not_in_template",
            "ghost",
        ),
        (
            declare_rootless,
            "/anything",
            "decorator.detection_exclusion.param_without_literal_segment",
            "tail",
        ),
    ],
)
def test_the_refusal_carries_the_kind_and_the_declared_name(
    declare: Declare, path: str, kind: str, subject: str
) -> None:
    app = _app(declare, flag=True)
    app.config["PROPAGATE_EXCEPTIONS"] = True

    with pytest.raises(MisconfigurationError) as refused:
        app.test_client().get(path)

    assert [(p.kind, p.subject) for p in refused.value.problems] == [(kind, subject)]


def test_with_the_flag_off_the_warning_carries_its_kind_and_the_request_is_served(
    caplog: pytest.LogCaptureFixture,
) -> None:
    app = _app(declare_missing, flag=False)
    caplog.set_level(logging.WARNING, logger=LOGGER)

    assert app.test_client().get("/items/7").status_code == 200
    assert app.test_client().get("/items/7").status_code == 200

    carried = [
        r.__dict__["problems"] for r in caplog.records if "problems" in r.__dict__
    ]
    assert (
        ("decorator.detection_exclusion.param_not_in_template", "ghost"),
    ) in carried


def test_the_adapter_holds_no_copy_of_the_engine_text() -> None:
    root = pathlib.Path(flaskapi_guard.__file__).parent
    assert not [
        p.name
        for p in root.rglob("*.py")
        if "@detection_exclusion(path_params=...) on route" in p.read_text()
    ]


def _guard_of(app: Flask) -> FlaskAPIGuard:
    guard = app.extensions["flaskapi_guard"]["guard"]
    assert isinstance(guard, FlaskAPIGuard)
    return guard


def test_three_refusals_are_three_distinct_errors_of_equal_traceback_depth() -> None:
    app = _app(declare_missing, flag=True)
    app.config["PROPAGATE_EXCEPTIONS"] = True
    errors: list[MisconfigurationError] = []

    for _ in range(3):
        with pytest.raises(MisconfigurationError) as refused:
            app.test_client().get("/items/7")
        errors.append(refused.value)

    assert len({id(error) for error in errors}) == 3
    depths: list[int] = []
    for error in errors:
        depth, trace = 0, error.__traceback__
        while trace is not None:
            depth, trace = depth + 1, trace.tb_next
        depths.append(depth)
    assert len(set(depths)) == 1


def test_the_problems_are_computed_once_and_logged_once_at_the_first_failure(
    caplog: pytest.LogCaptureFixture,
) -> None:
    app = _app(declare_missing, flag=True)
    app.config["PROPAGATE_EXCEPTIONS"] = True
    walks: list[int] = []
    real = app.url_map.iter_rules

    def counting(endpoint: str | None = None) -> Iterator[Rule]:
        walks.append(1)
        return real(endpoint)

    app.url_map.__dict__["iter_rules"] = counting
    caplog.set_level(logging.ERROR, logger=LOGGER)

    for _ in range(3):
        with pytest.raises(MisconfigurationError):
            app.test_client().get("/items/7")

    assert len(walks) == 1
    logged = [r for r in caplog.records if "@detection_exclusion" in r.getMessage()]
    assert len(logged) == 1


def test_while_failing_neither_redis_nor_agent_initialization_runs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = _app(declare_missing, flag=True)
    app.config["PROPAGATE_EXCEPTIONS"] = True
    guard = _guard_of(app)
    runs: list[int] = []
    monkeypatch.setattr(guard, "_initialize_handlers", lambda: runs.append(1))

    for _ in range(3):
        with pytest.raises(MisconfigurationError):
            app.test_client().get("/items/7")

    assert runs == []


def test_the_reporter_walks_the_app_itself_when_it_is_given_no_problems(
    caplog: pytest.LogCaptureFixture,
) -> None:
    from flaskapi_guard._declared_path_params import report_declared_path_params

    app = _app(declare_missing, flag=False)
    guard = _guard_of(app)
    caplog.set_level(logging.WARNING, logger=LOGGER)

    assert guard.config is not None
    report_declared_path_params(guard.config, app, guard.guard_decorator)

    assert (
        len([r for r in caplog.records if "@detection_exclusion" in r.getMessage()])
        == 1
    )


def test_a_later_request_with_the_flag_off_reports_nothing_again(
    caplog: pytest.LogCaptureFixture,
) -> None:
    from flaskapi_guard._declared_path_params import (
        declared_path_param_problems,
        report_declared_path_params,
    )

    app = _app(declare_missing, flag=False)
    guard = _guard_of(app)
    problems = declared_path_param_problems(app, guard.guard_decorator)
    caplog.set_level(logging.WARNING, logger=LOGGER)

    assert guard.config is not None
    report_declared_path_params(
        guard.config, app, guard.guard_decorator, problems=problems, first=False
    )

    assert [r for r in caplog.records if "@detection_exclusion" in r.getMessage()] == []


def test_flask_refuses_late_routes_after_the_first_request() -> None:
    # The cached path-param problems are only sound while Flask refuses new routes
    # once a request was handled (flask/sansio/app.py _check_setup_finished).
    from flask import Blueprint

    app = _app(declare_missing, flag=False)
    assert app.test_client().get("/items/7").status_code == 200

    with pytest.raises(AssertionError):
        app.add_url_rule("/late", "late", lambda: "ok")
    with pytest.raises(AssertionError):
        app.register_blueprint(Blueprint("late_bp", __name__))
