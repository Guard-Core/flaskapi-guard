"""fail_on_misconfiguration governs the first-request report of a declared
detection_exclusion path param, and the kind travels with every report."""

import logging
import pathlib

import pytest
from guard_core._misconfiguration_kinds import MisconfigurationError

import flaskapi_guard
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
