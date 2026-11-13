from collections.abc import Iterator

from flask import Flask
from guard_core.models import SecurityConfig
from guard_core.sync.adapter_support import (
    Problem,
    config_logger,
    detection_exclusion_path_param_problems,
    report_declared_path_param_problems,
    route_unknown_to_decorator_problem,
)
from guard_core.sync.decorators.base import BaseSecurityDecorator, RouteConfig
from guard_core.sync.protocols.request_protocol import SyncGuardRequest


def _route_configs(
    app: Flask, guard_decorator: BaseSecurityDecorator
) -> Iterator[tuple[str, str, RouteConfig | None]]:
    for rule in app.url_map.iter_rules():
        view = app.view_functions.get(rule.endpoint)
        route_id = getattr(view, "_guard_route_id", None)
        if route_id:
            yield rule.rule, route_id, guard_decorator.get_route_config(route_id)


def declared_path_param_problems(
    app: Flask, guard_decorator: BaseSecurityDecorator | None
) -> list[Problem]:
    if guard_decorator is None:
        return []
    problems: list[Problem] = []
    unknown: dict[str, Problem] = {}
    for template, route_id, route_config in _route_configs(app, guard_decorator):
        if route_config is None:
            unknown.setdefault(route_id, route_unknown_to_decorator_problem(route_id))
        elif declared := getattr(route_config, "excluded_detection_path_params", None):
            problems += detection_exclusion_path_param_problems(
                route_id, template, declared
            )
    return problems + list(unknown.values())


def report_declared_path_params(
    config: SecurityConfig[SyncGuardRequest],
    app: Flask,
    guard_decorator: BaseSecurityDecorator | None,
    *,
    problems: list[Problem] | None = None,
    first: bool = True,
) -> None:
    """The one report point, at the first request, when every route exists (Flask
    refuses new routes after it). With fail_on_misconfiguration every request
    raises a fresh error from the cached problems, never a stored exception (its
    traceback would grow on each raise), and the list is logged once; without it
    the first request logs one warning per problem."""
    if problems is None:
        problems = declared_path_param_problems(app, guard_decorator)
    if not problems:
        return
    if first and config.fail_on_misconfiguration:
        config_logger.error(
            "Every request is refused until this is fixed: %s",
            "; ".join(problems),
        )
    report_declared_path_param_problems(
        config, problems, logger=config_logger, stacklevel=2
    )
