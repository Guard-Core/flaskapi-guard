from flask import Flask
from guard_core._misconfiguration import config_logger, report_misconfigurations
from guard_core._misconfiguration_kinds import Problem
from guard_core.models import SecurityConfig
from guard_core.sync._utils.route_gate import detection_exclusion_path_param_problems
from guard_core.sync.decorators.base import BaseSecurityDecorator
from guard_core.sync.protocols.request_protocol import SyncGuardRequest


def declared_path_param_problems(
    app: Flask, guard_decorator: BaseSecurityDecorator | None
) -> list[Problem]:
    if guard_decorator is None:
        return []
    problems: list[Problem] = []
    for rule in app.url_map.iter_rules():
        view = app.view_functions.get(rule.endpoint)
        route_id = getattr(view, "_guard_route_id", None)
        if not route_id:
            continue
        route_config = guard_decorator.get_route_config(route_id)
        declared = getattr(route_config, "excluded_detection_path_params", None)
        if not declared:
            continue
        problems += detection_exclusion_path_param_problems(
            route_id, rule.rule, declared
        )
    return problems


def report_declared_path_params(
    config: SecurityConfig[SyncGuardRequest],
    app: Flask,
    guard_decorator: BaseSecurityDecorator | None,
) -> None:
    """The one report point, at the first request, when every route exists (Flask
    refuses new routes after it): fail_on_misconfiguration decides between a raise,
    which fails every request until the app is fixed, and one warning."""
    report_misconfigurations(
        config,
        declared_path_param_problems(app, guard_decorator),
        logger=config_logger,
        stacklevel=2,
    )
