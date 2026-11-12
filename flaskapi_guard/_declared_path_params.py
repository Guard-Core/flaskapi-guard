from flask import Flask
from guard_core._misconfiguration import config_logger
from guard_core.sync._utils.route_gate import (
    declared_path_param_problems as engine_problems,
)
from guard_core.sync.decorators.base import BaseSecurityDecorator


def declared_path_param_problems(
    app: Flask, guard_decorator: BaseSecurityDecorator | None
) -> list[str]:
    if guard_decorator is None:
        return []
    problems: list[str] = []
    for rule in app.url_map.iter_rules():
        view = app.view_functions.get(rule.endpoint)
        route_id = getattr(view, "_guard_route_id", None)
        route_config = guard_decorator.get_route_config(route_id) if route_id else None
        declared = getattr(route_config, "excluded_detection_path_params", None)
        if not declared:
            continue
        template = rule.rule
        for name, problem in engine_problems(template, declared).items():
            problems.append(
                f"@detection_exclusion(path_params=...) on route {route_id!r} "
                f"declares {name!r}, which {problem}"
            )
    return problems


def warn_at_first_request(
    app: Flask, guard_decorator: BaseSecurityDecorator | None
) -> None:
    for problem in declared_path_param_problems(app, guard_decorator):
        config_logger.warning(problem)
