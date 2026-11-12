from flask import Flask
from guard_core._misconfiguration import config_logger
from guard_core.sync._utils.route_gate import (
    path_params_missing_from_template,
    path_params_without_a_literal_segment_before,
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
        # keep in step with SuspiciousActivityCheck._report_declared_path_param_problems
        for name in path_params_without_a_literal_segment_before(template, declared):
            problems.append(
                f"@detection_exclusion(path_params=...) on route {route_id!r} "
                f"declares {name!r}, which has no literal segment before it in the "
                f"route template {template!r}: it would exempt the whole path from "
                "the probe rows, so the whole path is scanned."
            )
        for name in path_params_missing_from_template(template, declared):
            problems.append(
                f"@detection_exclusion(path_params=...) on route {route_id!r} "
                f"declares {name!r}, which is not in the route template "
                f"{template!r}, so it exempts nothing."
            )
    return problems


def warn_at_first_request(
    app: Flask, guard_decorator: BaseSecurityDecorator | None
) -> None:
    for problem in declared_path_param_problems(app, guard_decorator):
        config_logger.warning(problem)
