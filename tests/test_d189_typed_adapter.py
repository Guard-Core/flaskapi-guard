import asyncio
import logging
from collections.abc import Callable
from unittest.mock import patch

import pytest
from flask import Flask, Response, g, request
from guard_agent import SyncGuardAgentHandler
from guard_agent.models import AgentConfig
from guard_core.models import SecurityConfig
from guard_core.sync.decorators.base import RouteConfig
from guard_core.sync.protocols.request_protocol import SyncGuardRequest

from flaskapi_guard import FlaskAPIGuard
from flaskapi_guard.adapters import FlaskGuardRequest, FlaskResponseFactory
from tests.agent_loop import close_the_agent_event_loop


def _agent_config() -> AgentConfig:
    return AgentConfig(
        api_key="k" * 32, project_id="p", endpoint="https://example.invalid"
    )


def _agent_guard_config() -> SecurityConfig[SyncGuardRequest]:
    return SecurityConfig[SyncGuardRequest](
        enable_agent=True, agent_api_key="x", enable_redis=False
    )


def test_extension_built_inside_a_running_loop_holds_the_sync_agent_handler() -> None:
    async def build() -> FlaskAPIGuard:
        with patch.object(
            SecurityConfig, "to_agent_config", return_value=_agent_config()
        ):
            return FlaskAPIGuard(Flask(__name__), config=_agent_guard_config())

    # the handler is a process-wide singleton and stop() ends its loop thread
    close_the_agent_event_loop()
    try:
        guard = asyncio.run(build())

        assert type(guard.agent_handler).__name__ == SyncGuardAgentHandler.__name__
        assert guard.agent_handler is not None
        guard.agent_handler.start()
        guard.agent_handler.stop()
    finally:
        close_the_agent_event_loop()


def test_pipeline_is_not_built_before_config_and_logger_are_resolved() -> None:
    guard = FlaskAPIGuard()
    guard.logger = logging.getLogger(__name__)

    with pytest.raises(ValueError, match="resolved first"):
        guard._build_security_pipeline()


def test_redirect_outside_an_app_context_still_answers_a_flask_response() -> None:
    created = FlaskResponseFactory().create_redirect_response("/elsewhere", 307)

    assert created.status_code == 307
    assert created.headers["Location"] == "/elsewhere"


def test_a_configured_object_that_is_not_a_geo_handler_is_accepted_as_in_v4_4_0() -> (
    None
):
    config = SecurityConfig[SyncGuardRequest](enable_redis=False)
    config.__dict__["geo_ip_handler"] = object()
    app = Flask(__name__)

    FlaskAPIGuard(app, config=config)

    assert app.test_client().get("/").status_code == 404


def test_no_geo_handler_stays_none() -> None:
    config = SecurityConfig[SyncGuardRequest](enable_redis=False)

    guard = FlaskAPIGuard(Flask(__name__), config=config)

    assert guard.geo_ip_handler is None


def _initialized_guard() -> tuple[Flask, FlaskAPIGuard]:
    app = Flask(__name__)
    guard = FlaskAPIGuard(
        app, config=SecurityConfig[SyncGuardRequest](enable_redis=False)
    )
    with app.app_context():
        guard._ensure_initialized()
    return app, guard


def _usage(guard: FlaskAPIGuard) -> None:
    guard._process_behavioral_usage(FlaskGuardRequest(request), "1.1.1.1", None)


def _decorator_usage(guard: FlaskAPIGuard) -> None:
    guard._process_decorator_usage_rules(request, "1.1.1.1", RouteConfig())


def _decorator_return(guard: FlaskAPIGuard) -> None:
    guard._process_decorator_return_rules(request, Response(), "1.1.1.1", RouteConfig())


def _after(guard: FlaskAPIGuard) -> None:
    g.guard_response_pass = True
    guard._after_request(Response())


_BROKEN_INVARIANTS = [
    ("config", FlaskAPIGuard._before_request),
    ("bypass_handler", FlaskAPIGuard._before_request),
    ("route_resolver", FlaskAPIGuard._before_request),
    ("behavioral_processor", _usage),
    ("behavioral_processor", _decorator_usage),
    ("behavioral_processor", _decorator_return),
    ("behavioral_processor", lambda guard: guard._get_endpoint_id(request)),
    ("behavioral_processor", _after),
    ("response_factory", _after),
    ("response_factory", lambda guard: guard.create_error_response(400, "x")),
    ("validator", lambda guard: guard._check_time_window({})),
    ("config", FlaskAPIGuard.refresh_cloud_ip_ranges),
    ("rate_limit_handler", FlaskAPIGuard.reset),
    ("handler_initializer", FlaskAPIGuard._initialize_handlers),
    ("config", FlaskAPIGuard._init_redis_handler),
]


@pytest.mark.parametrize(("attribute", "call"), _BROKEN_INVARIANTS)
def test_a_missing_component_raises_instead_of_being_assumed(
    attribute: str, call: Callable[[FlaskAPIGuard], object]
) -> None:
    app, guard = _initialized_guard()
    setattr(guard, attribute, None)

    with app.test_request_context("/"):
        with pytest.raises(RuntimeError, match="is not initialized"):
            call(guard)


def test_a_request_without_an_endpoint_raises_instead_of_being_assumed() -> None:
    app, guard = _initialized_guard()

    with app.test_request_context("/"), pytest.raises(RuntimeError, match="endpoint"):
        guard._call_view(object())


def test_the_logger_is_required_before_lazy_initialization() -> None:
    app = Flask(__name__)
    guard = FlaskAPIGuard(
        app, config=SecurityConfig[SyncGuardRequest](enable_redis=False)
    )
    guard.logger = None

    with pytest.raises(RuntimeError, match="logger is not initialized"):
        guard._ensure_initialized()
