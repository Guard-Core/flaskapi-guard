import asyncio
import logging
import sys
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from flask import Flask, Request
from guard_agent import SyncGuardAgentHandler
from guard_agent.models import AgentConfig
from guard_core.models import SecurityConfig
from guard_core.sync.protocols.request_protocol import SyncGuardRequest

from flaskapi_guard import FlaskAPIGuard
from flaskapi_guard.adapters import FlaskGuardRequest, FlaskResponseFactory


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
    SyncGuardAgentHandler._instance = None
    try:
        guard = asyncio.run(build())

        assert type(guard.agent_handler).__name__ == SyncGuardAgentHandler.__name__
        assert guard.agent_handler is not None
        guard.agent_handler.start()
        guard.agent_handler.stop()
    finally:
        SyncGuardAgentHandler._instance = None


def test_a_handler_that_is_not_a_sync_agent_handler_is_refused(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setitem(
        sys.modules,
        "guard_agent",
        SimpleNamespace(SyncGuardAgentHandler=lambda _cfg: object()),
    )
    with (
        patch.object(SecurityConfig, "to_agent_config", return_value=object()),
        caplog.at_level(logging.ERROR),
    ):
        guard = FlaskAPIGuard(Flask(__name__), config=_agent_guard_config())

    assert guard.agent_handler is None
    assert "Failed to initialize Guard Agent" in caplog.text


def test_pipeline_is_not_built_before_config_and_logger_are_resolved() -> None:
    guard = FlaskAPIGuard()

    with pytest.raises(ValueError, match="resolved first"):
        guard._build_security_pipeline()


def test_request_headers_that_are_not_a_lookup_table_are_refused() -> None:
    app = Flask(__name__)
    with app.test_request_context("/"):
        request = Request({})
        guard_request = FlaskGuardRequest(request)
        request.__dict__["headers"] = object()
        with pytest.raises(TypeError, match="lookup table"):
            _ = guard_request.headers


def test_redirect_outside_an_app_context_still_answers_a_flask_response() -> None:
    created = FlaskResponseFactory().create_redirect_response("/elsewhere", 307)

    assert created.status_code == 307
    assert created.headers["Location"] == "/elsewhere"
