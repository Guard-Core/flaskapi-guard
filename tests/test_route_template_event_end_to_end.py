"""A real request to a routed endpoint makes the security event carry the
normalised ``route_template`` (LEDGER 6.549)."""

import pytest
from flask import Flask
from guard_agent import SyncGuardAgentHandler
from guard_agent.models import SecurityEvent
from guard_core.sync.protocols.request_protocol import SyncGuardRequest

from flaskapi_guard import FlaskAPIGuard, SecurityConfig


def test_a_blocked_request_event_carries_the_route_template(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sent: list[SecurityEvent] = []

    def record(self: SyncGuardAgentHandler, event: SecurityEvent) -> None:
        sent.append(event)

    monkeypatch.setattr(SyncGuardAgentHandler, "send_event", record)
    app = Flask(__name__)

    @app.get("/items/<int:item_id>")
    def item(item_id: int) -> dict[str, int]:
        return {"id": item_id}

    FlaskAPIGuard(
        app,
        config=SecurityConfig[SyncGuardRequest](
            enable_redis=False,
            enable_agent=True,
            agent_api_key="sk-test-0123456789",
            enable_rate_limiting=False,
            enable_ip_banning=False,
            blocked_user_agents=["badbot"],
        ),
    )

    response = app.test_client().get("/items/42", headers={"User-Agent": "badbot"})

    assert response.status_code == 403
    assert [event.endpoint for event in sent] == ["/items/42"]
    assert [event.route_template for event in sent] == ["/items/{item_id}"]
