import sys
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from flask import Flask
from guard_core.models import SecurityConfig
from guard_core.sync.protocols.request_protocol import SyncGuardRequest

from flaskapi_guard import FlaskAPIGuard


class _StatsAgentStub:
    def __init__(self) -> None:
        self.stats: dict[str, object] = {"buffer_stats": {"events_dropped": 3}}

    def start(self) -> None: ...

    def stop(self) -> None: ...

    def flush_buffer(self) -> None: ...

    def send_event(self, event: object) -> None: ...

    def send_metric(self, metric: object) -> None: ...

    def initialize_redis(self, redis_handler: object) -> None: ...

    def get_dynamic_rules(self) -> None:
        return None

    def get_status(self) -> None:
        return None

    def health_check(self) -> bool:
        return True

    def get_stats(self) -> dict[str, object]:
        return self.stats


def test_agent_stats_answers_after_the_composite_handler_is_swapped_in(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stub = _StatsAgentStub()
    monkeypatch.setitem(
        sys.modules, "guard_agent", SimpleNamespace(guard_agent=lambda _cfg: stub)
    )
    config = SecurityConfig[SyncGuardRequest](
        enable_agent=True, agent_api_key="x", enable_redis=False
    )
    with patch.object(SecurityConfig, "to_agent_config", return_value=object()):
        guard = FlaskAPIGuard(Flask(__name__), config=config)
    assert guard.agent_handler is stub

    guard._initialize_handlers()

    assert guard.agent_handler is not stub
    stats = guard.agent_stats
    assert stats["enabled"] is True
    assert stats["buffer_stats"] == {"events_dropped": 3}
