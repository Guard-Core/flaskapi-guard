import threading
import time
from typing import Any

import pytest
from flask import Flask
from guard_core.sync.core.initialization import HandlerInitializer
from guard_core.sync.protocols.request_protocol import SyncGuardRequest

from flaskapi_guard import FlaskAPIGuard, SecurityConfig


def _config() -> SecurityConfig[SyncGuardRequest]:
    return SecurityConfig[SyncGuardRequest](enable_redis=False, rate_limit=100000)


def test_concurrent_first_requests_initialize_the_handlers_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[int] = []
    original = HandlerInitializer.initialize_redis_handlers

    def slow(self: HandlerInitializer, *args: Any, **kwargs: Any) -> None:
        calls.append(threading.get_ident())
        time.sleep(0.2)
        original(self, *args, **kwargs)

    monkeypatch.setattr(HandlerInitializer, "initialize_redis_handlers", slow)
    app = Flask(__name__)

    @app.get("/")
    def index() -> str:
        return "ok"

    FlaskAPIGuard(app, config=_config())
    statuses: list[int] = []

    def hit() -> None:
        statuses.append(app.test_client().get("/").status_code)

    threads = [threading.Thread(target=hit) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert statuses == [200] * 8
    assert len(calls) == 1
