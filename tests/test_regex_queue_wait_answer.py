import concurrent.futures
import os
import threading
from collections.abc import Iterator
from typing import cast

import pytest
from flask import Flask
from flask.testing import FlaskClient
from guard_core.models import SecurityConfig
from guard_core.protocols.geo_ip_protocol import GeoIPHandler
from guard_core.sync.detection_engine import compiler as compiler_module
from guard_core.sync.handlers.ipinfo_handler import IPInfoManager
from guard_core.sync.handlers.suspatterns_handler import sus_patterns_manager_for
from guard_core.sync.protocols.request_protocol import SyncGuardRequest

from flaskapi_guard.extension import FlaskAPIGuard

IPINFO_TOKEN = str(os.getenv("IPINFO_TOKEN"))
BUSY_ROW = "[xyz]7"


@pytest.fixture
def saturated_regex_pool(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    workers = compiler_module._SHARED_EXECUTOR_MAX_WORKERS
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=workers)
    monkeypatch.setattr(compiler_module, "_shared_executor", pool)
    release = threading.Event()
    all_running = threading.Barrier(workers + 1)

    def hold() -> None:
        all_running.wait(10)
        release.wait(30)

    for _ in range(workers):
        pool.submit(hold)
    all_running.wait(10)
    yield
    release.set()
    pool.shutdown(wait=True)


@pytest.fixture
def client_of_the_app() -> Iterator[FlaskClient]:
    config = SecurityConfig[SyncGuardRequest](
        geo_ip_handler=cast(GeoIPHandler, IPInfoManager(IPINFO_TOKEN)),
        enable_rate_limiting=False,
        enable_redis=False,
        fail_secure=True,
        detection_compiler_timeout=0.3,
        custom_error_responses={503: "Busy, retry shortly"},
    )
    app = Flask(__name__)
    FlaskAPIGuard(app, config=config)

    @app.route("/ping")
    def ping() -> dict[str, bool]:
        return {"ok": True}

    with app.test_client() as client:
        assert client.get("/ping").status_code == 200
        sus_patterns_manager_for(config).add_pattern(BUSY_ROW, custom=True)
        yield client
        sus_patterns_manager_for(config).remove_pattern(BUSY_ROW, custom=True)


@pytest.mark.usefixtures("saturated_regex_pool")
def test_a_queue_wait_answers_503_with_retry_after_and_the_custom_message(
    client_of_the_app: FlaskClient,
) -> None:
    response = client_of_the_app.get("/ping?q=hello")

    assert response.status_code == 503
    assert response.headers["Retry-After"] == "1"
    assert response.get_data(as_text=True) == "Busy, retry shortly"


def test_the_same_request_on_a_free_pool_passes(
    client_of_the_app: FlaskClient,
) -> None:
    assert client_of_the_app.get("/ping?q=hello").status_code == 200
