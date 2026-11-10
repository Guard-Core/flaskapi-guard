from __future__ import annotations

import ipaddress
import time
from unittest.mock import MagicMock

import pytest
from flask import Flask
from guard_core.sync.protocols.request_protocol import SyncGuardRequest

from flaskapi_guard import SecurityConfig, SecurityDecorator
from flaskapi_guard.extension import FlaskAPIGuard

AWS_RANGE = ipaddress.ip_network("198.51.100.0/24")
CLIENT_IP = "198.51.100.77"


def _app() -> Flask:
    config = SecurityConfig[SyncGuardRequest](
        enable_redis=False,
        enable_penetration_detection=False,
        enable_rate_limiting=False,
        lazy_init=False,
    )
    app = Flask(__name__)
    decorator = SecurityDecorator(config)

    @app.route("/r")
    @decorator.block_clouds(["AWS"])
    def route() -> dict[str, str]:
        return {"ok": "yes"}

    guard = FlaskAPIGuard(app, config=config)
    guard.set_decorator_handler(decorator)
    return app


def test_a_route_only_block_clouds_loads_its_ranges_and_blocks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fetch_aws = MagicMock(return_value=({AWS_RANGE}, {}))
    monkeypatch.setattr(
        "guard_core.sync.handlers.cloud_handler._fetch_provider_ranges", fetch_aws
    )
    client = _app().test_client()
    peer = {"REMOTE_ADDR": CLIENT_IP}
    client.get("/r", environ_overrides=peer)
    time.sleep(0.5)
    response = client.get("/r", environ_overrides=peer)

    fetch_aws.assert_called_with("AWS")
    assert response.status_code == 403
