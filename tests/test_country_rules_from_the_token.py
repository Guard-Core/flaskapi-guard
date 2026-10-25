from collections.abc import Generator
from pathlib import Path

import pytest
from flask import Flask
from guard_core.sync.handlers.ipinfo_handler import IPInfoManager
from guard_core.sync.protocols.request_protocol import SyncGuardRequest

from flaskapi_guard import SecurityConfig, SecurityDecorator
from flaskapi_guard.extension import FlaskAPIGuard
from tests.geo_database import CLIENT_IP, country_database_bytes


@pytest.fixture(autouse=True)
def _reset_singleton() -> Generator[None, None, None]:
    IPInfoManager._instance = None
    yield
    IPInfoManager._instance = None


def _config(
    tmp_path: Path,
    blocked_countries: frozenset[str] = frozenset(),
    lazy_init: bool = False,
) -> SecurityConfig[SyncGuardRequest]:
    db_path = tmp_path / "geo.mmdb"
    db_path.write_bytes(country_database_bytes("CN"))
    return SecurityConfig[SyncGuardRequest](
        enable_redis=False,
        enable_penetration_detection=False,
        ipinfo_token="tok",
        ipinfo_db_path=db_path,
        lazy_init=lazy_init,
        trusted_proxies=("127.0.0.1",),
        blocked_countries=blocked_countries,
    )


def _status(app: Flask, path: str) -> int:
    with app.test_client() as client:
        return client.get(path, headers={"X-Forwarded-For": CLIENT_IP}).status_code


def test_global_blocked_countries_from_the_token_block_on_the_sync_engine(
    tmp_path: Path,
) -> None:
    app = Flask(__name__)
    FlaskAPIGuard(app, config=_config(tmp_path, blocked_countries=frozenset({"CN"})))

    @app.route("/")
    def index() -> dict[str, str]:
        return {"ok": "yes"}

    assert _status(app, "/") == 403


def test_route_block_countries_blocks_without_a_global_country_rule(
    tmp_path: Path,
) -> None:
    app = Flask(__name__)
    config = _config(tmp_path)
    decorator = SecurityDecorator(config)

    @app.route("/blocked")
    @decorator.block_countries(["CN"])
    def blocked() -> dict[str, str]:
        return {"ok": "yes"}

    @app.route("/open")
    def open_route() -> dict[str, str]:
        return {"ok": "yes"}

    guard = FlaskAPIGuard(app, config=config)
    guard.set_decorator_handler(decorator)

    assert _status(app, "/blocked") == 403
    assert _status(app, "/open") == 200


def test_route_block_countries_blocks_under_the_default_lazy_init(
    tmp_path: Path,
) -> None:
    app = Flask(__name__)
    config = _config(tmp_path, lazy_init=True)
    decorator = SecurityDecorator(config)

    @app.route("/blocked")
    @decorator.block_countries(["CN"])
    def blocked() -> dict[str, str]:
        return {"ok": "yes"}

    guard = FlaskAPIGuard(app, config=config)
    guard.set_decorator_handler(decorator)

    assert _status(app, "/blocked") == 403
