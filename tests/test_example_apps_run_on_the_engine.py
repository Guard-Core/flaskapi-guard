import importlib
import importlib.util
import sys
from pathlib import Path
from types import ModuleType

import pytest
from flask.testing import FlaskClient

from tests.redis_isolation import REDIS_PREFIX, REDIS_URL

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"
BLOCKED_COUNTRY_IP = "10.0.0.5"
ALLOWED_COUNTRY_IP = "10.0.0.6"
EXAMPLE_NAMES = ("simple_app", "advanced_app")


class _CountryStubGeoIPHandler:
    def __init__(
        self,
        token: str,
        db_path: Path | None = None,
        max_age: int = 86400,
        download_url: str | None = None,
    ) -> None:
        self.download_url = download_url
        self.is_initialized = True

    def initialize(self) -> None:
        return

    def initialize_redis(self, redis_handler: object) -> None:
        return

    def initialize_agent(self, agent_handler: object) -> None:
        return

    def get_country(self, ip: str) -> str | None:
        return "CN" if ip == BLOCKED_COUNTRY_IP else "US"

    def refresh(self) -> None:
        return

    def close(self) -> None:
        return


def _load_example(name: str, monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    monkeypatch.setenv("IPINFO_TOKEN", "test_token")
    monkeypatch.setenv("REDIS_URL", REDIS_URL)
    monkeypatch.setenv("REDIS_PREFIX", REDIS_PREFIX)
    monkeypatch.setattr(
        "guard_core.sync.handlers.ipinfo_handler.IPInfoManager",
        _CountryStubGeoIPHandler,
    )
    if name == "simple_app":
        spec = importlib.util.spec_from_file_location(
            "simple_app_main", EXAMPLES / name / "main.py"
        )
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    else:
        monkeypatch.syspath_prepend(str(EXAMPLES / name))
        for loaded in [m for m in sys.modules if m == "app" or m.startswith("app.")]:
            monkeypatch.delitem(sys.modules, loaded)
        module = importlib.import_module("app.main")
    module.security_config.enable_ip_banning = False
    module.security_config.rate_limit = 100000
    return module


def _documented_routes(module: ModuleType) -> list[tuple[str, str]]:
    return [
        (sorted(rule.methods - {"HEAD", "OPTIONS"})[0], rule.rule)
        for rule in module.app.url_map.iter_rules()
        if "<" not in rule.rule and rule.endpoint != "static"
    ]


def _status(module: ModuleType, method: str, path: str, client_ip: str) -> int:
    client: FlaskClient = module.app.test_client()
    return client.open(
        path, method=method, environ_base={"REMOTE_ADDR": client_ip}
    ).status_code


@pytest.mark.parametrize("name", EXAMPLE_NAMES)
def test_every_documented_example_route_answers_without_a_server_error(
    name: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load_example(name, monkeypatch)
    answers = {
        (method, path): _status(module, method, path, ALLOWED_COUNTRY_IP)
        for method, path in _documented_routes(module)
    }
    assert answers
    assert {key: code for key, code in answers.items() if code >= 500} == {}


@pytest.mark.parametrize("name", EXAMPLE_NAMES)
def test_example_country_block_route_blocks_the_blocked_country_only(
    name: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load_example(name, monkeypatch)
    blocked = _status(module, "GET", "/access/country-block", BLOCKED_COUNTRY_IP)
    allowed = _status(module, "GET", "/access/country-block", ALLOWED_COUNTRY_IP)
    assert (blocked, allowed) == (403, 200)


_HSTS_DEFAULTS = {"max_age": 31536000, "include_subdomains": True, "preload": False}


def _hsts_details(module: ModuleType) -> dict[str, object]:
    client: FlaskClient = module.app.test_client()
    response = client.get(
        "/headers/hsts-info", environ_base={"REMOTE_ADDR": ALLOWED_COUNTRY_IP}
    )
    assert response.status_code == 200
    details: dict[str, object] = response.get_json()["details"]
    return details


def test_simple_example_hsts_info_reports_the_configured_hsts_block(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_example("simple_app", monkeypatch)
    block = {"max_age": 63072000, "include_subdomains": False, "preload": True}
    monkeypatch.setitem(module.security_config.security_headers, "hsts", block)
    assert _hsts_details(module) == block


def test_simple_example_hsts_info_answers_the_defaults_without_an_hsts_block(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_example("simple_app", monkeypatch)
    monkeypatch.delitem(module.security_config.security_headers, "hsts")
    assert _hsts_details(module) == _HSTS_DEFAULTS


def test_simple_example_hsts_info_answers_the_defaults_for_a_none_hsts_block(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_example("simple_app", monkeypatch)
    monkeypatch.setitem(module.security_config.security_headers, "hsts", None)
    assert _hsts_details(module) == _HSTS_DEFAULTS
