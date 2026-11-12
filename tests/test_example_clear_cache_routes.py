import importlib
import importlib.util
import sys
import time
from pathlib import Path
from types import ModuleType

import pytest
from guard_core.sync.handlers.ipban_handler import ip_ban_manager_for
from guard_core.sync.handlers.ratelimit_handler import RateLimitManager

from tests.redis_isolation import REDIS_PREFIX, REDIS_URL

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"
LOCALHOST = {"REMOTE_ADDR": "127.0.0.1"}
BANNED_IP = "203.0.113.5"
WINDOWED_IP = "203.0.113.6"


def _load_example(name: str, monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    monkeypatch.setenv("IPINFO_TOKEN", "test_token")
    monkeypatch.setenv("REDIS_URL", REDIS_URL)
    monkeypatch.setenv("REDIS_PREFIX", REDIS_PREFIX)
    if name == "simple_app":
        spec = importlib.util.spec_from_file_location(
            "simple_app_main", EXAMPLES / name / "main.py"
        )
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    monkeypatch.syspath_prepend(str(EXAMPLES / name))
    for loaded in [m for m in sys.modules if m == "app" or m.startswith("app.")]:
        monkeypatch.delitem(sys.modules, loaded)
    return importlib.import_module("app.main")


@pytest.mark.parametrize("name", ["simple_app", "advanced_app"])
def test_clear_cache_route_drops_the_bans_and_the_rate_windows(
    name: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load_example(name, monkeypatch)
    assert module.security_config.redis_prefix != "flaskapi_guard:"
    client = module.app.test_client()
    client.get("/", environ_base=LOCALHOST)
    bans = ip_ban_manager_for(module.security_config)
    windows = RateLimitManager(module.security_config)
    bans.ban_ip(BANNED_IP, 300, "test")
    windows.request_timestamps[WINDOWED_IP].append(time.time())
    assert bans.is_ip_banned(BANNED_IP)
    assert windows.request_timestamps[WINDOWED_IP]

    response = client.post("/admin/clear-cache", environ_base=LOCALHOST)

    assert response.status_code == 200
    assert not bans.is_ip_banned(BANNED_IP)
    assert not windows.request_timestamps.get(WINDOWED_IP)
    assert b"geo_cache" not in response.data


@pytest.mark.parametrize("name", ["simple_app", "advanced_app"])
def test_clear_cache_route_stays_behind_the_localhost_gate(
    name: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load_example(name, monkeypatch)
    client = module.app.test_client()
    response = client.post(
        "/admin/clear-cache", environ_base={"REMOTE_ADDR": "203.0.113.5"}
    )
    assert response.status_code == 403
