import importlib
import importlib.util
import sys
import time
from pathlib import Path
from types import ModuleType
from typing import Any
from unittest.mock import MagicMock

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


@pytest.mark.parametrize("name", ["simple_app", "advanced_app"])
def test_unban_route_lifts_the_ban_it_names(
    name: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load_example(name, monkeypatch)
    assert module.security_config.redis_prefix != "flaskapi_guard:"
    client = module.app.test_client()
    client.get("/", environ_base=LOCALHOST)
    bans = ip_ban_manager_for(module.security_config)
    bans.ban_ip(BANNED_IP, 300, "test")
    assert bans.is_ip_banned(BANNED_IP)

    response = client.post(
        "/admin/unban-ip", json={"ip": BANNED_IP}, environ_base=LOCALHOST
    )

    assert response.status_code == 200
    assert not bans.is_ip_banned(BANNED_IP)
    assert response.get_json()["details"]["ip"] == BANNED_IP


@pytest.mark.parametrize("garbage", ["not-an-ip", "203.0.113.0/24", "", "1.2.3.999"])
@pytest.mark.parametrize("name", ["simple_app", "advanced_app"])
def test_unban_route_refuses_input_that_is_not_an_ip(
    name: str, garbage: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load_example(name, monkeypatch)
    client = module.app.test_client()
    response = client.post(
        "/admin/unban-ip", json={"ip": garbage}, environ_base=LOCALHOST
    )
    assert response.status_code == 400


OUTSIDER = {"REMOTE_ADDR": "10.0.0.6"}


@pytest.mark.parametrize("name", ["simple_app", "advanced_app"])
def test_emergency_switch_refuses_outsiders_and_keeps_the_admin(
    name: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load_example(name, monkeypatch)
    client = module.app.test_client()
    assert client.get("/", environ_base=OUTSIDER).status_code == 200

    on = client.put(
        "/admin/emergency-mode", json={"enable": True}, environ_base=LOCALHOST
    )
    assert on.status_code == 200
    assert on.get_json()["details"]["emergency_mode"] is True
    assert on.get_json()["details"]["added_to_emergency_whitelist"] == ["127.0.0.1"]
    assert on.get_json()["details"]["emergency_whitelist"] == ["127.0.0.1"]
    assert module.security_config.emergency_mode is True
    assert client.get("/", environ_base=OUTSIDER).status_code == 503
    assert client.get("/", environ_base=LOCALHOST).status_code == 200

    off = client.put(
        "/admin/emergency-mode", json={"enable": False}, environ_base=LOCALHOST
    )
    assert off.get_json()["details"]["emergency_mode"] is False
    assert off.get_json()["details"]["removed_from_emergency_whitelist"] == [
        "127.0.0.1"
    ]
    assert module.security_config.emergency_whitelist == []
    assert client.get("/", environ_base=OUTSIDER).status_code == 200
    assert client.get("/", environ_base=LOCALHOST).status_code == 200


@pytest.mark.parametrize("body", [{"enable": "yes"}, {"enable": 1}, {}, [True]])
@pytest.mark.parametrize("name", ["simple_app", "advanced_app"])
def test_emergency_switch_refuses_a_body_that_is_not_a_boolean(
    name: str, body: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load_example(name, monkeypatch)
    response = module.app.test_client().put(
        "/admin/emergency-mode", json=body, environ_base=LOCALHOST
    )
    assert response.status_code == 400
    assert module.security_config.emergency_mode is False


@pytest.mark.parametrize("name", ["simple_app", "advanced_app"])
def test_emergency_switch_defers_to_the_dashboard_when_dynamic_rules_are_on(
    name: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load_example(name, monkeypatch)
    monkeypatch.setattr("guard_agent.SyncGuardAgentHandler", lambda config: MagicMock())
    config = module.security_config
    monkeypatch.setattr(config, "agent_api_key", "test-key")
    monkeypatch.setattr(config, "enable_agent", True)
    monkeypatch.setattr(config, "enable_dynamic_rules", True)
    response = module.app.test_client().put(
        "/admin/emergency-mode", json={"enable": True}, environ_base=LOCALHOST
    )
    assert response.status_code == 409
    assert b"dashboard" in response.data
    assert config.emergency_mode is False


def _stats(client: Any) -> dict[str, Any]:
    body = client.get("/admin/stats", environ_base=LOCALHOST).get_json()
    payload: dict[str, Any] = body.get("details", body)
    return payload


@pytest.mark.parametrize("name", ["simple_app", "advanced_app"])
def test_stats_come_from_the_engine_and_carry_no_invented_numbers(
    name: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load_example(name, monkeypatch)
    client = module.app.test_client()
    client.get("/", environ_base=LOCALHOST)
    bans = ip_ban_manager_for(module.security_config)
    before = _stats(client)
    bans.ban_ip(BANNED_IP, 300, "test")
    after = _stats(client)
    bans.unban_ip(BANNED_IP)
    lifted = _stats(client)

    assert BANNED_IP not in before["banned_ips"]
    assert BANNED_IP in after["banned_ips"]
    assert BANNED_IP not in lifted["banned_ips"]
    assert not {"total_requests", "blocked_requests", "suspicious_activities"} & set(
        after
    )
    assert after["active_rules"]["rate_limit"] == module.security_config.rate_limit


@pytest.mark.parametrize("name", ["simple_app", "advanced_app"])
def test_emergency_switch_leaves_a_whitelist_it_did_not_extend_alone(
    name: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load_example(name, monkeypatch)
    monkeypatch.setattr(module.security_config, "emergency_whitelist", ["127.0.0.1"])
    client = module.app.test_client()

    on = client.put(
        "/admin/emergency-mode", json={"enable": True}, environ_base=LOCALHOST
    )
    off = client.put(
        "/admin/emergency-mode", json={"enable": False}, environ_base=LOCALHOST
    )

    assert on.get_json()["details"]["added_to_emergency_whitelist"] == []
    assert off.get_json()["details"]["removed_from_emergency_whitelist"] == []
    assert module.security_config.emergency_whitelist == ["127.0.0.1"]
