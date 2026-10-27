from __future__ import annotations

import time

from guard_core.models import SecurityConfig
from guard_core.sync.handlers import ipban_handler
from guard_core.sync.handlers.ipban_handler import (
    IPBanManager,
    ip_ban_manager,
    ip_ban_manager_for,
)
from guard_core.sync.protocols.request_protocol import SyncGuardRequest

from tests.redis_isolation import REDIS_URL


def _redis_config(prefix: str) -> SecurityConfig[SyncGuardRequest]:
    return SecurityConfig[SyncGuardRequest](
        enable_redis=True,
        redis_url=REDIS_URL,
        redis_prefix=prefix,
        enable_penetration_detection=False,
    )


def test_a_second_prefix_app_leaves_the_default_manager_as_singleton() -> None:
    first, second = _redis_config("wp186a:"), _redis_config("wp186b:")
    assert ip_ban_manager_for(first, bind=True) is ip_ban_manager
    own = ip_ban_manager_for(second, bind=True)
    assert own is not ip_ban_manager
    own.initialize_redis(None)
    assert IPBanManager() is ip_ban_manager
    ip_ban_manager.banned_ips["203.0.113.9"] = time.time() + 60


def test_the_reset_after_it_cleared_the_default_manager() -> None:
    assert IPBanManager() is ip_ban_manager
    assert ipban_handler.ip_ban_manager is ip_ban_manager
    assert "203.0.113.9" not in ip_ban_manager.banned_ips
