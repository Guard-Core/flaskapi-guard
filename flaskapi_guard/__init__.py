from importlib import import_module
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _pkg_version
from typing import TYPE_CHECKING

from guard_core import SecurityConfig
from guard_core._config_capabilities import register_adapter
from guard_core.sync import endpoint_rate_limit_key_problems, release_app
from guard_core.sync.decorators import RouteConfig, SecurityDecorator
from guard_core.sync.handlers.behavior_handler import BehaviorRule, BehaviorTracker
from guard_core.sync.handlers.ipban_handler import IPBanManager, ip_ban_manager
from guard_core.sync.handlers.security_headers_handler import (
    SecurityHeadersManager,
    security_headers_manager,
)
from guard_core.sync.handlers.suspatterns_handler import sus_patterns_handler
from guard_core.sync.protocols.geo_ip_protocol import SyncGeoIPHandler as GeoIPHandler
from guard_core.sync.protocols.redis_protocol import (
    SyncRedisHandlerProtocol as RedisHandlerProtocol,
)
from guard_core.sync.protocols.request_protocol import (
    SyncGuardRequest as GuardRequest,
)
from guard_core.sync.protocols.response_protocol import GuardResponse

from flaskapi_guard.adapters import FlaskGuardRequest, FlaskGuardResponse
from flaskapi_guard.extension import FlaskAPIGuard

register_adapter("flaskapi-guard")

if TYPE_CHECKING:
    from guard_core.sync.handlers.cloud_handler import CloudManager, cloud_handler
    from guard_core.sync.handlers.ipinfo_handler import IPInfoManager
    from guard_core.sync.handlers.ratelimit_handler import (
        RateLimitManager,
        rate_limit_handler,
    )
    from guard_core.sync.handlers.redis_handler import RedisManager, redis_handler

_LAZY_MODULE_BY_NAME: dict[str, str] = {
    "CloudManager": "guard_core.sync.handlers.cloud_handler",
    "cloud_handler": "guard_core.sync.handlers.cloud_handler",
    "IPInfoManager": "guard_core.sync.handlers.ipinfo_handler",
    "RateLimitManager": "guard_core.sync.handlers.ratelimit_handler",
    "rate_limit_handler": "guard_core.sync.handlers.ratelimit_handler",
    "RedisManager": "guard_core.sync.handlers.redis_handler",
    "redis_handler": "guard_core.sync.handlers.redis_handler",
}


def __getattr__(name: str) -> object:
    module_name = _LAZY_MODULE_BY_NAME.get(name)
    if module_name is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    value = getattr(import_module(module_name), name)
    globals()[name] = value
    return value


try:
    __version__ = _pkg_version("flaskapi_guard")
except PackageNotFoundError:
    __version__ = "0.0.0+unknown"

__all__ = [
    "__version__",
    "FlaskAPIGuard",
    "FlaskGuardRequest",
    "FlaskGuardResponse",
    "SecurityConfig",
    "SecurityDecorator",
    "RouteConfig",
    "BehaviorTracker",
    "BehaviorRule",
    "ip_ban_manager",
    "IPBanManager",
    "cloud_handler",
    "CloudManager",
    "IPInfoManager",
    "rate_limit_handler",
    "RateLimitManager",
    "redis_handler",
    "RedisManager",
    "security_headers_manager",
    "SecurityHeadersManager",
    "sus_patterns_handler",
    "endpoint_rate_limit_key_problems",
    "release_app",
    "GeoIPHandler",
    "RedisHandlerProtocol",
    "GuardRequest",
    "GuardResponse",
]
