import logging
import time
from datetime import datetime, timezone
from ipaddress import ip_address

from flask import Blueprint, jsonify, request
from flask.typing import ResponseReturnValue
from guard_core.sync.handlers.cloud_handler import cloud_handler_for
from guard_core.sync.handlers.ipban_handler import ip_ban_manager_for
from guard_core.sync.handlers.ratelimit_handler import RateLimitManager

from app.models import message_response, stats_response
from app.security import guard, security_config

logger = logging.getLogger(__name__)

bp = Blueprint("admin", __name__, url_prefix="/admin")

# 127.0.0.1 is added to emergency_whitelist only when absent, and removed on disable
# only when this route added it, so a startup or dashboard whitelist is never edited.
_ADMIN_ADDED_LOOPBACK = {"added": False}

DYNAMIC_RULES_OWN_EMERGENCY_MODE = (
    "this app takes emergency mode from the dashboard's dynamic rules; a local "
    "switch would be reverted at the next rule update"
)


@bp.route("/unban-ip", methods=["POST"])
@guard.require_ip(whitelist=["127.0.0.1"])
def unban_ip_address() -> ResponseReturnValue:
    data = request.get_json(silent=True) or {}
    try:
        ip = str(ip_address(str(data.get("ip", "")).strip()))
    except (ValueError, AttributeError):
        return jsonify({"detail": "Not an IP address"}), 400
    ip_ban_manager_for(security_config).unban_ip(ip)
    logger.info("Unbanning IP: %s", ip)
    return jsonify(
        message_response(
            f"IP {ip} has been unbanned",
            details={"action": "unban", "ip": ip},
        )
    )


@bp.route("/stats")
@guard.require_ip(whitelist=["127.0.0.1"])
def get_security_stats() -> ResponseReturnValue:
    """Reads this process's ban table (IPBanManager.banned_ips), its in-memory rate
    limit windows (RateLimitManager.request_timestamps) and the SecurityConfig
    rules. With Redis on, the windows live in Redis under redis_prefix and
    rate_limit_windows is null; bans other workers wrote also live in Redis. The
    engine keeps no request counters, so none are reported."""
    redis_in_use = bool(security_config.enable_redis and security_config.redis_url)
    now = time.time()
    banned_ips = sorted(
        ip
        for ip, expiry in ip_ban_manager_for(security_config).banned_ips.items()
        if expiry > now
    )
    rate_limit_windows = (
        None
        if redis_in_use
        else {
            key: len(window)
            for key, window in RateLimitManager(
                security_config
            ).request_timestamps.items()
            if window
        }
    )
    active_rules = {
        "rate_limit": security_config.rate_limit,
        "rate_limit_window": security_config.rate_limit_window,
        "auto_ban_threshold": security_config.auto_ban_threshold,
        "blocked_countries": list(security_config.blocked_countries),
        "block_cloud_providers": sorted(security_config.block_cloud_providers or ()),
    }
    return jsonify(
        stats_response(
            banned_ips=banned_ips,
            rate_limit_windows=rate_limit_windows,
            redis_in_use=redis_in_use,
            redis_prefix=security_config.redis_prefix,
            active_rules=active_rules,
        )
    )


@bp.route("/clear-cache", methods=["POST"])
@guard.require_ip(whitelist=["127.0.0.1"])
def clear_security_cache() -> ResponseReturnValue:
    """Clears all bans and rate limit windows for this app's Redis prefix."""
    ip_ban_manager_for(security_config).reset()
    RateLimitManager(security_config).reset()
    return jsonify(
        message_response(
            "Security caches cleared",
            details={"cleared": ["ip_bans", "rate_limit_windows"]},
        )
    )


@bp.route("/emergency-mode", methods=["PUT"])
@guard.require_ip(whitelist=["127.0.0.1"])
def toggle_emergency_mode() -> ResponseReturnValue:
    """Switches emergency mode on this process through SecurityConfig.

    Emergency mode has two sources: SecurityConfig.emergency_mode set at startup,
    or a dynamic rule from the dashboard at runtime. This is the local switch: it
    changes this process only, so a multi-worker deployment uses the dashboard's
    dynamic rule. While emergency mode is on only emergency_whitelist is admitted,
    so enabling adds 127.0.0.1 to keep this admin route reachable.
    """
    data = request.get_json(silent=True)
    enable = data.get("enable") if isinstance(data, dict) else None
    if not isinstance(enable, bool):
        return jsonify({"detail": 'The body must be {"enable": true|false}'}), 400
    if security_config.enable_dynamic_rules:
        return jsonify({"detail": DYNAMIC_RULES_OWN_EMERGENCY_MODE}), 409
    added: list[str] = []
    removed: list[str] = []
    if enable and "127.0.0.1" not in security_config.emergency_whitelist:
        security_config.emergency_whitelist = [
            *security_config.emergency_whitelist,
            "127.0.0.1",
        ]
        _ADMIN_ADDED_LOOPBACK["added"] = True
        added = ["127.0.0.1"]
    security_config.emergency_mode = enable
    if not enable and _ADMIN_ADDED_LOOPBACK["added"]:
        security_config.emergency_whitelist = [
            entry
            for entry in security_config.emergency_whitelist
            if entry != "127.0.0.1"
        ]
        _ADMIN_ADDED_LOOPBACK["added"] = False
        removed = ["127.0.0.1"]
    state = "enabled" if security_config.emergency_mode else "disabled"
    return jsonify(
        message_response(
            f"Emergency mode {state}",
            details={
                "emergency_mode": security_config.emergency_mode,
                "emergency_whitelist": list(security_config.emergency_whitelist),
                "added_to_emergency_whitelist": added,
                "removed_from_emergency_whitelist": removed,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
        )
    )


@bp.route("/cloud-status")
@guard.require_ip(whitelist=["127.0.0.1"])
def cloud_status() -> ResponseReturnValue:
    from app.security import security_config

    last_updated = {}
    # `cloud_handler` is the default app's; this app's own manager:
    for provider, dt in cloud_handler_for(security_config).last_updated.items():
        last_updated[provider] = dt.isoformat() if dt else None
    return jsonify(
        message_response(
            "Cloud provider IP range status",
            details={
                "refresh_interval": (security_config.cloud_ip_refresh_interval),
                "providers": last_updated,
            },
        )
    )
