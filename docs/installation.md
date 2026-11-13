---

title: Installation - FlaskAPI Guard
description: Learn how to install and set up FlaskAPI Guard, a comprehensive security extension for Flask applications
keywords: flaskapi guard installation, python security extension, flask security setup
---

Installation
============

Install `flaskapi-guard` with **uv** (recommended), **poetry**, or **pip**:

=== "uv"

    ```bash
    uv add flaskapi-guard
    ```

=== "poetry"

    ```bash
    poetry add flaskapi-guard
    ```

=== "pip"

    ```bash
    pip install flaskapi-guard
    ```

**Note**: Ensure you have Python 3.10 or higher installed.

Optional extras. The base install carries `flaskapi-guard`'s own dependencies and guard-core (`cachetools`, `pydantic` and `typing-extensions`); it does not carry the Redis client, the GeoIP reader or the downloaders. A config that needs a package you did not install is refused when `SecurityConfig` is built, with a message that names the extra:

| Extra | Adds | Needed for |
|---|---|---|
| `flaskapi-guard[redis]` | the Redis client | `enable_redis=True`: Redis-backed rate limits, bans, caches and shared state |
| `flaskapi-guard[geo]` | `maxminddb` and the downloader of the built-in GeoIP manager | country rules (`blocked_countries`, `whitelist_countries`, `@block_countries`, `@allow_countries`, `@geo_rate_limit`) and `ipinfo_token` |
| `flaskapi-guard[cloud]` | `aiohttp` and `requests` | `block_cloud_providers` |

Combine them as needed, for example `pip install "flaskapi-guard[redis,geo]"`.

___

Prerequisites
-------------

Before using `flaskapi-guard`'s country filtering features, obtain an IPInfo token:

1. Visit [IPInfo's website](https://ipinfo.io/signup) to create a free account.
2. After signing up, you'll receive an API token.
3. The free tier includes:
   - Up to 50,000 requests per month.
   - Access to IP to Country database.
   - Daily database updates.
   - IPv4 & IPv6 support.

Note: The IPInfo token is only required when using the country filtering features (`blocked_countries`, `whitelist_countries` and/or `block_cloud_providers`).

**Usage Example**:

```python
from flask import Flask
from flaskapi_guard import FlaskAPIGuard
from flaskapi_guard import SecurityConfig
from flaskapi_guard import IPInfoManager

app = Flask(__name__)
config = SecurityConfig(
    geo_ip_handler=IPInfoManager(
        "your_ipinfo_token_here"
    ),  # NOTE: Required when using country blocking
    enable_redis=True,  # Off unless a Redis field is set, enable to use Redis (without it state is in-memory)
    redis_url="redis://localhost:6379/0",
    redis_prefix="prod:security:",
    whitelist=["192.168.1.1", "2001:db8::1"],
    blacklist=["10.0.0.1", "2001:db8::2"],
    blocked_countries=["AR", "IT"],
    blocked_user_agents=["curl", "wget"],
    auto_ban_threshold=5,
    auto_ban_duration=86400,
    custom_log_file="security.log",
)

FlaskAPIGuard(app, config=config)
```

**Note**: When Redis is disabled:

- Rate limiting and IP bans become instance-local
- Cloud provider IP ranges refresh every hour
- Penetration patterns reset on app restart

___

Secure Proxy Configuration
---------------------------

If your application is behind a proxy or load balancer, configure trusted proxies:

```python
config = SecurityConfig(
    # Security configuration for proxies
    trusted_proxies=["10.0.0.1", "192.168.1.0/24"],  # Only trust specific IPs/ranges
    trusted_proxy_depth=1,  # Default proxy depth
    trust_x_forwarded_proto=True,  # Trust X-Forwarded-Proto from trusted proxies
    # Other config options...
)
```

This prevents IP spoofing attacks via X-Forwarded-For header manipulation.

___

Upgrading to 5.0.0
------------------

guard-core 5.0.0 starts with `fail_on_misconfiguration=True`, so a misconfiguration that older releases only logged now stops the app. A test suite that builds its own app with its own `SecurityDecorator` hits it first. The error looks like this, with one line per decorated route:

```text
MisconfigurationError: 159 misconfigurations:
- Route '<module.func>' carries a route id that this SecurityDecorator does not know: it was decorated by a different SecurityDecorator instance than the one the middleware uses, so none of its decorators apply. Decorate the route with the SecurityDecorator the middleware uses.
Set fail_on_misconfiguration=False to start with it anyway.
```

The routes were decorated by one `SecurityDecorator` and the extension uses another, so the decorators would never run. Build the test app the way production does: import the app's own decorator (or the factory that creates it) and decorate the test routes with that same instance (the instance you give to `set_decorator_handler`, or the only one that holds the routes of the app). Do not set `fail_on_misconfiguration=False` to silence the error: it hides the routes whose decorators are not enforced.
