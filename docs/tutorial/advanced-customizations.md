---

title: Advanced Customization - FlaskAPI Guard
description: Learn how to extend FlaskAPI Guard with custom protocols and handlers
keywords: custom protocols, extending flaskapi guard, advanced customization
---

Advanced Customization
=======================

FlaskAPI Guard uses a protocol-based architecture that makes it highly extensible. This guide explains how the protocol system works and how to create custom implementations.

___

Protocol-Based Architecture
----------------------------

FlaskAPI Guard uses Python's Protocol system to define interfaces that components must implement. This allows you to:

1. Replace built-in handlers with custom implementations
2. Extend functionality without modifying the core library
3. Better separate concerns in your codebase

___

Why Protocols?
--------------

The protocol system solves several important problems:

1. **Avoiding dependency on third-party services**: You can replace the built-in IPInfo geo-location with your own service
2. **Preventing circular imports**: The protocols help break dependency cycles in the codebase
3. **Enabling extension points**: Clear interfaces for adding custom functionality

___

Available Protocols
-------------------

GeoIPHandler Protocol
---------------------

The `GeoIPHandler` protocol (exported by `flaskapi_guard` as an alias of `guard_core.sync.protocols.geo_ip_protocol.SyncGeoIPHandler`) defines the interface for any geographical IP handler:

```python
@runtime_checkable
class GeoIPHandler(Protocol):
    """Protocol for geographical IP handler."""

    @property
    def is_initialized(self) -> bool: ...

    def initialize(self) -> None: ...

    def initialize_redis(self, redis_handler: RedisHandlerProtocol) -> None: ...

    def initialize_agent(self, agent_handler: SyncAgentHandlerProtocol) -> None: ...

    def get_country(self, ip: str) -> str | None: ...

    def refresh(self) -> None: ...

    def close(self) -> None: ...
```

Method Details
--------------

- `is_initialized`: Should return whether the handler is ready to use
- `initialize()`: Should set up the handler (load databases, connect to APIs, etc.)
- `initialize_redis()`: Should store the redis handler for optional caching
- `initialize_agent()`: Should store the agent handler so dataset-refresh failures can be reported
- `get_country()`: Should return the ISO 3166-1 alpha-2 country code for the IP
- `refresh()`: Should reload the dataset from its source (periodic update)
- `close()`: Should release the dataset and file handles

RedisHandlerProtocol
--------------------

**IMPORTANT**: Users do NOT need to implement this protocol. It exists purely for internal use to break dependency cycles and define what the Redis handler must support for the custom GeoIP handlers. `flaskapi_guard` exports it as an alias of `guard_core.sync.protocols.redis_protocol.SyncRedisHandlerProtocol`, and the listing below is that protocol in full.

```python
@runtime_checkable
class RedisHandlerProtocol(Protocol):
    def get_key(self, namespace: str, key: str) -> str | None: ...

    def get_many(self, pairs: Sequence[tuple[str, str]]) -> list[str | None]: ...

    def set_key(
        self, namespace: str, key: str, value: RedisValue, ttl: int | None = None
    ) -> bool | None: ...

    def set_key_if_absent(
        self, namespace: str, key: str, value: RedisValue, ttl: int | None = None
    ) -> bool: ...

    def incr(self, namespace: str, key: str, ttl: int | None = None) -> int | None: ...

    def write_atomically(
        self,
        *,
        sets: Sequence[tuple[str, str, RedisValue, int | None]] = (),
        deletes: Sequence[tuple[str, str]] = (),
        increment: tuple[str, str] | None = None,
    ) -> None: ...

    def delete(self, namespace: str, key: str) -> int | None: ...

    def delete_pattern(self, pattern: str) -> int | None: ...

    def keys(self, pattern: str) -> list[str] | None: ...

    def write_ban_extending_only(
        self,
        namespace: str,
        key: str,
        expiry: str,
        duration: int,
        *,
        version: tuple[str, str],
        advance_version: bool = False,
        rule_owned: bool = False,
    ) -> float: ...

    def owned_ban_members(self) -> list[str]: ...

    def owned_ban_state(
        self, namespace: str, key: str
    ) -> tuple[float | None, float | None]: ...

    def purge_owned_ban(self, member: str) -> int: ...

    def disown_ban(self, namespace: str, key: str) -> None: ...

    def record_sliding_window_hit(
        self,
        namespace: str,
        key: str,
        timestamp: float,
        window_start: float,
        ttl: int,
        *,
        index: tuple[str, int] | None = None,
        index_refused: list[bool] | None = None,
    ) -> int: ...

    def count_sliding_window_hits(
        self, namespace: str, key: str, window_start: float
    ) -> int: ...

    def sum_indexed_window_hits(
        self, namespace: str, index_key: str, window_start: float
    ) -> int: ...

    def detection_correlation_keys(self, client_ip: str) -> list[str]: ...

    def record_detection_strikes(
        self,
        client_ip: str,
        categories: Sequence[str],
        timestamp: float,
        window_start: float,
        ttl: int,
        cap: int,
    ) -> tuple[int, int, dict[str, int]]: ...

    def read_detection_categories(
        self, client_ip: str, window_start: float
    ) -> list[str]: ...

    def forget_detection_strikes(self, client_ip: str) -> None: ...

    def initialize(self) -> None: ...

    def initialize_agent(self, agent_handler: SyncAgentHandlerProtocol) -> None: ...

    def get_connection(self) -> ContextManager[Redis]: ...
```

___

How Protocols Are Used
----------------------

The FlaskAPI Guard initialization flow works like this:

1. You create a `SecurityConfig` with your custom `geo_ip_handler`
2. You initialize the `FlaskAPIGuard` extension with this config
3. When the extension initializes, it:
   - Checks if you provided a `geo_ip_handler` that implements the protocol
   - If Redis is enabled, it passes its internal `RedisManager` to your handler
   - Your handler can use this Redis connection for caching or whatever you need

This makes your custom geo IP handler fully integrated with the extension's Redis infrastructure.

___

Implementation Examples
-----------------------

Example: Custom Geo IP Service
-------------------------------

Here's a complete example of a custom GeoIPHandler implementation that uses a different service:

```python
from flaskapi_guard import GeoIPHandler
from flaskapi_guard import RedisHandlerProtocol
from guard_core.sync.protocols.agent_protocol import SyncAgentHandlerProtocol


class CustomGeoIPHandler:
    """Custom handler using Custom GeoIP database"""

    def __init__(self, license_key: str, db_path: str = "CustomGeoIP.mmdb"):
        self._initialized = False
        self.license_key = license_key
        self.db_path = db_path
        self.reader = None
        self.redis = None  # Will store the FlaskAPI Guard's Redis handler
        self.agent = None  # Will store the agent handler

    @property
    def is_initialized(self) -> bool:
        return self.reader is not None

    def initialize(self) -> None:
        """Initialize by downloading or loading the Custom GeoIP database"""
        import os
        import somelibrary

        # Check if we have a cached copy in Redis
        if self.redis:
            cached_db = self.redis.get_key("custom", "database")
            if cached_db:
                with open(self.db_path, "wb") as f:
                    f.write(
                        cached_db
                        if isinstance(cached_db, bytes)
                        else cached_db.encode("latin-1")
                    )
                self.reader = somelibrary.Reader(self.db_path)
                self._initialized = True
                return

        # Download if needed (simplified - in a real app, use your API)
        if not os.path.exists(self.db_path):
            # Custom code to download database using license_key
            pass

        # Open the database
        if os.path.exists(self.db_path):
            self.reader = somelibrary.Reader(self.db_path)
            self._initialized = True

    def initialize_redis(self, redis_handler: RedisHandlerProtocol) -> None:
        """Store Redis handler and initialize"""
        self.redis = redis_handler  # Store the Redis handler provided by FlaskAPI Guard
        self.initialize()

    def initialize_agent(self, agent_handler: SyncAgentHandlerProtocol) -> None:
        """Keep the agent handler to report dataset-refresh failures"""
        self.agent = agent_handler

    def get_country(self, ip: str) -> str | None:
        """Get country code from IP using Custom GeoIP database"""
        if not self.reader:
            raise RuntimeError("Database not initialized")

        try:
            response = self.reader.country(ip)
            return response.country.iso_code
        except Exception:
            return None

    def refresh(self) -> None:
        """Reload the database from disk"""
        self.initialize()

    def close(self) -> None:
        """Release the database"""
        self.reader = None
```

___

Usage in Application
--------------------

```python
from flask import Flask
from flaskapi_guard.extension import FlaskAPIGuard
from flaskapi_guard import SecurityConfig
from your_custom_module import CustomGeoIPHandler

app = Flask(__name__)

# Use custom handler instead of default IPInfoManager
config = SecurityConfig(
    geo_ip_handler=CustomGeoIPHandler(args),
    blocked_countries=["CN", "RU"],
    # Other configuration...
)

FlaskAPIGuard(app, config=config)
```

___

Technical Details: How Redis Integration Works
----------------------------------------------

When you create a custom GeoIPHandler:

1. FlaskAPI Guard's extension will call your handler's `initialize_redis()` method
2. It passes its internal `RedisManager` to your handler
3. Your handler can store this manager and use it for caching

You don't need to:

- Create your own Redis connection
- Implement RedisHandlerProtocol
- Manage Redis connection pools

The built-in RedisManager handles all of this for you.

When a GeoIPHandler implementation receives a Redis handler in `initialize_redis()`, it can use it to:

1. Cache lookup results to improve performance
2. Store database files across application restarts
3. Share state across multiple application instances

The Redis handler provides these key methods:

```python
# Store a value with optional TTL
redis_handler.set_key("namespace", "key", "value", ttl=3600)

# Retrieve a value
value = redis_handler.get_key("namespace", "key")

# Use the connection directly (advanced)
with redis_handler.get_connection() as conn:
    # Direct Redis operations
    pass
```

Remember: You don't implement the RedisHandlerProtocol yourself - FlaskAPI Guard provides its built-in RedisManager which meets this protocol and is automatically passed to your custom GeoIPHandler.
