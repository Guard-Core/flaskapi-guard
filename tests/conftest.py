import os
import sys
import weakref
from collections.abc import Callable, Generator, Iterator
from pathlib import Path
from typing import Any, Concatenate, ParamSpec, cast

import pytest
from flask import Flask
from guard_core.models import SecurityConfig
from guard_core.protocols.geo_ip_protocol import GeoIPHandler
from guard_core.sync import release_app
from guard_core.sync.core.initialization.handler_initializer import HandlerInitializer
from guard_core.sync.handlers.cloud_handler import cloud_handler, cloud_handler_for
from guard_core.sync.handlers.ipban_handler import reset_global_state
from guard_core.sync.handlers.ipinfo_handler import IPInfoManager
from guard_core.sync.handlers.ratelimit_handler import rate_limit_handler
from guard_core.sync.handlers.suspatterns_handler import sus_patterns_handler
from guard_core.sync.protocols.request_protocol import SyncGuardRequest

from flaskapi_guard.extension import FlaskAPIGuard
from tests import network_guard, thread_guard
from tests.agent_loop import close_the_agent_event_loop
from tests.redis_isolation import (
    REDIS_PREFIX,
    REDIS_URL,
    delete_every_key_under_the_suite_prefix,
    point_security_config_defaults_at_the_test_redis,
    refuse_connections_to_the_default_redis_port,
    refused_connections,
)

network_guard.install()
thread_guard.install()

IPINFO_TOKEN = str(os.getenv("IPINFO_TOKEN"))

point_security_config_defaults_at_the_test_redis()


@pytest.fixture(scope="session", autouse=True)
def _refuse_the_default_redis_port() -> Generator[None, None, None]:
    with pytest.MonkeyPatch.context() as monkeypatch:
        refuse_connections_to_the_default_redis_port(monkeypatch)
        yield


@pytest.fixture(autouse=True)
def _close_the_agent_event_loop() -> Generator[None, None, None]:
    yield
    close_the_agent_event_loop()


@pytest.fixture(autouse=True)
def refused_redis_connections() -> Generator[list[tuple[Any, ...]], None, None]:
    refused_connections.clear()
    yield refused_connections
    attempts = list(refused_connections)
    refused_connections.clear()
    assert not attempts, f"the test connected to port 6379: {attempts}"


def pytest_terminal_summary(terminalreporter: pytest.TerminalReporter) -> None:
    terminalreporter.write_line(
        f"redis isolation: REDIS_URL={REDIS_URL} REDIS_PREFIX={REDIS_PREFIX}"
    )


def _refuse_the_ipinfo_download(self: object) -> None:
    raise ConnectionError("the test suite has no network")


@pytest.fixture(autouse=True)
def no_ipinfo_database_download(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "guard_core.sync.handlers.ipinfo_handler.IPInfoManager._fetch_and_store_database",
        _refuse_the_ipinfo_download,
    )


@pytest.fixture(autouse=True)
def no_cloud_range_downloads(monkeypatch: pytest.MonkeyPatch) -> None:
    # The cloud refresh threads that apps start would otherwise download the
    # provider range files for real, in daemon threads that outlive the test
    # and allocate inside the tracemalloc window of the stream-peak tests.
    monkeypatch.setattr(
        "guard_core.sync.handlers.cloud_handler._fetch_provider_ranges",
        lambda provider: (set(), {}),
    )


_P = ParamSpec("_P")


def _recording_the_config_it_binds(
    original: Callable[Concatenate[HandlerInitializer, _P], None],
    bound: list[weakref.ref[SecurityConfig[SyncGuardRequest]]],
) -> Callable[Concatenate[HandlerInitializer, _P], None]:
    def initializer(
        self: HandlerInitializer, *args: _P.args, **kwargs: _P.kwargs
    ) -> None:
        original(self, *args, **kwargs)
        bound.append(weakref.ref(self.config))

    return initializer


def _let_the_scheduled_cloud_refresh_end(
    config: SecurityConfig[SyncGuardRequest],
) -> None:
    # A request schedules a background download; it must end while the fixture
    # that refuses the download is still in place.
    refresh = cloud_handler_for(config)._refresh_task
    if refresh is not None:
        refresh.join(timeout=30)


@pytest.fixture(autouse=True)
def _release_every_app_between_tests(
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[None]:
    """HandlerInitializer binds an app's config to the engine's managers; an app
    that nothing releases keeps that binding until the collector frees it, so
    which managers the next test gets would depend on collector timing (D-317)."""
    bound: list[weakref.ref[SecurityConfig[SyncGuardRequest]]] = []
    monkeypatch.setattr(
        HandlerInitializer,
        "__init__",
        _recording_the_config_it_binds(HandlerInitializer.__init__, bound),
    )
    yield
    for reference in bound:
        config = reference()
        if config is not None:
            _let_the_scheduled_cloud_refresh_end(config)
            release_app(config)


@pytest.fixture(autouse=True)
def reset_state() -> Generator[None, None, None]:
    reset_global_state()

    original_patterns = sus_patterns_handler.patterns.copy()

    cloud_instance = cloud_handler._instance
    if cloud_instance:
        cloud_instance.ip_ranges = {"AWS": set(), "GCP": set(), "Azure": set()}
        cloud_instance.redis_handler = None

    if IPInfoManager._instance:
        if IPInfoManager._instance.reader:
            IPInfoManager._instance.reader.close()
        IPInfoManager._instance = None

    yield
    sus_patterns_handler.patterns = original_patterns.copy()


@pytest.fixture
def security_config() -> SecurityConfig[SyncGuardRequest]:
    return SecurityConfig[SyncGuardRequest](
        geo_ip_handler=cast(GeoIPHandler, IPInfoManager(IPINFO_TOKEN, None)),
        enable_redis=False,
        enable_penetration_detection=False,
        whitelist=("127.0.0.1",),
        blacklist=("192.168.1.1",),
        blocked_countries=frozenset({"CN"}),
        blocked_user_agents=[r"badbot"],
        auto_ban_threshold=3,
        auto_ban_duration=300,
        custom_log_file="test_log.log",
        custom_error_responses={
            403: "Custom Forbidden",
            429: "Custom Too Many Requests",
        },
        enable_cors=True,
        cors_allow_origins=["https://example.com"],
        cors_allow_methods=["GET", "POST"],
        cors_allow_headers=["*"],
        cors_allow_credentials=True,
        cors_expose_headers=["X-Custom-Header"],
        cors_max_age=600,
    )


@pytest.fixture
def flaskapi_guard_app() -> Generator[tuple[Flask, FlaskAPIGuard], None, None]:
    config = SecurityConfig[SyncGuardRequest](
        geo_ip_handler=cast(GeoIPHandler, IPInfoManager(IPINFO_TOKEN)),
        enable_penetration_detection=False,
        whitelist=(),
        blacklist=(),
        auto_ban_threshold=10,
        auto_ban_duration=300,
    )
    app = Flask(__name__)
    app.config["TESTING"] = True
    guard = FlaskAPIGuard(app, config=config)
    yield app, guard
    guard.reset()


@pytest.fixture(scope="session")
def ipinfo_db_path(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return tmp_path_factory.mktemp("ipinfo_data") / "country_asn.mmdb"


@pytest.fixture
def security_config_redis(ipinfo_db_path: Path) -> SecurityConfig[SyncGuardRequest]:
    return SecurityConfig[SyncGuardRequest](
        geo_ip_handler=cast(GeoIPHandler, IPInfoManager(IPINFO_TOKEN, ipinfo_db_path)),
        redis_url=REDIS_URL,
        redis_prefix=REDIS_PREFIX,
        enable_penetration_detection=False,
        whitelist=("127.0.0.1",),
        blacklist=("192.168.1.1",),
        blocked_countries=frozenset({"CN"}),
        blocked_user_agents=[r"badbot"],
        auto_ban_threshold=3,
        auto_ban_duration=300,
        custom_log_file="test_log.log",
        custom_error_responses={
            403: "Custom Forbidden",
            429: "Custom Too Many Requests",
        },
        enable_cors=True,
        cors_allow_origins=["https://example.com"],
        cors_allow_methods=["GET", "POST"],
        cors_allow_headers=["*"],
        cors_allow_credentials=True,
        cors_expose_headers=["X-Custom-Header"],
        cors_max_age=600,
    )


@pytest.fixture(autouse=True)
def redis_cleanup() -> None:
    """Delete only the keys under this suite's own prefix before each test"""
    delete_every_key_under_the_suite_prefix()


@pytest.fixture(autouse=True, scope="session")
def redis_cleanup_at_session_end() -> Generator[None, None, None]:
    yield
    delete_every_key_under_the_suite_prefix()


@pytest.fixture(autouse=True)
def reset_rate_limiter() -> None:
    try:
        config = SecurityConfig[SyncGuardRequest](
            geo_ip_handler=cast(GeoIPHandler, IPInfoManager(IPINFO_TOKEN, None)),
            enable_redis=False,
        )
        rate_limit = rate_limit_handler(config)
        rate_limit.reset()
    except Exception:
        pass


@pytest.fixture
def clean_rate_limiter() -> None:
    from guard_core.sync.handlers.ratelimit_handler import _managers, _managers_lock

    with _managers_lock:
        _managers.clear()


@pytest.fixture(autouse=True)
def _no_outbound_network() -> Iterator[None]:
    network_guard.reset()
    yield
    violations = network_guard.drain()
    assert not violations, "test reached the network:\n" + "\n".join(violations)


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    thread_guard.stop_the_shared_regex_pools()
    leaked = thread_guard.leaked_threads()
    if leaked:
        sys.stderr.write(f"\nthreads the tests left running: {leaked}\n")
        session.exitstatus = pytest.ExitCode.TESTS_FAILED
