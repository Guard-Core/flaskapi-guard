import json
import subprocess
import sys
import textwrap
from typing import Any

import pytest

from tests.redis_isolation import REDIS_URL

PACKAGE = "flaskapi_guard"
DISTRIBUTION = "flaskapi-guard"
FOUR = ("redis", "maxminddb", "aiohttp", "requests")


def _run_without(blocked: tuple[str, ...], body: str) -> Any:
    script = (
        "import json, sys, warnings\n"
        "warnings.simplefilter('ignore')\n"
        f"for name in {blocked!r}:\n"
        "    sys.modules[name] = None\n" + textwrap.dedent(body)
    )
    result = subprocess.run(
        [sys.executable, "-c", script], capture_output=True, text=True, check=False
    )
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout.strip().splitlines()[-1])


def _serve(blocked: tuple[str, ...], config_kwargs: str) -> Any:
    return _run_without(blocked, SERVE.replace("CONFIG_KWARGS", config_kwargs))


SERVE = """
import flaskapi_guard
from flask import Flask
from flaskapi_guard import FlaskAPIGuard, SecurityConfig
app = Flask(__name__)
FlaskAPIGuard(app, config=SecurityConfig(CONFIG_KWARGS))
@app.get("/")
def root():
    return {"ok": True}
status = app.test_client().get("/").status_code
loaded = [m for m in ("redis", "maxminddb", "aiohttp", "requests") if sys.modules[m]]
print(json.dumps([status, loaded]))
"""


def test_the_adapter_imports_and_serves_with_none_of_the_four_installed() -> None:
    status, loaded = _serve(FOUR, "")
    assert status == 200
    assert loaded == []


def test_a_redis_config_with_an_agent_serves_without_aiohttp_or_requests() -> None:
    config_kwargs = (
        f"redis_url={REDIS_URL!r}, redis_prefix='wp49pin:', enable_agent=True, "
        "agent_api_key='wp49-pin-agent-key', agent_endpoint='http://127.0.0.1:9'"
    )
    status, loaded = _serve(("maxminddb", "aiohttp", "requests"), config_kwargs)
    assert status == 200
    assert "aiohttp" not in loaded
    assert "requests" not in loaded


def test_each_extra_feature_is_refused_naming_guard_cores_and_the_adapters_extra() -> (
    None
):
    refused = _run_without(
        FOUR,
        f"""
        import {PACKAGE}
        from {PACKAGE} import SecurityConfig
        config = SecurityConfig(enable_redis=False)
        cases = {{
            "redis": ("redis", dict(enable_redis=True, redis_url="redis://x")),
            "cloud": ("cloud", dict(block_cloud_providers={{"AWS"}})),
            "geo": ("geo", dict(ipinfo_token="t", blocked_countries={{"US"}})),
        }}
        out = {{}}
        for label, (extra, kwargs) in cases.items():
            seen = {{}}
            for path in ("construction", "assignment", "copy"):
                try:
                    if path == "construction":
                        SecurityConfig(**kwargs)
                    elif path == "assignment":
                        for key, value in kwargs.items():
                            setattr(config, key, value)
                    else:
                        config.model_copy(update=kwargs)
                except ValueError as error:
                    text = str(error)
                    seen[path] = (
                        "guard-core[" + extra + "]" in text
                        and "{DISTRIBUTION}[" + extra + "]" in text
                    )
            out[label] = seen
        print(json.dumps(out))
        """,
    )
    for label in ("redis", "cloud", "geo"):
        assert refused[label] == {
            "construction": True,
            "assignment": True,
            "copy": True,
        }, label


def test_a_sync_app_with_only_aiohttp_is_refused_for_cloud_blocking() -> None:
    message = _run_without(
        ("requests",),
        f"""
        import {PACKAGE}
        from {PACKAGE} import SecurityConfig
        try:
            SecurityConfig(block_cloud_providers={{"AWS"}})
        except ValueError as error:
            print(json.dumps(str(error)))
        """,
    )
    assert "'requests'" in message
    assert f"{DISTRIBUTION}[cloud]" in message


def test_the_lazy_reexports_resolve_to_the_engine_objects() -> None:
    import flaskapi_guard

    for name in (
        "RedisManager",
        "redis_handler",
        "CloudManager",
        "cloud_handler",
        "IPInfoManager",
        "RateLimitManager",
        "rate_limit_handler",
    ):
        assert getattr(flaskapi_guard, name) is not None
    missing = "not_an_export"
    with pytest.raises(AttributeError, match=missing):
        getattr(flaskapi_guard, missing)
