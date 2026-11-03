import os

import pytest
from flask import Flask
from guard_core.sync.protocols.request_protocol import SyncGuardRequest

from flaskapi_guard import FlaskAPIGuard, SecurityConfig
from tests.redis_isolation import suite_redis_prefix

ORIGIN_A = "https://a.example"
ORIGIN_B = "https://b.example"
REDIS_URL = os.getenv("REDIS_URL") or "redis://localhost:6379"


def _app(name: str, origin: str, max_age: int, redis: bool) -> Flask:
    app = Flask(__name__)
    FlaskAPIGuard(
        app,
        config=SecurityConfig[SyncGuardRequest](
            enable_redis=redis,
            redis_url=REDIS_URL if redis else None,
            redis_prefix=suite_redis_prefix("wp102"),
            enable_rate_limiting=False,
            enable_ip_banning=False,
            enable_cors=True,
            cors_allow_origins=[origin],
            security_headers={
                "enabled": True,
                "csp": {"default-src": ["'self'", f"https://{name}.csp.example"]},
                "hsts": {"max_age": max_age, "include_subdomains": True},
                "frame_options": "DENY" if name == "a" else "SAMEORIGIN",
                "custom": {"X-App-Name": name},
            },
        ),
    )

    @app.route("/x")
    def x() -> dict[str, bool]:
        return {"ok": True}

    return app


@pytest.mark.parametrize("redis", [False, True])
def test_two_apps_in_one_process_each_answer_with_their_own_headers(
    redis: bool,
) -> None:
    app_a = _app("a", ORIGIN_A, 31536000, redis)
    app_b = _app("b", ORIGIN_B, 63072000, redis)
    for _ in range(2):
        a = app_a.test_client().get("/x", headers={"Origin": ORIGIN_A}).headers
        b = app_b.test_client().get("/x", headers={"Origin": ORIGIN_B}).headers
        assert a["Content-Security-Policy"].endswith("https://a.csp.example")
        assert b["Content-Security-Policy"].endswith("https://b.csp.example")
        assert a["Strict-Transport-Security"].startswith("max-age=31536000")
        assert b["Strict-Transport-Security"].startswith("max-age=63072000")
        assert a["X-App-Name"] == "a"
        assert b["X-App-Name"] == "b"
        assert a["X-Frame-Options"] == "DENY"
        assert b["X-Frame-Options"] == "SAMEORIGIN"
        assert a["Access-Control-Allow-Origin"] == ORIGIN_A
        assert b["Access-Control-Allow-Origin"] == ORIGIN_B
        cross = app_a.test_client().get("/x", headers={"Origin": ORIGIN_B}).headers
        assert "Access-Control-Allow-Origin" not in cross
