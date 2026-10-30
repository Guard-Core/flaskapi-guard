import pytest
from flask import Flask, request
from guard_core.sync.protocols.request_protocol import SyncGuardRequest

from flaskapi_guard import FlaskAPIGuard, SecurityConfig


def _config() -> SecurityConfig[SyncGuardRequest]:
    return SecurityConfig[SyncGuardRequest](enable_redis=False, rate_limit=100000)


def test_an_oversize_body_under_max_content_length_answers_413(
    caplog: pytest.LogCaptureFixture,
) -> None:
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = 100

    @app.post("/raw")
    def raw() -> str:
        return str(len(request.get_data()))

    FlaskAPIGuard(app, config=_config())
    client = app.test_client()

    with caplog.at_level("DEBUG"):
        oversize = client.post("/raw", data=b"a" * 5000)
    within = client.post("/raw", data=b"a" * 50)

    assert oversize.status_code == 413
    assert "Suspicious activity" not in caplog.text
    assert (within.status_code, within.get_data()) == (200, b"50")
