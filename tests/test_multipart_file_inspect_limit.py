import io
from typing import Any

import pytest
from flask import Flask
from guard_core.models import SecurityConfig
from guard_core.sync.protocols.request_protocol import SyncGuardRequest

from flaskapi_guard.extension import FlaskAPIGuard

BODY_LIMIT = 262144
DEFAULT_FILE_LIMIT = SecurityConfig().detection_max_file_inspect_bytes
PAST_THE_LIMIT_PADDING = BODY_LIMIT + 1024
RAISED_FILE_LIMIT = 1_000_000
BOUNDARY = "wp251boundary"
_PAYLOAD = "1' UNION SELECT password FROM users--"
_FORWARDED = {"X-Forwarded-For": "203.0.113.50"}
_MULTIPART_TYPE = f"multipart/form-data; boundary={BOUNDARY}"


def _multipart_body() -> bytes:
    pad = (
        f'--{BOUNDARY}\r\nContent-Disposition: form-data; name="pad"\r\n\r\n'
        f"{'A' * PAST_THE_LIMIT_PADDING}\r\n"
    )
    comment = (
        f'--{BOUNDARY}\r\nContent-Disposition: form-data; name="comment"\r\n\r\n'
        f"{_PAYLOAD}\r\n--{BOUNDARY}--\r\n"
    )
    return (pad + comment).encode()


def _json_body() -> bytes:
    pad = "A" * PAST_THE_LIMIT_PADDING
    return ('{"pad": "' + pad + '", "comment": "' + _PAYLOAD + '"}').encode()


def _app(file_limit: int) -> Flask:
    config = SecurityConfig[SyncGuardRequest](
        enable_redis=False,
        enable_penetration_detection=True,
        trusted_proxies=("127.0.0.1",),
        detection_max_file_inspect_bytes=file_limit,
    )
    app = Flask(__name__)
    app.config["TESTING"] = True

    @app.route("/upload", methods=["POST"])
    def upload() -> dict[str, str]:
        return {"ok": "upload"}

    FlaskAPIGuard(app, config=config)
    return app


def _post(app: Flask, body: bytes, content_type: str, chunked: bool) -> Any:
    client = app.test_client()
    headers = {**_FORWARDED, "Content-Type": content_type}
    if chunked:
        return client.post(
            "/upload",
            input_stream=io.BytesIO(body),
            headers={**headers, "Transfer-Encoding": "chunked"},
            environ_overrides={"wsgi.input_terminated": True},
        )
    return client.post("/upload", data=body, headers=headers)


@pytest.mark.parametrize("chunked", [False, True])
def test_multipart_past_the_body_limit_is_scanned_under_a_raised_file_limit(
    chunked: bool,
) -> None:
    response = _post(
        _app(RAISED_FILE_LIMIT), _multipart_body(), _MULTIPART_TYPE, chunked
    )

    assert response.status_code == 400
    assert b"Suspicious activity detected" in response.data


@pytest.mark.parametrize("chunked", [False, True])
def test_a_multipart_body_past_the_default_file_limit_is_refused_not_passed(
    chunked: bool,
) -> None:
    response = _post(
        _app(DEFAULT_FILE_LIMIT), _multipart_body(), _MULTIPART_TYPE, chunked
    )

    assert response.status_code == 400
    assert b"Suspicious activity detected" not in response.data


@pytest.mark.parametrize("chunked", [False, True])
def test_a_json_body_of_the_same_size_stays_refused_under_a_raised_file_limit(
    chunked: bool,
) -> None:
    response = _post(_app(RAISED_FILE_LIMIT), _json_body(), "application/json", chunked)

    assert response.status_code == 400
    assert b"Suspicious activity detected" not in response.data
