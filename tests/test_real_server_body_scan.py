import json
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from http.client import HTTPConnection

import pytest
from flask import Flask
from guard_core.models import SecurityConfig
from werkzeug.serving import make_server

from flaskapi_guard.extension import FlaskAPIGuard

SQL_PAYLOAD = "1' OR '1'='1' UNION SELECT password FROM users--"


def _guarded_app() -> Flask:
    app = Flask(__name__)
    FlaskAPIGuard(
        app,
        config=SecurityConfig(
            enable_redis=False,
            enable_penetration_detection=True,
            enable_rate_limiting=False,
            enable_ip_banning=False,
        ),
    )

    @app.post("/echo")
    def echo() -> str:
        return "REACHED"

    return app


@contextmanager
def _serve(app: Flask) -> Iterator[int]:
    server = make_server("127.0.0.1", 0, app, threaded=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield int(server.server_port)
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def _post(port: int, content_type: str, body: str) -> tuple[int, str]:
    connection = HTTPConnection("127.0.0.1", port, timeout=10)
    try:
        connection.request("POST", "/echo", body, {"Content-Type": content_type})
        response = connection.getresponse()
        return response.status, response.read().decode("utf-8", errors="replace")
    finally:
        connection.close()


@pytest.mark.parametrize(
    ("content_type", "body"),
    [
        ("text/plain", SQL_PAYLOAD),
        ("application/json", json.dumps({"comment": SQL_PAYLOAD})),
    ],
)
def test_real_server_refuses_an_attack_in_the_request_body(
    content_type: str, body: str
) -> None:
    with _serve(_guarded_app()) as port:
        status, text = _post(port, content_type, body)
    assert status == 400, text
    assert "REACHED" not in text


def test_real_server_lets_a_benign_body_through() -> None:
    with _serve(_guarded_app()) as port:
        status, text = _post(port, "text/plain", "hello world")
    assert status == 200
    assert text == "REACHED"
