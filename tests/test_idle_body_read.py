import io
import socket
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any
from wsgiref.simple_server import WSGIRequestHandler, WSGIServer, make_server

import pytest
from flask import Flask, request
from guard_core.exceptions import BodyReadStalledError
from guard_core.models import SecurityConfig
from guard_core.sync.protocols.request_protocol import SyncGuardRequest
from werkzeug.serving import make_server as make_werkzeug_server

from flaskapi_guard.adapters import FlaskGuardRequest
from flaskapi_guard.extension import FlaskAPIGuard


class _DrippingInput(io.RawIOBase):
    def __init__(self, chunks: list[bytes], then: BaseException | None = None) -> None:
        self._chunks = list(chunks)
        self._then = then

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def seek(self, _offset: int, _whence: int = 0) -> int:
        return 0

    def tell(self) -> int:
        return 0

    def readinto(self, buffer: Any) -> int:
        if self._chunks:
            chunk = self._chunks.pop(0)[: len(buffer)]
            buffer[: len(chunk)] = chunk
            return len(chunk)
        if self._then is not None:
            raise self._then
        return 0


class _FakeSocket:
    def __init__(self) -> None:
        self.timeouts: list[float | None] = [None]

    def gettimeout(self) -> float | None:
        return self.timeouts[-1]

    def settimeout(self, value: float | None) -> None:
        self.timeouts.append(value)


def test_the_idle_read_returns_the_prefix_and_the_app_still_reads_everything() -> None:
    app = Flask(__name__)
    with app.test_request_context("/", method="POST", data=b"hello world"):
        guard_request = FlaskGuardRequest(request)

        assert guard_request.read_body_prefix_until_idle(5, 1.0) == b"hello"
        assert request.get_data() == b"hello world"


def test_the_idle_read_of_a_short_body_returns_all_of_it() -> None:
    app = Flask(__name__)
    with app.test_request_context("/", method="POST", data=b"tiny"):
        guard_request = FlaskGuardRequest(request)

        assert guard_request.read_body_prefix_until_idle(1024, 1.0) == b"tiny"
        assert guard_request.read_body_prefix_until_idle(0, 1.0) == b""
        assert request.get_data() == b"tiny"


def test_the_raw_wsgi_input_is_restored_for_an_app_that_reads_it_directly() -> None:
    app = Flask(__name__)
    with app.test_request_context("/", method="POST", data=b"hello world"):
        guard_request = FlaskGuardRequest(request)
        guard_request.read_body_prefix_until_idle(5, 1.0)

        assert request.environ["wsgi.input"].read() == b"hello world"


def test_a_cached_body_is_answered_from_the_cache() -> None:
    app = Flask(__name__)
    with app.test_request_context("/", method="POST", data=b"hello world"):
        assert request.get_data() == b"hello world"

        assert (
            FlaskGuardRequest(request).read_body_prefix_until_idle(5, 1.0) == b"hello"
        )


@pytest.mark.parametrize("timeout_type", [socket.timeout, TimeoutError])
def test_the_servers_socket_timeout_is_a_stalled_read_and_no_byte_is_lost(
    timeout_type: type[BaseException],
) -> None:
    app = Flask(__name__)
    stream = _DrippingInput([b"abc"], then=timeout_type("timed out"))
    with app.test_request_context(
        "/",
        method="POST",
        input_stream=stream,
        content_length=10,
        environ_overrides={"CONTENT_LENGTH": "10"},
    ):
        guard_request = FlaskGuardRequest(request)

        with pytest.raises(BodyReadStalledError):
            guard_request.read_body_prefix_until_idle(1024, 1.0)

        assert request.stream.read(3) == b"abc"


def test_the_replayed_stream_serves_reads_lines_and_iteration() -> None:
    app = Flask(__name__)
    with app.test_request_context(
        "/", method="POST", input_stream=io.BytesIO(b"a\nbb\nccc"), content_length=8
    ):
        guard_request = FlaskGuardRequest(request)
        guard_request.read_body_prefix_until_idle(3, 1.0)

        stream = request.stream
        assert stream.readline() == b"a\n"
        assert stream.read(1) == b"b"
        assert list(stream) == [b"b\n", b"ccc"]


def test_the_replayed_stream_reads_lines_across_the_prefix_boundary() -> None:
    app = Flask(__name__)
    with app.test_request_context(
        "/", method="POST", input_stream=io.BytesIO(b"abcdef\nghi"), content_length=10
    ):
        guard_request = FlaskGuardRequest(request)
        guard_request.read_body_prefix_until_idle(3, 1.0)

        assert request.stream.readlines() == [b"abcdef\n", b"ghi"]
        assert request.stream.read() == b""


def test_the_replayed_stream_honors_a_size_limited_line() -> None:
    app = Flask(__name__)
    with app.test_request_context(
        "/", method="POST", input_stream=io.BytesIO(b"abcdef\nghi"), content_length=10
    ):
        guard_request = FlaskGuardRequest(request)
        guard_request.read_body_prefix_until_idle(3, 1.0)

        assert request.stream.readline(2) == b"ab"
        assert request.stream.readline(4) == b"cdef"


def test_the_server_socket_gets_the_idle_timeout_for_the_read_and_gets_it_back() -> (
    None
):
    app = Flask(__name__)
    fake = _FakeSocket()
    with app.test_request_context(
        "/",
        method="POST",
        data=b"hello",
        environ_overrides={"werkzeug.socket": fake},
    ):
        FlaskGuardRequest(request).read_body_prefix_until_idle(5, 0.25)

    assert fake.timeouts == [None, 0.25, None]


def test_the_server_socket_is_restored_when_the_read_stalls() -> None:
    app = Flask(__name__)
    fake = _FakeSocket()
    stream = _DrippingInput([], then=TimeoutError("timed out"))
    with app.test_request_context(
        "/",
        method="POST",
        input_stream=stream,
        content_length=4,
        environ_overrides={"gunicorn.socket": fake, "CONTENT_LENGTH": "4"},
    ):
        with pytest.raises(BodyReadStalledError):
            FlaskGuardRequest(request).read_body_prefix_until_idle(5, 0.25)

    assert fake.timeouts == [None, 0.25, None]


def _guarded_app(**overrides: Any) -> Flask:
    app = Flask(__name__)
    fields: dict[str, Any] = {
        "enable_redis": False,
        "enable_penetration_detection": True,
        "enable_rate_limiting": False,
        "fail_secure": True,
        "body_read_timeout": 0.3,
        "ban_on_hostile_signals": False,
    }
    fields.update(overrides)
    FlaskAPIGuard(app, config=SecurityConfig[SyncGuardRequest](**fields))

    @app.post("/echo")
    def echo() -> dict[str, int]:
        return {"received": len(request.get_data())}

    return app


@contextmanager
def _serve_werkzeug(app: Flask) -> Iterator[int]:
    server = make_werkzeug_server("127.0.0.1", 0, app, threaded=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield int(server.server_port)
    finally:
        server.shutdown()
        thread.join(timeout=10)


class _TimingOutHandler(WSGIRequestHandler):
    timeout = 0.3

    def log_message(self, _format: str, *args: Any) -> None:
        return None


@contextmanager
def _serve_wsgiref(app: Flask) -> Iterator[int]:
    server: WSGIServer = make_server(
        "127.0.0.1", 0, app, handler_class=_TimingOutHandler
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield int(server.server_port)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=10)


def _raw_post(
    port: int, chunks: list[tuple[float, bytes]], declared: int = 0
) -> tuple[int, float]:
    body_length = declared or sum(len(chunk) for _, chunk in chunks)
    head = (
        "POST /echo HTTP/1.1\r\nHost: localhost\r\n"
        "Content-Type: text/plain\r\n"
        f"Content-Length: {body_length}\r\nConnection: close\r\n\r\n"
    ).encode()
    started = time.monotonic()
    with socket.create_connection(("127.0.0.1", port), timeout=10) as sock:
        sock.sendall(head)
        for pause, chunk in chunks:
            time.sleep(pause)
            try:
                sock.sendall(chunk)
            except OSError:
                break
        data = b""
        while b"\r\n" not in data:
            piece = sock.recv(4096)
            if not piece:
                break
            data += piece
    return int(data.split(b" ", 2)[1]), time.monotonic() - started


def test_werkzeug_server_a_client_with_headers_and_no_body_gets_408() -> None:
    with _serve_werkzeug(_guarded_app()) as port:
        status, elapsed = _raw_post(port, [], declared=10)

    assert status == 408
    assert elapsed < 1.5


def test_werkzeug_server_a_slow_client_that_keeps_sending_is_not_cut_off() -> None:
    with _serve_werkzeug(_guarded_app()) as port:
        status, elapsed = _raw_post(port, [(0.12, b"abcd")] * 6)

    assert status == 200
    assert elapsed > 0.6


def test_wsgiref_server_the_servers_own_socket_timeout_gets_408() -> None:
    with _serve_wsgiref(_guarded_app(body_read_timeout=30.0)) as port:
        status, elapsed = _raw_post(port, [], declared=10)

    assert status == 408
    assert elapsed < 2.0


def test_wsgiref_server_a_complete_body_is_scanned_and_passed_on() -> None:
    with _serve_wsgiref(_guarded_app()) as port:
        status, _ = _raw_post(port, [(0.0, b"hello world")])

    assert status == 200


def _route_app() -> Flask:
    app = Flask(__name__)
    FlaskAPIGuard(
        app,
        config=SecurityConfig[SyncGuardRequest](
            enable_redis=False,
            enable_penetration_detection=True,
            enable_rate_limiting=False,
            ban_on_hostile_signals=False,
        ),
    )

    @app.route("/shop/cart.php")
    def cart() -> dict[str, bool]:
        return {"ok": True}

    @app.route("/forum/viewtopic.php")
    def viewtopic() -> dict[str, bool]:
        return {"ok": True}

    @app.route("/files/<path:name>")
    def files(name: str) -> dict[str, str]:
        return {"name": name}

    @app.route("/<language>/news")
    def news(language: str) -> dict[str, str]:
        return {"language": language}

    return app


@pytest.mark.parametrize(
    ("path", "status"),
    [
        ("/shop/cart.php", 200),
        ("/forum/viewtopic.php", 200),
        ("/files/shop/cart.php", 400),
        ("/missing/cart.php", 400),
        ("/shop/other.php", 400),
        ("/language/news", 400),
    ],
)
def test_a_script_path_is_clean_only_when_the_app_declares_it(
    path: str, status: int
) -> None:
    with _route_app().test_client() as client:
        assert client.get(path).status_code == status


def test_a_client_that_disconnects_is_a_failed_read_not_a_stall() -> None:
    from werkzeug.exceptions import ClientDisconnected

    app = Flask(__name__)
    stream = _DrippingInput([], then=ConnectionResetError("reset by peer"))
    with app.test_request_context(
        "/",
        method="POST",
        input_stream=stream,
        content_length=10,
        environ_overrides={"CONTENT_LENGTH": "10"},
    ):
        with pytest.raises((ClientDisconnected, ConnectionResetError)):
            FlaskGuardRequest(request).read_body_prefix_until_idle(5, 1.0)


def test_a_timeout_wrapped_by_werkzeug_in_a_disconnect_is_still_a_stall() -> None:
    from werkzeug.exceptions import ClientDisconnected

    class _Wrapping(_DrippingInput):
        def readinto(self, buffer: Any) -> int:
            try:
                raise TimeoutError("timed out")
            except TimeoutError:
                raise ClientDisconnected() from None

    app = Flask(__name__)
    with app.test_request_context(
        "/",
        method="POST",
        input_stream=_Wrapping([]),
        content_length=10,
        environ_overrides={"CONTENT_LENGTH": "10"},
    ):
        with pytest.raises(BodyReadStalledError):
            FlaskGuardRequest(request).read_body_prefix_until_idle(5, 1.0)


def test_a_replayed_read_smaller_than_the_prefix_stays_inside_the_prefix() -> None:
    app = Flask(__name__)
    with app.test_request_context(
        "/", method="POST", input_stream=io.BytesIO(b"abcdef"), content_length=6
    ):
        FlaskGuardRequest(request).read_body_prefix_until_idle(4, 1.0)

        assert request.stream.read(2) == b"ab"
        assert request.stream.read() == b"cdef"


def test_a_replayed_read_larger_than_the_prefix_continues_into_the_stream() -> None:
    app = Flask(__name__)
    with app.test_request_context(
        "/", method="POST", input_stream=io.BytesIO(b"abcdefgh"), content_length=8
    ):
        FlaskGuardRequest(request).read_body_prefix_until_idle(3, 1.0)

        assert request.stream.read(5) == b"abcde"
        assert request.stream.read() == b"fgh"
