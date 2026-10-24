"""The response wrapper declares whether the body is in memory, and tees a stream.

The sync engine reads ``body_is_materialized`` once per response
(``ErrorResponseFactory.apply_modifier``): True hands the modifier the real
response, anything else takes the bounded path, reading the prefix lazily on the
first ``.body`` access.
"""

import hashlib
import itertools
import logging
import tempfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest
from flask import Flask, Response, request, send_file
from guard_core.sync.core.responses import reads_response_body
from guard_core.sync.core.responses.context import ResponseContext
from guard_core.sync.core.responses.factory import ErrorResponseFactory
from guard_core.sync.protocols.request_protocol import SyncGuardRequest

from flaskapi_guard import SecurityConfig
from flaskapi_guard.adapters import FlaskGuardRequest, FlaskGuardResponse
from flaskapi_guard.extension import FlaskAPIGuard

_IPS = itertools.count(1)
_BODY = bytes(range(256)) * 40
_CAP = 262144


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class _Pulled:
    def __init__(self) -> None:
        self.chunks = 0


def _counting_stream(chunks: list[bytes], pulled: _Pulled) -> Iterator[bytes]:
    for chunk in chunks:
        pulled.chunks += 1
        yield chunk


def _split(body: bytes, size: int) -> list[bytes]:
    return [body[i : i + size] for i in range(0, len(body), size)]


def _native_responses(path: Path) -> dict[str, Response]:
    path.write_bytes(_BODY)
    with Flask(__name__).test_request_context():
        file_response = send_file(path)
    return {
        "str": Response("text"),
        "bytes": Response(_BODY),
        "list": Response([b"a", b"b"]),
        "redirect": Response(status=302, headers={"Location": "/elsewhere"}),
        "generator": Response(_counting_stream([b"a"], _Pulled())),
        "send_file": file_response,
        "direct_passthrough": Response(path.open("rb"), direct_passthrough=True),
    }


_MATERIALIZED = {
    "str": True,
    "bytes": True,
    "list": True,
    "redirect": True,
    "generator": False,
    "send_file": False,
    "direct_passthrough": False,
}


@pytest.mark.parametrize("name", sorted(_MATERIALIZED))
def test_the_capability_matches_the_native_response_type(name: str) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        native = _native_responses(Path(tmp) / "file.bin")[name]
        try:
            assert (
                FlaskGuardResponse(native).body_is_materialized is (_MATERIALIZED[name])
            )
        finally:
            native.close()


def test_reading_the_capability_buffers_nothing() -> None:
    pulled = _Pulled()
    native = Response(_counting_stream([b"a", b"b"], pulled))
    wrapper = FlaskGuardResponse(native)
    assert wrapper.body_is_materialized is False
    assert wrapper.body_is_materialized is False
    assert pulled.chunks == 0
    assert native.is_streamed is True


class _Seen:
    def __init__(self) -> None:
        self.calls = 0
        self.body: bytes | None = None
        self.refused = False


def _modifier(seen: _Seen, marked: bool = False) -> Any:
    def modifier(response: Any) -> Any:
        seen.calls += 1
        try:
            seen.body = response.body
        except AttributeError:
            seen.refused = True
        response.headers["x-modified"] = "1"
        return response

    return reads_response_body(modifier) if marked else modifier


def _engine(modifier: Any, **overrides: Any) -> ErrorResponseFactory:
    config = SecurityConfig(enable_redis=False, **overrides)
    config.custom_response_modifier = modifier
    return ErrorResponseFactory(
        ResponseContext(
            config=config,
            logger=logging.getLogger("flaskapi_guard.test_response_body_capability"),
            metrics_collector=MagicMock(),
            response_factory=None,
        )
    )


def _apply(modifier: Any, native: Response, **overrides: Any) -> None:
    app = Flask(__name__)
    with app.test_request_context("/"):
        guard_request = FlaskGuardRequest(request)
        _engine(modifier, **overrides).apply_modifier(
            FlaskGuardResponse(native), guard_request
        )


def _drain(native: Response) -> bytes:
    return b"".join(native.iter_encoded())


def test_a_modifier_on_an_in_memory_response_gets_the_real_bytes_in_one_call() -> None:
    seen = _Seen()
    big = _BODY * 30
    assert len(big) > _CAP
    native = Response(big)
    _apply(_modifier(seen), native)
    assert seen.calls == 1
    assert seen.body == big
    assert native.headers["x-modified"] == "1"


def test_a_modifier_on_a_declared_stream_under_the_cap_gets_every_byte() -> None:
    seen = _Seen()
    pulled = _Pulled()
    chunks = _split(_BODY, 1000)
    native = Response(
        _counting_stream(chunks, pulled), headers={"Content-Length": str(len(_BODY))}
    )
    _apply(_modifier(seen), native)
    assert seen.calls == 1
    assert seen.body == _BODY
    assert pulled.chunks == len(chunks)
    assert _sha(_drain(native)) == _sha(_BODY)


def test_a_modifier_on_an_undeclared_stream_is_refused_and_nothing_is_lost() -> None:
    seen = _Seen()
    pulled = _Pulled()
    native = Response(_counting_stream(_split(_BODY, 1000), pulled))
    _apply(_modifier(seen), native)
    assert seen.refused
    assert seen.calls == 1
    assert native.headers["x-modified"] == "1"
    assert pulled.chunks == 0
    assert _sha(_drain(native)) == _sha(_BODY)


def test_a_modifier_on_a_declared_stream_over_the_cap_reads_one_chunk_at_most() -> None:
    seen = _Seen()
    pulled = _Pulled()
    native = Response(
        _counting_stream(_split(_BODY, 1000), pulled),
        headers={"Content-Length": str(len(_BODY))},
    )
    _apply(_modifier(seen), native, custom_response_modifier_max_body_bytes=2048)
    assert seen.refused
    assert pulled.chunks <= 1
    assert _sha(_drain(native)) == _sha(_BODY)


def test_a_modifier_on_server_sent_events_is_refused_and_nothing_is_lost() -> None:
    seen = _Seen()
    pulled = _Pulled()
    native = Response(
        _counting_stream(_split(_BODY, 1000), pulled),
        mimetype="text/event-stream",
        headers={"Content-Length": str(len(_BODY))},
    )
    _apply(_modifier(seen), native)
    assert seen.refused
    assert pulled.chunks == 0
    assert _sha(_drain(native)) == _sha(_BODY)


def test_a_modifier_on_send_file_reads_the_file_and_the_client_gets_it_all() -> None:
    seen = _Seen()
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "file.bin"
        path.write_bytes(_BODY)
        with Flask(__name__).test_request_context():
            native = send_file(path)
        try:
            _apply(_modifier(seen), native)
            assert seen.body == _BODY
            assert _sha(_drain(native)) == _sha(_BODY)
        finally:
            native.close()


def test_read_body_prefix_reads_a_declared_length_to_its_end_and_replays_it() -> None:
    native = Response(
        _counting_stream(_split(_BODY, 700), _Pulled()),
        headers={"Content-Length": str(len(_BODY))},
    )
    assert FlaskGuardResponse(native).read_body_prefix(_CAP) == _BODY
    assert _sha(_drain(native)) == _sha(_BODY)


def test_read_body_prefix_stops_at_the_declared_length_not_the_stream_end() -> None:
    pulled = _Pulled()
    native = Response(
        _counting_stream(_split(_BODY, 1000), pulled),
        headers={"Content-Length": "2500"},
    )
    assert FlaskGuardResponse(native).read_body_prefix(_CAP) == _BODY[:3000]
    assert pulled.chunks == 3
    assert _sha(_drain(native)) == _sha(_BODY)


def test_a_later_longer_read_continues_the_same_tee() -> None:
    pulled = _Pulled()
    native = Response(
        _counting_stream(_split(_BODY, 1000), pulled),
        headers={"Content-Length": "2500"},
    )
    wrapper = FlaskGuardResponse(native)
    assert wrapper.read_body_prefix(1500) == _BODY[:1000]
    assert pulled.chunks == 1
    assert wrapper.read_body_prefix(_CAP) == _BODY[:3000]
    assert pulled.chunks == 3
    assert wrapper.read_body_prefix(_CAP) == _BODY[:3000]
    assert pulled.chunks == 3
    assert _sha(_drain(native)) == _sha(_BODY)


@pytest.mark.parametrize(
    "headers",
    [{}, {"Content-Length": "abc"}, {"Content-Length": "999999"}],
)
def test_read_body_prefix_stops_at_the_first_chunk_without_a_usable_length(
    headers: dict[str, str],
) -> None:
    pulled = _Pulled()
    chunks = _split(_BODY, 1000)
    native = Response(_counting_stream(chunks, pulled), headers=headers)
    assert FlaskGuardResponse(native).read_body_prefix(1500) == chunks[0]
    assert pulled.chunks == 1
    assert _sha(_drain(native)) == _sha(_BODY)


def test_read_body_prefix_returns_what_a_short_declared_stream_produced() -> None:
    native = Response(
        _counting_stream([b"ab"], _Pulled()), headers={"Content-Length": "50"}
    )
    assert FlaskGuardResponse(native).read_body_prefix(_CAP) == b"ab"
    assert _drain(native) == b"ab"


def _app(config: SecurityConfig[SyncGuardRequest], path: Path) -> Flask:
    app = Flask(__name__)
    app.config["TESTING"] = True

    @app.route("/memory")
    def memory() -> Response:
        return Response(_BODY)

    @app.route("/stream-declared")
    def stream_declared() -> Response:
        return Response(
            _counting_stream(_split(_BODY, 900), _Pulled()),
            headers={"Content-Length": str(len(_BODY))},
        )

    @app.route("/stream-undeclared")
    def stream_undeclared() -> Response:
        return Response(_counting_stream(_split(_BODY, 900), _Pulled()))

    @app.route("/sse")
    def sse() -> Response:
        return Response(
            _counting_stream(_split(_BODY, 900), _Pulled()),
            mimetype="text/event-stream",
            headers={"Content-Length": str(len(_BODY))},
        )

    @app.route("/file")
    def file() -> Response:
        return send_file(path)

    FlaskAPIGuard(app, config=config)
    return app


@pytest.mark.parametrize(
    ("route", "readable"),
    [
        ("/memory", True),
        ("/stream-declared", True),
        ("/stream-undeclared", False),
        ("/sse", False),
        ("/file", True),
    ],
)
def test_through_the_extension_the_client_gets_every_byte(
    route: str, readable: bool
) -> None:
    seen = _Seen()
    config = SecurityConfig[SyncGuardRequest](
        enable_redis=False,
        enable_penetration_detection=False,
        enable_rate_limiting=False,
        trusted_proxies=("127.0.0.1",),
        custom_response_modifier=_modifier(seen),
    )
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "file.bin"
        path.write_bytes(_BODY)
        client = _app(config, path).test_client()
        headers = {"X-Forwarded-For": f"198.51.100.{next(_IPS)}"}
        response = client.get(route, headers=headers, buffered=False)
        with response:
            content = b"".join(response.iter_encoded())
    assert response.status_code == 200
    assert response.headers["x-modified"] == "1"
    assert _sha(content) == _sha(_BODY)
    assert seen.calls == 1
    assert seen.refused is not readable
    assert (seen.body == _BODY) is readable
