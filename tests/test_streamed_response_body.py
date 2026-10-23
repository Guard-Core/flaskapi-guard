import hashlib
import itertools
import tracemalloc
from collections.abc import Iterator
from typing import Any

import pytest
from flask import Flask, Response
from guard_core.models import BehaviorRuleConfig

from flaskapi_guard import SecurityConfig
from flaskapi_guard.adapters import FlaskGuardResponse, StreamedBodyUnavailable
from flaskapi_guard.extension import FlaskAPIGuard

CHUNK = 1024 * 1024
_IPS = itertools.count(1)


def _chunk(index: int) -> bytes:
    return bytes([index % 251]) * CHUNK


def _expected_sha(count: int) -> str:
    digest = hashlib.sha256()
    for index in range(count):
        digest.update(_chunk(index))
    return digest.hexdigest()


class _Pulls:
    def __init__(self) -> None:
        self.count = 0

    def stream(self, total: int) -> Iterator[bytes]:
        for index in range(total):
            self.count += 1
            yield _chunk(index)


def _config(**overrides: Any) -> SecurityConfig:
    fields: dict[str, Any] = {
        "enable_redis": False,
        "enable_penetration_detection": False,
        "enable_rate_limiting": False,
        "enable_ip_banning": True,
        "trusted_proxies": ["127.0.0.1"],
        "ban_on_hostile_signals": False,
        "behavior_scan_response_body": True,
        "global_behavior_rules": (
            BehaviorRuleConfig(
                rule_type="return_pattern",
                threshold=1,
                window=60,
                pattern="regex:\\x07{16}",
                action="ban",
            ),
        ),
    }
    fields.update(overrides)
    return SecurityConfig(**fields)


def _app(config: SecurityConfig, pulls: _Pulls, chunks: int) -> Flask:
    app = Flask(__name__)
    app.config["TESTING"] = True

    @app.route("/stream")
    def stream() -> Response:
        return Response(pulls.stream(chunks), mimetype="application/octet-stream")

    FlaskAPIGuard(app, config=config)
    return app


def _client_digest(response: Any) -> tuple[str, int]:
    digest = hashlib.sha256()
    total = 0
    with response:
        for chunk in response.iter_encoded():
            digest.update(chunk)
            total += len(chunk)
    return digest.hexdigest(), total


def _headers() -> dict[str, str]:
    return {"X-Forwarded-For": f"198.51.100.{next(_IPS)}"}


def test_prefix_read_pulls_one_chunk_and_the_client_gets_every_byte() -> None:
    pulls = _Pulls()
    response = Response(pulls.stream(64))
    guard_response = FlaskGuardResponse(response)

    assert guard_response.read_body_prefix(10) == _chunk(0)[:10]
    assert pulls.count == 1
    assert guard_response.read_body_prefix(10) == _chunk(0)[:10]
    assert pulls.count == 1

    digest = hashlib.sha256()
    total = 0
    for chunk in response.iter_encoded():
        digest.update(chunk)
        total += len(chunk)
    assert (digest.hexdigest(), total) == (_expected_sha(64), 64 * CHUNK)
    assert pulls.count == 64


def test_streamed_body_property_refuses_instead_of_buffering() -> None:
    pulls = _Pulls()
    guard_response = FlaskGuardResponse(Response(pulls.stream(8)))
    with pytest.raises(StreamedBodyUnavailable):
        _ = guard_response.body
    assert pulls.count == 0


def test_prefix_read_closes_the_original_stream() -> None:
    closed: list[bool] = []

    class Source:
        def __iter__(self) -> Iterator[bytes]:
            yield b"abc"
            yield b"def"

        def close(self) -> None:
            closed.append(True)

    response = Response(Source())
    assert FlaskGuardResponse(response).read_body_prefix(2) == b"ab"
    assert b"".join(response.iter_encoded()) == b"abcdef"
    response.close()
    assert closed == [True]


def test_prefix_read_stops_at_the_first_non_empty_chunk_of_an_endless_stream() -> None:
    def endless() -> Iterator[bytes]:
        yield b""
        yield b"data: 1\n\n"
        while True:
            yield b"data: x\n\n"

    response = Response(endless(), mimetype="text/event-stream")
    assert FlaskGuardResponse(response).read_body_prefix(1000) == b"data: 1\n\n"
    stream = response.iter_encoded()
    assert [next(stream) for _ in range(3)] == [b"", b"data: 1\n\n", b"data: x\n\n"]


def test_streamed_text_chunks_are_encoded() -> None:
    def text() -> Iterator[str]:
        yield "café"
        yield "!"

    response = Response(text())
    assert FlaskGuardResponse(response).read_body_prefix(100) == "café".encode()
    assert b"".join(response.iter_encoded()) == "café!".encode()


@pytest.mark.parametrize("size", [0, 1, 100, 65536, CHUNK])
def test_non_streamed_body_and_prefix_are_unchanged(size: int) -> None:
    data = bytes(range(256)) * (size // 256) + bytes(range(size % 256))
    guard_response = FlaskGuardResponse(Response(data))
    assert guard_response.body == data
    for limit in (-1, 0, 1, 10, size, size + 5):
        expected = b"" if limit <= 0 else data[:limit]
        assert guard_response.read_body_prefix(limit) == expected


def test_return_pattern_through_the_extension_reads_one_chunk() -> None:
    pulls = _Pulls()
    client = _app(_config(), pulls, 64).test_client()
    response = client.get("/stream", headers=_headers(), buffered=False)
    assert pulls.count == 1
    assert _client_digest(response) == (_expected_sha(64), 64 * CHUNK)
    assert pulls.count == 64


def test_return_pattern_verdict_follows_the_inspected_prefix() -> None:
    def route_app(first: bytes) -> Flask:
        app = Flask(__name__)

        @app.route("/stream")
        def stream() -> Response:
            return Response(
                iter([first, b"\x07" * 16]), mimetype="application/octet-stream"
            )

        FlaskAPIGuard(app, config=_config())
        return app

    hit = route_app(b"\x07" * 16).test_client()
    headers = _headers()
    hit_statuses = [hit.get("/stream", headers=headers).status_code for _ in range(3)]
    assert hit_statuses == [200, 200, 403]

    miss = route_app(b"clean").test_client()
    headers = _headers()
    miss_statuses = [miss.get("/stream", headers=headers).status_code for _ in range(3)]
    assert miss_statuses == [200, 200, 200]


def _peak_growth(run: Any) -> int:
    run()
    tracemalloc.start()
    try:
        baseline, _ = tracemalloc.get_traced_memory()
        tracemalloc.reset_peak()
        run()
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    return peak - baseline


STREAM_CHUNKS = 256


def _unguarded_stream_peak() -> int:
    app = Flask(__name__)
    pulls = _Pulls()

    @app.route("/stream")
    def stream() -> Response:
        return Response(pulls.stream(STREAM_CHUNKS))

    client = app.test_client()
    return _peak_growth(lambda: _client_digest(client.get("/stream", buffered=False)))


def test_return_pattern_on_a_256_mib_stream_adds_less_than_one_chunk() -> None:
    pulls = _Pulls()
    client = _app(_config(), pulls, STREAM_CHUNKS).test_client()
    result: list[tuple[str, int]] = []

    def run() -> None:
        pulls.count = 0
        response = client.get("/stream", headers=_headers(), buffered=False)
        result.append(_client_digest(response))

    assert _peak_growth(run) < _unguarded_stream_peak() + CHUNK
    assert result[-1] == (_expected_sha(STREAM_CHUNKS), STREAM_CHUNKS * CHUNK)


def test_body_reading_modifier_on_a_256_mib_stream_adds_less_than_one_chunk() -> None:
    seen: list[str] = []

    def modifier(response: Any) -> Any:
        response.headers["X-Prefix"] = response.read_body_prefix(4).hex()
        try:
            _ = response.body
        except AttributeError as error:
            seen.append(type(error).__name__)
        return response

    config = _config(global_behavior_rules=(), custom_response_modifier=modifier)
    pulls = _Pulls()
    client = _app(config, pulls, STREAM_CHUNKS).test_client()
    result: list[tuple[str, int, str | None]] = []

    def run() -> None:
        pulls.count = 0
        response = client.get("/stream", headers=_headers(), buffered=False)
        digest, total = _client_digest(response)
        result.append((digest, total, response.headers.get("X-Prefix")))

    assert _peak_growth(run) < _unguarded_stream_peak() + CHUNK
    assert result[-1] == (
        _expected_sha(STREAM_CHUNKS),
        STREAM_CHUNKS * CHUNK,
        _chunk(0)[:4].hex(),
    )
    assert seen == ["StreamedBodyUnavailable"] * 2
