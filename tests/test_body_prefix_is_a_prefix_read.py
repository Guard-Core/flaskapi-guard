import io
from typing import Any

from flask import Flask, request

from flaskapi_guard.adapters import FlaskGuardRequest


class _CountingInput(io.BytesIO):
    def __init__(self, data: bytes) -> None:
        super().__init__(data)
        self.delivered = 0

    def read(self, size: int | None = -1) -> bytes:
        chunk = super().read(size)
        self.delivered += len(chunk)
        return chunk

    def readinto(self, buffer: Any) -> int:
        count = super().readinto(buffer)
        self.delivered += count
        return count


def _post(body: bytes) -> tuple[Flask, _CountingInput]:
    return Flask(__name__), _CountingInput(body)


def test_read_body_prefix_does_not_read_past_the_prefix() -> None:
    app, stream = _post(b"x" * 1_000_000)
    with app.test_request_context(
        "/", method="POST", input_stream=stream, content_length=1_000_000
    ):
        prefix = FlaskGuardRequest(request).read_body_prefix(10)

    assert prefix == b"x" * 10
    assert stream.delivered <= 65536


def test_the_body_is_whole_for_the_view_after_a_prefix_read() -> None:
    body = bytes(range(256)) * 400
    app, stream = _post(body)
    with app.test_request_context(
        "/", method="POST", input_stream=stream, content_length=len(body)
    ):
        FlaskGuardRequest(request).read_body_prefix(10)

        assert request.get_data() == body
