import io
from typing import Any

import pytest
from flask import Flask
from guard_core.models import SecurityConfig
from guard_core.sync.core.events.middleware_events import SecurityEventBus
from guard_core.sync.protocols.request_protocol import SyncGuardRequest

from flaskapi_guard import SecurityDecorator
from flaskapi_guard.extension import FlaskAPIGuard

CAP = 1024
_PAYLOAD = b"1' UNION SELECT password FROM users--"
_PAST_THE_CAP_PAYLOAD = b"A" * (CAP + 5000) + _PAYLOAD
_ONE_BYTE_PAST = b"A" * (CAP + 1)
_AT_THE_CAP = b"A" * CAP
_HEADERS = {"Content-Type": "text/plain", "X-Forwarded-For": "203.0.113.50"}


@pytest.fixture
def captured_events(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    original = SecurityEventBus.send_middleware_event

    def _capture(self: SecurityEventBus, *args: Any, **kwargs: Any) -> None:
        events.append(kwargs)
        original(self, *args, **kwargs)

    monkeypatch.setattr(SecurityEventBus, "send_middleware_event", _capture)
    return events


def _app(fail_secure: bool) -> Flask:
    config = SecurityConfig[SyncGuardRequest](
        enable_redis=False,
        enable_penetration_detection=True,
        detection_max_body_inspect_bytes=CAP,
        fail_secure=fail_secure,
        trusted_proxies=("127.0.0.1",),
        auto_ban_threshold=2,
    )
    app = Flask(__name__)
    app.config["TESTING"] = True
    decorator = SecurityDecorator(config)

    @app.route("/small", methods=["POST"])
    def small() -> dict[str, str]:
        return {"ok": "small"}

    @app.route("/large", methods=["POST"])
    @decorator.max_request_size(len(_PAST_THE_CAP_PAYLOAD))
    def large() -> dict[str, str]:
        return {"ok": "large"}

    guard = FlaskAPIGuard(app, config=config)
    guard.set_decorator_handler(decorator)
    return app


def _post(app: Flask, path: str, body: bytes, chunked: bool) -> Any:
    client = app.test_client()
    if chunked:
        return client.post(
            path,
            input_stream=io.BytesIO(body),
            headers={**_HEADERS, "Transfer-Encoding": "chunked"},
            environ_overrides={"wsgi.input_terminated": True},
        )
    return client.post(path, data=body, headers=_HEADERS)


def _body_read_events(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [e for e in events if "Request body read failed" in e.get("reason", "")]


@pytest.mark.parametrize("chunked", [False, True])
@pytest.mark.parametrize("body", [_ONE_BYTE_PAST, _PAST_THE_CAP_PAYLOAD])
def test_a_body_past_the_cap_is_refused_with_an_event_and_no_strike(
    body: bytes, chunked: bool, captured_events: list[dict[str, Any]]
) -> None:
    app = _app(fail_secure=True)

    statuses = [_post(app, "/small", body, chunked).status_code for _ in range(4)]
    after = _post(app, "/small", b"hello", False)

    assert statuses == [400, 400, 400, 400]
    assert after.status_code == 200
    assert len(_body_read_events(captured_events)) == 4
    assert {e["action_taken"] for e in _body_read_events(captured_events)} == {
        "request_blocked"
    }


@pytest.mark.parametrize("chunked", [False, True])
def test_a_body_past_the_cap_passes_with_an_event_without_fail_secure(
    chunked: bool, captured_events: list[dict[str, Any]]
) -> None:
    response = _post(_app(fail_secure=False), "/small", _PAST_THE_CAP_PAYLOAD, chunked)

    assert response.status_code == 200
    assert [e["action_taken"] for e in _body_read_events(captured_events)] == [
        "logged_only"
    ]


@pytest.mark.parametrize("chunked", [False, True])
def test_a_route_with_max_request_size_above_the_cap_is_scanned_in_full(
    chunked: bool,
) -> None:
    app = _app(fail_secure=True)

    raised = _post(app, "/large", _PAST_THE_CAP_PAYLOAD, chunked)
    sibling = _post(app, "/small", _PAST_THE_CAP_PAYLOAD, chunked)

    assert raised.status_code == 400
    assert b"Suspicious activity detected" in raised.data
    assert sibling.status_code == 400
    assert b"Suspicious activity detected" not in sibling.data


@pytest.mark.parametrize("chunked", [False, True])
def test_a_body_at_exactly_the_cap_is_scanned_in_full_and_unchanged(
    chunked: bool, captured_events: list[dict[str, Any]]
) -> None:
    app = _app(fail_secure=True)
    hit = _AT_THE_CAP[: CAP - len(_PAYLOAD)] + _PAYLOAD

    clean = _post(app, "/small", _AT_THE_CAP, chunked)
    attack = _post(app, "/small", hit, chunked)

    assert clean.status_code == 200
    assert attack.status_code == 400
    assert b"Suspicious activity detected" in attack.data
    assert _body_read_events(captured_events) == []
