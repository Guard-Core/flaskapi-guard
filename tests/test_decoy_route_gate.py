"""A probe path is clean when the app declares it as a literal route, and stays
flagged when it is undeclared or served by a catch-all or converter route
(LEDGER 6.869)."""

import pytest
from flask import Flask
from guard_core.sync.protocols.request_protocol import SyncGuardRequest

from flaskapi_guard import FlaskAPIGuard, SecurityConfig

PROBE = "/wp-login.php"


def _status(rule: str | None) -> int:
    app = Flask(__name__)
    if rule is not None:

        @app.get(rule)
        def handler(**_: str) -> tuple[dict[str, str], int]:
            return {"detail": "Not Found"}, 404

    FlaskAPIGuard(
        app,
        config=SecurityConfig[SyncGuardRequest](
            enable_redis=False,
            security_headers=None,
            enable_penetration_detection=True,
            enable_rate_limiting=False,
        ),
    )
    client = app.test_client()
    return client.get(PROBE, environ_base={"REMOTE_ADDR": "203.0.113.42"}).status_code


def test_a_decoy_registered_as_a_literal_route_is_clean() -> None:
    assert _status(PROBE) == 404


def test_a_probe_the_app_does_not_declare_is_flagged() -> None:
    assert _status(None) == 400


@pytest.mark.parametrize("rule", ["/<path:filename>", "/<page>"])
def test_a_catch_all_or_converter_route_does_not_declare_the_probe(rule: str) -> None:
    assert _status(rule) == 400
