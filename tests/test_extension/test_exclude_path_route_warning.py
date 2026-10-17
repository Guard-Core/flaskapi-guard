import logging

import pytest
from flask import Blueprint, Flask
from guard_core.models import SecurityConfig

from flaskapi_guard.extension import FlaskAPIGuard


def _app(entries: list[str]) -> tuple[Flask, FlaskAPIGuard]:
    app = Flask(__name__, static_folder=None)
    config = SecurityConfig(
        enable_redis=False,
        enable_penetration_detection=False,
        exclude_paths=entries,
        ban_on_hostile_signals=False,
    )
    guard = FlaskAPIGuard(app, config=config)

    @app.get("/health")
    def health() -> dict[str, int]:
        return {"h": 1}

    @app.get("/items/<int:item_id>")
    def item(item_id: int) -> dict[str, int]:
        return {"item": item_id}

    admin = Blueprint("admin", __name__, url_prefix="/admin")

    @admin.get("/panel")
    def panel() -> dict[str, int]:
        return {"p": 1}

    app.register_blueprint(admin)
    return app, guard


def _warnings(caplog: pytest.LogCaptureFixture) -> list[str]:
    return [
        r.getMessage()
        for r in caplog.records
        if r.name == "guard_core.models" and "exclude_paths entry" in r.getMessage()
    ]


def _typo(entry: str) -> str:
    return (
        f"exclude_paths entry {entry!r} matches no registered route; check it for "
        "a typo."
    )


def test_only_a_typo_entry_warns_once_on_a_real_app(
    caplog: pytest.LogCaptureFixture,
) -> None:
    entries = [
        "/docs",
        "/health",
        "/items",
        "/items/7",
        "/admin",
        "/admin/panel",
        "/admin/typo",
        "/static",
        "/typo",
    ]
    app, _ = _app(entries)
    with caplog.at_level(logging.WARNING, logger="guard_core"):
        with app.test_client() as client:
            for _ in range(3):
                client.get("/health")

    assert _warnings(caplog) == [_typo("/admin/typo"), _typo("/typo")]


def test_the_prefixes_list_every_rule_with_its_open_ended_head() -> None:
    app, guard = _app([])

    with app.app_context():
        assert set(guard.static_route_prefixes()) == {
            "/health",
            "/items/",
            "/admin/panel",
        }


def test_the_prefixes_are_the_open_root_outside_an_app_context() -> None:
    _, guard = _app([])

    assert guard.static_route_prefixes() == ("/",)
