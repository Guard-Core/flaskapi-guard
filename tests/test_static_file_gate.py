from pathlib import Path
from typing import Any

import pytest
from flask import Blueprint, Flask
from guard_core.models import SecurityConfig

from flaskapi_guard.extension import FlaskAPIGuard


def _tree(root: Path) -> Path:
    for name in (
        "hls/live/segment_001.ts",
        "static/js/app.4f3a.js.map",
        "static/app.py",
        "static/dump.sql",
        "static/app.php",
        "static/real.ts",
        "secret.ts",
    ):
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("x")
    (root / "static" / "folder.ts").mkdir()
    return root


def _guard(app: Flask) -> FlaskAPIGuard:
    return FlaskAPIGuard(
        app,
        config=SecurityConfig(
            enable_redis=False,
            enable_penetration_detection=True,
            enable_rate_limiting=False,
            ban_on_hostile_signals=False,
            exclude_paths=[],
        ),
    )


def _static_app(root: Path) -> Flask:
    app = Flask(__name__, static_folder=str(root / "static"), static_url_path="/static")
    media = Blueprint(
        "media",
        __name__,
        static_folder=str(root / "hls"),
        static_url_path="/hls",
    )
    app.register_blueprint(media)
    _guard(app)

    @app.route("/<path:anything>")
    def anything(anything: str) -> dict[str, str]:
        return {"path": anything}

    return app


@pytest.mark.parametrize(
    ("path", "status"),
    [
        ("/hls/live/segment_001.ts", 200),
        ("/static/js/app.4f3a.js.map", 200),
        ("/static/real.ts", 200),
        ("/static/real.ts;jsessionid=1", 400),
        ("/hls/live/missing.ts", 400),
        ("/static/js/missing.js.map", 400),
        ("/static/folder.ts", 400),
        ("/static/app.py", 400),
        ("/static/dump.sql", 400),
        ("/static/app.php", 400),
        ("/static/../secret.ts", 400),
        ("/nowhere/live/segment_001.ts", 400),
    ],
)
def test_a_ts_or_map_file_is_clean_only_when_the_static_mount_has_it(
    tmp_path: Path, path: str, status: int
) -> None:
    app = _static_app(_tree(tmp_path))

    with app.test_client() as client:
        assert client.get(path).status_code == status


def _matches_issued_by_the_guard(
    app: Flask, monkeypatch: pytest.MonkeyPatch, method: str, path: str
) -> tuple[int, int]:
    from werkzeug.routing import Map

    binds: list[str] = []
    original = Map.bind

    def counting(self: Map, server_name: str, *args: Any, **kwargs: Any) -> Any:
        if server_name == "":
            binds.append(server_name)
        return original(self, server_name, *args, **kwargs)

    monkeypatch.setattr(Map, "bind", counting)
    with app.test_client() as client:
        status = client.open(path, method=method).status_code
    return status, len(binds)


def test_a_static_request_reuses_the_match_flask_already_made(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    app = _static_app(_tree(tmp_path))

    status, binds = _matches_issued_by_the_guard(
        app, monkeypatch, "GET", "/static/real.ts"
    )

    assert (status, binds) == (200, 0)


def test_a_catch_all_route_is_not_a_static_mount(tmp_path: Path) -> None:
    root = _tree(tmp_path)
    app = Flask(__name__, static_folder=None)
    _guard(app)

    @app.route("/<path:filename>")
    def anything(filename: str) -> dict[str, str]:
        return {"path": filename, "root": str(root)}

    with app.test_client() as client:
        assert client.get("/hls/live/segment_001.ts").status_code == 400


def test_the_lookup_is_traversal_safe_and_never_cached(tmp_path: Path) -> None:
    app = _static_app(_tree(tmp_path))
    guard = _guard(app)
    late = tmp_path / "static" / "late.ts"

    with app.test_request_context("/"):
        assert guard.static_file_exists("/static/real.ts") is True
        assert guard.static_file_exists("/static/../secret.ts") is False
        assert guard.static_file_exists("/static/a\x00.ts") is False
        assert guard.static_file_exists("/static/late.ts") is False
        late.write_text("x")
        assert guard.static_file_exists("/static/late.ts") is True
        late.unlink()
        assert guard.static_file_exists("/static/late.ts") is False


def test_a_redirect_a_missing_route_and_a_blueprint_without_a_folder_answer_false(
    tmp_path: Path,
) -> None:
    app = Flask(__name__, static_folder=None)
    plain = Blueprint("plain", __name__, static_folder=None)
    app.register_blueprint(plain)
    guard = _guard(app)

    @app.route("/dir/")
    def directory() -> str:
        return "d"

    with app.test_request_context("/"):
        assert guard.static_file_exists("/dir") is False
        assert guard.static_file_exists("/missing/x.ts") is False
        assert guard.static_file_exists("/dir/") is False


STATIC_MOUNT_CORPUS = (
    "hls/live/segment_000.ts",
    "hls/live/segment_001.ts",
    "hls/vod/720p/chunk-00042.ts",
    "hls/vod/1080p/chunk-00001.ts",
    "hls/audio/seg-12.ts",
    "assets/index-4f3a9c1e.js.map",
    "assets/vendor-b82d.js.map",
    "assets/main.css.map",
    "_next/static/chunks/app/page-9d8c.js.map",
    "_next/static/chunks/webpack-1a2b.js.map",
    "static/js/main.4f3a.chunk.js.map",
    "static/css/main.8e1.chunk.css.map",
    "dist/bundle.min.js.map",
    "build/static/js/2.abc123.chunk.js.map",
    "js/jquery.min.map",
    "assets/ts/sample.ts",
    "examples/demo.ts",
)


@pytest.mark.parametrize("name", STATIC_MOUNT_CORPUS)
def test_the_static_mount_benign_corpus_is_clean_when_the_files_exist(
    tmp_path: Path, name: str
) -> None:
    target = tmp_path / "media" / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("x")
    app = Flask(
        __name__, static_folder=str(tmp_path / "media"), static_url_path="/media"
    )
    _guard(app)

    with app.test_client() as client:
        assert client.get(f"/media/{name}").status_code == 200


@pytest.mark.parametrize("name", STATIC_MOUNT_CORPUS)
def test_the_static_mount_benign_corpus_is_flagged_without_a_static_mount(
    name: str,
) -> None:
    app = Flask(__name__, static_folder=None)
    _guard(app)

    @app.route("/<path:filename>")
    def anything(filename: str) -> dict[str, str]:
        return {"path": filename}

    with app.test_client() as client:
        assert client.get(f"/media/{name}").status_code == 400


def test_a_static_endpoint_whose_folder_was_unset_answers_false(tmp_path: Path) -> None:
    app = _static_app(_tree(tmp_path))
    guard = _guard(app)
    app.static_folder = None

    with app.test_request_context("/"):
        assert guard.static_file_exists("/static/real.ts") is False
