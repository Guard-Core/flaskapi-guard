from flask import Blueprint, Flask
from flask import request as flask_request
from guard_core.sync.protocols.request_protocol import SyncGuardRequest

from flaskapi_guard import FlaskAPIGuard, SecurityConfig
from flaskapi_guard.adapters import FlaskGuardRequest


def _template(app: Flask, path: str) -> object:
    ext = FlaskAPIGuard(app, config=SecurityConfig[SyncGuardRequest]())
    with app.test_request_context(path):
        guard_request = FlaskGuardRequest(flask_request)
        ext._populate_guard_state(guard_request)
        return getattr(guard_request.state, "guard_route_template", None)


def _view() -> str:
    return "ok"


def test_a_blueprint_url_prefix_is_in_the_template() -> None:
    blueprint = Blueprint("orgs", __name__, url_prefix="/orgs/<int:org>")
    blueprint.add_url_rule("/items/<item_id>", "item", _view)
    app = Flask(__name__)
    app.register_blueprint(blueprint)

    assert _template(app, "/orgs/5/items/a@x.io") == "/orgs/<int:org>/items/<item_id>"


def test_a_url_prefix_given_at_registration_is_in_the_template() -> None:
    blueprint = Blueprint("orgs", __name__)
    blueprint.add_url_rule("/items/<item_id>", "item", _view)
    app = Flask(__name__)
    app.register_blueprint(blueprint, url_prefix="/v2/<tenant>")

    assert _template(app, "/v2/acme/items/9") == "/v2/<tenant>/items/<item_id>"


def test_nested_blueprints_join_every_prefix_in_order() -> None:
    leaf = Blueprint("leaf", __name__, url_prefix="/things/<int:thing>")
    leaf.add_url_rule("/parts/<part>", "part", _view)
    middle = Blueprint("middle", __name__, url_prefix="/teams/<team>")
    middle.register_blueprint(leaf)
    outer = Blueprint("outer", __name__, url_prefix="/orgs/<org>")
    outer.register_blueprint(middle)
    app = Flask(__name__)
    app.register_blueprint(outer, url_prefix="/api")

    assert _template(app, "/api/teams/t/things/3/parts/p") == (
        "/api/teams/<team>/things/<int:thing>/parts/<part>"
    )


def test_a_nested_blueprint_prefix_given_at_registration_is_in_the_template() -> None:
    child = Blueprint("child", __name__)
    child.add_url_rule("/x/<x>", "x", _view)
    parent = Blueprint("parent", __name__, url_prefix="/p/<p>")
    parent.register_blueprint(child, url_prefix="/c/<c>")
    app = Flask(__name__)
    app.register_blueprint(parent)

    assert _template(app, "/p/1/c/2/x/3") == "/p/<p>/c/<c>/x/<x>"
