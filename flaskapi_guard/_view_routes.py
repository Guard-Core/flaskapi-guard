from flask.views import MethodView, http_method_funcs


def _verbs(view_class: type, method: str | None) -> list[str]:
    if method is None:
        return [verb for verb in http_method_funcs if hasattr(view_class, verb)]
    # MethodView.dispatch_request: HEAD is served by `get` unless the class has `head`
    if method == "head" and not hasattr(view_class, "head"):
        return ["get"]
    return [method]


def _class_places(view_class: type, method: str | None) -> list[tuple[str, object]]:
    places: list[tuple[str, object]] = [
        ("the class", view_class),
        ("dispatch_request", getattr(view_class, "dispatch_request", None)),
    ]
    if issubclass(view_class, MethodView):
        places += [
            (f"its {verb} method", getattr(view_class, verb, None))
            for verb in _verbs(view_class, method)
        ]
    return places


def route_ids_of_view(view: object, method: str | None) -> list[tuple[str, str]]:
    """Where a route decorator was applied to the view, as (place, route id).

    A decorator on the function, on `Class.as_view()` or through `View.decorators`
    marks the function Flask registered; one applied to the class marks the class;
    one on `dispatch_request` marks that method, which `View.as_view` calls for
    every HTTP method; on a `MethodView` the method named for the HTTP method is
    the one `dispatch_request` calls (a subclass that overrides `dispatch_request`
    decides for itself, so that override is the place checked then). `method` is
    the lower-cased HTTP method, or None for every method the class has.
    """
    places: list[tuple[str, object]] = [("the view function", view)]
    view_class = getattr(view, "view_class", None)
    if isinstance(view_class, type):
        places += _class_places(view_class, method)
    found = [(place, getattr(obj, "_guard_route_id", None)) for place, obj in places]
    return [(place, route_id) for place, route_id in found if route_id]


def endpoint_id_of_view(view: object, endpoint: str) -> str:
    """The per-endpoint rate-limit id. A function keeps `module.qualname`; a class
    based view takes its class (`as_view` gives every view the same qualname); a
    callable without a `__qualname__` (a partial, an instance) takes the id the
    engine stamped on it, and without a stamp the endpoint Flask registered it
    under, because two such views of one class are two routes."""
    owner = getattr(view, "view_class", None) or view
    qualname = getattr(owner, "__qualname__", None)
    if qualname:
        return f"{owner.__module__}.{qualname}"
    stamped = getattr(owner, "_guard_route_id", None)
    if stamped:
        return str(stamped)
    return f"{owner.__module__}.{type(owner).__qualname__}@{endpoint}"
